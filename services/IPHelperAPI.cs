namespace NetworkScanner.Services;

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

/// <summary>
/// Wrapper for Windows IP Helper API to discover devices via kernel connection table.
/// This finds devices that have communicated with this machine (far more reliable than blind scanning).
/// </summary>
public static class IPHelperAPI
{
    #region P/Invoke Declarations

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, TCP_TABLE_CLASS tblClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, UDP_TABLE_CLASS tblClass, uint reserved);

    // SendARP: on success (returns 0), the MAC is written directly into pMacAddr.
    // pMacAddr must be at least 8 bytes. PhyAddrLen is updated to the actual byte count written.
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

    // Legacy ARP table — still useful as a fast initial snapshot
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetIpNetTable(IntPtr pIpNetTable, ref int dwOutBufLen, bool sort);

    // Modern neighbor table (replaces GetIpNetTable, works properly on Windows Vista+)
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetIpNetTable2(ushort Family, out IntPtr Table);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern void FreeMibTable(IntPtr Memory);

    private enum TCP_TABLE_CLASS { TCP_TABLE_OWNER_PID_ALL = 5 }
    private enum UDP_TABLE_CLASS { UDP_TABLE_OWNER_PID = 1 }

    // AF_INET = 2, AF_INET6 = 23, AF_UNSPEC = 0 (both)
    private const ushort AF_UNSPEC = 0;
    private const ushort AF_INET   = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    // Legacy ARP table row (GetIpNetTable)
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPNETROW
    {
        public uint dwIndex;
        public uint dwPhysAddrLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] bPhysAddr;
        public uint dwAddr;
        public uint dwType;
    }

    // MIB_IPNET_ROW2 — explicit layout, x64, 88 bytes total.
    // See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipnet_row2
    //
    // Offset map:
    //   0   SOCKADDR_INET Address (union, 28 bytes):
    //         0  Family (ushort)  — 2=AF_INET, 23=AF_INET6
    //         2  Port   (ushort)
    //         4  SinAddr (uint)   — IPv4 address (network byte order)
    //         8  Sin6AddrLow (ulong)  — IPv6 addr bytes 0-7
    //        16  Sin6AddrHigh (ulong) — IPv6 addr bytes 8-15
    //        24  Sin6ScopeId (uint)
    //  28   InterfaceIndex (uint)
    //  32   InterfaceLuid (ulong)   — 8-byte aligned
    //  40   PhysicalAddress (byte[32])
    //  72   PhysicalAddressLength (uint)
    //  76   State (uint)            — NL_NEIGHBOR_STATE
    //  80   Flags (byte)
    //  84   ReachabilityTime (uint) — after 3 bytes implicit padding
    //  88   <end>
    [StructLayout(LayoutKind.Explicit, Size = 88)]
    private struct MIB_IPNET_ROW2
    {
        // SOCKADDR_INET union — expanded inline at offset 0
        [FieldOffset(0)]  public ushort Family;          // AF_INET=2, AF_INET6=23
        [FieldOffset(2)]  public ushort Port;
        [FieldOffset(4)]  public uint   SinAddr;         // IPv4 address (network byte order)
        [FieldOffset(8)]  public ulong  Sin6AddrLow;     // IPv6 bytes 0-7
        [FieldOffset(16)] public ulong  Sin6AddrHigh;    // IPv6 bytes 8-15
        [FieldOffset(24)] public uint   Sin6ScopeId;

        [FieldOffset(28)] public uint   InterfaceIndex;
        [FieldOffset(32)] public ulong  InterfaceLuid;

        [FieldOffset(40)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[]     PhysicalAddress;

        [FieldOffset(72)] public uint   PhysicalAddressLength;
        [FieldOffset(76)] public uint   State;           // NL_NEIGHBOR_STATE
        [FieldOffset(80)] public byte   Flags;           // bit0=IsRouter, bit1=IsUnreachable
        [FieldOffset(84)] public uint   ReachabilityTime;

        // SinAddr is in network byte order (big-endian); GetAddressBytes() also returns
        // big-endian, so we can compare directly with BitConverter.ToUInt32(addr.GetAddressBytes(), 0)
        // which reads it as little-endian. Instead, expose as IPAddress for safe comparison.
        public IPAddress? GetIPv4Address()
        {
            if (Family != 2) return null; // AF_INET
            // SinAddr bytes: [b0, b1, b2, b3] in network order, stored as little-endian uint
            // e.g. 192.168.2.1 → SinAddr = 0x0102A8C0
            byte b0 = (byte)(SinAddr & 0xFF);
            byte b1 = (byte)((SinAddr >> 8) & 0xFF);
            byte b2 = (byte)((SinAddr >> 16) & 0xFF);
            byte b3 = (byte)((SinAddr >> 24) & 0xFF);
            return new IPAddress(new[] { b0, b1, b2, b3 });
        }
    }

    // Confirmed via DiagnosticDump on this machine:
    //   - NumEntries is at offset 0 (4 bytes)
    //   - First row starts at offset 8 (4 bytes padding after NumEntries to 8-byte-align the row)
    //   - Row stride is 88 bytes
    //   - SinAddr at row+4 stores the IP in little-endian host order matching FormatIP()
    private const int MIB_IPNET_TABLE2_HEADER_SIZE = 8; // 4-byte NumEntries + 4-byte padding
    private const int MIB_IPNET_ROW2_SIZE = 88;

    #endregion

    #region Public API

    /// <summary>
    /// Discovers devices by querying the Windows ARP table, TCP connection table, and UDP connection table.
    /// </summary>
    public static HashSet<string> DiscoverDevicesFromConnectionTable(string? customSubnet = null)
    {
        var devices = new HashSet<string>();

        var localSubnet = customSubnet ?? GetLocalSubnet();
        if (string.IsNullOrEmpty(localSubnet))
        {
            System.Diagnostics.Debug.WriteLine("Could not detect local subnet");
            return devices;
        }

        System.Diagnostics.Debug.WriteLine($"Local subnet detected: {localSubnet}");

        // Gateway
        try
        {
            var gateway = GetDefaultGateway();
            if (!string.IsNullOrEmpty(gateway) && IsInLocalSubnet(gateway, localSubnet))
            {
                devices.Add(gateway);
                System.Diagnostics.Debug.WriteLine($"Added gateway: {gateway}");
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"Gateway error: {ex.Message}"); }

        // Modern neighbor table (GetIpNetTable2) — primary source
        try
        {
            var neighborIPs = GetNeighborTableEntries();
            System.Diagnostics.Debug.WriteLine($"Neighbor table returned {neighborIPs.Count} IPs");
            int added = 0;
            foreach (var ip in neighborIPs)
                if (IsInLocalSubnet(ip, localSubnet) && devices.Add(ip)) added++;
            System.Diagnostics.Debug.WriteLine($"Neighbor table added {added} local IPs");
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"Neighbor table error: {ex.Message}"); }

        // Legacy ARP table (GetIpNetTable) — fallback / additional entries
        try
        {
            var arpIPs = GetArpTableEntries();
            System.Diagnostics.Debug.WriteLine($"Legacy ARP table returned {arpIPs.Count} IPs");
            int added = 0;
            foreach (var ip in arpIPs)
                if (IsInLocalSubnet(ip, localSubnet) && devices.Add(ip)) added++;
            System.Diagnostics.Debug.WriteLine($"Legacy ARP added {added} new local IPs");
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"ARP table error: {ex.Message}"); }

        // TCP connections
        try
        {
            var tcpIPs = GetTcpConnections();
            int added = 0;
            foreach (var ip in tcpIPs)
                if (IsInLocalSubnet(ip, localSubnet) && devices.Add(ip)) added++;
            System.Diagnostics.Debug.WriteLine($"TCP added {added} new local IPs");
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"TCP error: {ex.Message}"); }

        // UDP connections
        try
        {
            var udpIPs = GetUdpConnections();
            int added = 0;
            foreach (var ip in udpIPs)
                if (IsInLocalSubnet(ip, localSubnet) && devices.Add(ip)) added++;
            System.Diagnostics.Debug.WriteLine($"UDP added {added} new local IPs");
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"UDP error: {ex.Message}"); }

        System.Diagnostics.Debug.WriteLine($"Total IPs to scan: {devices.Count}");
        return devices;
    }

    /// <summary>
    /// Gets the MAC address for an IPv4 device.
    /// Strategy:
    ///   1. Fast path — check modern neighbor table (GetIpNetTable2)
    ///   2. Fast path — check legacy ARP cache (GetIpNetTable)
    ///   3. Active probe — call SendARP and read the MAC directly from its output buffer
    ///      (SendARP is synchronous and returns the MAC in the buffer on success, not via the OS table)
    /// </summary>
    public static string? GetMACAddress(string ipAddress)
    {
        // 1. Modern neighbor table first — most complete and up to date
        var mac = GetMACFromNeighborTable(ipAddress);
        if (mac != null) return mac;

        // 2. Legacy ARP cache
        mac = GetMACFromArpTable(ipAddress);
        if (mac != null) return mac;

        // 3. Active ARP probe — SendARP writes the result directly into our buffer
        mac = ProbeViaSendARP(ipAddress);
        return mac;
    }

    /// <summary>
    /// Checks only the OS neighbor caches (GetIpNetTable2 + GetIpNetTable).
    /// Does NOT issue a new ARP probe. Returns null if no cached entry exists yet.
    /// </summary>
    public static string? GetMACFromCacheOnly(string ipAddress)
    {
        return GetMACFromNeighborTable(ipAddress) ?? GetMACFromArpTable(ipAddress);
    }

    /// <summary>
    /// Reads ALL entries from both ARP cache APIs in a single pass and returns
    /// a dictionary of IP → MAC. Called twice — before and after the ping burst —
    /// so the caller can merge the two snapshots without re-querying per-device.
    /// </summary>
    public static void SnapshotArpCache(Dictionary<string, string> target)
    {
        foreach (var kv in SnapshotArpCache())
            target[kv.Key] = kv.Value;
    }

    public static Dictionary<string, string> SnapshotArpCache()
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);

        // --- GetIpNetTable2 (modern) ---
        IntPtr tablePtr = IntPtr.Zero;
        try
        {
            if (GetIpNetTable2(AF_INET, out tablePtr) == 0 && tablePtr != IntPtr.Zero)
            {
                uint numEntries = (uint)Marshal.ReadInt32(tablePtr);
                IntPtr rowPtr = tablePtr + MIB_IPNET_TABLE2_HEADER_SIZE;
                for (uint i = 0; i < numEntries; i++, rowPtr += MIB_IPNET_ROW2_SIZE)
                {
                    var row = Marshal.PtrToStructure<MIB_IPNET_ROW2>(rowPtr);
                    if (row.Family != AF_INET || row.PhysicalAddressLength < 6 || row.PhysicalAddress == null)
                        continue;
                    var ip = row.GetIPv4Address()?.ToString();
                    if (ip == null) continue;
                    var mac = FormatMAC(row.PhysicalAddress, (int)row.PhysicalAddressLength);
                    if (mac != null && !result.ContainsKey(ip))
                        result[ip] = mac;
                }
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"SnapshotArpCache (table2): {ex.Message}"); }
        finally { if (tablePtr != IntPtr.Zero) FreeMibTable(tablePtr); }

        // --- GetIpNetTable (legacy) — catches entries not in GetIpNetTable2 ---
        int bufLen = 0;
        GetIpNetTable(IntPtr.Zero, ref bufLen, false);
        if (bufLen > 0)
        {
            var buf = Marshal.AllocHGlobal(bufLen);
            try
            {
                if (GetIpNetTable(buf, ref bufLen, false) == 0)
                {
                    int rowCount = Marshal.ReadInt32(buf);
                    IntPtr rowPtr = buf + 4;
                    int rowSize = Marshal.SizeOf<MIB_IPNETROW>();
                    for (int i = 0; i < rowCount; i++, rowPtr += rowSize)
                    {
                        var row = Marshal.PtrToStructure<MIB_IPNETROW>(rowPtr);
                        if (row.dwPhysAddrLen == 0 || row.bPhysAddr == null) continue;
                        var ip = FormatIP(row.dwAddr);
                        var mac = FormatMAC(row.bPhysAddr, (int)row.dwPhysAddrLen);
                        if (mac != null && !result.ContainsKey(ip))
                            result[ip] = mac;
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"SnapshotArpCache (legacy): {ex.Message}"); }
            finally { Marshal.FreeHGlobal(buf); }
        }

        System.Diagnostics.Debug.WriteLine($"SnapshotArpCache: {result.Count} total entries");
        return result;
    }

    // Keep for compatibility
    public static string? ProbeAndGetMACAddress(string ipAddress) => GetMACAddress(ipAddress);
    public static string? GetMACAddressFromArpTable(string ipAddress) => GetMACFromArpTable(ipAddress);

    /// <summary>
    /// Merges MAC addresses from two command-line sources into the cache:
    ///
    ///   1. "netsh interface ipv4 show neighbors" — reads all interfaces including
    ///      Stale entries that GetIpNetTable filters out. This is the richest source
    ///      and catches entries the P/Invoke APIs miss entirely.
    ///
    ///   2. "arp -a" — fallback for cases where netsh is unavailable.
    ///
    /// Results are merged without overwriting existing entries.
    /// </summary>
    public static void MergeArpCommandOutput(Dictionary<string, string> cache)
    {
        // Try netsh first — it exposes Stale entries that arp -a and GetIpNetTable miss
        var netshEntries = RunCommandAndParseMACs("netsh", "interface ipv4 show neighbors");
        if (netshEntries.Count > 0)
        {
            foreach (var kv in netshEntries)
                if (!cache.ContainsKey(kv.Key))
                {
                    cache[kv.Key] = kv.Value;
                    System.Diagnostics.Debug.WriteLine($"netsh neighbors: {kv.Key} → {kv.Value}");
                }
            System.Diagnostics.Debug.WriteLine($"netsh added {netshEntries.Count} entries");
            return; // netsh succeeded — no need for arp -a
        }

        // Fallback: arp -a (same data, fewer entries, but universally available)
        var arpEntries = RunCommandAndParseMACs("arp", "-a");
        foreach (var kv in arpEntries)
            if (!cache.ContainsKey(kv.Key))
            {
                cache[kv.Key] = kv.Value;
                System.Diagnostics.Debug.WriteLine($"arp -a: {kv.Key} → {kv.Value}");
            }
        System.Diagnostics.Debug.WriteLine($"arp -a added {arpEntries.Count} entries");
    }

    /// <summary>
    /// Reads the IPv6 NDP neighbor table (GetIpNetTable2 with AF_INET6) and returns
    /// a MAC-address-keyed dictionary. This is the key source SoftPerfect uses:
    /// IPv6 Neighbor Discovery uses multicast ICMPv6 which Wi-Fi APs pass through,
    /// unlike ARP which many APs block between wireless clients.
    ///
    /// The caller then correlates these MACs against their IPv4 scan results using
    /// BuildNdpMacToIpv4Map() to map MAC → IPv4 address.
    /// </summary>
    public static Dictionary<string, string> SnapshotNdpMacTable()
    {
        // MAC (uppercase, dashes) → MAC (same, deduplicated)
        var macs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        IntPtr tablePtr = IntPtr.Zero;
        try
        {
            if (GetIpNetTable2(23 /* AF_INET6 */, out tablePtr) != 0 || tablePtr == IntPtr.Zero)
                return macs;

            uint numEntries = (uint)Marshal.ReadInt32(tablePtr);
            IntPtr rowPtr = tablePtr + MIB_IPNET_TABLE2_HEADER_SIZE;

            for (uint i = 0; i < numEntries; i++, rowPtr += MIB_IPNET_ROW2_SIZE)
            {
                var row = Marshal.PtrToStructure<MIB_IPNET_ROW2>(rowPtr);
                if (row.Family != 23) continue; // AF_INET6
                if (row.PhysicalAddressLength < 6 || row.PhysicalAddress == null) continue;

                var mac = FormatMAC(row.PhysicalAddress, (int)row.PhysicalAddressLength);
                if (mac != null && !macs.ContainsKey(mac))
                    macs[mac] = mac;
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"SnapshotNdpMacTable: {ex.Message}"); }
        finally { if (tablePtr != IntPtr.Zero) FreeMibTable(tablePtr); }

        System.Diagnostics.Debug.WriteLine($"NDP MAC table: {macs.Count} unique MACs");
        return macs;
    }

    /// <summary>
    /// Given a set of IPv4 addresses found to be live (from the ping sweep) and the
    /// NDP MAC table, builds a MAC → IPv4 map by two methods:
    ///
    ///   1. EUI-64 derivation: many devices form their IPv6 link-local address directly
    ///      from their MAC (RFC 4291). The MAC is embedded in the IPv6 address as:
    ///        fe80::[first3 XOR 0x02][ff:fe][last3]
    ///      e.g. MAC 28-70-4E-DD-B3-E5 → fe80::2a70:4eff:fedd:b3e5
    ///      We can reverse this: extract MAC bytes from any fe80:: EUI-64 address.
    ///
    ///   2. Cross-reference: match MACs from the NDP table against MACs we already
    ///      know from the IPv4 ARP table.
    ///
    /// Returns a dictionary of IPv4 address → MAC for any IPv4 host whose MAC was
    /// found via NDP but not via ARP.
    /// </summary>
    public static Dictionary<string, string> BuildNdpIpv4MacMap(
        IEnumerable<string> liveIpv4Hosts,
        Dictionary<string, string> existingMacCache)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);

        // Step 1: Parse netsh ipv6 neighbor output — this has the IPv6↔MAC mappings
        // with the full IPv6 address visible, so we can do EUI-64 reversal
        var ndpEntries = ParseNdpCommandOutput(); // IPv6 addr → MAC

        System.Diagnostics.Debug.WriteLine($"NDP command entries: {ndpEntries.Count}");

        // Step 2: For each live IPv4 host that's still missing a MAC, try to find its
        // MAC by checking if any NDP entry's MAC matches an EUI-64 derived from the IPv4.
        // We do this by inverting: for each NDP MAC, try to derive a link-local IPv6,
        // then check if that MAC appears in our existing data.

        // Build reverse map: MAC → IPv6 address (from NDP)
        var macToIpv6 = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in ndpEntries)
            if (!macToIpv6.ContainsKey(kv.Value))
                macToIpv6[kv.Value] = kv.Key;

        // Step 3: For each NDP entry, check if its MAC is EUI-64 derived and if so,
        // match it against our live IPv4 hosts via the existing MAC cache (reverse lookup)
        // Build MAC → IPv4 from existing cache
        var macToIpv4 = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in existingMacCache)
            if (!macToIpv4.ContainsKey(kv.Value))
                macToIpv4[kv.Value] = kv.Key;

        // For each live IPv4 host without a MAC, check NDP table
        var liveSet = new HashSet<string>(liveIpv4Hosts, StringComparer.Ordinal);
        foreach (var kv in ndpEntries)
        {
            var ipv6 = kv.Key;
            var mac  = kv.Value;

            // Skip if this MAC is already mapped to an IPv4
            if (macToIpv4.ContainsKey(mac)) continue;

            // Try to extract MAC from EUI-64 link-local address
            // fe80::XXYY:ZZFF:FEAA:BBCC → MAC = (XX^0x02)-YY-ZZ-AA-BB-CC
            var macFromEui = ExtractMacFromEui64(ipv6);
            if (macFromEui != null && macFromEui.Equals(mac, StringComparison.OrdinalIgnoreCase))
            {
                // This is an EUI-64 derived address — we have the MAC but not the IPv4.
                // We'll store it in the result keyed by MAC for the caller to correlate.
                System.Diagnostics.Debug.WriteLine($"NDP EUI-64: {ipv6} → {mac}");
            }
        }

        // Step 4: The most useful thing we can do is provide the full NDP MAC set
        // so the caller can do the IPv4 correlation when a host reports in
        foreach (var kv in ndpEntries)
        {
            var mac = kv.Value;
            if (!macToIpv4.ContainsKey(mac))
                result[$"__ndp__{mac}"] = mac; // Flagged for later correlation
        }

        return result;
    }

    /// <summary>
    /// Attempts to extract a MAC address from an EUI-64 derived IPv6 link-local address.
    /// RFC 4291: fe80::A:Bff:feC:D where the MAC is derived by:
    ///   - Split the interface ID into [A][B ff fe][C][D]
    ///   - XOR the first byte with 0x02 to get the original MAC first byte
    /// e.g. fe80::2a70:4eff:fedd:b3e5 → 28-70-4e-dd-b3-e5
    /// Returns null if the address is not EUI-64 derived (doesn't contain ff:fe pattern).
    /// </summary>
    public static string? ExtractMacFromEui64(string ipv6)
    {
        try
        {
            if (!IPAddress.TryParse(ipv6, out var addr)) return null;
            if (addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) return null;

            var bytes = addr.GetAddressBytes(); // 16 bytes
            // Interface ID is bytes[8..15]
            // EUI-64 has 0xFF at bytes[11] and 0xFE at bytes[12]
            if (bytes[11] != 0xFF || bytes[12] != 0xFE) return null;

            // Reconstruct MAC: reverse the universal/local bit flip (XOR with 0x02)
            byte b0 = (byte)(bytes[8]  ^ 0x02);
            byte b1 = bytes[9];
            byte b2 = bytes[10];
            byte b3 = bytes[13];
            byte b4 = bytes[14];
            byte b5 = bytes[15];

            // Sanity: all-zeros or all-ones is invalid
            if (b0 == 0 && b1 == 0 && b2 == 0 && b3 == 0 && b4 == 0 && b5 == 0) return null;

            return $"{b0:X2}-{b1:X2}-{b2:X2}-{b3:X2}-{b4:X2}-{b5:X2}";
        }
        catch { return null; }
    }

    private static Dictionary<string, string> ParseNdpCommandOutput()
    {
        // IPv6 address → MAC
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var entries = RunCommandAndParseMACs("netsh", "interface ipv6 show neighbors");
            // RunCommandAndParseMACs returns IP→MAC, but for IPv6 the "IP" is the IPv6 addr
            foreach (var kv in entries)
                if (!result.ContainsKey(kv.Key))
                    result[kv.Key] = kv.Value;
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"ParseNdpCommandOutput: {ex.Message}"); }
        return result;
    }

    private static Dictionary<string, string> RunCommandAndParseMACs(string exe, string args)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName               = exe,
                Arguments              = args,
                RedirectStandardOutput = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };

            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return result;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            // Both arp -a and netsh output lines with IP and MAC as the first two tokens:
            //   "  192.168.2.1     1c-0b-8b-12-02-15     dynamic"        (arp -a)
            //   "  192.168.2.1     1c-0b-8b-12-02-15     Reachable"      (netsh)
            foreach (var line in output.Split('\n'))
            {
                var parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;

                var ip  = parts[0];
                var mac = parts[1];

                if (!System.Net.IPAddress.TryParse(ip, out _)) continue;

                // Must match XX-XX-XX-XX-XX-XX (arp format) or xx:xx:xx:xx:xx:xx
                var macNorm = mac.Replace(':', '-');
                if (!System.Text.RegularExpressions.Regex.IsMatch(macNorm,
                        @"^([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}$")) continue;

                // Exclude broadcast, multicast, and all-zeros
                if (macNorm.Equals("ff-ff-ff-ff-ff-ff", StringComparison.OrdinalIgnoreCase)) continue;
                if (macNorm.StartsWith("01-00-5e", StringComparison.OrdinalIgnoreCase)) continue;
                if (macNorm.Equals("00-00-00-00-00-00", StringComparison.OrdinalIgnoreCase)) continue;

                if (!result.ContainsKey(ip))
                    result[ip] = macNorm.ToUpper();
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"RunCommandAndParseMACs({exe}): {ex.Message}");
        }
        return result;
    }

    #endregion

    #region MAC lookup implementations

    /// <summary>
    /// Reads the MAC for a given IP from the modern Windows neighbor table (GetIpNetTable2).
    /// This is the preferred API on Vista+ — it sees more entries than GetIpNetTable.
    /// </summary>
    private static string? GetMACFromNeighborTable(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var addr) ||
            addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return null;

        IntPtr tablePtr = IntPtr.Zero;
        try
        {
            if (GetIpNetTable2(AF_INET, out tablePtr) != 0 || tablePtr == IntPtr.Zero)
                return null;

            // NumEntries is at offset 0 — read it directly to avoid marshalling the
            // embedded first row as part of a header struct (that causes the offset bug).
            uint numEntries = (uint)Marshal.ReadInt32(tablePtr);
            System.Diagnostics.Debug.WriteLine($"GetIpNetTable2 (AF_INET): {numEntries} neighbor entries");

            // First row starts at tablePtr + 96 (see MIB_IPNET_TABLE2_HEADER_SIZE comment)
            IntPtr rowPtr = tablePtr + MIB_IPNET_TABLE2_HEADER_SIZE;

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_IPNET_ROW2>(rowPtr);

                if (row.Family == AF_INET && row.PhysicalAddressLength >= 6 && row.PhysicalAddress != null)
                {
                    var rowIP = row.GetIPv4Address();
                    if (rowIP != null && rowIP.ToString() == ipAddress)
                    {
                        var mac = FormatMAC(row.PhysicalAddress, (int)row.PhysicalAddressLength);
                        if (mac != null)
                        {
                            System.Diagnostics.Debug.WriteLine($"GetIpNetTable2 hit: {ipAddress} → {mac} (state={row.State})");
                            return mac;
                        }
                    }
                }

                rowPtr += MIB_IPNET_ROW2_SIZE;
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"GetIpNetTable2 MAC lookup error: {ex.Message}");
        }
        finally
        {
            if (tablePtr != IntPtr.Zero) FreeMibTable(tablePtr);
        }

        return null;
    }

    /// <summary>
    /// Reads the MAC for a given IP from the legacy ARP table (GetIpNetTable).
    /// Kept as a fallback — some entries appear here that don't appear in GetIpNetTable2.
    /// The dwPhysAddrLen filter is relaxed to > 0 (instead of == 6) to catch valid entries
    /// that some drivers report with unusual lengths.
    /// </summary>
    private static string? GetMACFromArpTable(string ipAddress)
    {
        int bufLen = 0;
        GetIpNetTable(IntPtr.Zero, ref bufLen, false);
        if (bufLen <= 0) return null;

        var buf = Marshal.AllocHGlobal(bufLen);
        try
        {
            if (GetIpNetTable(buf, ref bufLen, false) != 0) return null;

            int rowCount = Marshal.ReadInt32(buf);
            IntPtr rowPtr = buf + 4;
            int rowSize = Marshal.SizeOf<MIB_IPNETROW>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_IPNETROW>(rowPtr);

                // Relaxed filter: accept any non-zero PhysAddrLen (was == 6, which dropped valid entries)
                if (FormatIP(row.dwAddr) == ipAddress &&
                    row.dwPhysAddrLen > 0 &&
                    row.bPhysAddr != null &&
                    row.bPhysAddr.Length >= row.dwPhysAddrLen)
                {
                    var mac = FormatMAC(row.bPhysAddr, (int)row.dwPhysAddrLen);
                    if (mac != null) return mac;
                }

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }

        return null;
    }

    /// <summary>
    /// Sends a directed ARP request via SendARP and reads the MAC directly from its output buffer.
    ///
    /// This is the key fix: SendARP is synchronous and writes the resolved MAC into the byte[]
    /// buffer you pass it. The old code was reading the result from GetIpNetTable after the call,
    /// which is unreliable — SendARP doesn't guarantee it populates the OS ARP cache.
    /// The return value of SendARP is NO_ERROR (0) on success; the MAC is in pMacAddr.
    /// </summary>
    public static string? ProbeViaSendARP(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var addr) ||
            addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return null;

        try
        {
            // Confirmed by DiagnosticDump: BitConverter.ToUInt32(GetAddressBytes(), 0) produces
            // 0x0102A8C0 for 192.168.2.1, which SendARP correctly interprets as 192.168.2.1.
            // No byte reversal needed — the little-endian read of network-order bytes happens
            // to match what SendARP expects on Windows x64.
            uint destIP = BitConverter.ToUInt32(addr.GetAddressBytes(), 0);

            // Buffer must be at least 8 bytes per MSDN; we use exactly 8
            var macBuf = new byte[8];
            uint macLen = (uint)macBuf.Length;

            uint result = SendARP(destIP, 0, macBuf, ref macLen);

            if (result == 0 && macLen >= 6)
            {
                // SUCCESS — MAC is in macBuf[0..macLen-1], read it directly from here
                var mac = FormatMAC(macBuf, (int)macLen);
                System.Diagnostics.Debug.WriteLine(
                    mac != null
                        ? $"SendARP succeeded for {ipAddress}: {mac}"
                        : $"SendARP returned all-zeros for {ipAddress}");
                return mac;
            }
            else
            {
                System.Diagnostics.Debug.WriteLine($"SendARP failed for {ipAddress}: error={result}");
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"SendARP exception for {ipAddress}: {ex.Message}");
        }

        return null;
    }

    /// <summary>
    /// Formats a raw MAC byte array into "XX-XX-XX-XX-XX-XX" notation.
    /// Returns null if the bytes are all zero (incomplete/invalid ARP entry).
    /// Accepts any length >= 6; uses only the first 6 bytes.
    /// </summary>
    private static string? FormatMAC(byte[] bytes, int length)
    {
        if (bytes == null || length < 6) return null;

        // Check for all-zeros (incomplete entry)
        bool allZero = true;
        for (int i = 0; i < 6; i++)
            if (bytes[i] != 0) { allZero = false; break; }
        if (allZero) return null;

        return $"{bytes[0]:X2}-{bytes[1]:X2}-{bytes[2]:X2}-{bytes[3]:X2}-{bytes[4]:X2}-{bytes[5]:X2}";
    }

    #endregion

    #region Device discovery helpers

    private static string? GetLocalSubnet()
    {
        try
        {
            var nics = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();

            // Two-pass approach:
            // Pass 1: prefer real Ethernet/Wi-Fi adapters with routable (non-link-local) IPs
            // Pass 2: accept any adapter with a routable IP (catches unusual setups)
            // This prevents Tailscale (169.254.x.x) and Hyper-V (172.x.x.x) from
            // being selected over the real LAN interface.
            foreach (var passLinkLocal in new[] { false, true })
            {
                foreach (var nic in nics)
                {
                    if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                        continue;

                    // On pass 1, restrict to physical Ethernet/Wi-Fi adapter types
                    if (!passLinkLocal &&
                        nic.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Ethernet &&
                        nic.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211)
                        continue;

                    foreach (var uni in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (uni.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                            continue;

                        var ip = uni.Address.ToString();
                        var parts = ip.Split('.');
                        if (parts.Length != 4) continue;

                        // Skip link-local (169.254.x.x) — Tailscale TAP and
                        // un-configured adapters use this range
                        if (parts[0] == "169" && parts[1] == "254") continue;

                        // Skip loopback
                        if (parts[0] == "127") continue;

                        // Prefer private routable ranges: 192.168.x.x, 10.x.x.x, 172.16-31.x.x
                        // On pass 1 skip non-private ranges
                        bool isPrivate = parts[0] == "192" || parts[0] == "10" ||
                            (parts[0] == "172" && int.TryParse(parts[1], out int b1) && b1 >= 16 && b1 <= 31);
                        if (!passLinkLocal && !isPrivate) continue;

                        System.Diagnostics.Debug.WriteLine($"Local IP via NIC ({nic.Name}): {ip}");
                        return $"{parts[0]}.{parts[1]}.{parts[2]}";
                    }
                }
            }

            // Fallback: DNS hostname
            var hostName = System.Net.Dns.GetHostName();
            var hostEntry = System.Net.Dns.GetHostEntry(hostName);
            foreach (var address in hostEntry.AddressList)
            {
                if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                var ip = address.ToString();
                var parts = ip.Split('.');
                if (parts.Length == 4 && parts[0] != "127" &&
                    !(parts[0] == "169" && parts[1] == "254"))
                {
                    System.Diagnostics.Debug.WriteLine($"Local IP via DNS: {address}");
                    return $"{parts[0]}.{parts[1]}.{parts[2]}";
                }
            }
        }
        catch { }

        return null;
    }

    private static string? GetDefaultGateway()
    {
        try
        {
            var nics = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
            foreach (var ni in nics)
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                    continue;
                if (ni.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Ethernet &&
                    ni.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211)
                    continue;

                // Skip Tailscale and other VPN virtual adapters — they report
                // gateway addresses that aren't on the local LAN segment
                var hasRoutableUnicast = ni.GetIPProperties().UnicastAddresses
                    .Any(u => u.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                              !u.Address.ToString().StartsWith("169.254.") &&
                              !u.Address.ToString().StartsWith("127."));
                if (!hasRoutableUnicast) continue;

                foreach (var gateway in ni.GetIPProperties().GatewayAddresses)
                {
                    if (gateway.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        System.Diagnostics.Debug.WriteLine($"Gateway: {gateway.Address}");
                        return gateway.Address.ToString();
                    }
                }
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"Gateway error: {ex.Message}"); }

        return null;
    }

    private static bool IsInLocalSubnet(string ipAddress, string localSubnet)
        => !string.IsNullOrEmpty(localSubnet) && ipAddress.StartsWith(localSubnet + ".");

    private static List<string> GetNeighborTableEntries()
    {
        var ips = new List<string>();
        IntPtr tablePtr = IntPtr.Zero;
        try
        {
            // AF_UNSPEC returns both IPv4 and IPv6 neighbors
            if (GetIpNetTable2(AF_UNSPEC, out tablePtr) != 0 || tablePtr == IntPtr.Zero)
                return ips;

            uint numEntries = (uint)Marshal.ReadInt32(tablePtr);
            IntPtr rowPtr = tablePtr + MIB_IPNET_TABLE2_HEADER_SIZE;

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_IPNET_ROW2>(rowPtr);

                // Only IPv4 entries — IPv6 neighbors can't provide local subnet IPv4 MACs
                if (row.Family == AF_INET && row.PhysicalAddressLength >= 6)
                {
                    var rowIP = row.GetIPv4Address();
                    if (rowIP != null)
                    {
                        var ip = rowIP.ToString();
                        var octets = ip.Split('.');
                        if (octets.Length == 4 &&
                            !ip.StartsWith("0.") && !ip.StartsWith("127.") &&
                            !ip.StartsWith("255.") && !ip.StartsWith("224.") &&
                            !ip.StartsWith("239.") &&
                            octets[3] != "0" && octets[3] != "255")
                        {
                            ips.Add(ip);
                        }
                    }
                }

                rowPtr += MIB_IPNET_ROW2_SIZE;
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"GetNeighborTableEntries error: {ex.Message}");
        }
        finally
        {
            if (tablePtr != IntPtr.Zero) FreeMibTable(tablePtr);
        }

        return ips;
    }

    private static List<string> GetArpTableEntries()
    {
        var ips = new List<string>();
        int bufLen = 0;

        GetIpNetTable(IntPtr.Zero, ref bufLen, false);
        if (bufLen <= 0) return ips;

        var buf = Marshal.AllocHGlobal(bufLen);
        try
        {
            if (GetIpNetTable(buf, ref bufLen, false) != 0) return ips;

            int rowCount = Marshal.ReadInt32(buf);
            IntPtr rowPtr = buf + 4;
            int rowSize = Marshal.SizeOf<MIB_IPNETROW>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_IPNETROW>(rowPtr);

                if (row.dwAddr != 0 && row.dwAddr != 0xFFFFFFFF)
                {
                    var ip = FormatIP(row.dwAddr);
                    var octets = ip.Split('.');
                    if (!ip.StartsWith("0.") && !ip.StartsWith("127.") &&
                        !ip.StartsWith("255.") && !ip.StartsWith("224.") &&
                        !ip.StartsWith("239.") &&
                        octets.Length == 4 && octets[3] != "0" && octets[3] != "255")
                    {
                        ips.Add(ip);
                    }
                }
                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }

        System.Diagnostics.Debug.WriteLine($"Legacy ARP found {ips.Count} IPs");
        return ips;
    }

    private static List<string> GetTcpConnections()
    {
        var ips = new List<string>();
        int bufLen = 0;

        GetExtendedTcpTable(IntPtr.Zero, ref bufLen, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufLen <= 0) return ips;

        var buf = Marshal.AllocHGlobal(bufLen);
        try
        {
            if (GetExtendedTcpTable(buf, ref bufLen, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return ips;

            int rowCount = Marshal.ReadInt32(buf);
            IntPtr rowPtr = buf + 4;
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                if (row.dwRemoteAddr != 0 && row.dwRemoteAddr != 0x7F000001)
                {
                    var remoteIP = FormatIP(row.dwRemoteAddr);
                    if (!remoteIP.StartsWith("0.") && !remoteIP.StartsWith("255."))
                        ips.Add(remoteIP);
                }
                rowPtr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(buf); }

        return ips;
    }

    private static List<string> GetUdpConnections()
    {
        var ips = new List<string>();
        int bufLen = 0;

        GetExtendedUdpTable(IntPtr.Zero, ref bufLen, true, 2, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
        if (bufLen <= 0) return ips;

        var buf = Marshal.AllocHGlobal(bufLen);
        try
        {
            if (GetExtendedUdpTable(buf, ref bufLen, true, 2, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0) != 0)
                return ips;

            int rowCount = Marshal.ReadInt32(buf);
            IntPtr rowPtr = buf + 4;
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                if (row.dwLocalAddr != 0 && row.dwLocalAddr != 0x7F000001)
                {
                    var localIP = FormatIP(row.dwLocalAddr);
                    if (!localIP.StartsWith("0.") && !localIP.StartsWith("255."))
                        ips.Add(localIP);
                }
                rowPtr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(buf); }

        return ips;
    }

    private static string FormatIP(uint ipAddr)
        => $"{ipAddr & 0xFF}.{(ipAddr >> 8) & 0xFF}.{(ipAddr >> 16) & 0xFF}.{(ipAddr >> 24) & 0xFF}";

    #endregion
}
