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

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SendARP(uint DestIP, uint SrcIP, IntPtr pMacAddr, ref uint PhyAddrLen);

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern uint inet_addr(string cp);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetIpNetTable(IntPtr pIpNetTable, ref int dwOutBufLen, bool sort);

    private enum TCP_TABLE_CLASS { TCP_TABLE_OWNER_PID_ALL = 5 }
    private enum UDP_TABLE_CLASS { UDP_TABLE_OWNER_PID = 1 }

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

    #endregion

    /// <summary>
    /// Discovers devices by querying the Windows ARP table, TCP connection table, and UDP connection table.
    /// The TCP/UDP tables capture devices that have communicated with this machine,
    /// which helps populate more MAC addresses than ARP alone.
    /// </summary>
    public static HashSet<string> DiscoverDevicesFromConnectionTable(string? customSubnet = null)
    {
        var devices = new HashSet<string>();

        // First, detect the local subnet
        var localSubnet = customSubnet ?? GetLocalSubnet();
        if (string.IsNullOrEmpty(localSubnet))
        {
            System.Diagnostics.Debug.WriteLine("Could not detect local subnet");
            return devices;
        }

        System.Diagnostics.Debug.WriteLine($"Local subnet detected: {localSubnet}");

        try
        {
            // Get gateway first (always add it)
            var gateway = GetDefaultGateway();
            if (!string.IsNullOrEmpty(gateway) && IsInLocalSubnet(gateway, localSubnet))
            {
                devices.Add(gateway);
                System.Diagnostics.Debug.WriteLine($"Added gateway: {gateway}");
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error getting gateway: {ex.Message}");
        }

        try
        {
            // Get ARP table entries (has MAC addresses)
            var arpIPs = GetArpTableEntries();
            System.Diagnostics.Debug.WriteLine($"ARP table returned {arpIPs.Count} IPs");
            
            int added = 0;
            foreach (var ip in arpIPs)
            {
                if (IsInLocalSubnet(ip, localSubnet))
                {
                    if (devices.Add(ip))
                        added++;
                }
            }
            System.Diagnostics.Debug.WriteLine($"ARP added {added} local IPs");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error getting ARP table: {ex.Message}");
        }

        try
        {
            // Get TCP connections (may have different devices than ARP)
            var tcpIPs = GetTcpConnections();
            int tcpAdded = 0;
            foreach (var ip in tcpIPs)
            {
                if (IsInLocalSubnet(ip, localSubnet) && devices.Add(ip))
                    tcpAdded++;
            }
            System.Diagnostics.Debug.WriteLine($"TCP added {tcpAdded} new local IPs");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error getting TCP connections: {ex.Message}");
        }

        try
        {
            // Get UDP connections (may have different devices than ARP/TCP)
            var udpIPs = GetUdpConnections();
            int udpAdded = 0;
            foreach (var ip in udpIPs)
            {
                if (IsInLocalSubnet(ip, localSubnet) && devices.Add(ip))
                    udpAdded++;
            }
            System.Diagnostics.Debug.WriteLine($"UDP added {udpAdded} new local IPs");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error getting UDP connections: {ex.Message}");
        }

        System.Diagnostics.Debug.WriteLine($"Total IPs to test: {devices.Count}");
        return devices;
    }

    private static string GetLocalSubnet()
    {
        try
        {
            // Get local IP address
            var hostName = System.Net.Dns.GetHostName();
            var hostEntry = System.Net.Dns.GetHostEntry(hostName);
            
            foreach (var address in hostEntry.AddressList)
            {
                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    // Return first three octets (e.g., "192.168.2")
                    var parts = address.ToString().Split('.');
                    if (parts.Length == 4)
                    {
                        System.Diagnostics.Debug.WriteLine($"Local IP detected: {address}");
                        return $"{parts[0]}.{parts[1]}.{parts[2]}";
                    }
                }
            }
        }
        catch
        {
        }

        return null;
    }

    private static string? GetDefaultGateway()
    {
        try
        {
            var nics = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
            foreach (var ni in nics)
            {
                if (ni.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Ethernet &&
                    ni.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211)
                    continue;

                var ipProps = ni.GetIPProperties();
                var gateways = ipProps.GatewayAddresses;
                
                foreach (var gateway in gateways)
                {
                    if (gateway.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        System.Diagnostics.Debug.WriteLine($"Default gateway found: {gateway.Address}");
                        return gateway.Address.ToString();
                    }
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error getting default gateway: {ex.Message}");
        }

        return null;
    }

    private static bool IsInLocalSubnet(string ipAddress, string localSubnet)
    {
        if (string.IsNullOrEmpty(localSubnet))
            return false;

        // Exact match with subnet prefix
        if (ipAddress.StartsWith(localSubnet + "."))
            return true;

        return false;
    }

    private static List<string> GetTcpConnections()
    {
        var ips = new List<string>();
        int bufLen = 0;

        GetExtendedTcpTable(IntPtr.Zero, ref bufLen, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

        var buf = Marshal.AllocHGlobal(bufLen);
        try
        {
            if (GetExtendedTcpTable(buf, ref bufLen, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return ips;

            int rowCount = Marshal.ReadInt32(buf);
            var rowPtr = buf + 4;
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                
                // Get remote IP from established connections
                if (row.dwRemoteAddr != 0 && row.dwRemoteAddr != 0x7F000001)
                {
                    var remoteIP = FormatIP(row.dwRemoteAddr);
                    if (!remoteIP.StartsWith("0.") && !remoteIP.StartsWith("255."))
                        ips.Add(remoteIP);
                }

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }

        return ips;
    }

    private static List<string> GetUdpConnections()
    {
        var ips = new List<string>();
        int bufLen = 0;

        GetExtendedUdpTable(IntPtr.Zero, ref bufLen, true, 2, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);

        var buf = Marshal.AllocHGlobal(bufLen);
        try
        {
            if (GetExtendedUdpTable(buf, ref bufLen, true, 2, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0) != 0)
                return ips;

            int rowCount = Marshal.ReadInt32(buf);
            var rowPtr = buf + 4;
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                
                // Get local IPs (devices listening on local network)
                if (row.dwLocalAddr != 0 && row.dwLocalAddr != 0x7F000001)
                {
                    var localIP = FormatIP(row.dwLocalAddr);
                    if (!localIP.StartsWith("0.") && !localIP.StartsWith("255."))
                        ips.Add(localIP);
                }

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }

        return ips;
    }

    private static List<string> GetArpTableEntries()
    {
        var ips = new List<string>();
        int bufLen = 0;

        GetIpNetTable(IntPtr.Zero, ref bufLen, false);

        var buf = Marshal.AllocHGlobal(bufLen);
        try
        {
            if (GetIpNetTable(buf, ref bufLen, false) != 0)
                return ips;

            int rowCount = Marshal.ReadInt32(buf);
            var rowPtr = buf + 4;
            int rowSize = Marshal.SizeOf<MIB_IPNETROW>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_IPNETROW>(rowPtr);
                
                if (row.dwAddr != 0 && row.dwAddr != 0xFFFFFFFF)
                {
                    var ip = FormatIP(row.dwAddr);
                    var octets = ip.Split('.');
                    
                    // Filter out:
                    // - Loopback (127.x.x.x)
                    // - Reserved (0.x.x.x, 255.x.x.x)
                    // - Multicast (224.x.x.x, 239.x.x.x)
                    // - Network addresses (.0)
                    // - Broadcast addresses (.255)
                    if (!ip.StartsWith("0.") && 
                        !ip.StartsWith("127.") &&
                        !ip.StartsWith("255.") &&
                        !ip.StartsWith("224.") &&
                        !ip.StartsWith("239.") &&
                        octets.Length == 4 &&
                        octets[3] != "0" &&    // Exclude .0
                        octets[3] != "255")    // Exclude .255
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

        System.Diagnostics.Debug.WriteLine($"GetArpTableEntries found {ips.Count} usable IPs");
        return ips;
    }

    private static string FormatIP(uint ipAddr)
    {
        return $"{(ipAddr & 0xFF)}.{((ipAddr >> 8) & 0xFF)}.{((ipAddr >> 16) & 0xFF)}.{((ipAddr >> 24) & 0xFF)}";
    }

    /// <summary>
    /// Probe a device via ARP to ensure it's in the ARP cache, then look it up.
    /// This forces Windows to send an ARP request and populate the table.
    /// </summary>
    public static string? ProbeAndGetMACAddress(string ipAddress)
    {
        try
        {
            // First try direct lookup
            var mac = GetMACAddressFromArpTable(ipAddress);
            if (!string.IsNullOrEmpty(mac))
                return mac;

            // If not found, probe via ARP
            if (uint.TryParse(ipAddress.Replace(".", ""), out _))
            {
                uint destIP = inet_addr(ipAddress);
                if (destIP != uint.MaxValue)
                {
                    uint srcIP = 0;
                    uint macLen = 6;
                    IntPtr macPtr = Marshal.AllocHGlobal((int)macLen);
                    try
                    {
                        // Send ARP request
                        SendARP(destIP, srcIP, macPtr, ref macLen);
                        
                        // Now try to look it up again
                        System.Threading.Thread.Sleep(50); // Give ARP cache time to update
                        return GetMACAddressFromArpTable(ipAddress);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(macPtr);
                    }
                }
            }
        }
        catch
        {
        }

        return null;
    }

    /// <summary>
    /// Probe a device via ARP to ensure it's in the ARP cache, then look it up.
    /// This forces Windows to send an ARP request and populate the table.
    /// </summary>
    /// <summary>
    /// Look up MAC address for a given IP from the ARP table.
    /// More reliable than running arp.exe command.
    /// </summary>
    public static string? GetMACAddressFromArpTable(string ipAddress)
    {
        try
        {
            if (!System.Net.IPAddress.TryParse(ipAddress, out var addr))
                return null;

            int bufLen = 0;
            GetIpNetTable(IntPtr.Zero, ref bufLen, false);

            var buf = Marshal.AllocHGlobal(bufLen);
            try
            {
                if (GetIpNetTable(buf, ref bufLen, false) != 0)
                    return null;

                int rowCount = Marshal.ReadInt32(buf);
                var rowPtr = buf + 4;
                int rowSize = Marshal.SizeOf<MIB_IPNETROW>();

                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_IPNETROW>(rowPtr);
                    
                    if (FormatIP(row.dwAddr) == ipAddress && row.dwPhysAddrLen == 6)
                    {
                        // MAC address is 6 bytes
                        var mac = row.bPhysAddr.Take(6)
                            .Select(b => b.ToString("X2"))
                            .Aggregate((a, b) => $"{a}-{b}");
                        
                        // Filter out all-zeros (incomplete entries)
                        if (mac != "00-00-00-00-00-00")
                            return mac;
                    }

                    rowPtr += rowSize;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch
        {
        }

        return null;
    }
}
