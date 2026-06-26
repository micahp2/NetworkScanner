using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace NetworkScanner.Core
{
    public static class NetworkScannerUtils
    {
        public static List<int> ParsePorts(string input)
        {
            var ports = new HashSet<int>();
            if (string.IsNullOrWhiteSpace(input)) return new();

            foreach (var item in input.Split(','))
            {
                var t = item.Trim();
                if (t.Contains('-'))
                {
                    var p = t.Split('-');
                    if (p.Length == 2 &&
                        int.TryParse(p[0].Trim(), out int s) &&
                        int.TryParse(p[1].Trim(), out int e))
                        for (int i = s; i <= e; i++)
                            if (i is >= 1 and <= 65535) ports.Add(i);
                }
                else if (int.TryParse(t, out int port) && port is >= 1 and <= 65535)
                    ports.Add(port);
            }
            return ports.OrderBy(p => p).ToList();
        }

        public static IEnumerable<string> ExpandRange(string range)
        {
            if (string.IsNullOrWhiteSpace(range)) return Array.Empty<string>();
            var results = new List<string>();
            try {
                if (range.Contains('/')) {
                    var parts = range.Split('/');
                    if (IPAddress.TryParse(parts[0], out var baseAddr) && int.TryParse(parts[1], out int prefix)) {
                        if (baseAddr.AddressFamily == AddressFamily.InterNetwork) {
                            uint b = IpToUint(baseAddr), m = prefix == 0 ? 0 : ~((1u << (32 - prefix)) - 1);
                            for (uint i = (b & m) + 1; i < ((b & m) | ~m); i++) results.Add(UintToIp(i));
                        }
                    }
                } else if (range.Contains('-')) {
                    var parts = range.Split('-');
                    if (IPAddress.TryParse(parts[0].Trim(), out var sAddr) && IPAddress.TryParse(parts[1].Trim(), out var eAddr)) {
                        uint s = IpToUint(sAddr), e = IpToUint(eAddr);
                        for (uint i = s; i <= e; i++) results.Add(UintToIp(i));
                    }
                } else if (IPAddress.TryParse(range, out _)) results.Add(range);
            } catch { }
            return results;
        }

        private static uint IpToUint(IPAddress addr) {
            var b = addr.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        private static string UintToIp(uint ip) => $"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}";

        public static void Shuffle<T>(IList<T> list)
        {
            int n = list.Count;
            while (n > 1)
            {
                n--;
                int k = Random.Shared.Next(n + 1);
                T value = list[k];
                list[k] = list[n];
                list[n] = value;
            }
        }

        private static int CompareBytes(byte[] a, byte[] b)
        {
            for (int i = 0; i < a.Length; i++)
            {
                int cmp = a[i].CompareTo(b[i]);
                if (cmp != 0) return cmp;
            }
            return 0;
        }

        public static bool IsIpInRanges(string ipStr, string ipRangesStr)
        {
            if (string.IsNullOrWhiteSpace(ipRangesStr)) return true;
            if (string.IsNullOrWhiteSpace(ipStr)) return false;

            if (!IPAddress.TryParse(ipStr, out var ip)) return false;

            var ranges = ipRangesStr.Split(new[] { ',', ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
                                    .Select(r => r.Trim())
                                    .Where(r => r.Length > 0);

            bool hasAnyValidRange = false;

            foreach (var range in ranges)
            {
                hasAnyValidRange = true;
                try
                {
                    if (range.Contains('/'))
                    {
                        var parts = range.Split('/');
                        if (parts.Length == 2 && 
                            IPAddress.TryParse(parts[0], out var baseAddr) && 
                            int.TryParse(parts[1], out int prefix))
                        {
                            if (ip.AddressFamily == baseAddr.AddressFamily)
                            {
                                if (ip.AddressFamily == AddressFamily.InterNetwork)
                                {
                                    uint ipVal = IpToUint(ip);
                                    uint baseVal = IpToUint(baseAddr);
                                    uint mask = prefix == 0 ? 0 : ~((1u << (32 - prefix)) - 1);
                                    if ((ipVal & mask) == (baseVal & mask)) return true;
                                }
                                else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                                {
                                    var ipBytes = ip.GetAddressBytes();
                                    var baseBytes = baseAddr.GetAddressBytes();
                                    int bytesToCheck = prefix / 8;
                                    int bitsToCheck = prefix % 8;
                                    bool match = true;
                                    for (int i = 0; i < bytesToCheck; i++)
                                    {
                                        if (ipBytes[i] != baseBytes[i]) { match = false; break; }
                                    }
                                    if (match && bitsToCheck > 0)
                                    {
                                        int mask = 0xFF << (8 - bitsToCheck);
                                        if ((ipBytes[bytesToCheck] & mask) != (baseBytes[bytesToCheck] & mask)) match = false;
                                    }
                                    if (match) return true;
                                }
                            }
                        }
                    }
                    else if (range.Contains('-'))
                    {
                        var parts = range.Split('-');
                        if (parts.Length == 2 && 
                            IPAddress.TryParse(parts[0].Trim(), out var sAddr) && 
                            IPAddress.TryParse(parts[1].Trim(), out var eAddr))
                        {
                            if (ip.AddressFamily == sAddr.AddressFamily)
                            {
                                if (ip.AddressFamily == AddressFamily.InterNetwork)
                                {
                                    uint ipVal = IpToUint(ip);
                                    uint sVal = IpToUint(sAddr);
                                    uint eVal = IpToUint(eAddr);
                                    if (sVal > eVal) (sVal, eVal) = (eVal, sVal);
                                    if (ipVal >= sVal && ipVal <= eVal) return true;
                                }
                                else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                                {
                                    var ipBytes = ip.GetAddressBytes();
                                    var sBytes = sAddr.GetAddressBytes();
                                    var eBytes = eAddr.GetAddressBytes();
                                    if (CompareBytes(sBytes, eBytes) > 0) (sBytes, eBytes) = (eBytes, sBytes);
                                    if (CompareBytes(ipBytes, sBytes) >= 0 && CompareBytes(ipBytes, eBytes) <= 0) return true;
                                }
                            }
                        }
                    }
                    else
                    {
                        if (IPAddress.TryParse(range, out var singleIp))
                        {
                            if (ip.Equals(singleIp)) return true;
                        }
                    }
                }
                catch
                {
                    // Ignore parsing
                }
            }

            return !hasAnyValidRange;
        }
    }

    public class IcmpPacket
    {
        public byte Type { get; set; }
        public byte Code { get; set; }
        public ushort Checksum { get; set; }
        public ushort Identifier { get; set; }
        public ushort Sequence { get; set; }
        public byte[] Data { get; set; } = Array.Empty<byte>();

        public byte[] Serialize()
        {
            var buffer = new byte[8 + Data.Length];
            buffer[0] = Type;
            buffer[1] = Code;
            buffer[2] = 0; // Checksum placeholder
            buffer[3] = 0; // Checksum placeholder
            
            var idBytes = BitConverter.GetBytes(Identifier);
            buffer[4] = idBytes[0];
            buffer[5] = idBytes[1];
            
            var seqBytes = BitConverter.GetBytes(Sequence);
            buffer[6] = seqBytes[0];
            buffer[7] = seqBytes[1];
            
            if (Data.Length > 0)
            {
                Buffer.BlockCopy(Data, 0, buffer, 8, Data.Length);
            }
            
            ushort checksum = ComputeChecksum(buffer);
            var checksumBytes = BitConverter.GetBytes(checksum);
            buffer[2] = checksumBytes[0];
            buffer[3] = checksumBytes[1];
            
            return buffer;
        }

        public static ushort ComputeChecksum(byte[] buffer)
        {
            int length = buffer.Length;
            uint sum = 0;
            int i = 0;

            while (length > 1)
            {
                sum += (uint)BitConverter.ToUInt16(buffer, i);
                i += 2;
                length -= 2;
            }

            if (length > 0)
            {
                sum += buffer[i];
            }

            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xffff) + (sum >> 16);
            }

            return (ushort)(~sum);
        }
    }
}
