import re, pathlib, sys

root = pathlib.Path(r'''C:\Users\Micah\OneDrive\Documents\GitHub\NetworkScanner''')
path = root / 'services' / 'NetworkScannerService.cs'
s = path.read_text(encoding='utf-8', errors='ignore')
orig = s

def sub(label, pattern, repl, flags=re.M|re.S, required=True):
    global s
    ns, n = re.subn(pattern, repl, s, flags=flags)
    if required and n == 0:
        raise RuntimeError(f'patch failed: {label}')
    s = ns
    return n

# 1) helper fields/methods
if 'NormalizeMacOrNull' not in s:
    sub('add normalize helper',
        r'(private static readonly SemaphoreSlim _vendorRateLimit = new SemaphoreSlim\(1, 1\);\r?\n)',
        r"\1    private static readonly System.Text.RegularExpressions.Regex _macRegex =\n        new(@"^([0-9A-F]{2}-){5}[0-9A-F]{2}$", System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.IgnoreCase);\n\n    private static string? NormalizeMacOrNull(string? mac)\n    {\n        if (string.IsNullOrWhiteSpace(mac)) return null;\n        var normalized = mac.Trim().Replace(':', '-').ToUpperInvariant();\n        if (!_macRegex.IsMatch(normalized)) return null;\n        if (normalized == "00-00-00-00-00-00") return null;\n        return normalized;\n    }\n\n")

# 2) StartScan target status + BuildCandidateList out params
sub('startscan build candidate call',
    r'StatusChanged\?\.Invoke\(this, "Building scan list\.\.\."\);\r?\n\s*var candidates = BuildCandidateList\(options\);',
    'StatusChanged?.Invoke(this, "Building scan list...");\n            var candidates = BuildCandidateList(options, out var explicitCount, out var augmentedCount, out var usedAugmentation);\n\n            if (usedAugmentation)\n                StatusChanged?.Invoke(this, $"Scan targets: explicit {explicitCount} + discovered {augmentedCount} = {candidates.Count}");\n            else\n                StatusChanged?.Invoke(this, $"Scan targets: explicit {explicitCount} (no connection-table augmentation)");')

# 3) passive host merge after combined cache
if 'MergePassiveHostsFromMacCache' not in s:
    sub('insert passive merge',
        r'(System\.Diagnostics\.Debug\.WriteLine\(\$"Combined MAC cache: \{macCache\.Count\} entries"\);\r?\n)',
        r"\1\n                // Include passive hosts discovered in local ARP/NDP cache that may block ICMP/TCP probes.\n                var passiveAdded = MergePassiveHostsFromMacCache(candidates, liveHosts, macCache);\n                if (passiveAdded > 0)\n                    StatusChanged?.Invoke(this, $"Added {passiveAdded} passive host(s) from ARP/NDP cache");\n")

# 4) Replace BuildCandidateList method completely
sub('replace BuildCandidateList',
    r'private HashSet<string> BuildCandidateList\(ScanOptions options\)\s*\{.*?\n\s*\}\n\n\s*private static IEnumerable<string> ExpandRange\(string range\)',
    '''private HashSet<string> BuildCandidateList(ScanOptions options, out int explicitCount, out int augmentedCount, out bool usedAugmentation)
    {
        var explicitCandidates = new HashSet<string>(StringComparer.Ordinal);
        foreach (var range in options.IPRanges)
            foreach (var ip in ExpandRange(range))
                explicitCandidates.Add(ip);

        explicitCount = explicitCandidates.Count;
        var candidates = new HashSet<string>(explicitCandidates, StringComparer.Ordinal);

        augmentedCount = 0;
        usedAugmentation = false;

        // Only augment from OS connection tables for CIDR inputs.
        // Explicit single-host and dash-range scans should remain bounded to user input.
        bool hasCidrInput = options.IPRanges.Any(r => (r ?? string.Empty).Trim().Contains('/'));

        if (hasCidrInput)
        {
            usedAugmentation = true;
            var subnet = ExtractSubnetFromRange(options.IPRanges.FirstOrDefault());
            foreach (var ip in IPHelperAPI.DiscoverDevicesFromConnectionTable(subnet))
            {
                if (candidates.Add(ip))
                    augmentedCount++;
            }
        }

        System.Diagnostics.Debug.WriteLine($"Candidate list: total={candidates.Count}, explicit={explicitCount}, augmented={augmentedCount}, usedAug={usedAugmentation}");
        return candidates;
    }

    private static int MergePassiveHostsFromMacCache(HashSet<string> candidates, List<string> liveHosts, Dictionary<string, string> macCache)
    {
        var liveSet = new HashSet<string>(liveHosts, StringComparer.Ordinal);
        int added = 0;

        foreach (var ip in candidates)
        {
            if (ip.Contains(':')) continue;
            if (liveSet.Contains(ip)) continue;
            if (!IsDirectlyReachableIpv4(ip)) continue;

            if (macCache.TryGetValue(ip, out var mac) && NormalizeMacOrNull(mac) != null)
            {
                liveHosts.Add(ip);
                liveSet.Add(ip);
                added++;
            }
        }

        return added;
    }

    private static IEnumerable<string> ExpandRange(string range)''')

# 5) Replace /24 helper with mask-aware helper
sub('replace local subnet helper',
    r'// Cached set of local /24 subnet prefixes .*?private async Task EnrichAndReportAsync\(',
    '''// Determines whether an IPv4 target is directly reachable on a local NIC subnet
    // using each interface's actual subnet mask (not a fixed /24 assumption).
    private static bool IsDirectlyReachableIpv4(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var target) || target.AddressFamily != AddressFamily.InterNetwork)
            return false;

        uint targetInt = IpToUint(target);

        try
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;

                foreach (var uni in nic.GetIPProperties().UnicastAddresses)
                {
                    if (uni.Address.AddressFamily != AddressFamily.InterNetwork) continue;

                    var localIp = uni.Address;
                    var mask = uni.IPv4Mask;
                    if (mask == null || mask.AddressFamily != AddressFamily.InterNetwork)
                        mask = IPAddress.Parse("255.255.255.0");

                    uint localInt = IpToUint(localIp);
                    uint maskInt = IpToUint(mask);

                    if ((targetInt & maskInt) == (localInt & maskInt))
                        return true;
                }
            }
        }
        catch { }

        return false;
    }

    private async Task EnrichAndReportAsync(''')

# 6) Switch enrichment local check to helper
sub('replace enrichment local check',
    r'var ipPrefix = string\.Join\("\.", capturedIp\.Split\(\'\.\'\)\.Take\(3\)\);\r?\n\s*bool isLocal = localPrefixes\.Contains\(ipPrefix\);',
    'bool isLocal = IsDirectlyReachableIpv4(capturedIp);')

# remove now-stale localPrefixes declaration if still present
s = re.sub(r'\s*var localPrefixes = GetLocalSubnetPrefixes\(\);\r?\n', '\n', s, flags=re.M)

# 7) Replace ResolveMACForHost with hardened version
sub('replace ResolveMACForHost',
    r'private static string\? ResolveMACForHost\(string ipv4, Dictionary<string, string> macCache\)\s*\{.*?\n\s*\}\n\n\s*private async Task<bool> PingHostAsync\(',
    '''private static string? ResolveMACForHost(string ipv4, Dictionary<string, string> macCache)
    {
        if (macCache.TryGetValue(ipv4, out var mac))
        {
            var normalized = NormalizeMacOrNull(mac);
            if (normalized != null)
            {
                System.Diagnostics.Debug.WriteLine($"Cache hit (IPv4): {ipv4} -> {normalized}");
                return normalized;
            }
        }

        var probed = NormalizeMacOrNull(IPHelperAPI.ProbeViaSendARP(ipv4));
        if (probed != null)
        {
            System.Diagnostics.Debug.WriteLine($"SendARP hit: {ipv4} -> {probed}");
            return probed;
        }

        var postProbe = NormalizeMacOrNull(IPHelperAPI.GetMACFromCacheOnly(ipv4));
        if (postProbe != null)
        {
            System.Diagnostics.Debug.WriteLine($"Cache hit (post-SendARP): {ipv4} -> {postProbe}");
            return postProbe;
        }

        var legacy = NormalizeMacOrNull(IPHelperAPI.GetMACAddress(ipv4));
        if (legacy != null)
        {
            System.Diagnostics.Debug.WriteLine($"Legacy MAC helper hit: {ipv4} -> {legacy}");
            return legacy;
        }

        System.Diagnostics.Debug.WriteLine($"No MAC found: {ipv4}");
        return null;
    }

    private async Task<bool> PingHostAsync(''')

if s != orig:
    path.write_text(s, encoding='utf-8', newline='\r\n')

print('patched=' + str(s != orig))
