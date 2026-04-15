import json, pathlib

root = pathlib.Path(r'''C:\Users\Micah\OneDrive\Documents\GitHub\NetworkScanner''')
files = {
  'svc': root / 'services/NetworkScannerService.cs',
  'ui': root / 'MainWindow.xaml.cs',
  'ip': root / 'services/IPHelperAPI.cs',
}
patterns = {
  'svc': ['BuildCandidateList','ParseIpRange','ParseIpTargets','StartScanAsync','ScanIPAsync','GetIPsFromConnectionTable','macCache','Vendor','SendARP','GetMacAddress'],
  'ui': ['ParseIpRanges','ParsePorts','StartScanButton_Click','IpRangeText','PortsText','AddResultToGrid'],
  'ip': ['GetIpNetTable2','GetIpNetTable','SendARP','GetAllNeighborIPs','GetMacAddressForIP','GetIPv6NeighborTable'],
}
out = {}
for k,p in files.items():
    s = p.read_text(encoding='utf-8', errors='ignore')
    lines = s.splitlines()
    matches=[]
    for pat in patterns[k]:
        for i,ln in enumerate(lines, start=1):
            if pat in ln:
                a=max(1,i-8); b=min(len(lines),i+28)
                snippet='\n'.join(f'{j:4}: {lines[j-1]}' for j in range(a,b+1))
                matches.append({'pat':pat,'line':i,'snippet':snippet})
    # dedupe by line
    seen=set(); ded=[]
    for m in sorted(matches, key=lambda x:x['line']):
        if m['line'] in seen: continue
        seen.add(m['line']); ded.append(m)
    out[k] = {'path': str(p), 'line_count': len(lines), 'matches': ded[:200]}

print(json.dumps(out))
