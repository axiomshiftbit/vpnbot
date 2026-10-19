from pathlib import Path
import subprocess,time,json,re
base=Path(__file__).parent
cases=['wireguard','wireguard_extra','openvpn','openvpn_extra','ikev2','l2tp','openconnect','adguard','shadowsocks','proxies','trusttunnel_native','xdrive_native','dat_routes','routes_cores','exit_nodes','reality_fingerprints','naive_native','dnstt','dnstt_identity','hysteria_extra','warp_network','telemt','telemt_web','panel','ssh_host_keys']
rows=[]
for name in cases:
 start=time.monotonic()
 print('START '+name,flush=True)
 try:
  with (base/(name+'.log')).open('w') as out:
   p=subprocess.run(['python3',str(base/(name+'.py'))],stdout=out,stderr=subprocess.STDOUT,timeout=1200)
  row={'case':name,'exit':p.returncode,'seconds':round(time.monotonic()-start,1)}
 except subprocess.TimeoutExpired:row={'case':name,'exit':'timeout','seconds':1200}
 s=(base/(name+'.log')).read_text()
 for line in s.splitlines()[::-1]:
  try:
   v=json.loads(line)
   if isinstance(v,dict) and 'passed' in v and 'total' in v:row.update({k:v[k] for k in ['passed','total']});break
  except ValueError:pass
 rows.append(row);(base/'results.json').write_text(json.dumps(rows,indent=2))
 print(json.dumps(row),flush=True)
print('POSTRESTORE NATIVE COMPLETE',flush=True)
raise SystemExit(1 if any(r['exit'] for r in rows) else 0)
