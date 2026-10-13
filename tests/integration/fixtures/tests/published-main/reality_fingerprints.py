#!/usr/bin/env python3
"""Отпечатки REALITY на всех ядрах образа xr: основном, двух запасных слотах и
форке. Бот отдаёт в ссылки и подписки только Bot::REALITY_FINGERPRINTS — здесь
каждый из них проходит настоящее рукопожатие с сервером каждого ядра. С
Xray 26.9.8 сервер отвергает ClientHello без X25519MLKEM768, и клиент с
«не тем» отпечатком молча получает сайт-маску: такое изменение в очередном
обновлении ядра должно всплыть в сборке, а не у пользователей. Проверка идёт в
одноразовом контейнере без сети."""
import json,os,pathlib,re,shutil,subprocess
os.umask(0o077);ROOT=pathlib.Path('/opt/vpnbot-hosted-ci');R=ROOT/'stand';O=R/'results/reality-fingerprints';O.mkdir(mode=0o700,exist_ok=True);results=[]
NAME='vpnbot-ci-retain-reality';CORES={'main':'xray','slot2':'xray-2','slot3':'xray-3','fork':'xray-smux'}
def run(*a,timeout=60):return subprocess.run(list(map(str,a)),capture_output=True,text=True,timeout=timeout)
def check(n,v):results.append({'name':n,'passed':bool(v)});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
work=O/'work'
try:
 shutil.rmtree(work,ignore_errors=True);work.mkdir(mode=0o755);work.chmod(0o755)
 source=(R/'bot/app/bot.php').read_text()
 required=re.findall(r"'([a-z0-9]+)'",re.search(r'REALITY_FINGERPRINTS\s*=\s*\[([^\]]+)\]',source).group(1))
 offered=re.findall(r"'([a-z0-9]+)'",re.search(r'function fingerprints\(\)\s*\{\s*return \[([^\]]+)\]',source).group(1))
 check('bot-fingerprint-lists-read',len(required)>=1 and set(required)<=set(offered) and len(offered)>=8)
 for binary in CORES.values():
  run('docker','cp','-L','xray-audit:/usr/bin/'+binary,work/binary).check_returncode();(work/binary).chmod(0o755)
 run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout',work/'key.pem','-out',work/'cert.pem','-subj','/CN=mask.example.test').check_returncode()
 for name in ('key.pem','cert.pem'):(work/name).chmod(0o644)
 image=run('docker','inspect','--format','{{.Image}}','php-audit').stdout.strip()
 run('docker','rm','-f',NAME)
 r=run('docker','run','--rm','--name',NAME,'--network','none','--entrypoint','python3','-v',str(work)+':/cores:ro','-v',str(ROOT/'reality-cores')+':/lab:ro',image,
  '/lab/check.py','/cores/cert.pem','/cores/key.pem',*['/cores/'+b for b in CORES.values()],'--',*offered,timeout=900)
 (O/'output.log').write_text(r.stdout+r.stderr)
 report=json.loads(r.stdout.strip().splitlines()[-1]) if r.returncode==0 and r.stdout.strip() else {}
 (O/'accepted.json').write_text(json.dumps(report,indent=2))
 check('all-four-cores-checked',set(report)==set(CORES.values()) and all('accepted' in v for v in report.values()))
 for slot,binary in CORES.items():
  accepted=report.get(binary,{}).get('accepted',{})
  for fingerprint in required:check('%s-accepts-%s'%(slot,fingerprint),accepted.get(fingerprint) is True)
  # Клиент без TLS 1.3 сервером REALITY не принимается никогда: признак того, что проверка различает отказ.
  check('%s-rejects-android'%slot,accepted.get('android') is False)
finally:
 run('docker','rm','-f',NAME)
 shutil.rmtree(work,ignore_errors=True)
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
