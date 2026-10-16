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
# Настоящий код бота в php-audit: правило «ядро требует ML-KEM» и поле requireMlkem.
PHP='''require '/app/bot.php';$in=json_decode($argv[1],true);
$b=new class extends Bot{public array $probe=[];public array $conf=[];public function __construct(){}
public function xrayCoreProbe(bool $fresh=false):array{return $this->probe;}public function getPacConf(){return $this->conf;}};
$b->probe=$in['probe']??[];$b->conf=$in['pac'];
if(isset($in['reality'])){$rs=$in['reality'];$b->ensureRealityRequireMlkem($rs,$in['pac']);echo json_encode($rs);}
else echo json_encode($b->realityRequiresMlkem());'''
def bot(data):
 r=run('docker','exec','php-audit','php','-r',PHP,'--',json.dumps(data));r.check_returncode();return json.loads(r.stdout)
def probe(path,version,slot):
 # Те же признаки, что берёт проба бота (Bot::xrayCoreProbe) из бинарника.
 data=path.read_bytes();m=re.search(rb'github\.com/xtls/reality\s+(v[0-9A-Za-z.+_-]+)',data)
 return {'ok':True,'running':'','active':'fork' if slot=='fork' else 'origin','version':version,
  'reality':m.group(1).decode() if m else '','reality_local':re.search(rb'=>\s+\./third_party/reality\s',data) is not None}
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
  # У ios нет X25519MLKEM768: сервер принимает его ровно тогда, когда ML-KEM не требует.
  # Бот обязан решать так же — от этого зависят предупреждения и подписки sing-box.
  version=report.get(binary,{}).get('version','')
  requires=bot({'probe':probe(work/binary,version,slot),'pac':{'transport':'Reality','xray_core':'fork' if slot=='fork' else 'origin'}})
  check('%s-bot-mlkem-rule-matches-core'%slot,requires==(accepted.get('ios') is False))
  # Новые образцы uTLS с ML-KEM: не отказ, а повод пополнить REALITY_FINGERPRINTS
  # (тогда бот перестанет предупреждать о них). random проходит через раз.
  newer=sorted(fp for fp,ok in accepted.items() if ok and requires and fp not in required and not fp.startswith('random'))
  if newer:print('NOTICE %s (ML-KEM) принимает и %s — проверьте REALITY_FINGERPRINTS'%(slot,', '.join(newer)),flush=True)
 # Форк 26.10.13+: requireMlkem, выставленный кодом бота, — сервер ведёт себя как апстрим.
 minimum=re.search(r"REALITY_REQUIRE_MLKEM_FORK_MIN\s*=\s*'([0-9.]+)'",source).group(1)
 forkv=re.search(r'Xray\s+v?([0-9.]+)',report.get(CORES['fork'],{}).get('version',''))
 # Без отчёта ядер (отказ уже записан выше) второй проход не имеет смысла.
 if forkv and [int(x) for x in forkv.group(1).split('.')]>=[int(x) for x in minimum.split('.')]:
  pac={'transport':'Reality','xray_core':'fork','reality':{'requireMlkem':1}}
  extra=bot({'pac':pac,'reality':{}});(work/'extra.json').write_text(json.dumps(extra));(work/'extra.json').chmod(0o644)
  check('fork-bot-sets-requireMlkem',extra=={'requireMlkem':True})
  r=run('docker','run','--rm','--name',NAME,'--network','none','--entrypoint','python3','-v',str(work)+':/cores:ro','-v',str(ROOT/'reality-cores')+':/lab:ro',image,
   '/lab/check.py','/cores/cert.pem','/cores/key.pem','--server-extra','/cores/extra.json','/cores/'+CORES['fork'],'--',*offered,timeout=900)
  (O/'output-require-mlkem.log').write_text(r.stdout+r.stderr)
  strict=(json.loads(r.stdout.strip().splitlines()[-1]) if r.returncode==0 and r.stdout.strip() else {}).get(CORES['fork'],{}).get('accepted',{})
  (O/'accepted-require-mlkem.json').write_text(json.dumps(strict,indent=2))
  for fingerprint in required:check('fork-requireMlkem-accepts-%s'%fingerprint,strict.get(fingerprint) is True)
  for fingerprint in ('ios','edge','qq'):check('fork-requireMlkem-rejects-%s'%fingerprint,strict.get(fingerprint) is False)
  probe_fork=probe(work/CORES['fork'],report[CORES['fork']]['version'],'fork')
  check('fork-requireMlkem-bot-rule',bot({'probe':probe_fork,'pac':pac}) is True)
finally:
 run('docker','rm','-f',NAME)
 shutil.rmtree(work,ignore_errors=True)
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
