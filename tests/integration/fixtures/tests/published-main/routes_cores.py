#!/usr/bin/env python3
"""Списки routes на настоящих ядрах из проверяемых образов: xray, sing-box и
Mihomo. Бот собирает профили из своих шаблонов, списки отдаются ядрам по HTTP
так же, как их отдаёт бот, маршрут каждой записи проверяется запросом через
ядро; отдельно — серверные правила block/WARP. Всё идёт в одноразовом
контейнере без сети, установка стенда не затрагивается."""
import json,os,pathlib,re,shutil,subprocess
os.umask(0o077);ROOT=pathlib.Path('/opt/vpnbot-hosted-ci');R=ROOT/'stand';O=R/'results/routes-cores';O.mkdir(mode=0o700,exist_ok=True);results=[]
NAME='vpnbot-ci-retain-routes'
def run(*a,timeout=60):return subprocess.run(list(map(str,a)),capture_output=True,text=True,timeout=timeout)
def check(n,v):results.append({'name':n,'passed':bool(v)});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
work=O/'work'
try:
 shutil.rmtree(work,ignore_errors=True);work.mkdir(mode=0o700)
 # Ядро Xray — из работающего контейнера стенда; sing-box и Mihomo есть в образе php.
 run('docker','cp','-L','xray-audit:/usr/bin/xray',O/'xray').check_returncode();(O/'xray').chmod(0o755)
 image=run('docker','inspect','--format','{{.Image}}','php-audit').stdout.strip()
 check('images-and-core-available',bool(image) and (O/'xray').stat().st_size>1000000)
 run('docker','rm','-f',NAME)
 r=run('docker','run','--rm','--name',NAME,'--network','none','--entrypoint','php',
  '-v',str(R/'bot')+':/src:ro','-v',str(work)+':/work','-v',str(O/'xray')+':/xray:ro','-v',str(ROOT/'routes-cores')+':/lab:ro',image,'/lab/routes.php',timeout=900)
 (O/'output.log').write_text(r.stdout+r.stderr)
 lines=[l for l in r.stdout.splitlines() if l.startswith(('PASS ','FAIL '))]
 # Названия проверок в журнале — латиницей по порядку: подробности в output.log.
 for index,line in enumerate(lines,1):check('check-%02d'%index,line.startswith('PASS '))
 total=re.search(r'все (\d+) проверок прошли',r.stdout)
 check('all-checks-ran',r.returncode==0 and total is not None and int(total.group(1))==len(lines) and len(lines)>=30)
 check('no-php-warnings',not re.search(r'(?:PHP )?(?:Warning|Deprecated|Fatal error):',r.stdout+r.stderr))
finally:
 run('docker','rm','-f',NAME)
 shutil.rmtree(work,ignore_errors=True);(O/'xray').unlink(missing_ok=True)
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
