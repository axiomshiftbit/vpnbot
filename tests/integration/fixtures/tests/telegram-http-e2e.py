from pathlib import Path
import subprocess,json,time

r=Path('/opt/vpnbot-hosted-ci/tests')
b=Path('/opt/vpnbot-hosted-ci/stand/bot')
api=b.parent/'fixture/state/methods.log'
checks=[]
def check(name,ok):
    checks.append({'name':name,'ok':bool(ok)})
    (r/'published/telegram-http-results.json').write_text(json.dumps(checks,indent=2))
    print(('PASS ' if ok else 'FAIL ')+name,flush=True)
    if not ok:raise RuntimeError(name)

def log_size(path):
    return path.stat().st_size if path.exists() else 0

errors=b/'logs/php_error';before=log_size(errors)
request_errors=b/'logs/requests_error';request_before=log_size(request_errors)
commands=['/menu','/menu config','/telemt','/telemtWeb','/telemtWebHttp method','/telemtWebHttp conveyor','/menuhelp telemt_method 0','/menuhelp telemt_conveyor 0','/logs','/export']
for command in commands:
    offset=api.stat().st_size
    p=subprocess.run(['docker','exec','php-audit','php','/tmp/telegram-http-e2e.php',command],capture_output=True,text=True,timeout=100)
    response=json.loads(p.stdout)
    methods=[line.split()[1] for line in api.read_text()[offset:].splitlines() if len(line.split())==3]
    check(command+' HTTP/FreeUnit',p.returncode==0 and response['http']==200 and response['curl']==0 and not response['php_error_in_response'])
    check(command+' HTTPS Bot API response',('sendDocument' in methods and 'pinChatMessage' in methods) if command=='/export' else bool(set(methods)&{'sendMessage','editMessageText'}))
    check(command+' callback acknowledged','answerCallbackQuery' in methods)
offset=api.stat().st_size
p=subprocess.run(['docker','exec','php-audit','php','/tmp/telegram-http-e2e.php','/menu config','unauthorized'],capture_output=True,text=True,timeout=30)
methods=[line.split()[1] for line in api.read_text()[offset:].splitlines() if len(line.split())==3]
check('unauthorized sender cannot render settings',p.returncode==0 and not set(methods)&{'sendMessage','editMessageText','sendDocument'})
new_errors=''
if errors.exists():
    with errors.open() as f:f.seek(before);new_errors=f.read()
check('HTTP handlers have no PHP warnings/fatal/deprecated',not any(x in new_errors for x in ['Warning','Fatal','Deprecated','Exception']))
check('real polling and callbacks have no new API transport errors',log_size(request_errors)==request_before)
print(json.dumps({'passed':sum(x['ok'] for x in checks),'total':len(checks)}))
