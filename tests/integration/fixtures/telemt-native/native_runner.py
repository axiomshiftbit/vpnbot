from pathlib import Path
import sys,json,subprocess,os,importlib.util
root=Path(sys.argv[1]);cfg=json.loads((root/'fixture.json').read_text());action=sys.argv[2]
spec=importlib.util.spec_from_file_location('telemt_state',cfg['source']+'/scripts/telemt_state.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
s=m.TelemtState(root, 'http://127.0.0.1:'+str(cfg['a']))
try:
 if action=='start':
  with (root/'native.log').open('ab') as log:
   p=subprocess.Popen([cfg['binary'],'run','--data-path',str(root/'data'),str(root/'telemt.toml')],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
 elif action=='probe':
  print(' '.join(map(str,s.processes())));sys.exit(0)
 elif action=='version':pass
 elif action=='reset':
  import base64;s.reset(base64.b64decode(sys.argv[3],validate=True).decode())
 else:getattr(s,action)()
 print('TELEMT_STATE_OK')
except Exception as e:
 print(type(e).__name__,file=sys.stderr);sys.exit(1)
