"""run.py CHECKOUT MIERU_IMAGE PHP_IMAGE PREVIOUS_CLIENT RESULTS_DIRECTORY"""
from pathlib import Path
import json, os, shutil, subprocess, sys
SOURCE, IMAGE, PHP, CLIENT, OUTPUT = sys.argv[1:]
ROOT=Path(OUTPUT).resolve();ROOT.mkdir(parents=True,exist_ok=True,mode=0o700);os.umask(0o077)
LAB=Path(__file__).resolve().parent;NAME='vpnbot-mieru-idle';created=False

def need(*args,timeout=30):
 r=subprocess.run(list(map(str,args)),capture_output=True,timeout=timeout)
 if r.returncode:
  (ROOT/'command-error.log').write_bytes(r.stdout+r.stderr);raise RuntimeError('fixture command failed')
 return r.stdout.decode().strip()

try:
 shutil.copy2(CLIENT,ROOT/'mieru-client');(ROOT/'mieru-client').chmod(0o700)
 shutil.copy2(LAB/'probe.py',ROOT/'probe.py')
 need('docker','run','--rm','--network','none','--entrypoint','php','-v',f'{SOURCE}:/source:ro','-v',f'{LAB}:/fixture:ro','-v',f'{ROOT}:/probe',PHP,'/fixture/fixture.php','/source','/probe')
 need('docker','run','-d','--name',NAME,'--network','none','--entrypoint','sleep','-v',f'{ROOT}:/probe',IMAGE,'infinity');created=True
 pid=need('docker','inspect','--format','{{.State.Pid}}',NAME)
 need('nsenter','-t',pid,'-n','ip','addr','add','198.51.100.2/32','dev','lo')
 r=subprocess.run(['docker','exec',NAME,'python3','/probe/probe.py'],timeout=110)
 if r.returncode:raise RuntimeError('Mieru idle probe failed')
finally:
 if created:need('docker','rm','-f',NAME)
 for name in ('server.json','client.json','live-client.json','enabled.json','disabled.json'):(ROOT/name).unlink(missing_ok=True)
 # Synthetic accounts are private test data, not an artifact of the run.
 if (ROOT/'state').exists():shutil.rmtree(ROOT/'state')
