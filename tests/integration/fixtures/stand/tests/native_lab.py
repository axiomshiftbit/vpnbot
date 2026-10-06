import json, os, socket, subprocess, time
from pathlib import Path
BASE=Path(__file__).resolve().parent
BIN=BASE/"bin"
LAB=BASE/"lab"
LAB.mkdir(exist_ok=True,mode=0o700)
ENV=dict(os.environ)
RESULT_FILE=LAB/"results.json"
RESULTS=[]

def run(args, **kw):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=30, env=ENV, **kw)

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def record(name, actual, expected=True, detail=''):
    ok = actual == expected
    RESULTS.append(dict(name=name, passed=ok, actual=actual, expected=expected, detail=detail))
    RESULT_FILE.write_text(json.dumps(RESULTS, indent=2, ensure_ascii=False))
    print(('PASS ' if ok else 'FAIL ') + name + (': ' + detail if detail else ''), flush=True)

def ready(proc, p):
    for _ in range(70):
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(('127.0.0.1', p), timeout=.1):
                return True
        except OSError:
            time.sleep(.03)
    return False

def read_exact(sock, n):
    out = b''
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise OSError('Unexpected SOCKS EOF')
        out += chunk
    return out

def config_args(kind, path, check=False, binary=None):
    binary = BIN / (binary or kind)
    if kind == 'xray':
        return [binary, 'run', *(['-test'] if check else []), '-config', path]
    if kind == 'mihomo':
        return [binary, *(['-t'] if check else []), '-d', LAB, '-f', path]
    return [binary, 'check' if check else 'run', '-c', path]
