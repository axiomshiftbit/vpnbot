from pathlib import Path
import subprocess,time,json,re
from registry import load_cases,validate_results
base=Path(__file__).parent
cases=load_cases(base)
rows=[]
def attempt(name):
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
 return row
for name in cases:
 row=attempt(name)
 # Набор и так идёт на одном стенде дважды (до и после восстановления), поэтому
 # отказ повторяется один раз: случайный сетевой сбой не должен стоить
 # перезапуска всего стенда (~80 мин), устойчивая ошибка провалит обе попытки.
 # После тайм-аута не повторяем: убитый набор не успел убрать за собой.
 if type(row['exit']) is int and row['exit']:
  (base/(name+'.log')).replace(base/(name+'.attempt1.log'))
  print('RETRY '+json.dumps(row),flush=True)
  row=attempt(name)|{'retried':True}
 rows.append(row);(base/'results.json').write_text(json.dumps(rows,indent=2))
 print(json.dumps(row),flush=True)
print('POSTRESTORE NATIVE COMPLETE',flush=True)
validate_results(rows,cases)
raise SystemExit(1 if any(r['exit'] for r in rows) else 0)
