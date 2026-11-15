#!/usr/bin/env python3
import http.client,json,pathlib,secrets,sys,time
def one(label, client):
    q=secrets.token_bytes(2)+b'\1\0\0\1'+bytes(6)+b''.join(bytes([len(s)])+s.encode() for s in 'answer.audit.test'.split('.'))+b'\0\0\1\0\1'
    c=http.client.HTTPConnection('ad',3000,timeout=3)
    try:
        c.request('POST','/dns-query/'+client,q,{'Content-Type':'application/dns-message'})
        r=c.getresponse(); body=r.read(4096)
        valid=len(body)>12 and body[:2]==q[:2] and bool(body[2]&128) and body[3]&15==0 and int.from_bytes(body[6:8],'big')>0
        return {'client':label,'http_status':r.status,'dns_answer':valid,'expected_answer':valid and body[-4:]==bytes([11,77,78,2]),
                'dns_rcode':body[3]&15 if len(body)>=12 else None,'answer_count':int.from_bytes(body[6:8],'big') if len(body)>=12 else None,
                'dns_id_matches':len(body)>=12 and body[:2]==q[:2]}
    except (OSError,http.client.HTTPException) as e:
        return {'client':label,'transport_error':type(e).__name__,'dns_answer':False,'expected_answer':False}
    finally:c.close()
known=pathlib.Path('/work/client_id').read_text().strip()
if sys.argv[1:] == ['wait']:
    for _ in range(50):
        r=one('known',known)
        if 'transport_error' not in r:break
        time.sleep(.2)
    else:raise SystemExit(2)
print(json.dumps({'known':one('known',known),'unknown':one('unknown','audit-unknown-client')}))
