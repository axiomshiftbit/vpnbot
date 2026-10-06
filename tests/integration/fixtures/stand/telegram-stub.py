import http.server,ssl,json,time,pathlib,threading
counter=100
lock=threading.Lock()
class API(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global counter
        method=self.path.rsplit('/',1)[-1].split('?')[0]
        size=min(int(self.headers.get('Content-Length',0)),16*1024*1024)
        self.rfile.read(size)
        with lock:
            counter+=1; mid=counter
            with open('/state/methods.log','a') as f: f.write(f'{int(time.time())} {method} {size}\n')
        result=True
        if method=='getUpdates':
            time.sleep(.5)
            result=[]
        elif method=='getMe': result={'id':123456789,'is_bot':True,'first_name':'VPNBot Audit','username':'vpnbot_audit_bot'}
        elif method=='getMyName': result={'name':'VPNBot Audit'}
        elif method=='getWebhookInfo': result={'url':'','pending_update_count':0}
        elif method=='getChat': result={'id':1,'type':'private','first_name':'Audit'}
        elif method.startswith('send') or method.startswith('editMessage'):
            result={'message_id':mid,'date':int(time.time()),'chat':{'id':1,'type':'private'}}
        data=json.dumps({'ok':True,'result':result}).encode()
        self.send_response(200); self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def log_message(self,*args): pass
s=http.server.ThreadingHTTPServer(('0.0.0.0',8443),API)
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain('/tls/public.pem','/tls/private.pem');s.socket=c.wrap_socket(s.socket,server_side=True);s.serve_forever()
