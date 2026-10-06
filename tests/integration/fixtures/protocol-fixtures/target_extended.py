import http.server,socket,ssl,struct,threading,time
DATA=b'VPNBot controlled payload\n'*40960
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_GET(self):
        if self.path=='/stream':
            self.send_response(200);self.send_header('Content-Length','104857600');self.end_headers()
            try:
                for _ in range(102400):self.wfile.write(b'X'*1024);self.wfile.flush();time.sleep(.02)
            except (BrokenPipeError,ConnectionResetError):pass
        else:
            body=DATA if self.path=='/large' else b'VPNBOT-PROTOCOL-TARGET\n'
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def do_POST(self):
        body=self.rfile.read(int(self.headers.get('Content-Length',0)))
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass
def dns():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',10053))
    while True:
        data,remote=s.recvfrom(65535)
        if len(data)<12:continue
        reply=data[:2]+b'\x81\x80\0\1\0\1\0\0\0\0'+data[12:]+b'\xc0\x0c\0\1\0\1\0\0\0\x3c\0\x04'+socket.inet_aton('11.77.0.2')
        s.sendto(reply,remote)
threading.Thread(target=dns,daemon=True).start()
httpd=http.server.ThreadingHTTPServer(('0.0.0.0',8081),Handler)
threading.Thread(target=httpd.serve_forever,daemon=True).start()
tls=http.server.ThreadingHTTPServer(('0.0.0.0',8443),Handler)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain('/test.pem','/test.key')
tls.socket=ctx.wrap_socket(tls.socket,server_side=True);tls.serve_forever()
