import http.server, socket, threading
DATA = (b'VPNBot controlled payload\n' * 40960)
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        body = DATA if self.path == '/large' else b'VPNBOT-PROTOCOL-TARGET\n'
        self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length',0)))
        self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*args): pass

def udp():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',9999))
    while True:
        b,a=s.recvfrom(65535); s.sendto(b,a)
threading.Thread(target=udp,daemon=True).start()
http.server.ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
