import socket,struct,threading,http.server,time
class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=('WARP-UDP-FIXTURE '+self.client_address[0]).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*a):pass
def udp(host):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((host,18080))
    while True:
        b,p=s.recvfrom(65535);s.sendto(b,p)
def dns(host):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((host,53))
    while True:
        b,p=s.recvfrom(4096);q=12;labels=[]
        while b[q]:n=b[q];labels.append(b[q+1:q+1+n].decode());q+=n+1
        q+=1;typ=struct.unpack('!H',b[q:q+2])[0];name='.'.join(labels)
        ip='10.80.0.245' if name=='private.test' else '203.0.113.20'
        ans=b'\xc0\x0c'+struct.pack('!HHIH',1,1,1,4)+socket.inet_aton(ip) if typ==1 else b''
        s.sendto(b[:2]+struct.pack('!HHHHH',0x8180,1,1 if ans else 0,0,0)+b[12:q+4]+ans,p)
for host in ('203.0.113.20','10.80.0.245','127.0.0.1'):threading.Thread(target=udp,args=(host,),daemon=True).start()
for host in ('1.1.1.1','1.0.0.1'):threading.Thread(target=dns,args=(host,),daemon=True).start()
http.server.ThreadingHTTPServer(('0.0.0.0',18080),HTTP).serve_forever()
