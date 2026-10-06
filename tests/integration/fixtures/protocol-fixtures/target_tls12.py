import ssl,http.server
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b'TLS12-ONLY')
 def log_message(self,*a):pass
s=http.server.ThreadingHTTPServer(('0.0.0.0',8444),Handler);c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.maximum_version=ssl.TLSVersion.TLSv1_2;c.load_cert_chain('/test.pem','/test.key');s.socket=c.wrap_socket(s.socket,server_side=True);s.serve_forever()
