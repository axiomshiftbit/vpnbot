"""Цель трафика snolc: HTTP (байты и хеш выгрузки), TCP- и UDP-эхо на всех адресах."""
import hashlib, http.server, socket, threading


class Http(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        size = int(self.path[7:]) if self.path.startswith('/bytes/') else 24
        if size < 0 or size > 32 * 1024 * 1024:
            self.send_error(400); return
        self.send_response(200); self.send_header('Content-Length', str(size)); self.end_headers()
        try:
            while size:
                chunk = b'S' * min(size, 16384); self.wfile.write(chunk); size -= len(chunk)
        except OSError:
            pass

    def do_POST(self):
        size = int(self.headers.get('Content-Length', '0')); digest = hashlib.sha256()
        if size > 32 * 1024 * 1024:
            self.send_error(400); return
        while size:
            data = self.rfile.read(min(size, 65536))
            if not data:
                return
            digest.update(data); size -= len(data)
        body = digest.hexdigest().encode()
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, *args):
        pass


udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
udp.bind(('0.0.0.0', 9099))


def echo():
    while True:
        data, peer = udp.recvfrom(65535); udp.sendto(data, peer)


def tcp_echo(conn):
    with conn:
        try:
            while data := conn.recv(65536):
                conn.sendall(data)
        except OSError:
            pass


def tcp():
    server = socket.create_server(('0.0.0.0', 8083), backlog=64)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=tcp_echo, args=(conn,), daemon=True).start()


threading.Thread(target=echo, daemon=True).start()
threading.Thread(target=tcp, daemon=True).start()
http.server.ThreadingHTTPServer(('0.0.0.0', 8082), Http).serve_forever()
