"""Check the node's HTTPS and UDP egress through its authenticated loopback probe."""
import hashlib
import http.client
import os
import re
import socket
import ssl
import struct
import sys


TRACE_HOST = 'www.cloudflare.com'
DNS_ADDRESS = b'\x01' + socket.inet_aton('1.1.1.1') + struct.pack('!H', 53)


def connect(port, password, command, destination):
    # The Trojan inbound listens on TCP loopback only, including for UDP.
    sock = socket.create_connection(('127.0.0.1', port), timeout=10)
    try:
        digest = hashlib.sha224(password).hexdigest().encode('ascii')
        sock.sendall(digest + b'\r\n' + command + destination + b'\r\n')
        return sock
    except OSError:
        sock.close()
        raise


def check_trace(port, password):
    host = TRACE_HOST.encode('ascii')
    destination = b'\x03' + bytes([len(host)]) + host + struct.pack('!H', 443)
    with connect(port, password, b'\x01', destination) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=TRACE_HOST) as sock:
            sock.sendall(b'GET /cdn-cgi/trace HTTP/1.1\r\nHost: ' + host + b'\r\nConnection: close\r\n\r\n')
            with http.client.HTTPResponse(sock) as response:
                response.begin()
                return response.status == 200 and any(line in (b'warp=on', b'warp=plus')
                                                       for line in response.read(8192).splitlines())


def check_udp(port, password):
    identifier = os.urandom(2)
    question = b'\x07example\x03com\x00\x00\x01\x00\x01'
    query = identifier + struct.pack('!5H', 0x0100, 1, 0, 0, 0) + question
    with connect(port, password, b'\x03', DNS_ADDRESS) as sock, sock.makefile('rb') as reply:
        sock.sendall(DNS_ADDRESS + struct.pack('!H', len(query)) + b'\r\n' + query)
        if reply.read(len(DNS_ADDRESS)) != DNS_ADDRESS:
            return False
        size, = struct.unpack('!H', reply.read(2))
        if not len(query) <= size <= 4096 or reply.read(2) != b'\r\n':
            return False
        response = reply.read(size)
    if len(response) != size or response[:2] != identifier or not response[12:].startswith(question):
        return False
    flags, questions, answers = struct.unpack_from('!3H', response, 2)
    return (flags & 0x800f) == 0x8000 and questions == 1 and answers > 0


def measure(check, port, password):
    try:
        return 'ok' if check(port, password) else 'invalid'
    except TimeoutError:
        return 'timeout'
    except ssl.SSLError:
        return 'tls'
    except (OSError, ValueError, http.client.HTTPException, struct.error):
        return 'failed'


if __name__ == '__main__':
    try:
        port = int(sys.argv[1])
        password = sys.stdin.buffer.readline(66).removesuffix(b'\n')
        if re.fullmatch(rb'[0-9a-f]{64}', password):
            https = measure(check_trace, port, password)
            udp = measure(check_udp, port, password)
            if '--details' in sys.argv[2:]:
                print(f'https={https} udp={udp}')
            elif https == udp == 'ok':
                print('warp=ok')
    except (OSError, ValueError, http.client.HTTPException, struct.error):
        pass
