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
        # Trojan authenticates with hex(SHA-224(password)) by protocol; the core expects exactly this.
        # The password is a 256-bit HMAC derived for this probe, not a human password.
        digest = hashlib.sha224(password).hexdigest().encode('ascii')
        sock.sendall(digest + b'\r\n' + command + destination + b'\r\n')
        return sock
    except OSError:
        sock.close()
        raise


def tls_context():
    # Cloudflare serves TLS 1.2 and 1.3; never negotiate an older protocol, whatever the container's defaults.
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


TRACE_FIELDS = {'warp': rb'(on|plus|off)', 'ip': rb'[0-9a-fA-F:.]{2,45}', 'colo': rb'[A-Z]{3}', 'loc': rb'[A-Z]{2}'}


def trace(port, password):
    """Fields of Cloudflare's trace through the node's WARP; only well-formed values are kept."""
    host = TRACE_HOST.encode('ascii')
    destination = b'\x03' + bytes([len(host)]) + host + struct.pack('!H', 443)
    with connect(port, password, b'\x01', destination) as raw:
        with tls_context().wrap_socket(raw, server_hostname=TRACE_HOST) as sock:
            sock.sendall(b'GET /cdn-cgi/trace HTTP/1.1\r\nHost: ' + host + b'\r\nConnection: close\r\n\r\n')
            with http.client.HTTPResponse(sock) as response:
                response.begin()
                return trace_fields(response.read(8192)) if response.status == 200 else {}


def trace_fields(body):
    result = {}
    for line in body.splitlines():
        name, _, value = line.partition(b'=')
        pattern = TRACE_FIELDS.get(name.decode('ascii', 'replace'))
        if pattern and re.fullmatch(pattern, value):
            result[name.decode()] = value.decode()
    return result


def check_trace(port, password):
    host = TRACE_HOST.encode('ascii')
    destination = b'\x03' + bytes([len(host)]) + host + struct.pack('!H', 443)
    with connect(port, password, b'\x01', destination) as raw:
        with tls_context().wrap_socket(raw, server_hostname=TRACE_HOST) as sock:
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
        if re.fullmatch(rb'[0-9a-f]{64}', password) and '--trace' in sys.argv[2:]:
            try:
                fields = trace(port, password)
            except (OSError, ValueError, ssl.SSLError, http.client.HTTPException, struct.error):
                fields = {}
            print(' '.join(f'{key}={fields[key]}' for key in TRACE_FIELDS if key in fields))
        elif re.fullmatch(rb'[0-9a-f]{64}', password):
            https = measure(check_trace, port, password)
            udp = measure(check_udp, port, password)
            if '--details' in sys.argv[2:]:
                print(f'https={https} udp={udp}')
            elif https == udp == 'ok':
                print('warp=ok')
    except (OSError, ValueError, http.client.HTTPException, struct.error):
        pass
