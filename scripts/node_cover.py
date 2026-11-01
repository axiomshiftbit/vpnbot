#!/usr/bin/env python3
"""Password-protected HTTPS cover and fixed loopback VPN upstreams."""
import re


def password_hash(value):
    # The full bot uses bcrypt. The minimal installer can also use OpenSSL's
    # SHA-512 crypt for a random 384-bit throwaway password, never a human password.
    if not isinstance(value, str) or not re.fullmatch(r'(?:\$2[aby]\$(?:0[4-9]|1[0-2])\$[A-Za-z0-9./]{53}|\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86})', value):
        raise ValueError('invalid cover password hash')
    return value


def nginx(options, keys, ipv6):
    domain, transport = options['domain'], options['transport']
    proxy = ' proxy_protocol' if options.get('xray', {}).get('reality', {}).get('xver', 0) else ''
    listen = ['listen 127.0.0.1:9443 ssl'+proxy+';'] if transport == 'reality' else ['listen 0.0.0.0:8443 ssl;']
    if transport != 'reality' and ipv6:
        listen.append('listen [::]:8443 ssl ipv6only=on;')
    locations = []
    if transport == 'ws':
        locations = ['location = /'+keys['path']+' {',
                     ' proxy_pass http://127.0.0.1:9444;', ' proxy_http_version 1.1;',
                     ' proxy_set_header Upgrade $http_upgrade;', ' proxy_set_header Connection "upgrade";',
                     ' proxy_set_header Host $host;', ' proxy_buffering off;', ' proxy_read_timeout 3600s;',
                     ' proxy_send_timeout 3600s;', ' proxy_intercept_errors on;', ' error_page 400 404 = @cover;', ' }']
    elif transport in ('grpc', 'xhttp', 'trojan-grpc'):
        locations = ['location /'+keys['path']+' {', ' grpc_pass grpc://127.0.0.1:9444;',
                     ' grpc_read_timeout 3600s;', ' grpc_send_timeout 3600s;',
                     ' grpc_set_header Host $host;', ' grpc_socket_keepalive on;', ' }']
    return '\n'.join([
        'worker_processes 1;', 'pid /tmp/nginx.pid;', 'error_log /dev/stderr crit;',
        'events { worker_connections 1024; }', 'http {', ' access_log off;', ' server_tokens off;',
        ' client_body_temp_path /tmp/client_body;', ' proxy_temp_path /tmp/proxy;',
        ' fastcgi_temp_path /tmp/fastcgi;', ' uwsgi_temp_path /tmp/uwsgi;', ' scgi_temp_path /tmp/scgi;',
        ' client_max_body_size 2m;', ' client_body_timeout 15s;', ' client_header_timeout 10s;',
        ' keepalive_timeout 30s;', ' send_timeout 60s;', ' ssl_protocols TLSv1.2 TLSv1.3;',
        ' ssl_certificate /node/fullchain.pem;', ' ssl_certificate_key /node/privkey.pem;',
        ' server {', *listen, ' http2 on;', ' server_name '+' '.join([domain, *options.get('domain_aliases', [])])+';',
        ' root /node/site;', ' charset utf-8;', ' default_type text/html;',
        # Same closed-site behavior as the full bot: missing and incorrect
        # credentials both get a real Basic Auth challenge from NGINX.
        ' location ~ /\\. { return 404; }',
        ' location ~* \\.(?:php|py|sh|ini|conf|json|key|pem|bak|log)(?:$|/) { return 404; }',
        ' location / { auth_basic "Restricted Content";',
        '  auth_basic_user_file /node/htpasswd; try_files /index.html =503; }',
        ' location @cover { auth_basic "Restricted Content";',
        '  auth_basic_user_file /node/htpasswd; try_files /index.html =503; }',
        *locations, ' }', '}', ''])
