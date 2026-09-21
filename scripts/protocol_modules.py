#!/usr/bin/env python3
"""Compose entry point and bounded host worker for optional protocol containers."""
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import uuid

DEFAULTS = {"oc": True, "ovpn": True, "ipsec": True, "ikev2": True, "l2tp": True, "anytls": False, "mieru": False, "tuic": False, "shadowtls": False}
SERVICES = ("oc", "ovpn", "ipsec", "anytls", "mieru", "tuic", "shadowtls")
SYSTEMD_UNIT = Path('/etc/systemd/system/vpnbot.service')


def migrate_systemd_stop(root):
    """Upgrade the stock stop command of this installation, retaining custom unit data."""
    unit = SYSTEMD_UNIT
    if unit.is_symlink() or not unit.is_file(): return False
    with open(root / 'update/systemd-unit.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = unit.read_bytes()
        directories = re.findall(rb'^WorkingDirectory=(.*)$', before, re.M)
        if not directories or Path(os.fsdecode(directories[-1].rstrip(b'\r'))).resolve() != root.resolve():
            return False
        old = b'ExecStop=/bin/sh -c "docker compose down --remove-orphans"'
        if before.splitlines().count(old) != 1: return False
        new = b'ExecStop=/bin/sh -c "docker compose --profile \'*\' down --remove-orphans"'
        after = re.sub(rb'^' + re.escape(old) + rb'(?=\r?$)', lambda match: new, before, count=1, flags=re.M)
        original = unit.stat()

        def write(path, data, mode):
            temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
            try:
                with open(temporary, 'xb') as stream:
                    os.fchmod(stream.fileno(), mode)
                    if path == unit: os.fchown(stream.fileno(), original.st_uid, original.st_gid)
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
                os.replace(temporary, path)
                directory = os.open(path.parent, os.O_DIRECTORY)
                try: os.fsync(directory)
                finally: os.close(directory)
            finally: temporary.unlink(missing_ok=True)

        write(root / 'update/vpnbot.service.before-protocols', before, 0o600)
        if unit.is_symlink() or unit.read_bytes() != before:
            raise RuntimeError('systemd unit changed during migration')
        try:
            write(unit, after, original.st_mode & 0o777)
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, check=True, timeout=30)
        except Exception:
            if unit.read_bytes() == after:
                write(unit, before, original.st_mode & 0o777)
                subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=30)
            raise
        return True


def migrate_upstream(text):
    """Add optional DNS resolution and the TLS bridge to existing installations."""
    if not re.search(r'\bresolver\s', text):
        text = text.replace('stream {', 'stream {\n    resolver 127.0.0.11 valid=10s ipv6=off;', 1)
    for name, host, port in (("ocserv", "oc", 443), ("openvpn", "ovpn", 1194)):
        pattern = r'upstream\s+' + name + r'\s*\{\s*server\s+' + host + ':' + str(port) + r'\s*;\s*\}'
        text = re.sub(pattern, f'upstream {name} {{\n        zone {name} 64k;\n        server {host}:{port} resolve;\n    }}', text)
    if 'upstream anytls_bridge' not in text:
        block = '''
    upstream anytls_backend {
        zone anytls_backend 64k;
        server anytls:8443 resolve;
    }
    upstream anytls_bridge { server 127.0.0.1:10444; }
    server {
        listen 127.0.0.1:10444 proxy_protocol;
        proxy_pass anytls_backend;
        proxy_protocol off;
    }
'''
        position = text.rfind('}')
        if position < 0: raise ValueError('invalid upstream configuration')
        text = text[:position] + block + text[position:]
    if not re.search(r'^\s*#anytls\s*$', text, re.M):
        text = re.sub(r'(map\s+\$ssl_preread_server_name\s+\$sni_name\s*\{)',
                      r'\1\n        #anytls\n        # disabled\n        #anytls', text, count=1)
    return text


def prepare_upstream(root):
    path = root / 'config/upstream.conf'
    if not path.exists(): return
    # Preserve the inode: existing installations bind-mount this individual file.
    with open(root / 'config/upstream.lock', 'a') as lock:
        for _ in range(4):
            fcntl.flock(lock, fcntl.LOCK_EX)
            before = path.read_text()
            fcntl.flock(lock, fcntl.LOCK_UN)
            after = migrate_upstream(before)
            if before == after: return
            validate_upstream(root, after)
            fcntl.flock(lock, fcntl.LOCK_EX)
            if path.read_text() != before:
                fcntl.flock(lock, fcntl.LOCK_UN)
                continue
            backup = root / 'update/upstream.before-protocols.conf'
            if not backup.exists():
                with open(backup, 'x') as stream:
                    stream.write(before); stream.flush(); os.fsync(stream.fileno())
            try:
                with open(path, 'r+') as stream:
                    stream.write(after); stream.truncate(); stream.flush(); os.fsync(stream.fileno())
            except OSError:
                with open(path, 'r+') as stream:
                    stream.write(before); stream.truncate(); stream.flush(); os.fsync(stream.fileno())
                raise
            return
        raise RuntimeError('upstream changed during migration')


def validate_upstream(root, candidate):
    # No live service, public port, or SSH is needed during a cold update.
    # Use the exact selected NGINX image and its bind mounts. Static upstream
    # names get dummy addresses solely for syntax validation, without traffic.
    current = settings(root)
    result = compose(current, ['config', '--format', 'json'], capture=True)
    result.check_returncode()
    upstream = json.loads(result.stdout)['services']['up']
    image = upstream['image']
    exists = subprocess.run(['docker', 'image', 'inspect', image], capture_output=True)
    if exists.returncode:
        compose(current, ['build', 'up'], capture=True).check_returncode()
    command = ['docker', 'run', '--rm', '-i', '--network', 'none', '--log-driver', 'none',
               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--entrypoint', '/bin/sh']
    for volume in upstream.get('volumes', []):
        if volume['type'] != 'bind': raise ValueError('unsupported upstream validation mount')
        command += ['--volume', volume['source'] + ':' + volume['target'] + (':ro' if volume.get('read_only') else '')]
    for host in sorted(set(re.findall(r'\bserver\s+([a-zA-Z][a-zA-Z0-9.-]*):[0-9]+\b', candidate))):
        command += ['--add-host', host + ':127.0.0.1']
    command += [image, '-c', 'umask 077; cat > /tmp/protocol-migration.conf && nginx -t -c /tmp/protocol-migration.conf']
    subprocess.run(command, input=candidate.encode(), capture_output=True, check=True, timeout=30)


def settings(root):
    path = root / "config/protocol-services.json"
    if not path.exists():
        return DEFAULTS.copy()
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.keys() - DEFAULTS.keys() or any(type(v) is not bool for v in value.values()):
        raise ValueError("invalid module settings")
    return DEFAULTS | value


def enabled(s, service):
    return s[service] and (service != "ipsec" or s["ikev2"] or s["l2tp"])


def environment(s):
    env = os.environ.copy()
    env["COMPOSE_PROFILES"] = ",".join(service for service in SERVICES if enabled(s, service))
    env["IPSEC_IKEV2_ENABLED"] = "1" if s["ipsec"] and s["ikev2"] else "0"
    env["IPSEC_L2TP_ENABLED"] = "1" if s["ipsec"] and s["l2tp"] else "0"
    for service, port in bindings(Path.cwd()).items(): env[service.upper() + "_PORT"] = str(port)
    if not env.get("VER"):
        result = subprocess.run(["git", "describe", "--tags", "--always"], capture_output=True, text=True)
        env["VER"] = result.stdout.strip() if result.returncode == 0 else "local"
    return env


def bindings(root):
    ports = {}
    for service in ("mieru", "tuic", "shadowtls"):
        path = root / "config/protocols" / service / "desired.json"
        if path.exists():
            try: port = json.loads(path.read_text())["settings"]["port"]
            except (OSError, ValueError, KeyError, TypeError): continue
            if type(port) is int and 1024 <= port <= 65535: ports[service] = port
    return ports


def sync_certificates(root, current):
    # Network-facing cores see only their selected TLS pair. In particular,
    # never mount the directory containing the other VPNs' CA/private keys.
    source_root = (root / 'certs').resolve()
    for service in ('anytls', 'tuic'):
        desired = root / 'config/protocols' / service / 'desired.json'
        if not current[service] or not desired.exists(): continue
        config = json.loads(desired.read_text())['settings']
        target_root = root / 'update/protocol-certs' / service
        target_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        pair = []
        for key in ('certificate', 'private_key'):
            path = config[key]
            if not isinstance(path, str) or not re.fullmatch(r'/certs/[a-zA-Z0-9_./-]+', path) or '..' in path:
                raise ValueError('invalid certificate path')
            relative = Path(path).relative_to('/certs')
            source = (source_root / relative).resolve()
            target = target_root / relative
            if not source.is_relative_to(source_root) or not target.resolve().is_relative_to(target_root.resolve()):
                raise ValueError('certificate path leaves its directory')
            pair.append((source, target))
        try: material = [(target, source.read_bytes()) for source, target in pair]
        except FileNotFoundError: continue  # Initial SSL setup or a renewal in progress.
        for target, data in material:
            if target.exists() and target.read_bytes() == data: continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temporary = target.with_name(target.name + '.' + uuid.uuid4().hex + '.tmp')
            try:
                with open(temporary, 'xb') as stream:
                    os.chmod(temporary, 0o600)
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
                os.replace(temporary, target)
            finally: temporary.unlink(missing_ok=True)


def compose(s, arguments, capture=False, input_data=None, port_overrides=None):
    env = environment(s)
    for service, port in (port_overrides or {}).items(): env[service.upper() + '_PORT'] = str(port)
    return subprocess.run(["docker", "compose", "--env-file", ".env", "--env-file", "override.env"] + arguments,
                          env=env, capture_output=capture, input=input_data, check=False)


def check_port(s, service, port):
    own = compose(s, ['ps', '-q', service], capture=True)
    own.check_returncode()
    identities = set(own.stdout.split())
    for network in (('tcp', 'udp') if service == 'mieru' else ('udp',) if service == 'tuic' else ('tcp',)):
        used = subprocess.run(['docker', 'ps', '--filter', f'publish={port}/{network}', '--format', '{{.ID}}'],
                              capture_output=True, check=True).stdout.split()
        # Docker ps uses short IDs; compose ps uses full IDs.
        if any(not any(identity.startswith(uid) for identity in identities) for uid in used):
            raise RuntimeError('protocol port is already published')
        if not used:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if network == 'udp' else socket.SOCK_STREAM) as probe:
                probe.bind(('0.0.0.0', port))


def apply(root):
    desired = root / "config/protocol-services.json"
    if not desired.exists():
        return
    lock = open(root / "update/protocol-services.lock", "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = settings(root)
        certificate_errors = {}
        for service in ('anytls', 'tuic'):
            try: sync_certificates(root, current | {other: False for other in ('anytls', 'tuic') if other != service})
            except (OSError, ValueError, KeyError, TypeError): certificate_errors[service] = 'certificate_copy_failed'
        status = root / "config/protocol-services.status.json"
        previous = json.loads(status.read_text()) if status.exists() else {}
        ports = bindings(root)
        if previous.get("settings") == current and previous.get("bindings", {}) == ports and previous.get("ok") and not certificate_errors:
            return
        old = previous.get("settings", {})
        applied = old.copy()
        applied_ports = previous.get('bindings', {}).copy()
        failures = certificate_errors.copy()
        changed = []
        for service in SERVICES:
            same = old.get(service) == current[service]
            same = same and previous.get("bindings", {}).get(service) == ports.get(service)
            if service == "ipsec":
                same = same and all(old.get(k) == current[k] for k in ("l2tp", "ikev2"))
            pending = previous.get('errors', {}).get(service, '')
            if same and service in old and pending not in ('operation_failed', 'operation_failed_rolled_back'):
                continue
            if enabled(current, service):
                if service in ('mieru', 'tuic', 'shadowtls'):
                    if service not in ports:
                        failures[service] = 'invalid_protocol_port'
                        continue
                    if previous.get('bindings', {}).get(service) != ports[service]:
                        try: check_port(current, service, ports[service])
                        except (OSError, RuntimeError, subprocess.SubprocessError):
                            failures[service] = 'port_unavailable'
                            continue
                result = compose(current, ["up", "-d", "--no-deps", service], capture=True)
            else:
                # Explicit service names activate profiles for stop/rm, never for a pull.
                result = compose(current, ["stop", "--timeout", "10", service], capture=True)
                if result.returncode == 0:
                    result = compose(current, ["rm", "--force", service], capture=True)
            if result.returncode != 0:
                prior_port = previous.get('bindings', {}).get(service)
                rolled_back = False
                if old.get(service) and prior_port and prior_port != ports.get(service):
                    rolled_back = compose(current, ['up', '-d', '--no-deps', service], capture=True,
                                          port_overrides={service: prior_port}).returncode == 0
                failures[service] = 'operation_failed_rolled_back' if rolled_back else 'operation_failed'
                continue
            applied[service] = current[service]
            if service == 'ipsec':
                for key in ('ikev2', 'l2tp'): applied[key] = current[key]
            if service in ports: applied_ports[service] = ports[service]
            else: applied_ports.pop(service, None)
            changed.append(service)
        # A disabled OpenConnect may later return with the same address. Refresh the
        # AdGuard route that was absent when AdGuard itself started.
        if "oc" in changed and current["oc"]:
            compose(current, ["exec", "-T", "ad", "sh", "-c", 'address=$(getent hosts oc | awk "{print \\$1}"); [ -z "$address" ] || ip route replace 10.0.2.0/24 via "$address"'], capture=True)
        write_status(status, {"ok": not failures, "settings": applied, "bindings": applied_ports, "changed": changed,
                              "errors": failures, "failed_service": next(iter(failures), None)})
    finally:
        lock.close()


def write_status(path, value):
    temporary = path.with_suffix(".tmp")
    with open(temporary, "w") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def filter_ipsec(text, ikev2=True, l2tp=True):
    """Remove only disabled connection blocks; keep the original persistent file intact."""
    tokens = list(re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|#[^\n]*|[{}]|[^\s{}"\'#]+', text))
    depth = 0
    connections_depth = None
    remove = []
    i = 0
    while i < len(tokens):
        word = tokens[i].group()
        if word.startswith(("#", '"', "'")):
            i += 1
            continue
        if word == "connections" and i + 1 < len(tokens) and tokens[i + 1].group() == "{":
            connections_depth = depth + 1
        blocked = (word == "ikev2" and not ikev2) or (word == "l2tp" and not l2tp)
        if blocked and depth == connections_depth and i + 1 < len(tokens) and tokens[i + 1].group() == "{":
            end, level = i + 2, 1
            while end < len(tokens) and level:
                if tokens[end].group() == "{": level += 1
                elif tokens[end].group() == "}": level -= 1
                end += 1
            if level:
                raise ValueError("invalid swanctl block")
            remove.append((tokens[i].start(), tokens[end - 1].end()))
            i = end
            continue
        if word == "{": depth += 1
        elif word == "}":
            if depth == connections_depth: connections_depth = None
            depth -= 1
        i += 1
    if depth != 0:
        raise ValueError("unbalanced swanctl configuration")
    for start, end in reversed(remove):
        text = text[:start] + text[end:]
    return text


def main():
    command = sys.argv[1]
    if command == "ipsec-filter":
        text = filter_ipsec(Path(sys.argv[2]).read_text(), os.environ.get("IPSEC_IKEV2_ENABLED", "1") == "1",
                            os.environ.get("IPSEC_L2TP_ENABLED", "1") == "1")
        Path(sys.argv[3]).write_text(text)
        return 0
    root = Path.cwd()
    if command == "apply":
        apply(root)
        return 0
    if command == "compose":
        if sys.argv[2:3] == ["up"]:
            migrate_systemd_stop(root)
            sync_certificates(root, settings(root))
            prepare_upstream(root)
        return compose(settings(root), sys.argv[2:]).returncode
    raise ValueError("unknown operation")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        sys.exit(main())
    except Exception:
        # Compose stderr may contain interpolated credentials. Keep it out of bot logs.
        print("protocol modules: operation failed; settings and saved credentials retained", file=sys.stderr)
        sys.exit(1)
