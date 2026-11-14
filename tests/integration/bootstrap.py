#!/usr/bin/env python3
"""Create a disposable stand from tracked code and freshly generated data only.

Never run on an installation. The caller has to check the host and owns cleanup.
No production configuration, account, certificate or backup is an input.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time

ROOT = Path('/opt/vpnbot-hosted-ci')
BOT = ROOT / 'stand/bot'
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'HOME': str(ROOT / 'home'), 'LANG': 'C.UTF-8', 'VER': 'audit',
       'COMPOSE_PROJECT_NAME': 'vpnbot-audit',
       'COMPOSE_FILE': 'docker-compose.yml:compose.audit.yml:compose.migration.json:compose.fresh.json',
       'COMPOSE_ENV_FILES': '.env,override.env',
       'VPNBOT_HOST_SERVICES': 'off',
       'VPNBOT_BUNDLE_FILE': str(ROOT / 'active-test-bundle.json')}


def run(*args, input=None, timeout=180, cwd=None):
    p = subprocess.run(list(map(str, args)), input=input, capture_output=True,
                       text=True, env=ENV, cwd=cwd, timeout=timeout)
    if p.returncode:
        # Logs can contain generated profiles; keep them private even on failure.
        with (ROOT / 'bootstrap-private.log').open('a') as log:
            log.write(p.stdout + p.stderr)
        raise RuntimeError('fixture command failed: ' + str(args[0]))
    return p.stdout


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) if isinstance(value, (dict, list)) else value)
    path.chmod(0o600)


def certificate(cert, key, names):
    cert.parent.mkdir(parents=True, exist_ok=True)
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
        '-keyout', key, '-out', cert, '-subj', '/CN=' + names[0],
        '-addext', 'subjectAltName=' + ','.join('DNS:' + n for n in names))
    cert.chmod(0o644)


def docker_file(image, source, destination):
    container = run('docker', 'create', '--network', 'none', image, '/bin/true').strip()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        run('docker', 'cp', container + ':' + source, destination)
    finally:
        run('docker', 'rm', container)


def wait_frontend():
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        p = subprocess.run(['docker', 'inspect', 'php-audit', 'nginx-audit'],
                           env=ENV, capture_output=True, text=True)
        if p.returncode == 0 and all(d['State'].get('Health', {}).get('Status') == 'healthy'
                                     for d in json.loads(p.stdout)):
            # start_service.sh runs service.php before cron.php. The frontend
            # can already be healthy while initialization still rewrites Xray.
            ready = subprocess.run(['docker', 'exec', 'service-audit', 'pgrep', '-f',
                                    '^php cron[.]php$'], env=ENV, capture_output=True)
            if ready.returncode == 0:
                return
        time.sleep(1)
    raise RuntimeError('fresh frontend/service initialization timeout')


def validate_compose_inputs(config):
    """Reject accidental host data/credentials before starting services."""
    root = ROOT.resolve()
    system = {Path(p).resolve() for p in ('/etc/localtime', '/var/run/docker.sock',
                                         '/lib/modules', '/dev/net/tun', '/dev/ppp')}
    for service in config.get('services', {}).values():
        if service.get('network_mode'):
            raise ValueError('external network namespace in stand')
        for key in service.get('environment', {}):
            if (key.endswith('TOKEN') or key.startswith(('GITHUB_TOKEN_', 'ACTIONS_', 'GHCR_TOKEN'))
                    or key in ('SSH_AUTH_SOCK', 'DOCKER_AUTH_CONFIG')):
                raise ValueError('host credential variable in stand configuration')
        for mount in service.get('volumes', []):
            if mount['type'] == 'bind':
                source = Path(mount['source']).resolve()
                if not source.is_relative_to(root) and source not in system:
                    raise ValueError('host bind outside disposable stand')
            elif mount['type'] != 'volume':
                raise ValueError('unexpected stand mount type')
        for port in service.get('ports', []):
            if port.get('host_ip') not in ('127.0.0.1', '::1'):
                raise ValueError('stand entrypoint outside loopback')
        if any(service.get(key) for key in ('env_file', 'configs', 'secrets')):
            raise ValueError('external configuration input in stand')
    for volume in config.get('volumes', {}).values():
        if (volume.get('external') or volume.get('driver_opts')
                or volume.get('driver', 'local') != 'local'
                or volume.get('name') not in ('vpnbot-audit_adguard', 'vpnbot-audit_warp')):
            raise ValueError('volume outside disposable stand')

def bootstrap(checkout, candidate, client_image):
    os.umask(0o077)
    if BOT.exists():
        raise RuntimeError('refusing to reuse an existing stand')
    if run('docker', 'ps', '-aq').strip():
        raise RuntimeError('stand requires a Docker host without containers')
    if any(k.endswith('TOKEN') or k.startswith(('GITHUB_TOKEN', 'GH_TOKEN', 'ACTIONS_'))
           for k in os.environ):
        raise RuntimeError('credentials must be removed before provisioning')
    source = checkout / 'tests/integration'
    shutil.copytree(source / 'fixtures', ROOT, dirs_exist_ok=True)
    shutil.copytree(source / 'suite', ROOT / 'suite', dirs_exist_ok=True)
    BOT.mkdir(parents=True)
    # git archive excludes .git, local override.env, runtime state and audits.
    archive = subprocess.run(['git', '-C', str(checkout), 'archive', 'HEAD'],
                             capture_output=True, check=True).stdout
    subprocess.run(['tar', '-xf', '-', '-C', str(BOT)], input=archive, check=True)
    for directory in ('.git', 'ssh/pub', 'certs', 'logs', 'mirror', 'singbox_windows',
                      'config/openvpn', 'config/ipsec', 'config/wg', 'config/wg1'):
        (BOT / directory).mkdir(parents=True, exist_ok=True)
    for directory in ('home', 'tests/published', 'tests/optional-native/private',
                      'tests/optional-native/results', 'stand/results', 'stand/results/sing-mux-final-fix',
                      'stand/fixture/state', 'lab/bin'):
        (ROOT / directory).mkdir(parents=True, exist_ok=True)
    # A one-run dummy token is valid only for our local HTTPS API.
    write(BOT / 'app/config.php', "<?php\n$c = ['key'=>'123456789:" + secrets.token_hex(18)
          + "', 'admin'=>[1], 'debug'=>false];\n")
    write(BOT / 'override.env', 'IP=203.0.113.10\nVER=audit\nTELEGRAM_API=tg-audit:8443\n')
    env_file = BOT / '.env'
    env_file.write_text(re.sub(r'^TELEGRAM_API=.*$', 'TELEGRAM_API=tg-audit:8443',
                               env_file.read_text(), flags=re.M))
    write(BOT / 'docker-compose.override.yml', 'services: {}\n')
    for name in ('pipe', 'message', 'reload_message', 'key', 'curl'):
        write(BOT / 'update' / name, '')
    for name in ('wg0.conf', 'wg1.conf', 'location.conf', 'override.conf'):
        write(BOT / 'config' / name, '')
    write(BOT / 'config/pac.json', {'domain': 'vpnbot.test', 'language': 'ru', 'limitpage': 5,
                                    'letsencrypt': 'letsencrypt', 'warpoff': 1})
    print('START fresh-certificates', flush=True)
    # Fresh certificates and SSH keys are created on this disposable host.
    cert = BOT / 'certs'
    certificate(cert / 'cert_public', cert / 'cert_private', ['vpnbot.test', '*.vpnbot.test'])
    shutil.copy2(cert / 'cert_public', cert / 'self_public')
    shutil.copy2(cert / 'cert_private', cert / 'self_private')
    certificate(cert / 'vpnbot-protocol-test/server.pem', cert / 'vpnbot-protocol-test/server.key', ['anytls.test'])
    certificate(cert / 'vpnbot-migration/server.crt', cert / 'vpnbot-migration/server.key', ['masque.test'])
    tls = ROOT / 'stand/fixture/tls'
    certificate(tls / 'public.pem', tls / 'private.pem', ['tg-audit'])
    run('ssh-keygen', '-q', '-m', 'PEM', '-t', 'rsa', '-N', '', '-f', BOT / 'ssh/key')
    shutil.copy2(BOT / 'ssh/key.pub', BOT / 'ssh/pub/key.pub')
    # Trust only this generated test CA in addition to the normal public roots.
    ca = ROOT / 'stand/fixture/ca.pem'
    ca.write_bytes(Path('/etc/ssl/certs/ca-certificates.crt').read_bytes() + (tls / 'public.pem').read_bytes())
    ca.chmod(0o644)
    with (BOT / 'config/php.ini').open('a') as f:
        f.write('\ncurl.cainfo=/test-ca.pem\nopenssl.cafile=/test-ca.pem\n')
    # Preseed a fresh, disabled WARP fixture. Never call Cloudflare registration.
    warp = ROOT / 'stand/fixture/warp'
    key = run('docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'wg',
              candidate['images']['wg'], 'genkey').strip()
    public = run('docker', 'run', '--rm', '-i', '--network', 'none', '--entrypoint', 'wg',
                 candidate['images']['wg'], 'pubkey', input=key).strip()
    write(warp / 'wgcf-account.toml', '# generated synthetic fixture; no provider account\n')
    write(warp / 'wgcf-profile.conf', '[Interface]\nPrivateKey = ' + key + '\nAddress = 172.30.0.2/32\n'
          '[Peer]\nPublicKey = ' + public + '\nAllowedIPs = 0.0.0.0/0\nEndpoint = 10.10.0.245:51820\n')
    # MASQUE device fixture: synthetic as well, Cloudflare is never contacted.
    # The endpoint is a TEST-NET-3 address nothing answers from, so the stand
    # checks what does not need Cloudflare: refusal without an outage, the
    # kill switch, failing closed and the way back to WireGuard.
    masque = warp / 'masque'
    masque.mkdir(mode=0o700, parents=True, exist_ok=True)
    sec1 = run('openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout')
    write(masque / 'key.pem', run('openssl', 'pkcs8', '-topk8', '-nocrypt', input=sec1))
    endpoint_key = run('openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout')
    write(masque / 'device.json', {
        'id': 'stand-synthetic-device', 'endpoint_v4': '203.0.113.77:0', 'endpoint_v6': '',
        'endpoint_public_key': run('openssl', 'pkey', '-pubout', input=endpoint_key),
        'address_v4': '172.16.0.2', 'address_v6': '', 'account_type': 'free', 'warp_plus': False, 'registered': 0})
    write(masque / 'wgcf-account.toml', '# generated synthetic fixture; no provider account\n')
    # The bot re-registers a device whose licence mark differs from pac.json:
    # the mark of "no key" keeps the stand away from Cloudflare.
    write(masque / 'license.sha256', hashlib.sha256(b'').hexdigest() + '\n')
    services = {s: {} for s in candidate_services()}
    # All public entrypoints on the disposable stand bind to loopback only.
    # The original ports inside containers and real bot protocol code stay intact.
    import yaml
    original = yaml.safe_load((BOT / 'docker-compose.yml').read_text())['services']
    text = 'services:\n'
    for name in services:
        ports = original[name].get('ports', [])
        text += '  ' + name + ':\n    ports: !override\n'
        if not ports:
            text += '      []\n'
        else:
            for port in ports:
                port = str(port)
                if port.startswith('127.0.0.1:'): port = port[len('127.0.0.1:'):]
                text += '      - "127.0.0.1:' + port + '"\n'
        if name in ('php', 'service'):
            text += '    volumes:\n      - ' + str(ca) + ':/test-ca.pem:ro\n'
        if name == 'wp':
            text += '    volumes:\n      - ' + str(warp) + ':/etc/warp\n'
        if name in ('anytls', 'mieru', 'tuic', 'shadowtls', 'snolc', 'masque'):
            text += '    networks:\n      default: {}\n      protocol_test: {}\n'
    text += '''  tg-audit:
    image: ''' + candidate['images']['php'] + '''
    entrypoint: [python3, /fixture/telegram-stub.py]
    volumes:
      - ../telegram-stub.py:/fixture/telegram-stub.py:ro
      - ../fixture/tls:/tls:ro
      - ../fixture/state:/state
    networks:
      default:
        ipv4_address: 10.10.0.250
networks:
  protocol_test:
    external: true
    name: vpnbot-protocol-test
'''
    write(BOT / 'compose.audit.yml', text)
    for name in ('compose.migration.json', 'compose.fresh.json'):
        write(BOT / name, {'services': {}})
    write(ROOT / 'active-test-bundle.json', candidate)
    write(BOT / 'update/image-bundle.json', candidate)
    shutil.copyfile(ROOT / 'rollback-bundle.json', BOT / 'update/image-bundle.previous.json')
    run('docker', 'network', 'create', '--subnet', '11.77.0.0/24',
        '--ip-range', '11.77.0.128/25', '--internal', 'vpnbot-protocol-test')
    print('START fresh-installation', flush=True)
    # A clean server starts with TeleMT only, exactly as init.sh writes it; the
    # other protocol containers are switched on through the bot further below.
    run('python3', 'scripts/protocol_modules.py', 'fresh-minimal', cwd=BOT)
    if json.loads((BOT / 'config/protocol-services.json').read_text()) != {
            n: n == 'telemt' for n in ('oc', 'ovpn', 'tt', 'hy', 'ss', 'dnstt', 'telemt', 'ipsec', 'ikev2', 'l2tp',
                                       'anytls', 'mieru', 'tuic', 'shadowtls', 'snolc', 'masque')}:
        raise RuntimeError('fresh installation must enable TeleMT only')
    config = json.loads(run('docker', 'compose', '--profile', '*', '--env-file', '.env',
                            '--env-file', 'override.env', 'config', '--format', 'json', cwd=BOT))
    validate_compose_inputs(config)
    # The service's normal image cleanup must not remove the still-unused
    # client image while initialization finishes. Owned cleanup handles failure.
    client_pin = run('docker', 'create', '--network', 'none', '--label',
                     'vpnbot.hosted-ci=true', '--entrypoint', '/bin/true', client_image).strip()
    run('python3', 'scripts/protocol_modules.py', 'compose', 'up', '-d', '--no-build', '--pull', 'never', cwd=BOT, timeout=500)
    wait_frontend()
    enable_protocols_after_fresh_install()
    ids = run('docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=vpnbot-audit').split()
    for container in json.loads(run('docker', 'inspect', *ids)):
        for bindings in (container['HostConfig'].get('PortBindings') or {}).values():
            if any(p.get('HostIp') != '127.0.0.1' for p in bindings or []):
                raise RuntimeError('a stand entrypoint is exposed outside loopback')
        names = {v.partition('=')[0] for v in container['Config'].get('Env', [])}
        if names & {'GH_TOKEN', 'GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'SSH_AUTH_SOCK'}:
            raise RuntimeError('a host credential was passed to a test container')
    # Clients are isolated network namespaces with no application/runtime mounts.
    for suffix, ip in [('wgclient', 249), ('ovpnclient', 247), ('ipsecclient', 248), ('ssclient', 246), ('warppeer', 245)]:
        run('docker', 'run', '-d', '--name', 'vpnbot-audit-' + suffix, '--label', 'vpnbot.hosted-ci=true',
            '--network', 'vpnbot-audit_default', '--ip', '10.10.0.' + str(ip), '--cap-add', 'NET_ADMIN',
            '--device', '/dev/net/tun', '--device', '/dev/ppp', '--sysctl', 'net.ipv4.conf.all.src_valid_mark=1', client_image)
    run('docker', 'rm', client_pin)
    run('docker', 'cp', ROOT / 'stand/bin/trusttunnel', 'vpnbot-audit-ssclient:/tmp/trusttunnel')
    target = ROOT / 'protocol-fixtures'
    write(target / 'private-target-ip', '10.10.0.242\n')
    run('docker', 'run', '-d', '--name', 'vpnbot-protocol-target', '--label', 'vpnbot.hosted-ci=true',
        '--network', 'vpnbot-protocol-test', '--ip', '11.77.0.2',
        '-v', str(target) + ':/fixture:ro', '-v', str(cert / 'vpnbot-protocol-test/server.pem') + ':/test.pem:ro',
        '-v', str(cert / 'vpnbot-protocol-test/server.key') + ':/test.key:ro',
        '-v', str(target / 'private-target-ip') + ':/private-target-ip:ro',
        '--entrypoint', 'python3', candidate['images']['php'], '/fixture/target.py')
    run('docker', 'network', 'connect', '--ip', '10.10.0.242', 'vpnbot-audit_default', 'vpnbot-protocol-target')
    for name in ('target_extended.py', 'target_dns.py', 'target_tls12.py', 'target_private.py'):
        run('docker', 'exec', '-d', 'vpnbot-protocol-target', 'python3', '/fixture/' + name)
    # Native host clients come exclusively from the tested images/build inputs.
    for image, src, dst in [(candidate['images']['php'], '/usr/bin/mihomo', 'clients/mihomo'),
                            (candidate['images']['php'], '/usr/bin/sing-box', 'clients/sing-box'),
                            (candidate['images']['masque'], '/usr/local/bin/xray', 'tests/xray'),
                            (candidate['images']['xr'], '/usr/bin/xray-smux', 'tests/xray-fork'),
                            (client_image, '/usr/bin/mieru', 'tests/optional-native/bin/mieru')]:
        docker_file(image, src, ROOT / dst)
    print('START fresh-users', flush=True)
    prepare_users()
    artifacts = [{'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                 for p in [ROOT / 'clients/mihomo', ROOT / 'clients/sing-box', ROOT / 'tests/xray', ROOT / 'tests/optional-native/bin/mieru']]
    write(ROOT / 'suite/client-artifacts.json', artifacts)
    with (ROOT / 'host-worker.log').open('ab') as log:
        subprocess.Popen(['bash', 'update/update.sh'], cwd=BOT, env=ENV,
                         stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    print('Fresh synthetic stand provisioned', flush=True)


def compose_services():
    return set(run('docker', 'ps', '--format', '{{.Label "com.docker.compose.service"}}',
                   '--filter', 'label=com.docker.compose.project=vpnbot-audit').split())


def enable_protocols_after_fresh_install():
    classic = ['oc', 'ovpn', 'tt', 'hy', 'ss', 'dnstt', 'ipsec']
    managed = ['anytls', 'mieru', 'tuic', 'shadowtls', 'snolc', 'masque']
    # Only TeleMT of the protocol containers runs after the clean installation.
    running = compose_services()
    if running & set(classic + managed) or 'telemt' not in running:
        raise RuntimeError('fresh installation started an unexpected protocol container set')
    # The administrator switches classic protocols on with the same menu buttons
    # as in Telegram; the host worker step then starts them for the first time.
    script = '''require '/app/config.php'; require '/app/bot.php'; require '/app/i18n.php';
class T { public function call($m, $d, $j = 0) { return ['ok' => true, 'result' => ['message_id' => 1, 'chat' => ['id' => 1]]]; } }
$b = new Bot($c['key'], $i); $b->transport = new T(); $b->admin = true;
foreach (['oc', 'ovpn', 'tt', 'hy', 'ss', 'dnstt', 'ipsec', 'ikev2', 'l2tp'] as $m) {
    $b->input = ['chat' => 1, 'from' => 1, 'message_id' => 1, 'callback_id' => 'ci', 'username' => 'ci', 'callback' => "/protocolModules $m"];
    $b->action();
}
$s = (new ProtocolModules($b->protocolModulesFile))->read();
foreach (['oc', 'ovpn', 'tt', 'hy', 'ss', 'dnstt', 'ipsec', 'ikev2', 'l2tp'] as $m) if (!$s[$m]) throw new RuntimeException("module $m is still off");
echo "enabled\n";'''
    if run('docker', 'exec', 'php-audit', 'php', '-r', script).strip() != 'enabled':
        raise RuntimeError('protocol modules were not enabled through the bot')
    run('python3', 'scripts/protocol_modules.py', 'apply', cwd=BOT, timeout=600)
    status = json.loads((BOT / 'config/protocol-services.status.json').read_text())
    missing = set(classic) - compose_services()
    if not status.get('ok') or status.get('errors') or missing:
        raise RuntimeError('first start of the enabled protocol containers failed: '
                           + ','.join(sorted(set(status.get('errors') or {}) | missing)))
    # Optional managed cores stay synthetic input, configured by the suites.
    run('docker', 'exec', 'php-audit', 'php', '-r', "require '/app/ProtocolModules.php'; (new ProtocolModules())->setMany("
        + "array_fill_keys(['anytls', 'mieru', 'tuic', 'shadowtls', 'snolc', 'masque'], true));")
    run('python3', 'scripts/protocol_modules.py', 'compose', 'up', '-d', '--no-build', '--pull', 'never', cwd=BOT, timeout=500)
    wait_frontend()
    print('Protocols enabled after the fresh installation', flush=True)


def candidate_services():
    # Import from the exact checkout; no separate, drifting service matrix.
    from image_bundle import SERVICES
    return SERVICES


def prepare_users():
    tests = ROOT / 'tests'
    drivers = {'audit-driver.php': tests / 'fresh-restore/restore-driver.php',
               'module-cycle.php': tests / 'module-cycle.php', 'telegram-http-e2e.php': tests / 'telegram-http-e2e.php',
               'managed_protocol_fixture.php': tests / 'optional-native/managed_protocol_fixture.php',
               'protocol-driver.php': tests / 'optional-native/bot_protocol_driver.php',
               'mieru-driver.php': tests / 'optional-native/mieru_driver.php',
               'tuic-driver.php': tests / 'optional-native/tuic_driver.php',
               'shadowtls-driver.php': tests / 'optional-native/shadowtls_driver.php'}
    for name, source in drivers.items():
        run('docker', 'cp', source, 'php-audit:/tmp/' + name)
    for action in [('wg-create', '0'), ('wg-create', '1'), ('init-xray',), ('ipsec-init',),
                   ('ovpn-init',), ('oc-init',), ('telemt-init',), ('ss-init',), ('dnstt-init',),
                   ('hy-init',), ('naive-init',), ('tt-init',)]:
        value = json.loads(run('docker', 'exec', 'php-audit', 'php', '/tmp/audit-driver.php', *action, timeout=300))
        if value['warnings']:
            raise RuntimeError('fresh user creation produced PHP warnings')
    for driver in ('protocol-driver.php', 'mieru-driver.php', 'tuic-driver.php', 'shadowtls-driver.php'):
        for action in ('init', 'cards'):
            run('docker', 'exec', 'php-audit', 'php', '/tmp/' + driver, action)
    code = """require '/app/config.php';require '/app/bot.php';require '/app/i18n.php';
$b=new Bot($c['key'],$i);$m=$b->protocolStore('masque');
$m->configure(['host'=>'127.0.0.1','sni'=>'masque.test','port'=>24449,
'certificate'=>'/certs/vpnbot-migration/server.crt','private_key'=>'/certs/vpnbot-migration/server.key'],true);
$b->protocolStore('snolc')->configure(['host'=>'127.0.0.1','port'=>24448],true);
$b->syncXrayProtocolUsers();$b->syncManagedUpstreams();"""
    run('docker', 'exec', 'php-audit', 'php', '-r', code)
