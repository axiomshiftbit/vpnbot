#!/usr/bin/env python3
"""Installation primitives for the node-only mode; no credentials in templates."""
import base64
import os
from pathlib import Path
import pwd
import re
import shutil

import node_config as config
import node_state as state
from node_runtime import command

LIB = Path('/usr/local/lib/vpnbot-node')
ETC = Path('/etc/vpnbot-node')
CONTROL = 'vpnbot-ctl'
CORE = 'vpnbot-core'
COVER = 'vpnbot-cover'
AWG = 'vpnbot-awg'
RPC_COMMAND = '/usr/bin/sudo -n -- /usr/bin/python3 -I /usr/local/lib/vpnbot-node/node_manager.py rpc'


def public_key(value):
    fields = value.strip().split()
    if len(fields) < 2 or fields[0] != 'ssh-ed25519' or not re.fullmatch(r'[A-Za-z0-9+/]{68}', fields[1]):
        raise ValueError('an ED25519 public key is required')
    try:
        raw = base64.b64decode(fields[1], validate=True)
    except ValueError as error:
        raise ValueError('invalid public key') from error
    if len(raw) != 51 or raw[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':
        raise ValueError('invalid public key')
    return 'ssh-ed25519 '+fields[1]


def ssh_configuration(effective):
    # AllowUsers/AllowGroups accumulate. Preserve existing restrictions while
    # adding only the dedicated identity; never introduce a global restriction
    # on a machine that did not have one before.
    lines = []
    for field in ('allowusers', 'allowgroups'):
        values = []
        for line in effective.splitlines():
            if line.startswith(field+' '):
                values.extend(line.split()[1:])
        if values:
            if any(not re.fullmatch(r'[A-Za-z0-9_.*?!@:/%+\[\]-]+', value) for value in values):
                raise ValueError('existing SSH access policy requires manual integration')
            lines.append(('AllowUsers' if field == 'allowusers' else 'AllowGroups')+' '+CONTROL)
    lines += ['Match User '+CONTROL,
              '    AuthorizedKeysFile /etc/vpnbot-node/controller.pub',
              '    AuthenticationMethods publickey', '    PubkeyAuthentication yes',
              '    PasswordAuthentication no', '    KbdInteractiveAuthentication no',
              # PermitUserEnvironment is global-only. The root-owned empty home
              # and fixed authorized-key file provide no user-writable env source.
              '    PermitTTY no', '    PermitUserRC no',
              '    DisableForwarding yes', '    AllowTcpForwarding no', '    AllowStreamLocalForwarding no',
              '    AllowAgentForwarding no', '    X11Forwarding no', '    PermitTunnel no',
              '    MaxSessions 1', '    ForceCommand '+RPC_COMMAND, 'Match all', '']
    return '\n'.join(lines)


def sudo_configuration():
    return ('Defaults:'+CONTROL+' !setenv, !log_input, !log_output, !use_pty\n'
            +CONTROL+' ALL=(root) NOPASSWD: NOLOG_INPUT: NOLOG_OUTPUT: '
            '/usr/bin/python3 -I /usr/local/lib/vpnbot-node/node_manager.py rpc\n')


def units():
    executable = '/usr/bin/python3 -I /usr/local/lib/vpnbot-node/node_manager.py '
    hardening = ('User=root\nGroup=root\nUMask=0077\nEnvironment=GODEBUG=multipathtcp=0\n'
                 'Environment=HOME=/var/lib/vpnbot-node\nNoNewPrivileges=yes\nPrivateTmp=yes\n'
                 'ProtectSystem=strict\nProtectHome=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\n'
                 'ProtectControlGroups=yes\nReadWritePaths=/var/lib/vpnbot-node /etc/vpnbot-node\n'
                 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n'
                 'StandardOutput=null\nStandardError=journal\n')
    result = {}
    for name, action, extra in [('vpnbot-node', 'boot', 'RemainAfterExit=yes\nExecStop='+executable+'stop\n'),
                                ('vpnbot-node-worker', 'worker', ''), ('vpnbot-node-watch', 'watch', ''),
                                ('vpnbot-node-renew', 'renew', '')]:
        result[name+'.service'] = ('[Unit]\nDescription=VPNBot managed node '+action+'\n'
            'After=docker.service nftables.service network-online.target\nWants=network-online.target\n'
            'Requires=docker.service\n\n[Service]\nType=oneshot\n'+hardening+
            'TimeoutStartSec=600\nExecStart='+executable+action+'\n'+extra+
            ('\n[Install]\nWantedBy=multi-user.target\n' if name == 'vpnbot-node' else ''))
    # The code phase of a full update writes the same host paths as a manual
    # node_setup.py --upgrade-code (library, units, nftables, sysctl, clone):
    # it cannot run inside the worker sandbox. Its input is only a commit of
    # a published bundle that is reachable from the release branch.
    result['vpnbot-node-upgrade.service'] = ('[Unit]\nDescription=VPNBot managed node code upgrade\n'
        'After=docker.service nftables.service network-online.target\nWants=network-online.target\n'
        'Requires=docker.service\n\n[Service]\nType=oneshot\nUser=root\nGroup=root\nUMask=0077\n'
        'Environment=HOME=/root\nStandardOutput=null\nStandardError=journal\n'
        'TimeoutStartSec=1800\nExecStart='+executable+'upgrade\n')
    result['vpnbot-node-watch.timer'] = ('[Unit]\nDescription=VPNBot node recovery timer\n'
        '[Timer]\nOnBootSec=30s\nOnUnitActiveSec=15s\nAccuracySec=1s\n'
        '[Install]\nWantedBy=timers.target\n')
    result['vpnbot-node-renew.timer'] = ('[Unit]\nDescription=VPNBot node certificate renewal\n'
        '[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=yes\n'
        '[Install]\nWantedBy=timers.target\n')
    return result


def accounts():
    for name, shell in [(CONTROL, '/bin/sh'), (CORE, '/usr/sbin/nologin'), (COVER, '/usr/sbin/nologin'), (AWG, '/usr/sbin/nologin')]:
        try:
            account = pwd.getpwnam(name)
            if not (ETC/'deployment.json').exists():
                raise ValueError('account name is already in use')
            if account.pw_uid < 100 or account.pw_shell != shell:
                raise ValueError('incompatible service account')
        except KeyError:
            command(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/var/empty/'+name,
                     '--shell', shell, name])
            # An impossible password permits key-only authentication even with UsePAM=no.
            command(['usermod', '--password', '*', name])
        home = Path('/var/empty')/name
        state.trusted(home)
        home.mkdir(mode=0o755, parents=True, exist_ok=True)
    return pwd.getpwnam(CORE)


def install_code(source):
    for directory in (LIB, ETC, Path('/var/lib/vpnbot-node')):
        state.trusted(directory)
        directory.mkdir(mode=0o755 if directory == LIB else 0o700, parents=True, exist_ok=True)
    # The control user must traverse ETC to read only its root-owned public key.
    os.chmod(ETC, 0o711)
    # Read every module first: a missing or unreadable source file must fail
    # before the first write, never leave old and new modules mixed.
    modules = {name: (Path(source)/name).read_bytes() for name in (
        'node_manager.py', 'node_runtime.py', 'node_config.py', 'node_xray.py', 'node_dpi.py', 'node_cover.py',
        'node_wg.py', 'node_awg.py', 'node_state.py', 'node_upgrade.py', 'image_bundle.py')}
    services = units()
    for name, data in modules.items():
        state.atomic(LIB/name, data, 0o644)
    for name, text in services.items():
        state.atomic(Path('/etc/systemd/system')/name, text.encode(), 0o644)
    command(['systemctl', 'daemon-reload'])


def restore_ssh(original):
    for path, content in original.items():
        if content is None:
            path.unlink(missing_ok=True)
        else:
            state.atomic(path, content, 0o440 if path == Path('/etc/sudoers.d/vpnbot-node') else 0o644)
    command(['sshd', '-t'])
    command(['systemctl', 'reload', 'ssh.service'])


def install_ssh(key, sources):
    key = public_key(key)
    sources = [config.public_ip(address) for address in sources]
    if not sources or len(sources) > 32:
        raise ValueError('trusted controller addresses are required')
    dropin = Path('/etc/ssh/sshd_config.d/00-vpnbot-node.conf')
    sudoers = Path('/etc/sudoers.d/vpnbot-node')
    authorized = ETC/'controller.pub'
    for path in (dropin, sudoers, authorized):
        state.trusted(path)
    original = {path: path.read_bytes() if path.exists() else None for path in (dropin, sudoers, authorized)}
    effective = command(['sshd', '-T']).stdout.decode()
    try:
        state.atomic(authorized, ('restrict,from="'+','.join(sources)+'" '+key+'\n').encode(), 0o644)
        state.atomic(sudoers, sudo_configuration().encode(), 0o440)
        command(['visudo', '-c', '-f', sudoers])
        state.atomic(dropin, ssh_configuration(effective).encode(), 0o644)
        command(['sshd', '-t'])
        for source in sources:
            output = command(['sshd', '-T', '-C', f'user={CONTROL},host=node,addr={source}']).stdout.decode()
            expected = ['forcecommand '+RPC_COMMAND, 'disableforwarding yes', 'permittty no',
                        'passwordauthentication no', 'authenticationmethods publickey', 'permituserrc no']
            if any(line not in output.splitlines() for line in expected):
                raise ValueError('existing SSH policy overrides node restrictions')
        command(['systemctl', 'reload', 'ssh.service'])
    except Exception:
        restore_ssh(original)
        raise
    return original
