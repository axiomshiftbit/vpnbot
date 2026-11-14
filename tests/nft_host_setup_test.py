import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import nft_host_setup as nft

FULL = '''#!/usr/sbin/nft -f
flush ruleset
define PUBLIC_IP = 11.77.0.3
table ip filter {
 chain input { type filter hook input priority 0; policy drop;
 iifname "eth0" ip daddr $PUBLIC_IP tcp dport 22 accept
 }
}
table ip6 filter {
 set node6_sources { type ipv6_addr; elements = { 2606:4700:4700::2 }; }
 set node6_public { type ipv6_addr; }
 map egress6_snat { type ipv6_addr : ipv6_addr; }
 set ipv6_routers { type ipv6_addr; }
}
'''
NODE = '''#!/usr/sbin/nft -f
# VPNBOT_MANAGED_NODE_HOST
flush ruleset
define PUBLIC_IP = 11.77.0.3
table ip filter {
 chain ssh { accept; }
 chain input { type filter hook input priority 0; policy drop;
 iifname "lo" accept
 ct state established,related accept
 iifname "eth0" ip saddr 11.77.0.2 tcp dport 22 ct state new tcp flags & (fin|syn|rst|ack) == syn jump ssh
 }
}
table ip6 filter {
 set node6_sources { type ipv6_addr; }
 set node6_public { type ipv6_addr; }
 set ipv6_routers { type ipv6_addr; }
 chain ssh { accept; }
 chain input { type filter hook input priority 0; policy drop;
 iifname "lo" accept
 ct state established,related accept
 iifname "eth0" ip6 saddr @node6_sources tcp dport 22 ct state new tcp flags & (fin|syn|rst|ack) == syn jump ssh
 }
}
'''
HOST = dict(interface='ens3', public4='11.77.0.4', public6='2606:4700:4700::1111',
            routers=['fe80::1'], sources6=['2606:4700:4700::3'],
            sources=['11.77.0.2', '2606:4700:4700::2'],
            admins=['11.77.0.3', '2606:4700:4700::3'], ssh_ports=[2222],
            ssh_networks=['11.77.0.128/25', '2606:4700:4700::200/120'])


class HostFirewallTest(unittest.TestCase):
    def test_service_is_started_only_for_an_inactive_node(self):
        import os, subprocess, tempfile
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / 'nftables.conf'
            profile.write_text('# profile\n')
            for mode, active, expected in (('node', 1, True), ('node', 0, False), ('full', 1, False)):
                calls = []
                with self.subTest(mode=mode, active=active), \
                        patch.object(nft.os, 'open', return_value=os.open(os.devnull, os.O_RDONLY)), \
                        patch.object(nft.fcntl, 'flock'), patch.object(nft, 'ensure', return_value=False), \
                        patch.object(nft, 'run', side_effect=lambda args, data=None: calls.append(list(args)) or ''), \
                        patch.object(nft.subprocess, 'run', return_value=subprocess.CompletedProcess([], active)):
                    nft.configure(profile, host={}, mode=mode)
                self.assertIn(['systemctl', 'enable', 'nftables.service'], calls)
                self.assertEqual(expected, ['systemctl', 'start', 'nftables.service'] in calls)

    def test_management_binding_does_not_move_legacy_asn_port(self):
        prepared = nft.render(NODE, HOST, 'node')
        prepared = 'define SERVER_SSH_PORTS = { 2222 }\n'+prepared
        out = nft.render(prepared, HOST | {'ssh_ports': [7384]}, 'node')
        self.assertIn('define NODE_SSH_PORTS = { 2222 }', out)
        self.assertIn('define SERVER_SSH_PORTS = { 7384 }', out)
        for version in (4, 6):
            for name in ('admins', 'ssh'):
                self.assertIn('@node'+str(version)+'_'+name+' tcp dport $SERVER_SSH_PORTS', out)
        self.assertEqual(out, nft.render(out, HOST | {'ssh_ports': [7384]}, 'node'))

    def test_full_addresses_keep_trust_and_no_public_ingress(self):
        out = nft.render(FULL, HOST, 'full')
        self.assertIn('define PUBLIC_IP = 11.77.0.4', out)
        self.assertIn('fd42:7662:6::9 : 2606:4700:4700::1111', out)
        self.assertIn('2606:4700:4700::2, 2606:4700:4700::3', out)
        self.assertIn('iifname "ens3"', out)
        self.assertEqual(out, nft.render(out, HOST, 'full'))
        self.assertIn('flush ruleset', out)
        self.assertEqual(out.count(' accept'), FULL.count(' accept'))

    def test_node_installer_sources_admins_ports_and_not_container_snat(self):
        out = nft.render(NODE, HOST, 'node')
        self.assertIn('define NODE_SSH_PORTS = { 2222 }', out)
        for v in (4, 6):
            for name in ('sources', 'admins', 'ssh'):
                self.assertIn('set node'+str(v)+'_'+name, out)
        self.assertIn('ct status dnat', out)
        self.assertNotIn('egress6_snat', out)
        self.assertEqual(out, nft.render(out, HOST, 'node'))

    def test_no_ipv6_clears_own_addresses_only(self):
        out = nft.render(nft.render(FULL, HOST, 'full'), HOST|{'public6':'', 'sources6':[]}, 'full')
        self.assertNotIn('fd42:7662:6::9 :', out)
        self.assertNotIn('2606:4700:4700::1111', out)
        self.assertIn('2606:4700:4700::2', out)

    def test_node_vpn_only_channels_follow_guard_with_literal_or_defined_wan(self):
        for defined in (False, True):
            text = nft.render(NODE, HOST, 'node')
            if defined:
                text = text.replace('flush ruleset', 'define WAN = "ens3"\nflush ruleset').replace('iifname "ens3"', 'iifname $WAN')
            # Reproduce the old base profile: TCP was supported, reserve UDP
            # still required installer source lists. Upgrade adds it once.
            text = '\n'.join(line for line in text.splitlines() if not ('ct status dnat ct original proto-dst { 51820, 51821 }' in line and 'saddr' not in line))+'\n'
            host = HOST | {'interface':'eth0.100', 'ssh_ports':[2222,7384]}
            out = nft.render(text, host, 'node')
            for version in (4,6):
                family = 'ip' if version == 4 else 'ip6'
                a,b = nft.block(out, r'^\s*table\s+'+family+r'\s+filter\s*\{')
                rules = out[a:b]
                prefix = 'iifname $WAN' if defined else 'iifname "eth0.100"'
                for ports in ('443 tcp dport 8443', '{ 51820, 51821 } udp dport { 51830, 51831 }'):
                    self.assertEqual(rules.count(prefix+' ct status dnat ct original proto-dst '+ports+' counter accept'), 1)
                self.assertIn('saddr @node'+str(version)+'_admins tcp dport $NODE_SSH_PORTS', rules)
            self.assertEqual(out, nft.render(out, host, 'node'))

    def test_wrong_modes_injection_private_addresses_are_rejected(self):
        for mode, text in [('node',FULL), ('full',NODE)]:
            with self.assertRaises(ValueError): nft.render(text, HOST, mode)
        for field, value in [('interface','eth0" accept'), ('public6','::ffff:11.77.0.4'),
                             ('public4','127.0.0.1'), ('routers',['2606:4700:4700::1111'])]:
            with self.assertRaises(ValueError): nft.render(FULL, HOST|{field:value}, 'full')

    def test_existing_snat_other_keys_and_comments_preserved(self):
        text=FULL.replace('map egress6_snat { type ipv6_addr : ipv6_addr; }',
             'map egress6_snat { type ipv6_addr : ipv6_addr; # }\n elements = { fd42:7662:6::8 : 2606:4700:4700::2 }; }')
        out=nft.render(text, HOST, 'full')
        self.assertIn('fd42:7662:6::8 : 2606:4700:4700::2',out)

    def test_commented_examples_and_newline_terminated_type(self):
        text=FULL.replace('map egress6_snat { type ipv6_addr : ipv6_addr; }',
                          'map egress6_snat {\n type ipv6_addr : ipv6_addr\n # elements = { example }\n }')
        out=nft.render(text,HOST,'full')
        active='\n'.join(line for line in out.splitlines() if not line.lstrip().startswith('#'))
        self.assertIn('elements = { fd42:7662:6::9 : 2606:4700:4700::1111 }',active)
        self.assertNotIn('ipv6_addr elements',active)

    def test_nft_singleton_anonymous_set_roundtrip_is_equivalent(self):
        value={'prefix':{'addr':'10.10.0.0','len':23}}
        self.assertEqual(nft.clean({'set':[value]}),nft.clean(value))

    def test_unknown_live_chain_refuses_and_foreign_tables_untouched(self):
        rule={'family':'ip','table':'filter','chain':'input','expr':[{'accept':None}]}
        old={'nftables':[{'table':{'family':'ip','name':'filter'}},{'rule':rule}]}
        new=copy.deepcopy(old);new['nftables'][1]['rule']['expr']=[{'drop':None}]
        live=copy.deepcopy(old)
        live['nftables'] += [{'table':{'family':'inet','name':'foreign'}}]
        change, reverse=nft.delta(old,new,live)
        self.assertNotIn('foreign',json.dumps(change)+json.dumps(reverse))
        self.assertEqual(len(change['nftables']),2)
        self.assertEqual(change['nftables'][0],{'flush':{'chain':{'family':'ip','table':'filter','name':'input'}}})
        live['nftables'].append({'rule':rule|{'expr':[{'drop':None}]}})
        with self.assertRaises(ValueError): nft.delta(old,new,live)

    def test_counter_activity_does_not_hide_drift_or_block_update(self):
        a={'counter':{'packets':1,'bytes':40}}
        b={'counter':{'packets':90,'bytes':4000}}
        self.assertEqual(nft.clean(a),nft.clean(b))
        self.assertNotEqual(nft.clean(a),nft.clean({'accept':None}))

    def test_included_runtime_guards_are_not_owned_by_installer(self):
        doc={'nftables':[{'table':{'family':'ip','name':'filter'}},
                         {'table':{'family':'inet','name':'vpnbot_node'}},
                         {'set':{'family':'inet','table':'vpnbot_node','name':'ipv6_routers','type':'ipv6_addr'}}]}
        selected=nft.profile_rules(doc,FULL+'include "/etc/vpnbot-node/guard*.nft"\n')
        self.assertEqual(selected,{'nftables':[doc['nftables'][0]]})

    def test_missing_live_set_is_repaired_even_when_disk_is_current(self):
        table={'table':{'family':'ip6','name':'filter'}}
        definition={'set':{'family':'ip6','table':'filter','name':'node6_public','type':'ipv6_addr','elem':['2606:4700:4700::1111']}}
        doc={'nftables':[table,definition]}
        change,reverse=nft.delta(doc,doc,{'nftables':[table]})
        self.assertEqual(change['nftables'][0]['add']['set']['name'],'node6_public')
        self.assertEqual(reverse['nftables'][0]['delete']['set']['name'],'node6_public')

    def test_empty_sets_do_not_emit_invalid_empty_element_commands(self):
        table={'table':{'family':'ip6','name':'filter'}}
        definition={'set':{'family':'ip6','table':'filter','name':'node6_public','type':'ipv6_addr'}}
        doc={'nftables':[table,definition]}
        change,reverse=nft.delta(doc,doc,{'nftables':[table]})
        self.assertTrue(change['nftables'])
        for command in change['nftables']+reverse['nftables']:
            self.assertNotIn('element',command.get('add',{}))

    def test_discover_no_network_probe_or_unstable_source(self):
        from subprocess import CompletedProcess
        route=json.dumps([{'dev':'ens3','prefsrc':'11.77.0.4'}])
        addresses=json.dumps([{'addr_info':[{'family':'inet','scope':'global','local':'11.77.0.4'}]}])
        with patch.object(nft.subprocess,'run',side_effect=[CompletedProcess([],0,route),CompletedProcess([],1,'')]), patch.object(nft,'run',return_value=addresses):
            self.assertEqual(nft.discover()['public4'],'11.77.0.4')
        with patch.object(nft.subprocess,'run',return_value=CompletedProcess([],0,route)), patch.object(nft,'run',return_value=addresses.replace('"scope": "global"','"scope": "global", "temporary": true')):
            with self.assertRaises(ValueError): nft.discover()


if __name__=='__main__': unittest.main()
