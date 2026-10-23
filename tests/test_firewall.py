import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_controller import load

firewall = load('discover-firewall')
SCRIPT = str(Path(__file__).resolve().parents[1] / 'scripts/discover-firewall')


def integration(script, parent_netns):
    # Refuse to execute mutating integration checks in the caller's namespace.
    assert os.stat('/proc/self/ns/net').st_ino != parent_netns
    assert os.geteuid() == 0

    def call(*args, data=None, ok=True):
        result = subprocess.run(args, input=data, universal_newlines=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        assert (result.returncode == 0) == ok, (args, result.stdout, result.stderr)
        return result

    def discover():
        return json.loads(call(script).stdout)

    def apply(tcp, udp):
        return json.loads(call(script, '--apply', json.dumps({'tcp': tcp, 'udp': udp})).stdout)

    def restore(saved):
        with tempfile.NamedTemporaryFile(mode='w') as out:
            json.dump(saved, out)
            out.flush()
            return json.loads(call(script, '--restore', out.name).stdout)

    call('nft', '-f', '-', data='''table inet old {
 chain input { type filter hook input priority 0; policy drop;
 ip saddr 192.0.2.0/24 tcp dport 22 counter accept
 }
}
''')
    original = discover()
    assert original['source_rules'] and original['explicit_inbound_accepts']
    assert original['allowed_tcp'] is None and original['ssh22'] is None
    saved = json.loads(call(script, '--snapshot').stdout)
    assert apply([22, 80, 443], [53])['allowed_tcp'] == [22, 80, 443]
    assert apply([22, 443], []) == discover()
    assert restore(saved) == original
    for hook in ('type nat hook prerouting priority -100; policy accept;',
                 'type filter hook forward priority 0; policy drop;',
                 'type filter hook output priority 0; policy accept; tcp dport 25 drop'):
        call('nft', '-f', '-', data='flush ruleset\ntable inet bad {\n chain bad {\n' + hook + '\n }\n}\n')
        before = discover()
        call(script, '--apply', '{"tcp":[22],"udp":[]}', ok=False)
        assert discover() == before
    call('nft', 'flush', 'ruleset')
    for prefix in ('iptables', 'ip6tables'):
        call(prefix, '-A', 'INPUT', '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT')
        call(prefix, '-A', 'FORWARD', '-j', 'DROP')
        call(prefix, '-A', 'OUTPUT', '-p', 'tcp', '--dport', '25', '-j', 'REJECT')
        call(prefix, '-t', 'nat', '-A', 'POSTROUTING', '-j', 'MASQUERADE')
    # Docker embedded DNS uses OUTPUT DNAT plus POSTROUTING SNAT. These are
    # unsafe to flush through nft, but must survive the iptables INPUT path.
    call('iptables', '-t', 'nat', '-N', 'DOCKER_OUTPUT')
    call('iptables', '-t', 'nat', '-A', 'OUTPUT', '-d', '127.0.0.11', '-j', 'DOCKER_OUTPUT')
    call('iptables', '-t', 'nat', '-A', 'DOCKER_OUTPUT', '-p', 'udp', '--dport', '53',
         '-j', 'DNAT', '--to-destination', '127.0.0.11:55212')
    original = discover()
    assert original['backend'] == 'iptables'
    saved = json.loads(call(script, '--snapshot').stdout)
    assert apply([22, 443], [53])['allowed_tcp'] == [22, 443]
    first = discover()
    assert apply([22, 443], [53]) == first
    for family in ('ip', 'ip6'):
        observed = discover()['rules']['iptables'][family]
        expected = original['rules']['iptables'][family]
        assert observed['nat'] == expected['nat']
        rules = observed['filter']['rules']
        assert [rule for rule in rules if rule[1] == 'INPUT'][0] == ['-A', 'INPUT', '-j', 'CCDC_INPUT']
        for chain in ('FORWARD', 'OUTPUT'):
            assert [r for r in rules if r[1] == chain] == [r for r in expected['filter']['rules'] if r[1] == chain]
        # Unsolicited IPv6 echo is not approved; neighbor discovery is explicit.
        if family == 'ip6':
            icmp = [r for r in rules if 'ipv6-icmp' in r]
            assert len(icmp) == 4 and all('--icmpv6-type' in r for r in icmp)
    assert restore(saved)['rules']['iptables'] == original['rules']['iptables']
    call('nft', '-f', '-', data='table inet native {\n chain input {\n type filter hook input priority -10; policy drop;\n }\n}\n')
    before = discover()
    assert before['backend'] == 'mixed'
    call(script, '--apply', '{"tcp":[22],"udp":[]}', ok=False)
    assert discover() == before
    call('nft', 'flush', 'ruleset')
    call('nft', '-f', '-', data='table inet firewalld {\n chain input {\n type filter hook input priority 0; policy drop;\n }\n}\n')
    before = discover()
    call(script, '--apply', '{"tcp":[22],"udp":[]}', ok=False)
    assert discover() == before and before['rules']['managers'] == ['firewalld']


class FirewallTests(unittest.TestCase):
    def test_backend_self_checks_include_second_family_failure_rollback(self):
        with contextlib.redirect_stdout(io.StringIO()):
            firewall.self_test()

    def test_docker_dns_nat_is_compat_only_when_save_tools_account_for_it(self):
        raw = ('*nat\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n'
               ':DOCKER_OUTPUT - [0:0]\n:DOCKER_POSTROUTING - [0:0]\n'
               '-A OUTPUT -d 127.0.0.11/32 -j DOCKER_OUTPUT\n'
               '-A POSTROUTING -d 127.0.0.11/32 -j DOCKER_POSTROUTING\n'
               '-A DOCKER_OUTPUT -d 127.0.0.11/32 -p udp --dport 53 -j DNAT --to-destination 127.0.0.11:55212\n'
               '-A DOCKER_POSTROUTING -s 127.0.0.11/32 -p udp --sport 55212 -j SNAT --to-source :53\n'
               'COMMIT\n')
        entries = [{'table': {'family': 'ip', 'name': 'nat'}}]
        for name, hook, priority in [('OUTPUT', 'output', -100), ('POSTROUTING', 'postrouting', 100)]:
            entries.append({'chain': {'family': 'ip', 'table': 'nat', 'name': name,
                                      'hook': hook, 'type': 'nat', 'prio': priority, 'policy': 'accept'}})
        for name in ('DOCKER_OUTPUT', 'DOCKER_POSTROUTING'):
            entries.append({'chain': {'family': 'ip', 'table': 'nat', 'name': name}})
        for chain, expression in [('OUTPUT', {'jump': {'target': 'DOCKER_OUTPUT'}}),
                                  ('POSTROUTING', {'jump': {'target': 'DOCKER_POSTROUTING'}}),
                                  ('DOCKER_OUTPUT', {'xt': {'name': 'DNAT', 'type': 'target'}}),
                                  ('DOCKER_POSTROUTING', {'xt': {'name': 'SNAT', 'type': 'target'}})]:
            entries.append({'rule': {'family': 'ip', 'table': 'nat', 'chain': chain, 'expr': [expression]}})
        info = {'nft': entries, 'tables': {}, 'impl': {}, 'extra_legacy': {}}
        self.assertEqual(firewall.choose_backend(info), 'nftables')
        with self.assertRaisesRegex(firewall.Refusal, 'nft replacement refuses'):
            firewall.check_nft_replacement(entries)
        info.update(tables={'ip': firewall.parse_save(raw), 'ip6': {}},
                    impl={'ip': 'nf_tables', 'ip6': 'nf_tables'})
        self.assertEqual(firewall.choose_backend(info), 'iptables')
        program = firewall.iptables_program(info['tables']['ip'], {'tcp': [22, 80, 9000], 'udp': []})
        self.assertTrue(program.startswith('*filter\n'))
        self.assertNotIn('nat', program)

    def test_counters_change_neither_rules_nor_hints_but_limits_remain_semantic(self):
        before = {'nftables': [{'rule': {'family': 'inet', 'table': 'test', 'chain': 'input',
                   'handle': 1, 'expr': [{'counter': {'packets': 10, 'bytes': 50}},
                                       {'limit': {'rate': 10, 'burst': 5, 'rate_unit': 'bytes'}}]}}]}
        after = copy.deepcopy(before)
        after['nftables'][0]['rule']['handle'] = 99
        after['nftables'][0]['rule']['expr'][0]['counter']['packets'] = 100
        self.assertEqual(firewall.normalize_nft(before), firewall.normalize_nft(after))
        after['nftables'][0]['rule']['expr'][1]['limit']['rate'] = 20
        self.assertNotEqual(firewall.normalize_nft(before), firewall.normalize_nft(after))

    def test_conditional_accept_is_reported_without_claiming_reachability(self):
        tables = firewall.parse_save('*filter\n:INPUT DROP [0:0]\n-A INPUT -s 192.0.2.0/24 -p tcp --dport 22 -j ACCEPT\nCOMMIT\n')
        info = {'backend': 'iptables', 'nft': [], 'tables': {'ip': tables, 'ip6': tables},
                'extra_legacy': {}, 'managers': []}
        state = firewall.state(info)
        self.assertIsNone(state['ssh22'])
        self.assertIsNone(state['allowed_tcp'])
        self.assertEqual(state['default_inbound'], 'drop')
        self.assertTrue(state['source_rules'])
        self.assertEqual(state['explicit_inbound_accepts'][0]['ports'], ['22'])

    @unittest.skipUnless(all(shutil.which(tool) for tool in ('unshare', 'nft', 'iptables', 'ip6tables')), 'namespace/firewall tools unavailable')
    def test_isolated_kernel_enforcement_and_full_rollback(self):
        probe = subprocess.run(['unshare', '-Urn', 'true'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if probe.returncode:
            self.skipTest('unprivileged user/network namespaces unavailable')
        parent = os.stat('/proc/self/ns/net').st_ino
        code = ('import sys; sys.path.insert(0, ' + repr(str(Path(__file__).parent)) + '); '
                'from test_firewall import integration; integration(' + repr(SCRIPT) + ', ' + str(parent) + ')')
        result = subprocess.run(['unshare', '-Urn', sys.executable, '-c', code],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
