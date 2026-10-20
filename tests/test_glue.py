"""Offline, deterministic tests for genuine parent referral (not resolver cache) glue."""
import subprocess
import unittest
from unittest.mock import patch
from zwhois_lib import core

REFERRAL = ''';; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 2, ADDITIONAL: 4
;; AUTHORITY SECTION:
example.test.  172800 IN NS ns1.example.test.
example.test.  172800 IN NS ns2.example.test.

;; ADDITIONAL SECTION:
ns1.example.test. 172800 IN A 192.0.2.10
ns1.example.test. 172800 IN AAAA 2001:db8::10
ns2.example.test. 172800 IN A 192.0.2.20
'''

class GlueTests(unittest.TestCase):
    def test_parent_referral_parses_only_authority_delegation_and_additional_glue(self):
        with patch.object(core.shutil, 'which', return_value='/usr/bin/dig'), \
             patch.object(core.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, REFERRAL, '')) as run:
            status, names, glue, tc = core.parent_referral('example.test', '192.0.2.1')
        self.assertEqual(status, 'NOERROR')
        self.assertEqual(names, ['ns1.example.test', 'ns2.example.test'])
        self.assertEqual(glue['ns1.example.test']['AAAA'], {'2001:db8::10'})
        self.assertNotIn('AAAA', glue['ns2.example.test'])
        self.assertFalse(tc)
        self.assertIn('+norecurse', run.call_args.args[0])

    def test_no_delegation_not_mistaken_for_empty_glue(self):
        r = REFERRAL.replace('example.test.  172800 IN NS', 'other.test.  172800 IN NS')
        with patch.object(core.shutil, 'which', return_value='/usr/bin/dig'), \
             patch.object(core.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, r, '')):
            _, ns, _, _ = core.parent_referral('example.test', '192.0.2.1')
        self.assertEqual(ns, [])

    def test_truncation_flag_detected(self):
        r = REFERRAL.replace('flags: qr;', 'flags: qr tc;')
        with patch.object(core.shutil, 'which', return_value='/usr/bin/dig'), \
             patch.object(core.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, r, '')):
            _, _, _, tc = core.parent_referral('example.test', '192.0.2.1')
        self.assertTrue(tc)

    def test_missing_ipv6_glue_is_warning_not_protocol_violation(self):
        def fake_lookup(name, typ):
            if name == 'test' and typ == 'NS':
                return 'NOERROR', ['a.parent.test.','b.parent.test.']
            if name.startswith(('a.parent','b.parent')) and typ == 'A':
                return 'NOERROR', ['192.0.2.1']
            return 'NOERROR', []
        def fake_referral(domain, ip, tcp=False):
            return 'NOERROR', ['ns1.example.test'], {'ns1.example.test': {'A': {'192.0.2.10'}}}, False
        def fake_dig(name, typ, **kwargs):
            return 'NOERROR', [(name,typ,'2001:db8::10' if typ == 'AAAA' else '192.0.2.10')]
        with patch.object(core, 'lookup', side_effect=fake_lookup), \
             patch.object(core, 'parent_referral', side_effect=fake_referral), \
             patch.object(core, 'dig', side_effect=fake_dig):
            report = '\n'.join(core.parent_glue_report('example.test'))
        self.assertIn('PASS: ns1.example.test A matches child zone', report)
        self.assertIn('MISSING FROM PARENT GLUE', report)
        self.assertIn('2001:db8::10', report)

    def test_child_glue_mismatch(self):
        def fake_lookup(name, typ):
            if name == 'test' and typ == 'NS':
                return 'NOERROR', ['a.parent.test.']
            if name == 'a.parent.test' and typ == 'A':
                return 'NOERROR', ['192.0.2.1']
            return 'NOERROR', []
        def fake_referral(*_args, **_kwargs):
            return 'NOERROR', ['ns.example.test'], {'ns.example.test':{'A':{'192.0.2.11'}}}, False
        with patch.object(core, 'lookup', side_effect=fake_lookup), \
             patch.object(core, 'parent_referral', side_effect=fake_referral), \
             patch.object(core, 'dig', return_value=('NOERROR',[('ns.example.test','A','192.0.2.10')])):
            report = '\n'.join(core.parent_glue_report('example.test'))
        self.assertIn('GLUE MISMATCH', report)

    def test_spamhaus_policy_error_is_inconclusive(self):
        with patch.object(core, 'mx_hosts', return_value=('NOERROR', [])), \
             patch.object(core, 'lookup', side_effect=lambda name, typ: ('NOERROR', ['8.8.8.8']) if name=='example.test' and typ=='A' else ('NOERROR', ['127.255.255.254']) if name.endswith('zen.spamhaus.org') else ('NXDOMAIN', [])):
            report = '\n'.join(core.blacklist_report('example.test', {'dnsbls':['zen.spamhaus.org']}))
        self.assertIn('INCONCLUSIVE', report)
        self.assertIn('127.255.255.254', report)

if __name__ == '__main__':
    unittest.main()

class HostnameDelegationTests(unittest.TestCase):
    def test_host_zone_shadowing_is_warned(self):
        def fake_lookup(name, typ):
            if name == 'example.test' and typ == 'NS':
                return 'NOERROR', ['ns.example.test.']
            if name == 'ns.example.test' and typ == 'A':
                return 'NOERROR', ['192.0.2.10']
            return 'NOERROR', []
        with patch.object(core, 'lookup', side_effect=fake_lookup), \
             patch.object(core, 'parent_referral', return_value=('NOERROR', [], {}, False)), \
             patch.object(core, 'dig', return_value=('NOERROR',[('secure.example.test','SOA','ns.example.test. hostmaster.example.test. 123 1 1 1 1')])):
            result = '\n'.join(core.hostname_delegation_report('example.test','secure.example.test'))
        self.assertIn('shadow zone', result)

class DirectAuthoritativeQueryTests(unittest.TestCase):
    def test_direct_lame_server_cannot_pass(self):
        response=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd; QUERY: 1\nexample.test. 300 IN SOA ns1.example.test. hostmaster.example.test. 44 1 1 1 1\n'
        with patch.object(core.shutil, 'which', return_value='/usr/bin/dig'), \
             patch.object(core.subprocess, 'run',return_value=subprocess.CompletedProcess([],0,response,'')):
            status, answer=core.dig('example.test','SOA',server='192.0.2.1',family=4)
        self.assertEqual(status,'NONAUTHORITATIVE')
