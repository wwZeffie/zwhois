import unittest
from unittest.mock import patch
from zwhois_lib import core
from zwhois_lib.cli import parser

class CoreTests(unittest.TestCase):
    def test_help(self):
        self.assertEqual(parser().parse_args(['-m','example.com']).targets, ['example.com'])
    def test_dates(self):
        obj = {'events':[{'eventAction':'expiration','eventDate':'2028-01-01T00:00:00Z'}]}
        text = core.report_rdap('domain','example.com',obj)
        self.assertIn('2028-01-01',text)
        self.assertIn('Not provided',text)
    def test_ip_dispatch(self):
        with patch.object(core, 'bootstrap_url', return_value='https://rdap.example/'), patch.object(core,'get_json', return_value={'name':'TEST'}):
            self.assertEqual(core.rdap_for('8.8.8.8')[0], 'ip')
            self.assertEqual(core.rdap_for('AS15169')[0], 'asn')
    def test_registered_hostname(self):
        def rdap(url):
            if '/domain/example.com' in url:
                return {'ldhName':'example.com'}
            raise core.LookupError_('404')
        with patch.object(core,'bootstrap_url', return_value='https://rdap.example/'), patch.object(core,'get_json', side_effect=rdap):
            self.assertEqual(core.registered_domain('secure.example.com')[0], 'example.com')
    def test_dig_parser(self):
        import subprocess
        stdout = ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nexample.com. 300 IN A 192.0.2.7\n'
        with patch.object(core.shutil,'which',return_value='/usr/bin/dig'), patch.object(core.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout,'')):
            self.assertEqual(core.lookup('example.com','A')[1], ['192.0.2.7'])
    def test_reject_invalid(self):
        with self.assertRaises(core.LookupError_):
            core.rdap_for('bad host with spaces')

if __name__ == '__main__':
    unittest.main()
