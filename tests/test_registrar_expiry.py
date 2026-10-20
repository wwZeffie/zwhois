"""Offline regression tests for correct RDAP expiration provenance."""
import io
import json
import unittest
from unittest.mock import patch
from zwhois_lib import core


def registry_obj(registrar_date=None):
    events = [
        {'eventAction': 'registration', 'eventDate': '2005-01-25T03:18:10Z'},
        {'eventAction': 'expiration', 'eventDate': '2028-01-25T03:18:10Z'},
    ]
    if registrar_date:
        events.append({'eventAction': 'registrar expiration', 'eventDate': registrar_date})
    return {
        'ldhName': 'thelinuxpros.com',
        'events': events,
        'entities': [{
            'roles': ['registrar'], 'handle': '48',
            'publicIds': [{'type': 'IANA Registrar ID', 'identifier': '48'}],
            'vcardArray': ['vcard', [['fn', {}, 'text', 'eNom, LLC']]]
        }],
        'nameservers': [{'ldhName': 'ns1.thelinuxpros.com'}],
    }


class ExpiryTests(unittest.TestCase):
    def test_iana_csv_services(self):
        data = b'ID,Registrar Name,Status,RDAP Base URL\n48,"eNom, LLC",Accredited,https://enom.rdap.tucows.com/\n2,Other,Accredited,http://insecure.example/\n'
        class Context:
            def __enter__(self):
                return io.BytesIO(data)
            def __exit__(self, *args):
                pass
        core.registrar_services.cache_clear()
        try:
            with patch.object(core.urllib.request, 'urlopen', return_value=Context()) as mock:
                self.assertEqual(core.registrar_services(), {'48': 'https://enom.rdap.tucows.com/'})
                mock.assert_called_once()
        finally:
            core.registrar_services.cache_clear()

    def test_registrar_rdap_used_over_registry_copy(self):
        response = {'ldhName': 'thelinuxpros.com', 'events': [
            {'eventAction': 'registrar expiration', 'eventDate': '2027-01-25T03:18:10Z'},
            {'eventAction': 'expiration', 'eventDate': '2028-01-25T03:18:10Z'}]}
        with patch.object(core, 'registrar_services', return_value={'48': 'https://enom.rdap.tucows.com/'}), \
             patch.object(core, 'get_json', return_value=response) as mock:
            date, src, note = core.registrar_expiration('thelinuxpros.com', registry_obj('2029-01-25T03:18:10Z'))
        self.assertEqual(date, '2027-01-25T03:18:10Z')
        self.assertEqual(src, 'Registrar RDAP')
        self.assertIsNone(note)
        mock.assert_called_once_with('https://enom.rdap.tucows.com/domain/thelinuxpros.com', timeout=7)

    def test_registry_only_expiry_is_not_called_registrar_expiry(self):
        obj = registry_obj()
        with patch.object(core, 'registrar_services', return_value={'48': 'https://enom.rdap.tucows.com/'}), \
             patch.object(core, 'get_json', side_effect=core.LookupError_('503')):
            date, src, note = core.registrar_expiration('thelinuxpros.com', obj)
        self.assertIsNone(date)
        self.assertIsNone(src)
        self.assertIn('unavailable', note)
        report = core.report_rdap('domain', 'thelinuxpros.com', obj, registrar_expiry=date, registrar_notice=note)
        self.assertIn('Registry Expires:   2028-', report)
        self.assertIn('Registrar Expires:  Not provided', report)

    def test_registry_registrar_date_as_fallback(self):
        obj = registry_obj('2027-01-25T03:18:10Z')
        with patch.object(core, 'registrar_services', return_value={}), \
             patch.object(core, 'get_json') as mock:
            date, src, note = core.registrar_expiration('thelinuxpros.com', obj)
        self.assertEqual(date, '2027-01-25T03:18:10Z')
        self.assertEqual(src, 'Registry RDAP (registrar expiration event)')
        mock.assert_not_called()
        report = core.report_rdap('domain', 'thelinuxpros.com', obj, registrar_expiry=date, registrar_source=src)
        self.assertIn('WARN: Registrar and registry expiration dates differ', report)

    def test_registrar_rdap_without_specific_event_does_not_mislabel_expiration(self):
        with patch.object(core, 'registrar_services', return_value={'48': 'https://enom.rdap.tucows.com/'}), \
             patch.object(core, 'get_json', return_value={
                 'ldhName':'thelinuxpros.com',
                 'events':[{'eventAction':'expiration','eventDate':'2030-01-25T03:18:10Z'}]}):
            date, src, note = core.registrar_expiration('thelinuxpros.com', registry_obj())
        self.assertIsNone(date)
        self.assertIsNone(src)
        self.assertIn('omitted registrar expiration', note)

    def test_mismatched_domain_not_trusted(self):
        with patch.object(core, 'registrar_services', return_value={'48': 'https://enom.rdap.tucows.com/'}), \
             patch.object(core, 'get_json', return_value={
                 'ldhName':'other.example',
                 'events':[{'eventAction':'registrar expiration','eventDate':'2027-01-25T03:18:10Z'}]}):
            date, src, note = core.registrar_expiration('thelinuxpros.com', registry_obj())
        self.assertIsNone(date)
        self.assertIn('different or missing domain', note)

    def test_different_timezone_spellings_are_same_instant(self):
        self.assertFalse(core.different_expiration_dates('2027-01-25T03:18:10Z', '2027-01-24T22:18:10-05:00'))
        self.assertTrue(core.different_expiration_dates('2027-01-25T03:18:10Z', '2026-01-25T03:18:10Z'))

    def test_missing_iana_id_skips_external_directory(self):
        obj={'events':[{'eventAction': 'expiration', 'eventDate': '2027-01-25T03:18:10Z'}]}
        with patch.object(core,'registrar_services') as mock:
            self.assertEqual(core.registrar_expiration('thelinuxpros.com', obj), (None, None, None))
            mock.assert_not_called()

    def test_main_audit_includes_distinct_expiration_dates(self):
        with patch.object(core, 'rdap_for', return_value=('domain', 'thelinuxpros.com', registry_obj(), 'thelinuxpros.com')), \
             patch.object(core, 'registrar_expiration', return_value=('2027-01-25T03:18:10Z','Registrar RDAP',None)):
            report=core.audit('thelinuxpros.com', (False,)*8, {})
        self.assertIn('Registry Expires:', report)
        self.assertIn('Registrar Expires:', report)
        self.assertIn('2027-01-25T03:18:10Z', report)
        self.assertIn('2028-01-25T03:18:10Z', report)


    def test_fractional_timestamp_supports_python39_parser_rules(self):
        # CPython 3.9/3.10 fromisoformat only accepts 3- or 6-digit fractions.
        # Simulate that parser restriction so this test still fails on newer
        # interpreters if we accidentally remove the normalization.
        real_datetime = core.datetime.datetime

        class LegacyDatetime:
            @staticmethod
            def fromisoformat(value):
                fraction = __import__('re').search(r'\.(\d+)(?=[+-]\d\d:\d\d$)', value)
                if fraction and len(fraction.group(1)) not in (3, 6):
                    raise ValueError('Python 3.9 cannot parse that fraction length')
                return real_datetime.fromisoformat(value)

        with patch.object(core.datetime, 'datetime', LegacyDatetime):
            for registrar in (
                '2027-01-25T03:18:00.0Z',
                '2027-01-25T03:18:00.00Z',
                '2027-01-25T03:18:00.0000Z',
                '2027-01-25T03:18:00.00000Z',
                '2027-01-25T03:18:00.0000000Z',
                '2027-01-24T22:18:00.00-05:00',
            ):
                with self.subTest(value=registrar):
                    self.assertFalse(core.different_expiration_dates(
                        '2027-01-25T03:18:10Z', registrar))

    def test_rdap_timestamp_preserves_subsecond_precision(self):
        self.assertEqual(core.parse_rdap_timestamp('2027-01-25T03:18:00.12Z').microsecond, 120000)
        self.assertEqual(core.parse_rdap_timestamp('2027-01-25T03:18:00.123456789Z').microsecond, 123456)
        with self.assertRaises(ValueError):
            core.parse_rdap_timestamp('2027-01-25T03:18:00.22Zgarbage')

    def test_ten_second_enom_difference_is_not_renewal_warning(self):
        registry = '2027-01-25T03:18:10Z'
        registrar = '2027-01-25T03:18:00.00Z'
        self.assertFalse(core.different_expiration_dates(registry, registrar))
        obj = registry_obj()
        obj['events'] = [{'eventAction': 'expiration', 'eventDate': registry}]
        report = core.report_rdap('domain', 'thelinuxpros.com', obj,
                                  registrar_expiry=registrar, registrar_source='Registrar RDAP')
        self.assertIn('Registry Expires:   ' + registry, report)
        self.assertIn('Registrar Expires:  ' + registrar, report)
        self.assertNotIn('WARN: Registrar and registry expiration dates differ', report)

    def test_real_date_disagreements_still_warn(self):
        self.assertTrue(core.different_expiration_dates('2027-01-25T03:18:10Z',
                                                        '2027-01-25T03:20:00Z'))
        self.assertTrue(core.different_expiration_dates('2027-01-25T03:18:10Z',
                                                        '2028-01-25T03:18:10Z'))

    def test_small_difference_crossing_utc_midnight_warns(self):
        self.assertTrue(core.different_expiration_dates('2027-01-25T00:00:05Z',
                                                        '2027-01-24T23:59:55Z'))

    def test_differences_up_to_one_minute_on_same_day_do_not_warn(self):
        self.assertFalse(core.different_expiration_dates('2027-01-25T03:18:10Z',
                                                         '2027-01-25T03:19:10Z'))
        self.assertTrue(core.different_expiration_dates('2027-01-25T03:18:10Z',
                                                        '2027-01-25T03:19:11Z'))

if __name__ == '__main__':
    unittest.main()
