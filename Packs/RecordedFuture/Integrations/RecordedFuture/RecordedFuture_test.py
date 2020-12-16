import unittest
import os
import json
import requests_mock
from RecordedFuture import lookup_command, Client, enrich_command, \
    get_alert_rules_command, get_alerts_command, triage_command
from mock_samples import IP_LOOKUP, IP_REP, TRIAGE, ALERT_RULES, ALERTS
from CommonServerPython import CommandResults


@requests_mock.Mocker()
class RFTest(unittest.TestCase):

    def setUp(self) -> None:
        base_url = 'https://api.recordedfuture.com/v2/'
        verify_ssl = True
        self.token = os.environ.get('RF_TOKEN')
        headers = {
            'X-RFToken': self.token,
            'X-RF-User-Agent': 'Cortex_XSOAR/2.0 Cortex_XSOAR_unittest_0.1'
        }

        self.client = Client(base_url=base_url, verify=verify_ssl,
                             headers=headers, proxy=None)

    def test_ip_reputation(self, m) -> None:
        m.register_uri('POST',
                       'https://api.recordedfuture.com/v2/soar/enrichment',
                       text=json.dumps(IP_REP))
        resp = lookup_command(self.client, '1.2.3.4,8.8.8.8', 'ip')
        self.assertIsInstance(resp[0], CommandResults)
        self.assertEqual('1.2.3.4',
                         resp[0].to_context()['Contents']['data']
                         ['results'][0]['entity']['name'])
        self.assertIsInstance(resp[1], CommandResults)
        self.assertEqual('8.8.8.8',
                         resp[1].to_context()['Contents']['data']
                         ['results'][1]['entity']['name'])

    def test_intelligence(self, m) -> None:
        m.register_uri('GET',
                       'https://api.recordedfuture.com/v2/ip/1.2.3.4?'
                       'fields=entity,risk,timestamps,threatLists,intelCard,'
                       'metrics,location,relatedEntities,riskyCIDRIPs',
                       text=json.dumps(IP_LOOKUP))
        resp = enrich_command(self.client, '1.2.3.4', 'ip', True, True)
        self.assertIsInstance(resp, CommandResults)
        self.assertEqual('1.2.3.4',
                         resp.to_context()['Contents']['data']['name'])

    def test_threat_assessment(self, m) -> None:
        m.register_uri('POST',
                       'https://api.recordedfuture.com/v2/soar'
                       '/triage/contexts/phishing',
                       text=json.dumps(TRIAGE))
        context = 'phishing'
        entities = {'ip': ['8.8.8.8', '1.1.1.1'],
                    'domain': ['www.feddoctor.com'],
                    'hash': ['fa964842244e752950fd4ed711759382a'
                             '8950e13cc2794d6f73ab7eb9169e5ee'],
                    'url': ['https://sites.google.com/site/unblockingnotice/'],
                    'vulnerability': ['CVE-2020-8813', 'CVE-2011-3874']}
        resp = triage_command(self.client, entities, context)
        self.assertIsInstance(resp, List[CommandResults])
        self.assertFalse(resp.to_context()['Contents']['verdict'])
        self.assertEqual('phishing', resp.to_context()['Contents']['context'])

    def test_get_alerting_rules(self, m) -> None:
        m.register_uri('GET',
                       'https://api.recordedfuture.com/v2/alert/rule?limit=10',
                       text=json.dumps(ALERT_RULES))
        resp = get_alert_rules_command(self.client, rule_name='', limit=10)
        self.assertTrue(resp)
        self.assertTrue(resp['Contents']['data'])
        self.assertIsInstance(resp, dict)
        self.assertIsNotNone(resp['Contents']['data']['results'])

    def test_get_alerts(self, m) -> None:
        m.register_uri('GET',
                       'https://api.recordedfuture.com/v2/alert/search',
                       text=json.dumps(ALERTS))
        resp = get_alerts_command(self.client, params={})
        self.assertTrue(resp)
        self.assertTrue(resp['Contents']['data'])
        self.assertIsInstance(resp, dict)
        self.assertIsNotNone(resp['Contents']['data']['results'])
