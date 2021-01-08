import unittest
import os
import json
from pathlib import Path
import operator
from functools import reduce
import requests_mock
from RecordedFuture import (
    lookup_command,
    Client,
    enrich_command,
    get_alert_rules_command,
    get_alerts_command,
    get_alert_single_command,
    triage_command,
)
from mock_samples import ALERT_RULES
from CommonServerPython import CommandResults

import vcr as vcrpy

CASSETTES = Path(__file__).parent / 'cassettes'


def filter_out_whoami(response):
    body = response['body']['string']
    try:
        body.decode('utf-8')
        json_blob = json.loads(body)
        json_blob.pop('api_key', None)
        response['body']['string'] = json.dumps(json_blob).encode('utf-8')
    except UnicodeDecodeError:
        pass  # It's not a json string
    return response


vcr = vcrpy.VCR(
    serializer='yaml',
    cassette_library_dir=str(CASSETTES),
    record_mode='once',
    filter_headers=[('X-RFToken', 'XXXXXX')],
    before_record_response=filter_out_whoami,
)


class RFTest(unittest.TestCase):
    def setUp(self) -> None:
        base_url = "https://api.recordedfuture.com/v2/"
        verify_ssl = True
        self.token = os.environ.get("RF_TOKEN")
        headers = {
            "X-RFToken": self.token,
            "X-RF-User-Agent": "Cortex_XSOAR/2.0 Cortex_XSOAR_unittest_0.1",
        }

        self.client = Client(
            base_url=base_url, verify=verify_ssl, headers=headers, proxy=None
        )

    @vcr.use_cassette()
    def test_ip_reputation(self) -> None:
        resp = lookup_command(self.client, "37.48.83.137", "ip")
        entity = resp[0].to_context()["Contents"]["data"]["results"][0]
        context = resp[0].to_context()["EntryContext"]['RecordedFuture.IP(val.name == obj.name)']

        self.assertIsInstance(resp[0], CommandResults)
        # there are many rules that are concatenated
        self.assertIn(',', context["rules"])
        self.assertEqual("37.48.83.137", entity["entity"]["name"])

    @vcr.use_cassette()
    def test_intelligence(self) -> None:
        resp = enrich_command(self.client, "184.168.221.96", "ip", True, True)
        context = resp.to_context()["EntryContext"]['RecordedFuture.IP(val.name == obj.name)'] # noqa

        self.assertIsInstance(resp, CommandResults)
        # rules are concatenated
        self.assertIn(',', context['concatRules'])
        self.assertEqual(
            "184.168.221.96", resp.to_context()["Contents"]["data"]["name"]
        )

    @vcr.use_cassette()
    def test_whoami(self) -> None:
        resp = self.client.whoami()
        self.assertEqual(isinstance(resp, dict), True)

    @vcr.use_cassette()
    def test_intelligence_profile(self) -> None:
        """Will fetch related entities even if related_entities param is false""" # noqa
        resp = enrich_command(self.client, "184.168.221.96", "ip", False, False, "Vulnerability Analyst") # noqa
        self.assertIsInstance(resp, CommandResults)
        data = resp.raw_response['data']

        list_of_lists = [list(entry.keys()) for entry in data['relatedEntities']]  # noqa
        flat_related_types = sorted(reduce(operator.add, list_of_lists))
        expected = ['RelatedMalwareCategory', 'RelatedMalware', 'RelatedThreatActor']  # noqa
        self.assertEqual(flat_related_types, sorted(expected))

    @vcr.use_cassette()
    def test_threat_assessment(self) -> None:
        context = "phishing"
        entities = {
            "ip": ["8.8.8.8", "1.1.1.1"],
            "domain": ["www.feddoctor.com"],
            "hash": [
                "fa964842244e752950fd4ed711759382a"
                "8950e13cc2794d6f73ab7eb9169e5ee"
            ],
            "url": ["https://sites.google.com/site/unblockingnotice/"],
            "vulnerability": ["CVE-2020-8813", "CVE-2011-3874"],
        }
        resp = triage_command(self.client, entities, context)
        self.assertIsInstance(resp, CommandResults)
        self.assertFalse(resp.to_context()["Contents"]["verdict"])
        self.assertEqual("phishing", resp.to_context()["Contents"]["context"])

    @vcr.use_cassette()
    def test_threat_assessment_empty(self) -> None:
        """Filters away empty entities"""
        context = "phishing"
        entities = {
            "ip": ["8.8.8.8", "1.1.1.1"],
            "domain": ["www.feddoctor.com"],
            "hash": [
                "fa964842244e752950fd4ed711759382a"
                "8950e13cc2794d6f73ab7eb9169e5ee"
            ],
            "url": ["https://sites.google.com/site/unblockingnotice/"],
            "vulnerability": ["CVE-2020-8813", "CVE-2011-3874"],
            "filter": "yes"
        }
        resp = triage_command(self.client, entities, context)
        self.assertIsInstance(resp, CommandResults)
        self.assertFalse(resp.to_context()["Contents"]["verdict"])
        context = resp.to_context()["Contents"]
        self.assertEqual("phishing", context["context"])
        scores = [e for e in context['entities'] if e['score'] == 0]
        self.assertEqual(len(scores), 0, "Response contains entities with zero score") # noqa

    @requests_mock.Mocker()
    def test_get_alerting_rules(self, m) -> None:
        m.register_uri(
            "GET",
            "https://api.recordedfuture.com/v2/alert/rule?limit=10",
            text=json.dumps(ALERT_RULES),
        )
        resp = get_alert_rules_command(self.client, rule_name="", limit=10)
        self.assertTrue(resp)
        self.assertTrue(resp["Contents"]["data"])
        self.assertIsInstance(resp, dict)
        self.assertIsNotNone(resp["Contents"]["data"]["results"])

    @vcr.use_cassette()
    def test_get_alerts(self) -> None:
        resp = get_alerts_command(self.client, params={'limit': 200})
        self.assertTrue(resp)
        self.assertTrue(resp["Contents"]["data"])
        self.assertIsInstance(resp, dict)
        self.assertIsNotNone(resp["Contents"]["data"]["results"])

    @vcr.use_cassette()
    def test_single_alert_vulnerability(self) -> None:
        """Gets data for an alert related to vulnerabilities"""
        resp = get_alert_single_command(self.client, "f1IGiW")
        self.assertTrue(resp.get('HumanReadable'))

    @vcr.use_cassette()
    def test_single_alert_credential_leaks(self):
        """Alert related to credential leaks"""
        resp = get_alert_single_command(self.client, "fzpmIG")
        self.assertTrue(resp.get('HumanReadable'))
        context = resp['EntryContext']['RecordedFuture.SingleAlert(val.ID === obj.id)'] # noqa
        entity = context['flat_entities'][0]

        self.assertIn('documents', context.keys())
        self.assertIn('flat_entities', context.keys())
        self.assertIn('fragment', entity.keys())
        self.assertIn('name', entity.keys())
        self.assertIn('id', entity.keys())
        self.assertIn('type', entity.keys())

    @vcr.use_cassette()
    def test_single_alert_typosquat(self):
        """Alert related to typosquats"""
        resp = get_alert_single_command(self.client, "fp0_an")
        self.assertTrue(resp.get('HumanReadable'))
