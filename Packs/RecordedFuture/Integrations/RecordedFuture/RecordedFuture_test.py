import os
import unittest
import json
from pathlib import Path
from RecordedFuture import (
    Actions,
    Client,
)

from CommonServerPython import CommandResults
import vcr as vcrpy
import io

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
        self.actions = Actions(self.client)

    @vcr.use_cassette()
    def test_ip_reputation(self) -> None:
        resp = self.actions.lookup_command("37.48.83.137", "ip")
        entity = resp[0].to_context()["Contents"]["data"]["results"][0]
        context = resp[0].to_context()["EntryContext"]['RecordedFuture.IP(val.name && val.name == obj.name)']
        self.assertIsInstance(resp[0], CommandResults)
        # there are many rules that are concatenated
        self.assertIn(',', context["rules"])
        self.assertEqual("37.48.83.137", entity["entity"]["name"])

    @vcr.use_cassette()
    def test_intelligence(self) -> None:
        resp = self.actions.enrich_command("125.63.101.62", "ip", True, True)
        context = resp[0].to_context()["EntryContext"]['RecordedFuture.IP(val.name && val.name == obj.name)']  # noqa

        self.assertIsInstance(resp[0], CommandResults)
        # rules are concatenated
        self.assertIn(',', context['concatRules'])
        self.assertEqual(
            "125.63.101.62", resp[0].to_context()["Contents"]["data"]["name"]
        )

    @vcr.use_cassette()
    def test_whoami(self) -> None:
        resp = self.client.whoami()
        self.assertEqual(isinstance(resp, dict), True)

    @vcr.use_cassette()
    def test_intelligence_profile(self) -> None:
        """Will fetch related entities even if related_entities param is false"""  # noqa
        resp = self.actions.enrich_command("184.168.221.96", "ip", True, False, "Vulnerability Analyst")  # noqa
        self.assertIsInstance(resp[0], CommandResults)
        data = resp[0].raw_response['data']
        list_of_lists = sorted([[*entry][0] for entry in data['relatedEntities']]) # noqa
        expected = ['RelatedMalwareCategory', 'RelatedMalware', 'RelatedThreatActor']  # noqa
        self.assertEqual(list_of_lists, sorted(expected))

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
        # mocker.patch.object(DBotScore, 'get_integration_name', return_value='Recorded Future v2')
        resp = self.actions.triage_command(entities, context)
        self.assertIsInstance(resp[0], CommandResults)
        self.assertFalse(resp[0].to_context()["Contents"]["verdict"])
        self.assertEqual("phishing", resp[0].to_context()["Contents"]["context"])

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
        resp = self.actions.triage_command(entities, context)
        context = resp[0].to_context()
        self.assertIsInstance(resp[0], CommandResults)
        self.assertFalse(context["Contents"]["verdict"])
        self.assertEqual("phishing", context["Contents"]["context"])
        scores = [e for e in context["Contents"]['Entities'] if e['score'] == 0]
        self.assertEqual(len(scores), 0, "Response contains entities with zero score")  # noqa

    @vcr.use_cassette()
    def test_get_alerting_rules(self) -> None:
        resp = self.actions.get_alert_rules_command(rule_name="", limit=10)
        self.assertTrue(resp)
        self.assertTrue(resp["Contents"]["data"])
        self.assertIsInstance(resp, dict)
        self.assertIsNotNone(resp["Contents"]["data"]["results"])

    @vcr.use_cassette()
    def test_get_alerts(self) -> None:
        resp = self.actions.get_alerts_command(params={'limit': 200})
        self.assertTrue(resp)
        self.assertTrue(resp["Contents"]["data"])
        self.assertIsInstance(resp, dict)
        self.assertIsNotNone(resp["Contents"]["data"]["results"])

    @vcr.use_cassette()
    def test_single_alert_vulnerability(self) -> None:
        """Gets data for an alert related to vulnerabilities"""
        resp = self.actions.get_alert_single_command("f1IGiW")
        self.assertTrue(resp.get('HumanReadable'))

    @vcr.use_cassette()
    def test_single_alert_credential_leaks(self):
        """Alert related to credential leaks"""
        resp = self.actions.get_alert_single_command("fzpmIG")
        self.assertTrue(resp.get('HumanReadable'))
        context = resp['EntryContext']['RecordedFuture.SingleAlert(val.ID === obj.id)']  # noqa
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
        resp = self.actions.get_alert_single_command("fp0_an")
        self.assertTrue(resp.get('HumanReadable'))

    @vcr.use_cassette()
    def test_get_links_command(self):
        """Get Technical Links"""
        resp = self.actions.get_links_command('152.169.22.67', 'ip')
        context = resp.to_context()
        self.assertIsInstance(resp, CommandResults)
        self.assertTrue(context.get('HumanReadable'))
        self.assertTrue(context.get('Contents'))


def create_client():
    base_url = "https://api.recordedfuture.com/gw/xsoar/"
    verify_ssl = True
    token = os.environ.get("RF_TOKEN")
    headers = {
        "X-RFToken": token,
        "X-RF-User-Agent": "Cortex_XSOAR/2.0 Cortex_XSOAR_unittest_0.1",
    }

    return Client(
        base_url=base_url, verify=verify_ssl, headers=headers, proxy=None
    )


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_entity_enrich_with_related_entities(mocker):
    """

    Given:
        a request for entity enrichment with the argument fetch_related_entities as True
    When:
        requesting the API for entity enrichment
    Then:
        The returned data is valid and has the key relatedEntities

    """
    client = create_client()
    raw_response = util_load_json('./cassettes/entity_raw_response_related.json')
    mocker.patch.object(Client, '_http_request', return_value=raw_response)
    expected_entity_data = util_load_json('./cassettes/enrich_entity_related.json')
    returned_data = client.entity_enrich('184.168.221.96', 'ip', True, False, 'Vulnerability Analyst')
    assert expected_entity_data == returned_data
    assert 'relatedEntities' in returned_data.get('data').keys()


def test_entity_enrich_no_related_entities(mocker):
    """

    Given:
        a request for entity enrichment with the argument fetch_related_entities as False
    When:
        requesting the API for entity enrichment
    Then:
        The returned data is valid and does not have the key relatedEntities

    """
    client = create_client()
    raw_response = util_load_json('./cassettes/entity_raw_response_no_related.json')
    mocker.patch.object(Client, '_http_request', return_value=raw_response)
    expected_entity_data = util_load_json('./cassettes/enrich_entity_no_related.json')
    returned_data = client.entity_enrich('184.168.221.96', 'ip', False, False, 'Vulnerability Analyst')
    assert expected_entity_data == returned_data
    assert 'relatedEntities' not in returned_data.get('data').keys()
