import requests
import pytest
import json

import demistomock as demisto

mocked_get_token_response = """{"access_token": "fababfafbh"}"""

enrich_bundle = {
    "ip": {
        "items": [
            {
                "created": "2020-09-11T21:11:21.670Z",
                "description": "IP address was listed as an Emotet C2 server",
                "external_reference": [
                    {
                        "description": "Mitre attack tactics and technique reference",
                        "mitre_attack_tactic": "Command and Control",
                        "mitre_attack_tactic_id": "TA0011",
                        "mitre_attack_tactic_url": "https://attack.mitre.org/tactics/TA0011/",
                        "source_name": "mitre-attack",
                    }
                ],
                "id": "indicator--f518b066-003d-4eb2-9783-ece9898d8a82",
                "labels": ["malicious-activity", "cnc", "c2", "malware", "emotet", "Command and Control"],
                "lang": "en",
                "modified": "2020-09-11T21:11:21.670Z",
                "pattern": "[ipv4-addr:value = '8.8.8.8']",
                "sixgill_actor": "<SIXGILL_ACTOR>",
                "sixgill_confidence": 90,
                "sixgill_feedid": "darkfeed_005",
                "sixgill_feedname": "emotet_c2s",
                "sixgill_postid": "<SIXGILL_POST_ID>",
                "sixgill_posttitle": "<SIXGILL_POST_TITLE>",
                "sixgill_severity": 80,
                "sixgill_source": "<SIXGILL_SOURCE>",
                "spec_version": "2.0",
                "type": "indicator",
                "valid_from": "2020-09-11T21:04:44Z",
            }
        ],
        "total": 1,
    },
    "domain": {
        "items": [
            {
                "created": "2020-11-18T10:25:58.138Z",
                "description": "This domain is being sold on the dark web and may be used in an attack",
                "external_reference": [
                    {
                        "description": "Mitre attack tactics and technique reference",
                        "mitre_attack_tactic": "Establish & Maintain Infrastructure",
                        "mitre_attack_tactic_id": "TA0022",
                        "mitre_attack_tactic_url": "https://attack.mitre.org/tactics/TA0022/",
                        "mitre_attack_technique": "Buy domain name",
                        "mitre_attack_technique_id": "T1328",
                        "mitre_attack_technique_url": "https://attack.mitre.org/techniques/T1328/",
                        "source_name": "mitre-attack",
                    }
                ],
                "id": "indicator--73a1c332-fcae-4b65-ad0a-4417e7493ab9",
                "labels": [
                    "anomalous-activity",
                    "suspicious domain",
                    "phishing",
                    "cnc",
                    "c&c",
                    "Establish & Maintain Infrastructure",
                    "Buy domain name",
                ],
                "lang": "en",
                "modified": "2020-11-18T10:25:58.138Z",
                "pattern": "[domain-name:value = '<DOMAIN_NAME>']",
                "sixgill_actor": "<SIXGILL_ACTOR>",
                "sixgill_confidence": 60,
                "sixgill_feedid": "darkfeed_003",
                "sixgill_feedname": "domains_sold_dark_web",
                "sixgill_postid": "<SIXGILL_POST_ID>",
                "sixgill_posttitle": "<SIXGILL_POST_TITLE>",
                "sixgill_severity": 60,
                "sixgill_source": "<SIXGILL_SOURCE>",
                "spec_version": "2.0",
                "type": "indicator",
                "valid_from": "2020-11-18T09:18:00Z",
            }
        ],
        "total": 1,
    },
    "url": {
        "items": [
            {
                "created": "2020-11-13T13:35:27.674Z",
                "description": "Malware available for download from file-sharing sites",
                "external_reference": [
                    {
                        "description": "Mitre attack tactics and technique reference",
                        "mitre_attack_tactic": "Build Capabilities",
                        "mitre_attack_tactic_id": "TA0024",
                        "mitre_attack_tactic_url": "https://attack.mitre.org/tactics/TA0024/",
                        "mitre_attack_technique": "Obtain/re-use payloads",
                        "mitre_attack_technique_id": "T1346",
                        "mitre_attack_technique_url": "https://attack.mitre.org/techniques/T1346/",
                        "source_name": "mitre-attack",
                    }
                ],
                "id": "indicator--6c5f8f9a-c31f-47f0-8719-b716ac05c770",
                "labels": ["malicious-activity", "malware", "Build Capabilities", "Obtain/re-use payloads"],
                "lang": "ru",
                "modified": "2020-11-13T13:35:27.674Z",
                "pattern": "[url:value = '<url>']",
                "sixgill_actor": "<SIXGILL_ACTOR>",
                "sixgill_confidence": 80,
                "sixgill_feedid": "darkfeed_010",
                "sixgill_feedname": "malware_download_urls",
                "sixgill_postid": "<SIXGILL_POST_ID>",
                "sixgill_posttitle": "<SIXGILL_POST_TITLE>",
                "sixgill_severity": 70,
                "sixgill_source": "<SIXGILL_SOURCE>",
                "spec_version": "2.0",
                "type": "indicator",
                "valid_from": "2020-11-09T11:33:00Z",
            }
        ],
        "total": 1,
    },
    "hash": {
        "items": [
            {
                "created": "2020-11-13T13:35:27.681Z",
                "description": "Virustotal link that appeared on a dark web site, generally to show malware that is "
                "undedetected",
                "external_reference": [
                    {
                        "description": "Mitre attack tactics and technique reference",
                        "mitre_attack_tactic": "Test capabilities",
                        "mitre_attack_tactic_id": "TA0025",
                        "mitre_attack_tactic_url": "https://attack.mitre.org/tactics/TA0025/",
                        "mitre_attack_technique": "Test signature detection for file upload/email filters",
                        "mitre_attack_technique_id": "T1361",
                        "mitre_attack_technique_url": "https://attack.mitre.org/techniques/T1361/",
                        "source_name": "mitre-attack",
                    }
                ],
                "id": "indicator--c9710887-4032-4541-bb12-028efbdc4fdc",
                "labels": [
                    "malicious-activity",
                    "malware",
                    "malicious",
                    "Test capabilities",
                    "Test signature detection for file upload/email filters",
                ],
                "lang": "ru",
                "modified": "2020-11-13T13:35:27.681Z",
                "pattern": "[file:hashes.MD5 = '<md5-hash-value>' OR file:hashes.'SHA-1' = "
                "'<sha1-hash-value>' OR file:hashes.'SHA-256' = "
                "'<sha256-hash-value>']",
                "sixgill_actor": "<SIXGILL_ACTOR>",
                "sixgill_confidence": 80,
                "sixgill_feedid": "darkfeed_002",
                "sixgill_feedname": "darkweb_vt_links",
                "sixgill_postid": "<SIXGILL_POST_ID>",
                "sixgill_posttitle": "<SIXGILL_POST_TITLE",
                "sixgill_severity": 70,
                "sixgill_source": "<SIXGILL_SOURCE",
                "spec_version": "2.0",
                "type": "indicator",
                "valid_from": "2020-11-09T11:11:00Z",
            }
        ],
        "total": 1,
    },
    "actor": {
        "items": [
            {
                "created": "2020-11-13T13:35:27.681Z",
                "description": "Virustotal link that appeared on a dark web site, generally to show malware that is "
                "undedetected",
                "external_reference": [
                    {
                        "description": "Mitre attack tactics and technique reference",
                        "mitre_attack_tactic": "Test capabilities",
                        "mitre_attack_tactic_id": "TA0025",
                        "mitre_attack_tactic_url": "https://attack.mitre.org/tactics/TA0025/",
                        "mitre_attack_technique": "Test signature detection for file upload/email filters",
                        "mitre_attack_technique_id": "T1361",
                        "mitre_attack_technique_url": "https://attack.mitre.org/techniques/T1361/",
                        "source_name": "mitre-attack",
                    }
                ],
                "id": "indicator--c9710887-4032-4541-bb12-028efbdc4fdc",
                "labels": [
                    "malicious-activity",
                    "malware",
                    "malicious",
                    "Test capabilities",
                    "Test signature detection for file upload/email filters",
                ],
                "lang": "ru",
                "modified": "2020-11-13T13:35:27.681Z",
                "pattern": "[file:hashes.MD5 = '<md5-hash_value>' OR file:hashes.'SHA-1' = "
                "'<sha1-hash_value>' OR file:hashes.'SHA-256' = "
                "'<sha256-hash_value>']",
                "sixgill_actor": "<SIXGILL_ACTOR>",
                "sixgill_confidence": 80,
                "sixgill_feedid": "darkfeed_002",
                "sixgill_feedname": "darkweb_vt_links",
                "sixgill_postid": "<SIXGILL_POST_ID>",
                "sixgill_posttitle": "<SIXGILL_POST_TITLE>",
                "sixgill_severity": 70,
                "sixgill_source": "<SIXGILL_SOURCE>",
                "spec_version": "2.0",
                "type": "indicator",
                "valid_from": "2020-11-09T11:11:00Z",
            }
        ],
        "total": 1,
    },
    "post_id": {
        "items": [
            {
                "created": "2020-11-13T13:35:27.674Z",
                "description": "Malware available for download from file-sharing sites",
                "external_reference": [
                    {
                        "description": "Mitre attack tactics and technique reference",
                        "mitre_attack_tactic": "Build Capabilities",
                        "mitre_attack_tactic_id": "TA0024",
                        "mitre_attack_tactic_url": "https://attack.mitre.org/tactics/TA0024/",
                        "mitre_attack_technique": "Obtain/re-use payloads",
                        "mitre_attack_technique_id": "T1346",
                        "mitre_attack_technique_url": "https://attack.mitre.org/techniques/T1346/",
                        "source_name": "mitre-attack",
                    }
                ],
                "id": "indicator--6c5f8f9a-c31f-47f0-8719-b716ac05c770",
                "labels": ["malicious-activity", "malware", "Build Capabilities", "Obtain/re-use payloads"],
                "lang": "ru",
                "modified": "2020-11-13T13:35:27.674Z",
                "pattern": "[url:value = '<url_value>']",
                "sixgill_actor": "<SIXGILL_ACTOR>",
                "sixgill_confidence": 80,
                "sixgill_feedid": "darkfeed_010",
                "sixgill_feedname": "malware_download_urls",
                "sixgill_postid": "<SIXGILL_POST_ID>",
                "sixgill_posttitle": "<SIXGILL_POST_TITLE>",
                "sixgill_severity": 70,
                "sixgill_source": "<SIXGILL_SOURCE>",
                "spec_version": "2.0",
                "type": "indicator",
                "valid_from": "2020-11-09T11:33:00Z",
            }
        ],
        "total": 1,
    },
}


class MockedResponse(object):
    def __init__(self, status_code, text, reason=None, url=None, method=None):
        self.status_code = status_code
        self.text = text
        self.reason = reason
        self.url = url
        self.request = requests.Request("GET")
        self.ok = True if self.status_code == 200 else False

    def json(self):
        return json.loads(self.text)


def init_params():
    return {
        "client_id": "WRONG_CLIENT_ID_TEST",
        "client_secret": "CLIENT_SECRET_TEST",
    }


def mocked_request(*args, **kwargs):
    enrich_ioc_data = []
    request = kwargs.get("request", {})
    end_point = request.path_url
    method = request.method
    body = request.body

    if end_point == "/ioc/enrich":
        result = json.loads(body)
        if "ioc_type" in result:
            enrich_ioc_data = enrich_bundle.get(result.get("ioc_type"))
        elif "sixgill_field" in result:
            enrich_ioc_data = enrich_bundle.get(result.get("sixgill_field"))

    response_dict = {
        "POST": {
            "/auth/token": MockedResponse(200, mocked_get_token_response),
            "/ioc/enrich": MockedResponse(200, json.dumps(enrich_ioc_data)),
        },
    }

    response_dict = response_dict.get(method)
    response = response_dict.get(end_point)

    return response


def test_test_module_command_raise_exception(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", return_value=MockedResponse(400, "error"))

    from Sixgill_Darkfeed_Enrichment import test_module_command

    with pytest.raises(Exception):
        test_module_command()


def test_test_module_command(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", return_value=MockedResponse(200, "ok"))

    from Sixgill_Darkfeed_Enrichment import test_module_command

    test_module_command()


def test_ip_reputation_command(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from Sixgill_Darkfeed_Enrichment import ip_reputation_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient("client_id", "client_secret", "some_channel")

    output = ip_reputation_command(client, {"ip": "<some ip>", "skip": 0})

    assert output[0].outputs == enrich_bundle.get("ip")["items"]


def test_domain_reputation_command(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from Sixgill_Darkfeed_Enrichment import domain_reputation_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient("client_id", "client_secret", "some_channel")

    output = domain_reputation_command(client, {"domain": "<some domain>", "skip": 0})

    assert output[0].outputs == enrich_bundle.get("domain")["items"]


def test_url_reputation_command(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from Sixgill_Darkfeed_Enrichment import url_reputation_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient("client_id", "client_secret", "some_channel")

    output = url_reputation_command(client, {"url": "<some_url>", "skip": 0})

    assert output[0].outputs == enrich_bundle.get("url")["items"]


def test_file_reputation_command(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from Sixgill_Darkfeed_Enrichment import file_reputation_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient("client_id", "client_secret", "some_channel")

    output = file_reputation_command(client, {"file": "<some hash>", "skip": 0})

    assert output[0].outputs == enrich_bundle.get("hash")["items"]


def test_actor_reputation_command(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from Sixgill_Darkfeed_Enrichment import actor_reputation_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient("client_id", "client_secret", "some_channel")

    output = actor_reputation_command(client, {"actor": "<some actor>", "skip": 0})

    assert output[0].outputs == enrich_bundle.get("actor")["items"]


def test_postid_reputation_command(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from Sixgill_Darkfeed_Enrichment import postid_reputation_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient("client_id", "client_secret", "some_channel")

    output = postid_reputation_command(client, {"post_id": "b12bd4ea4a112c3b6406c2d60e01d848d76e7c33", "skip": 0})

    assert output[0].outputs == enrich_bundle.get("post_id")["items"]
