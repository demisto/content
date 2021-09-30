import requests
import pytest
import json

import demistomock as demisto

cve_enrich = {
    "created": "2020-06-26T00:00:00.001000Z",
    "description": "A vulnerability exists that could allow the execution of unauthorized code or operating "
    "system commands on systems running exacqVision Web Service versions 20.06.3.0 and prior "
    "and exacqVision Enterprise Manager versions 20.06.4.0 and prior. An attacker with "
    "administrative privileges could potentially download and run a malicious executable "
    "that could allow OS command injection on the system.",
    "external_references": [{"external_id": "CVE-2020-9047", "source_name": "cve"}],
    "id": "vulnerability--143fb02c-accf-947e-4619-e0befa4e7068",
    "last_activity_date": "2021-03-28T02:05:19Z",
    "name": "CVE-2020-9047",
    "type": "vulnerability",
    "x_sixgill_info": {
        "attributes": [
            {
                "description": "This CVE was mentioned at least once by the actor Metasploit",
                "name": "Metasploit_attribute",
                "value": False,
            },
            {
                "description": "This CVE is currently recently trending in the cyber Underground",
                "name": "Is_Trend_Underground_attribute",
                "value": False,
            },
            {
                "description": "This CVE scanned at least once by hacktivism collective “Anonymous”",
                "name": "Is_Scanned_by_Anonymous_attribute",
                "value": False,
            },
            {
                "description": "This CVE is currently trending in the Chinese Underground",
                "name": "Is_Trend_Chinese_attribute",
                "value": False,
            },
            {
                "description": "This CVE has at least one published Proof of Concept (POC) exploit.",
                "name": "Has_POC_exploit_attribute",
                "value": False,
            },
            {
                "description": "The CVE is part of an at least one exploit kit",
                "name": "Has_Exploit_kit_attribute",
                "value": False,
            },
            {
                "description": "This CVE is currently trending in the Russian Underground",
                "name": "Is_Trend_Russian_attribute",
                "value": False,
            },
            {
                "description": "This CVE is currently trending in the Arab Underground",
                "name": "Is_Trend_Arabic_attribute",
                "value": False,
            },
            {
                "description": "This CVE is currently trending in the Farsi Underground",
                "name": "Is_Trend_Farsi_attribute",
                "value": False,
            },
            {
                "description": "This CVE is currently trending on GitHub",
                "name": "Is_Trend_GitHub_General_attribute",
                "value": False,
            },
            {
                "description": "This CVE is currently trending on Twitter",
                "name": "Is_Trend_Twitter_attribute",
                "value": False,
            },
        ],
        "github": {
            "activity": {"first_date": "2020-06-26T12:46:26Z", "last_date": "2021-03-28T02:05:19Z"},
            "github_forks": 5,
            "github_projects": 2,
            "github_watchers": 38,
            "projects": [
                {"link": "https://github.com/xqx12/daily-info", "name": "xqx12/daily-info"},
                {"link": "https://github.com/norrismw/CVE-2020-9047", "name": "norrismw/CVE-2020-9047"},
            ],
        },
        "mentions": {
            "first_mention": "2019-12-08T13:03:54Z",
            "last_mention": "2021-01-02T22:19:18Z",
            "mentions_total": 17,
        },
        "nvd": {
            "configurations": {
                "nodes": [
                    {
                        "cpe_match": [
                            {
                                "cpe23Uri": "cpe:2.3:a:exacq:exacq:*:*:*:*:*:*:*:*",
                                "versionEndIncluding": "20.06.3.0",
                                "vulnerable": True,
                            },
                            {
                                "cpe23Uri": "cpe:2.3:a:exacq:exacqvision_enterprise_manager:*:*:*:*:*:*:*:*",
                                "versionEndIncluding": "20.06.4.0",
                                "vulnerable": True,
                            },
                        ],
                        "operator": "OR",
                    }
                ],
                "version": "4.0",
            },
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-9047",
            "modified": "2020-08-17T17:43:00Z",
            "published": "2020-06-26T19:15:00Z",
            "v2": {
                "accessVector": "NETWORK",
                "attackComplexity": None,
                "attackVector": None,
                "authentication": "SINGLE",
                "availabilityImpact": "COMPLETE",
                "confidentialityImpact": "COMPLETE",
                "current": 9.0,
                "exploitabilityScore": 8.0,
                "impactScore": 10.0,
                "integrityImpact": "COMPLETE",
                "obtainAllPrivilege": False,
                "obtainOtherPrivilege": False,
                "obtainUserPrivilege": False,
                "privilegesRequired": None,
                "severity": "HIGH",
                "userInteraction": None,
                "userInteractionRequired": False,
                "vector": "AV:N/AC:L/Au:S/C:C/I:C/A:C",
            },
            "v3": {
                "accessVector": None,
                "attackComplexity": "LOW",
                "attackVector": "NETWORK",
                "authentication": None,
                "availabilityImpact": "HIGH",
                "confidentialityImpact": "HIGH",
                "current": 7.2,
                "exploitabilityScore": 1.2,
                "impactScore": 5.9,
                "integrityImpact": "HIGH",
                "privilegesRequired": "HIGH",
                "severity": "HIGH",
                "userInteraction": "NONE",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            },
        },
        "score": {
            "current": 4.83,
            "highest": {"date": "2020-07-14T00:00:00Z", "value": 8.21},
            "history": [
                {"current": 4.83, "date": "2021-04-01T00:00:00Z", "previouslyExploited": 0.0},
                {"current": 4.83, "date": "2021-03-01T00:00:00Z", "previouslyExploited": 0.0},
                {"current": None, "date": "2021-02-01T00:00:00Z", "previouslyExploited": 0.0},
                {"current": None, "date": "2021-01-01T00:00:00Z", "previouslyExploited": 0.0},
                {"current": None, "date": "2020-12-01T00:00:00Z", "previouslyExploited": 0.0},
                {"current": None, "date": "2020-11-01T00:00:00Z", "previouslyExploited": 0.0},
                {"current": 4.59, "date": "2020-10-01T00:00:00Z", "previouslyExploited": 0.0},
                {"current": 6.72, "date": "2020-09-01T00:00:00Z", "previouslyExploited": 0.0},
                {"current": 6.74, "date": "2020-08-01T00:00:00Z", "previouslyExploited": 0.0},
                {"current": 7.1, "date": "2020-07-01T00:00:00Z", "previouslyExploited": 0.55},
                {"current": 5.74, "date": "2020-06-01T00:00:00Z", "previouslyExploited": 1.3},
            ],
            "previouslyExploited": 0.0,
        },
    },
}
expected_enrich_output = [
    {
        'value': 'CVE-2020-9047',
        'Description': 'A vulnerability exists that could allow the execution of unauthorized code or operating '
                       'system commands on systems running exacqVision Web Service versions 20.06.3.0 and prior '
                       'and exacqVision Enterprise Manager versions 20.06.4.0 and prior. '
                       'An attacker with administrative privileges could potentially download and '
                       'run a malicious executable that could allow OS command injection on the system.',
        'Created': '2020-06-26T00:00:00.001000Z',
        'Modified': '',
        'Cybersixgill_DVE_score_current': 4.83,
        'Cybersixgill_DVE_score_highest_ever_date': '2020-07-14T00:00:00Z',
        'Cybersixgill_DVE_score_highest_ever': 8.21,
        'Cybersixgill_Previously_exploited_probability': 0.0,
        'Previous_Level': '',
        'CVSS_3_1_score': 1.2,
        'CVSS_3_1_severity': 'HIGH',
        'NVD_Link': 'https://nvd.nist.gov/vuln/detail/CVE-2020-9047',
        'NVD_last_modified_date': '2020-08-17T17:43:00Z',
        'NVD_publication_date': '2020-06-26T19:15:00Z',
        'CVSS_2_0_score': 8.0,
        'CVSS_2_0_severity': 'HIGH',
        'NVD_Vector_V2_0': 'AV:N/AC:L/Au:S/C:C/I:C/A:C',
        'NVD_Vector_V3_1': 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
        'rawJSON': {
            'created': '2020-06-26T00:00:00.001000Z',
            'description': 'A vulnerability exists that could allow the execution of unauthorized '
                           'code or operating system commands on systems running exacqVision Web '
                           'Service versions 20.06.3.0 and prior and exacqVision Enterprise Manager '
                           'versions 20.06.4.0 and prior. An attacker with administrative '
                           'privileges could potentially download and run a malicious executable '
                           'that could allow OS command injection on the system.',
            'external_references': [{
                'external_id': 'CVE-2020-9047',
                'source_name': 'cve'
            }],
            'id': 'vulnerability--143fb02c-accf-947e-4619-e0befa4e7068',
            'last_activity_date': '2021-03-28T02:05:19Z',
            'name': 'CVE-2020-9047',
            'type': 'vulnerability',
            'x_sixgill_info': {
                'attributes': [{
                    'description': 'This CVE was mentioned at least once by the actor Metasploit',
                    'name': 'Metasploit_attribute',
                    'value': False
                }, {
                    'description': 'This CVE is currently recently trending in the cyber Underground',
                    'name': 'Is_Trend_Underground_attribute',
                    'value': False
                }, {
                    'description': 'This CVE scanned at least once by hacktivism collective “Anonymous”',
                    'name': 'Is_Scanned_by_Anonymous_attribute',
                    'value': False
                }, {
                    'description': 'This CVE is currently trending in the Chinese Underground',
                    'name': 'Is_Trend_Chinese_attribute',
                    'value': False
                }, {
                    'description': 'This CVE has at least one published Proof of Concept (POC) exploit.',
                    'name': 'Has_POC_exploit_attribute',
                    'value': False
                }, {
                    'description': 'The CVE is part of an at least one exploit kit',
                    'name': 'Has_Exploit_kit_attribute',
                    'value': False
                }, {
                    'description': 'This CVE is currently trending in the Russian Underground',
                    'name': 'Is_Trend_Russian_attribute',
                    'value': False
                }, {
                    'description': 'This CVE is currently trending in the Arab Underground',
                    'name': 'Is_Trend_Arabic_attribute',
                    'value': False
                }, {
                    'description': 'This CVE is currently trending in the Farsi Underground',
                    'name': 'Is_Trend_Farsi_attribute',
                    'value': False
                }, {
                    'description': 'This CVE is currently trending on GitHub',
                    'name': 'Is_Trend_GitHub_General_attribute',
                    'value': False
                }, {
                    'description': 'This CVE is currently trending on Twitter',
                    'name': 'Is_Trend_Twitter_attribute',
                    'value': False
                }],
                'github': {
                    'activity': {
                        'first_date': '2020-06-26T12:46:26Z',
                        'last_date': '2021-03-28T02:05:19Z'
                    },
                    'github_forks': 5,
                    'github_projects': 2,
                    'github_watchers': 38,
                    'projects': [{
                        'link': 'https://github.com/xqx12/daily-info',
                        'name': 'xqx12/daily-info'
                    }, {
                        'link': 'https://github.com/norrismw/CVE-2020-9047',
                        'name': 'norrismw/CVE-2020-9047'
                    }]
                },
                'mentions': {
                    'first_mention': '2019-12-08T13:03:54Z',
                    'last_mention': '2021-01-02T22:19:18Z',
                    'mentions_total': 17
                },
                'nvd': {
                    'configurations': {
                        'nodes': [{
                            'cpe_match': [{
                                'cpe23Uri': 'cpe:2.3:a:exacq:exacq:*:*:*:*:*:*:*:*',
                                'versionEndIncluding': '20.06.3.0',
                                'vulnerable': True
                            }, {
                                'cpe23Uri': 'cpe:2.3:a:exacq:exacqvision_enterprise_manager:*:*:*:*:*:*:*:*',
                                'versionEndIncluding': '20.06.4.0',
                                'vulnerable': True
                            }],
                            'operator': 'OR'
                        }],
                        'version': '4.0'
                    },
                    'link': 'https://nvd.nist.gov/vuln/detail/CVE-2020-9047',
                    'modified': '2020-08-17T17:43:00Z',
                    'published': '2020-06-26T19:15:00Z',
                    'v2': {
                        'accessVector': 'NETWORK',
                        'attackComplexity': None,
                        'attackVector': None,
                        'authentication': 'SINGLE',
                        'availabilityImpact': 'COMPLETE',
                        'confidentialityImpact': 'COMPLETE',
                        'current': 9.0,
                        'exploitabilityScore': 8.0,
                        'impactScore': 10.0,
                        'integrityImpact': 'COMPLETE',
                        'obtainAllPrivilege': False,
                        'obtainOtherPrivilege': False,
                        'obtainUserPrivilege': False,
                        'privilegesRequired': None,
                        'severity': 'HIGH',
                        'userInteraction': None,
                        'userInteractionRequired': False,
                        'vector': 'AV:N/AC:L/Au:S/C:C/I:C/A:C'
                    },
                    'v3': {
                        'accessVector': None,
                        'attackComplexity': 'LOW',
                        'attackVector': 'NETWORK',
                        'authentication': None,
                        'availabilityImpact': 'HIGH',
                        'confidentialityImpact': 'HIGH',
                        'current': 7.2,
                        'exploitabilityScore': 1.2,
                        'impactScore': 5.9,
                        'integrityImpact': 'HIGH',
                        'privilegesRequired': 'HIGH',
                        'severity': 'HIGH',
                        'userInteraction': 'NONE',
                        'vector': 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H'
                    }
                },
                'score': {
                    'current': 4.83,
                    'highest': {
                        'date': '2020-07-14T00:00:00Z',
                        'value': 8.21
                    },
                    'history': [{
                        'current': 4.83,
                        'date': '2021-04-01T00:00:00Z',
                        'previouslyExploited': 0.0
                    }, {
                        'current': 4.83,
                        'date': '2021-03-01T00:00:00Z',
                        'previouslyExploited': 0.0
                    }, {
                        'current': None,
                        'date': '2021-02-01T00:00:00Z',
                        'previouslyExploited': 0.0
                    }, {
                        'current': None,
                        'date': '2021-01-01T00:00:00Z',
                        'previouslyExploited': 0.0
                    }, {
                        'current': None,
                        'date': '2020-12-01T00:00:00Z',
                        'previouslyExploited': 0.0
                    }, {
                        'current': None,
                        'date': '2020-11-01T00:00:00Z',
                        'previouslyExploited': 0.0
                    }, {
                        'current': 4.59,
                        'date': '2020-10-01T00:00:00Z',
                        'previouslyExploited': 0.0
                    }, {
                        'current': 6.72,
                        'date': '2020-09-01T00:00:00Z',
                        'previouslyExploited': 0.0
                    }, {
                        'current': 6.74,
                        'date': '2020-08-01T00:00:00Z',
                        'previouslyExploited': 0.0
                    }, {
                        'current': 7.1,
                        'date': '2020-07-01T00:00:00Z',
                        'previouslyExploited': 0.55
                    }, {
                        'current': 5.74,
                        'date': '2020-06-01T00:00:00Z',
                        'previouslyExploited': 1.3
                    }],
                    'previouslyExploited': 0.0
                }
            }
        }
    }
]

mock_response = ""
mocked_get_token_response = """{"access_token": "fababfafbh"}"""
args = {"cve_id": "CVE-2020-9047"}
channel_code = "d5cd46c205c20c87006b55a18b106428"


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
    return {"client_id": "WRONG_CLIENT_ID_TEST", "client_secret": "CLIENT_SECRET_TEST"}


def mocked_request(*args, **kwargs):
    global mock_response
    request = kwargs.get("request", {})
    end_point = request.path_url
    method = request.method
    mock_response = json.dumps(cve_enrich)
    response_dict = {
        "POST": {"/auth/token": MockedResponse(200, mocked_get_token_response)},
        "GET": {"/dve_enrich/CVE-2020-9047": MockedResponse(200, mock_response)},
    }
    response_dict = response_dict.get(method)
    response = response_dict.get(end_point)

    return response


def test_test_module_command_raise_exception(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", return_value=MockedResponse(400, "error"))

    from CybersixgillDVEEnrichment import test_module

    with pytest.raises(Exception):
        test_module()


def test_test_module_command(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", return_value=MockedResponse(200, "ok"))

    from CybersixgillDVEEnrichment import test_module

    test_module(
        demisto.params()["client_id"], demisto.params()["client_secret"], channel_code, requests.Session(), True
    )


def test_stix_to_indicator(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from CybersixgillDVEEnrichment import stix_to_indicator

    output = []
    cve_data = stix_to_indicator(cve_enrich)
    output.append(cve_data)
    assert output == expected_enrich_output


def test_cve_enrich_command(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from CybersixgillDVEEnrichment import cve_enrich_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient(
        demisto.params()["client_id"], demisto.params()["client_secret"], channel_code, demisto
    )

    output = cve_enrich_command(client, demisto.args())
    assert output[0].outputs == expected_enrich_output
