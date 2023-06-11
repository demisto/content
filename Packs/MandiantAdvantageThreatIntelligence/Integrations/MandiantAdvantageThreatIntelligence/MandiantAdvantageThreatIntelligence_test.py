import pytest
import io
from CommonServerPython import *
import MandiantAdvantageThreatIntelligence

SERVER_URL = "https://api.intelligence.mandiant.com"

MOCK_MD5_INDICATOR_RESPONSE = {
    "id": "md5--7c8be1f2-b949-aaaa-af7f-18908175108f",
    "mscore": 100,
    "type": "md5",
    "value": "0cc22fd05a3e771b09b584db0a16aaaa",
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2022-06-09T15:00:23.000+0000",
            "last_seen": "2022-12-08T19:24:27.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant",
        }
    ],
    "associated_hashes": [
        {
            "id": "md5--7c8be1f2-b949-aaaa-af7f-18908175108f",
            "type": "md5",
            "value": "0cc22fd05a3e771b09b584db0a16aaaa",
        },
        {
            "id": "sha1--7494fdf5-b6ae-aaaa-8c85-d36fe15682b9",
            "type": "sha1",
            "value": "587977c02a628b8e1070bdc8dffbe4dcd414aaaa",
        },
        {
            "id": "sha256--4865e7ce-5670-aaaa-a8fe-0279ccab638b",
            "type": "sha256",
            "value": "efd431ae58a6092962ee9253722cfffe85cfc93bc051ba97ba26652a490faaaa",
        },
    ],
    "last_updated": "2023-02-01T13:59:55.422Z",
    "first_seen": "2022-06-09T15:00:23.000Z",
    "last_seen": "2022-12-08T19:24:27.000Z",
}

MOCK_FQDN_INDICATOR_RESPONSE = {
    "id": "fqdn--be2e92a7-aaaa-5f35-8c6e-0731685aee19",
    "mscore": 93,
    "type": "fqdn",
    "value": "some.url.com",
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2020-09-22T08:14:31.000+0000",
            "last_seen": "2021-01-25T23:17:10.081+0000",
            "osint": True,
            "category": ["malware"],
            "source_name": "Mandiant",
        }
    ],
    "attributed_associations": [
        {
            "id": "malware--b2bd3b57-aaaa-5c18-a383-990cc3d97c72",
            "name": "MALWARE_FAMILY_NAME",
            "type": "malware",
        }
    ],
    "last_updated": "2023-01-18T04:52:14.116Z",
    "first_seen": "2020-07-01T08:31:44.000Z",
    "last_seen": "2022-12-07T23:15:01.000Z",
}

MOCK_IP_INDICATOR_RESPONSE = {
    "id": "ipv4--27063181-abcd-53ec-b785-3b9772febd50",
    "mscore": 40,
    "type": "ipv4",
    "value": "192.168.84.82",
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2022-08-04T23:18:00.878+0000",
            "last_seen": "2022-12-07T23:18:01.001+0000",
            "osint": True,
            "category": ["exploit/vuln-scanning", "exploit"],
            "source_name": "SOME_SOURCE",
        }
    ],
    "last_updated": "2023-02-03T02:22:54.665Z",
    "first_seen": "2022-08-04T23:18:00.000Z",
    "last_seen": "2022-12-07T23:18:01.000Z",
}

MOCK_URL_INDICATOR_RESPONSE = {
    "id": "url--02183bee-dcba-5d25-956b-765650f9e42a",
    "mscore": 2,
    "type": "url",
    "value": "https://someurl.com",
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2021-09-09T10:18:18.000+0000",
            "last_seen": "2021-11-24T04:30:49.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant",
        }
    ],
    "last_updated": "2023-01-19T06:25:18.624Z",
    "first_seen": "2021-06-19T06:58:22.000Z",
    "last_seen": "2022-12-08T12:48:03.000Z",
}

MOCK_IOC_INDICATOR_REPORT_RESPONSE = {
    "id": "INDICATOR--UUID",
    "mscore": 100,
    "type": "INDICATOR_TYPE",
    "value": "INDICATOR_VALUE",
    "is_publishable": True,
    "first_seen": "2020-06-06T11:05:00Z",
    "last_seen": "2023-02-01T10:10:01Z",
    "is_customer_releasable": True,
    "reports": [],
}

MOCK_CVE_RESPONSE = {
    "id": "vulnerability--e3b6a556-abcd-dcba-b1df-8e1f0444e978",
    "type": "vulnerability",
    "is_publishable": True,
    "risk_rating": "MEDIUM",
    "analysis": "INSERT_ANALYSIS_HERE",
    "executive_summary": "INSERT_EXECUTIVE_SUMMARY_HERE",
    "description": "INSERT_DESCRIPTION_HERE",
    "exploitation_vectors": ["General Network Connectivity"],
    "title": "CVE TITLE GOES HERE",
    "associated_actors": [],
    "associated_malware": [],
    "associated_reports": [],
    "exploitation_consequence": "Code Execution",
    "cwe": "Double Free",
    "cve_id": "CVE-1234-12345",
    "vulnerable_products": "A LIST OF VULNERABLE PRODUCTS",
    "exploitation_state": "Available",
    "vendor_fix_references": [
        {
            "url": "https://github.com/some/repo",
            "name": "REFERENCE NAME",
            "unique_id": "12341234123513245456567456",
        }
    ],
    "date_of_disclosure": "2023-01-15T05:00:00.000Z",
    "observed_in_the_wild": False,
    "vulnerable_cpes": [],
    "was_zero_day": False,
    "workarounds": None,
    "publish_date": "2023-02-07T15:40:00.000Z",
    "updated_date": "2023-02-07T15:40:00.000Z",
    "last_modified_date": "2023-02-07T15:40:00.000Z",
    "available_mitigation": ["Patch"],
    "sources": [
        {
            "source_name": "Project",
            "unique_id": "12341234123513245456567456",
            "source_description": "12341234123513245456567456",
            "date": "2023-02-02T17:00:00.000Z",
            "url": "https://github.com/some/repo",
            "is_vendor_fix": False,
        },
    ],
    "exploits": [
        {
            "name": "CVE-1234-12345_PoC",
            "description": "POC DESCRIPTION",
            "reliability": "Untested",
            "file_size": 100,
            "md5": "4D2939009D0C2B15DD4A220BAA060000",
            "release_date": "2023-02-02T05:00:00Z",
            "exploit_url": "https://some.url/",
            "replication_urls": [],
            "index": None,
            "grade": "",
            "hashes": {},
        }
    ],
    "common_vulnerability_scores": {
        "v2.0": {
            "access_complexity": "MEDIUM",
            "access_vector": "NETWORK",
            "authentication": "NONE",
            "availability_impact": "COMPLETE",
            "base_score": 9.3,
            "confidentiality_impact": "COMPLETE",
            "exploitability": "PROOF_OF_CONCEPT",
            "integrity_impact": "COMPLETE",
            "remediation_level": "OFFICIAL_FIX",
            "report_confidence": "CONFIRMED",
            "temporal_score": 7.3,
            "vector_string": "AV:N/AC:M/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C",
        }
    },
    "audience": ["intel_vuln"],
    "intel_free": False,
    "affects_ot": False,
    "aliases": [],
    "cisa_known_exploited": None,
    "cpe_ranges": [],
    "cwe_details": None,
    "days_to_patch": None,
    "epss": None,
    "version_history": [],
    "workarounds_list": [],
}

MOCK_THREATACTOR_RESPONSE = {
    "industries": [
        {
            "id": "identity--65be572d-abcd-dcba-96e5-a5fb1d7f2bab",
            "name": "TARGET_INDUSTRY",
            "attribution_scope": "confirmed",
            "first_seen": "2017-05-02T11:55:27.000Z",
            "last_seen": "2022-08-16T08:02:00.000Z",
        }
    ],
    "suspected_attribution": [],
    "locations": {
        "source": [
            {
                "region": {
                    "id": "location--8fc231f3-aaaa-57e7-b734-eaee0a734612",
                    "name": "SOURCE_REGION",
                    "attribution_scope": "confirmed",
                },
                "country": {
                    "id": "location--39c533c9-bbbb-5e4d-89a0-d906a9e6043c",
                    "name": "SOURCE_COUNTRY",
                    "iso2": "SC",
                    "attribution_scope": "confirmed",
                },
                "sub_region": {
                    "attribution_scope": "confirmed",
                    "id": "location--62844260-cccc-5826-a895-78b38e0f37ca",
                    "name": "SOURCE_SUBREGION",
                },
            }
        ],
        "target": [
            {
                "id": "location--27a1d59f-dddd-5da4-963c-ce1f9c6c0402",
                "name": "TARGET_COUNTRY",
                "iso2": "TC",
                "region": "TARGET_REGION",
                "sub-region": "TARGET_SUBREGION",
                "attribution_scope": "confirmed",
            },
        ],
        "target_sub_region": [
            {
                "id": "location--cdf44f32-eeee-5661-be2b-58fbd1479d05",
                "name": "TARGET_SUBREGION",
                "key": "targetsubregion",
                "region": "TARGET_REGION",
                "attribution_scope": "confirmed",
            },
        ],
        "target_region": [
            {
                "id": "location--6d65522f-ffff-5e7e-973c-35cf7973e4e3",
                "name": "TARGET_REGION",
                "key": "targetregion",
                "attribution_scope": "confirmed",
            },
        ],
    },
    "id": "threat-actor--f7fdbf0c-abcd-5b95-b005-702afffe4a72",
    "name": "FAKE_ACT0R",
    "description": "ACTOR DESCRIPTION GOES HERE",
    "type": "threat-actor",
    "last_activity_time": "2022-11-09T20:21:04.000Z",
    "audience": [
        {"name": "intel_fusion", "license": "INTEL_RBI_FUS"},
        {"name": "intel_oper", "license": "INTEL_RBI_OPS"},
        {"name": "tlp_marking", "license": "amber"},
    ],
    "is_publishable": True,
    "intel_free": False,
    "counts": {
        "reports": 43,
        "malware": 13,
        "cve": 0,
        "associated_uncs": 3,
        "aliases": 12,
        "industries": 8,
        "attack_patterns": 87,
    },
    "last_updated": "2023-02-01T06:27:30.000Z",
    "aliases": [
        {"name": "OTHER_ACT0R", "attribution_scope": "confirmed"},
    ],
    "malware": [
        {
            "id": "malware--e6810cc5-abcd-52cc-bf57-9b2ffc381760",
            "name": "MALWARE_FAMILY",
            "attribution_scope": "confirmed",
            "first_seen": "2022-08-24T19:40:14.000Z",
            "last_seen": "2023-01-24T05:01:13.000Z",
        },
    ],
    "motivations": [
        {
            "id": "motivation--1b8ca82a-7cff-5622-bedd-965c11d38a9e",
            "name": "Espionage",
            "attribution_scope": "confirmed",
        },
    ],
    "associated_uncs": [
        {
            "attribution_scope": "suspected",
            "id": "threat-actor--feb78504-abcd-5217-ad21-7dc9dab8974b",
            "name": "UNC0000",
        },
    ],
    "cve": [],
    "observed": [
        {
            "earliest": "2020-04-20T13:33:39.000Z",
            "recent": "2020-06-18T14:32:57.000Z",
            "attribution_scope": "suspected",
        },
        {
            "earliest": "2015-04-06T00:00:00.000Z",
            "recent": "2022-11-09T20:21:04.000Z",
            "attribution_scope": "confirmed",
        },
        {
            "earliest": "2021-01-16T00:00:00.000Z",
            "recent": "2023-01-09T00:00:00.000Z",
            "attribution_scope": "possible",
        },
    ],
    "tools": [
        {
            "id": "malware--7d778724-abcd-dcba-b01d-119a0b1c8c5f",
            "name": "SOME_FREE_TOOL",
            "attribution_scope": "possible",
        },
    ],
}

MOCK_THREATACTOR_REPORTS_RESPONSE = {
    "reports": [
        {
            "id": "report--655fac2b-abcd-abcd-9a88-d3bb11b8e10f",
            "report_id": "23-00000722",
            "title": "REPORT TITLE",
            "published_date": "January 13, 2023 05:44:20 PM",
            "report_type": "Event Coverage/Implication",
            "version": "1.0",
            "audience": [
                {"license": "INTEL_CYB_CRIME", "name": "cyber crime"},
                {"license": "INTEL_CYB_ESP", "name": "cyber espionage"},
                {"license": "INTEL_RBI_FUS", "name": "fusion"},
            ],
            "attribution_scope": "confirmed",
        }
    ],
    "id": "threat-actor--f7fdbf0c-abcd-5b95-b005-702afffe4a72",
    "name": "FAKE_ACT0R",
    "description": "ACTOR DESCRIPTION GOES HERE",
    "last_updated": "2023-02-01T06:27:30.000Z",
    "is_publishable": True,
}

MOCK_THREATACTOR_INDICATORS_RESPONSE = {
    "id": "threat-actor--f7fdbf0c-abcd-5b95-b005-702afffe4a72",
    "name": "FAKE_ACT0R",
    "indicators": [
        {
            "first_seen": "2017-05-18T16:24:40.000Z",
            "last_seen": "2017-09-10T02:30:28.000Z",
            "sources": [
                {
                    "first_seen": "2017-05-18T16:24:40.000+0000",
                    "last_seen": "2017-09-10T02:30:28.000+0000",
                    "osint": False,
                    "category": [],
                    "source_name": "Mandiant",
                },
            ],
            "mscore": 100,
            "attributed_associations": [
                {
                    "id": "malware--c5151965-abcd-5907-ae0e-9019414e1b44",
                    "name": "MALWARE",
                    "type": "malware",
                }
            ],
            "id": "url--16028aa3-abcd-5d07-86ad-7c4f92997edf",
            "type": "url",
            "value": "http://somesite.com/qb/svhost.exe",
            "is_publishable": True,
            "is_exclusive": True,
            "last_updated": "2022-08-01T15:45:39.702Z",
        },
    ],
}

MOCK_THREATACTOR_ATTACKPATTERN_RESPONSE = {
    "threat-actors": [
        {
            "id": "threat-actor--f7fdbf0c-abcd-5b95-b005-702afffe4a72",
            "name": "FAKE_ACT0R",
            "type": "actor-mitre",
            "attack-patterns": {
                "Impact": [
                    {
                        "id": "attack-pattern--ff73aa03-aaaa-4464-83ac-f89e233c02bc",
                        "attribution_scope": "confirmed",
                    }
                ],
            },
        }
    ],
    "attack-patterns": {
        "attack-pattern--ff73aa03-aaaa-4464-83ac-f89e233c02bc": {
            "x_mitre_is_subtechnique": False,
            "created": "2019-10-04T20:42:28.541Z",
            "name": "System Shutdown/Reboot",
            "attack_pattern_identifier": "T1529",
            "modified": "2020-03-27T21:18:48.149Z",
            "description": "ATTACK PATTERN DESCRIPTION",
            "id": "attack-pattern--ff73aa03-aaaa-4464-83ac-f89e233c02bc",
        },
    },
}

MOCK_THREATACTOR_CAMPAIGNS_RESPONSE = {
    "campaigns": [
        {
            "name": "CAMPAIGN_NAME",
            "id": "campaign--6562546d-abcd-52fd-a4a4-57ca99e1e5db",
            "short_name": "CAMP.00.007",
            "profile_updated": "2023-02-07T07:00:11.770Z",
        },
    ],
    "total_count": 4,
    "id": "threat-actor--f7fdbf0c-abcd-5b95-b005-702afffe4a72",
    "name": "FAKE_ACT0R",
    "last_updated": "2023-02-01T06:27:30Z",
    "last_activity_time": "2022-11-09T20:21:04Z",
}

MOCK_MALWARE_RESPONSE = {
    "actors": [
        {
            "id": "threat-actor--f7fdbf0c-abcd-abcd-b005-702afffe4a72",
            "name": "FAKE_ACT0R",
            "country_name": "SOURCE_COUNTRY",
            "iso2": "SC",
            "last_updated": "2023-02-01T06:27:30Z",
        }
    ],
    "description": "MALWARE_DESCRIPTION",
    "detections": ["DETECTION_ONE", "DETECTION_TWO"],
    "id": "malware--2debd90b-0000-1234-8838-1f9f58ca256b",
    "industries": [],
    "inherently_malicious": 1,
    "last_activity_time": "2023-02-07T02:17:24.000Z",
    "last_updated": "2023-02-07T02:17:24.000Z",
    "malware": [],
    "name": "MALWARE_NAME",
    "operating_systems": ["Windows"],
    "type": "malware",
    "yara": [
        {
            "id": "signature--9de209a1-1234-4321-a920-3c4c4f5339a5",
            "name": "FE_APT_Backdoor_Win_CHAIRSMACK_1",
        },
    ],
    "is_publishable": True,
    "intel_free": False,
    "counts": {
        "reports": 8,
        "capabilities": 38,
        "malware": 0,
        "actors": 1,
        "detections": 11,
        "cve": 0,
        "aliases": 0,
        "industries": 0,
        "attack_patterns": 25,
    },
    "aliases": [],
    "capabilities": [
        {"name": "Allocates memory", "description": "Capable of allocating memory. "},
    ],
    "cve": [],
    "roles": ["Backdoor"],
}

MOCK_MALWARE_REPORTS_RESPONSE = {
    "reports": [
        {
            "id": "report--d5a62569-1234-1234-882e-25d40c63e4c1",
            "report_id": "22-0000000",
            "title": "REPORT_TITLE",
            "published_date": "August 01, 2022 04:33:59 PM",
            "report_type": "Actor Profile",
            "version": "1.5",
            "audience": [{"license": "INTEL_CYB_ESP", "name": "cyber espionage"}],
        },
    ],
    "last_updated": "2023-02-07T02:17:24.000Z",
    "id": "malware--2debd90b-0000-1234-8838-1f9f58ca256b",
    "name": "MALWARE_NAME",
    "description": "MALWARE DESCRIPTION",
    "is_publishable": True,
}

MOCK_MALWARE_INDICATORS_RESPONSE = {
    "id": "malware--2debd90b-0000-1234-8838-1f9f58ca256b",
    "name": "MALWARE_NAME",
    "indicator_count": {
        "total": 13,
        "file": 12,
        "hash": 36,
        "url": 1,
        "fqdn": 0,
        "ipv4": 0,
        "email": 0,
    },
    "indicators": [
        {
            "first_seen": "2020-02-05T07:21:06.000Z",
            "last_seen": "2020-11-24T14:43:53.000Z",
            "sources": [
                {
                    "first_seen": "2020-02-05T07:21:06.000+0000",
                    "last_seen": "2020-02-07T00:56:09.000+0000",
                    "osint": False,
                    "category": [],
                    "source_name": "Mandiant",
                },
            ],
            "mscore": 100,
            "attributed_associations": [
                {
                    "id": "malware--2debd90b-0000-1234-8838-1f9f58ca256b",
                    "name": "FAKE_MALWARE",
                    "type": "malware",
                }
            ],
            "id": "url--19fbaec0-1111-2222-b6ac-d55dcc2c0d52",
            "type": "url",
            "value": "http://ip.ip.address/sushi/pages/controllers/session_controller.php",
            "is_publishable": True,
            "is_exclusive": True,
            "last_updated": "2022-08-01T15:44:40.342Z",
        },
    ],
}

MOCK_MALWARE_ATTACKPATTERN_RESPONSE = {
    "malware": [
        {
            "id": "malware--2debd90b-0000-1234-8838-1f9f58ca256b",
            "name": "MALWARE_NAME",
            "type": "malware-mitre",
            "attack-patterns": {
                "Persistence": [
                    {
                        "id": "attack-pattern--1ecb2399-1111-4f6b-8ba7-5c27d49405cf",
                        "sub_techniques": [],
                    }
                ],
            },
        }
    ],
    "attack-patterns": {
        "attack-pattern--1ecb2399-1111-4f6b-8ba7-5c27d49405cf": {
            "x_mitre_is_subtechnique": False,
            "created": "2020-01-23T17:46:59.535Z",
            "name": "Boot or Logon Autostart Execution",
            "attack_pattern_identifier": "T1547",
            "description": "ATTACK_PATTERN_DESCRIPTION",
            "modified": "2020-10-09T16:05:36.772Z",
            "id": "attack-pattern--1ecb2399-1111-4f6b-8ba7-5c27d49405cf",
        }
    },
}

MOCK_MALWARE_CAMPAIGNS_RESPONSE = {
    "campaigns": [],
    "total_count": 0,
    "id": "malware--2debd90b-0000-1234-8838-1f9f58ca256b",
    "name": "MALWARE_NAME",
    "last_transformed": "2023-02-07T04:59:45.331Z",
    "last_activity_time": "2023-02-07T02:17:24Z",
}


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client(requests_mock) -> MandiantAdvantageThreatIntelligence.MandiantClient:
    requests_mock.post(
        f"{SERVER_URL}/token",
        json={
            "access_token": "FAKE_ACCESS_TOKEN",
            "expires_in": 9999,
            "token_type": "Bearer",
        },
    )

    return MandiantAdvantageThreatIntelligence.MandiantClient(
        base_url=SERVER_URL,
        api_key="test",
        secret_key="test",
        verify=True,
        proxy=True,
        timeout=30,
        first_fetch="2020-01-24T05:01:13.000Z",
        limit=50,
        types=["Malware", "Actors", "Indicators"],
        metadata=True,
        enrichment=True,
        tags=None,
        tlp_color="RED",
    )


def test_reputation_file(
    client: MandiantAdvantageThreatIntelligence.MandiantClient, requests_mock, mocker
):
    requests_mock.post(
        f"{SERVER_URL}/v4/indicator", json={"indicators": [MOCK_MD5_INDICATOR_RESPONSE]}
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/indicator/{MOCK_MD5_INDICATOR_RESPONSE['id']}/reports",
        json=MOCK_IOC_INDICATOR_REPORT_RESPONSE,
    )

    mocker.patch.object(demisto, "command", return_value="file")

    results = MandiantAdvantageThreatIntelligence.fetch_reputation(
        client, args={"file": "0cc22fd05a3e771b09b584db0a16aaaa"}
    )

    results_dict = results.to_context()["Contents"][0]

    assert results_dict["score"] == 3
    assert results_dict["type"] == "File"
    assert (
        results_dict["fields"]["stixid"] == "md5--7c8be1f2-b949-aaaa-af7f-18908175108f"
    )
    assert (
        results_dict["fields"]["DBotScore"]["Indicator"]
        == "0cc22fd05a3e771b09b584db0a16aaaa"
    )
    assert results_dict["fields"]["md5"] == "0cc22fd05a3e771b09b584db0a16aaaa"
    assert (
        results_dict["fields"]["sha256"]
        == "efd431ae58a6092962ee9253722cfffe85cfc93bc051ba97ba26652a490faaaa"
    )
    assert results_dict["fields"]["sha1"] == "587977c02a628b8e1070bdc8dffbe4dcd414aaaa"
    assert results_dict["fields"]["trafficlightprotocol"] == "RED"


def test_reputation_domain(
    client: MandiantAdvantageThreatIntelligence.MandiantClient, requests_mock, mocker
):
    requests_mock.post(
        f"{SERVER_URL}/v4/indicator",
        json={"indicators": [MOCK_FQDN_INDICATOR_RESPONSE]},
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/indicator/{MOCK_FQDN_INDICATOR_RESPONSE['id']}/reports",
        json=MOCK_IOC_INDICATOR_REPORT_RESPONSE,
    )

    mocker.patch.object(demisto, "command", return_value="domain")

    results = MandiantAdvantageThreatIntelligence.fetch_reputation(
        client, args={"domain": "some.url.com"}
    )

    results_dict = results.to_context()["Contents"][0]

    assert results_dict["score"] == 3
    assert results_dict["type"] == "Domain"
    assert (
        results_dict["fields"]["stixid"] == "fqdn--be2e92a7-aaaa-5f35-8c6e-0731685aee19"
    )
    assert results_dict["fields"]["DBotScore"]["Indicator"] == "some.url.com"
    assert results_dict["fields"]["dns"] == "some.url.com"
    assert results_dict["fields"]["domain"] == "some.url.com"
    assert results_dict["fields"]["trafficlightprotocol"] == "GREEN"


def test_reputation_ip(
    client: MandiantAdvantageThreatIntelligence.MandiantClient, requests_mock, mocker
):
    requests_mock.post(
        f"{SERVER_URL}/v4/indicator", json={"indicators": [MOCK_IP_INDICATOR_RESPONSE]}
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/indicator/{MOCK_IP_INDICATOR_RESPONSE['id']}/reports",
        json=MOCK_IOC_INDICATOR_REPORT_RESPONSE,
    )

    mocker.patch.object(demisto, "command", return_value="ip")

    results = MandiantAdvantageThreatIntelligence.fetch_reputation(client, args={"ip": "154.91.84.82"})

    results_dict = results.to_context()["Contents"][0]

    assert results_dict["score"] == 0
    assert results_dict["type"] == "IP"
    assert (
        results_dict["fields"]["stixid"] == "ipv4--27063181-abcd-53ec-b785-3b9772febd50"
    )
    assert results_dict["fields"]["DBotScore"]["Indicator"] == "192.168.84.82"
    assert results_dict["fields"]["ip"] == "192.168.84.82"
    assert results_dict["fields"]["trafficlightprotocol"] == "GREEN"


def test_reputation_url(
    client: MandiantAdvantageThreatIntelligence.MandiantClient, requests_mock, mocker
):
    requests_mock.post(
        f"{SERVER_URL}/v4/indicator", json={"indicators": [MOCK_URL_INDICATOR_RESPONSE]}
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/indicator/{MOCK_URL_INDICATOR_RESPONSE['id']}/reports",
        json=MOCK_IOC_INDICATOR_REPORT_RESPONSE,
    )

    mocker.patch.object(demisto, "command", return_value="url")

    results = MandiantAdvantageThreatIntelligence.fetch_reputation(
        client, args={"url": "https://someurl.com"}
    )

    results_dict = results.to_context()["Contents"][0]

    assert results_dict["score"] == 1
    assert results_dict["type"] == "URL"
    assert (
        results_dict["fields"]["stixid"] == "url--02183bee-dcba-5d25-956b-765650f9e42a"
    )
    assert results_dict["fields"]["DBotScore"]["Indicator"] == "https://someurl.com"
    assert results_dict["fields"]["url"] == "https://someurl.com"
    assert results_dict["fields"]["trafficlightprotocol"] == "RED"


def test_reputation_cve(
    client: MandiantAdvantageThreatIntelligence.MandiantClient, requests_mock, mocker
):
    requests_mock.get(
        f"{SERVER_URL}/v4/vulnerability/{MOCK_CVE_RESPONSE['cve_id']}",
        json=MOCK_CVE_RESPONSE,
    )

    mocker.patch.object(demisto, "command", return_value="cve")

    results = MandiantAdvantageThreatIntelligence.fetch_reputation(
        client, args={"cve": "CVE-1234-12345"}
    )

    results_dict = results.to_context()["Contents"][0]

    assert results_dict["score"] == 0
    assert results_dict["type"] == "CVE"
    assert (
        results_dict["fields"]["stixid"]
        == "vulnerability--e3b6a556-abcd-dcba-b1df-8e1f0444e978"
    )
    assert results_dict["fields"]["trafficlightprotocol"] == "RED"
    assert results_dict["fields"]["DBotScore"]["Score"] == 0
    assert results_dict["fields"]["cvss"] == "v2.0"
    assert len(results_dict["fields"]["cvss2"]) > 0


def test_get_actor(client: MandiantAdvantageThreatIntelligence.MandiantClient, requests_mock, mocker):

    requests_mock.get(
        f"{SERVER_URL}/v4/actor/{MOCK_THREATACTOR_RESPONSE['name']}",
        json=MOCK_THREATACTOR_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/actor/{MOCK_THREATACTOR_RESPONSE['id']}/reports",
        json=MOCK_THREATACTOR_REPORTS_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/actor/{MOCK_THREATACTOR_RESPONSE['id']}/indicators",
        json=MOCK_THREATACTOR_INDICATORS_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/actor/{MOCK_THREATACTOR_RESPONSE['id']}/attack-pattern",
        json=MOCK_THREATACTOR_ATTACKPATTERN_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/actor/{MOCK_THREATACTOR_RESPONSE['id']}/campaigns",
        json=MOCK_THREATACTOR_CAMPAIGNS_RESPONSE,
    )

    mocker.patch.object(demisto, "command", return_value="get-actor")

    results = MandiantAdvantageThreatIntelligence.fetch_threat_actor(
        client, args={"actor_name": "FAKE_ACT0R"}
    )

    results_dict = results.to_context()["Contents"][0]

    assert results_dict["value"] == "FAKE_ACT0R"
    assert results_dict["type"] == "Threat Actor"
    assert results_dict["fields"]["primarymotivation"] == "Espionage"
    assert "TARGET_INDUSTRY" in results_dict["fields"]["tags"]
    assert "OTHER_ACT0R" in results_dict["fields"]["aliases"]
    assert "TARGET_COUNTRY" in results_dict["fields"]["targets"]
    assert (
        results_dict["fields"]["stixid"]
        == "threat-actor--f7fdbf0c-abcd-5b95-b005-702afffe4a72"
    )
    assert results_dict["fields"]["name"] == "FAKE_ACT0R"
    assert results_dict["fields"]["description"] == "ACTOR DESCRIPTION GOES HERE"
    assert results_dict["fields"]["trafficlightprotocol"] == "RED"
    assert results_dict["fields"]["DBot Score"]["Type"] == "Actor"
    assert results_dict["fields"]["publications"][0]["title"] == "REPORT TITLE"
    assert (
        results_dict["fields"]["publications"][0]["link"]
        == "https://advantage.mandiant.com/reports/23-00000722"
    )

    assert results_dict["relationships"][1]["entityB"] == "SOME_FREE_TOOL"
    assert results_dict["relationships"][1]["entityBType"] == "Tool"

    assert (
        results_dict["relationships"][4]["entityB"]
        == "http://somesite.com/qb/svhost.exe"
    )
    assert results_dict["relationships"][4]["entityBType"] == "URL"
    assert results_dict["relationships"][4]["entityBFamily"] == "Indicator"


def test_get_malware(client: MandiantAdvantageThreatIntelligence.MandiantClient, requests_mock, mocker):
    requests_mock.get(
        f"{SERVER_URL}/v4/malware/{MOCK_MALWARE_RESPONSE['name']}",
        json=MOCK_MALWARE_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/malware/{MOCK_MALWARE_RESPONSE['id']}/reports",
        json=MOCK_MALWARE_REPORTS_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/malware/{MOCK_MALWARE_RESPONSE['id']}/indicators",
        json=MOCK_MALWARE_INDICATORS_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/malware/{MOCK_MALWARE_RESPONSE['id']}/attack-pattern",
        json=MOCK_MALWARE_ATTACKPATTERN_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/malware/{MOCK_MALWARE_RESPONSE['id']}/campaigns",
        json=MOCK_MALWARE_CAMPAIGNS_RESPONSE,
    )

    mocker.patch.object(demisto, "command", return_value="get-malware")

    results = MandiantAdvantageThreatIntelligence.fetch_malware_family(
        client, args={"malware_name": "MALWARE_NAME"}
    )

    results_dict = results.to_context()["Contents"][0]

    assert results_dict["value"] == "MALWARE_NAME"
    assert results_dict["type"] == "Malware"

    assert results_dict["fields"]["operatingsystemrefs"] == ["Windows"]
    assert len(results_dict["fields"]["mandiantdetections"]) == 2
    assert "Backdoor" in results_dict["fields"]["roles"]
    assert (
        results_dict["fields"]["stixid"]
        == "malware--2debd90b-0000-1234-8838-1f9f58ca256b"
    )

    assert results_dict["fields"]["description"] == "MALWARE_DESCRIPTION"

    assert results_dict["fields"]["trafficlightprotocol"] == "RED"

    assert results_dict["fields"]["Is Malware Family"]

    assert results_dict["fields"]["publications"][0]["title"] == "REPORT_TITLE"
    assert (
        results_dict["fields"]["publications"][0]["link"]
        == "https://advantage.mandiant.com/reports/22-0000000"
    )

    assert (
        results_dict["relationships"][2]["entityB"]
        == "http://ip.ip.address/sushi/pages/controllers/session_controller.php"
    )
    assert results_dict["relationships"][2]["entityBType"] == "URL"
    assert results_dict["relationships"][2]["entityBFamily"] == "Indicator"


def test_fetch_indicators(
    client: MandiantAdvantageThreatIntelligence.MandiantClient, requests_mock, mocker
):
    requests_mock.get(
        f"{SERVER_URL}/v4/malware", json={"malware": [MOCK_MALWARE_RESPONSE]}
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/actor", json={"threat-actors": [MOCK_THREATACTOR_RESPONSE]}
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/indicator", json={"indicators": [MOCK_MD5_INDICATOR_RESPONSE]}
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/indicator/{MOCK_MD5_INDICATOR_RESPONSE['id']}", json=MOCK_MD5_INDICATOR_RESPONSE
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/malware/{MOCK_MALWARE_RESPONSE['id']}",
        json=MOCK_MALWARE_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/malware/{MOCK_MALWARE_RESPONSE['id']}/reports",
        json=MOCK_MALWARE_REPORTS_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/malware/{MOCK_MALWARE_RESPONSE['id']}/reports",
        json=MOCK_MALWARE_REPORTS_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/malware/{MOCK_MALWARE_RESPONSE['id']}/indicators",
        json=MOCK_MALWARE_INDICATORS_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/malware/{MOCK_MALWARE_RESPONSE['id']}/attack-pattern",
        json=MOCK_MALWARE_ATTACKPATTERN_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/malware/{MOCK_MALWARE_RESPONSE['id']}/campaigns",
        json=MOCK_MALWARE_CAMPAIGNS_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/actor/{MOCK_THREATACTOR_RESPONSE['id']}",
        json=MOCK_THREATACTOR_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/actor/{MOCK_THREATACTOR_RESPONSE['id']}/reports",
        json=MOCK_THREATACTOR_REPORTS_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/actor/{MOCK_THREATACTOR_RESPONSE['id']}/indicators",
        json=MOCK_THREATACTOR_INDICATORS_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/actor/{MOCK_THREATACTOR_RESPONSE['id']}/attack-pattern",
        json=MOCK_THREATACTOR_ATTACKPATTERN_RESPONSE,
    )

    requests_mock.get(
        f"{SERVER_URL}/v4/actor/{MOCK_THREATACTOR_RESPONSE['id']}/campaigns",
        json=MOCK_THREATACTOR_CAMPAIGNS_RESPONSE,
    )

    mocker.patch.object(
        demisto, "command", return_value="threat-intelligence-get-indicators"
    )

    results = MandiantAdvantageThreatIntelligence.fetch_indicators(client, args={"limit": 1})[0]

    malware = results[0]
    actor = results[1]
    file_ioc = results[2]

    assert malware["value"] == "MALWARE_NAME"
    assert malware["fields"]["mandiantdetections"] == ["DETECTION_ONE", "DETECTION_TWO"]
    assert (
        malware["fields"]["publications"][0]["link"]
        == "https://advantage.mandiant.com/reports/22-0000000"
    )

    assert malware["relationships"][0]["entityB"] == "FAKE_ACT0R"
    assert len(malware["relationships"][0]) == 10

    assert actor["value"] == "FAKE_ACT0R"
    assert actor["fields"]["tags"] == ["TARGET_INDUSTRY"]
    assert actor["fields"]["aliases"] == ["OTHER_ACT0R"]

    assert (
        actor["fields"]["publications"][0]["link"]
        == "https://advantage.mandiant.com/reports/23-00000722"
    )

    assert actor["relationships"][1]["entityB"] == "SOME_FREE_TOOL"
    assert actor["relationships"][1]["name"] == "uses"

    assert len(actor["relationships"]) == 7

    assert file_ioc["value"] == "0cc22fd05a3e771b09b584db0a16aaaa"

    assert file_ioc["score"] == 3
    assert file_ioc["fields"]["stixid"] == "md5--7c8be1f2-b949-aaaa-af7f-18908175108f"
