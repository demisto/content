import Mandiant
import pytest

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import


ADV_BASE_URL = "https://advantage.mandiant.com"

MOCK_IP_INDICATOR = {
    "id": "ipv4--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "ipv4",
    "value": "1.2.3.4",
    "is_exclusive": True,
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 100
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_DOMAIN_INDICATOR = {
    "id": "fqdn--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "fqdn",
    "value": "domain.test",
    "is_exclusive": True,
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 10
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_URL_INDICATOR = {
    "id": "url--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "url",
    "value": "https://domain.test/test",
    "is_exclusive": True,
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 25
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_FILE_INDICATOR = {
    "id": "md5--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "md5",
    "value": "ae1747c930e9e4f45fbc970a83b52284",
    "is_exclusive": True,
    "is_publishable": True,
    "associated_hashes": [
        {
            "id": "md5--1526529a-8489-55f5-a2f1-603ec2576f6c",
            "type": "md5",
            "value": "ae1747c930e9e4f45fbc970a83b52284"
        },
        {
            "id": "sha1--1526529a-8489-55f5-a2f1-603ec2576f6c",
            "type": "sha1",
            "value": "638cde28bbe3cfe7b53aa75a7cf6991baa692a4a"
        },
        {
            "id": "sha256--1526529a-8489-55f5-a2f1-603ec2576f6c",
            "type": "sha256",
            "value": "f68ec69a53130a24b0fe53d1d1fe70992d86a6d67006ae45f986f9ef4f450b6c"
        }
    ],
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 25
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
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
    "associated_actors": [
        {
            "aliases": [
                {
                    "attribution_scope": "confirmed",
                    "name": "Alias1"
                }
            ],
            "country_code": "PK",
            "description": "Actor Description",
            "id": "threat-actor--8e6665f0-0bf2-57ae-8299-1d041a82f362",
            "intel_free": False,
            "last_updated": "2024-07-11T03:17:06.023Z",
            "name": "ACTOR_NAME"
        }
    ],
    "associated_malware": [
        {
            "aliases": [
                {
                    "name": "Alias1"
                }
            ],
            "description": "Malware description",
            "has_yara": False,
            "id": "malware--ecf0417c-4abf-5f61-b4d9-4f9b4d2856c4",
            "intel_free": False,
            "is_malicious": True,
            "last_updated": "2022-10-05T14:33:11.263Z",
            "name": "MALWARE_NAME"
        }
    ],
    "associated_reports": [
        {
            "audience": [
                "vulnerability"
            ],
            "published_date": "2022-05-10T19:08:55.620Z",
            "report_id": "21-00014500",
            "report_type": "Trends and Forecasting",
            "title": "REPORT_TITLE"
        }
    ],
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
    "vulnerable_cpes": [
        {
            "cpe": "cpe:2.3:o:product:vendor:40:*:*:*:*:*:*:*",
            "cpe_title": "Vendor Product Version",
            "technology_name": "Product",
            "vendor_name": "Vendor"
        }
    ],
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
    "cpe_ranges": [
        {
            "end_cpe": None,
            "end_rel": None,
            "start_cpe": {
                "product": "Product",
                "uri": "cpe:2.3:o:product:vendor:40:*:*:*:*:*:*:*",
                "vendor": "Vendor",
                "version": "40"
            },
            "start_rel": "="
        },
    ],
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
    "cve": [
        {
            "attribution_scope": "confirmed",
            "cve_id": "CVE-2024-1234",
            "id": "vulnerability--12345678"
        }
    ],
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
    "industries": [
        {
            "id": "identity--65be572d-abcd-dcba-96e5-a5fb1d7f2bab",
            "name": "TARGET_INDUSTRY",
            "attribution_scope": "confirmed",
            "first_seen": "2017-05-02T11:55:27.000Z",
            "last_seen": "2022-08-16T08:02:00.000Z",
        }
    ],
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

MOCK_CAMPAIGN_RESPONSE = {
    "type": "campaign",
    "id": "campaign--7d322878-9cf2-5898-a9c0-dfcd852f567a",
    "name": "CAMPAIGN NAME",
    "description": "CAMPAIGN DESCRIPTION",
    "releasable": True,
    "counts": {
        "actors": 1,
        "reports": 3,
        "malware": 4,
        "campaigns": 0,
        "industries": 3,
        "timeline": 38,
        "vulnerabilities": 0,
        "actor_collaborations": 0,
        "tools": 3
    },
    "audience": [
        {
            "name": "intel_fusion",
            "license": "INTEL_RBI_FUS"
        },
        {
            "name": "intel_oper",
            "license": "INTEL_RBI_OPS"
        },
        {
            "name": "tlp_marking",
            "license": "amber"
        }
    ],
    "aliases": {
        "releasable": True,
        "malware": [],
        "campaign": [],
        "actor": []
    },
    "profile_updated": "2024-07-16T21:09:48.846Z",
    "campaign_type": "Individual",
    "short_name": "CAMP.24.004",
    "last_activity_time": "2024-07-16T00:00:00.000Z",
    "timeline": [
        {
            "name": "First Observed",
            "description": "Mandiant Observed First Activity of Campaign",
            "releasable": True,
            "event_type": "first_observed",
            "timestamp": "2023-07-10T00:00:00.000Z"
        }
    ],
    "campaigns": [],
    "actors": [
        {
            "type": "threat-actor",
            "id": "threat-actor--2067bce6-44c0-5d82-afd8-f2f1c9dd30e0",
            "name": "APT44",
            "attribution_scope": "confirmed",
            "releasable": True,
            "motivations": [
                {
                    "type": "motivation",
                    "id": "motivation--1b8ca82a-7cff-5622-bedd-965c11d38a9e",
                    "name": "Espionage",
                    "attribution_scope": "confirmed",
                    "releasable": True
                },
                {
                    "type": "motivation",
                    "id": "motivation--e73a81b4-c299-5f2e-bff2-3aa97781d7e2",
                    "name": "Attack / Destruction",
                    "attribution_scope": "confirmed",
                    "releasable": True
                }
            ],
            "source_locations": [
                {
                    "releasable": True,
                    "country": {
                        "type": "location",
                        "id": "location--188145fd-6fd1-5bd6-a70c-8e33ed149584",
                        "name": "Russia",
                        "attribution_scope": "confirmed",
                        "iso2": "RU",
                        "releasable": True
                    },
                    "region": {
                        "type": "location",
                        "id": "location--89b58fc6-de5e-55e4-9d8c-29ba659e770f",
                        "name": "Europe",
                        "attribution_scope": "confirmed",
                        "releasable": True
                    },
                    "sub_region": {
                        "type": "location",
                        "id": "location--57644af5-a064-5e14-be58-05b22d2768be",
                        "name": "East Europe",
                        "attribution_scope": "confirmed",
                        "releasable": True
                    }
                }
            ]
        }
    ],
    "malware": [
        {
            "type": "malware",
            "id": "malware--b3679502-9015-5d9b-a819-4947df9a0e6a",
            "name": "BACKORDER.V2",
            "attribution_scope": "confirmed",
            "releasable": True,
            "inherently_malicious": 1
        }
    ],
    "tools": [
        {
            "type": "malware",
            "id": "malware--5ea42033-7378-58d7-9bed-e317ebf24485",
            "name": "CURL",
            "attribution_scope": "confirmed",
            "releasable": True
        }
    ],
    "vulnerabilities": [],
    "industries": [
        {
            "type": "identity",
            "id": "identity--8d0881d8-d199-5e5a-bef9-be3ca6bb8f0d",
            "name": "Governments",
            "attribution_scope": "confirmed",
            "releasable": True
        }
    ],
    "target_locations": {
        "releasable": True,
        "countries": [
            {
                "id": "location--1228220c-7de8-5dc6-94bf-98b2fa79bb7f",
                "name": "Ukraine",
                "attribution_scope": "confirmed",
                "releasable": True,
                "type": "location",
                "count": 5,
                "iso2": "UA",
                "sub_region": "location--57644af5-a064-5e14-be58-05b22d2768be",
                "region": "location--89b58fc6-de5e-55e4-9d8c-29ba659e770f"
            }
        ],
        "regions": [
            {
                "id": "location--89b58fc6-de5e-55e4-9d8c-29ba659e770f",
                "name": "Europe",
                "attribution_scope": "confirmed",
                "releasable": True,
                "type": "location",
                "count": 5
            }
        ],
        "sub_regions": [
            {
                "id": "location--57644af5-a064-5e14-be58-05b22d2768be",
                "name": "East Europe",
                "attribution_scope": "confirmed",
                "releasable": True,
                "type": "location",
                "count": 5,
                "region": "location--89b58fc6-de5e-55e4-9d8c-29ba659e770f"
            }
        ]
    },
    "actor_collaborations": [],
    "is_publishable": True,
    "intel_free": False
}

MOCK_MALWARE_CAMPAIGNS_RESPONSE = {
    "campaigns": [],
    "total_count": 0,
    "id": "malware--2debd90b-0000-1234-8838-1f9f58ca256b",
    "name": "MALWARE_NAME",
    "last_transformed": "2023-02-07T04:59:45.331Z",
    "last_activity_time": "2023-02-07T02:17:24Z",
}

MOCK_THREAT_ACTOR_CAMPAIGNS_RESPONSE = {
    "campaigns": [],
    "total_count": 1,
    "id": "threat-actor--2debd90b-0000-1234-8838-1f9f58ca256b",
    "name": "ACTOR_NAME",
    "last_transformed": "2023-02-07T04:59:45.331Z",
    "last_activity_time": "2023-02-07T02:17:24Z",
}


@pytest.fixture
def config():
    """Fixture to provide a mock configuration."""
    return {
        "api_key": "test_api_key",
        "secret_key": "test_secret_key",
        "timeout": 60,
        "tlp_color": "RED",
        "reliability": "A - Completely reliable",
        "tags": "tag1, tag2",
        "map_to_mitre_attack": True
    }


@pytest.fixture
def client(config):
    """Fixture to create a MandiantClient instance with mock config."""
    return Mandiant.MandiantClient(config)


@pytest.fixture
def mock_http_request(mocker):
    """Fixture to mock the _http_request method."""
    return mocker.patch.object(Mandiant.MandiantClient, "_http_request", autospec=True)


def test_mandiant_client_init(client, config):
    """Test that the client is initialized correctly."""
    assert client.api_key == config["api_key"]
    assert client.secret_key == config["secret_key"]
    assert client.timeout == config["timeout"]
    assert client.reliability == config["reliability"]
    assert client.tlp_color == "RED"


def test_get_entitlements(client, mock_http_request):
    """Test getting entitlements."""
    mock_response = {"entitlements": ["Entitlement1"]}
    mock_http_request.return_value = mock_response

    response = client.get_entitlements()
    assert response == mock_response
    assert mock_http_request.call_count == 1


def test_get_indicators_by_value(client, mock_http_request):
    """Testing getting indicator"""
    mock_response = {"indicators": [MOCK_IP_INDICATOR]}
    mock_http_request.return_value = mock_response

    response = client.get_indicators_by_value(["1.2.3.4"])

    assert response == mock_response.get("indicators")
    assert mock_http_request.call_count == 1


def test_get_actor(client, mock_http_request):
    """Test getting actor"""
    mock_response = MOCK_THREATACTOR_RESPONSE
    mock_http_request.return_value = mock_response

    response = client.get_actor("FAKE_ACTOR")

    assert response == mock_response
    assert mock_http_request.call_count == 1


def test_get_malware(client, mock_http_request):
    """Test getting malware"""
    mock_response = MOCK_MALWARE_RESPONSE
    mock_http_request.return_value = mock_response

    response = client.get_actor("FAKE_MALWARE")

    assert response == mock_response
    assert mock_http_request.call_count == 1


def test_get_campaign(client, mock_http_request):
    """Test getting campaign"""
    mock_response = MOCK_CAMPAIGN_RESPONSE
    mock_http_request.return_value = mock_response

    response = client.get_campaign("campaign--1234")

    assert response == mock_response
    assert mock_http_request.call_count == 1


def test_get_attack_patterns(client, mock_http_request):
    """Test getting attack patterns"""
    mock_response = MOCK_THREATACTOR_ATTACKPATTERN_RESPONSE
    mock_http_request.return_value = mock_response

    response = client.get_attack_patterns("actor", "threat-actor--1234")

    assert response == mock_response
    assert mock_http_request.call_count == 1


def test_get_associated_campaigns(client, mock_http_request):
    """Test getting associated campaigns"""
    mock_response = MOCK_MALWARE_REPORTS_RESPONSE
    mock_http_request.return_value = mock_response

    response = client.get_associated_campaigns("malware", "malware--1234")

    assert response == mock_response
    assert mock_http_request.call_count == 1


def test_get_cve(client, mock_http_request):
    """Test getting cve"""
    mock_response = MOCK_CVE_RESPONSE
    mock_http_request.return_value = mock_response

    response = client.get_cve_by_cveid("CVE-2024-1234")

    assert response == mock_response
    assert mock_http_request.call_count == 1


def test_calculate_dbot_score(client):
    """
    Tests the calculate_dbot_score function with various threat scores
    and their expected DBotScore values.
    """
    result = Mandiant.MatiIndicator(client, MOCK_IP_INDICATOR, FeedIndicatorType.IP).calculate_dbot_score()
    assert result == 3


def test_create_dbot_score(client):
    """Test creating DBotScore"""
    indicator_client = Mandiant.MatiIndicator(client, MOCK_IP_INDICATOR, FeedIndicatorType.IP)
    indicator_client.dbot_score_type = DBotScoreType.IP
    result = indicator_client.create_dbot_score()

    assert isinstance(result, Common.DBotScore)
    assert result.indicator == "1.2.3.4"
    assert result.indicator_type == "ip"
    assert result.reliability == "A - Completely reliable"
    assert result.score == 3


@pytest.mark.parametrize(
    "indicator, expected_sources",
    [({}, []),
     ({"some_other_key": "value"}, []),
     ({"sources": []}, []),
     ({"sources": [{"source_name": "SourceA"}, {"source_name": "SourceB"}, {}]}, ["sourcea", "sourceb", ""]),
     ({"sources": [{"source_name": "SOURCE_C"}]}, ["source_c"])]
)
def test_build_sources(client, indicator, expected_sources):
    assert Mandiant.MatiIndicator(client, indicator, FeedIndicatorType.IP).build_source_names() == expected_sources


@pytest.mark.parametrize(
    "indicator, expected_output",
    [
        ({}, "-"),
        ({"campaigns": []}, "-"),
        (
            {
                "campaigns": [
                    {"title": "Campaign 1", "name": "camp1"},
                    {"title": "Campaign 2", "name": "camp2"},
                ]
            },
            "Campaign 1 (camp1), Campaign 2 (camp2)",
        ),
        ({"campaigns": [{"title": "Only Title"}]}, "-"),
        (
            {"campaigns": [{"name": "Only ID"}]},
            "-"
        ),
    ],
)
def test_get_indicator_campaigns(client, indicator, expected_output):
    result = Mandiant.MatiIndicator(client, indicator, FeedIndicatorType.IP).build_campaigns()
    assert result == expected_output


@pytest.mark.parametrize(
    "indicator, expected_output",
    [
        ({}, "-"),
        ({"attributed_associations": []}, "-"),
        ({"attributed_associations": [{"type": "other"}]}, "-"),
        (
            {"attributed_associations": [{"type": "malware", "name": "TrickBot"}]},
            "TrickBot",
        ),
        (
            {
                "attributed_associations": [
                    {"type": "malware", "name": "TrickBot"},
                    {"type": "malware", "name": "Emotet"},
                ]
            },
            "TrickBot, Emotet",
        ),
    ],
)
def test_get_indicator_malware_families(client, indicator, expected_output):
    result = Mandiant.MatiIndicator(client, indicator, FeedIndicatorType.IP).build_malware_families()
    assert result == expected_output


@pytest.mark.parametrize(
    "indicator, publication_count",
    [
        # Test case 1: Empty reports list
        ({}, 0),

        # Test case 2: Single report
        (
            {
                "reports": [
                    {"title": "Report 1", "report_id": "12345", "published_date": "2024-07-16"}
                ]
            },
            1
        ),

        # Test case 3: Multiple reports
        (
            {
                "reports": [
                    {"title": "Report 1", "report_id": "12345", "published_date": "2024-07-16"},
                    {"title": "Report 2", "report_id": "67890", "published_date": "2024-07-15"}
                ]
            },
            2
        )
    ]
)
def test_build_publications(client, indicator, publication_count):
    result = Mandiant.MatiIndicator(client, indicator, FeedIndicatorType.IP).build_publications()
    assert len(result) == publication_count
    if len(result) > 0:
        for r in result:
            assert r.source == "Mandiant"
            assert hasattr(r, "title")
            assert hasattr(r, "link")
            assert hasattr(r, "timestamp")


def test_build_indicator_relationships(client):
    result = Mandiant.MatiIndicator(client, MOCK_IP_INDICATOR, FeedIndicatorType.IP).build_relationships()
    assert isinstance(result, List)
    for r in result:
        assert isinstance(r, EntityRelationship)


def test_build_threat_types(client):
    result = Mandiant.MatiIndicator(client, MOCK_IP_INDICATOR, FeedIndicatorType.IP).build_threat_types()
    assert isinstance(result, List)
    for r in result:
        assert isinstance(r, Common.ThreatTypes)


@pytest.mark.parametrize(
    "indicator, hash_type, expected_hash_value",
    [({"associated_hashes": [{"type": "md5", "value": "abcdef123"}]}, "md5", "abcdef123"),
     ({"associated_hashes": [{"type": "sha256", "value": ""}]}, "sha256", ""),
     ({"associated_hashes": [{"type": "sha1", "value": "zyx987"}]}, "md5", ""),
     ({"associated_hashes": []}, "md5", ""),
     ({}, "md5", "")]
)
def test_get_hash_value(client, indicator, hash_type, expected_hash_value):
    assert Mandiant.MatiFileIndicator(client, indicator, "asdf").get_hash_value(hash_type) == expected_hash_value


def test_ip_reputation_command_success(client, mock_http_request):
    mock_response = {"indicators": [MOCK_IP_INDICATOR]}
    mock_http_request.return_value = mock_response
    args = {"ip": "1.2.3.4"}
    results = Mandiant.ip_reputation_command(client, args)
    assert len(results) == 1
    result = results[0]
    assert result.outputs_prefix == "Mandiant.IP"
    assert result.indicator.ip == "1.2.3.4"
    assert result.indicator.tags == ["control-server", "tag1", "tag2"]
    assert result.indicator.stix_id == "ipv4--1526529a-8489-55f5-a2f1-603ec2576f6c"
    assert result.indicator.traffic_light_protocol == "RED"
    assert result.indicator.campaign == "CAMPAIGN_TITLE (CAMP.123)"
    assert result.indicator.publications[0].source == "Mandiant"
    assert result.indicator.publications[0].title == "REPORT_TITLE (REPORT_ID)"
    assert result.indicator.publications[0].link == f"{ADV_BASE_URL}/reports/REPORT_ID"
    assert result.indicator.publications[0].timestamp == "2024-05-31T12:00:53.000Z"
    assert result.indicator.malware_family == "MALWARE_NAME"
    assert result.indicator.relationships[0]._name == "uses"
    assert result.indicator.relationships[0]._reverse_name == "used-by"
    assert result.indicator.relationships[0]._relationship_type == "IndicatorToIndicator"
    assert result.indicator.relationships[0]._entity_a == "1.2.3.4"
    assert result.indicator.relationships[0]._entity_a_type == "IP"
    assert result.indicator.relationships[0]._entity_a_family == "Indicator"
    assert result.indicator.relationships[0]._entity_b == "ACTOR_NAME"
    assert result.indicator.relationships[0]._entity_b_type == "Threat Actor"
    assert result.indicator.relationships[0]._entity_b_family == "Indicator"
    assert result.indicator.relationships[0]._brand == "Mandiant"
    assert result.indicator.relationships[1]._name == "indicates"
    assert result.indicator.relationships[1]._reverse_name == "indicator-of"
    assert result.indicator.relationships[1]._relationship_type == "IndicatorToIndicator"
    assert result.indicator.relationships[1]._entity_a == "1.2.3.4"
    assert result.indicator.relationships[1]._entity_a_type == "IP"
    assert result.indicator.relationships[1]._entity_a_family == "Indicator"
    assert result.indicator.relationships[1]._entity_b == "MALWARE_NAME"
    assert result.indicator.relationships[1]._entity_b_type == "Malware"
    assert result.indicator.relationships[1]._entity_b_family == "Indicator"
    assert result.indicator.relationships[1]._brand == "Mandiant"
    assert result.outputs.get("value") == "1.2.3.4"
    assert result.outputs.get("type") == "ipv4"
    assert result.indicator.dbot_score.indicator == "1.2.3.4"
    assert result.indicator.dbot_score.indicator_type == "ip"
    assert result.indicator.dbot_score.integration_name == "Mandiant"
    assert result.indicator.dbot_score.score == 3
    assert result.indicator.dbot_score.reliability == "A - Completely reliable"
    assert result.readable_output == ("### Mandiant Advantage Threat Intelligence information for 1.2.3.4\n[View on Man"
                                      + f"diant Advantage]({ADV_BASE_URL}/indicator/ipv4--1526529a-"
                                      + "8489-55f5-a2f1-603ec2576f6c)\n|Campaigns|Categories|Last Seen|Malware|Reports|"
                                      + "Threat Score|\n|---|---|---|---|---|---|\n| CAMPAIGN_TITLE (CAMP.123) | contro"
                                      + "l-server | 2024-06-09T00:14:03.000Z | MALWARE_NAME | REPORT_TITLE (REPORT_ID) "
                                      + "| 100 |\n")


def test_domain_reputation_command_success(client, mock_http_request):
    mock_response = {"indicators": [MOCK_DOMAIN_INDICATOR]}
    mock_http_request.return_value = mock_response
    args = {"domain": "domain.test"}
    results = Mandiant.domain_reputation_command(client, args)
    assert len(results) == 1
    result = results[0]
    assert result.outputs_prefix == "Mandiant.Domain"
    assert result.indicator.domain == "domain.test"
    assert result.indicator.stix_id == "fqdn--1526529a-8489-55f5-a2f1-603ec2576f6c"
    assert result.indicator.tags == ["control-server", "tag1", "tag2"]
    assert result.indicator.traffic_light_protocol == "RED"
    assert result.indicator.malware_family == "MALWARE_NAME"
    assert result.indicator.campaign == "CAMPAIGN_TITLE (CAMP.123)"
    assert result.indicator.publications[0].source == "Mandiant"
    assert result.indicator.publications[0].title == "REPORT_TITLE (REPORT_ID)"
    assert result.indicator.publications[0].link == f"{ADV_BASE_URL}/reports/REPORT_ID"
    assert result.indicator.publications[0].timestamp == "2024-05-31T12:00:53.000Z"
    assert result.indicator.malware_family == "MALWARE_NAME"
    assert result.indicator.relationships[0]._name == "uses"
    assert result.indicator.relationships[0]._reverse_name == "used-by"
    assert result.indicator.relationships[0]._relationship_type == "IndicatorToIndicator"
    assert result.indicator.relationships[0]._entity_a == "domain.test"
    assert result.indicator.relationships[0]._entity_a_type == "Domain"
    assert result.indicator.relationships[0]._entity_a_family == "Indicator"
    assert result.indicator.relationships[0]._entity_b == "ACTOR_NAME"
    assert result.indicator.relationships[0]._entity_b_type == "Threat Actor"
    assert result.indicator.relationships[0]._entity_b_family == "Indicator"
    assert result.indicator.relationships[0]._brand == "Mandiant"
    assert result.indicator.relationships[1]._name == "indicates"
    assert result.indicator.relationships[1]._reverse_name == "indicator-of"
    assert result.indicator.relationships[1]._relationship_type == "IndicatorToIndicator"
    assert result.indicator.relationships[1]._entity_a == "domain.test"
    assert result.indicator.relationships[1]._entity_a_type == "Domain"
    assert result.indicator.relationships[1]._entity_a_family == "Indicator"
    assert result.indicator.relationships[1]._entity_b == "MALWARE_NAME"
    assert result.indicator.relationships[1]._entity_b_type == "Malware"
    assert result.indicator.relationships[1]._entity_b_family == "Indicator"
    assert result.indicator.relationships[1]._brand == "Mandiant"
    assert result.outputs.get("value") == "domain.test"
    assert result.outputs.get("type") == "fqdn"
    assert result.indicator.dbot_score.indicator == "domain.test"
    assert result.indicator.dbot_score.indicator_type == "domain"
    assert result.indicator.dbot_score.integration_name == "Mandiant"
    assert result.indicator.dbot_score.score == 1
    assert result.indicator.dbot_score.reliability == "A - Completely reliable"
    assert result.readable_output == ("### Mandiant Advantage Threat Intelligence information for domain.test\n[View on"
                                      + f" Mandiant Advantage]({ADV_BASE_URL}/indicator/fqdn--15265"
                                      + "29a-8489-55f5-a2f1-603ec2576f6c)\n|Campaigns|Categories|Last Seen|Malware|Repo"
                                      + "rts|Threat Score|\n|---|---|---|---|---|---|\n| CAMPAIGN_TITLE (CAMP.123) | co"
                                      + "ntrol-server | 2024-06-09T00:14:03.000Z | MALWARE_NAME | REPORT_TITLE (REPORT_"
                                      + "ID) | 10 |\n")


def test_url_reputation_command_success(client, mock_http_request):
    mock_response = {"indicators": [MOCK_URL_INDICATOR]}
    mock_http_request.return_value = mock_response
    args = {"url": "https://domain.test/test"}
    results = Mandiant.url_reputation_command(client, args)
    assert len(results) == 1
    result = results[0]
    assert result.outputs_prefix == "Mandiant.URL"
    assert result.indicator.url == "https://domain.test/test"
    assert result.indicator.stix_id == "url--1526529a-8489-55f5-a2f1-603ec2576f6c"
    assert result.indicator.tags == ["control-server", "tag1", "tag2"]
    assert result.indicator.traffic_light_protocol == "RED"
    assert result.indicator.malware_family == "MALWARE_NAME"
    assert result.indicator.campaign == "CAMPAIGN_TITLE (CAMP.123)"
    assert result.indicator.relationships[0]._name == "uses"
    assert result.indicator.relationships[0]._reverse_name == "used-by"
    assert result.indicator.relationships[0]._relationship_type == "IndicatorToIndicator"
    assert result.indicator.relationships[0]._entity_a == "https://domain.test/test"
    assert result.indicator.relationships[0]._entity_a_type == "URL"
    assert result.indicator.relationships[0]._entity_a_family == "Indicator"
    assert result.indicator.relationships[0]._entity_b == "ACTOR_NAME"
    assert result.indicator.relationships[0]._entity_b_type == "Threat Actor"
    assert result.indicator.relationships[0]._entity_b_family == "Indicator"
    assert result.indicator.relationships[0]._brand == "Mandiant"
    assert result.indicator.relationships[1]._name == "indicates"
    assert result.indicator.relationships[1]._reverse_name == "indicator-of"
    assert result.indicator.relationships[1]._relationship_type == "IndicatorToIndicator"
    assert result.indicator.relationships[1]._entity_a == "https://domain.test/test"
    assert result.indicator.relationships[1]._entity_a_type == "URL"
    assert result.indicator.relationships[1]._entity_a_family == "Indicator"
    assert result.indicator.relationships[1]._entity_b == "MALWARE_NAME"
    assert result.indicator.relationships[1]._entity_b_type == "Malware"
    assert result.indicator.relationships[1]._entity_b_family == "Indicator"
    assert result.indicator.relationships[1]._brand == "Mandiant"
    assert result.outputs.get("value") == "https://domain.test/test"
    assert result.outputs.get("type") == "url"
    assert result.indicator.dbot_score.indicator == "https://domain.test/test"
    assert result.indicator.dbot_score.indicator_type == "url"
    assert result.indicator.dbot_score.integration_name == "Mandiant"
    assert result.indicator.dbot_score.score == 2
    assert result.readable_output == ("### Mandiant Advantage Threat Intelligence information for https://domain.test/t"
                                      + f"est\n[View on Mandiant Advantage]({ADV_BASE_URL}/indicator"
                                      + "/url--1526529a-8489-55f5-a2f1-603ec2576f6c)\n|Campaigns|Categories|Last Seen|M"
                                      + "alware|Reports|Threat Score|\n|---|---|---|---|---|---|\n| CAMPAIGN_TITLE (CAM"
                                      + "P.123) | control-server | 2024-06-09T00:14:03.000Z | MALWARE_NAME | REPORT_TIT"
                                      + "LE (REPORT_ID) | 25 |\n")


def test_file_reputation_command_success(client, mock_http_request):
    mock_response = {"indicators": [MOCK_FILE_INDICATOR]}
    mock_http_request.return_value = mock_response
    args = {"file": "ae1747c930e9e4f45fbc970a83b52284"}
    results = Mandiant.file_reputation_command(client, args)
    assert len(results) == 1
    result = results[0]
    assert result.outputs_prefix == "Mandiant.File"
    assert result.indicator.md5 == "ae1747c930e9e4f45fbc970a83b52284"
    assert result.indicator.sha1 == "638cde28bbe3cfe7b53aa75a7cf6991baa692a4a"
    assert result.indicator.sha256 == "f68ec69a53130a24b0fe53d1d1fe70992d86a6d67006ae45f986f9ef4f450b6c"
    assert result.indicator.stix_id == "md5--1526529a-8489-55f5-a2f1-603ec2576f6c"
    assert result.indicator.tags == ["control-server", "tag1", "tag2"]
    assert result.indicator.traffic_light_protocol == "RED"
    assert result.indicator.name == "ae1747c930e9e4f45fbc970a83b52284"
    assert result.indicator.malware_family == "MALWARE_NAME"
    assert result.indicator.campaign == "CAMPAIGN_TITLE (CAMP.123)"
    assert result.indicator.relationships[0]._name == "uses"
    assert result.indicator.relationships[0]._reverse_name == "used-by"
    assert result.indicator.relationships[0]._relationship_type == "IndicatorToIndicator"
    assert result.indicator.relationships[0]._entity_a == "ae1747c930e9e4f45fbc970a83b52284"
    assert result.indicator.relationships[0]._entity_a_type == "File"
    assert result.indicator.relationships[0]._entity_a_family == "Indicator"
    assert result.indicator.relationships[0]._entity_b == "ACTOR_NAME"
    assert result.indicator.relationships[0]._entity_b_type == "Threat Actor"
    assert result.indicator.relationships[0]._entity_b_family == "Indicator"
    assert result.indicator.relationships[0]._brand == "Mandiant"
    assert result.indicator.relationships[1]._name == "indicates"
    assert result.indicator.relationships[1]._reverse_name == "indicator-of"
    assert result.indicator.relationships[1]._relationship_type == "IndicatorToIndicator"
    assert result.indicator.relationships[1]._entity_a == "ae1747c930e9e4f45fbc970a83b52284"
    assert result.indicator.relationships[1]._entity_a_type == "File"
    assert result.indicator.relationships[1]._entity_a_family == "Indicator"
    assert result.indicator.relationships[1]._entity_b == "MALWARE_NAME"
    assert result.indicator.relationships[1]._entity_b_type == "Malware"
    assert result.indicator.relationships[1]._entity_b_family == "Indicator"
    assert result.indicator.relationships[1]._brand == "Mandiant"
    assert result.outputs.get("value") == "ae1747c930e9e4f45fbc970a83b52284"
    assert result.outputs.get("type") == "md5"
    assert result.indicator.dbot_score.indicator == "ae1747c930e9e4f45fbc970a83b52284"
    assert result.indicator.dbot_score.indicator_type == "file"
    assert result.indicator.dbot_score.integration_name == "Mandiant"
    assert result.indicator.dbot_score.score == 2
    assert result.readable_output == ("### Mandiant Advantage Threat Intelligence information for ae1747c930e9e4f45fbc9"
                                      + f"70a83b52284\n[View on Mandiant Advantage]({ADV_BASE_URL}/indic"
                                      + "ator/md5--1526529a-8489-55f5-a2f1-603ec2576f6c)\n|Campaigns|Categories|Las"
                                      + "t Seen|Malware|Reports|Threat Score|\n|---|---|---|---|---|---|\n| CAMPAIGN_TI"
                                      + "TLE (CAMP.123) | control-server | 2024-06-09T00:14:03.000Z | MALWARE_NAME | RE"
                                      + "PORT_TITLE (REPORT_ID) | 25 |\n")


def test_ip_reputation_ip_not_found(client, mock_http_request):
    mock_response: Dict[str, List] = {"indicators": []}
    mock_http_request.return_value = mock_response
    args = {"ip": "6.7.8.9"}
    results = Mandiant.ip_reputation_command(client, args)
    assert results[0].readable_output == "6.7.8.9 not found"


def test_doamin_reputation_domain_not_found(client, mock_http_request):
    mock_response: Dict[str, List] = {"indicators": []}
    mock_http_request.return_value = mock_response
    args = {"domain": "not.exists"}
    results = Mandiant.domain_reputation_command(client, args)
    assert results[0].readable_output == "not.exists not found"


def test_url_reputation_url_not_found(client, mock_http_request):
    mock_response: Dict[str, List] = {"indicators": []}
    mock_http_request.return_value = mock_response
    args = {"url": "http://not.exists"}
    results = Mandiant.url_reputation_command(client, args)
    assert results[0].readable_output == "http://not.exists not found"


def test_file_reputation_file_not_found(client, mock_http_request):
    mock_response: Dict[str, List] = {"indicators": []}
    mock_http_request.return_value = mock_response
    args = {"file": "asdf"}
    results = Mandiant.file_reputation_command(client, args)
    assert results[0].readable_output == "asdf not found"


def test_build_cve_relationships(client):
    result = Mandiant.MatiCve(MOCK_CVE_RESPONSE, client.reliability, "RED", ["tag1"]).build_relationships()
    assert result[0]._name == "used-by"
    assert result[0]._reverse_name == "exploits"
    assert result[0]._relationship_type == "IndicatorToIndicator"
    assert result[0]._entity_a == "CVE-1234-12345"
    assert result[0]._entity_a_type == "Indicator"
    assert result[0]._entity_a_family == "Indicator"
    assert result[0]._entity_b == "ACTOR_NAME"
    assert result[0]._entity_b_type == "Threat Actor"
    assert result[0]._entity_b_family == "Indicator"
    assert result[1]._name == "used-by"
    assert result[1]._reverse_name == "exploits"
    assert result[1]._relationship_type == "IndicatorToIndicator"
    assert result[1]._entity_a == "CVE-1234-12345"
    assert result[1]._entity_a_type == "Indicator"
    assert result[1]._entity_a_family == "Indicator"
    assert result[1]._entity_b == "MALWARE_NAME"
    assert result[1]._entity_b_type == "Malware"
    assert result[1]._entity_b_family == "Indicator"


def test_build_cve_publications(client):
    result = Mandiant.MatiCve(MOCK_CVE_RESPONSE, client.reliability, "RED", ["tag1"]).build_publications()
    assert result[0].source == "Mandiant"
    assert result[0].title == "REPORT_TITLE"
    assert result[0].link == f"{ADV_BASE_URL}/reports/21-00014500"
    assert result[0].timestamp == "2022-05-10T19:08:55.620Z"


@pytest.mark.parametrize(
    "cvss_score, expected_dbot_score",
    [
        ("0.0", Common.DBotScore.NONE),
        # ("2.5", Common.DBotScore.GOOD),
        # ("4.8", Common.DBotScore.SUSPICIOUS),
        # ("9.2", Common.DBotScore.BAD),
        # ("10.5", Common.DBotScore.NONE),
        # ("-1.3", Common.DBotScore.NONE),
        # ("invalid", Common.DBotScore.NONE),
    ],
)
def test_calculate_cve_dbot_score(client, cvss_score, expected_dbot_score):
    """Tests the calculation of the DBot score based on a given CVSS score."""
    cve_client = Mandiant.MatiCve(MOCK_CVE_RESPONSE, client.reliability, "RED", ["tag1"])
    cve_client.cvss_score = cvss_score
    result = cve_client.calculate_cve_dbot_score()
    assert result == expected_dbot_score


def test_create_cve_dbot_score(client):
    result = Mandiant.MatiCve(MOCK_CVE_RESPONSE, client.reliability, "RED", ["tag1"]).create_dbot_score()
    assert result.indicator == "CVE-1234-12345"
    assert result.indicator_type == "cve"
    assert result.integration_name == "Mandiant"
    assert result.score == 3
    assert result.reliability == "A - Completely reliable"


def test_build_cpe_objects(client):
    result = Mandiant.MatiCve(MOCK_CVE_RESPONSE, client.reliability, "RED", ["tag1"]).build_cpe_objects()
    assert result[0].cpe == "cpe:2.3:o:product:vendor:40:*:*:*:*:*:*:*"


def test_build_cve_markdown(client):
    result = Mandiant.MatiCve(MOCK_CVE_RESPONSE, client.reliability, "RED", ["tag1"]).build_markdown()
    assert result == ("## CVE-1234-12345\n\nINSERT_EXECUTIVE_SUMMARY_HERE\n\n### Details\n|Description|Exploitation Vec"
                      + "tors|Last Modified|Published|Risk Rating|Vulnerable Products|\n|---|---|---|---|---|---|\n| IN"
                      + "SERT_DESCRIPTION_HERE | General Network Connectivity | 2023-02-07T15:40:00.000Z | 2023-02-07T1"
                      + "5:40:00.000Z | MEDIUM | A LIST OF VULNERABLE PRODUCTS |\n")


def test_cve_reputation_command(client, mock_http_request):
    mock_http_request.return_value = MOCK_CVE_RESPONSE
    result = Mandiant.cve_reputation_command(client, {"cve": "CVE-2024-1234"})
    assert result[0].outputs_prefix == "Mandiant.CVE"
    assert isinstance(result[0].outputs, Dict)
    assert result[0].indicator.id == "CVE-1234-12345"
    assert result[0].indicator.cvss == "9.3"
    assert result[0].indicator.cvss_version == "2.0"
    assert result[0].indicator.cvss_score == "9.3"
    assert result[0].indicator.cvss_vector == "AV:N/AC:M/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C"
    assert result[0].indicator.description == "INSERT_DESCRIPTION_HERE"
    assert result[0].indicator.modified == "2023-02-07T15:40:00.000Z"
    assert result[0].indicator.published == "2023-02-07T15:40:00.000Z"
    assert result[0].indicator.stix_id == "vulnerability--e3b6a556-abcd-dcba-b1df-8e1f0444e978"
    assert result[0].indicator.tags == "tag1, tag2"
    assert result[0].indicator.traffic_light_protocol == "RED"
    assert result[0].indicator.publications[0].source == "Mandiant"
    assert result[0].indicator.publications[0].title == "REPORT_TITLE"
    assert result[0].indicator.publications[0].link == f"{ADV_BASE_URL}/reports/21-00014500"
    assert result[0].indicator.publications[0].timestamp == "2022-05-10T19:08:55.620Z"
    assert result[0].indicator.relationships[0]._name == "used-by"
    assert result[0].indicator.relationships[0]._reverse_name == "exploits"
    assert result[0].indicator.relationships[0]._relationship_type == "IndicatorToIndicator"
    assert result[0].indicator.relationships[0]._entity_a == "CVE-1234-12345"
    assert result[0].indicator.relationships[0]._entity_a_type == "Indicator"
    assert result[0].indicator.relationships[0]._entity_a_family == "Indicator"
    assert result[0].indicator.relationships[0]._entity_b == "ACTOR_NAME"
    assert result[0].indicator.relationships[0]._entity_b_type == "Threat Actor"
    assert result[0].indicator.relationships[0]._entity_b_family == "Indicator"
    assert result[0].indicator.relationships[0]._brand == "Mandiant"
    assert result[0].indicator.relationships[1]._name == "used-by"
    assert result[0].indicator.relationships[1]._reverse_name == "exploits"
    assert result[0].indicator.relationships[1]._relationship_type == "IndicatorToIndicator"
    assert result[0].indicator.relationships[1]._entity_a == "CVE-1234-12345"
    assert result[0].indicator.relationships[1]._entity_a_type == "Indicator"
    assert result[0].indicator.relationships[1]._entity_a_family == "Indicator"
    assert result[0].indicator.relationships[1]._entity_b == "MALWARE_NAME"
    assert result[0].indicator.relationships[1]._entity_b_type == "Malware"
    assert result[0].indicator.relationships[1]._entity_b_family == "Indicator"
    assert result[0].indicator.relationships[1]._brand == "Mandiant"
    assert result[0].indicator.dbot_score.indicator == "CVE-1234-12345"
    assert result[0].indicator.dbot_score.indicator_type == "cve"
    assert result[0].indicator.dbot_score.integration_name == "Mandiant"
    assert result[0].indicator.dbot_score.score == 3
    assert result[0].indicator.dbot_score.reliability == "A - Completely reliable"
    assert result[0].indicator.vulnerable_products[0].cpe == "cpe:2.3:o:product:vendor:40:*:*:*:*:*:*:*"
    assert result[0].indicator.vulnerable_configurations[0].cpe == "cpe:2.3:o:product:vendor:40:*:*:*:*:*:*:*"
    assert result[0].readable_output == ("## CVE-1234-12345\n\nINSERT_EXECUTIVE_SUMMARY_HERE\n\n### Details\n|Descripti"
                                         + "on|Exploitation Vectors|Last Modified|Published|Risk Rating|Vulnerable Prod"
                                         + "ucts|\n|---|---|---|---|---|---|\n| INSERT_DESCRIPTION_HERE | General Netwo"
                                         + "rk Connectivity | 2023-02-07T15:40:00.000Z | 2023-02-07T15:40:00.000Z | MED"
                                         + "IUM | A LIST OF VULNERABLE PRODUCTS |\n")


def test_mati_threat_actor_init(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE)

    assert result.actor_data == MOCK_THREATACTOR_RESPONSE
    assert result.actor_name == MOCK_THREATACTOR_RESPONSE.get("value")
    assert result.actor_id == MOCK_THREATACTOR_RESPONSE.get("id")
    assert result.description == MOCK_THREATACTOR_RESPONSE.get("description")
    assert result.target_industries == ["TARGET_INDUSTRY"]


def test_mati_threat_actor_get_associated_reports(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).get_associated_reports()

    assert result[0].get("source") == "Mandiant"
    assert result[0].get("title") == "REPORT TITLE"
    assert result[0].get("link") == f"{ADV_BASE_URL}/reports/23-00000722"
    assert result[0].get("timestamp") == 1673631860.0


def test_mati_threat_actor_build_target_industries(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_target_industries()

    assert result[0] == "TARGET_INDUSTRY"


def test_mati_threat_actor_build_target_industries_str(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_target_industries_str()

    assert result == "TARGET_INDUSTRY"


def test_mati_threat_actor_build_build_motivations(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_motivations()

    assert result == "Espionage"


def test_mati_threat_actor_build_target_countries(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_target_countries()

    assert result == "TARGET_COUNTRY"


def test_mati_threat_actor_build_associated_malware(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_associated_malware()

    assert result == "MALWARE_FAMILY"


def test_mati_threat_actor_build_associated_tools(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_associated_tools()

    assert result == "SOME_FREE_TOOL"


def test_mati_threat_actor_build_associated_vulnerabilities(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_associated_vulnerabilities()

    assert result == "CVE-2024-1234"


def test_mati_threat_actor_build_aliases(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_aliases()

    assert result == "OTHER_ACT0R"


def test_mati_threat_actor_build_primary_motivation(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_primary_motivation()

    assert result == "Cyber Espionage"


def test_mati_threat_actor_get_source_country(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).get_source_country()

    assert result == "SOURCE_COUNTRY"


def test_mati_threat_actor_get_last_activity_time(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).get_last_activity_time()

    assert result == "2022-11-09T20:21:04.000Z"


def test_mati_threat_actor_get_last_updated(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).get_last_updated()

    assert result == "2023-02-01T06:27:30.000Z"


def test_mati_threat_actor_build_attribute_md(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_attribute_md()

    assert result == ("### Threat Actor Attributes\n|Associated Malware|Associated Tools|Associated Vulnerabilities|Las"
                      + "t Activity Time|Last Updated|Link|Motivations|Target Industries|\n|---|---|---|---|---|---|---"
                      + "|---|\n| MALWARE_FAMILY | SOME_FREE_TOOL | CVE-2024-1234 | 2022-11-09T20:21:04.000Z | 2023-02-"
                      + f"01T06:27:30.000Z | [{ADV_BASE_URL}/actors/threat-actor--f7fdbf0c-abcd-5b95-b00"
                      + f"5-702afffe4a72]({ADV_BASE_URL}/actors/threat-actor--f7fdbf0c-abcd-5b95-b005-70"
                      + "2afffe4a72) | Espionage | TARGET_INDUSTRY |\n")


def test_mati_threat_actor_build_report_md(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_report_md()

    assert result == "### Recent Associated Reports\n**No entries.**\n"


def test_mati_threat_actor_build_actor_markdown(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_actor_markdown()

    assert result == ("## FAKE_ACT0R\n\nACTOR DESCRIPTION GOES HERE\n\n### Threat Actor Attributes\n|Associated Malware"
                      + "|Associated Tools|Associated Vulnerabilities|Last Activity Time|Last Updated|Link|Motivations|"
                      + "Target Industries|\n|---|---|---|---|---|---|---|---|\n| MALWARE_FAMILY | SOME_FREE_TOOL | CVE"
                      + f"-2024-1234 | 2022-11-09T20:21:04.000Z | 2023-02-01T06:27:30.000Z | [{ADV_BASE_URL}/actors/thr"
                      + f"eat-actor--f7fdbf0c-abcd-5b95-b005-702afffe4a72]({ADV_BASE_URL}"
                      + "/actors/threat-actor--f7fdbf0c-abcd-5b95-b005-702afffe4a72) | Espionage | TARGET_INDUSTRY |\n"
                      + "\n\n### Recent Associated Reports\n**No entries.**\n")


def test_mati_threat_actor_build_malware_relationships(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    for result in Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_malware_relationships():
        assert result.get("name") == "uses"
        assert result.get("reverseName") == "used-by"
        assert result.get("type") == "IndicatorToIndicator"
        assert result.get("entityA") == "FAKE_ACT0R"
        assert result.get("entityAType") == "Threat Actor"
        assert result.get("entityBType") == "Malware"


def test_mati_threat_actor_build_unc_relationships(client, mock_http_request):
    mock_http_request.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")

    for result in Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_unc_relationships():
        assert result.get("name") == "related-to"
        assert result.get("reverseName") == "related-to"
        assert result.get("type") == "IndicatorToIndicator"
        assert result.get("entityA") == "FAKE_ACT0R"
        assert result.get("entityAType") == "Threat Actor"
        assert result.get("entityBType") == "Threat Actor"


def test_mati_threat_actor_build_attack_pattern_relationships(client, mocker):
    mock_reports_response = mocker.patch.object(Mandiant.MandiantClient, "get_associated_reports", autospec=True)
    mock_reports_response.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")
    mock_attack_patterns_response = mocker.patch.object(Mandiant.MandiantClient, "get_attack_patterns", autospec=True)
    mock_attack_patterns_response.return_value = MOCK_THREATACTOR_ATTACKPATTERN_RESPONSE
    mock_get_mitre_attack_patterns = mocker.patch.object(demisto, "searchIndicators", autospec=True)
    mock_get_mitre_attack_patterns.return_value = {
        "iocs": [
            {"id": "", "value": "", "fields": {"mitreId": "T1529", "name": "ttp name"}}
        ]
    }

    for result in Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_attack_pattern_relationships():
        assert result.get("name") == "uses"
        assert result.get("reverseName") == "used-by"
        assert result.get("type") == "IndicatorToIndicator"
        assert result.get("entityA") == "FAKE_ACT0R"
        assert result.get("entityAType") == "Threat Actor"
        assert result.get("entityBType") == "Attack Pattern"


def test_mati_threat_actor_build_campaign_relationships(client, mocker):
    mock_reports_response = mocker.patch.object(Mandiant.MandiantClient, "get_associated_reports", autospec=True)
    mock_reports_response.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")
    mock_attack_patterns_response = mocker.patch.object(Mandiant.MandiantClient, "get_associated_campaigns", autospec=True)
    mock_attack_patterns_response.return_value = MOCK_THREATACTOR_ATTACKPATTERN_RESPONSE

    for result in Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_campaign_relationships():
        assert result.get("name") == "uses"
        assert result.get("reverseName") == "used-by"
        assert result.get("type") == "IndicatorToIndicator"
        assert result.get("entityA") == "FAKE_ACT0R"
        assert result.get("entityAType") == "Threat Actor"
        assert result.get("entityBType") == "Campaign"


def test_mati_threat_actor_build_actor_relationships(client, mocker):
    mock_reports_response = mocker.patch.object(Mandiant.MandiantClient, "get_associated_reports", autospec=True)
    mock_reports_response.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")
    mock_attack_patterns_response = mocker.patch.object(Mandiant.MandiantClient, "get_associated_campaigns", autospec=True)
    mock_attack_patterns_response.return_value = MOCK_THREATACTOR_ATTACKPATTERN_RESPONSE
    mock_attack_patterns_response = mocker.patch.object(Mandiant.MandiantClient, "get_attack_patterns", autospec=True)
    mock_attack_patterns_response.return_value = MOCK_THREATACTOR_ATTACKPATTERN_RESPONSE

    for result in Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_actor_relationships():
        assert isinstance(result, Dict)
        assert "name" in result
        assert "reverseName" in result
        assert "type" in result
        assert "entityA" in result
        assert "entityAType" in result
        assert "entityBType" in result
        assert "entityBType" in result


def test_mati_threat_actor_build_indicator(client, mocker):
    mock_reports_response = mocker.patch.object(Mandiant.MandiantClient, "get_associated_reports", autospec=True)
    mock_reports_response.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    MOCK_THREATACTOR_RESPONSE["value"] = MOCK_THREATACTOR_RESPONSE.get("name")
    MOCK_THREATACTOR_RESPONSE["type"] = "Threat Actor"
    mock_attack_patterns_response = mocker.patch.object(Mandiant.MandiantClient, "get_associated_campaigns", autospec=True)
    mock_attack_patterns_response.return_value = MOCK_THREATACTOR_ATTACKPATTERN_RESPONSE
    mock_attack_patterns_response = mocker.patch.object(Mandiant.MandiantClient, "get_attack_patterns", autospec=True)
    mock_attack_patterns_response.return_value = MOCK_THREATACTOR_ATTACKPATTERN_RESPONSE

    result = Mandiant.MatiThreatActor(client, MOCK_THREATACTOR_RESPONSE).build_indicator()

    assert isinstance(result, Dict)
    assert result.get("value") == "FAKE_ACT0R"
    assert result.get("type") == "Threat Actor"
    assert result.get("score") == 3
    assert result.get("rawJSON", {}).get("value") == "FAKE_ACT0R"
    assert result.get("rawJSON", {}).get("type") == "Threat Actor"
    assert result.get("fields", {}).get("Aliases") == "OTHER_ACT0R"
    assert result.get("fields", {}).get("STIX ID") == "threat-actor--f7fdbf0c-abcd-5b95-b005-702afffe4a72"
    assert result.get("fields", {}).get("Description") == "ACTOR DESCRIPTION GOES HERE"
    assert result.get("fields", {}).get("Geo Country") == "SOURCE_COUNTRY"
    assert result.get("fields", {}).get("Primary Motivation") == "Cyber Espionage"
    assert result.get("fields", {}).get("Tags") == "TARGET_INDUSTRY"
    assert result.get("fields", {}).get("Publications") == [
        {
            "source": "Mandiant",
            "title": "REPORT TITLE",
            "link": f"{ADV_BASE_URL}/reports/23-00000722",
            "timestamp": 1673631860.0
        }
    ]
    assert result.get("fields", {}).get("Industry sectors", []) == ["TARGET_INDUSTRY"]


def test_fetch_threat_actor(client, mocker):
    mock_actor = mocker.patch.object(client, "get_actor")
    mock_actor.return_value = MOCK_THREATACTOR_RESPONSE
    mock_actor_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_actor_reports_response.return_value = MOCK_THREATACTOR_REPORTS_RESPONSE
    mock_actor_campaigns_response = mocker.patch.object(client, "get_associated_campaigns")
    mock_actor_campaigns_response.return_value = MOCK_THREAT_ACTOR_CAMPAIGNS_RESPONSE
    mock_actor_attack_patterns_response = mocker.patch.object(client, "get_attack_patterns")
    mock_actor_attack_patterns_response.return_value = MOCK_THREATACTOR_ATTACKPATTERN_RESPONSE

    result = Mandiant.fetch_threat_actor_command(client, {"actor_name": "FAKE_ACT0R"})

    assert isinstance(result.outputs, Dict)
    assert result.outputs.get("id", "") == MOCK_THREATACTOR_RESPONSE.get("id")
    assert result.outputs.get("value") == MOCK_THREATACTOR_RESPONSE.get("name")
    assert result.outputs.get("type") == "Threat Actor"
    assert result.outputs_prefix == "Mandiant.Actor"
    assert result.tags == ["TARGET_INDUSTRY"]
    assert result.readable_output == ("## FAKE_ACT0R\n\nACTOR DESCRIPTION GOES HERE\n\n### Threat Actor Attributes\n|As"
                                      + "sociated Malware|Associated Tools|Associated Vulnerabilities|Last Activity Tim"
                                      + "e|Last Updated|Link|Motivations|Target Industries|\n|---|---|---|---|---|---|-"
                                      + "--|---|\n| MALWARE_FAMILY | SOME_FREE_TOOL | CVE-2024-1234 | 2022-11-09T20:21:"
                                      + f"04.000Z | 2023-02-01T06:27:30.000Z | [{ADV_BASE_URL}/actors/threat-actor--f7f"
                                      + f"dbf0c-abcd-5b95-b005-702afffe4a72]({ADV_BASE_URL}/actors/threat-actor--f7fdbf"
                                      + "0c-abcd-5b95-b005-702afffe4a72) | Espionage | TARGET_INDUSTRY |\n"
                                      + "\n\n### Recent Associated Reports\n**No entries.**\n")


def test_mati_malware_init(client, mocker):
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    MOCK_MALWARE_RESPONSE["value"] = MOCK_MALWARE_RESPONSE.get("name")
    MOCK_MALWARE_RESPONSE["type"] = "Malware"

    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE)

    assert result.malware_data == MOCK_MALWARE_RESPONSE
    assert result.malware_name == MOCK_MALWARE_RESPONSE.get("value")
    assert result.malware_id == MOCK_MALWARE_RESPONSE.get("id")
    assert result.description == MOCK_MALWARE_RESPONSE.get("description")
    assert result.target_industries == ["TARGET_INDUSTRY"]


def test_mati_malware_build_target_industries(client, mocker):
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    MOCK_MALWARE_RESPONSE["value"] = MOCK_MALWARE_RESPONSE.get("name")
    MOCK_MALWARE_RESPONSE["type"] = "Malware"

    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_target_industries()

    assert result == ["TARGET_INDUSTRY"]


def test_mati_malware_get_associated_reports(client, mocker):
    mock_malware = mocker.patch.object(client, "get_malware")
    mock_malware.return_value = MOCK_MALWARE_RESPONSE
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    MOCK_MALWARE_RESPONSE["value"] = MOCK_MALWARE_RESPONSE.get("name")
    MOCK_MALWARE_RESPONSE["type"] = "Malware"

    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).get_associated_reports()

    assert result[0].get("source") == "Mandiant"
    assert result[0].get("title") == "REPORT_TITLE"
    assert result[0].get("link") == f"{ADV_BASE_URL}/reports/22-0000000"
    assert result[0].get("timestamp") == 1659371639.0


def test_mati_malware_build_actor_relationships(client, mocker):
    MOCK_MALWARE_RESPONSE["value"] = MOCK_MALWARE_RESPONSE.get("name")
    mock_malware = mocker.patch.object(client, "get_malware")
    mock_malware.return_value = MOCK_MALWARE_RESPONSE
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE

    for result in Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_actor_relationships():
        assert isinstance(result, Dict)
        assert result.get("name") == "used-by"
        assert result.get("reverseName") == "uses"
        assert result.get("type") == "IndicatorToIndicator"
        assert result.get("entityA") == "MALWARE_NAME"
        assert result.get("entityAType") == "Malware"
        assert result.get("entityBType") == "Threat Actor"


def test_mati_malware_build_vulnerability_relationships(client, mocker):
    MOCK_MALWARE_RESPONSE["value"] = MOCK_MALWARE_RESPONSE.get("name")
    mock_malware = mocker.patch.object(client, "get_malware")
    mock_malware.return_value = MOCK_MALWARE_RESPONSE
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE

    for result in Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_vulnerability_relationships():
        assert isinstance(result, Dict)
        assert result.get("name") == "exploits"
        assert result.get("reverseName") == "used-by"
        assert result.get("type") == "IndicatorToIndicator"
        assert result.get("entityA") == "MALWARE_NAME"
        assert result.get("entityAType") == "Malware"
        assert result.get("entityBType") == "CVE"


def test_mati_malware_build_attack_pattern_relationships(client, mocker):
    MOCK_MALWARE_RESPONSE["value"] = MOCK_MALWARE_RESPONSE.get("name")
    mock_malware = mocker.patch.object(client, "get_malware")
    mock_malware.return_value = MOCK_MALWARE_RESPONSE
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    mock_malware_attack_patterns_response = mocker.patch.object(client, "get_attack_patterns")
    mock_malware_attack_patterns_response.return_value = MOCK_MALWARE_ATTACKPATTERN_RESPONSE

    for result in Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_attack_pattern_relationships():
        assert isinstance(result, Dict)
        assert result.get("name") == "uses"
        assert result.get("reverseName") == "used-by"
        assert result.get("type") == "IndicatorToIndicator"
        assert result.get("entityA") == "MALWARE_NAME"
        assert result.get("entityAType") == "Malware"
        assert result.get("entityBType") == "Attack Pattern"


def test_mati_malware_build_campaign_relationships(client, mocker):
    MOCK_MALWARE_RESPONSE["value"] = MOCK_MALWARE_RESPONSE.get("name")
    mock_malware = mocker.patch.object(client, "get_malware")
    mock_malware.return_value = MOCK_MALWARE_RESPONSE
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    mock_malware_campaigns_response = mocker.patch.object(client, "get_associated_campaigns")
    mock_malware_campaigns_response.return_value = MOCK_MALWARE_CAMPAIGNS_RESPONSE

    for result in Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_campaign_relationships():
        assert isinstance(result, Dict)
        assert result.get("name") == "uses"
        assert result.get("reverseName") == "used-by"
        assert result.get("type") == "IndicatorToIndicator"
        assert result.get("entityA") == "MALWARE_NAME"
        assert result.get("entityAType") == "Malware"
        assert result.get("entityBType") == "Campaign"


def test_mati_malware_build_malware_relationships(client, mocker):
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    mock_malware_campaigns_response = mocker.patch.object(client, "get_associated_campaigns")
    mock_malware_campaigns_response.return_value = MOCK_MALWARE_CAMPAIGNS_RESPONSE
    mock_malware_attack_patterns_response = mocker.patch.object(client, "get_attack_patterns")
    mock_malware_attack_patterns_response.return_value = MOCK_MALWARE_ATTACKPATTERN_RESPONSE

    for result in Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_malware_relationships():
        assert isinstance(result, Dict)
        assert "name" in result
        assert "reverseName" in result
        assert "type" in result
        assert "entityA" in result
        assert "entityAType" in result
        assert "entityBType" in result
        assert "entityBType" in result


def test_mati_malware_build_indicator(client, mocker):
    MOCK_MALWARE_RESPONSE["value"] = MOCK_MALWARE_RESPONSE.get("name")
    MOCK_MALWARE_RESPONSE["type"] = "Malware"
    mock_malware = mocker.patch.object(client, "get_malware")
    mock_malware.return_value = MOCK_MALWARE_RESPONSE
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    mock_malware_campaigns_response = mocker.patch.object(client, "get_associated_campaigns")
    mock_malware_campaigns_response.return_value = MOCK_MALWARE_CAMPAIGNS_RESPONSE
    mock_malware_attack_patterns_response = mocker.patch.object(client, "get_attack_patterns")
    mock_malware_attack_patterns_response.return_value = MOCK_MALWARE_ATTACKPATTERN_RESPONSE

    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_indicator()

    assert isinstance(result, Dict)
    assert result.get("value") == "MALWARE_NAME"
    assert result.get("type") == "Malware"
    assert result.get("score") == 3
    assert result.get("rawJSON", {}).get("value") == "MALWARE_NAME"
    assert result.get("rawJSON", {}).get("type") == "Malware"
    assert result.get("fields", {}).get("Tags") == ["TARGET_INDUSTRY"]
    assert result.get("fields", {}).get("Publications") == [
        {
            "source": "Mandiant",
            "title": "REPORT_TITLE",
            "link": f"{ADV_BASE_URL}/reports/22-0000000",
            "timestamp": 1659371639.0
        }
    ]
    assert result.get("fields", {}).get("Industry sectors", []) == ["TARGET_INDUSTRY"]


def test_mati_malware_build_roles(client, mocker):
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_roles()
    assert result == "Backdoor"


def test_mati_malware_build_capabilities(client, mocker):
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_capabilities()
    assert result == "Allocates memory"


def test_mati_malware_build_detections(client, mocker):
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_detections()
    assert result == "DETECTION_ONE, DETECTION_TWO"


def test_mati_malware_build_operating_systems(client, mocker):
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_operating_systems()
    assert result == "Windows"


def test_mati_malware_build_target_indistries_str(client, mocker):
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_target_indistries_str()
    assert result == "TARGET_INDUSTRY"


def test_mati_malware_build_associated_actors(client, mocker):
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_associated_actors()
    assert result == "FAKE_ACT0R"


def test_mati_malware_build_associated_vulnerabilities(client, mocker):
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_associated_vulnerabilities()
    assert result == ""


def test_mati_malware_get_last_activity_time(client, mocker):
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).get_last_activity_time()
    assert result == "2023-02-07T02:17:24.000Z"


def test_mati_malware_get_last_updated(client, mocker):
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).get_last_updated()
    assert result == "2023-02-07T02:17:24.000Z"


def test_mati_malware_build_malware_markdown(client, mocker):
    MOCK_MALWARE_RESPONSE["value"] = MOCK_MALWARE_RESPONSE.get("name")
    MOCK_MALWARE_RESPONSE["type"] = "Malware"
    mock_malware = mocker.patch.object(client, "get_malware")
    mock_malware.return_value = MOCK_MALWARE_RESPONSE
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    mock_malware_campaigns_response = mocker.patch.object(client, "get_associated_campaigns")
    mock_malware_campaigns_response.return_value = MOCK_MALWARE_CAMPAIGNS_RESPONSE
    mock_malware_attack_patterns_response = mocker.patch.object(client, "get_attack_patterns")
    mock_malware_attack_patterns_response.return_value = MOCK_MALWARE_ATTACKPATTERN_RESPONSE

    result = Mandiant.MatiMalware(client, MOCK_MALWARE_RESPONSE).build_malware_markdown()
    assert result == ("## MALWARE_NAME\n\nMALWARE_DESCRIPTION\n\n### Malware Family Attributes\n|Associated Threat Acto"
                      + "rs|Associated Vulnerabilities|Capabilities|Detections|Last Activity Time|Last Updated|Link|Ope"
                      + "rating Systems|Roles|Target Industries|\n|---|---|---|---|---|---|---|---|---|---|\n| FAKE_ACT"
                      + "0R |  | Allocates memory | DETECTION_ONE, DETECTION_TWO | 2023-02-07T02:17:24.000Z | 2023-02-0"
                      + f"7T02:17:24.000Z | [{ADV_BASE_URL}/malware/malware--2debd90b-0000-1234-8838-1f9"
                      + f"f58ca256b]({ADV_BASE_URL}/malware/malware--2debd90b-0000-1234-8838-1f9f58ca256"
                      + "b) | Windows | Backdoor | TARGET_INDUSTRY |\n\n\n### Recent Associated Reports\n**No entries.*"
                      + "*\n")


def test_fetch_malware_family(client, mocker):
    mock_malware = mocker.patch.object(client, "get_malware")
    mock_malware.return_value = MOCK_MALWARE_RESPONSE
    mock_malware_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_malware_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    mock_malware_campaigns_response = mocker.patch.object(client, "get_associated_campaigns")
    mock_malware_campaigns_response.return_value = MOCK_MALWARE_CAMPAIGNS_RESPONSE
    mock_malware_attack_patterns_response = mocker.patch.object(client, "get_attack_patterns")
    mock_malware_attack_patterns_response.return_value = MOCK_MALWARE_ATTACKPATTERN_RESPONSE

    result = Mandiant.fetch_malware_family_command(client, {"malware_name": "MALWARE_NAME"})

    assert isinstance(result.outputs, Dict)
    assert result.outputs.get("id", "") == MOCK_MALWARE_RESPONSE.get("id")
    assert result.outputs.get("value") == MOCK_MALWARE_RESPONSE.get("name")
    assert result.outputs.get("type") == "Malware"
    assert result.outputs_prefix == "Mandiant.Malware"
    assert result.tags == ["TARGET_INDUSTRY"]
    assert result.readable_output == ("## MALWARE_NAME\n\nMALWARE_DESCRIPTION\n\n### Malware Family Attributes\n|Associ"
                                      + "ated Threat Actors|Associated Vulnerabilities|Capabilities|Detections|Last Act"
                                      + "ivity Time|Last Updated|Link|Operating Systems|Roles|Target Industries|\n|---|"
                                      + "---|---|---|---|---|---|---|---|---|\n| FAKE_ACT0R |  | Allocates memory | DET"
                                      + "ECTION_ONE, DETECTION_TWO | 2023-02-07T02:17:24.000Z | 2023-02-07T02:17:24.000"
                                      + f"Z | [{ADV_BASE_URL}/malware/malware--2debd90b-0000-1234-8838-1"
                                      + f"f9f58ca256b]({ADV_BASE_URL}/malware/malware--2debd90b-0000-123"
                                      + "4-8838-1f9f58ca256b) | Windows | Backdoor | TARGET_INDUSTRY |\n\n\n### Recent "
                                      + "Associated Reports\n**No entries.**\n")


def test_fetch_campaign_command(client, mocker):
    mock_campaign = mocker.patch.object(client, "get_campaign")
    mock_campaign.return_value = MOCK_CAMPAIGN_RESPONSE
    mock_campaign_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_campaign_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE
    result = Mandiant.fetch_campaign_command(client, {"campaign_id": "CAMP.24.004"})

    assert result.outputs_prefix == "Mandiant.Campaign"
    assert result.outputs == MOCK_CAMPAIGN_RESPONSE
    assert result.tags == ["Governments"]
    assert result.readable_output == ("## CAMPAIGN NAME (CAMP.24.004)\n\n**Short Name:** CAMP.24.004 | **Last Active:**"
                                      + f" 2024-07-16T00:00:00.000Z\n\nCAMPAIGN DESCRIPTION\n\n**Link:** {ADV_BASE_URL}"
                                      + "/campaigns/campaign--7d322878-9cf2-5898-a9c0-dfcd852f567a")


def test_build_campaign_indicator(client, mocker):
    mock_campaign = mocker.patch.object(client, "get_campaign")
    mock_campaign.return_value = MOCK_CAMPAIGN_RESPONSE
    mock_campaign_reports_response = mocker.patch.object(client, "get_associated_reports")
    mock_campaign_reports_response.return_value = MOCK_MALWARE_REPORTS_RESPONSE

    result = Mandiant.MatiCampaign(client, MOCK_CAMPAIGN_RESPONSE).build_indicator()

    assert isinstance(result, Dict)
    assert result.get("value") == "CAMPAIGN NAME (CAMP.24.004)"
    assert result.get("type") == "Campaign"
    assert result.get("rawJSON") == MOCK_CAMPAIGN_RESPONSE
    assert result.get("score") == 3
    relationships: List[Dict] = result.get("relationships", [])
    assert relationships[0].get("name") == "related-to"
    assert relationships[0].get("name") == "related-to"
    assert relationships[0].get("reverseName") == "related-to"
    assert relationships[0].get("type") == "IndicatorToIndicator"
    assert relationships[0].get("entityA") == "CAMPAIGN NAME (CAMP.24.004)"
    assert relationships[0].get("entityAFamily") == "Indicator"
    assert relationships[0].get("entityAType") == "Campaign"
    assert relationships[0].get("entityB") == "APT44"
    assert relationships[0].get("entityBFamily") == "Indicator"
    assert relationships[0].get("entityBType") == "Campaign"
    assert relationships[1].get("name") == "related-to"
    assert relationships[1].get("reverseName") == "related-to"
    assert relationships[1].get("type") == "IndicatorToIndicator"
    assert relationships[1].get("entityA") == "CAMPAIGN NAME (CAMP.24.004)"
    assert relationships[1].get("entityAFamily") == "Indicator"
    assert relationships[1].get("entityAType") == "Campaign"
    assert relationships[1].get("entityB") == "BACKORDER.V2"
    assert relationships[1].get("entityBFamily") == "Indicator"
    assert relationships[1].get("entityBType") == "Campaign"
    assert result.get("fields", {}).get("Industry sectors", []) == ["Governments"]


def test_strip_html_tags(client):
    html = "<p><span style=\"color:black\">hello xsoar!!!</span><p>"
    result = Mandiant.MatiCve(MOCK_CVE_RESPONSE, client.reliability, client.tlp_color, client.tags).strip_html_tags(
        html, True, True)

    assert result == "hello xsoar!!!"
