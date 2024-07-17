import Mandiant
import pytest

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import


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


@pytest.fixture
def config():
    """Fixture to provide a mock configuration."""
    return {
        "api_key": "test_api_key",
        "secret_key": "test_secret_key",
        "timeout": 60,
        "tlp_color": "RED",
        "reliability": "A - Completely reliable",
        "tags": "tag1, tag2"
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


def test_get_associated_reports(client, mock_http_request):
    """Test getting associated reports"""
    mock_response = MOCK_MALWARE_REPORTS_RESPONSE
    mock_http_request.return_value = mock_response

    response = client.get_associated_reports("malware", "malware--1234")

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


@pytest.mark.parametrize(
    "threat_score, expected_dbot_score",
    [
        (-10, Common.DBotScore.NONE),        # Invalid (less than 0)
        (0, Common.DBotScore.NONE),
        (15, Common.DBotScore.GOOD),
        (20, Common.DBotScore.GOOD),
        (21, Common.DBotScore.SUSPICIOUS),
        (50, Common.DBotScore.SUSPICIOUS),
        (80, Common.DBotScore.SUSPICIOUS),
        (81, Common.DBotScore.BAD),
        (95, Common.DBotScore.BAD),
        (100, Common.DBotScore.BAD),
        (101, Common.DBotScore.NONE),       # Invalid (greater than 100)
        (None, Common.DBotScore.NONE),       # Test for missing input
    ],
)
def test_calculate_dbot_score(threat_score, expected_dbot_score):
    """
    Tests the calculate_dbot_score function with various threat scores
    and their expected DBotScore values.
    """
    result = Mandiant.calculate_dbot_score(threat_score)
    assert result == expected_dbot_score


def test_create_dbot_score():
    """Test creating DBotScore"""
    result = Mandiant.create_dbot_score("1.2.3.4", DBotScoreType.IP, "A - Completely reliable", 88)

    assert isinstance(result, Common.DBotScore)
    assert result.indicator == "1.2.3.4"
    assert result.indicator_type == "ip"
    assert result.reliability == "A - Completely reliable"
    assert result.score == 3


@pytest.mark.parametrize(
    "indicator, expected_sources",
    [
        ({}, []),  # Empty input
        ({"some_other_key": "value"}, []),  # Missing 'sources' key
        ({"sources": []}, []),  # Empty 'sources' list
        (
            {
                "sources": [
                    {"source_name": "SourceA"},
                    {"source_name": "SourceB"},
                    {},  # Missing 'source_name'
                ]
            },
            ["sourcea", "sourceb", ""],
        ),
        (
            {
                "sources": [
                    {"source_name": "SOURCE_C"},  # Test case sensitivity
                ]
            },
            ["source_c"],
        ),
    ],
)
def test_build_sources(indicator, expected_sources):
    assert Mandiant.build_sources(indicator) == expected_sources


@pytest.mark.parametrize(
    "indicator, expected_output",
    [
        ({}, "-"),                                   # Empty indicator
        ({"campaigns": []}, "-"),                     # Empty campaigns list
        (
            {
                "campaigns": [
                    {"title": "Campaign 1", "name": "camp1"},
                    {"title": "Campaign 2", "name": "camp2"},
                ]
            },
            "Campaign 1 (camp1), Campaign 2 (camp2)",  # Multiple campaigns
        ),
        ({"campaigns": [{"title": "Only Title"}]}, "-"),  # Missing campaign ID
        (
            {"campaigns": [{"name": "Only ID"}]},
            "-"
        ),  # Missing campaign title, resulting in an empty title
    ],
)
def test_get_indicator_campaigns(indicator, expected_output):
    result = Mandiant.get_indicator_campaigns(indicator)
    assert result == expected_output


@pytest.mark.parametrize(
    "indicator, expected_output",
    [
        ({}, "-"),                                                    # No associations
        ({"attributed_associations": []}, "-"),                     # Empty associations
        ({"attributed_associations": [{"type": "other"}]}, "-"),     # No malware
        (
            {"attributed_associations": [{"type": "malware", "name": "TrickBot"}]},
            "TrickBot",
        ),                                                            # One malware
        (
            {
                "attributed_associations": [
                    {"type": "malware", "name": "TrickBot"},
                    {"type": "malware", "name": "Emotet"},
                ]
            },
            "TrickBot, Emotet",
        ),                                                            # Multiple malware
    ],
)
def test_get_indicator_malware_families(indicator, expected_output):
    result = Mandiant.get_indicator_malware_families(indicator)
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
def test_get_indicator_reports(indicator, publication_count):
    result = Mandiant.get_indicator_reports(indicator)
    assert len(result) == publication_count
    if len(result) > 0:
        for r in result:
            assert r.source == "Mandiant"
            assert hasattr(r, "title")
            assert hasattr(r, "link")
            assert hasattr(r, "timestamp")


def test_build_relationship():
    result = Mandiant.build_relationship("uses", "used_by", "entityA", "Indicator", "FAKE ACTOR", "Threat Actor")
    assert isinstance(result, EntityRelationship)
    assert result._entity_a == "entityA"
    assert result._entity_b == "FAKE ACTOR"
    assert result._entity_b_type == "Threat Actor"
    assert result._name == "uses"
    assert result._reverse_name == "used_by"


def test_build_indicator_relationships():
    result = Mandiant.build_indicator_relationships(MOCK_IP_INDICATOR)
    assert isinstance(result, List)
    for r in result:
        assert isinstance(r, EntityRelationship)


def test_build_threat_types():
    result = Mandiant.build_threat_types(MOCK_IP_INDICATOR)
    assert isinstance(result, List)
    for r in result:
        assert isinstance(r, Common.ThreatTypes)


@pytest.mark.parametrize(
    "indicator, hash_type, expected_hash_value",
    [
        (
            {"associated_hashes": [{"type": "md5", "value": "abcdef123"}]},
            "md5",
            "abcdef123",
        ),
        (
            {"associated_hashes": [{"type": "sha256", "value": ""}]},
            "sha256",
            "",
        ),
        (
            {"associated_hashes": [{"type": "sha1", "value": "zyx987"}]},
            "md5",
            "",
        ),
        ({"associated_hashes": []}, "md5", ""),
        ({}, "md5", ""),
    ],
)
def test_get_hash_value(indicator, hash_type, expected_hash_value):
    assert Mandiant.get_hash_value(indicator, hash_type) == expected_hash_value


def test_ip_reputation_command_success(client, mock_http_request):
    mock_response = {"indicators": [MOCK_IP_INDICATOR]}
    mock_http_request.return_value = mock_response
    args = {"ip": "1.2.3.4"}
    results = Mandiant.ip_reputation_command(client, args)
    assert len(results) == 1
    result = results[0]
    assert result.readable_output
    assert result.outputs_prefix == "Mandiant.IP"
    assert result.indicator
    assert result.indicator.ip == "1.2.3.4"


def test_domain_reputation_command_success(client, mock_http_request):
    mock_response = {"indicators": [MOCK_DOMAIN_INDICATOR]}
    mock_http_request.return_value = mock_response
    args = {"domain": "domain.test"}
    results = Mandiant.domain_reputation_command(client, args)
    assert len(results) == 1
    result = results[0]
    assert result.readable_output
    assert result.outputs_prefix == "Mandiant.Domain"
    assert result.indicator
    assert result.indicator.domain == "domain.test"


def test_url_reputation_command_success(client, mock_http_request):
    mock_response = {"indicators": [MOCK_URL_INDICATOR]}
    mock_http_request.return_value = mock_response
    args = {"url": "https://domain.test/test"}
    results = Mandiant.url_reputation_command(client, args)
    assert len(results) == 1
    result = results[0]
    assert result.readable_output
    assert result.outputs_prefix == "Mandiant.URL"
    assert result.indicator
    assert result.indicator.url == "https://domain.test/test"


def test_file_reputation_command_success(client, mock_http_request):
    mock_response = {"indicators": [MOCK_FILE_INDICATOR]}
    mock_http_request.return_value = mock_response
    args = {"file": "ae1747c930e9e4f45fbc970a83b52284"}
    results = Mandiant.file_reputation_command(client, args)
    assert len(results) == 1
    result = results[0]
    assert result.readable_output
    assert result.outputs_prefix == "Mandiant.File"
    assert result.indicator
    assert result.indicator.md5 == "ae1747c930e9e4f45fbc970a83b52284"
    assert result.indicator.sha1 == "638cde28bbe3cfe7b53aa75a7cf6991baa692a4a"
    assert result.indicator.sha256 == "f68ec69a53130a24b0fe53d1d1fe70992d86a6d67006ae45f986f9ef4f450b6c"


# def test_ip_reputation_ip_not_found(client, mock_http_request):
#     mock_response: Dict[str, List] = {"indicators": []}
#     mock_http_request.return_value = mock_response
#     args = {"ip": "6.7.8.9"}
#     results = Mandiant.ip_reputation_command(client, args)
#     assert results[0].readable_output == "6.7.8.9 not found"


# def test_doamin_reputation_domain_not_found(client, mock_http_request):
#     mock_response: Dict[str, List] = {"indicators": []}
#     mock_http_request.return_value = mock_response
#     args = {"domain": "not.exists"}
#     results = Mandiant.domain_reputation_command(client, args)
#     assert results[0].readable_output == "not.exists not found"


# def test_url_reputation_url_not_found(client, mock_http_request):
#     mock_response: Dict[str, List] = {"indicators": []}
#     mock_http_request.return_value = mock_response
#     args = {"url": "http://not.exists"}
#     results = Mandiant.url_reputation_command(client, args)
#     assert results[0].readable_output == "http://not.exists not found"


# def test_file_reputation_file_not_found(client, mock_http_request):
#     mock_response: Dict[str, List] = {"indicators": []}
#     mock_http_request.return_value = mock_response
#     args = {"file": "asdf"}
#     results = Mandiant.file_reputation_command(client, args)
#     assert results[0].readable_output == "asdf not found"
