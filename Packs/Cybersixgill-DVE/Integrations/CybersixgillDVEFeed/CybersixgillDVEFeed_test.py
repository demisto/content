import requests
import pytest
import json

import demistomock as demisto

bundle_index = 0
submitted_indicators = 0
mocked_get_token_response = """{"access_token": "fababfafbh"}"""
iocs_bundle = [
    {
        "id": "bundle--f00374ec-429c-40cb-b7bb-61f920814775",
        "objects": [
            {
                "created": "2017-01-20T00:00:00.000Z",
                "definition": {"tlp": "amber"},
                "definition_type": "tlp",
                "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                "type": "marking-definition",
            },
            {
                "created": "2019-12-26T00:00:00Z",
                "definition": {"statement": "Copyright Sixgill 2020. All rights reserved."},
                "definition_type": "statement",
                "id": "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                "type": "marking-definition",
            },
            {
                "created": "2020-09-06T20:33:33.538Z",
                "external_references": [{"external_id": "CVE-2020-15392", "source_name": "cve"}],
                "id": "cveevent--a26f4710-0d64-4a76-ae27-6ac038e7536b",
                "modified": "2020-09-06T20:33:33.538Z",
                "object_marking_refs": [
                    "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                ],
                "spec_version": "2.0",
                "type": "x-cybersixgill-com-cve-event",
                "x_sixgill_info": {
                    "event": {
                        "_id": "5f1f17164731b1cef86c8aaf",
                        "action": "trend",
                        "description": "Trend of Github commits related to CVE-2020-15392",
                        "event_datetime": "2020-06-30T00:00Z",
                        "name": "trend_Github_commits",
                        "prev_level": "prev_level",
                        "type": "github_authoring",
                    },
                    "nvd": {
                        "base_score_v3": 5.3,
                        "base_severity_v3": "MEDIUM",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-15392",
                        "modified": "2020-07-15T16:52Z",
                        "published": "2020-07-07T14:15Z",
                        "score_2_0": 5.0,
                        "severity_2_0": "MEDIUM",
                        "vector_v2": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                        "vector_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    },
                    "rating": {
                        "current": 0.02,
                        "highest": {"date": "2020-07-27T00:00Z", "value": 0.02},
                        "previouslyExploited": 0.07,
                    },
                },
            },
            {
                "created": "2020-08-19T23:08:05.709Z",
                "external_references": [{"external_id": "CVE-2020-2021", "source_name": "cve"}],
                "id": "cveevent--9c735811-6e08-44d8-a844-75acb10d79b9",
                "modified": "2020-08-19T23:08:05.709Z",
                "object_marking_refs": [
                    "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                ],
                "spec_version": "2.0",
                "type": "x-cybersixgill-com-cve-event",
                "x_sixgill_info": {
                    "event": {
                        "_id": "5f3db0ec3ecfe5a6d70b6245",
                        "action": "trend",
                        "description": "CVE-2020-2021 is trending on Twitter.",
                        "event_datetime": "2020-06-30T00:00Z",
                        "name": "trend_Twitter",
                        "prev_level": "prev_level",
                        "type": "dark_mention",
                    },
                    "nvd": {
                        "base_score_v3": 10.0,
                        "base_severity_v3": "CRITICAL",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-2021",
                        "modified": "2020-07-06T14:39Z",
                        "published": "2020-06-29T15:15Z",
                        "score_2_0": 9.3,
                        "severity_2_0": "HIGH",
                        "vector_v2": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                        "vector_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    },
                    "rating": {
                        "current": 9.13,
                        "highest": {"date": "2020-07-14T00:00Z", "value": 9.25},
                        "previouslyExploited": 5.32,
                    },
                },
            },
            {
                "created": "2020-08-19T23:08:05.709Z",
                "external_references": [{"external_id": "CVE-2020-12828", "source_name": "cve"}],
                "id": "cveevent--dffdcd6b-2157-4652-b7eb-4ce4bb9eebc5",
                "modified": "2020-08-19T23:08:05.709Z",
                "object_marking_refs": [
                    "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                ],
                "spec_version": "2.0",
                "type": "x-cybersixgill-com-cve-event",
                "x_sixgill_info": {
                    "event": {
                        "_id": "5f3db0ec3ecfe5a6d70b6274",
                        "action": "trend",
                        "description": "CVE-2020-12828 is trending on Twitter.",
                        "event_datetime": "2020-06-30T00:00Z",
                        "name": "trend_Twitter",
                        "prev_level": "prev_level",
                        "type": "dark_mention",
                    },
                    "nvd": {
                        "base_score_v3": 9.8,
                        "base_severity_v3": "CRITICAL",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-12828",
                        "modified": "2020-06-02T16:55Z",
                        "published": "2020-05-21T17:15Z",
                        "score_2_0": 10.0,
                        "severity_2_0": "HIGH",
                        "vector_v2": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                        "vector_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                    "rating": {
                        "current": 8.33,
                        "highest": {"date": "2020-07-25T00:00Z", "value": 8.4},
                        "previouslyExploited": 5.07,
                    },
                },
            },
            {
                "created": "2020-08-19T23:08:05.709Z",
                "external_references": [{"external_id": "CVE-2020-9771", "source_name": "cve"}],
                "id": "cveevent--4b86077c-99f6-42ca-8b4d-953411fa17bd",
                "modified": "2020-08-19T23:08:05.709Z",
                "object_marking_refs": [
                    "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                ],
                "spec_version": "2.0",
                "type": "x-cybersixgill-com-cve-event",
                "x_sixgill_info": {
                    "event": {
                        "_id": "5f3db0ec3ecfe5a6d70b627c",
                        "action": "trend",
                        "description": "CVE-2020-9771 is trending on Twitter.",
                        "event_datetime": "2020-06-30T00:00Z",
                        "name": "trend_Twitter",
                        "prev_level": "prev_level",
                        "type": "dark_mention",
                    },
                    "nvd": {
                        "base_score_v3": None,
                        "base_severity_v3": None,
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-9771",
                        "modified": None,
                        "published": None,
                        "score_2_0": None,
                        "severity_2_0": None,
                        "vector_v2": "None",
                        "vector_v3": "None",
                    },
                    "rating": {"current": None, "highest": {"date": None, "value": None}, "previouslyExploited": None},
                },
            },
            {
                "created": "2020-08-25T17:16:52.536Z",
                "external_references": [{"external_id": "CVE-2015-6086", "source_name": "cve"}],
                "id": "cveevent--1d6320f1-8b22-48e2-876d-5e31b9d36288",
                "modified": "2020-08-25T17:16:52.536Z",
                "object_marking_refs": [
                    "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                ],
                "spec_version": "2.0",
                "type": "x-cybersixgill-com-cve-event",
                "x_sixgill_info": {
                    "event": {
                        "_id": "5f454784ffebcfa91197c9d0",
                        "action": "modified",
                        "description": "Sixgill Current score of CVE-2015-6086 changed from Low to None.",
                        "event_datetime": "2020-06-30T00:00Z",
                        "level": "None",
                        "name": "Sixgill_score_level_change",
                        "prev_level": "prev_level",
                        "type": "score_level",
                    },
                    "nvd": {
                        "base_score_v3": None,
                        "base_severity_v3": None,
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2015-6086",
                        "modified": "2018-10-12T22:10Z",
                        "published": "2015-11-11T12:59Z",
                        "score_2_0": 4.3,
                        "severity_2_0": "MEDIUM",
                        "vector_v2": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                        "vector_v3": "None",
                    },
                    "rating": {
                        "current": None,
                        "highest": {"date": "2016-04-14T00:00Z", "value": 7.02},
                        "previouslyExploited": 1.51,
                    },
                },
            },
            {
                "created": "2020-08-25T17:16:52.536Z",
                "external_references": [{"external_id": "CVE-2015-6086", "source_name": "cve"}],
                "id": "cveevent--1d6320f1-8b22-48e2-876d-5e31b9d36288",
                "modified": "2020-08-25T17:16:52.536Z",
                "object_marking_refs": [
                    "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                ],
                "spec_version": "2.0",
                "type": "x-cybersixgill-com-cve-event",
                "x_sixgill_info": {
                    "event": {
                        "_id": "5f454784ffebcfa91197c9d0",
                        "action": "modified",
                        "description": "Sixgill Current score of CVE-2015-6086 changed from Low to None.",
                        "event_datetime": "2020-06-30T00:00Z",
                        "level": "None",
                        "name": "Sixgill_score_level_change",
                        "prev_level": "prev_level",
                        "type": "score_level",
                    },
                    "nvd": {
                        "base_score_v3": None,
                        "base_severity_v3": None,
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2015-6086",
                        "modified": "2018-10-12T22:10Z",
                        "published": "2015-11-11T12:59Z",
                        "score_2_0": 4.3,
                        "severity_2_0": "MEDIUM",
                        "vector_v2": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                        "vector_v3": "None",
                    },
                    "rating": {
                        "current": None,
                        "highest": {"date": "2016-04-14T00:00Z", "value": 7.02},
                        "previouslyExploited": 1.51,
                    },
                },
            },
        ],
        "spec_version": "2.0",
        "type": "bundle",
    },
    {
        "id": "bundle--f00374ec-429c-40cb-b7bb-61f920814775",
        "objects": [
            {
                "created": "2017-01-20T00:00:00.000Z",
                "definition": {"tlp": "amber"},
                "definition_type": "tlp",
                "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                "type": "marking-definition",
            },
            {
                "created": "2019-12-26T00:00:00Z",
                "definition": {"statement": "Copyright Sixgill 2020. All rights reserved."},
                "definition_type": "statement",
                "id": "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                "type": "marking-definition",
            },
        ],
        "spec_version": "2.0",
        "type": "bundle",
    },
]

expected_ioc_output = [
    {
        "value": "CVE-2020-15392",
        "type": "CVE",
        "rawJSON": {
            "value": "CVE-2020-15392",
            "type": "x-cybersixgill-com-cve-event",
            "created": "2020-09-06T20:33:33.538Z",
            "external_references": [{"external_id": "CVE-2020-15392", "source_name": "cve"}],
            "id": "cveevent--a26f4710-0d64-4a76-ae27-6ac038e7536b",
            "modified": "2020-09-06T20:33:33.538Z",
            "object_marking_refs": [
                "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            ],
            "spec_version": "2.0",
            "x_sixgill_info": {
                "event": {
                    "_id": "5f1f17164731b1cef86c8aaf",
                    "action": "trend",
                    "description": "Trend of Github commits related to CVE-2020-15392",
                    "event_datetime": "2020-06-30T00:00Z",
                    "name": "trend_Github_commits",
                    "prev_level": "prev_level",
                    "type": "github_authoring",
                },
                "nvd": {
                    "base_score_v3": 5.3,
                    "base_severity_v3": "MEDIUM",
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-15392",
                    "modified": "2020-07-15T16:52Z",
                    "published": "2020-07-07T14:15Z",
                    "score_2_0": 5.0,
                    "severity_2_0": "MEDIUM",
                    "vector_v2": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                    "vector_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                },
                "rating": {
                    "current": 0.02,
                    "highest": {"date": "2020-07-27T00:00Z", "value": 0.02},
                    "previouslyExploited": 0.07,
                },
            },
        },
        "score": 3,
        "fields": {
            "description": """Description: Trend of Github commits related to CVE-2020-15392
Created: 2020-09-06T20:33:33.538Z
Modified: 2020-09-06T20:33:33.538Z
External id: CVE-2020-15392
Sixgill DVE score - current: 0.02
Sixgill DVE score - highest ever date: 2020-07-27T00:00Z
Sixgill DVE score - highest ever: 0.02
Sixgill - Previously exploited probability: 0.07
Event Name: trend_Github_commits
Event Type: github_authoring
Event Action: trend
Previous level: prev_level
Event Description: Trend of Github commits related to CVE-2020-15392
Event Datetime: 2020-06-30T00:00Z
CVSS 3.1 score: 5.3
CVSS 3.1 severity: MEDIUM
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2020-15392
NVD - last modified date: 2020-07-15T16:52Z
NVD - publication date: 2020-07-07T14:15Z
CVSS 2.0 score: 5.0
CVSS 2.0 severity: MEDIUM
NVD Vector - V2.0: AV:N/AC:L/Au:N/C:P/I:N/A:N
NVD Vector - V3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
""",
            "creationdate": "2020-09-06T20:33:33.538Z",
            "modified": "2020-09-06T20:33:33.538Z",
            "externalid": "CVE-2020-15392",
            "sixgilldvescorecurrent": 0.02,
            "sixgilldvescorehighesteverdate": "2020-07-27T00:00Z",
            "sixgilldvescorehighestever": 0.02,
            "sixgillpreviouslyexploitedprobability": 0.07,
            "eventname": "trend_Github_commits",
            "eventtype": "github_authoring",
            "eventaction": "trend",
            "previouslevel": "prev_level",
            "eventdescription": "Trend of Github commits related to CVE-2020-15392",
            "eventdatetime": "2020-06-30T00:00Z",
            "cvss31score": 5.3,
            "cvss31severity": "MEDIUM",
            "nvdlink": "https://nvd.nist.gov/vuln/detail/CVE-2020-15392",
            "nvdlastmodifieddate": "2020-07-15T16:52Z",
            "nvdpublicationdate": "2020-07-07T14:15Z",
            "cvss20score": 5.0,
            "cvss20severity": "MEDIUM",
            "nvdvectorv20": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "nvdvectorv31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        },
    },
    {
        "value": "CVE-2020-2021",
        "type": "CVE",
        "rawJSON": {
            "value": "CVE-2020-2021",
            "type": "x-cybersixgill-com-cve-event",
            "created": "2020-08-19T23:08:05.709Z",
            "external_references": [{"external_id": "CVE-2020-2021", "source_name": "cve"}],
            "id": "cveevent--9c735811-6e08-44d8-a844-75acb10d79b9",
            "modified": "2020-08-19T23:08:05.709Z",
            "object_marking_refs": [
                "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            ],
            "spec_version": "2.0",
            "x_sixgill_info": {
                "event": {
                    "_id": "5f3db0ec3ecfe5a6d70b6245",
                    "action": "trend",
                    "description": "CVE-2020-2021 is trending on Twitter.",
                    "event_datetime": "2020-06-30T00:00Z",
                    "name": "trend_Twitter",
                    "prev_level": "prev_level",
                    "type": "dark_mention",
                },
                "nvd": {
                    "base_score_v3": 10,
                    "base_severity_v3": "CRITICAL",
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-2021",
                    "modified": "2020-07-06T14:39Z",
                    "published": "2020-06-29T15:15Z",
                    "score_2_0": 9.3,
                    "severity_2_0": "HIGH",
                    "vector_v2": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                    "vector_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                },
                "rating": {
                    "current": 9.13,
                    "highest": {"date": "2020-07-14T00:00Z", "value": 9.25},
                    "previouslyExploited": 5.32,
                },
            },
        },
        "score": 3,
        "fields": {
            "description": """Description: CVE-2020-2021 is trending on Twitter.
Created: 2020-08-19T23:08:05.709Z
Modified: 2020-08-19T23:08:05.709Z
External id: CVE-2020-2021
Sixgill DVE score - current: 9.13
Sixgill DVE score - highest ever date: 2020-07-14T00:00Z
Sixgill DVE score - highest ever: 9.25
Sixgill - Previously exploited probability: 5.32
Event Name: trend_Twitter
Event Type: dark_mention
Event Action: trend
Previous level: prev_level
Event Description: CVE-2020-2021 is trending on Twitter.
Event Datetime: 2020-06-30T00:00Z
CVSS 3.1 score: 10.0
CVSS 3.1 severity: CRITICAL
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2020-2021
NVD - last modified date: 2020-07-06T14:39Z
NVD - publication date: 2020-06-29T15:15Z
CVSS 2.0 score: 9.3
CVSS 2.0 severity: HIGH
NVD Vector - V2.0: AV:N/AC:M/Au:N/C:C/I:C/A:C
NVD Vector - V3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
""",
            "creationdate": "2020-08-19T23:08:05.709Z",
            "modified": "2020-08-19T23:08:05.709Z",
            "externalid": "CVE-2020-2021",
            "sixgilldvescorecurrent": 9.13,
            "sixgilldvescorehighesteverdate": "2020-07-14T00:00Z",
            "sixgilldvescorehighestever": 9.25,
            "sixgillpreviouslyexploitedprobability": 5.32,
            "eventname": "trend_Twitter",
            "eventtype": "dark_mention",
            "eventaction": "trend",
            "previouslevel": "prev_level",
            "eventdescription": "CVE-2020-2021 is trending on Twitter.",
            "eventdatetime": "2020-06-30T00:00Z",
            "cvss31score": 10.0,
            "cvss31severity": "CRITICAL",
            "nvdlink": "https://nvd.nist.gov/vuln/detail/CVE-2020-2021",
            "nvdlastmodifieddate": "2020-07-06T14:39Z",
            "nvdpublicationdate": "2020-06-29T15:15Z",
            "cvss20score": 9.3,
            "cvss20severity": "HIGH",
            "nvdvectorv20": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
            "nvdvectorv31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        },
    },
    {
        "value": "CVE-2020-12828",
        "type": "CVE",
        "rawJSON": {
            "value": "CVE-2020-12828",
            "type": "x-cybersixgill-com-cve-event",
            "created": "2020-08-19T23:08:05.709Z",
            "external_references": [{"external_id": "CVE-2020-12828", "source_name": "cve"}],
            "id": "cveevent--dffdcd6b-2157-4652-b7eb-4ce4bb9eebc5",
            "modified": "2020-08-19T23:08:05.709Z",
            "object_marking_refs": [
                "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            ],
            "spec_version": "2.0",
            "x_sixgill_info": {
                "event": {
                    "_id": "5f3db0ec3ecfe5a6d70b6274",
                    "action": "trend",
                    "description": "CVE-2020-12828 is trending on Twitter.",
                    "event_datetime": "2020-06-30T00:00Z",
                    "name": "trend_Twitter",
                    "prev_level": "prev_level",
                    "type": "dark_mention",
                },
                "nvd": {
                    "base_score_v3": 9.8,
                    "base_severity_v3": "CRITICAL",
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-12828",
                    "modified": "2020-06-02T16:55Z",
                    "published": "2020-05-21T17:15Z",
                    "score_2_0": 10.0,
                    "severity_2_0": "HIGH",
                    "vector_v2": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                    "vector_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                "rating": {
                    "current": 8.33,
                    "highest": {"date": "2020-07-25T00:00Z", "value": 8.4},
                    "previouslyExploited": 5.07,
                },
            },
        },
        "score": 3,
        "fields": {
            "description": """Description: CVE-2020-12828 is trending on Twitter.
Created: 2020-08-19T23:08:05.709Z
Modified: 2020-08-19T23:08:05.709Z
External id: CVE-2020-12828
Sixgill DVE score - current: 8.33
Sixgill DVE score - highest ever date: 2020-07-25T00:00Z
Sixgill DVE score - highest ever: 8.4
Sixgill - Previously exploited probability: 5.07
Event Name: trend_Twitter
Event Type: dark_mention
Event Action: trend
Previous level: prev_level
Event Description: CVE-2020-12828 is trending on Twitter.
Event Datetime: 2020-06-30T00:00Z
CVSS 3.1 score: 9.8
CVSS 3.1 severity: CRITICAL
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2020-12828
NVD - last modified date: 2020-06-02T16:55Z
NVD - publication date: 2020-05-21T17:15Z
CVSS 2.0 score: 10.0
CVSS 2.0 severity: HIGH
NVD Vector - V2.0: AV:N/AC:L/Au:N/C:C/I:C/A:C
NVD Vector - V3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
""",
            "creationdate": "2020-08-19T23:08:05.709Z",
            "modified": "2020-08-19T23:08:05.709Z",
            "externalid": "CVE-2020-12828",
            "sixgilldvescorecurrent": 8.33,
            "sixgilldvescorehighesteverdate": "2020-07-25T00:00Z",
            "sixgilldvescorehighestever": 8.4,
            "sixgillpreviouslyexploitedprobability": 5.07,
            "eventname": "trend_Twitter",
            "eventtype": "dark_mention",
            "eventaction": "trend",
            "previouslevel": "prev_level",
            "eventdescription": "CVE-2020-12828 is trending on Twitter.",
            "eventdatetime": "2020-06-30T00:00Z",
            "cvss31score": 9.8,
            "cvss31severity": "CRITICAL",
            "nvdlink": "https://nvd.nist.gov/vuln/detail/CVE-2020-12828",
            "nvdlastmodifieddate": "2020-06-02T16:55Z",
            "nvdpublicationdate": "2020-05-21T17:15Z",
            "cvss20score": 10.0,
            "cvss20severity": "HIGH",
            "nvdvectorv20": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "nvdvectorv31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
    },
    {
        "value": "CVE-2020-9771",
        "type": "CVE",
        "rawJSON": {
            "value": "CVE-2020-9771",
            "type": "x-cybersixgill-com-cve-event",
            "created": "2020-08-19T23:08:05.709Z",
            "external_references": [{"external_id": "CVE-2020-9771", "source_name": "cve"}],
            "id": "cveevent--4b86077c-99f6-42ca-8b4d-953411fa17bd",
            "modified": "2020-08-19T23:08:05.709Z",
            "object_marking_refs": [
                "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            ],
            "spec_version": "2.0",
            "x_sixgill_info": {
                "event": {
                    "_id": "5f3db0ec3ecfe5a6d70b627c",
                    "action": "trend",
                    "description": "CVE-2020-9771 is trending on Twitter.",
                    "event_datetime": "2020-06-30T00:00Z",
                    "name": "trend_Twitter",
                    "prev_level": "prev_level",
                    "type": "dark_mention",
                },
                "nvd": {
                    "base_score_v3": None,
                    "base_severity_v3": None,
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-9771",
                    "modified": None,
                    "published": None,
                    "score_2_0": None,
                    "severity_2_0": None,
                    "vector_v2": "None",
                    "vector_v3": "None",
                },
                "rating": {"current": None, "highest": {"date": None, "value": None}, "previouslyExploited": None},
            },
        },
        "score": 3,
        "fields": {
            "description": """Description: CVE-2020-9771 is trending on Twitter.
Created: 2020-08-19T23:08:05.709Z
Modified: 2020-08-19T23:08:05.709Z
External id: CVE-2020-9771
Sixgill DVE score - current: None
Sixgill DVE score - highest ever date: None
Sixgill DVE score - highest ever: None
Sixgill - Previously exploited probability: None
Event Name: trend_Twitter
Event Type: dark_mention
Event Action: trend
Previous level: prev_level
Event Description: CVE-2020-9771 is trending on Twitter.
Event Datetime: 2020-06-30T00:00Z
CVSS 3.1 score: None
CVSS 3.1 severity: None
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2020-9771
NVD - last modified date: None
NVD - publication date: None
CVSS 2.0 score: None
CVSS 2.0 severity: None
NVD Vector - V2.0: None
NVD Vector - V3.1: None
""",
            "creationdate": "2020-08-19T23:08:05.709Z",
            "modified": "2020-08-19T23:08:05.709Z",
            "externalid": "CVE-2020-9771",
            "sixgilldvescorecurrent": None,
            "sixgilldvescorehighesteverdate": None,
            "sixgilldvescorehighestever": None,
            "sixgillpreviouslyexploitedprobability": None,
            "eventname": "trend_Twitter",
            "eventtype": "dark_mention",
            "eventaction": "trend",
            "previouslevel": "prev_level",
            "eventdescription": "CVE-2020-9771 is trending on Twitter.",
            "eventdatetime": "2020-06-30T00:00Z",
            "cvss31score": None,
            "cvss31severity": None,
            "nvdlink": "https://nvd.nist.gov/vuln/detail/CVE-2020-9771",
            "nvdlastmodifieddate": None,
            "nvdpublicationdate": None,
            "cvss20score": None,
            "cvss20severity": None,
            "nvdvectorv20": "None",
            "nvdvectorv31": "None",
        },
    },
    {
        "value": "CVE-2015-6086",
        "type": "CVE",
        "rawJSON": {
            "value": "CVE-2015-6086",
            "type": "x-cybersixgill-com-cve-event",
            "created": "2020-08-25T17:16:52.536Z",
            "external_references": [{"external_id": "CVE-2015-6086", "source_name": "cve"}],
            "id": "cveevent--1d6320f1-8b22-48e2-876d-5e31b9d36288",
            "modified": "2020-08-25T17:16:52.536Z",
            "object_marking_refs": [
                "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            ],
            "spec_version": "2.0",
            "x_sixgill_info": {
                "event": {
                    "_id": "5f454784ffebcfa91197c9d0",
                    "action": "modified",
                    "description": "Sixgill Current score of CVE-2015-6086 changed from Low to None.",
                    "event_datetime": "2020-06-30T00:00Z",
                    "level": "None",
                    "name": "Sixgill_score_level_change",
                    "prev_level": "prev_level",
                    "type": "score_level",
                },
                "nvd": {
                    "base_score_v3": None,
                    "base_severity_v3": None,
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2015-6086",
                    "modified": "2018-10-12T22:10Z",
                    "published": "2015-11-11T12:59Z",
                    "score_2_0": 4.3,
                    "severity_2_0": "MEDIUM",
                    "vector_v2": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                    "vector_v3": "None",
                },
                "rating": {
                    "current": None,
                    "highest": {"date": "2016-04-14T00:00Z", "value": 7.02},
                    "previouslyExploited": 1.51,
                },
            },
        },
        "score": 3,
        "fields": {
            "description": """Description: Sixgill Current score of CVE-2015-6086 changed from Low to None.
Created: 2020-08-25T17:16:52.536Z
Modified: 2020-08-25T17:16:52.536Z
External id: CVE-2015-6086
Sixgill DVE score - current: None
Sixgill DVE score - highest ever date: 2016-04-14T00:00Z
Sixgill DVE score - highest ever: 7.02
Sixgill - Previously exploited probability: 1.51
Event Name: Sixgill_score_level_change
Event Type: score_level
Event Action: modified
Previous level: prev_level
Event Description: Sixgill Current score of CVE-2015-6086 changed from Low to None.
Event Datetime: 2020-06-30T00:00Z
CVSS 3.1 score: None
CVSS 3.1 severity: None
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2015-6086
NVD - last modified date: 2018-10-12T22:10Z
NVD - publication date: 2015-11-11T12:59Z
CVSS 2.0 score: 4.3
CVSS 2.0 severity: MEDIUM
NVD Vector - V2.0: AV:N/AC:M/Au:N/C:P/I:N/A:N
NVD Vector - V3.1: None
""",
            "creationdate": "2020-08-25T17:16:52.536Z",
            "modified": "2020-08-25T17:16:52.536Z",
            "externalid": "CVE-2015-6086",
            "sixgilldvescorecurrent": None,
            "sixgilldvescorehighesteverdate": "2016-04-14T00:00Z",
            "sixgilldvescorehighestever": 7.02,
            "sixgillpreviouslyexploitedprobability": 1.51,
            "eventname": "Sixgill_score_level_change",
            "eventtype": "score_level",
            "eventaction": "modified",
            "previouslevel": "prev_level",
            "eventdescription": "Sixgill Current score of CVE-2015-6086 changed from Low to None.",
            "eventdatetime": "2020-06-30T00:00Z",
            "cvss31score": None,
            "cvss31severity": None,
            "nvdlink": "https://nvd.nist.gov/vuln/detail/CVE-2015-6086",
            "nvdlastmodifieddate": "2018-10-12T22:10Z",
            "nvdpublicationdate": "2015-11-11T12:59Z",
            "cvss20score": 4.3,
            "cvss20severity": "MEDIUM",
            "nvdvectorv20": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
            "nvdvectorv31": "None",
        },
    },
    {
        "value": "CVE-2015-6086",
        "type": "CVE",
        "rawJSON": {
            "value": "CVE-2015-6086",
            "type": "x-cybersixgill-com-cve-event",
            "created": "2020-08-25T17:16:52.536Z",
            "external_references": [{"external_id": "CVE-2015-6086", "source_name": "cve"}],
            "id": "cveevent--1d6320f1-8b22-48e2-876d-5e31b9d36288",
            "modified": "2020-08-25T17:16:52.536Z",
            "object_marking_refs": [
                "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            ],
            "spec_version": "2.0",
            "x_sixgill_info": {
                "event": {
                    "_id": "5f454784ffebcfa91197c9d0",
                    "action": "modified",
                    "description": "Sixgill Current score of CVE-2015-6086 changed from Low to None.",
                    "event_datetime": "2020-06-30T00:00Z",
                    "level": "None",
                    "name": "Sixgill_score_level_change",
                    "prev_level": "prev_level",
                    "type": "score_level",
                },
                "nvd": {
                    "base_score_v3": None,
                    "base_severity_v3": None,
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2015-6086",
                    "modified": "2018-10-12T22:10Z",
                    "published": "2015-11-11T12:59Z",
                    "score_2_0": 4.3,
                    "severity_2_0": "MEDIUM",
                    "vector_v2": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                    "vector_v3": "None",
                },
                "rating": {
                    "current": None,
                    "highest": {"date": "2016-04-14T00:00Z", "value": 7.02},
                    "previouslyExploited": 1.51,
                },
            },
        },
        "score": 3,
        "fields": {
            "description": """Description: Sixgill Current score of CVE-2015-6086 changed from Low to None.
Created: 2020-08-25T17:16:52.536Z
Modified: 2020-08-25T17:16:52.536Z
External id: CVE-2015-6086
Sixgill DVE score - current: None
Sixgill DVE score - highest ever date: 2016-04-14T00:00Z
Sixgill DVE score - highest ever: 7.02
Sixgill - Previously exploited probability: 1.51
Event Name: Sixgill_score_level_change
Event Type: score_level
Event Action: modified
Previous level: prev_level
Event Description: Sixgill Current score of CVE-2015-6086 changed from Low to None.
Event Datetime: 2020-06-30T00:00Z
CVSS 3.1 score: None
CVSS 3.1 severity: None
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2015-6086
NVD - last modified date: 2018-10-12T22:10Z
NVD - publication date: 2015-11-11T12:59Z
CVSS 2.0 score: 4.3
CVSS 2.0 severity: MEDIUM
NVD Vector - V2.0: AV:N/AC:M/Au:N/C:P/I:N/A:N
NVD Vector - V3.1: None
""",
            "creationdate": "2020-08-25T17:16:52.536Z",
            "modified": "2020-08-25T17:16:52.536Z",
            "externalid": "CVE-2015-6086",
            "sixgilldvescorecurrent": None,
            "sixgilldvescorehighesteverdate": "2016-04-14T00:00Z",
            "sixgilldvescorehighestever": 7.02,
            "sixgillpreviouslyexploitedprobability": 1.51,
            "eventname": "Sixgill_score_level_change",
            "eventtype": "score_level",
            "eventaction": "modified",
            "previouslevel": "prev_level",
            "eventdescription": "Sixgill Current score of CVE-2015-6086 changed from Low to None.",
            "eventdatetime": "2020-06-30T00:00Z",
            "cvss31score": None,
            "cvss31severity": None,
            "nvdlink": "https://nvd.nist.gov/vuln/detail/CVE-2015-6086",
            "nvdlastmodifieddate": "2018-10-12T22:10Z",
            "nvdpublicationdate": "2015-11-11T12:59Z",
            "cvss20score": 4.3,
            "cvss20severity": "MEDIUM",
            "nvdvectorv20": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
            "nvdvectorv31": "None",
        },
    },
]


class MockedResponse:
    def __init__(
        self,
        status_code,
        text,
        reason=None,
        url=None,
        method=None,
    ):
        self.status_code = status_code
        self.text = text
        self.reason = reason
        self.url = url
        self.request = requests.Request("GET")
        self.ok = self.status_code == 200
        self.headers = ""

    def json(self):
        return json.loads(self.text)


def init_params():
    return {"client_id": "WRONG_CLIENT_ID_TEST", "client_secret": "CLIENT_SECRET_TEST"}


def mocked_request(*args, **kwargs):
    global bundle_index
    global submitted_indicators

    request = kwargs.get("request", {})
    end_point = request.path_url
    method = request.method
    response_dict = {
        "POST": {
            "/auth/token": MockedResponse(200, mocked_get_token_response),
            "/dvefeed/ioc/ack": MockedResponse(200, str(submitted_indicators)),
        },
        "GET": {"/dvefeed/ioc?limit=1000": MockedResponse(200, json.dumps(iocs_bundle[bundle_index]))},
    }

    response_dict = response_dict.get(method)
    response = response_dict.get(end_point)

    if method == "GET" and end_point == "/dvefeed/ioc?limit=1000":
        submitted_indicators = len(iocs_bundle[bundle_index].get("objects")) - 2
        bundle_index += 1
    return response


def test_test_module_command_raise_exception(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", return_value=MockedResponse(400, "error"))

    from CybersixgillDVEFeed import module_command_test

    with pytest.raises(Exception):
        module_command_test()


def test_test_module_command(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", return_value=MockedResponse(200, "ok"))

    from CybersixgillDVEFeed import module_command_test

    module_command_test()


def test_fetch_indicators_command(mocker):
    global bundle_index
    global submitted_indicators

    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from CybersixgillDVEFeed import fetch_indicators_command
    from sixgill.sixgill_feed_client import SixgillFeedClient
    from sixgill.sixgill_constants import FeedStream

    client = SixgillFeedClient(
        demisto.params()["client_id"],
        demisto.params()["client_secret"],
        "some_channel",
        FeedStream.DVEFEED,
        demisto,
        1000,
    )

    output = fetch_indicators_command(client)

    bundle_index = 0
    submitted_indicators = 0
    assert output == expected_ioc_output


def test_get_indicators_command(mocker):
    global bundle_index
    global submitted_indicators

    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from CybersixgillDVEFeed import get_indicators_command
    from sixgill.sixgill_feed_client import SixgillFeedClient
    from sixgill.sixgill_constants import FeedStream

    client = SixgillFeedClient(
        demisto.params()["client_id"],
        demisto.params()["client_secret"],
        "some_channel",
        FeedStream.DVEFEED,
        demisto,
        1000,
    )

    output = get_indicators_command(client, {"limit": 10})
    bundle_index = 0
    submitted_indicators = 0
    assert output[2] == expected_ioc_output


@pytest.mark.parametrize("tlp_color", ["", None, "AMBER"])
def test_feed_tags_and_tlp_color(mocker, tlp_color):
    """
    Given:
    - feedTags parameter
    When:
    - Executing fetch command on feed
    Then:
    - Validate the tags supplied are added to the tags list in addition to the tags that were there before
    """

    global bundle_index
    global submitted_indicators

    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from CybersixgillDVEFeed import fetch_indicators_command
    from sixgill.sixgill_feed_client import SixgillFeedClient
    from sixgill.sixgill_constants import FeedStream

    client = SixgillFeedClient(
        demisto.params()["client_id"],
        demisto.params()["client_secret"],
        "some_channel",
        FeedStream.DVEFEED,
        demisto,
        1000,
    )

    output = fetch_indicators_command(client, tags=["tag1", "tag2"], tlp_color=tlp_color)
    assert all(item in output[0]["fields"]["tags"] for item in ["tag1", "tag2"])
    if tlp_color:
        assert output[0]["fields"]["trafficlightprotocol"] == tlp_color
    else:
        assert not output[0]["fields"].get("trafficlightprotocol")
        bundle_index -= 1
