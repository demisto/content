Find, prioritize, and fix vulnerabilities on your IT & OT assets.
This integration was integrated and tested with version 13.11 of Cyberwatch.

## Configure Cyberwatch in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Master scanner URL (e.g. https://192.168.0.1) | The Cyberwatch master scanner URL. | True |
| API Access key | See the Cyberwatch documentation for instructions to generate the API access and secret keys. | True |
| API Secret key | See the Cyberwatch documentation for instructions to generate the API access and secret keys. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cyberwatch-list-cves

***
Get a list of CVEs from Cyberwatch.

#### Base Command

`cyberwatch-list-cves`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exploit_code_maturity[] | Filter CVE announcements with exploit_code_maturity. Available values: undefined, unproven, proof_of_concept, functional, high. Possible values are: undefined, unproven, proof_of_concept, functional, high. | Optional | 
| access_vector[] | Filter CVE announcements with access_vector. Available values: access_vector_physical, access_vector_local, access_vector_adjacent, access_vector_network. Possible values are: access_vector_physical, access_vector_local, access_vector_adjacent, access_vector_network. | Optional | 
| active | Filter CVE announcements that are active or not (true or false). Possible values are: true, false. | Optional | 
| level | Filter CVE announcements based on their level. Available values: level_unknown, level_none, level_low, level_medium, level_high, level_critical. Possible values are: level_unknown, level_none, level_low, level_medium, level_high, level_critical. | Optional | 
| ignored | Filter CVE announcements that are ignored or not  (true or false). Possible values are: true, false. | Optional | 
| prioritized | Filter CVE announcements that are prioritized or not (true or false). Possible values are: true, false. | Optional | 
| technology_product | Filter CVE announcements with technology_product (CPE product field). | Optional | 
| technology_vendor | Filter CVE announcements with technology_vendor (CPE vendor field). | Optional | 
| groups[] | Filter CVE announcements with a list of groups. Multiple groups can be provided with comma, e.g. groups[]=GroupA,GroupB. | Optional | 
| page | Get a specific CVE announcements page. If not specified, get all CVEs. | Optional | 
| per_page | Specify the number of CVE per page. Default value 500. | Optional | 
| hard_limit | Specify the maximum number of results. This is useful to avoid memory issues on Cortex. Default value is 2000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberwatch.CVE.cve_code | string | CVE reference | 
| Cyberwatch.CVE.score | number | CVE score | 
| Cyberwatch.CVE.exploitable | boolean | CVE exploitability | 
| Cyberwatch.CVE.epss | number | CVE EPSS | 
| Cyberwatch.CVE.published | date | CVE publication date | 
| Cyberwatch.CVE.last_modified | date | CVE last modification date | 

#### Command example
```!cyberwatch-list-cves page=1 per_page=5```
#### Context Example
```json
{
    "Cyberwatch": {
        "CVE": [
            {
                "content": "The Zombie...",
                "cve_code": "CVE-2014-7552",
                "cvss": {
                    "access_complexity": "access_complexity_medium",
                    "access_vector": "access_vector_adjacent_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16778597,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cwe": {
                    "attacks": [],
                    "capecs": [],
                    "cwe_id": "CWE-310"
                },
                "epss": 0.00049,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2014-11-14T13:13:46.943Z",
                "level": "level_medium",
                "published": "2014-10-20T08:55:10.450Z",
                "score": 5.4,
                "score_v2": 5.4,
                "technologies": [
                    {
                        "product": "zombie_diary",
                        "vendor": "129zou"
                    }
                ]
            },
            {
                "content": "The 9GAG -...",
                "cve_code": "CVE-2014-5669",
                "cvss": {
                    "access_complexity": "access_complexity_medium",
                    "access_vector": "access_vector_adjacent_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16778597,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cwe": {
                    "attacks": [],
                    "capecs": [],
                    "cwe_id": "CWE-310"
                },
                "epss": 0.00049,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2014-09-10T23:33:44.000Z",
                "level": "level_medium",
                "published": "2014-09-08T23:55:36.977Z",
                "score": 5.4,
                "score_v2": 5.4,
                "technologies": [
                    {
                        "product": "9gag_-_funny_pics_and_videos",
                        "vendor": "9gag"
                    }
                ]
            },
            {
                "content": "Multiple a...",
                "cve_code": "CVE-2013-5021",
                "cvss": {
                    "access_complexity": "access_complexity_medium",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_complete",
                    "confidentiality_impact": "confidentiality_impact_complete",
                    "id": 16779942,
                    "integrity_impact": "integrity_impact_complete"
                },
                "cwe": {
                    "attacks": [
                        "T1036",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-126",
                        "..."
                    ],
                    "cwe_id": "CWE-22"
                },
                "epss": 0.89796,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2023-11-07T01:16:25.783Z",
                "level": "level_critical",
                "published": "2013-08-06T18:55:05.287Z",
                "score": 9.3,
                "score_v2": 9.3,
                "technologies": [
                    {
                        "product": "labview",
                        "vendor": "ni"
                    }
                ]
            },
            {
                "content": "The ACC Ad...",
                "cve_code": "CVE-2014-7387",
                "cvss": {
                    "access_complexity": "access_complexity_medium",
                    "access_vector": "access_vector_adjacent_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16778597,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cwe": {
                    "attacks": [],
                    "capecs": [],
                    "cwe_id": "CWE-310"
                },
                "epss": 0.00049,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2014-11-14T13:10:30.627Z",
                "level": "level_medium",
                "published": "2014-10-19T08:55:15.207Z",
                "score": 5.4,
                "score_v2": 5.4,
                "technologies": [
                    {
                        "product": "acc_advocacy_action",
                        "vendor": "accadvocacy"
                    }
                ]
            },
            {
                "content": "pbs_mom in...",
                "cve_code": "CVE-2013-4319",
                "cvss": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_single",
                    "availability_impact": "availability_impact_complete",
                    "confidentiality_impact": "confidentiality_impact_complete",
                    "id": 16779930,
                    "integrity_impact": "integrity_impact_complete"
                },
                "cwe": {
                    "attacks": [],
                    "capecs": [],
                    "cwe_id": "CWE-264"
                },
                "epss": 0.0026,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2013-10-15T14:05:34.140Z",
                "level": "level_critical",
                "published": "2013-10-11T20:55:40.067Z",
                "score": 9,
                "score_v2": 9,
                "technologies": [
                    {
                        "product": "torque_resource_manager",
                        "vendor": "adaptivecomputing"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberwatch CVEs
>|cve_code|content|published|last_modified|level|score|epss|cvss_v3|
>|---|---|---|---|---|---|---|---|
>| CVE-2014-7552 | The Zombie Diary (aka com.ezjoy.feelingtouch.zombiediary)... | 2014-10-20T08:55:10 | 2014-11-14T13:13:46 | level_medium | 5.4 | 0.00049 |  |
>| CVE-2014-5669 | The 9GAG - Funny pics and videos (aka com.ninegag.android.app)... | 2014-09-08T23:55:36 | 2014-09-10T23:33:44 | level_medium | 5.4 | 0.00049 |  |
>| CVE-2013-5021 | Multiple absolute path traversal vulnerabilities in National Instruments... | 2013-08-06T18:55:05 | 2023-11-07T01:16:25 | level_critical | 9.3 | 0.89796 |  |
>| CVE-2014-7387 | The ACC Advocacy Action (aka com.acc.app.android.ui) application 2.0... | 2014-10-19T08:55:15 | 2014-11-14T13:10:30 | level_medium | 5.4 | 0.00049 |  |
>| CVE-2013-4319 | pbs_mom in Terascale Open-Source Resource and Queue Manager (aka TORQUE Resource Manager)... | 2013-10-11T20:55:40 | 2013-10-15T14:05:34 | level_critical | 9.0 | 0.0026 |  |


#### Command example
```!cyberwatch-list-cves prioritized=true page=1 per_page=5```
#### Context Example
```json
{
    "Cyberwatch": {
        "CVE": [
            {
                "content": "Mozilla de...",
                "cve_code": "CVE-2020-15683",
                "cvss": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16778602,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_none"
                },
                "cwe": {
                    "attacks": [
                        "T1134",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-10",
                        "..."
                    ],
                    "cwe_id": "CWE-416"
                },
                "epss": 0.01033,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2022-04-28T16:24:03.743Z",
                "level": "level_critical",
                "published": "2020-10-22T19:15:13.513Z",
                "score": 9.8,
                "score_v2": 7.5,
                "score_v3": 9.8,
                "technologies": [
                    {
                        "product": "firefox",
                        "vendor": "mozilla"
                    },
                    {
                        "product": "...",
                        "vendor": "..."
                    }
                ]
            },
            {
                "content": "Crossbeam ...",
                "cve_code": "CVE-2020-15254",
                "cvss": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16778602,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_none"
                },
                "cwe": {
                    "attacks": [
                        "T1134",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-125",
                        "..."
                    ],
                    "cwe_id": "CWE-401"
                },
                "epss": 0.00603,
                "exploit_code_maturity": "functional",
                "exploitable": true,
                "last_modified": "2022-08-05T17:30:49.067Z",
                "level": "level_critical",
                "published": "2020-10-16T15:15:12.057Z",
                "score": 9.8,
                "score_v2": 7.5,
                "score_v3": 9.8,
                "technologies": [
                    {
                        "product": "crossbeam",
                        "vendor": "crossbeam_project"
                    }
                ]
            },
            {
                "content": "Use ...",
                "cve_code": "CVE-2020-15969",
                "cvss": {
                    "access_complexity": "access_complexity_medium",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16778598,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_required"
                },
                "cwe": {
                    "attacks": [
                        "T1134",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-10",
                        "..."
                    ],
                    "cwe_id": "CWE-416"
                },
                "epss": 0.00833,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2023-11-07T02:17:58.410Z",
                "level": "level_high",
                "published": "2020-11-03T02:15:12.790Z",
                "score": 8.8,
                "score_v2": 6.8,
                "score_v3": 8.8,
                "technologies": [
                    {
                        "product": "chrome",
                        "vendor": "google"
                    },
                    {
                        "product": "...",
                        "vendor": "..."
                    }
                ]
            },
            {
                "content": "In certain...",
                "cve_code": "CVE-2020-26950",
                "cvss": {
                    "access_complexity": "access_complexity_medium",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_complete",
                    "confidentiality_impact": "confidentiality_impact_complete",
                    "id": 16779942,
                    "integrity_impact": "integrity_impact_complete"
                },
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_required"
                },
                "cwe": {
                    "attacks": [
                        "T1134",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-10",
                        "..."
                    ],
                    "cwe_id": "CWE-416"
                },
                "epss": 0.92391,
                "exploit_code_maturity": "high",
                "exploitable": true,
                "last_modified": "2022-04-08T09:28:19.070Z",
                "level": "level_high",
                "published": "2020-12-09T00:15:12.503Z",
                "score": 8.8,
                "score_v2": 9.3,
                "score_v3": 8.8,
                "technologies": [
                    {
                        "product": "firefox",
                        "vendor": "mozilla"
                    },
                    {
                        "product": "...",
                        "vendor": "..."
                    }
                ]
            },
            {
                "content": "Out of bou...",
                "cve_code": "CVE-2021-30547",
                "cvss": {
                    "access_complexity": "access_complexity_medium",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16778598,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_required"
                },
                "cwe": {
                    "attacks": [
                        "T1134",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-10",
                        "..."
                    ],
                    "cwe_id": "CWE-787"
                },
                "epss": 0.00829,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2023-11-07T02:33:06.280Z",
                "level": "level_high",
                "published": "2021-06-15T20:15:08.930Z",
                "score": 8.8,
                "score_v2": 6.8,
                "score_v3": 8.8,
                "technologies": [
                    {
                        "product": "chrome",
                        "vendor": "google"
                    },
                    {
                        "product": "...",
                        "vendor": "..."
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberwatch CVEs
>|cve_code|content|published|last_modified|level|score|epss|cvss_v3|
>|---|---|---|---|---|---|---|---|
>| CVE-2020-15683 | Mozilla developers and community members... | 2020-10-22T19:15:13 | 2022-04-28T16:24:03 | level_critical | 9.8 | 0.01033 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_none<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |
>| CVE-2020-15254 | Crossbeam is a set of tools for concurrent programming. In crossbeam... | 2020-10-16T15:15:12 | 2022-08-05T17:30:49 | level_critical | 9.8 | 0.00603 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_none<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |
>| CVE-2020-15969 | Use after free in WebRTC in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. | 2020-11-03T02:15:12 | 2023-11-07T02:17:58 | level_high | 8.8 | 0.00833 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_required<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |
>| CVE-2020-26950 | In certain circumstances, the MCallGetProperty opcode can be emitted... | 2020-12-09T00:15:12 | 2022-04-08T09:28:19 | level_high | 8.8 | 0.92391 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_required<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |
>| CVE-2021-30547 | Out of bounds write in ANGLE in Google Chrome prior... | 2021-06-15T20:15:08 | 2023-11-07T02:33:06 | level_high | 8.8 | 0.00829 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_required<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |


#### Command example
```!cyberwatch-list-cves exploit_code_maturity[]=functional,high access_vector[]=access_vector_physical,access_vector_network active=true level=level_critical ignored=false page=1 per_page=5```
#### Context Example
```json
{
    "Cyberwatch": {
        "CVE": [
            {
                "content": "An Imprope...",
                "cve_code": "CVE-2018-13382",
                "cvss": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_none",
                    "confidentiality_impact": "confidentiality_impact_none",
                    "id": 16777514,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_none",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_none"
                },
                "cwe": {
                    "attacks": [
                        "T1005",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-1",
                        "..."
                    ],
                    "cwe_id": "CWE-285"
                },
                "epss": 0.89131,
                "exploit_code_maturity": "functional",
                "exploitable": true,
                "last_modified": "2021-06-03T11:15:08.413+02:00",
                "level": "level_critical",
                "published": "2019-06-04T21:29:00.373+02:00",
                "score": 9.1,
                "score_v2": 5,
                "score_v3": 9.1,
                "technologies": [
                    {
                        "product": "fortios",
                        "vendor": "fortinet"
                    }
                ]
            },
            {
                "content": "Crossbeam ...",
                "cve_code": "CVE-2020-15254",
                "cvss": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16778602,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_none"
                },
                "cwe": {
                    "attacks": [
                        "T1134",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-125",
                        "..."
                    ],
                    "cwe_id": "CWE-401"
                },
                "epss": 0.00603,
                "exploit_code_maturity": "functional",
                "exploitable": true,
                "last_modified": "2022-08-05T19:30:49.067+02:00",
                "level": "level_critical",
                "published": "2020-10-16T17:15:12.057+02:00",
                "score": 9.8,
                "score_v2": 7.5,
                "score_v3": 9.8,
                "technologies": [
                    {
                        "product": "crossbeam",
                        "vendor": "crossbeam_project"
                    }
                ]
            },
            {
                "content": "An unexpec...",
                "cve_code": "CVE-2022-26486",
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_changed",
                    "user_interaction": "user_interaction_required"
                },
                "cwe": {
                    "attacks": [
                        "T1134",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-10",
                        "..."
                    ],
                    "cwe_id": "CWE-416"
                },
                "epss": 0.0032,
                "exploit_code_maturity": "functional",
                "exploitable": true,
                "last_modified": "2022-12-30T20:55:00.220+01:00",
                "level": "level_critical",
                "published": "2022-12-22T20:15:22.797+01:00",
                "score": 9.6,
                "score_v3": 9.6,
                "technologies": [
                    {
                        "product": "firefox_focus",
                        "vendor": "mozilla"
                    },
                    {
                        "product": "...",
                        "vendor": "..."
                    }
                ]
            },
            {
                "content": "A use-afte...",
                "cve_code": "CVE-2023-32412",
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_none"
                },
                "cwe": {
                    "attacks": [
                        "T1134",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-10",
                        "..."
                    ],
                    "cwe_id": "CWE-416"
                },
                "epss": 0.02044,
                "exploit_code_maturity": "functional",
                "exploitable": true,
                "last_modified": "2023-07-27T04:15:34.367+02:00",
                "level": "level_critical",
                "published": "2023-06-23T18:15:13.320+02:00",
                "score": 9.8,
                "score_v3": 9.8,
                "technologies": [
                    {
                        "product": "ipados",
                        "vendor": "apple"
                    },
                    {
                        "product": "...",
                        "vendor": "..."
                    }
                ]
            },
            {
                "content": "A out-of-b...",
                "cve_code": "CVE-2024-21762",
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_none"
                },
                "cwe": {
                    "attacks": [
                        "T1134",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-10",
                        "..."
                    ],
                    "cwe_id": "CWE-787"
                },
                "epss": 0.01842,
                "exploit_code_maturity": "functional",
                "exploitable": true,
                "last_modified": "2024-02-13T18:21:14.607+01:00",
                "level": "level_critical",
                "published": "2024-02-09T09:15:08.087+01:00",
                "score": 9.8,
                "score_v3": 9.8,
                "technologies": [
                    {
                        "product": "fortiproxy",
                        "vendor": "fortinet"
                    },
                    {
                        "product": "fortios",
                        "vendor": "fortinet"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberwatch CVEs
>|cve_code|content|published|last_modified|level|score|epss|cvss_v3|
>|---|---|---|---|---|---|---|---|
>| CVE-2018-13382 | An Improper Authorization vulnerability... | 2019-06-04T19:29:00 | 2021-06-03T09:15:08 | level_critical | 9.1 | 0.89131 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_none<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_none |
>| CVE-2020-15254 | Crossbeam is a set of tools for concurrent programming... | 2020-10-16T15:15:12 | 2022-08-05T17:30:49 | level_critical | 9.8 | 0.00603 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_none<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |
>| CVE-2022-26486 | An unexpected message in the WebGPU IPC framework could... | 2022-12-22T19:15:22 | 2022-12-30T19:55:00 | level_critical | 9.6 | 0.0032 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_required<br/>***scope***: scope_changed<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |
>| CVE-2023-32412 | A use-after-free issue was addressed with improved... | 2023-06-23T16:15:13 | 2023-07-27T02:15:34 | level_critical | 9.8 | 0.02044 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_none<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |
>| CVE-2024-21762 | A out-of-bounds write in Fortinet FortiOS versions 7.4.0... | 2024-02-09T08:15:08 | 2024-02-13T17:21:14 | level_critical | 9.8 | 0.01842 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_none<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |


#### Command example
```!cyberwatch-list-cves page=1 per_page=5 groups[]=ENV_PRODUCTION,Cloud active=true ignored=false prioritized=true```
#### Context Example
```json
{
    "Cyberwatch": {
        "CVE": [
            {
                "content": "Internet E...",
                "cve_code": "CVE-2021-26411",
                "cvss": {
                    "access_complexity": "access_complexity_high",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16778594,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_low",
                    "confidentiality_impact": "confidentiality_impact_low",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_changed",
                    "user_interaction": "user_interaction_required"
                },
                "cwe": {
                    "attacks": [
                        "T1134",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-10",
                        "..."
                    ],
                    "cwe_id": "CWE-416"
                },
                "epss": 0.04096,
                "exploit_code_maturity": "proof_of_concept",
                "exploitable": true,
                "last_modified": "2023-12-29T17:15:59.767+01:00",
                "level": "level_high",
                "published": "2021-03-11T16:15:13.863+01:00",
                "score": 8.8,
                "score_v2": 5.1,
                "score_v3": 8.8,
                "technologies": [
                    {
                        "product": "edge",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "internet_explorer",
                        "vendor": "microsoft"
                    }
                ]
            },
            {
                "content": "Windows DN...",
                "cve_code": "CVE-2021-26877",
                "cvss": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16778602,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_none"
                },
                "cwe": {
                    "attacks": [],
                    "capecs": [],
                    "cwe_id": "NVD-CWE-noinfo"
                },
                "epss": 0.04652,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2023-12-29T20:15:53.500+01:00",
                "level": "level_critical",
                "published": "2021-03-11T16:15:15.190+01:00",
                "score": 9.8,
                "score_v2": 7.5,
                "score_v3": 9.8,
                "technologies": [
                    {
                        "product": "windows_server_2008",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "windows_server_2012",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "windows_server_2016",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "windows_server_2019",
                        "vendor": "microsoft"
                    }
                ]
            },
            {
                "content": "Windows DN...",
                "cve_code": "CVE-2021-26893",
                "cvss": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16778602,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_none"
                },
                "cwe": {
                    "attacks": [],
                    "capecs": [],
                    "cwe_id": "NVD-CWE-noinfo"
                },
                "epss": 0.04652,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2023-12-29T20:15:56.410+01:00",
                "level": "level_critical",
                "published": "2021-03-11T16:15:16.130+01:00",
                "score": 9.8,
                "score_v2": 7.5,
                "score_v3": 9.8,
                "technologies": [
                    {
                        "product": "windows_server_2008",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "windows_server_2012",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "windows_server_2016",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "windows_server_2019",
                        "vendor": "microsoft"
                    }
                ]
            },
            {
                "content": "Windows DN...",
                "cve_code": "CVE-2021-26894",
                "cvss": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_complete",
                    "confidentiality_impact": "confidentiality_impact_complete",
                    "id": 16779946,
                    "integrity_impact": "integrity_impact_complete"
                },
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_none"
                },
                "cwe": {
                    "attacks": [],
                    "capecs": [],
                    "cwe_id": "NVD-CWE-noinfo"
                },
                "epss": 0.04652,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2023-12-29T20:15:56.610+01:00",
                "level": "level_critical",
                "published": "2021-03-11T16:15:16.190+01:00",
                "score": 9.8,
                "score_v2": 10,
                "score_v3": 9.8,
                "technologies": [
                    {
                        "product": "windows_server_2012",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "windows_server_2008",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "windows_server_2016",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "windows_server_2019",
                        "vendor": "microsoft"
                    }
                ]
            },
            {
                "content": "Windows DN...",
                "cve_code": "CVE-2021-26895",
                "cvss": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_complete",
                    "confidentiality_impact": "confidentiality_impact_complete",
                    "id": 16779946,
                    "integrity_impact": "integrity_impact_complete"
                },
                "cvss_v3": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "availability_impact": "availability_impact_high",
                    "confidentiality_impact": "confidentiality_impact_high",
                    "integrity_impact": "integrity_impact_high",
                    "privileges_required": "privileges_required_none",
                    "scope": "scope_unchanged",
                    "user_interaction": "user_interaction_none"
                },
                "cwe": {
                    "attacks": [],
                    "capecs": [],
                    "cwe_id": "NVD-CWE-noinfo"
                },
                "epss": 0.04652,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2023-12-29T20:15:56.820+01:00",
                "level": "level_critical",
                "published": "2021-03-11T16:15:16.253+01:00",
                "score": 9.8,
                "score_v2": 10,
                "score_v3": 9.8,
                "technologies": [
                    {
                        "product": "windows_server_2012",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "windows_server_2008",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "windows_server_2016",
                        "vendor": "microsoft"
                    },
                    {
                        "product": "windows_server_2019",
                        "vendor": "microsoft"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberwatch CVEs
>|cve_code|content|published|last_modified|level|score|epss|cvss_v3|
>|---|---|---|---|---|---|---|---|
>| CVE-2021-26411 | Internet Explorer Memory Corruption Vulnerability | 2021-03-11T15:15:13 | 2023-12-29T16:15:59 | level_high | 8.8 | 0.04096 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_required<br/>***scope***: scope_changed<br/>***confidentiality_impact***: confidentiality_impact_low<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_low |
>| CVE-2021-26877 | Windows DNS Server Remote Code Execution Vulnerability | 2021-03-11T15:15:15 | 2023-12-29T19:15:53 | level_critical | 9.8 | 0.04652 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_none<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |
>| CVE-2021-26893 | Windows DNS Server Remote Code Execution Vulnerability | 2021-03-11T15:15:16 | 2023-12-29T19:15:56 | level_critical | 9.8 | 0.04652 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_none<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |
>| CVE-2021-26894 | Windows DNS Server Remote Code Execution Vulnerability | 2021-03-11T15:15:16 | 2023-12-29T19:15:56 | level_critical | 9.8 | 0.04652 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_none<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |
>| CVE-2021-26895 | Windows DNS Server Remote Code Execution Vulnerability | 2021-03-11T15:15:16 | 2023-12-29T19:15:56 | level_critical | 9.8 | 0.04652 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_none<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high |


#### Command example
```!cyberwatch-list-cves exploit_code_maturity[]=high,functional technology_vendor=openbsd technology_product=openssh page=1 per_page=5```
#### Context Example
```json
{
    "Cyberwatch": {
        "CVE": [
            {
                "content": "The auth_p...",
                "cve_code": "CVE-2012-0814",
                "cvss": {
                    "access_complexity": "access_complexity_medium",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_single",
                    "availability_impact": "availability_impact_none",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16777302,
                    "integrity_impact": "integrity_impact_none"
                },
                "cwe": {
                    "attacks": [],
                    "capecs": [],
                    "cwe_id": "CWE-255"
                },
                "epss": 0.00285,
                "exploit_code_maturity": "functional",
                "exploitable": true,
                "last_modified": "2023-11-07T02:10:02.853+01:00",
                "level": "level_low",
                "published": "2012-01-27T19:55:01.063+01:00",
                "score": 3.5,
                "score_v2": 3.5,
                "technologies": [
                    {
                        "product": "openssh",
                        "vendor": "openbsd"
                    }
                ]
            },
            {
                "content": "The ssh_gs...",
                "cve_code": "CVE-2011-5000",
                "cvss": {
                    "access_complexity": "access_complexity_medium",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_single",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_none",
                    "id": 16778262,
                    "integrity_impact": "integrity_impact_none"
                },
                "cwe": {
                    "attacks": [],
                    "capecs": [],
                    "cwe_id": "CWE-189"
                },
                "epss": 0.00353,
                "exploit_code_maturity": "functional",
                "exploitable": true,
                "last_modified": "2012-07-22T03:33:00.197+02:00",
                "level": "level_low",
                "published": "2012-04-05T14:55:03.590+02:00",
                "score": 3.5,
                "score_v2": 3.5,
                "technologies": [
                    {
                        "product": "openssh",
                        "vendor": "openbsd"
                    }
                ]
            },
            {
                "content": "The (1) re...",
                "cve_code": "CVE-2010-4755",
                "cvss": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_single",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_none",
                    "id": 16778266,
                    "integrity_impact": "integrity_impact_none"
                },
                "cwe": {
                    "attacks": [],
                    "capecs": [],
                    "cwe_id": "CWE-399"
                },
                "epss": 0.01098,
                "exploit_code_maturity": "functional",
                "exploitable": true,
                "last_modified": "2014-08-08T21:01:22.163+02:00",
                "level": "level_medium",
                "published": "2011-03-02T20:00:00.990+01:00",
                "score": 4,
                "score_v2": 4,
                "technologies": [
                    {
                        "product": "openssh",
                        "vendor": "openbsd"
                    }
                ]
            },
            {
                "content": "OpenSSH be...",
                "cve_code": "CVE-2008-3259",
                "cvss": {
                    "access_complexity": "access_complexity_high",
                    "access_vector": "access_vector_local",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_none",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16777312,
                    "integrity_impact": "integrity_impact_none"
                },
                "cwe": {
                    "attacks": [
                        "T1007",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-116",
                        "..."
                    ],
                    "cwe_id": "CWE-200"
                },
                "epss": 0.00042,
                "exploit_code_maturity": "functional",
                "exploitable": true,
                "last_modified": "2017-08-08T01:31:43.293+02:00",
                "level": "level_low",
                "published": "2008-07-22T16:41:00.000+02:00",
                "score": 1.2,
                "score_v2": 1.2,
                "technologies": [
                    {
                        "product": "openssh",
                        "vendor": "openbsd"
                    }
                ]
            },
            {
                "content": "OpenSSH 4....",
                "cve_code": "CVE-2007-2243",
                "cvss": {
                    "access_complexity": "access_complexity_low",
                    "access_vector": "access_vector_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_none",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16777322,
                    "integrity_impact": "integrity_impact_none"
                },
                "cwe": {
                    "attacks": [
                        "T1014",
                        "..."
                    ],
                    "capecs": [
                        "CAPEC-114",
                        "..."
                    ],
                    "cwe_id": "CWE-287"
                },
                "epss": 0.00721,
                "exploit_code_maturity": "functional",
                "exploitable": true,
                "last_modified": "2017-07-29T01:31:19.517+02:00",
                "level": "level_medium",
                "published": "2007-04-25T16:19:00.000+02:00",
                "score": 5,
                "score_v2": 5,
                "technologies": [
                    {
                        "product": "openssh",
                        "vendor": "openbsd"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberwatch CVEs
>|cve_code|content|published|last_modified|level|score|epss|cvss_v3|
>|---|---|---|---|---|---|---|---|
>| CVE-2012-0814 | The auth_parse_options function in auth-options... | 2012-01-27T18:55:01 | 2023-11-07T01:10:02 | level_low | 3.5 | 0.00285 |  |
>| CVE-2011-5000 | The ssh_gssapi_parse_ename function in gss-serv.c... | 2012-04-05T12:55:03 | 2012-07-22T01:33:00 | level_low | 3.5 | 0.00353 |  |
>| CVE-2010-4755 | The (1) remote_glob function in sftp-glob.c and the... | 2011-03-02T19:00:00 | 2014-08-08T19:01:22 | level_medium | 4.0 | 0.01098 |  |
>| CVE-2008-3259 | OpenSSH before 5.1 sets the SO_REUSEADDR socket... | 2008-07-22T14:41:00 | 2017-08-07T23:31:43 | level_low | 1.2 | 0.00042 |  |
>| CVE-2007-2243 | OpenSSH 4.6 and earlier, when ChallengeResponseAuthentication is enabled... | 2007-04-25T14:19:00 | 2017-07-28T23:31:19 | level_medium | 5.0 | 0.00721 |  |


#### Command example
```!cyberwatch-list-cves exploit_code_maturity[]=high,functional technology_vendor=openbsd technology_product=openssh page=1 per_page=5```
#### Context Example
```json
{
    "Cyberwatch": {
        "CVE": [
            {
                "content": "The Zombie Diary...",
                "cve_code": "CVE-2014-7552",
                "cvss": {
                    "access_complexity": "access_complexity_medium",
                    "access_vector": "access_vector_adjacent_network",
                    "authentication": "authentication_none",
                    "availability_impact": "availability_impact_partial",
                    "confidentiality_impact": "confidentiality_impact_partial",
                    "id": 16778597,
                    "integrity_impact": "integrity_impact_partial"
                },
                "cwe": {
                    "attacks": [],
                    "capecs": [],
                    "cwe_id": "CWE-310"
                },
                "epss": 0.00049,
                "exploit_code_maturity": "unproven",
                "exploitable": false,
                "last_modified": "2014-11-14T13:13:46.943Z",
                "level": "level_medium",
                "published": "2014-10-20T08:55:10.450Z",
                "score": 5.4,
                "score_v2": 5.4,
                "technologies": [
                    {
                        "product": "zombie_diary",
                        "vendor": "129zou"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberwatch CVEs
>|cve_code|content|published|last_modified|level|score|epss|cvss_v3|
>|---|---|---|---|---|---|---|---|
>| CVE-2014-7552 | The Zombie Diary... | 2014-10-20T08:55:10 | 2014-11-14T13:13:46 | level_medium | 5.4 | 0.00049 |  |


### cyberwatch-fetch-cve

***
Get all details for a CVE from Cyberwatch.

#### Base Command

`cyberwatch-fetch-cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_code | The CVE number to fetch. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberwatch.CVE.cve_code | string | CVE reference | 
| Cyberwatch.CVE.score | number | CVE score | 
| Cyberwatch.CVE.exploitable | boolean | CVE exploitability | 
| Cyberwatch.CVE.epss | number | CVE EPSS | 
| Cyberwatch.CVE.published | date | CVE publication date | 
| Cyberwatch.CVE.last_modified | date | CVE last modification date | 

#### Command example
```!cyberwatch-fetch-cve cve_code=CVE-2024-21413```
#### Context Example
```json
{
    "Cyberwatch": {
        "CVE": {
            "content": "Microsoft ...",
            "cve_code": "CVE-2024-21413",
            "cvss_v3": {
                "access_complexity": "access_complexity_low",
                "access_vector": "access_vector_network",
                "availability_impact": "availability_impact_high",
                "confidentiality_impact": "confidentiality_impact_high",
                "integrity_impact": "integrity_impact_high",
                "privileges_required": "privileges_required_none",
                "scope": "scope_unchanged",
                "user_interaction": "user_interaction_none"
            },
            "cwe": {
                "attacks": [],
                "capecs": [],
                "cwe_id": "NVD-CWE-noinfo"
            },
            "epss": 0.00586,
            "exploit_code_maturity": "proof_of_concept",
            "exploitable": true,
            "last_modified": "2024-05-29T00:15:34.720+02:00",
            "level": "level_critical",
            "published": "2024-02-13T18:16:00.137+01:00",
            "references": [
                {
                    "code": "CERT-EU-2024-019",
                    "source": "CERT_EU",
                    "url": "https://cert.europa.eu/publications/security-advisories/2024-019/"
                },
                {
                    "code": "CERTFR-2024-AVI-0127",
                    "source": "Anssi",
                    "url": "https://www.cert.ssi.gouv.fr/avis/CERTFR-2024-AVI-0127/"
                },
                {
                    "code": "CERTFR-2024-ALE-005",
                    "source": "Anssi",
                    "url": "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-005/"
                },
                {
                    "code": "CERTFR-2024-ACT-009",
                    "source": "Anssi",
                    "url": "https://www.cert.ssi.gouv.fr/actualite/CERTFR-2024-ACT-009/"
                },
                {
                    "code": "CERT-IST/AV-2024.0280",
                    "source": "Thales",
                    "url": "https://wws.cert-ist.com/private/en/advisory_detail?ref=CERT-IST/AV-2024.0280"
                },
                {
                    "code": "CERTFR-2024-ACT-010",
                    "source": "Anssi",
                    "url": "https://www.cert.ssi.gouv.fr/actualite/CERTFR-2024-ACT-010/"
                },
                {
                    "code": "#1424-CERT-EDF-2024",
                    "source": "EDF",
                    "url": "https://g3.cert.edf.fr/2024/251cf943-7862-40bf-87ab-57b106718fd5"
                }
            ],
            "score": 9.8,
            "score_v3": 9.8,
            "security_announcements": [
                {
                    "level": "level_unknown",
                    "link": "https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-21413",
                    "sa_code": "CVE-2024-21413",
                    "type": "SecurityAnnouncements::MicrosoftCve"
                },
                {
                    "level": "level_unknown",
                    "link": "https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates",
                    "sa_code": "sa-office-february-13-2024",
                    "type": "SecurityAnnouncements::MicrosoftOffice"
                }
            ],
            "servers": [
                {
                    "active": true,
                    "detected_at": "2024-02-14T00:08:32.113+01:00",
                    "environmental_score": 9.3,
                    "fixed_at": null,
                    "hostname": "WIN-4DBFESNOHB",
                    "id": 1257,
                    "ignored": false,
                    "os": {
                        "arch": "AMD64",
                        "eol": "2029-01-09",
                        "key": "windows_2019",
                        "name": "Windows Server 2019",
                        "short_name": "Windows 2019",
                        "type": "Os::Windows"
                    },
                    "prioritized": true,
                    "updates": [
                        {
                            "current": {
                                "product": "Microsoft Office 365 ProPlus - en-us",
                                "type": "Packages::WinApp",
                                "vendor": null,
                                "version": "11328.20512"
                            },
                            "id": 442869,
                            "ignored": false,
                            "patchable": false,
                            "target": {
                                "product": "Microsoft Office 365 ProPlus - en-us",
                                "type": "Packages::WinApp",
                                "vendor": null,
                                "version": "16130.21026"
                            }
                        }
                    ]
                },
                {
                    "active": true,
                    "detected_at": "2024-02-14T00:56:15.742+01:00",
                    "environmental_score": 9.3,
                    "fixed_at": null,
                    "hostname": "Windows_airgap",
                    "id": 1212,
                    "ignored": false,
                    "os": {
                        "arch": "AMD64",
                        "eol": "2029-01-09",
                        "key": "windows_2019",
                        "name": "Windows Server 2019",
                        "short_name": "Windows 2019",
                        "type": "Os::Windows"
                    },
                    "prioritized": true,
                    "updates": [
                        {
                            "current": {
                                "product": "Microsoft Office 365 ProPlus - en-us",
                                "type": "Packages::WinApp",
                                "vendor": null,
                                "version": "11328.20512"
                            },
                            "id": 442870,
                            "ignored": false,
                            "patchable": false,
                            "target": {
                                "product": "Microsoft Office 365 ProPlus - en-us",
                                "type": "Packages::WinApp",
                                "vendor": null,
                                "version": "16130.21026"
                            }
                        }
                    ]
                }
            ],
            "technologies": [
                {
                    "product": "365_apps",
                    "vendor": "microsoft"
                },
                {
                    "product": "office",
                    "vendor": "microsoft"
                },
                {
                    "product": "office_long_term_servicing_channel",
                    "vendor": "microsoft"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Cyberwatch CVE
>|cve_code|content|published|last_modified|level|score|epss|cvss_v3|servers_count|security_announcements_count|
>|---|---|---|---|---|---|---|---|---|---|
>| CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability | 2024-02-13T17:16:00 | 2024-05-28T22:15:34 | level_critical | 9.8 | 0.00586 | ***access_vector***: access_vector_network<br/>***access_complexity***: access_complexity_low<br/>***privileges_required***: privileges_required_none<br/>***user_interaction***: user_interaction_none<br/>***scope***: scope_unchanged<br/>***confidentiality_impact***: confidentiality_impact_high<br/>***integrity_impact***: integrity_impact_high<br/>***availability_impact***: availability_impact_high | 2 | 2 |


### cyberwatch-list-assets

***
Get a list of assets scanned by Cyberwatch.

#### Base Command

`cyberwatch-list-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment_id | Filter assets by environment (criticality) ID. | Optional | 
| reboot_required | Filter assets that require a reboot (true or false). Possible values are: true, false. | Optional | 
| os | Filter assets by OS (must use keys as mentioned on &lt;URL_SCANNER&gt;/cbw_assets/os). | Optional | 
| group_id | Filter assets by group ID. | Optional | 
| hostname | Filter assets by hostname. | Optional | 
| address | Filter assets by IP address. | Optional | 
| category | Filter assets by category. Available values : no_category, server, desktop, hypervisor, network_device, network_target_or_website, docker_image, industrial_device, cloud, mobile. Possible values are: no_category, server, desktop, hypervisor, network_device, network_target_or_website, docker_image, industrial_device, cloud, mobile. | Optional | 
| communication_failed | Filter assets with communication failed (true or false). Possible values are: true, false. | Optional | 
| page | Get a specific asset page. If not specified, get all assets. | Optional | 
| per_page | Specify the number of assets per page. Default value 500. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberwatch.Asset.id | number | Asset ID | 
| Cyberwatch.Asset.hostname | string | Asset hostname | 
| Cyberwatch.Asset.description | string | Asset description | 
| Cyberwatch.Asset.created_at | date | Asset creation date | 
| Cyberwatch.Asset.last_communication | date | Asset last communication date | 
| Cyberwatch.Asset.analyzed_at | date | Asset last analysis date | 
| Cyberwatch.Asset.cve_announcements_count | number | Number of active CVEs on the asset | 
| Cyberwatch.Asset.updates_count | number | Number of recommended security updates on the asset | 
| Cyberwatch.Asset.prioritized_cve_announcements_count | number | Number of prioritized CVEs on the asset | 
| Cyberwatch.Asset.reboot_required | boolean | Asset reboot requirement | 

#### Command example
```!cyberwatch-list-assets page=1 per_page=5```
#### Context Example
```json
{
    "Cyberwatch": {
        "Asset": [
            {
                "analyzed_at": "2020-11-10T16:36:29.000+01:00",
                "category": "server",
                "created_at": "2017-01-24T09:33:08.000+01:00",
                "cve_announcements_count": 0,
                "description": "Lorem ipsu...",
                "environment": {
                    "availability_requirement": "availability_requirement_high",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_high",
                    "id": 34,
                    "integrity_requirement": "integrity_requirement_high",
                    "name": "High"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 617,
                        "name": "ENV_PRODUCTION"
                    },
                    {
                        "color": "#342e37",
                        "description": "",
                        "id": 774,
                        "name": "Sentinelo"
                    }
                ],
                "hostname": "ip-192-168-0-214",
                "id": 912,
                "last_communication": "2020-11-10T16:36:29.000+01:00",
                "os": {
                    "arch": "x86_64",
                    "eol": "2019-04-01",
                    "key": "ubuntu_1404_64",
                    "name": "Ubuntu 14.04 LTS",
                    "short_name": "Ubuntu 14.04",
                    "type": "Os::Ubuntu"
                },
                "prioritized_cve_announcements_count": 0,
                "status": "server_vulnerable",
                "updates_count": 0
            },
            {
                "addresses": [
                    "EC2AMAZ-C9SIS5H",
                    "127.0.0.1"
                ],
                "analyzed_at": "2019-01-19T08:28:13.000+01:00",
                "category": "server",
                "created_at": "2019-01-18T22:33:12.000+01:00",
                "cve_announcements_count": 2858,
                "environment": {
                    "availability_requirement": "availability_requirement_low",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_low",
                    "id": 32,
                    "integrity_requirement": "integrity_requirement_low",
                    "name": "Low"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 788,
                        "name": "Cloud"
                    },
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 793,
                        "name": "ZONE_EU_FR"
                    }
                ],
                "hostname": "EC2AMAZ-C9SIS5H",
                "id": 1183,
                "last_communication": "2019-01-19T08:28:13.000+01:00",
                "os": {
                    "arch": "AMD64",
                    "eol": "2026-07-14",
                    "key": "windows_2016",
                    "name": "Windows Server 2016",
                    "short_name": "Windows 2016",
                    "type": "Os::Windows"
                },
                "prioritized_cve_announcements_count": 110,
                "reboot_required": false,
                "status": "server_vulnerable",
                "updates_count": 3
            },
            {
                "addresses": [
                    "ip-192-168-0-56",
                    "127.0.0.1"
                ],
                "analyzed_at": "2019-01-18T22:41:46.000+01:00",
                "category": "server",
                "created_at": "2019-01-18T22:41:44.000+01:00",
                "cve_announcements_count": 1210,
                "environment": {
                    "availability_requirement": "availability_requirement_low",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_low",
                    "id": 32,
                    "integrity_requirement": "integrity_requirement_low",
                    "name": "Low"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 788,
                        "name": "Cloud"
                    },
                    {
                        "color": "#ffd166",
                        "description": "Machines L...",
                        "id": 856,
                        "name": "LINUX "
                    }
                ],
                "hostname": "ip-192-168-0-56",
                "id": 1186,
                "last_communication": "2019-02-11T10:14:01.000+01:00",
                "os": {
                    "arch": "x86_64",
                    "eol": "2023-04-26",
                    "key": "ubuntu_1804_64",
                    "name": "Ubuntu 18.04 LTS",
                    "short_name": "Ubuntu 18.04",
                    "type": "Os::Ubuntu"
                },
                "prioritized_cve_announcements_count": 9,
                "reboot_required": false,
                "status": "server_vulnerable",
                "updates_count": 225
            },
            {
                "addresses": [
                    "ip-192-168-0-39",
                    "127.0.0.1"
                ],
                "analyzed_at": "2019-01-19T08:15:26.000+01:00",
                "category": "server",
                "created_at": "2019-01-19T08:15:24.000+01:00",
                "cve_announcements_count": 1167,
                "environment": {
                    "availability_requirement": "availability_requirement_low",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_low",
                    "id": 32,
                    "integrity_requirement": "integrity_requirement_low",
                    "name": "Low"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 617,
                        "name": "ENV_PRODUCTION"
                    },
                    {
                        "color": "#ffd166",
                        "description": "Machines L...",
                        "id": 856,
                        "name": "LINUX "
                    }
                ],
                "hostname": "ip-192-168-0-39",
                "id": 1187,
                "last_communication": "2019-02-11T10:15:01.000+01:00",
                "os": {
                    "arch": "x86_64",
                    "eol": "2023-04-26",
                    "key": "ubuntu_1804_64",
                    "name": "Ubuntu 18.04 LTS",
                    "short_name": "Ubuntu 18.04",
                    "type": "Os::Ubuntu"
                },
                "prioritized_cve_announcements_count": 9,
                "reboot_required": true,
                "status": "server_vulnerable",
                "updates_count": 217
            },
            {
                "addresses": [
                    "MacBook-Pro.local",
                    "127.0.0.1"
                ],
                "analyzed_at": "2024-07-03T07:53:40.430+02:00",
                "category": "desktop",
                "created_at": "2019-01-19T08:18:12.000+01:00",
                "cve_announcements_count": 3966,
                "environment": {
                    "availability_requirement": "availability_requirement_low",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_low",
                    "id": 32,
                    "integrity_requirement": "integrity_requirement_low",
                    "name": "Low"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 609,
                        "name": "Direction_Comm"
                    }
                ],
                "hostname": "MacBook-Pro.local",
                "id": 1188,
                "last_communication": "2019-05-16T16:29:20.000+02:00",
                "os": {
                    "arch": null,
                    "eol": "2022-09-12",
                    "key": "macosx",
                    "name": "Mac OS X",
                    "short_name": "macOS X",
                    "type": "Os::Macos"
                },
                "prioritized_cve_announcements_count": 86,
                "reboot_required": false,
                "status": "server_vulnerable",
                "updates_count": 19
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberwatch Assets
>|id|hostname|reboot_required|category|last_communication|os|environment|groups|cve_announcements_count|prioritized_cve_announcements_count|updates_count|compliance_repositories|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 912 | ip-192-168-0-214 | None | server | 2020-11-10T15:36:29 | Ubuntu 14.04 LTS | High | ***values***: ENV_PRODUCTION, Sentinelo, auditeur, APP_Apache, LINUX  | 0 | 0 | 0 | ***values***:  |
>| 1183 | EC2AMAZ-C9SIS5H | False | server | 2019-01-19T07:28:13 | Windows Server 2016 | Low | ***values***: Cloud, ZONE_EU_FR | 2858 | 110 | 3 | ***values***:  |
>| 1186 | ip-192-168-0-56 | False | server | 2019-02-11T09:14:01 | Ubuntu 18.04 LTS | Low | ***values***: Cloud, LINUX  | 1210 | 9 | 225 | ***values***:  |
>| 1187 | ip-192-168-0-39 | True | server | 2019-02-11T09:15:01 | Ubuntu 18.04 LTS | Low | ***values***: ENV_PRODUCTION, LINUX  | 1167 | 9 | 217 | ***values***:  |
>| 1188 | MacBook-Pro.local | False | desktop | 2019-05-16T14:29:20 | Mac OS X | Low | ***values***: Direction_Comm | 3966 | 86 | 19 | ***values***:  |


#### Command example
```!cyberwatch-list-assets environment_id=27 page=1 per_page=5```
#### Context Example
```json
{
    "Cyberwatch": {
        "Asset": [
            {
                "addresses": [
                    "Siemens Rapidlab 1200"
                ],
                "analyzed_at": "2022-10-19T11:50:02.796+02:00",
                "category": "industrial_device",
                "created_at": "2022-10-19T11:43:12.736+02:00",
                "cve_announcements_count": 2,
                "environment": {
                    "availability_requirement": "availability_requirement_high",
                    "ceiling_cvss_v3": {
                        "access_complexity": "access_complexity_low",
                        "access_vector": "access_vector_physical",
                        "availability_impact": "availability_impact_high",
                        "confidentiality_impact": "confidentiality_impact_high",
                        "integrity_impact": "integrity_impact_high",
                        "privileges_required": "privileges_required_none",
                        "scope": "scope_changed",
                        "user_interaction": "user_interaction_none"
                    },
                    "confidentiality_requirement": "confidentiality_requirement_high",
                    "id": 27,
                    "integrity_requirement": "integrity_requirement_high",
                    "name": "Actif isolé critique"
                },
                "groups": [
                    {
                        "color": "#ffd166",
                        "description": "",
                        "id": 860,
                        "name": "Sante"
                    }
                ],
                "hostname": "Siemens Rapidlab 1200",
                "id": 1548,
                "last_communication": "2022-10-19T11:50:02.796+02:00",
                "os": {
                    "arch": null,
                    "eol": null,
                    "key": "siemens",
                    "name": "Siemens",
                    "short_name": "Siemens",
                    "type": "Os::IndustrialDevice"
                },
                "prioritized_cve_announcements_count": 0,
                "status": "server_vulnerable",
                "updates_count": 1
            },
            {
                "addresses": [
                    "127.0.0.1",
                    "WIN-09PACDLD"
                ],
                "analyzed_at": "2022-12-08T15:26:31.467+01:00",
                "boot_at": "2022-12-08T10:35:06.000+01:00",
                "category": "desktop",
                "created_at": "2022-12-08T10:47:57.464+01:00",
                "cve_announcements_count": 1038,
                "environment": {
                    "availability_requirement": "availability_requirement_high",
                    "ceiling_cvss_v3": {
                        "access_complexity": "access_complexity_low",
                        "access_vector": "access_vector_physical",
                        "availability_impact": "availability_impact_high",
                        "confidentiality_impact": "confidentiality_impact_high",
                        "integrity_impact": "integrity_impact_high",
                        "privileges_required": "privileges_required_none",
                        "scope": "scope_changed",
                        "user_interaction": "user_interaction_none"
                    },
                    "confidentiality_requirement": "confidentiality_requirement_high",
                    "id": 27,
                    "integrity_requirement": "integrity_requirement_high",
                    "name": "Actif isolé critique"
                },
                "hostname": "WIN-09PACDLD",
                "id": 1577,
                "last_communication": "2022-12-08T15:26:31.467+01:00",
                "os": {
                    "arch": "AMD64",
                    "eol": "2021-05-11",
                    "key": "windows_10_1809_64",
                    "name": "Windows 10 1809",
                    "short_name": "Windows 10 1809",
                    "type": "Os::Windows"
                },
                "prioritized_cve_announcements_count": 44,
                "reboot_required": false,
                "status": "server_vulnerable",
                "updates_count": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberwatch Assets
>|id|hostname|reboot_required|category|last_communication|os|environment|groups|cve_announcements_count|prioritized_cve_announcements_count|updates_count|compliance_repositories|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1548 | Siemens Rapidlab 1200 | None | industrial_device | 2022-10-19T09:50:02 | Siemens | Actif isolé critique | ***values***: Sante | 2 | 0 | 1 | ***values***:  |
>| 1577 | WIN-09PACDLD | False | desktop | 2022-12-08T14:26:31 | Windows 10 1809 | Actif isolé critique | ***values***:  | 1038 | 44 | 2 | ***values***:  |


#### Command example
```!cyberwatch-list-assets reboot_required=true communication_failed=false page=1 per_page=5```
#### Context Example
```json
{
    "Cyberwatch": {
        "Asset": [
            {
                "addresses": [
                    "ip-192-168-0-39",
                    "127.0.0.1"
                ],
                "analyzed_at": "2019-01-19T08:15:26.000+01:00",
                "category": "server",
                "created_at": "2019-01-19T08:15:24.000+01:00",
                "cve_announcements_count": 1167,
                "environment": {
                    "availability_requirement": "availability_requirement_low",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_low",
                    "id": 32,
                    "integrity_requirement": "integrity_requirement_low",
                    "name": "Low"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 617,
                        "name": "ENV_PRODUCTION"
                    },
                    {
                        "color": "#ffd166",
                        "description": "Machines L...",
                        "id": 856,
                        "name": "LINUX "
                    }
                ],
                "hostname": "ip-192-168-0-39",
                "id": 1187,
                "last_communication": "2019-02-11T10:15:01.000+01:00",
                "os": {
                    "arch": "x86_64",
                    "eol": "2023-04-26",
                    "key": "ubuntu_1804_64",
                    "name": "Ubuntu 18.04 LTS",
                    "short_name": "Ubuntu 18.04",
                    "type": "Os::Ubuntu"
                },
                "prioritized_cve_announcements_count": 9,
                "reboot_required": true,
                "status": "server_vulnerable",
                "updates_count": 217
            },
            {
                "addresses": [
                    "fic2019",
                    "127.0.0.1"
                ],
                "analyzed_at": "2019-01-22T15:22:02.000+01:00",
                "category": "server",
                "created_at": "2019-01-22T15:22:00.000+01:00",
                "cve_announcements_count": 1203,
                "environment": {
                    "availability_requirement": "availability_requirement_low",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_low",
                    "id": 32,
                    "integrity_requirement": "integrity_requirement_low",
                    "name": "Low"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 788,
                        "name": "Cloud"
                    },
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 794,
                        "name": "ZONE_EU_ES"
                    },
                    {
                        "color": "#ffd166",
                        "description": "Machines L...",
                        "id": 856,
                        "name": "LINUX "
                    }
                ],
                "hostname": "fic2019",
                "id": 1189,
                "last_communication": "2019-02-11T10:14:01.000+01:00",
                "os": {
                    "arch": "x86_64",
                    "eol": "2023-04-26",
                    "key": "ubuntu_1804_64",
                    "name": "Ubuntu 18.04 LTS",
                    "short_name": "Ubuntu 18.04",
                    "type": "Os::Ubuntu"
                },
                "prioritized_cve_announcements_count": 9,
                "reboot_required": true,
                "status": "server_vulnerable",
                "updates_count": 221
            },
            {
                "addresses": [
                    "127.0.0.1",
                    "melchior"
                ],
                "analyzed_at": "2023-07-25T15:19:15.778+02:00",
                "boot_at": "2021-04-11T06:23:22.000+02:00",
                "category": "server",
                "created_at": "2020-06-05T12:05:35.000+02:00",
                "cve_announcements_count": 1060,
                "description": "test",
                "environment": {
                    "availability_requirement": "availability_requirement_medium",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_medium",
                    "id": 33,
                    "integrity_requirement": "integrity_requirement_medium",
                    "name": "Medium"
                },
                "hostname": "melchior",
                "id": 1208,
                "last_communication": "2021-04-12T09:48:36.000+02:00",
                "os": {
                    "arch": null,
                    "eol": "2023-10-10",
                    "key": "windows_2012_r2",
                    "name": "Windows Server 2012 R2",
                    "short_name": "Windows 2012 R2",
                    "type": "Os::Windows"
                },
                "prioritized_cve_announcements_count": 230,
                "reboot_required": true,
                "status": "server_vulnerable",
                "updates_count": 5
            },
            {
                "addresses": [
                    "127.0.0.1",
                    "192.168.0.128",
                    "ip-192-168-0-128"
                ],
                "analyzed_at": "2024-07-02T02:46:02.160+02:00",
                "boot_at": "2021-06-23T18:35:20.000+02:00",
                "category": "server",
                "created_at": "2022-03-25T14:56:54.000+01:00",
                "cve_announcements_count": 1167,
                "environment": {
                    "availability_requirement": "availability_requirement_medium",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_medium",
                    "id": 33,
                    "integrity_requirement": "integrity_requirement_medium",
                    "name": "Medium"
                },
                "groups": [
                    {
                        "color": "#ffd166",
                        "description": "Machines L...",
                        "id": 856,
                        "name": "LINUX "
                    }
                ],
                "hostname": "ip-192-168-0-128",
                "id": 1393,
                "last_communication": "2024-07-03T09:53:49.369+02:00",
                "os": {
                    "arch": "x86_64",
                    "eol": "2025-04-01",
                    "key": "ubuntu_2004_64",
                    "name": "Ubuntu 20.04 LTS",
                    "short_name": "Ubuntu 20.04",
                    "type": "Os::Ubuntu"
                },
                "prioritized_cve_announcements_count": 88,
                "reboot_required": true,
                "status": "server_vulnerable",
                "updates_count": 207
            },
            {
                "addresses": [
                    "192.168.0.102",
                    "127.0.0.1",
                    "EC2AMAZ-SNIAI0J"
                ],
                "analyzed_at": "2022-10-31T10:35:44.641+01:00",
                "boot_at": "2022-10-31T10:30:30.000+01:00",
                "category": "server",
                "created_at": "2022-10-31T09:27:14.035+01:00",
                "cve_announcements_count": 1355,
                "environment": {
                    "availability_requirement": "availability_requirement_medium",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_medium",
                    "id": 33,
                    "integrity_requirement": "integrity_requirement_medium",
                    "name": "Medium"
                },
                "hostname": "EC2AMAZ-SNIAI0J",
                "id": 1555,
                "last_communication": "2022-11-04T10:05:52.964+01:00",
                "os": {
                    "arch": "AMD64",
                    "eol": "2031-10-14",
                    "key": "windows_2022",
                    "name": "Windows Server 2022",
                    "short_name": "Windows 2022",
                    "type": "Os::Windows"
                },
                "prioritized_cve_announcements_count": 256,
                "reboot_required": true,
                "status": "server_vulnerable",
                "updates_count": 3
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberwatch Assets
>|id|hostname|reboot_required|category|last_communication|os|environment|groups|cve_announcements_count|prioritized_cve_announcements_count|updates_count|compliance_repositories|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1187 | ip-192-168-0-39 | True | server | 2019-02-11T09:15:01 | Ubuntu 18.04 LTS | Low | ***values***: ENV_PRODUCTION, LINUX  | 1167 | 9 | 217 | ***values***:  |
>| 1189 | fic2019 | True | server | 2019-02-11T09:14:01 | Ubuntu 18.04 LTS | Low | ***values***: Cloud, ZONE_EU_ES, LINUX  | 1203 | 9 | 221 | ***values***:  |
>| 1208 | melchior | True | server | 2021-04-12T07:48:36 | Windows Server 2012 R2 | Medium | ***values***:  | 1060 | 230 | 5 | ***values***:  |
>| 1393 | ip-192-168-0-128 | True | server | 2024-07-03T07:53:49 | Ubuntu 20.04 LTS | Medium | ***values***: LINUX  | 1167 | 88 | 207 | ***values***:  |
>| 1555 | EC2AMAZ-SNIAI0J | True | server | 2022-11-04T09:05:52 | Windows Server 2022 | Medium | ***values***:  | 1355 | 256 | 3 | ***values***:  |


#### Command example
```!cyberwatch-list-assets hostname=WIN-GNVEC8UIKUD page=1 per_page=5```
#### Context Example
```json
{
    "Cyberwatch": {
        "Asset": [
            {
                "addresses": [
                    "WIN-GNVEC8UIKUD",
                    "127.0.0.1"
                ],
                "analyzed_at": "2022-06-08T09:57:47.440+02:00",
                "category": "server",
                "created_at": "2019-09-10T16:59:23.000+02:00",
                "cve_announcements_count": 1699,
                "description": "Machine Wi...",
                "environment": {
                    "availability_requirement": "availability_requirement_high",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_high",
                    "id": 34,
                    "integrity_requirement": "integrity_requirement_high",
                    "name": "High"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 807,
                        "name": "APP_Apache"
                    },
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 808,
                        "name": "APP_BaseDeDonnees"
                    },
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 768,
                        "name": "AmazonWebServices"
                    }
                ],
                "hostname": "WIN-GNVEC8UIKUD",
                "id": 1197,
                "last_communication": "2019-09-13T11:14:34.000+02:00",
                "os": {
                    "arch": null,
                    "eol": "2023-10-10",
                    "key": "windows_2012_r2",
                    "name": "Windows Server 2012 R2",
                    "short_name": "Windows 2012 R2",
                    "type": "Os::Windows"
                },
                "prioritized_cve_announcements_count": 645,
                "reboot_required": false,
                "status": "server_vulnerable",
                "updates_count": 9
            },
            {
                "addresses": [
                    "WIN-GNVEC8UIKUD",
                    "127.0.0.1"
                ],
                "analyzed_at": "2023-03-17T16:02:20.511+01:00",
                "category": "server",
                "created_at": "2019-09-18T15:27:09.000+02:00",
                "cve_announcements_count": 1699,
                "environment": {
                    "availability_requirement": "availability_requirement_high",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_high",
                    "id": 34,
                    "integrity_requirement": "integrity_requirement_high",
                    "name": "High"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 808,
                        "name": "APP_BaseDeDonnees"
                    }
                ],
                "hostname": "WIN-GNVEC8UIKUD",
                "id": 1198,
                "last_communication": "2019-09-21T14:57:20.000+02:00",
                "os": {
                    "arch": null,
                    "eol": "2023-10-10",
                    "key": "windows_2012_r2",
                    "name": "Windows Server 2012 R2",
                    "short_name": "Windows 2012 R2",
                    "type": "Os::Windows"
                },
                "prioritized_cve_announcements_count": 644,
                "reboot_required": false,
                "status": "server_awaiting_analysis",
                "updates_count": 9
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberwatch Assets
>|id|hostname|reboot_required|category|last_communication|os|environment|groups|cve_announcements_count|prioritized_cve_announcements_count|updates_count|compliance_repositories|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1197 | WIN-GNVEC8UIKUD | False | server | 2019-09-13T09:14:34 | Windows Server 2012 R2 | High | ***values***: APP_Apache, APP_BaseDeDonnees, AmazonWebServices | 1699 | 645 | 9 | ***values***:  |
>| 1198 | WIN-GNVEC8UIKUD | False | server | 2019-09-21T12:57:20 | Windows Server 2012 R2 | High | ***values***: APP_BaseDeDonnees | 1699 | 644 | 9 | ***values***:  |


#### Command example
```!cyberwatch-list-assets address=127.0.0.1 page=1 per_page=5```
#### Context Example
```json
{
    "Cyberwatch": {
        "Asset": [
            {
                "addresses": [
                    "127.0.0.1"
                ],
                "analyzed_at": "2024-07-03T07:53:40.430+02:00",
                "category": "desktop",
                "created_at": "2019-01-19T08:18:12.000+01:00",
                "cve_announcements_count": 3966,
                "environment": {
                    "availability_requirement": "availability_requirement_low",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_low",
                    "id": 32,
                    "integrity_requirement": "integrity_requirement_low",
                    "name": "Low"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 609,
                        "name": "Direction_Comm"
                    }
                ],
                "hostname": "MacBook-Pro.local",
                "id": 1188,
                "last_communication": "2019-05-16T16:29:20.000+02:00",
                "os": {
                    "arch": null,
                    "eol": "2022-09-12",
                    "key": "macosx",
                    "name": "Mac OS X",
                    "short_name": "macOS X",
                    "type": "Os::Macos"
                },
                "prioritized_cve_announcements_count": 86,
                "reboot_required": false,
                "status": "server_vulnerable",
                "updates_count": 19
            },
            {
                "addresses": [
                    "127.0.0.1"
                ],
                "analyzed_at": "2021-03-10T16:47:46.000+01:00",
                "boot_at": "2021-03-10T14:45:28.000+01:00",
                "category": "server",
                "compliance_repositories": [
                    {
                        "color": "#336699",
                        "description": null,
                        "id": 20,
                        "name": "Mon_Catalogue"
                    }
                ],
                "created_at": "2021-03-10T16:47:41.000+01:00",
                "cve_announcements_count": 259,
                "environment": {
                    "availability_requirement": "availability_requirement_low",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_low",
                    "id": 32,
                    "integrity_requirement": "integrity_requirement_low",
                    "name": "Low"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 789,
                        "name": "0_Compliance"
                    }
                ],
                "hostname": "WIN-97RELK05NHD",
                "id": 1226,
                "last_communication": "2021-03-11T12:05:45.000+01:00",
                "os": {
                    "arch": null,
                    "eol": "2023-10-10",
                    "key": "windows_2012_r2",
                    "name": "Windows Server 2012 R2",
                    "short_name": "Windows 2012 R2",
                    "type": "Os::Windows"
                },
                "prioritized_cve_announcements_count": 8,
                "reboot_required": false,
                "status": "server_vulnerable",
                "updates_count": 23
            },
            {
                "addresses": [
                    "127.0.0.1"
                ],
                "analyzed_at": "2023-11-21T15:40:16.057+01:00",
                "boot_at": "2021-07-18T08:10:50.000+02:00",
                "category": "server",
                "compliance_repositories": [
                    {
                        "color": "#336699",
                        "description": null,
                        "id": 18,
                        "name": "Security_Best_Practices"
                    }
                ],
                "created_at": "2021-07-02T10:30:34.000+02:00",
                "cve_announcements_count": 1617,
                "environment": {
                    "availability_requirement": "availability_requirement_medium",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_medium",
                    "id": 33,
                    "integrity_requirement": "integrity_requirement_medium",
                    "name": "Medium"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 789,
                        "name": "0_Compliance"
                    }
                ],
                "hostname": "midas",
                "id": 1270,
                "last_communication": "2021-07-19T16:36:09.000+02:00",
                "os": {
                    "arch": "AMD64",
                    "eol": "2029-01-09",
                    "key": "windows_2019",
                    "name": "Windows Server 2019",
                    "short_name": "Windows 2019",
                    "type": "Os::Windows"
                },
                "prioritized_cve_announcements_count": 368,
                "reboot_required": false,
                "status": "server_awaiting_analysis",
                "updates_count": 3
            },
            {
                "addresses": [
                    "127.0.0.1"
                ],
                "analyzed_at": "2023-07-25T15:19:15.778+02:00",
                "boot_at": "2021-04-11T06:23:22.000+02:00",
                "category": "server",
                "created_at": "2020-06-05T12:05:35.000+02:00",
                "cve_announcements_count": 1060,
                "description": "test",
                "environment": {
                    "availability_requirement": "availability_requirement_medium",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_medium",
                    "id": 33,
                    "integrity_requirement": "integrity_requirement_medium",
                    "name": "Medium"
                },
                "hostname": "melchior",
                "id": 1208,
                "last_communication": "2021-04-12T09:48:36.000+02:00",
                "os": {
                    "arch": null,
                    "eol": "2023-10-10",
                    "key": "windows_2012_r2",
                    "name": "Windows Server 2012 R2",
                    "short_name": "Windows 2012 R2",
                    "type": "Os::Windows"
                },
                "prioritized_cve_announcements_count": 230,
                "reboot_required": true,
                "status": "server_vulnerable",
                "updates_count": 5
            },
            {
                "addresses": [
                    "127.0.0.1"
                ],
                "analyzed_at": "2019-01-18T22:41:46.000+01:00",
                "category": "server",
                "created_at": "2019-01-18T22:41:44.000+01:00",
                "cve_announcements_count": 1210,
                "environment": {
                    "availability_requirement": "availability_requirement_low",
                    "ceiling_cvss_v3": null,
                    "confidentiality_requirement": "confidentiality_requirement_low",
                    "id": 32,
                    "integrity_requirement": "integrity_requirement_low",
                    "name": "Low"
                },
                "groups": [
                    {
                        "color": "#12AFCB",
                        "description": null,
                        "id": 788,
                        "name": "Cloud"
                    },
                    {
                        "color": "#ffd166",
                        "description": "Machines L...",
                        "id": 856,
                        "name": "LINUX "
                    }
                ],
                "hostname": "ip-192-168-0-56",
                "id": 1186,
                "last_communication": "2019-02-11T10:14:01.000+01:00",
                "os": {
                    "arch": "x86_64",
                    "eol": "2023-04-26",
                    "key": "ubuntu_1804_64",
                    "name": "Ubuntu 18.04 LTS",
                    "short_name": "Ubuntu 18.04",
                    "type": "Os::Ubuntu"
                },
                "prioritized_cve_announcements_count": 9,
                "reboot_required": false,
                "status": "server_vulnerable",
                "updates_count": 225
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberwatch Assets
>|id|hostname|reboot_required|category|last_communication|os|environment|groups|cve_announcements_count|prioritized_cve_announcements_count|updates_count|compliance_repositories|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1188 | MacBook-Pro.local | False | desktop | 2019-05-16T14:29:20 | Mac OS X | Low | ***values***: Direction_Comm | 3966 | 86 | 19 | ***values***:  |
>| 1226 | WIN-97RELK05NHD | False | server | 2021-03-11T11:05:45 | Windows Server 2012 R2 | Low | ***values***: 0_Compliance | 259 | 8 | 23 | ***values***: Mon_Catalogue |
>| 1270 | midas | False | server | 2021-07-19T14:36:09 | Windows Server 2019 | Medium | ***values***: 0_Compliance | 1617 | 368 | 3 | ***values***: Security_Best_Practices |
>| 1208 | melchior | True | server | 2021-04-12T07:48:36 | Windows Server 2012 R2 | Medium | ***values***:  | 1060 | 230 | 5 | ***values***:  |
>| 1186 | ip-192-168-0-56 | False | server | 2019-02-11T09:14:01 | Ubuntu 18.04 LTS | Low | ***values***: Cloud, LINUX  | 1210 | 9 | 225 | ***values***:  |


#### Command example
```!cyberwatch-list-assets os=windows_2008_r2 category=server group_id=768 page=1 per_page=5```
#### Context Example
```json
{
    "Cyberwatch": {
        "Asset": {
            "addresses": [
                "WIN-IUVBSL1UF49",
                "127.0.0.1"
            ],
            "analyzed_at": "2019-09-18T15:35:31.000Z",
            "category": "server",
            "created_at": "2019-09-18T15:21:30.000Z",
            "cve_announcements_count": 1800,
            "environment": {
                "availability_requirement": "availability_requirement_low",
                "ceiling_cvss_v3": null,
                "confidentiality_requirement": "confidentiality_requirement_low",
                "id": 32,
                "integrity_requirement": "integrity_requirement_low",
                "name": "Low"
            },
            "groups": [
                {
                    "color": "#12AFCB",
                    "description": null,
                    "id": 768,
                    "name": "AmazonWebServices"
                }
            ],
            "hostname": "WIN-IUVBSL1UF49",
            "id": 1200,
            "last_communication": "2019-09-21T12:56:28.000Z",
            "os": {
                "arch": null,
                "eol": "2020-01-14",
                "key": "windows_2008_r2",
                "name": "Windows Server 2008 R2",
                "short_name": "Windows 2008 R2",
                "type": "Os::Windows"
            },
            "prioritized_cve_announcements_count": 66,
            "reboot_required": false,
            "status": "server_vulnerable",
            "updates_count": 12
        }
    }
}
```

#### Human Readable Output

>### Cyberwatch Assets
>|id|hostname|reboot_required|category|last_communication|os|environment|groups|cve_announcements_count|prioritized_cve_announcements_count|updates_count|compliance_repositories|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1200 | WIN-IUVBSL1UF49 | False | server | 2019-09-21T12:56:28 | Windows Server 2008 R2 | Low | ***values***: AmazonWebServices | 1800 | 66 | 12 | ***values***:  |


### cyberwatch-fetch-asset

***
Get security details for an asset scanned by Cyberwatch.

#### Base Command

`cyberwatch-fetch-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID to fetch. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberwatch.Asset.id | number | Asset ID | 
| Cyberwatch.Asset.hostname | string | Asset hostname | 
| Cyberwatch.Asset.description | string | Asset description | 
| Cyberwatch.Asset.created_at | date | Asset creation date | 
| Cyberwatch.Asset.last_communication | date | Asset last communication date | 
| Cyberwatch.Asset.analyzed_at | date | Asset last analysis date | 
| Cyberwatch.Asset.cve_announcements_count | number | Number of active CVEs on the asset | 
| Cyberwatch.Asset.prioritized_cve_announcements_count | number | Number of prioritized CVEs on the asset | 
| Cyberwatch.Asset.reboot_required | boolean | Asset reboot requirement | 

#### Command example
```!cyberwatch-fetch-asset id=1206```
#### Context Example
```json
{
    "Cyberwatch": {
        "Asset": {
            "addresses": [
                "vps418658",
                "127.0.0.1"
            ],
            "analyzed_at": "2020-06-01T19:48:33.000+02:00",
            "boot_at": null,
            "category": "server",
            "compliance_repositories": [
                {
                    "color": "#336699",
                    "description": null,
                    "id": 18,
                    "name": "Security_Best_Practices"
                }
            ],
            "created_at": "2020-06-01T19:48:31.000+02:00",
            "cve_announcements": [
                {
                    "active": true,
                    "cve_code": "CVE-2020-13777",
                    "detected_at": "2020-06-06T21:15:52.000+02:00",
                    "environmental_score": 7.6,
                    "epss": 0.00348,
                    "fixed_at": null,
                    "ignored": false,
                    "prioritized": true,
                    "published": "2020-06-04T07:15:10.000+02:00",
                    "score": 7.4
                },
                {
                    "active": true,
                    "cve_code": "CVE-2020-10756",
                    "detected_at": "2020-07-19T20:45:33.000+02:00",
                    "environmental_score": 8.1,
                    "epss": 0.00069,
                    "fixed_at": null,
                    "ignored": false,
                    "prioritized": true,
                    "published": "2020-07-09T16:15:13.470+02:00",
                    "score": 6.5
                },
                // ...
                {
                    "active": true,
                    "cve_code": "CVE-2024-33599",
                    "detected_at": "2024-06-30T17:32:35.552+02:00",
                    "environmental_score": 6,
                    "epss": null,
                    "fixed_at": null,
                    "ignored": false,
                    "prioritized": false,
                    "published": "2024-05-06T20:15:11.437+02:00",
                    "score": 7.6
                }
            ],
            "cve_announcements_count": 898,
            "description": null,
            "environment": {
                "availability_requirement": "availability_requirement_low",
                "ceiling_cvss_v3": null,
                "confidentiality_requirement": "confidentiality_requirement_high",
                "id": 9,
                "integrity_requirement": "integrity_requirement_low",
                "name": "Privacy"
            },
            "groups": [
                {
                    "color": "#12AFCB",
                    "description": null,
                    "id": 789,
                    "name": "0_Compliance"
                },
                {
                    "color": "#12AFCB",
                    "description": null,
                    "id": 764,
                    "name": "demonstration"
                },
                {
                    "color": "#ffd166",
                    "description": "Machines L...",
                    "id": 856,
                    "name": "LINUX "
                }
            ],
            "hostname": "vps418658",
            "id": 1206,
            "last_communication": "2020-11-03T11:25:01.000+01:00",
            "os": {
                "arch": "x86_64",
                "eol": "2024-06-30",
                "key": "debian_10_64",
                "name": "Debian 10 (Buster)",
                "short_name": "Debian 10",
                "type": "Os::Debian"
            },
            "prioritized_cve_announcements_count": 117,
            "reboot_required": false,
            "security_issues": [
                {
                    "description": "All softwa...",
                    "detected_at": "2024-06-30T02:36:37.488+02:00",
                    "editable": false,
                    "id": 120,
                    "level": "level_critical",
                    "sid": "Obsolete-Os",
                    "status": "active",
                    "title": "Obsolete operating system"
                }
            ],
            "status": "server_vulnerable",
            "updates": [
                {
                    "current": {
                        "product": "libjson-c3",
                        "type": "Packages::Deb",
                        "vendor": null,
                        "version": "0.12.1+ds-2"
                    },
                    "cve_announcements": [
                        "CVE-2020-12762"
                    ],
                    "id": 430218,
                    "ignored": false,
                    "patchable": true,
                    "target": {
                        "product": "libjson-c3",
                        "type": "Packages::Deb",
                        "vendor": null,
                        "version": "0.12.1+ds-2+deb10u1"
                    }
                },
                {
                    "current": {
                        "product": "libfreetype6",
                        "type": "Packages::Deb",
                        "vendor": null,
                        "version": "2.9.1-3+deb10u1"
                    },
                    "cve_announcements": [
                        "CVE-2020-15999"
                    ],
                    "id": 431107,
                    "ignored": false,
                    "patchable": true,
                    "target": {
                        "product": "libfreetype6",
                        "type": "Packages::Deb",
                        "vendor": null,
                        "version": "2.9.1-3+deb10u2"
                    }
                },
                // ...
                {
                    "current": {
                        "product": "libpython3.7-stdlib",
                        "type": "Packages::Deb",
                        "vendor": null,
                        "version": "3.7.3-2+deb10u1"
                    },
                    "cve_announcements": [
                        "CVE-2022-37454",
                        "CVE-2015-20107",
                        "CVE-2020-10735",
                        "CVE-2021-3426",
                        "CVE-2021-3733",
                        "CVE-2021-3737",
                        "CVE-2021-4189",
                        "CVE-2022-45061",
                        "CVE-2022-48560",
                        "CVE-2022-48564",
                        "CVE-2022-48565",
                        "CVE-2022-48566",
                        "CVE-2023-40217",
                        "CVE-2023-6597",
                        "CVE-2024-0450"
                    ],
                    "id": 441709,
                    "ignored": false,
                    "patchable": true,
                    "target": {
                        "product": "libpython3.7-stdlib",
                        "type": "Packages::Deb",
                        "vendor": null,
                        "version": "3.7.3-2+deb10u7"
                    }
                }
            ],
            "updates_count": 127
        }
    }
}
```

#### Human Readable Output

>### Cyberwatch Asset
>|id|hostname|description|reboot_required|category|last_communication|os|environment|groups|cve_announcements_count|prioritized_cve_announcements_count|updates_count|compliance_repositories|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1206 | vps418658 | None | False | server | 2020-11-03T10:25:01 | Debian 10 (Buster) | Privacy | ***values***: 0_Compliance, demonstration, LINUX  | 898 | 117 | 127 | ***values***: Security_Best_Practices |

### cyberwatch-fetch-asset-fulldetails

***
Get all details for an asset scanned by Cyberwatch, including packages, ports, services, metadata.

#### Base Command

`cyberwatch-fetch-asset-fulldetails`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID to fetch with all details. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberwatch.Asset.id | number | Asset ID | 
| Cyberwatch.Asset.hostname | string | Asset hostname | 
| Cyberwatch.Asset.description | string | Asset description | 
| Cyberwatch.Asset.created_at | date | Asset creation date | 
| Cyberwatch.Asset.last_communication | date | Asset last communication date | 
| Cyberwatch.Asset.analyzed_at | date | Asset last analysis date | 
| Cyberwatch.Asset.cve_announcements_count | number | Number of active CVEs on the asset | 
| Cyberwatch.Asset.prioritized_cve_announcements_count | number | Number of prioritized CVEs on the asset | 
| Cyberwatch.Asset.reboot_required | boolean | Asset reboot requirement | 

#### Command example
```!cyberwatch-fetch-asset-fulldetails id=1206```
#### Context Example
```json
{
    "Cyberwatch": {
        "Asset": {
            "addresses": [
                "vps418658"
            ],
            "analyzed_at": "2020-06-01T17:48:33.000Z",
            "boot_at": null,
            "category": "server",
            "compliance_repositories": [
                {
                    "color": "#336699",
                    "description": null,
                    "id": 18,
                    "name": "Security_Best_Practices"
                }
            ],
            "connector": {
                "id": 17,
                "path": "/api/v3/assets/agents/17",
                "type": "Agent"
            },
            "created_at": "2020-06-01T17:48:31.000Z",
            "cve_announcements": [
                {
                    "active": true,
                    "cve_code": "CVE-2020-13777",
                    "detected_at": "2020-06-06T19:15:52.000Z",
                    "environmental_score": 7.6,
                    "epss": 0.00348,
                    "fixed_at": null,
                    "ignored": false,
                    "prioritized": true,
                    "published": "2020-06-04T05:15:10.000Z",
                    "score": 7.4
                },
                // ...
                {
                    "active": true,
                    "cve_code": "CVE-2020-10756",
                    "detected_at": "2020-07-19T18:45:33.000Z",
                    "environmental_score": 8.1,
                    "epss": 0.00069,
                    "fixed_at": null,
                    "ignored": false,
                    "prioritized": true,
                    "published": "2020-07-09T14:15:13.470Z",
                    "score": 6.5
                }
            ],
            "cve_announcements_count": 898,
            "description": null,
            "environment": {
                "availability_requirement": "availability_requirement_low",
                "ceiling_cvss_v3": null,
                "confidentiality_requirement": "confidentiality_requirement_high",
                "id": 9,
                "integrity_requirement": "integrity_requirement_low",
                "name": "Privacy"
            },
            "groups": [
                {
                    "color": "#12AFCB",
                    "description": null,
                    "id": 789,
                    "name": "0_Compliance"
                },
                {
                    "color": "#12AFCB",
                    "description": null,
                    "id": 764,
                    "name": "demonstration"
                }
            ],
            "hostname": "vps418658",
            "id": 1206,
            "last_communication": "2020-11-03T10:25:01.000Z",
            "metadata": [],
            "os": {
                "arch": "x86_64",
                "eol": "2024-06-30",
                "key": "debian_10_64",
                "name": "Debian 10 (Buster)",
                "short_name": "Debian 10",
                "type": "Os::Debian"
            },
            "packages": [
                {
                    "active": true,
                    "paths": [
                        "ii"
                    ],
                    "product": "libdns-export1104",
                    "type": "Packages::Deb",
                    "vendor": null,
                    "version": "1:9.11.5.P4+dfsg-5.1+deb10u1"
                },
                // ...
                {
                    "active": true,
                    "paths": [
                        "ii"
                    ],
                    "product": "libmagic1",
                    "type": "Packages::Deb",
                    "vendor": null,
                    "version": "1:5.35-4+deb10u1"
                }
            ],
            "ports": [],
            "prioritized_cve_announcements_count": 117,
            "reboot_required": false,
            "security_issues": [
                {
                    "description": "All software,...",
                    "detected_at": "2024-06-30T00:36:37.488Z",
                    "editable": false,
                    "id": 120,
                    "level": "level_critical",
                    "sid": "Obsolete-Os",
                    "status": "active",
                    "title": "Obsolete operating system"
                }
            ],
            "services": [],
            "status": "server_vulnerable",
            "updates": [
                {
                    "current": {
                        "product": "libnettle6",
                        "type": "Packages::Deb",
                        "vendor": null,
                        "version": "3.4.1-1"
                    },
                    "cve_announcements": [
                        "CVE-2021-20305",
                        "CVE-2021-3580"
                    ],
                    "id": 432864,
                    "ignored": false,
                    "patchable": true,
                    "target": {
                        "product": "libnettle6",
                        "type": "Packages::Deb",
                        "vendor": null,
                        "version": "3.4.1-1+deb10u1"
                    }
                },
                // ...
                {
                    "current": {
                        "product": "libicu63",
                        "type": "Packages::Deb",
                        "vendor": null,
                        "version": "63.1-6+deb10u1"
                    },
                    "cve_announcements": [
                        "CVE-2020-21913"
                    ],
                    "id": 433995,
                    "ignored": false,
                    "patchable": true,
                    "target": {
                        "product": "libicu63",
                        "type": "Packages::Deb",
                        "vendor": null,
                        "version": "63.1-6+deb10u2"
                    }
                }
            ],
            "updates_count": 127
        }
    }
}
```

#### Human Readable Output

### Cyberwatch Asset
|id|hostname|description|reboot_required|category|last_communication|os|environment|groups|cve_announcements_count|prioritized_cve_announcements_count|updates_count|compliance_repositories|packages_count|metadata_count|services_count|ports_count|connector_type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1206 | vps418658 | None | False | server | 2020-11-03T10:25:01 | Debian 10 (Buster) | Privacy | ***values***: 0_Compliance, demonstration, LINUX  | 898 | 117 | 127 | ***values***: Security_Best_Practices | 312 | 0 | 0 | 0 | Agent |

### cyberwatch-list-securityissues

***
Get a list of Security issues from Cyberwatch.

#### Base Command

`cyberwatch-list-securityissues`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| level | Filter Security Issues based on their level. Available values: level_info, level_low, level_medium, level_high, level_critical. Possible values are: level_info, level_low, level_medium, level_high, level_critical. | Optional | 
| sid | Filter Security Issues by Security Issue reference / sid. | Optional | 
| page | Get a specific Security Issues page. If not specified, get all Security Issues. | Optional | 
| per_page | Specify the number of Security Issues per page. Default value 500. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberwatch.SecurityIssue.id | number | Security Issue ID | 
| Cyberwatch.SecurityIssue.title | string | Security Issue title | 
| Cyberwatch.SecurityIssue.description | string | Security Issue description | 
| Cyberwatch.SecurityIssue.level | string | Security Issue level | 
| Cyberwatch.SecurityIssue.sid | string | Security Issue SID | 
| Cyberwatch.SecurityIssue.editable | boolean | Security Issue editability | 

#### Command example
```!cyberwatch-list-securityissues page=1 per_page=5 level=level_critical```
#### Context Example
```json
{
    "Cyberwatch": {
        "SecurityIssue": [
            {
                "editable": true,
                "id": 42,
                "level": "level_critical",
                "sid": "Pentest-2020-01",
                "title": "Capacité à faire une injection SQL"
            },
            {
                "description": "Descriptio...",
                "editable": true,
                "id": 44,
                "level": "level_critical",
                "sid": "PENTEST-2021-REF-1",
                "title": "Résultat d'un test d'intrusion"
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberwatch Security Issues
>|id|sid|level|title|description|
>|---|---|---|---|---|
>| 42 | Pentest-2020-01 | level_critical | Capacité à faire une injection SQL |  |
>| 44 | PENTEST-2021-REF-1 | level_critical | Résultat d'un test d'intrusion | Description technique du résultat de test d'intrusion |
>| 47 | WSTG-INPV-05 | level_critical | SQL Injection | An SQL injection attack ... |
>| 48 | WSTG-INPV-06 | level_critical | LDAP Injection | LDAP injection is a server ... |
>| 50 | WSTG-INPV-08 | level_critical | SSI Injection | The Server-Side Includes attack ... |


#### Command example
```!cyberwatch-list-securityissues sid=WSTG-INPV-05 page=1 per_page=5```
#### Context Example
```json
{
    "Cyberwatch": {
        "SecurityIssue": {
            "description": "An SQL inj...",
            "editable": false,
            "id": 47,
            "level": "level_critical",
            "sid": "WSTG-INPV-05",
            "title": "SQL Injection"
        }
    }
}
```

#### Human Readable Output

>### Cyberwatch Security Issues
>|id|sid|level|title|description|
>|---|---|---|---|---|
>| 47 | WSTG-INPV-05 | level_critical | SQL Injection | An SQL injection attack ... |


### cyberwatch-fetch-securityissue

***
Get all details for a Security issue from Cyberwatch.

#### Base Command

`cyberwatch-fetch-securityissue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The Security Issue ID to fetch. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberwatch.SecurityIssue.id | number | Security Issue ID | 
| Cyberwatch.SecurityIssue.title | string | Security Issue title | 
| Cyberwatch.SecurityIssue.description | string | Security Issue description | 
| Cyberwatch.SecurityIssue.level | string | Security Issue level | 
| Cyberwatch.SecurityIssue.sid | string | Security Issue SID | 
| Cyberwatch.SecurityIssue.editable | boolean | Security Issue editability | 

#### Command example
```!cyberwatch-fetch-securityissue id=47```
#### Context Example
```json
{
    "Cyberwatch": {
        "SecurityIssue": {
            "cve_announcements": [],
            "description": "An SQL inj...",
            "editable": false,
            "id": 47,
            "level": "level_critical",
            "servers": [
                {
                    "detected_at": "2024-03-05T18:29:25.399+01:00",
                    "hostname": "test.website.com",
                    "id": 1781,
                    "status": "active"
                },
                {
                    "detected_at": "2024-03-05T18:29:25.403+01:00",
                    "hostname": "test.website.com",
                    "id": 1781,
                    "status": "active"
                }
            ],
            "sid": "WSTG-INPV-05",
            "title": "SQL Injection"
        }
    }
}
```

#### Human Readable Output

>### Cyberwatch Security Issue
>|id|sid|title|description|servers_count|cve_announcements_count|
>|---|---|---|---|---|---|
>| 47 | WSTG-INPV-05 | SQL Injection | An SQL injection attack... |  |  |
