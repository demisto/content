Fetches ThreatMon alarms as incidents with every finding and screenshot, mirrors the alarm status between ThreatMon and Cortex in both directions, submits takedown and data removal requests, and brings ThreatMon Vulnerability Knowledge, the sandbox, the attack surface, the CISO Dashboard and MSSP customer management into playbooks.

This integration was integrated and tested with the ThreatMon External API (November 2026).

## Before you start

- **API key**: in ThreatMon, open **Settings**, then **Integrations**, then **Settings**, and copy the **External API Key**.
- **IP whitelisting**: if it is enabled for your ThreatMon account, send the public IP address of the Cortex server or engine to [support@threatmonit.io](mailto:support@threatmonit.io). Until then ThreatMon answers with *403 Forbidden* and the integration reports that the address is not whitelisted.
- **MSSP accounts**: enter the exact sub company name in **Customer Name (MSSP)**. A name that does not match is rejected like a wrong API key.

## How fetching works

- The integration follows alarm **changes** with a `(lastUpdateDate, alarmCode)` cursor. Alarms that ThreatMon approves later with an older alarm code, and alarms that move to one of the **Alarm Statuses to Fetch** later, are fetched too.
- Each fetch reads the last **Look-back Window (minutes)** again, because ThreatMon makes changes visible with a delay of a few minutes. An alarm is never created twice.
- When **Maximum number of incidents per fetch** is reached, the next fetch continues from the exact position.
- Incidents are named `ThreatMon #<alarm code>: <title>` and use the **ThreatMon Alert** incident type and layout, with the findings, the finding IDs and the mitigation.
- With **Attach Screenshots**, the screenshots of the findings (for example of a phishing page) are attached to the incident, up to 3 per alarm.
- **Upgrading from version 1.x**: existing instances continue after the last alarm that version 1.x fetched, so no incident is created twice. Incidents fetched before the upgrade are not mirrored. To use the new incident type, layout and mirroring, set **Incident type** to *ThreatMon Alert*, **Mapper (incoming)** to *ThreatMon - Incoming Mapper* and **Mapper (outgoing)** to *ThreatMon - Outgoing Mapper* in the instance settings. Check the release notes for the changed defaults.

## Modules

Some commands need a ThreatMon module or permission:

| Commands | Requires |
| --- | --- |
| `cve`, `threatmon-cve-get`, `threatmon-cve-search`, `threatmon-cve-subscription-list`, `threatmon-subscribed-cve-search` | The Vulnerability Knowledge module |
| `threatmon-sandbox-*` | The Sandbox module |
| `threatmon-data-removal-request` | Black Market Data Removal credits |
| `threatmon-customer-create`, `-update`, `-delete`, `-keyword-add`, `-keyword-remove` | The External API Key of the MSSP administrator account. The keys of MSSP sub companies can list the customers but cannot change them. |

## Configure ThreatMon Incident Management in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API URL | The ThreatMon External API URL. A URL that ends with /v1 also works. | True |
| API Key | The External API Key. In ThreatMon, open Settings, then Integrations, then Settings. | True |
| Customer Name (MSSP) | For MSSP accounts, the exact name of the sub company to work with, as shown in ThreatMon. Leave empty to use the account of the API key. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Source Reliability | The reliability of ThreatMon for the file verdicts of the sandbox. | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| First Fetch Time | How far back to look for alarms on the first fetch, for example "3 days", "12 hours" or "2026-11-01". | False |
| Maximum number of incidents per fetch | The maximum number of incidents to create in one fetch \(1-200\). The next fetch continues from the same position. | False |
| Alarm Statuses to Fetch | Only alarms with one of these statuses are created as incidents. An alarm that moves to one of them later is created then. | False |
| Minimum Severity to Fetch | Alarms with a lower severity are not fetched. | False |
| Alarm Categories to Fetch | Only alarms in these categories are fetched. Leave empty to fetch every category. | False |
| Mask Secrets in Findings | When selected, passwords, tokens and cookies in leak findings are shortened \(for example "Wi\*\*\*\*\*\*"\) before they are stored in Cortex. | False |
| Attach Screenshots | When selected, the screenshots of the findings \(for example of a phishing page\) are attached to the incident, up to 3 per alarm. | False |
| Look-back Window (minutes) | The number of minutes of alarm changes to read again on each fetch and mirroring cycle, because ThreatMon makes changes visible with a delay of a few minutes. Alarms that already exist are not created again. | False |
| Last Incident ID (for initial fetch) | Alarms with this alarm code or a lower one are never fetched. Leave empty to rely on the First Fetch Time only. | False |
| Incident Mirroring Direction | The direction to mirror the alarm status: Incoming \(from ThreatMon to Cortex\), Outgoing \(from Cortex to ThreatMon\), or both. Applies to incidents fetched after the setting is changed. Cortex XSOAR only parameter. | False |
| Close Mirrored Cortex Incident | When selected, an incident is closed when its alarm is set to Resolved or Ignore in ThreatMon, and reopened when the alarm is opened again. Cortex XSOAR only parameter. | False |
| Close Mirrored ThreatMon Alarm | When selected, closing an incident sets its alarm to Ignore when the close reason is False Positive or Duplicate, and to Resolved otherwise. Cortex XSOAR only parameter. | False |
| Fetch Interval (minutes) (Deprecated) | Deprecated. This parameter is not used. Use Incidents Fetch Interval instead. | False |
| Incidents Fetch Interval |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### threatmon-alarm-list

***
Lists ThreatMon alarms, ordered by alarm code, or by change time when updated_after is set. Use the filters to find an alarm and its findings, for example before a takedown request.

#### Base Command

`threatmon-alarm-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of alarms to return (1-100). Default is 10. | Optional |
| page | The page to return, 0-based. Each page holds "limit" alarms. Default is 0. | Optional |
| severity | A comma-separated list of severities to return. Possible values are: Information, Low, Medium, High, Critical. | Optional |
| category | The category of the alarms to return, for example Brand Intelligence. | Optional |
| status | A comma-separated list of statuses to return. The filter is applied to the alarms of the requested page. Possible values are: Open, In Progress, Resolved, Ignore. | Optional |
| start_date | Return alarms created at or after this time, for example "7 days" or "2026-11-01T00:00:00Z". | Optional |
| end_date | Return alarms created before this time. | Optional |
| updated_after | Return alarms changed at or after this time, ordered by change time. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.Alarm.AlarmCode | Number | The alarm code. |
| ThreatMon.Alarm.Title | String | The alarm title. |
| ThreatMon.Alarm.AlarmType | String | The alarm type. |
| ThreatMon.Alarm.Category | String | The alarm category. |
| ThreatMon.Alarm.SubCategory | String | The alarm subcategory. |
| ThreatMon.Alarm.Severity | String | The alarm severity. |
| ThreatMon.Alarm.Status | String | The alarm status. |
| ThreatMon.Alarm.Source | String | The source that detected the alarm. |
| ThreatMon.Alarm.AlarmDate | Date | The time the alarm was created \(e.g., 2026-11-05T09:23:47.553Z\). |
| ThreatMon.Alarm.LastUpdateDate | Date | The time the alarm was last changed \(e.g., 2026-11-06T12:01:10.12Z\). |
| ThreatMon.Alarm.Description | String | The alarm description. |
| ThreatMon.Alarm.Mitigation | String | The recommended mitigation. |
| ThreatMon.Alarm.Findings | Unknown | The findings of the alarm. Secret values are masked. |
| ThreatMon.Alarm.FindingIDs | Number | The finding IDs of the alarm, used for takedown and data removal requests. |

#### Command example

```!threatmon-alarm-list limit=1 category="Brand Intelligence" status=Open```

#### Context Example

```json
{
    "ThreatMon": {
        "Alarm": [
            {
                "AlarmCode": 20377999,
                "Title": "Phishing Domain Detected",
                "AlarmType": "Phishing Domain Detected",
                "Category": "Brand Intelligence",
                "SubCategory": "Phishing Monitoring",
                "Severity": "High",
                "Status": "Open",
                "Source": "ThreatMon Engine",
                "AlarmDate": "2026-10-01T12:53:38.526462Z",
                "LastUpdateDate": "2026-10-01T12:53:38.564501Z",
                "Description": "An active phishing domain directly impersonating your organization has been detected.",
                "Mitigation": "Domain Blocking: Add the phishing domain to organization DNS blacklists, web filtering solutions and email gateway rules.",
                "Findings": [
                    {
                        "findingId": 21541113,
                        "Phishing Domain": "examp1e-login.pages.dev",
                        "Asset": "example.com"
                    }
                ],
                "FindingIDs": [
                    21541113
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatMon Alarms (Total Records: 29)
>
>|AlarmCode|Title|Severity|Status|Category|AlarmDate|LastUpdateDate|FindingIDs|
>|---|---|---|---|---|---|---|---|
>| 20377999 | Phishing Domain Detected | High | Open | Brand Intelligence | 2026-10-01T12:53:38.526462Z | 2026-10-01T12:53:38.564501Z | 21541113 |

### threatmon-alarm-status-update

***
Sets the status of one or more ThreatMon alarms.

#### Base Command

`threatmon-alarm-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_ids | A comma-separated list of alarm codes. | Required |
| status | The new status. Possible values are: Open, In Progress, Resolved, Ignore. | Required |
| remarks | The remarks to save with the status change in ThreatMon. | Optional |
| assigned_email | The e-mail address of the ThreatMon user to assign the alarm to. | Optional |
| info_email_list | A comma-separated list of e-mail addresses that ThreatMon informs about the change. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.Alarm.AlarmCode | Number | The alarm code. |
| ThreatMon.Alarm.Status | String | The new alarm status. |

#### Command example

```!threatmon-alarm-status-update alarm_ids=20377999 status="In Progress" remarks="Investigating in Cortex."```

#### Context Example

```json
{
    "ThreatMon": {
        "Alarm": [
            {
                "AlarmCode": 20377999,
                "Status": "In Progress"
            }
        ]
    }
}
```

#### Human Readable Output

>The status of ThreatMon alarm(s) 20377999 was set to In Progress.

### threatmon-alarm-stats

***
Returns the number of ThreatMon alarms by status, severity and category.

#### Base Command

`threatmon-alarm-stats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | Count alarms from this date, for example "30 days" or "2026-10-01". | Optional |
| to_date | Count alarms up to this date. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.AlarmStats.Status | Unknown | The number of alarms per status. |
| ThreatMon.AlarmStats.Severity | Unknown | The number of alarms per severity. |
| ThreatMon.AlarmStats.Category | Unknown | The number of alarms per category. |

#### Command example

```!threatmon-alarm-stats from_date="30 days"```

#### Context Example

```json
{
    "ThreatMon": {
        "AlarmStats": {
            "Status": {
                "Open": 61,
                "Resolved": 5
            },
            "Severity": {
                "High": 32,
                "Critical": 2,
                "Information": 32
            },
            "Category": {
                "Brand Intelligence": 30,
                "Strategic Intelligence": 36
            }
        }
    }
}
```

#### Human Readable Output

>### ThreatMon Alarms by Status
>
>|Name|Count|
>|---|---|
>| Open | 61 |
>| Resolved | 5 |
>
>### ThreatMon Alarms by Severity
>
>|Name|Count|
>|---|---|
>| High | 32 |
>| Critical | 2 |
>| Information | 32 |
>
>### ThreatMon Alarms by Category
>
>|Name|Count|
>|---|---|
>| Brand Intelligence | 30 |
>| Strategic Intelligence | 36 |

### threatmon-takedown-request

***
Submits a takedown request for a finding, such as a phishing domain, a rogue mobile app or a fake social media account. The request is submitted once and never retried automatically.

#### Base Command

`threatmon-takedown-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| finding_id | The finding ID, from the findings of the alarm. | Required |
| finding | The finding to take down, for example the phishing domain. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.Takedown.FindingID | Number | The finding ID. |
| ThreatMon.Takedown.Finding | String | The finding. |
| ThreatMon.Takedown.Result | String | The result: Submitted, Already Requested, Not Eligible, Not Allowed or Not Found. |
| ThreatMon.Takedown.Submitted | Boolean | Whether a takedown request for the finding exists in ThreatMon. |
| ThreatMon.Takedown.Message | String | The explanation of the result. |

#### Command example

```!threatmon-takedown-request finding_id=21541113 finding=examp1e-login.pages.dev```

#### Context Example

```json
{
    "ThreatMon": {
        "Takedown": {
            "FindingID": 21541113,
            "Finding": "examp1e-login.pages.dev",
            "Result": "Submitted",
            "Submitted": true,
            "Message": "The request was submitted to ThreatMon."
        }
    }
}
```

#### Human Readable Output

>### ThreatMon Takedown
>
>**Submitted**: The request was submitted to ThreatMon. (findingId 21541113)

### threatmon-data-removal-request

***
Submits a Black Market Monitoring data removal request for a finding. Requires Black Market Data Removal credits. The request is submitted once and never retried automatically.

#### Base Command

`threatmon-data-removal-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| finding_id | The finding ID, from the findings of the alarm. | Required |
| finding | The URL or content identifier of the finding to remove. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.DataRemoval.FindingID | Number | The finding ID. |
| ThreatMon.DataRemoval.Finding | String | The finding. |
| ThreatMon.DataRemoval.Result | String | The result: Submitted, Already Requested, Not Eligible, Not Allowed or Not Found. |
| ThreatMon.DataRemoval.Submitted | Boolean | Whether a data removal request for the finding exists in ThreatMon. |
| ThreatMon.DataRemoval.Message | String | The explanation of the result. |

#### Command example

```!threatmon-data-removal-request finding_id=99999999 finding=https://market.example/item/1```

#### Context Example

```json
{
    "ThreatMon": {
        "DataRemoval": {
            "FindingID": 99999999,
            "Finding": "https://market.example/item/1",
            "Result": "Not Found",
            "Submitted": false,
            "Message": "The finding was not found in ThreatMon."
        }
    }
}
```

#### Human Readable Output

>### ThreatMon Data removal
>
>**Not Found**: The finding was not found in ThreatMon. (findingId 99999999)

### cve

***
Returns ThreatMon Vulnerability Knowledge about a CVE, with its CVSS, ThreatMon risk scores, exploitation signals and CISA KEV entry. Requires the Vulnerability Knowledge module.

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | A comma-separated list of CVE IDs, for example CVE-2024-3400. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. |
| CVE.CVSS.Score | Number | The CVSS score of the CVE. |
| CVE.Published | Date | The date the CVE was published. |
| CVE.Modified | Date | The date the CVE was last modified. |
| CVE.Description | String | The description of the CVE. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. |
| ThreatMon.CVE.cve | String | The CVE ID. |
| ThreatMon.CVE.severity | String | The severity of the newest CVSS version. |
| ThreatMon.CVE.tmvs | Number | The ThreatMon vulnerability score. |
| ThreatMon.CVE.brvs | Number | The Brainify Risk Vulnerability Score, the risk of the CVE for the company. |
| ThreatMon.CVE.epss | Number | The EPSS exploit probability. |
| ThreatMon.CVE.exploit | Boolean | Whether a known exploit exists. |
| ThreatMon.CVE.hasPoc | Boolean | Whether a public proof of concept exists. |
| ThreatMon.CVE.kev | Unknown | The CISA Known Exploited Vulnerabilities entry. |
| ThreatMon.CVE.affectedAssets | Unknown | The number of confirmed and potentially affected company assets. |

#### Command example

```!cve cve=CVE-2024-3400```

#### Context Example

```json
{
    "CVE": {
        "ID": "CVE-2024-3400",
        "CVSS": {
            "Score": 10.0,
            "Version": "3.1"
        },
        "Published": "2024-04-12T08:15:06Z",
        "Modified": "2025-11-04T16:49:20Z",
        "Description": "A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software."
    },
    "ThreatMon": {
        "CVE": {
            "cve": "CVE-2024-3400",
            "severity": "CRITICAL",
            "cvssV3_1": 10.0,
            "tmvs": 25.0,
            "brvs": 22.5,
            "epss": 0.99999,
            "exploit": true,
            "hasPoc": true,
            "kev": {
                "dateAdded": "2024-04-12",
                "dueDate": "2024-04-19"
            },
            "affectedAssets": {
                "confirmedCount": 0,
                "potentiallyCount": 0,
                "totalCount": 0
            }
        }
    }
}
```

#### Human Readable Output

>### ThreatMon CVE CVE-2024-3400
>
>|Affected Assets|BRVS|CISA KEV|CVE|CVSS|EPSS|Exploit|Public PoC|Published|Ransomware Use|Severity|TMVS|Trending|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0 | 22.5 | 2024-04-12 | CVE-2024-3400 | 10.0 | 0.99999 | true | true | 2024-04-12T08:15:06Z | Unknown | CRITICAL | 25.0 | false |
>
>A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software.
>
>**CISA required action:** Apply mitigations per vendor instructions as they become available.

### threatmon-cve-get

***
Gets a ThreatMon Vulnerability Knowledge CVE in detail, optionally with the AI report, the timeline and the mentions. Requires the Vulnerability Knowledge module.

#### Base Command

`threatmon-cve-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | The CVE ID, for example CVE-2024-3400. | Required |
| include | A comma-separated list of extra sections to return. Possible values are: report, timeline, mentions. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.CVE.cve | String | The CVE ID. |
| ThreatMon.CVE.summary | String | The CVE summary. |
| ThreatMon.CVE.severity | String | The severity of the newest CVSS version. |
| ThreatMon.CVE.tmvs | Number | The ThreatMon vulnerability score. |
| ThreatMon.CVE.brvs | Number | The Brainify Risk Vulnerability Score, the risk of the CVE for the company. |
| ThreatMon.CVE.epss | Number | The EPSS exploit probability. |
| ThreatMon.CVE.exploit | Boolean | Whether a known exploit exists. |
| ThreatMon.CVE.hasPoc | Boolean | Whether a public proof of concept exists. |
| ThreatMon.CVE.kev | Unknown | The CISA Known Exploited Vulnerabilities entry. |
| ThreatMon.CVE.pocs | Unknown | The known proofs of concept. |
| ThreatMon.CVE.riskBreakdown | Unknown | The parts of the ThreatMon vulnerability score. |
| ThreatMon.CVE.report | Unknown | The AI enrichment report, when requested. |
| ThreatMon.CVE.timeline | Unknown | The timeline of the CVE, when requested. |
| ThreatMon.CVE.mentions | Unknown | The mentions on X, Reddit and the dark web, when requested. |

#### Command example

```!threatmon-cve-get cve_id=CVE-2024-3400 include=report```

#### Context Example

```json
{
    "ThreatMon": {
        "CVE": {
            "cve": "CVE-2024-3400",
            "severity": "CRITICAL",
            "tmvs": 25.0,
            "brvs": 22.5,
            "epss": 0.99999,
            "exploit": true,
            "hasPoc": true,
            "report": {
                "header": {
                    "title": "Palo Alto Networks PAN-OS GlobalProtect command injection allows unauthenticated RCE"
                },
                "analyst_brief": {
                    "priority": "P1"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### AI Report: Palo Alto Networks PAN-OS GlobalProtect command injection allows unauthenticated RCE
>
>**Priority:** P1. Pre-auth network RCE with public PoC, active in-the-wild exploitation, and ransomware usage.
>
>### Response Steps
>
>|Step|Title|Description|ETA|
>|---|---|---|---|
>| 1 | Isolate affected firewalls | Disable GlobalProtect features on affected PAN-OS versions via temporary policies to stop active exploitation. | 0-15 min |
>| 2 | Apply emergency updates | Install the latest PAN-OS emergency update and content package to patch the vulnerability. | 45 min - 2h |

### threatmon-cve-search

***
Searches ThreatMon Vulnerability Knowledge for CVEs published or updated in a period, oldest first. Requires the Vulnerability Knowledge module.

#### Base Command

`threatmon-cve-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | The start of the period, for example "7 days" or "2026-11-01". The period can be at most 366 days. | Required |
| end_date | The end of the period. Default is now. | Optional |
| date_field | The date to search by. Possible values are: published, updated. Default is published. | Optional |
| cvss | The severity of the newest CVSS version. Possible values are: NONE, LOW, MEDIUM, HIGH, CRITICAL. | Optional |
| search | A part of a CVE ID, for example 2026-1234. | Optional |
| vendor | The CPE vendor name. | Optional |
| product | The CPE product name. | Optional |
| exploit | Whether a known exploit exists. Possible values are: true, false. | Optional |
| has_poc | Whether a public proof of concept exists. Possible values are: true, false. | Optional |
| trending | Whether the CVE is trending. Possible values are: true, false. | Optional |
| known_ransomware_use | Whether the CVE is used in ransomware campaigns. Possible values are: true, false. | Optional |
| confirmed_affected | Whether company assets are confirmed to be affected. Possible values are: true, false. | Optional |
| potentially_affected | Whether company assets are potentially affected. Possible values are: true, false. | Optional |
| limit | The maximum number of CVEs to return (1-1000). Default is 50. | Optional |
| cursor | The cursor returned by the previous search, to get the next CVEs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.CVE.cve | String | The CVE ID. |
| ThreatMon.CVE.cweId | String | The CWE IDs. |
| ThreatMon.CVE.summary | String | The CVE summary. |
| ThreatMon.CVE.severity | String | The severity of the newest CVSS version. |
| ThreatMon.CVE.cvssV3_1 | Number | The CVSS v3.1 score. |
| ThreatMon.CVE.cvssV4 | Number | The CVSS v4 score. |
| ThreatMon.CVE.tmvs | Number | The ThreatMon vulnerability score. |
| ThreatMon.CVE.brvs | Number | The Brainify Risk Vulnerability Score, the risk of the CVE for the company. |
| ThreatMon.CVE.epss | Number | The EPSS exploit probability. |
| ThreatMon.CVE.exploit | Boolean | Whether a known exploit exists. |
| ThreatMon.CVE.hasPoc | Boolean | Whether a public proof of concept exists. |
| ThreatMon.CVE.vendors | Unknown | The affected vendors and products. |
| ThreatMon.CVE.publishedAt | Date | The date the CVE was published \(e.g., 2026-11-01T00:00:23.604Z\). |
| ThreatMon.CVESearch.NextCursor | String | The cursor to get the next CVEs, or empty when there are no more. |

#### Command example

```!threatmon-cve-search start_date=2026-11-01 cvss=CRITICAL exploit=true limit=1```

#### Context Example

```json
{
    "ThreatMon": {
        "CVE": [
            {
                "cve": "CVE-2026-102895",
                "cweId": "CWE-287, CWE-290, CWE-346",
                "severity": "CRITICAL",
                "cvssV3_1": 9.8,
                "tmvs": 27.27,
                "epss": 0.00331,
                "exploit": true,
                "hasPoc": false,
                "publishedAt": "2026-11-04T21:16:59.842Z",
                "vendors": {
                    "gpustack": [
                        "gpustack"
                    ]
                }
            }
        ],
        "CVESearch": {
            "NextCursor": "eyJ0IjoiMjAyNi0xMS0wNFQyMToxNjo1OS44NDJaIn0"
        }
    }
}
```

#### Human Readable Output

>### ThreatMon CVEs (1)
>
>|CVE|Severity|CVSS 3.1|TMVS|EPSS|Exploit|Public PoC|Published|Summary|
>|---|---|---|---|---|---|---|---|---|
>| CVE-2026-102895 | CRITICAL | 9.8 | 27.27 | 0.00331 | true | false | 2026-11-04T21:16:59.842Z | GPUStack is an open-source GPU cluster manager for AI model serving and GPU instance provisioning. Prior to 2.2.0, get_current_user in gpustack/api/auth.py... |
>
>More CVEs are available. Run the command again with cursor=eyJ0IjoiMjAyNi0xMS0wNFQyMToxNjo1OS44NDJaIn0.

### threatmon-cve-subscription-list

***
Lists the vendors and products the company follows in ThreatMon Vulnerability Knowledge, with the recipients of the CVE e-mails.

#### Base Command

`threatmon-cve-subscription-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| recipient_email | Show only the subscriptions of this recipient of the CVE e-mails. | Optional |
| limit | The maximum number of subscriptions to return (1-1000). Default is 50. | Optional |
| cursor | The cursor returned by the previous command, to get the next subscriptions. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.CVESubscription.vendor | String | The vendor. |
| ThreatMon.CVESubscription.product | String | The product. |
| ThreatMon.CVESubscription.productId | Number | The product ID. |
| ThreatMon.CVESubscription.subscribedAt | Date | The time of the subscription. |
| ThreatMon.CVESubscription.recipients | Unknown | The recipients of the CVE e-mails. |
| ThreatMon.CVESubscriptionList.NextCursor | String | The cursor to get the next subscriptions, or empty when there are no more. |

#### Command example

```!threatmon-cve-subscription-list```

#### Context Example

```json
{
    "ThreatMon": {
        "CVESubscription": [
            {
                "vendor": "Fortinet",
                "product": "Fortios",
                "productId": 80611,
                "internal": true,
                "external": false,
                "subscribedAt": "2026-09-01T10:00:00Z",
                "recipients": [
                    {
                        "email": "soc@example.com",
                        "type": "USER"
                    }
                ]
            }
        ],
        "CVESubscriptionList": {
            "NextCursor": null
        }
    }
}
```

#### Human Readable Output

>### ThreatMon CVE Subscriptions (1)
>
>|Vendor|Product|Internal|External|Subscribed At|Recipients|
>|---|---|---|---|---|---|
>| Fortinet | Fortios | true | false | 2026-09-01T10:00:00Z | soc@example.com |

### threatmon-subscribed-cve-search

***
Searches the CVEs published in a period for the vendors and products the company follows, oldest first.

#### Base Command

`threatmon-subscribed-cve-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | The start of the period, for example "30 days" or "2026-10-01". The period can be at most 366 days. | Required |
| end_date | The end of the period. Default is now. | Optional |
| cvss | The severity of the newest CVSS version. Possible values are: NONE, LOW, MEDIUM, HIGH, CRITICAL. | Optional |
| recipient_email | Show only the CVEs e-mailed to this recipient. | Optional |
| limit | The maximum number of CVEs to return (1-1000). Default is 50. | Optional |
| cursor | The cursor returned by the previous search, to get the next CVEs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.CVE.cve | String | The CVE ID. |
| ThreatMon.CVE.summary | String | The CVE summary. |
| ThreatMon.CVE.severity | String | The severity of the newest CVSS version. |
| ThreatMon.CVE.riskScore | Number | The risk score of the CVE. |
| ThreatMon.CVE.subscribedProducts | Unknown | The subscribed products the CVE was matched to. |
| ThreatMon.SubscribedCVESearch.NextCursor | String | The cursor to get the next CVEs, or empty when there are no more. |

#### Command example

```!threatmon-subscribed-cve-search start_date="30 days" cvss=HIGH```

#### Context Example

```json
{
    "ThreatMon": {
        "CVE": [
            {
                "cve": "CVE-2026-24858",
                "severity": "HIGH",
                "riskScore": 7.4,
                "subscribedProducts": [
                    {
                        "vendor": "Fortinet",
                        "product": "Fortios"
                    }
                ]
            }
        ],
        "SubscribedCVESearch": {
            "NextCursor": null
        }
    }
}
```

#### Human Readable Output

>### ThreatMon CVEs of Subscribed Products (1)
>
>|CVE|Severity|Summary|
>|---|---|---|
>| CVE-2026-24858 | HIGH | An authentication bypass in FortiOS SSL-VPN. |

### threatmon-asset-list

***
Lists the company assets that ThreatMon discovered (Digital Footprint), such as IP addresses, domains, websites, certificates and technologies.

#### Base Command

`threatmon-asset-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | The type of assets to list. Possible values are: IP, Cloud IP, Domain, Subdomain, Cloud Subdomain, WHOIS, Website, SSL Certificate, Technology, DNS Record, Bucket, Bucket File. Default is Domain. | Required |
| limit | The maximum number of assets to return (1-100). Default is 50. | Optional |
| page | The page to return, 0-based. Each page holds "limit" assets. Default is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.Asset.AssetType | String | The asset type. |
| ThreatMon.Asset.ip | String | The IP address \(IP and Cloud IP assets\). |
| ThreatMon.Asset.domainName | String | The domain name \(Domain assets\). |
| ThreatMon.Asset.subDomainName | String | The subdomain name \(Subdomain and Cloud Subdomain assets\). |
| ThreatMon.Asset.websiteUrl | String | The website URL \(Website assets\). |
| ThreatMon.Asset.asset | String | The asset the record belongs to \(WHOIS, SSL Certificate and Technology assets\). |
| ThreatMon.Asset.expireDate | Date | The expiry date of the certificate \(SSL Certificate assets\). |
| ThreatMon.Asset.productName | String | The technology name \(Technology assets\). |
| ThreatMon.Asset.monitor | Boolean | Whether ThreatMon monitors the asset. |

#### Command example

```!threatmon-asset-list asset_type="SSL Certificate" limit=1```

#### Context Example

```json
{
    "ThreatMon": {
        "Asset": [
            {
                "AssetType": "SSL Certificate",
                "asset": "www.example.com:443",
                "issuedBy": "WE1",
                "issuedName": "example.com",
                "grade": "B",
                "expireDate": "2027-01-13",
                "vuln": true,
                "sslProtocolNames": [
                    "TLSv1.0",
                    "TLSv1.1",
                    "TLSv1.2",
                    "TLSv1.3"
                ],
                "monitor": true
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatMon SSL Certificate Assets (Total Records: 1)
>
>|Asset|Expire Date|Grade|Issued By|Issued Name|Monitor|SSL Protocols|Vulnerable|
>|---|---|---|---|---|---|---|---|
>| www.example.com:443 | 2027-01-13 | B | WE1 | example.com | true | TLSv1.0,<br>TLSv1.1,<br>TLSv1.2,<br>TLSv1.3 | true |

### threatmon-ciso-dashboard-get

***
Gets the ThreatMon CISO Dashboard, with the Brainify Risk Score, the module scores, the alert statistics and the AI risk report.

#### Base Command

`threatmon-ciso-dashboard-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| include_report | Whether to show the AI risk report in the War Room. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.CISODashboard.statistics | Unknown | The alert statistics and the average score. |
| ThreatMon.CISODashboard.score.score | Number | The Brainify Risk Score. |
| ThreatMon.CISODashboard.score.grade | String | The grade of the Brainify Risk Score. |
| ThreatMon.CISODashboard.score.report | String | The AI risk report, in Markdown. |
| ThreatMon.CISODashboard.topAlerts | Unknown | The most frequent alerts. |
| ThreatMon.CISODashboard.topAssets | Unknown | The assets with the most findings. |
| ThreatMon.CISODashboard.topCveAlerts | Unknown | The CVEs with the highest risk for the company. |
| ThreatMon.CISODashboard.highDemandAssets | Unknown | The company assets offered on black markets. |

#### Command example

```!threatmon-ciso-dashboard-get include_report=false```

#### Context Example

```json
{
    "ThreatMon": {
        "CISODashboard": {
            "statistics": {
                "averageScore": 64.0,
                "confidenceLevel": 85,
                "confidenceLevelText": "High Confidence",
                "totalAlert": 19616,
                "openAlert": 64,
                "criticalFindings": 18154
            },
            "score": {
                "score": 64.0,
                "grade": "D",
                "asScore": 97,
                "asGrade": "A",
                "dwScore": 1,
                "dwGrade": "F"
            },
            "topAlerts": [
                {
                    "title": "VIP/C-Level Machine Infected by Malware",
                    "total": 18076
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ThreatMon CISO Dashboard: Risk Score 64.0 (D)
>
>|Average Score|Confidence Level|Confidence Level Text|Critical Findings|Open Alert|Total Alert|
>|---|---|---|---|---|---|
>| 64.0 | 85 | High Confidence | 18154 | 64 | 19616 |
>
>### Module Scores
>
>|Module|Score|Grade|
>|---|---|---|
>| Attack Surface | 97 | A |
>| Dark Web | 1 | F |
>
>### Top Alerts
>
>|Title|Total|
>|---|---|
>| VIP/C-Level Machine Infected by Malware | 18076 |

### threatmon-screenshot-get

***
Downloads the screenshot of a finding, for example of a phishing page, and adds it to the War Room.

#### Base Command

`threatmon-screenshot-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| blob_name | The value of the Screenshot item of the finding, as the full URL or the blob name. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | String | The file name. |
| InfoFile.EntryID | String | The entry ID of the file. |
| InfoFile.Size | Number | The file size. |
| InfoFile.Type | String | The file type. |
| InfoFile.Info | String | The basic information of the file. |
| InfoFile.Extension | String | The file extension. |

#### Command example

```!threatmon-screenshot-get blob_name="FILE-SHARE/b2da3c55-c8e4-4e0f-96e5-0fce6fa0b7ba.png"```

#### Context Example

```json
{
    "InfoFile": {
        "Name": "b2da3c55-c8e4-4e0f-96e5-0fce6fa0b7ba.png",
        "EntryID": "1234@abcd",
        "Size": 215196,
        "Type": "PNG image data",
        "Extension": "png",
        "Info": "image/png"
    }
}
```

#### Human Readable Output

The screenshot is added to the War Room as an image.

### threatmon-sandbox-file-submit

***
Submits a file to the ThreatMon sandbox for malware analysis and waits for the verdict. The file is submitted once.

#### Base Command

`threatmon-sandbox-file-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the file. | Required |
| archive_password | The password of an encrypted archive. | Optional |
| polling | Whether to wait for the verdict. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.Sandbox.ID | Number | The row ID of the submission. It does not change. |
| ThreatMon.Sandbox.SID | String | The submission ID. |
| ThreatMon.Sandbox.FileName | String | The submitted file name. |
| ThreatMon.Sandbox.OverallRating | String | The verdict, for example Clean or Malicious. |
| ThreatMon.Sandbox.Results.SHA256 | String | The SHA-256 of an analysed file. |
| ThreatMon.Sandbox.Results.Rating | String | The rating of an analysed file. |
| ThreatMon.Sandbox.Results.MalwareName | String | The detected malware name. |
| ThreatMon.Sandbox.Results.BehaviorData | Unknown | The behavior of the analysed file. |
| File.SHA256 | String | The SHA-256 of the file. |
| File.SHA1 | String | The SHA-1 of the file. |
| File.Name | String | The file name. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. |

#### Command example

```!threatmon-sandbox-file-submit entry_id=1234@abcd```

#### Context Example

```json
{
    "ThreatMon": {
        "Sandbox": {
            "SID": "8492267284349462431",
            "FileName": "invoice.txt",
            "FileSize": 70,
            "Status": 2,
            "TotalJobs": 1,
            "OverallRating": "Clean",
            "CreatedAt": "2026-11-10T12:20:45.230084",
            "Results": [
                {
                    "FileName": "invoice.txt",
                    "FileType": "txt",
                    "SHA256": "e377e9997013ef1c04c8ddede14b00f88396c0ec88c0dbfa14057dc42d416a51",
                    "Rating": "Clean",
                    "MalwareName": "N/A",
                    "RatingSource": "Static Scan Engine"
                }
            ]
        }
    },
    "DBotScore": {
        "Indicator": "e377e9997013ef1c04c8ddede14b00f88396c0ec88c0dbfa14057dc42d416a51",
        "Type": "file",
        "Vendor": "ThreatMon",
        "Score": 1,
        "Reliability": "B - Usually reliable"
    }
}
```

#### Human Readable Output

>### ThreatMon Sandbox Submission 8492267284349462431: Clean
>
>|Created At|File Name|File Size|Overall Rating|SID|Status|Total Jobs|
>|---|---|---|---|---|---|---|
>| 2026-11-10T12:20:45.230084 | invoice.txt | 70 | Clean | 8492267284349462431 | 2 | 1 |
>
>### Analysed Files
>
>|File Name|File Type|Rating|Malware Name|Rating Source|SHA256|
>|---|---|---|---|---|---|
>| invoice.txt | txt | Clean | N/A | Static Scan Engine | e377e9997013ef1c04c8ddede14b00f88396c0ec88c0dbfa14057dc42d416a51 |

### threatmon-sandbox-submission-list

***
Lists the files submitted to the ThreatMon sandbox.

#### Base Command

`threatmon-sandbox-submission-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of submissions to return (1-100). Default is 20. | Optional |
| page | The page to return, 0-based. Default is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.Sandbox.ID | Number | The row ID of the submission. It does not change. |
| ThreatMon.Sandbox.SID | String | The submission ID. |
| ThreatMon.Sandbox.FileName | String | The submitted file name. |
| ThreatMon.Sandbox.FileSize | Number | The file size in bytes. |
| ThreatMon.Sandbox.OverallRating | String | The verdict, for example Clean or Malicious. |
| ThreatMon.Sandbox.CreatedAt | Date | The time of the submission. |

#### Command example

```!threatmon-sandbox-submission-list limit=1```

#### Context Example

```json
{
    "ThreatMon": {
        "Sandbox": [
            {
                "SID": "8492267284349462431",
                "FileName": "invoice.txt",
                "FileSize": 70,
                "Status": 2,
                "TotalJobs": 1,
                "OverallRating": "Clean",
                "CreatedAt": "2026-11-10T12:20:45.230084",
                "UpdatedAt": "2026-11-10T12:25:02.655001"
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatMon Sandbox Submissions (Total: 14)
>
>|SID|File Name|Overall Rating|Total Jobs|Created At|Updated At|
>|---|---|---|---|---|---|
>| 8492267284349462431 | invoice.txt | Clean | 1 | 2026-11-10T12:20:45.230084 | 2026-11-10T12:25:02.655001 |

### threatmon-sandbox-result-get

***
Gets the verdict and the analysed files of a ThreatMon sandbox submission.

#### Base Command

`threatmon-sandbox-result-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sid | The submission ID (SID) from threatmon-sandbox-submission-list. A new submission gets its final SID when the analysis starts. | Required |
| limit | The maximum number of analysed files to return (1-100). Default is 50. | Optional |
| page | The page to return, 0-based. Default is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.Sandbox.ID | Number | The row ID of the submission. It does not change. |
| ThreatMon.Sandbox.SID | String | The submission ID. |
| ThreatMon.Sandbox.OverallRating | String | The verdict, for example Clean or Malicious. |
| ThreatMon.Sandbox.Results.FileName | String | The name of an analysed file. |
| ThreatMon.Sandbox.Results.SHA256 | String | The SHA-256 of an analysed file. |
| ThreatMon.Sandbox.Results.Rating | String | The rating of an analysed file. |
| ThreatMon.Sandbox.Results.MalwareName | String | The detected malware name. |
| ThreatMon.Sandbox.Results.BehaviorData | Unknown | The behavior of the analysed file. |
| File.SHA256 | String | The SHA-256 of the file. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. |

#### Command example

```!threatmon-sandbox-result-get sid=8049628341845326322```

#### Context Example

```json
{
    "ThreatMon": {
        "Sandbox": {
            "SID": "8049628341845326322",
            "FileName": "report.doc",
            "OverallRating": "Malicious",
            "Results": [
                {
                    "FileName": "report.doc",
                    "FileType": "doc",
                    "SHA256": "fbd4e59df6c46f8647bb4f2992cbb65a58909e5c941b4b3a9f91db73d42cd5aa",
                    "SHA1": "d2b2d743bd9f85fb5b0454c0d0773017479107c0",
                    "Rating": "Malicious",
                    "MalwareName": "MSOffice/Agent.D068!tr.dldr",
                    "RatingSource": "AV Scan Engine"
                }
            ]
        }
    },
    "File": {
        "Name": "report.doc",
        "SHA256": "fbd4e59df6c46f8647bb4f2992cbb65a58909e5c941b4b3a9f91db73d42cd5aa",
        "SHA1": "d2b2d743bd9f85fb5b0454c0d0773017479107c0",
        "Malicious": {
            "Vendor": "ThreatMon",
            "Description": "MSOffice/Agent.D068!tr.dldr"
        }
    },
    "DBotScore": {
        "Indicator": "fbd4e59df6c46f8647bb4f2992cbb65a58909e5c941b4b3a9f91db73d42cd5aa",
        "Type": "file",
        "Vendor": "ThreatMon",
        "Score": 3,
        "Reliability": "B - Usually reliable"
    }
}
```

#### Human Readable Output

>### ThreatMon Sandbox Submission 8049628341845326322: Malicious
>
>|File Name|Overall Rating|SID|
>|---|---|---|
>| report.doc | Malicious | 8049628341845326322 |
>
>### Analysed Files
>
>|File Name|File Type|Rating|Malware Name|Rating Source|SHA256|
>|---|---|---|---|---|---|
>| report.doc | doc | Malicious | MSOffice/Agent.D068!tr.dldr | AV Scan Engine | fbd4e59df6c46f8647bb4f2992cbb65a58909e5c941b4b3a9f91db73d42cd5aa |

### threatmon-customer-list

***
Lists the customers of a ThreatMon MSSP account.

#### Base Command

`threatmon-customer-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_name | Return only this customer. | Optional |
| page | The page to return, 0-based. Default is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.Customer.CustomerName | String | The customer name. |
| ThreatMon.Customer.License | String | The license type, TRIAL or CUSTOMER. |
| ThreatMon.Customer.Domain | String | The domain of the customer. |
| ThreatMon.Customer.Keywords | String | The monitoring keywords. |
| ThreatMon.Customer.ContractEndDate | Date | The end of the contract. |

#### Command example

```!threatmon-customer-list customer_name="Example Corp"```

#### Context Example

```json
{
    "ThreatMon": {
        "Customer": [
            {
                "CustomerName": "Example Corp",
                "License": "CUSTOMER",
                "Domain": "example.com",
                "Keywords": [
                    "example"
                ],
                "ContractEndDate": "2030-02-28T23:59:59.999999999Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatMon MSSP Customers (Total Records: 1)
>
>|Customer Name|License|Domain|Keywords|Contract End Date|
>|---|---|---|---|---|
>| Example Corp | CUSTOMER | example.com | example | 2030-02-28T23:59:59.999999999Z |

### threatmon-customer-create

***
Creates a customer in a ThreatMon MSSP account. The change is applied at once. Requires the API key of the MSSP administrator account.

#### Base Command

`threatmon-customer-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_name | The customer name. | Required |
| license | The license type. Possible values are: TRIAL, CUSTOMER. | Required |
| customer_domain | The domain of the customer. | Required |
| keywords | A comma-separated list of monitoring keywords. | Optional |
| contract_end_date | The end of the contract, for example 2027-12-31. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.Customer.CustomerName | String | The customer name. |
| ThreatMon.Customer.License | String | The license type. |
| ThreatMon.Customer.Domain | String | The domain of the customer. |

#### Command example

```!threatmon-customer-create customer_name="Example Corp" license=TRIAL customer_domain=example.com keywords=example contract_end_date=2027-12-31```

#### Context Example

```json
{
    "ThreatMon": {
        "Customer": {
            "CustomerName": "Example Corp",
            "License": "TRIAL",
            "Domain": "example.com",
            "Keywords": [
                "example"
            ],
            "ContractEndDate": "2027-12-31T00:00:00.000000Z"
        }
    }
}
```

#### Human Readable Output

>The ThreatMon customer Example Corp was created.

### threatmon-customer-update

***
Changes the license, the domain or the contract end date of a customer in a ThreatMon MSSP account. Requires the API key of the MSSP administrator account.

#### Base Command

`threatmon-customer-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_name | The customer to change. | Required |
| license | The new license type. Possible values are: TRIAL, CUSTOMER. | Optional |
| customer_domain | The new domain of the customer. | Optional |
| contract_end_date | The new end of the contract, for example 2027-12-31. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!threatmon-customer-update customer_name="Example Corp" license=CUSTOMER```

#### Human Readable Output

>The ThreatMon customer Example Corp was updated.

### threatmon-customer-delete

***
Deletes a customer from a ThreatMon MSSP account. The change is applied at once and cannot be undone. Requires the API key of the MSSP administrator account.

#### Base Command

`threatmon-customer-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_name | The customer to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!threatmon-customer-delete customer_name="Example Corp"```

#### Human Readable Output

>The ThreatMon customer Example Corp was deleted.

### threatmon-customer-keyword-add

***
Adds a monitoring keyword to a customer of a ThreatMon MSSP account. Requires the API key of the MSSP administrator account.

#### Base Command

`threatmon-customer-keyword-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_name | The customer. | Required |
| keyword | The keyword to add. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!threatmon-customer-keyword-add customer_name="Example Corp" keyword=examplebrand```

#### Human Readable Output

>The keyword examplebrand was added to the ThreatMon customer Example Corp.

### threatmon-customer-keyword-remove

***
Removes a monitoring keyword from a customer of a ThreatMon MSSP account. Requires the API key of the MSSP administrator account.

#### Base Command

`threatmon-customer-keyword-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_name | The customer. | Required |
| keyword | The keyword to remove. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!threatmon-customer-keyword-remove customer_name="Example Corp" keyword=examplebrand```

#### Human Readable Output

>The keyword examplebrand was removed from the ThreatMon customer Example Corp.

### threatmon-website-url-submit

***
Reports files and directories found on the company websites, so ThreatMon monitors them. The website of each URL must already be a ThreatMon asset.

#### Base Command

`threatmon-website-url-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urls | A comma-separated list of full URLs (at most 1000), for example https://www.example.com/backup/db.zip. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.WebsiteURL.URL | String | The submitted URL. |
| ThreatMon.WebsiteURL.NormalizedURL | String | The URL as ThreatMon stored it. |
| ThreatMon.WebsiteURL.Status | String | The result: INSERTED, UPDATED or FAILED. |
| ThreatMon.WebsiteURL.Reason | String | Why the URL failed. |

#### Command example

```!threatmon-website-url-submit urls=https://www.example.com/backup/db.zip,https://shop.example.net/admin/```

#### Context Example

```json
{
    "ThreatMon": {
        "WebsiteURL": [
            {
                "URL": "https://www.example.com/backup/db.zip",
                "NormalizedURL": "https://www.example.com:443/backup/db.zip",
                "Status": "INSERTED"
            },
            {
                "URL": "https://shop.example.net/admin/",
                "Status": "FAILED",
                "Reason": "Website https://shop.example.net:443 is not registered as an asset for this company."
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatMon Website URL Submission
>
>|Failed|Inserted|Received|Updated|
>|---|---|---|---|
>| 1 | 1 | 2 | 0 |
>
>### Results
>
>|URL|Status|Reason|
>|---|---|---|
>| https://www.example.com/backup/db.zip | INSERTED |  |
>| https://shop.example.net/admin/ | FAILED | Website https://shop.example.net:443 is not registered as an asset for this company. |

### get-remote-data

***
Gets the latest status of a mirrored alarm. This command is used by mirroring and for debugging; it does not update the current incident.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The alarm code. | Required |
| lastUpdate | Retrieves changes made after this time. | Required |

#### Context Output

There is no context output for this command.

### get-modified-remote-data

***
Gets the alarms that changed since the last update. This command is used by mirroring and for debugging.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | A date string. Only alarms changed after this time are returned. | Optional |

#### Context Output

There is no context output for this command.

### update-remote-system

***
Updates the ThreatMon alarm with the changes of the mirrored incident. This command is used by mirroring and for debugging; it does not update the current incident.

#### Base Command

`update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### get-mapping-fields

***
Returns the ThreatMon fields that outgoing mirroring can update.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and ThreatMon alarms (available from Cortex XSOAR version 6.0.0). Mirroring is available in Cortex XSOAR only; in Cortex XSIAM the mirroring parameters are hidden.

1. Enable **Fetching incidents** in your instance configuration.
2. In **Incident Mirroring Direction**, select **Incoming**, **Outgoing** or **Incoming And Outgoing**.
3. Optional: select **Close Mirrored Cortex Incident** to close an incident when its alarm is set to *Resolved* or *Ignore* in ThreatMon, and to reopen it when the alarm is opened again.
4. Optional: select **Close Mirrored ThreatMon Alarm** to set the alarm to *Resolved* when the incident is closed, or to *Ignore* when the close reason is *False Positive* or *Duplicate*.

The mirrored field is **ThreatMon Status**. Incoming changes add a note to the incident, once per status change. Changes made by the integration itself are not mirrored back.

Newly fetched incidents are mirrored in the chosen direction. Changing the direction does not affect existing incidents.

**Important note:** to ensure mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and ThreatMon. The pack includes the **ThreatMon - Incoming Mapper** and the **ThreatMon - Outgoing Mapper**.

## Troubleshooting

| Message | Cause and fix |
| --- | --- |
| ThreatMon rejected the API key | The External API Key is wrong or was renewed. When Customer Name (MSSP) is set, check that it is the exact name of a sub company. |
| This server's public IP address is not whitelisted | Send the public IP address of the Cortex server or engine to support@threatmonit.io. |
| The request was blocked by the ThreatMon firewall (error code 1010) | A proxy changes the request headers. Allow the request unchanged, or contact support@threatmonit.io. |
| ThreatMon did not allow this request for the API key (API key is not whitelisted) | The customer management commands need the External API Key of the MSSP administrator account. |
| ThreatMon rejected the API key, with Customer Name (MSSP) set | Check that the name is exactly the sub company name in ThreatMon. ThreatMon currently rejects sub company names that contain a space; contact support@threatmonit.io for such a sub company. |
| The ThreatMon rate limit was exceeded | ThreatMon allows 10 requests in 10 seconds. The integration paces and retries its requests; run the command again in a minute. |
