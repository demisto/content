This playbook does the following:

Collect indicators to aid in your threat hunting process.
- Retrieve IOCs of FireEye red team tools.
- Discover IOCs of associated activity related to the infection.
- Generate an indicator list to block indicators with SUNBURST tags.

Hunt for the indicators
- Search endpoints with the FireEye red team tools CVEs.
- Search endpoint logs for FireEye red team tools hashes.
- Search and link previous incidents with the FireEye hashes.

If compromised hosts are found, fire off sub-playbooks to isolate/quarantine infected hosts/endpoints and await further actions from the security team.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Search Endpoint by CVE - Generic
* Search Endpoints By Hash - Generic V2
* Isolate Endpoint - Generic V2

### Integrations
This playbook does not use any integrations.

### Scripts
* http
* findIncidentsWithIndicator

### Commands
* extractIndicators
* enrichIndicators
* appendIndicatorField
* createNewIndicator
* cve
* closeInvestigation
* linkIncidents

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FireEyeToolsCVE  | CVE-2019-0708	,CVE-2017-11774 | CVE-2018-15961,CVE-2019-19781	,CVE-2019-3398,CVE-2019-11580	,CVE-2018-13379,CVE-2020-0688	,CVE-2019-11510,CVE-2019-0604	,CVE-2020-10189,CVE-2019-8394	,CVE-2020-1472,CVE-2018-8581	,CVE-2016-0167,CVE-2014-1812 | Optional |
| FireEyeRedTeamToolsCVEsURL | The URL of FireEye red team tools CVEs | https://github.com/fireeye/red_team_tool_countermeasures/blob/master/all-hashes.csv | Optional |
| IsolateEndpointAutomatically | Whether to automatically isolate endpoints, or opt for manual user approval. True means isolation will be done automatically. | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![FireEye Red Team Tools Investigation and Response](../doc_files/FireEye_Red_Team_Tools_Investigation_and_Response.png)