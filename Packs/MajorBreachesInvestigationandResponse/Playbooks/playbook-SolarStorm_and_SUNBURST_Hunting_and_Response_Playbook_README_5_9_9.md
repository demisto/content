This playbook does the following:

Collect indicators to aid in your threat hunting process

- Retrieve IOCs of SUNBURST (a trojanized version of the SolarWinds Orion plugin)
- Retrieve C2 domains and URLs associated with Sunburst
- Discover IOCs of associated activity related to the infection
- Generate an indicator list to block indicators with SUNBURST tags

Hunt for the SUNBURST backdoor

- Query firewall logs to detect network activity
- Search endpoint logs for Sunburst hashes to detect presence on hosts

If compromised hosts are found then:

- Notify security team to review and trigger remediation response actions
- Fire off sub-playbooks to isolate/quarantine infected hosts/endpoints and await further actions from the security team.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block Indicators - Generic v2
* Isolate Endpoint - Generic
* Palo Alto Networks - Hunting And Threat Detection
* Search Endpoints By Hash - Generic V2
* Panorama Query Logs

### Integrations
This playbook does not use any integrations.

### Scripts
* UnEscapeIPs
* UnEscapeURLs
* http

### Commands
* appendIndicatorField
* closeInvestigation
* createNewIndicator

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ThreatID | Threat IDs to hunt through NGFW Threat Logs | 86246,86237,34801,39934,58049,38399,55378,37582,36709,37781,38388,56269 | Optional |
| IsolateEndpointAutomatically | Whether to automatically isolate endpoints, or opt for manual user approval. True means isolation will be done automatically. | False | Optional |
| BlockIndicatorsAutomatically | Whether to automatically indicators involved with SolarStorm. | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![SolarStorm and SUNBURST Hunting and Response Playbook](https://raw.githubusercontent.com/demisto/content/9d5ace6b2b1c3e6d40d8a36613d83217c62ef8b6/Packs/MajorBreachesInvestigationandResponse/doc_files/SolarStorm_and_SUNBURST_Hunting_and_Response_Playbook.png)