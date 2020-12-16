This playbook collects IOCs from known sources that relate to SolarStorm and SUNBURST. 
The playbook will hunt the IOCs across the organization using EDR platforms for endpoints and Panorama for network activity.
Lastly, the playbook will mitigate the threat by isolating the compromised hosts and blocking the indicators across the organization network.

Note: This is a beta pack, which lets you implement and test pre-release software. Since the pack is beta, it might contain bugs. Updates to the pack during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the pack to help us identify issues, fix them, and continually improve.


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