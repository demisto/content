This playbook processes indicators by enriching indicators
based on the indicator feed's reputation, as specified in the playbook
inputs. This playbook needs to be used with caution as it might use up the user
enrichment integration's API license when running enrichment for large amounts of
indicators.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Cymon
* Cylance_Protect
* Wildfire
* SecBI
* PhishMe
* SecurityAdvisor
* SlashNextPhishingIncidentResponse
* ArcSightESM
* CveInfo
* PaloAltoNetworksCortex
* LightCyberMagna
* jira
* DemistoLocking
* Malwr
* AzureCompute
* AzureSecurityCenter
* MISP
* AzureSecurityCenter_v2
* cisco-ise
* DemistoRESTAPI
* secdo
* Mimecast
* RiskSense
* Panorama
* KeyLight
* SymantecEndpointProtectionDeprecated
* Kenna
* Intezer
* BPA
* AzureCompute_v2
* Flashpoint
* PostgreSQL
* opswat-metadefender
* Mimecast-Auth
* Lastline
* Shodan
* PaloAltoNetworks_Traps
* PaloAlto_MineMeld
* AlienVaultOTX
* aws
* PaloAltoNetworks_PAN_OS_EDL_Management
* ProofpointTAP
* ExtraHop
* Pwned

### Scripts
This playbook does not use any scripts.

### Commands
* ip

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| EnrichBadIndicators | Enter a value of true to enrich indicators whose reputation from the feed is bad. |  | Optional |
| EnrichGoodIndicators | Enter a value of true to enrich indicators whose reputation from the feed is good. |  | Optional |
| EnrichSuspiciousIndicators | Enter a value of true to enrich indicators whose reputation from the feed is suspicious. |  | Optional |
| EnrichUnknownIndicators | Enter a value of true to enrich indicators whose reputation from the feed is unknown. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Playbook Image](https://raw.githubusercontent.com/demisto/content/0ce0007e6dcec27648d6dd4d30a432de945681f1/Packs/TIM_Processing/doc_files/TIM_-_Run_Enrichment_For_IP_Indicators.png)