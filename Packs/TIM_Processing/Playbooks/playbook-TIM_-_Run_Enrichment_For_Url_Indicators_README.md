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
* Malwr
* aws
* Mimecast
* KeyLight
* AzureSecurityCenter_v2
* SlashNextPhishingIncidentResponse
* Panorama
* RiskSense
* SecurityAdvisor
* Shodan
* AlienVaultOTX
* SymantecEndpointProtectionDeprecated
* PaloAltoNetworksCortex
* PaloAlto_MineMeld
* Intezer
* ExtraHop
* jira
* Cylance_Protect
* AzureSecurityCenter
* MISP
* CveInfo
* PhishMe
* DemistoRESTAPI
* Flashpoint
* opswat-metadefender
* Mimecast-Auth
* Lastline
* Pwned
* Kenna
* ArcSightESM
* PaloAltoNetworks_Traps
* LightCyberMagna
* Wildfire
* ProofpointTAP

### Scripts
This playbook does not use any scripts.

### Commands
* url

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
![Playbook Image](https://raw.githubusercontent.com/demisto/content/0ce0007e6dcec27648d6dd4d30a432de945681f1/Packs/TIM_Processing/doc_files/TIM_-_Run_Enrichment_For_Url_Indicators.png)