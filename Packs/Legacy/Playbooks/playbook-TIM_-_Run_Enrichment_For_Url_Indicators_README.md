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
* integration-Malwr
* integration-aws
* integration-Mimecast
* integration-KeyLight
* AzureSecurityCenter_v2
* SlashNextPhishingIncidentResponse
* Panorama
* RiskSense
* SecurityAdvisor
* integration-Shodan
* integration-AlienVaultOTX
* integration-SymantecEndpointProtectionDeprecated
* PaloAltoNetworksCortex
* PaloAlto_MineMeld
* integration-Intezer
* ExtraHop
* integration-jira
* integration-Cylance_Protect
* AzureSecurityCenter
* integration-MISP
* integration-CveInfo
* integration-PhishMe
* integration-DemistoRESTAPI
* Flashpoint
* integration-opswat-metadefender
* integration-Mimecast-Auth
* integration-Lastline
* integration-Pwned
* integration-Kenna
* integration-ArcSightESM
* PaloAltoNetworks_Traps
* integration-LightCyberMagna
* integration-Wildfire
* integration-ProofpointTAP

### Scripts
This playbook does not use any scripts.

### Commands
* url

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| EnrichBadIndicators | Enter a value of True to enrich indicators whose reputation from the feed is bad. |  | Optional |
| EnrichGoodIndicators | Enter a value of True to enrich indicators whose reputation from the feed is good. |  | Optional |
| EnrichSuspiciousIndicators | Enter a value of True to enrich indicators whose reputation from the feed is suspicious. |  | Optional |
| EnrichUnknownIndicators | Enter a value of True to enrich indicators whose reputation from the feed is unknown. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

![TIM - Run Enrichment For Url Indicators](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/TIM_-_Run_Enrichment_For_Url_Indicators.png)