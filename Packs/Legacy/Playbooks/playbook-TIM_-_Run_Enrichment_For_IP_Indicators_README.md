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
* integration-Cylance_Protect
* integration-Wildfire
* SecBI
* integration-PhishMe
* SecurityAdvisor
* SlashNextPhishingIncidentResponse
* integration-ArcSightESM
* integration-CveInfo
* PaloAltoNetworksCortex
* integration-LightCyberMagna
* integration-jira
* integration-DemistoLocking
* integration-Malwr
* AzureCompute
* AzureSecurityCenter
* integration-MISP
* AzureSecurityCenter_v2
* cisco-ise
* integration-DemistoRESTAPI
* integration-secdo
* integration-Mimecast
* RiskSense
* Panorama
* integration-KeyLight
* integration-SymantecEndpointProtectionDeprecated
* integration-Kenna
* integration-Intezer
* BPA
* AzureCompute_v2
* Flashpoint
* integration-PostgreSQL
* integration-opswat-metadefender
* integration-Mimecast-Auth
* integration-Lastline
* integration-Shodan
* PaloAltoNetworks_Traps
* PaloAlto_MineMeld
* integration-AlienVaultOTX
* integration-aws
* PaloAltoNetworks_PAN_OS_EDL_Management
* integration-ProofpointTAP
* ExtraHop
* integration-Pwned

### Scripts
This playbook does not use any scripts.

### Commands
* ip

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

![TIM - Run Enrichment For IP Indicators](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/TIM_-_Run_Enrichment_For_IP_Indicators.png)