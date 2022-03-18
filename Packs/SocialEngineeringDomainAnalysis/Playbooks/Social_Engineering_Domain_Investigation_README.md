Enrich and Investigate domains which may present a social engineering threat to your organization. Review before blocking potentially dangerous indicators.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Social Engineering Domain Enrichment

### Integrations
This playbook does not use any integrations.

### Scripts
* ConvertTableToHTML

### Commands
* setIndicator
* extractIndicators

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SocialEngineeringDomainList | The CSV list of domains to test or array of domains | ${incident.socialengineeringdomainanalysislist} | Optional |
| SocialEngineeringRegisteredDomain | Your company domain | ${incident.socialengineeringdomainanalysisregistereddomain} | Optional |
| BadNameservers | An XSOAR BadNameserver list. This should be a CSV list with a single column and the header of "nameserver"<br/><br/>Example List Contents:<br/><br/>nameserver<br/>badnameserver1.com<br/>badnameserver2.com |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
