This playbook uses several sub playbooks to process and tag indicators based on the results of the Whois tool.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* TIM - Process Domain Age With Whois
* TIM - Process Domain Registrant With Whois

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* whois

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| CheckForWhoisRegistrant | Setting this input as True will run the TIM \- Process Domain registrant With Whois playbook. | True | Optional |
| CheckForWhoisDomainAgeCreation | Setting this input as True will run the TIM \- Process Domain Creation Age With Whois playbook. | True | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DomainsNotApproved | Domains for which the registrant isn't approved. | string |
| ApprovedRegistrantDomains | Domains for which the registrant is approved. | string |
| DomainsNotResolvedByWhois | Domains Not Resolved By Whois. | string |
| NewDomains | Domains whose create value is after the tested date. | string |
| NotNewDomains | Domains whose create value is before the tested date. | string |
| DomainsNotProcessed | Domains that could not be processed for any reason are outputted to this context path. | string |

## Playbook Image
---
![TIM - Process Domains With Whois](../doc_files/TIM_-_Process_Domains_With_Whois.png)