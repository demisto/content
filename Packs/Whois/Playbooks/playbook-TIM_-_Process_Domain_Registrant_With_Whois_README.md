This playbook runs the whois enrichment on domain indicators provided by an indicator query such as "type:Domain". The playbook then compares the domain registrant against the Cortex XSOAR list provided in the inputs. A registrant is the company or entity that owns the domain.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* SetAndHandleEmpty
* FilterByList

### Commands
* whois

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input. |  | Optional |
| ApprovedregistrantsListName | The Cortex XSOAR list name that contains the approved registrars.  A registrant is the company or entity  that owns the domain. |  | Optional |
| registrantListDelimiter | A one\-character string used to delimit fields. This must match the value that you defined in the list separator server configuration.
The default value is a comma, however, as registrants might contain the "," character in their name,
Cortex XSOAR recommends that you select a different delimiter. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DomainsNotApproved | Domains for which the registrant isn't approved. | string |
| ApprovedDomains | Domains for which the registrant is approved. | string |
| DomainsNotResolvedByWhois | Domains which Whois wasn't able to resolve. | string |

## Playbook Image
---
![Playbook Image](https://raw.githubusercontent.com/demisto/content/9d1fb26ca3d7b801b27b8e892f09bf97885a7274/Packs/Whois/doc_files/TIM_-_Process_Domain_registrant_With_Whois.png)
