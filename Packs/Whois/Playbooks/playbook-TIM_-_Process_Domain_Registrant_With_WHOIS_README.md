This playbook runs the whois enrichment on domain indicators provided by an indicator query such as "type:Domain". The playbook then compares the domain registrant against the Cortex XSOAR list provided in the inputs.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Whois

### Scripts
* FilterByList
* SetAndHandleEmpty

### Commands
* whois

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| ApprovedRegistrantListName | The Cortex XSOAR list name that contains the approved registrars.  A registrant is the company or entity  that owns the domain. |  | Optional |
| RegistrarListDelimiter | A one\-character string used to delimit fields. This must match the value that you defined in the list separator server configuration.  
The default value is a comma, however, as registrars might contain the "," character in their name, 
Cortex XSOAR recommends that you select a different delimiter. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NonApprovedDomains | Domains for which the registrar isn't approved. | string |
| ApprovedDomains | Domains for which the registrar is approved. | string |
| DomainsNotResolvedByWhois | Domains which Whois wasn't able to resolve. | string |

<!-- Playbook PNG image comes here -->