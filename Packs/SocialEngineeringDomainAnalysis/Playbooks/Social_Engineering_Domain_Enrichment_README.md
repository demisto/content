Enrich a domain and compare against your registered domain for potential social engineering against your organization.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Rasterize

### Scripts
* GetStringsDistance
* AddDBotScoreToContext
* GetListRow
* DeleteContext
* GetDomainDNSDetails

### Commands
* setIndicator
* rasterize
* enrichIndicators
* whois
* createNewIndicator

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RegisteredDomain | Your company domain to use for checking if potential InputDomains are potentially used for typosquatting and other similar domain attacks. | paloaltonetworks.com | Optional |
| InputDomain | The potentially malicious domain to check | palonetworks.com | Optional |
| BadNameservers | The csv of known bad nameservers<br/><br/>Example:<br/><br/>nameserver<br/>examplenameserver1<br/>examplenameserver2<br/>examplenameserver3 | BadNameservers | Optional |
| LevenshteinDistance | The Levenshtein distance to consider close. Lower scores mean strings are more similar | 10 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
