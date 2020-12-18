Subplaybook for Handle Expanse Incident playbooks.
Extract and Enrich Indicators (CIDRs, IPs, Certificates, Domains and DomainGlobs) from Expanse Incidents.
Enrichment is performed via enrichIndicators command and generic playbooks.
Returns the enriched indicators.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Domain Enrichment - Generic v2
* IP Enrichment - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* expanse-get-iprange
* expanse-get-certificate
* enrichIndicators
* expanse-get-domain
* createNewIndicator

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Expanse Assets | Expanse Assets to Extract and Enrich. | incident.expanseasset | Optional |
| Create Indicators | Create Indicators for types that are not handled by AutoExtract, such as Certificates, Domains and DomainGlobs. | true | Optional |
| Expanse IP | IP from the Expanse Incident. | incident.expanseip | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Expanse.Certificate | Expanse Certificate Information | unknown |
| Expanse.IPRange | Expanse IP Range | unknown |
| Domain | The domain objects. | unknown |
| DBotScore | Indicator, Score, Type, and Vendor. | unknown |
| IP | The IP objects | unknown |
| Endpoint | The Endpoint's object | unknown |
| Expanse.Domain | Expanse Domain | unknown |
| DomainDNSDetails | Domain DNS Details | Unknown |

## Playbook Image
---
![Extract and Enrich Expanse Indicators](Insert the link to your image here)