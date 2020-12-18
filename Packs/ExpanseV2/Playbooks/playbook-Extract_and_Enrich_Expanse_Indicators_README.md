  Subplaybook for Handle Expanse Incident playbooks.
  Extract and Enrich Indicators (CIDRs, IPs, Certificates, Domains and DomainGlobs) from Expanse Incidents.
  Enrichment is performed via enrichIndicators command and generic playbooks.
  Returns the enriched indicators.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* IP Enrichment - Generic v2
* Domain Enrichment - Generic v2

### Integrations
* ExpanseV2

### Scripts
* GetDomainDNSDetails
* SetAndHandleEmpty

### Commands
* createNewIndicator
* expanse-get-domain
* expanse-get-iprange
* enrichIndicators
* expanse-get-certificate

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
![Extract and Enrich Expanse Indicators](https://raw.githubusercontent.com/demisto/content/cfcd4dbc38cc4ec560202da62750c73c9452b553/Packs/ExpanseV2/Playbooks/playbook-Extract_and_Enrich_Expanse_Indicators.png)