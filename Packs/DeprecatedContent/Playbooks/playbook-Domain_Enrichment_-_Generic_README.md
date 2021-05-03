Deprecated. Use "Domain Enrichment - Generic v2" playbook instead. Enrich Domain using one or more integrations.
Domain enrichment includes:
* Domain reputation
* Threat information

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* VirusTotal - Private API

### Scripts
* DomainReputation

### Commands
* vt-private-get-domain-report

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain | The domain name to enrich | Domain.Name | Optional |
| GetReputation | Should the playbook get reputation for the Domain | True | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain | The domain objects | unknown |
| DBotScore | Indicator, Score, Type, Vendor | unknown |

## Playbook Image
---
![Domain Enrichment - Generic](Insert the link to your image here)