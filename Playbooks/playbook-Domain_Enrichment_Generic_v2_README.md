Enriches domains using one or more integrations.

Domain enrichment includes:
* Threat information

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* VirusTotal - Private API

### Scripts
This playbook does not use any scripts.

### Commands
* vt-private-get-domain-report
* umbrella-domain-categorization

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| Domain | The domain name to enrich. | Name | Domain | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain | The domain objects. | unknown |
| DBotScore | The indicator, score, type, and vendor. | unknown |

![Domain_Enrichment_Generic_v2](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Domain_Enrichment_Generic_v2.png)
