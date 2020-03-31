Enriches domains using one or more integrations.

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

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| Domain | The domain name to enrich. | Name | Domain | Optional |
| GetReputation | Whether the playbook should get the reputation for the domain. | True | - | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain | The domain objects. | unknown |
| DBotScore | The indicator, score, type, and vendor. | unknown |

![Domain_Enrichment_Generic](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Domain_Enrichment_Generic.png)
