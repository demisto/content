Enrich domains using RST Threat Feed integration

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* RST Cloud - Threat Feed API

### Scripts
This playbook does not use any scripts.

### Commands
* domain

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain | The domain name to enrich. | Domain.Name | Required |
| threshold | Defines the minimum score to set indicators as malicious | inputs.threshold | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain | The domain objects. | unknown |
| DBotScore | Indicator, Score, Type, and Vendor. | unknown |

