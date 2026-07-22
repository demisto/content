Enrich File hashes using RST Threat Feed integrations

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* RST Cloud - Threat Feed API

### Scripts
This playbook does not use any scripts.

### Commands
* file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | The Files to enrich. | File | Required |
| threshold | Defines the minimum score to set indicators as malicious | inputs.threshold | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The File objects. | unknown |
| DBotScore | Indicator, Score, Type, and Vendor. | unknown |

