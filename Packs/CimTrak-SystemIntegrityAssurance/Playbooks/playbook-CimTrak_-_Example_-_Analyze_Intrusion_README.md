

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CimTrak

### Scripts
This playbook does not use any scripts.

### Commands
* compliance-scan-with-summary
* get-objects
* add-hash-allow-list
* add-hash-deny-list
* file-analysis-by-objectdetail-id
* promote-authoritative-baseline-files

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| lObjectDetailID |  | ${incident.labels.objectDetailId} | Optional |
| lParentID |  | ${incident.labels.parentId} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

