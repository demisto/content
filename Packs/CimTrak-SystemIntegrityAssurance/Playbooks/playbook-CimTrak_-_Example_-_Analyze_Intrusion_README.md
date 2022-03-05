

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CimTrak

### Scripts
This playbook does not use any scripts.

### Commands
* promote-authoritative-baseline-files
* file-analysis-by-objectdetail-id
* add-hash-allow-list
* get-objects
* compliance-scan-with-summary
* add-hash-deny-list

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

## Playbook Image
---
![CimTrak - Example - Analyze Intrusion](Insert the link to your image here)