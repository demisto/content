This playbook checks for WildFire verdict and submits a flip-verdict request if the file found as benign.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* core-report-incorrect-wildfire

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileHash | The file hash. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore | The Indicator's object | unknown |

## Playbook Image
---
![Get WildFire Verdict](../doc_files/Get_WildFire_Verdict.png)