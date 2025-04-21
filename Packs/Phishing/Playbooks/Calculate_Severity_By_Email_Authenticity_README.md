Calculates the severity according to the verdict coming from the `CheckEmailAuthenticity` script.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
This playbook does not use any integrations.

## Scripts
* Set

## Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| EmailAuthenticityCheck | The verdict regarding the authenticity of the investigated email. Returned from `CheckEmailAuthenticity script`. | AuthenticityCheck | Email | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Severities.EmailAuthenticitySeverity | The maliciousness score evaluated by the `Calculate Severity - Email Authenticity` playbook. | number |

## Playbook Image
---
![Calculate_Severity_By_Email_Authenticity](../doc_files/Calculate_Severity_By_Email_Authenticity.png)
