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

![Calculate_Severity_By_Email_Authenticity](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Calculate_Severity_By_Email_Authenticity.png)
