This playbook processes CIDR indicators of both IPV4 and IPV6. By specifying in the inputs the maximum number of hosts allowed per CIDR, the playbook tags any CIDR that exceeds the number as pending_review. If the maximum CIDR size is not specified in the inputs, the playbook does not run.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin

### Scripts
This playbook does not use any scripts.

### Commands
* appendIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
|  |  |  |  | Optional |
| MaximumHostSizePermitted | The maximum number of hosts that a CIDR can contain for auto approval. If the number of hosts is greater than approved, the CIDR is tagged for manual review. |  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

![TIM - Process CIDR Indicators By Size](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/TIM_-_Process_CIDR_Indicators_By_Size.png)