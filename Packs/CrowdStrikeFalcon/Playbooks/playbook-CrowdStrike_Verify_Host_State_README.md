The playbook verifies and sets the actions of the policy applied by CrowdStrike Falcon

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| PolicyBehaviourDetails | The path that contains the detection results. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Policy.State | Is the policy active? | string |
| Host.State | Is the host isolated? | string |
| Process.State | Was the process contained? | string |

## Playbook Image
---
![CrowdStrike Verify Host State](../doc_files/CrowdStrike_Verify_Host_State.png)