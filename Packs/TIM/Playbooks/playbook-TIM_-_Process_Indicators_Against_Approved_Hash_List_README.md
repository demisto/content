This playbook checks if file hash indicators exist in a Cortex XSOAR list. If the indicators exist in the list, they are tagged as approved_hash.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin

### Scripts
* SetAndHandleEmpty
* FilterByList

### Commands
* appendIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| ApprovedHashList | A Cortex XSOAR list containing approved hash values. Hash indicators that appear in the list are tagged as approved. |  |  | Optional |
|  |  |  |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HashesInApprovedList | File hashes that are found in the approved\_hash list. | string |
| HashesNotInApprovedList | File hashes that are not found in the approved\_hash list. | string |

![TIM - Process Indicators Against Approved Hash List](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/TIM_-_Process_Indicators_Against_Approved_Hash_List.png)