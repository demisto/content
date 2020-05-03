This playbook processes indicators to check if they exist in a Cortex XSOAR list containing the organizational External IP addresses, and tags the indicators accordingly.

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
|  |  |  |  | Optional |
| OrganizationsExternalIPListName | A Cortex XSOAR list containing the organization&\#x27;s External IP address values. IP Indicators that appear in the list are tagged as organizations external ip. | {} |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| OrganizationExternalIP | IP addresses that are found in the  organization&\#x27;s external IP list. | string |
| NotOrganizationExternalIP | IP addresses that are not found in the organization&\#x27;s external IP list. | string |

![TIM - Process Indicators Against Organizations External IP List](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/TIM_-_Process_Indicators_Against_Organizations_External_IP_List.png)