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

## Playbook Image
---
![Playbook Image](https://raw.githubusercontent.com/demisto/content/e92ff661c91a592df117d0e1ea7e3234568946d0/Packs/TIM/doc_files/TIM_-_Process_Indicators_Against_Organizations_External_IP_List.png)