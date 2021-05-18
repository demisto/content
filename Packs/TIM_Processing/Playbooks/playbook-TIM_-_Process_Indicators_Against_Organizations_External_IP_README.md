This playbook processes indicators to check if they exist in a Cortex XSOAR list containing the organizational External IP addresses, and tags the indicators accordingly.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* FilterByList
* SetAndHandleEmpty

### Commands
* appendIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| OrganizationsExternalIPListName | A Cortex XSOAR list containing the organization's External IP address values. IP Indicators that appear in the list are tagged as organizations external ip. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| OrganizationExternalIP | IP addresses that are found in the  organization's external IP list. | string |
| NotOrganizationExternalIP | IP addresses that are not found in the organization's external IP list. | string |

## Playbook Image
---
![Playbook Image](https://raw.githubusercontent.com/demisto/content/0ce0007e6dcec27648d6dd4d30a432de945681f1/Packs/TIM_Processing/doc_files/TIM_-_Process_Indicators_Against_Organizations_External_IP_List.png)