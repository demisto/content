This playbook processes indicators to check if they exist in a Cortex XSOAR list containing business partner IP addresses, and tags the indicators accordingly.

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
| Indicator Query | Indicators matching the indicator query will be used as playbook input | type:ip | Optional |
| BusinessPartnersIPListName | A Cortex XSOAR list containing business partner IP address values. IP Indicators that appear in the list are tagged as business partner ip. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BusinessPartnerIP | IP addresses that are found in the business partner ip list. | string |
| NotBusinessPartnerIP | IP addresses that are not found in the business partner ip list. | string |

## Playbook Image
---
![Playbook Image](../doc_files/TIM_-_Process_Indicators_Against_Business_Partners_IP_List.png)