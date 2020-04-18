This playbook processes indicators to check if they exist in a Cortex XSOAR list containing business partner urls, and tags the indicators accordingly. To enable the playbook, provide a Cortex XSOAR list name containing business partner urls.

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
| BusinessPartnersUrlListName | A Cortex XSOAR list containing business partner url values. Url Indicators that appear in the list are tagged as business partners. |  |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BusinessPartnerUrl | URLs that are found in the business partner url list. | string |
| NotBusinessPartnerUrl | URLs that are not found in the business partner url list. | string |

![TIM - Process Indicators Against Business Partners URL List](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/TIM_-_Process_Indicators_Against_Business_Partners_URL_List.png)