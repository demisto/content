This playbook uses several sub playbooks to process and tag indicators, which is used to identify indicators that shouldn't be added to block list. For example IP indicators that belong to business partners or important hashes. Additional sub playbooks can be added for improving the business logic and tagging according to the user's needs. This playbook doesn't have its own indicator query as it processes indicators provided by the parent playbook query. To enable the playbook, provide the relevant list names in the sub playbook indicators, such as the ApprovedHashList, OrganizationsExternalIPListName, BusinessPartnersIPListName, etc. Also be sure to append the results of additional sub playbooks to Set indicators to Process Indicators for the additional playbooks results to be in the outputs.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* TIM - Process File Indicators With File Hash Type
* TIM - Process Indicators Against Business Partners Domains List
* TIM - Process CIDR Indicators By Size
* TIM - Process Domains With Whois
* TIM - Process Indicators Against Business Partners URL List
* TIM - Process Indicators Against Business Partners IP List
* TIM - Process Indicators Against Approved Hash List
* TIM - Process Indicators Against Organizations External IP List

### Integrations
This playbook does not use any integrations.

### Scripts
* SetAndHandleEmpty

### Commands
This playbook does not use any commands.

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ProcessedIndicators | The outputs of this playbook are tagged for manual review in the parent playbook or tagged using approved_block, approved_allow etc. | string |

## Playbook Image
---
![TIM - Indicator Auto Processing](https://raw.githubusercontent.com/demisto/content/af0957a7f2d6633bfd8e0083d70809463313ca66/Packs/TIM_Processing/doc_files/TIM_-_Indicator_Auto_Processing.png)
