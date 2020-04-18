This playbook queries indicators based on a pre-defined query or results from a parent playbook, and adds the resulting indicators to an ArcSight Active List. The Active List ID should also be defined in the playbook inputs, as well as the field name in the Active list to add to.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* ArcSight ESM v2
* Builtin

### Scripts
This playbook does not use any scripts.

### Commands
* appendIndicatorField
* as-add-entries

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| ArcSightBlackListDomainActiveListID | ID of the black list Domain Active List resource as it appears in ArcSight. |  |  | Optional |
| ArcsightBlackDomainValueFieldName | The name of the black list Active List field to insert the Domain value to. |  |  | Optional |
| ArcSightWhiteListDomainActiveListID | ID of the white list Domain Active List resource as appears in ArcSight. |  |  | Optional |
| ArcsightWhiteListDomainValueFieldName | The name of the white list Active List field to insert the Domain value to. |  |  | Optional |
| ArcSightWatchListDomainActiveListID | ID of the watch list Domain Active List resource as appears in ArcSight. |  |  | Optional |
| ArcsightWatchListDomainValueFieldName | The name of the watch list Active List field to insert the Domain value to. |  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

![TIM - ArcSight Add Domain Indicators](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/TIM_-_ArcSight_Add_Domain_Indicators.png)