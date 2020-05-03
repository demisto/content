This playbook receives indicators from its parent playbook and provides the indicators as inputs for the sub-playbooks that push the indicators to SIEM.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin
* ArcSight ESM v2

### Scripts
This playbook does not use any scripts.

### Commands
* appendIndicatorField
* as-add-entries

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| ArcSightBlackListIPActiveListID | ID of the black list IP Active List resource as appears in ArcSight. |  |  | Optional |
| ArcsightBlackIPValueFieldName | The name of the black list Active List field to insert the IP value to. |  |  | Optional |
| ArcSightWhiteListIPActiveListID | ID of the white list IP Active List resource as appears in ArcSight. |  |  | Optional |
| ArcsightWhiteListIPValueFieldName | The name of the white list Active List field to insert the IP value to. |  |  | Optional |
| ArcSightWatchListIPActiveListID | ID of the watch list IP Active List resource as appears in ArcSight. |  |  | Optional |
| ArcsightWatchListIPValueFieldName | The name of the watch list Active List field to insert the IP value to. |  |  | Optional |
|  |  |  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

![TIM - ArcSight Add IP Indicators](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/TIM_-_ArcSight_Add_IP_Indicators.png)