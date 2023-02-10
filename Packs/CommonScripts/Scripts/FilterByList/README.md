Checks whether the specified item is in a list. The default list is the XSOAR Indicators Whitelist.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Tags | whitelist |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* TIM - Process Domain Registrant With Whois
* TIM - Process Indicators Against Approved Hash List
* TIM - Process Indicators Against Business Partners Domains List
* TIM - Process Indicators Against Business Partners IP List
* TIM - Process Indicators Against Business Partners URL List

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| values | The item to look for in the list. |
| listname | Name of the list against which to check the value. The default is the Indicators Whitelist. |
| ignorecase | Whether to ignore the case of the item for which you are searching. Default is "No". |
| matchexact | Whether to match the exact item in the list, or look for any string that contains it. Default is "No". |
| delimiter | A one-character string used to delimit fields. For example, a comma "," should match the list separator configuration. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| List.ListName | The name of the list you compared with. | string |
| List.In | The list of items in the list. | Unknown |
| List.NotIn | The list of items not in the list. | Unknown |
