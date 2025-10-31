This automation is for comparing array(list) data of context to existing lists on XSOAR server. You can avoid using loop of sub-playbook.
inputArray: the context array/list data
listName: the XSOAR system list.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Condition |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| searchString | the string to look for |
| listName | the XSOAR system list name. |
| caseInsensitive |  Set to "true" to ignore case when matching. Default is "false". |
| useWildcard |  Set to "true" to enable \* and ? wildcard matching. Default is "false". |

## Outputs

---
There are no outputs for this script.
