Joining values by index from 2 list according to a given format.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| list1 | The first list. List must be at same size as list2. |
| format | A format to join strings by, for example- \{1\}-\{2\} will take values in the same index of both list, <br/>where the \{1\} will be replaced with the value from list1 and \{2\} will be replaced with the value from list2. |
| list2 | The second list. List must be at same size as list1. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| zipped_list | A list of joined values by the format given. | string |
