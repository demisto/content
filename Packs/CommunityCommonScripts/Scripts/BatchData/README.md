This Automation takes in a string of comma separated items and returns a dictionary of with the defined chunk size. 

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| batch_size | number of items that will be returned in each dictionary items \(must be of type int\) |
| data | comma separated list of items |
| context_path | This nest the path under BatchedData in context. If you are running this script multiple times/simultaneously in a playbook, your  data will be over written. |

## Outputs
---
There are no outputs for this script.
