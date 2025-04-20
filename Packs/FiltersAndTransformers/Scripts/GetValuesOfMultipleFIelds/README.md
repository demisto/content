The script receives a list of fields and a context key base path. For example, Key=Test.result List=username,user and will get all of the values from Test.result.username and Test.result.user.
The Get field of the task must have the value ${.=[]}.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| key | The base context path under which to find the fields. For example Test.Results. |
| list | The list of fields to retrieve from context. The list can contain comma seperated values. For example key1,key1 |
| value | The value to set in context for the key. |

## Outputs
---
There are no outputs for this script.
