Set a value in context under the key you entered. If no value is entered, the script doesn't do anything.

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here:
https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/playbooks/automations.html

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| key | The key to set in context. |
| value | The value of the key to set in context. The value is usually a DQ expression. Can be an array. |
| append | Whether to append the new context key to the existing context key. If "false", then the existing context key will be overwritten with the new context key. |
| stringify | Whether to save the argument as a string. The default value is "false". |
| force | Whether to force the creation of the context. The default value is "false". |

## Outputs
---
There are no outputs for this script.
