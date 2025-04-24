Set a value in context under the key you entered. If no value is entered, the script doesn't do anything.

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: For Cortex XSOAR 6, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations for Cortex XSOAR 8 Cloud, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script for Cortex XSOAR 8 On-prem, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
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
