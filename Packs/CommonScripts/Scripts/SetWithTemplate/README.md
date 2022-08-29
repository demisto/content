Set a value built by a template in context under the key you entered.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| key | The key to set. Can be a full path such as "Key.ID". If using append=true can also use a DT selector such as "Data\(val.ID == obj.ID\)". |
| template | The template text which can include DT expressions sush as $\{value\}. |
| append | If false then the context key will be overwritten. If set to true then the script will append to existing context key. |
| stringify | Whether to save the argument as a string. The default value is "false". |
| force | Whether to force the creation of the context. The default value is "false". |
| context | The context data which overwrites the demisto context. |
| variable_markers | The pair of start and end markers to bracket a variable name |
| keep_symbol_to_null | Set to true not to replace a value if the variable is null, otherwise false. |

## Outputs
---
There are no outputs for this script.
