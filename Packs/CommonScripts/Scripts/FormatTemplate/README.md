Build a text from a template which can include DT expressions.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, general |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The template text |
| ctx_demisto | \`demisto\` context: Input . \(single dot\) on \`From previous tasks\` to enable to extract the context data. |
| ctx_inputs | \`inputs\` context: Input 'inputs' \(no quotation\) on \`From previous tasks\` to enable $\{inputs.\} expression in DT. |
| ctx_incident | \`demisto\` context: Input 'incident' \(no quotation\) on \`From previous tasks\` to enable $\{incident.\} expression in DT. |
| variable_markers | The pair of start and end markers to bracket a variable name |
| keep_symbol_to_null | Set to true not to replace a value if the variable is null, otherwise false. |

## Outputs
---
There are no outputs for this script.
