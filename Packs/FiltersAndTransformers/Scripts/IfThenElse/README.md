A transformer for simple if-then-else logic.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | transformer, general |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The value to evaluate |
| equals | \(Deprecated\) If value equals this |
| then | Return this value if 'condition' is true |
| else | Return this value if 'condition' is false |
| condition | The condition expression to evaluate such as lhs==rhs or lhs\!=rhs. Will evaluate as value==rhs if left empty for backward compatibility. |
| lhs | The value to compare in the condition \(left hand side\) |
| rhs | The value to compare in the condition \(right hand side\) |
| options | Option flags \(comma separated list\): available options are \`case_insensitive\`, \`regex_dot_all\`, \`regex_multiline\`, \`regex_full_match\`, \`input_data_type:then=&amp;lt;type&amp;gt;\`, \`input_data_type:else=&amp;lt;type&amp;gt;\`, \`input_data_type:lhs=&amp;lt;type&amp;gt;\` and \`input_data_type:rhs=&amp;lt;type&amp;gt;\`. Choose \`value\`, \`json\` or \`raw\` for &amp;lt;type&amp;gt;. |
| lhsB | The value to compare in the second condition \(left hand side\) |
| rhsB | The value to compare in the second condition \(right hand side\) |
| conditionB | The second condition expression to evaluate such as lhsB==rhsB or lhsB\!=rhsB. Will evaluate as value==rhsB if left empty for backward compatibility. |
| conditionInBetween | The condition to put between the first condition \(lhs and rhs\) and the second condition \(lhsB and rhsB\) |
| optionsB | Option flags \(comma separated list\): available options are \`case_insensitive\`, \`regex_dot_all\`, \`regex_multiline\`, \`regex_full_match\`, \`input_data_type:then=&amp;lt;type&amp;gt;\`, \`input_data_type:else=&amp;lt;type&amp;gt;\`, \`input_data_type:lhs=&amp;lt;type&amp;gt;\` and \`input_data_type:rhs=&amp;lt;type&amp;gt;\`. Choose \`value\`, \`json\` or \`raw\` for &amp;lt;type&amp;gt;. |

## Outputs
---
There are no outputs for this script.
