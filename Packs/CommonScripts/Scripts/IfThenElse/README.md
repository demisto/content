A transformer for simple if-then-else logic. This can potentially reduce the number of tasks required for a given playbook.

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
| value | (Optional) The value to evaluate |
| equals | (Optional, Deprecated) If value equals this |
| then | (Optional) Return this value if 'condition' is true |
| else | (Optional) Return this value if 'condition' is false |
| condition | (Optional) The condition expression to evaluate, See `Condition` |
| lhs | (Optional) The value to compare in the condition given in `condition` (left hand side). |
| rhs | (Optional) The value to compare in the condition given in `condition` (right hand side). |
| options | (Optional) Option flags (comma separated list), See `Options` |

#### Condition

The evaluation performs with the condition expression given in the `condition` parameter.<br>
The format of the condition expression is:

    <lhs> <operator> <rhs>

    e.g. lhs==rhs
    e.g. value in list rhs

You can specify `lhs`, `rhs` or `value` for `<lhs>` and `<rhs>`. Those keywords are corresponding to its argument name.<br>
Also, see `Operator` for the available operators.

If the condition is empty, evaluates `value` == `equals` for backward compatibility.


#### Operator
| **Operator** | **Description** |
| --- | --- |
| === | Checks whether its two operands are equal. It always considers operands of different types to be different. |
| !== | Checks whether its two operands are not equal. It always considers operands of different types to be different. |
| == | Checks whether its two operands are equal. |
| != | Checks whether its two operands are not equal. |
| > | Returns true if the left operand is greater than the right operand, and false otherwise. |
| >= | Returns true if the left operand is greater than or equal to the right operand, and false otherwise. |
| < | Returns true if the left operand is less than the right operand, and false otherwise. |
| <= | Returns true if the left operand is less than or equal to the right operand, and false otherwise. |
| =~ | Performs a regular expression match of the string to its left to the regular expression on its right. See `regex_full_match` if you need whetner the pattern matches the whole string. |
| in list | Checks whether the right values which is a list comma separated includes the left value. |
| not in list | Checks whether the right values which is a list comma separated doesn't include the left value. |


#### Options
| **Option** | **Description** |
| --- | --- |
| case_insensitive | Enables case-insensitive matching |
| regex_dot_all | Enables that that dot special character (".") should additionally match the following line terminator ("newline") characters in a string. This only applies to applies to regular expression. |
| regex_multiline | Enables that a multiline input string should be treated as multiple lines. This only applies to applies to regular expression. |
| regex_full_match | Matched only when the whole string given matched with the regular expression pattern. This only applies to applies to regular expression. |
| input_data_type:then=&lt;type&gt; | The data given in `then` is converted based on the keyword specified in `<type>`. See `input_data_type`. e.g. input_data_type:then=json |
| input_data_type:else=&lt;type&gt; | The data given in `else` is converted based on the keyword specified in `<type>`. See `input_data_type`. e.g. input_data_type:else=json |
| input_data_type:lhs=&lt;type&gt; | The data given in `lhs` is converted based on the keyword specified in `<type>`. See `input_data_type`. e.g. input_data_type:lhs=json |
| input_data_type:rhs=&lt;type&gt; | The data given in `rhs` is converted based on the keyword specified in `<type>`. See `input_data_type`. e.g. input_data_type:rhs=json |

#### input_data_type
| **Type** | **Description** |
| --- | --- |
| raw | Nothing to be modified. The data given is passed to as it is. |
| json | The data formatted as JSON string is decoded. |
| value | `value` given in this transformer is input as the data, and replaced with the original value. |


## Outputs
---
There are no outputs for this script.

