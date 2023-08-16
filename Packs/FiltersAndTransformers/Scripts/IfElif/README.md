### A transformer for "if else-if else" logic.

This transformer simulates an *"if else-if else"* tree using a JSON provided in the ***conditions*** argument.
The JSON should be list of dictionaries where all but the last have the keys "*condition*", which contains a boolean expression, and "return", which contains the value to return if "*condition*" is evaluated to be true. The last dictionary should have only the key "else" which is the value to return if all "*condition*"s were false.
Context values can be added as variables in the *variables* argument using the `var = ${context.key}` syntax. Each variable assignment must be on it's own line.
The ***"Get" value*** of the transformer can be retrieved using the keyword `VALUE`

### Example:
---

##### conditions:
```json
[
  {
    "condition": "variable1 >= 5 and VALUE == 'Yes'",
    "return": "a string"
  },
  {
    "condition": "regex_match('\d+', VALUE)",
    "return": variable2
  },
  {
    "else": default_value
  }
]
```

##### variables:
```bash
variable1 = ${path.to.context}
variable2 = ${another.path.to.context}
default_value = ${default.value}
```
##### flags:
```
case_insensitive,regex_dot_all,regex_multiline
```
---
##### Supported Operators:

**Comparison operators** will work like Python operator:
| Operator | Name | Example |
| --- | --- | --- |
| == | Equal | x == y |
| != | Not equal | x != y |
| > | Greater than | x > y |
| < | Less than | x < y |
| >= | Greater than or equal to | x >= y |
| <= | Less than or equal to | x <= y |
| in | In | x in y|
| not in | Not in | x not in y|

**Logical operators** also follow Python syntax:
| Operator | Description | Example |
| --- | --- | --- |
| and | Returns True if both statements are true | x < 5 and x < 10 |
| or | Returns True if one of the statements is true | x < 5 or x < 4 |
| not | Reverse the result, returns False if the result is true | not(x < 5 and x < 10) |

**regular expressions** are implemented with the "regex_match" function, in the format: "regex_match(\<pattern>, \<string>)". The behavior of the function is controlled with the ***flags*** argument. 


## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, general |
| Cortex XSOAR Version | 6.9.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | Replaces any instance of the literal `#VALUE` in the "conditions" argument. |
| conditions | A JSON formatted list, where all but the last items are dictionaries with the keys "condition" and "return".<br/>The last value can be any valid JSON object. |
| variables | Variables to be used in the "conditions" argument in the format "variable = ${context.path}", each variable on it's own line. |
| flags | Flags to control comparison and regular expression behavior. Possible values are: case_insensitive, regex_dot_all, regex_multiline, regex_full_match|

## Outputs

---
There are no context outputs for this script.
