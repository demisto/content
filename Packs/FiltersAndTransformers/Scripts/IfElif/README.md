### A transformer for "if else-if else" logic.

This transformer simulates an *"if else-if else"* tree using a JSON provided in the ***conditions*** argument.
The JSON should be list of dictionaries where all but the last have the keys "*condition*", which contains a boolean expression, and "return", which contains the value to return if "*condition*" is evaluated to be true. The last dictionary should have only the key "else" which is the value to return if no "*condition*" was true.

**Example:**
```json
[
  {
    "condition": "#VALUE >= 5 and #{path.to.context} == 'Yes'",
    "return": "1"
  },
  {
    "condition": "regex_match('\d+', #VALUE)",
    "return": #{value.to.return}
  },
  {
    "else": #{default.value}
  }
]
```


#### Supported Operators:

*Comparison operators* will work like Python operator:
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

*Logical operators* also follow Python syntax:
| Operator | Description | Example |
| --- | --- | --- |
| and | Returns True if both statements are true | x < 5 and x < 10 |
| or | Returns True if one of the statements is true | x < 5 or x < 4 |
| not | Reverse the result, returns False if the result is true | not(x < 5 and x < 10) |

*regular expressions* are implemented with the "regex_match" function, in the format: "regex_match(\<pattern>, \<string>)". The behavior of the function is controlled with the ***flags*** argument. 

#### Context Retrieval:
The If-Elif transformer uses the hash-curly brackets `#{...}` syntax to retrieve values from the context data. This syntax is used in the way the classic XSOAR `${...}` syntax is used and conforms to the [Cortex XSOAR Transform Language (DT)](https://xsoar.pan.dev/docs/integrations/dt).

The ***value*** of the transformer can be retrieved using the keyword `#VALUE` 


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
| flags | Flags to control comparison and regular expression behavior. |

## Outputs

---
There are no context outputs for this script.
