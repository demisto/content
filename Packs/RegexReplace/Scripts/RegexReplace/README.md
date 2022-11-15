Format patterns matched with regex. If the regex does not match any pattern, the original value is returned.

Example 1:
 value: user=john
 regex: user=(.*)
 output_format: name=\1
 -> output value: name=john

Example 2:
 value: xxx=yyy
 regex: user=(.*)
 output_format: name=\1
 -> output value: xxx=yyy

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, string |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | Text to match against |
| regex | Regex pattern to search |
| output_format | Template string to format patterns matched with regex |
| ignore_case | Whether character matching will be case-insensitive. Default is "false". |
| multi_line | Process value in multiline mode.  See more information on re.MULTILINE, see https://docs.python.org/3/library/re.html. |
| period_matches_newline | Whether to make the '.' character also match a new line. Default is "false". |
| action_dt | The last action for each matched value to transform |

## Outputs
---
There are no outputs for this script.
