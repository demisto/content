Extract the strings matched to the patterns by doing backslash substitution on the template string.
This transformer allow to specify multiple regex patterns and multiple match targets, and those can be given in the input value and the argument parameters.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, string, entirelist |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | List of regex or text for the pattern match. |
| regex | A regex pattern to search \(in Python\). |
| text | A match target text. |
| template | The template text that will be returned for the output by doing backslash substitution to the patterns matched. |
| template_type | The data type of the template. |
| value_takes | Which type of value takes from the value argument, 'text' \(match target\) or 'regex'. |
| flags | The comma separated flags for pattern matching in regex. "dotall" \(s\), "multiline" \(m\), "ignorecase" \(i\) and "unicode" \(u\) are supported. |
| search_limit | The maximum limit for scanning patterns. \(0 means unlimited\) |

## Outputs
---
There are no outputs for this script.
