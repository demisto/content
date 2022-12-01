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


## Examples
---
### Extract patterns from a text given to `value`

#### Parameters

##### Control Parameters
| **Argument Name** | **Value** |
| --- | --- |
| template_type | |
| value_takes | text |
| flags | |
| search_limit | |

##### value (Array)

- xxx CVE-2021-0001 yyy XXCVE-2021-0003 zzz
- xxx
- CVE-2021-0002

##### regex

(^|\s)(CVE-\d+-\d+)($|\s)

##### text

`blank`

##### template

\2

#### Output (Array)

- CVE-2021-0001
- CVE-2021-0002

---
### Extract patterns matched to list of regex given to `value`

#### Parameters

##### Control Parameters
| **Argument Name** | **Value** |
| --- | --- |
| template_type | |
| value_takes | regex |
| flags | |
| search_limit | |

##### value (Array)

- (^|\s)(CVE-2021-0001)($|\s)
- (^|\s)(CVE-2021-0002)($|\s)
- (^|\s)(CVE-2021-0003)($|\s)

##### regex

`blank`

##### text

xxx CVE-2021-0001 yyy XXCVE-2021-0003 zzz CVE-2021-0004

##### template

\2

#### Output (Array)

- CVE-2021-0001


---
### Extract groups matched to a regex pattern and format them in JSON

#### Parameters

##### Control Parameters
| **Argument Name** | **Value** |
| --- | --- |
| template_type | json |
| value_takes | text |
| flags | |
| search_limit | |

##### value (Array)

- jdoe@paloaltonetworks.com

##### regex

(.+)@(.+)

##### text

user@paloaltonetworks.com

##### template
```json
{
  "user": "\\1",
  "domain": "\\2"
}
```

#### Output (Array)

```json
[
  {
    "user": "jdoe",
    "domain": "paloaltonetworks.com"
  },  {
    "user": "user",
    "domain": "paloaltonetworks.com"
  }
]
```
