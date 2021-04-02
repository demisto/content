This transformer will take in a value and transform it based on multiple condition expressions (wildcard, regex, etc) defined in a JSON dictionary structure. The key:value pair of the JSON dictionary should be:

"condition expression": "desired outcome"

For example:

{
    ".*match 1.*": "Dest Val1",
    ".*match 2.*": "Dest Val2",
    ".*match 3(.*)": "\\1",
    "*match 4*": {
        "algorithm": "wildcard",
        "output": "Dest Val4"
    }
}

The transformer will return the value matched to a pattern following to the priority.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, string |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The value to modify. |
| mappings | A JSON dictionary that contains key:value pairs that represent the "Condition":"Outcome". |
| algorithm | The default algorithm for pattern match. Available algorithm: literal,wildcard,regex and regmatch. |
| caseless | Set to true for caseless comparison, otherwise false. |
| priority | The option to choose which value matched to return. |
| context | \`demisto\` context: Input . \(single dot\) on \`From previous tasks\` to enable to extract the context data. |

## Outputs
---
There are no outputs for this script.
