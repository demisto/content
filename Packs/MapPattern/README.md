This transformer will take in a value and transform it based on multiple condition expressions (wildcard, regex, etc) defined in a JSON dictionary structure.

---
##### What does this pack do?
- Transform a value based on multiple condition expressions defined in a JSON dictionary structure.
- Condition expressions support wildcard, regex, and literal.

---
## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, string |


---
## Examples

The key:value pair of the JSON dictionary should be:

"condition expression": "desired outcome"

For example:

```
    {
        ".*match 1.*": "Dest Val1",
        ".*match 2.*": "Dest Val2",
        ".*match 3(.*)": "\\1",
        "*match 4*": {
            "algorithm": "wildcard",
            "output": "Dest Val4"
        }
    }
```

The transformer will return the value matched to a pattern following to the priority.
When unmatched or the input value is structured (dict or list), it will simply return the input value.
