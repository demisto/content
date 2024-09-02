Removes items from the given list of values if they match any of the patterns in the provided `filters`.
If the match_exact argument is 'yes', direct string compare is used, otherwise the comparison is done using regex.

### Example:

---

##### value (Get):

```json
[
    "https://domain1.com/some/url",
    "http://another.url.com",
    "domain2.com/faq",
    "domain3.com/login",
    "sub.domain3.com/login"
]
```

##### filters:

```text
^*.\.domain1.com/.*\n
^*.\.domain2.com/.*\n
^sub.domain3.com/.*
```

##### Result:

```json
[    
    "http://another.url.com",
    "domain3.com/login"
]
```

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, entirelist, general |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| value | The value on which the transformer is applied. |
| ignore_case | Whether to ignore the case of the item for which you are searching. Default is "Yes". |
| match_exact | Whether to match the exact item in the list, or look for any string that contains it. Default is "No". |
| delimiter | A string used to delimit fields. For example, a new line "\n" should match the list separator configuration. |
| filters | A list of patterns to remove from the value. This can be a single string or a list of patterns, separated by the pattern defined in the delimiter argument. Unless match_exact is yes, regex pattern is supported. |

## Outputs

---
There are no outputs for this script.

