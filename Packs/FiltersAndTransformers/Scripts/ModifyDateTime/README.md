Takes a date or time input and adds or subtracts a determined amount of time. Returns a string in date or time in ISO Format.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, date |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | Input date or time in a format that is supported by the dateparser.parse\(\) function as outlined here\- https://dateparser.readthedocs.io/en/latest/#popular-formats. For example: '2020\-01\-01' or '1999/02/03 12:01:59' |
| variation | Variation of time \(for example: 'in 1 day', or '3 months ago'\). Must be supported by the dateparser.parse\(\) function here \- https://dateparser.readthedocs.io/en/latest/#relative-dates |

## Outputs
---
There are no outputs for this script.


## Script Example
```!ModifyDateTime value=2020,02,02 variation="1 day"```

## Context Example
```
{}
```

## Human Readable Output
2020-02-01T00:00:00
