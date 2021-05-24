Whether value is within a date range.
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
| value | Value to check |
| begin_date | Lower date range |
| end_date | Upper date range |

## Outputs
---
There are no outputs for this script.


## Script Example
```!BetweenDates value=2020-04-04T15:13:29 begin_date=2020-04-01T12:00:00 end_date=2020-04-14T12:00:00```

## Context Example
```
{}
```

## Human Readable Output
True
