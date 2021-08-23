Whether value is within an hour range.
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
| begin_time | Format is HH:MM:SS |
| end_time | Format is HH:MM:SS |

## Outputs
---
There are no outputs for this script.


## Script Example
```!BetweenHours value=12:00:00 begin_time=02:00:00 end_time=21:00:00```

## Context Example
```
{}
```

## Human Readable Output
True
