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

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BetweenDates.result | Whether the input hour is between the given hours. | boolean |
| BetweenDates.value | The value to check. | string |
| BetweenDates.begin_date | Lower date range. | string |
| BetweenDates.end_date | Upper date range. | string |
