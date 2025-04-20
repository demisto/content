Checks whether the given value is within the specified time (hour) range.

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
| value | The value to check. |
| begin_time | The start time range in the format HH:MM:SS. |
| end_time | The end time range in the format HH:MM:SS. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BetweenHours.result | Whether the input hour is between the given hours. | boolean |
| BetweenHours.value | The value to check. | string |
| BetweenHours.begin_time | The start time range in the format HH:MM:SS. | string |
| BetweenHours.end_time | The end time range in the format HH:MM:SS. | string |
