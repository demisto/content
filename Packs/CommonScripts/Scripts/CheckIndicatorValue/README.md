Check if indicators exist in the Threat Intel DB.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator | The indicator value to check |
| encoding | Decode indicators by the algorithm given |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CheckIndicatorValue.Indicator | The indicator value | string |
| CheckIndicatorValue.EncodedIndicator | The encoded indicator value given | string |
| CheckIndicatorValue.Exists | Whether the indicator exist | boolean |
