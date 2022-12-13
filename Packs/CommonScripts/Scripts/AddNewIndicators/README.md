Add indicators to the Threat Intel DB only if they are not registered.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator_values | The indicator values |
| type | The indicator type of the indicators |
| source | The indicator source |
| verdict | The indicator reputation |
| tags | The tags to add to the new indicators |
| verbose | Output additional messages as readable output |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AddNewIndicators.ID | The indicator ID | string |
| AddNewIndicators.Value | The indicator value | string |
| AddNewIndicators.Type | The indicator type | string |
| AddNewIndicators.Score | The indicator score | number |
| AddNewIndicators.Status | The status of the indicator requested to add, which states either one of new, existing or unavailable. | string |
