Create indicators to the Threat Intel database only if they are not registered. When using the script with many indicators, or when the Threat Intel Management database is highly populated, this script may have low performance issue.

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
| type | The indicator type of the indicators. |
| source | The indicator source. |
| verdict | The indicator reputation. |
| tags | The tags to add to the new indicators. |
| verbose | Whether to output additional messages as readable output. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CreateNewIndicatorsOnly.ID | The indicator ID. | string |
| CreateNewIndicatorsOnly.Value | The indicator value. | string |
| CreateNewIndicatorsOnly.Type | The indicator type. | string |
| CreateNewIndicatorsOnly.Score | The indicator score. | number |
| CreateNewIndicatorsOnly.CreationStatus | The status of the indicator requested to add. Value is either new, existing, or unavailable. | string |

## Notice
---

When using the script with many indicators, or when the Threat Intel Management database is highly populated, this script may have low performance issue. 