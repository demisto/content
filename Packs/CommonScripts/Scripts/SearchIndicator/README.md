Searches Cortex XSOAR Indicators.

Search for XSOAR Indicators and returns the id, indicator_type, value, and score/verdict.

You can add additional fields from the indicators using the add_field_to_context argument.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | Query to use to find the Indicators, same as you'd use on the Threat Intel page.  |
| size | The number of indicators to return, defaults to a max of 25. |
| add_fields_to_context | A comma seperated list of fields to return to the context, \(default: id,indicator_type,value,score,verdict\)\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| foundIndicators.id | The id of the indicator in the XSOAR database. | Unknown |
| foundIndicators.indicator_type | The type of Indicator \(i.e. IP, Domain, URL, etc\) | Unknown |
| foundIndicators.value | The value of the Indicator | Unknown |
| foundIndicators.score | The numeric score of the indicator \(0 = Unknown, 1 = Good, 2 = Suspicious, 3 = Malicious\) | Unknown |
| foundIndicators.verdict | The human readable score/verdict of the Indicator. | Unknown |
