Search for Indicators and returns the id, indicator_type, value, expiration status, lastSeen timestamp, related investigations and score/verdict.

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
| value | A single value or comma separated list of values to search. |
| expirationStatus | The expiration status of the indicator. |
| type | The type of the indicator to search can be a single value or a comma separated list of values. |
| investigationIDs | The investigation that is linked to the indicator can be a single value or a comma separated list of values. |
| size | The number of indicators to return, defaults to a max of 25. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| foundIndicators.id | The id of the indicator in the XSOAR database. | Unknown |
| foundIndicators.indicator_type | The type of Indicator \(i.e. IP, Domain, URL, etc\) | Unknown |
| foundIndicators.value | The value of the Indicator | Unknown |
| foundIndicators.score | The numeric score of the indicator \(0 = Unknown, 1 = Good, 2 = Suspicious, 3 = Malicious\) | Unknown |
| foundIndicators.verdict | The human readable score/verdict of the Indicator. | Unknown |
| foundIndicators.investigationIDs | The investigations related to the indicator. | Unknown |
| foundIndicators.expiration | The expiration status of the indicator. | Unknown |
| foundIndicators.lastSeen | The timestamp of the last time the indicator was sensitive. | Unknown |
