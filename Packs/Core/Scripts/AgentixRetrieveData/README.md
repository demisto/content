Gets an indicator data set and timeframe, and searches for the indicator.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| indicator | The indicator to look for. |
| time_frame | How many days back to search for the indicator. |
| data_set | The dataset to search in. |
| query_name | The name of the query. |
| interval_in_seconds | The interval in seconds between each poll. |
| timeout_in_seconds | The timeout in seconds until polling ends. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXQL | A list of records \(dictionaries\) which contain the given indicator. | List |
