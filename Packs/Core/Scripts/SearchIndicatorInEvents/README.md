Searches for a specific indicator in the tenant's event and log data, and extracts the logs the indicator appears in.

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
| indicator | The indicator value \(e.g., IP address, domain, hash\) to search for in the selected dataset logs. |
| time_frame | The search timeframe in days \(e.g., "7 days" means searching the past 7 days of data\). |
| data_set | The dataset for the search. By default, this is "xdr_data". |
| query_name | The name to use for the query results. Find the query results under this name in the War Room context. |
| interval_in_seconds | The interval in seconds for checking query completion. |
| timeout_in_seconds | The maximum time to wait for the query to finish \(in seconds\). The command fails if the query takes longer. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXQL | A list of event records \(constructed as dictionaries\) where the specified indicator was found. | List |
