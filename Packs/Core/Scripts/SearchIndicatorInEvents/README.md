Searches for a specific indicator in the tenant's events and logs data and extract the logs which the indicator appears in.

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
| time_frame | The time range to search within, specified in days \(e.g., "7 days" means searching the past 7 days of data\). |
| data_set | The name of the dataset to search in. If not specified, the search defaults to the "xdr_data" dataset. |
| query_name | A user-defined name. The query results will appear under the query_name in the context data of the current war room. |
| interval_in_seconds | The interval, in seconds, between checking the status of the query while waiting for the query to complete. |
| timeout_in_seconds | The maximum time, in seconds, to wait for the query to finish before the command is forced to fail. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXQL | A list of event records \(constructed as dictionaries\) where the specified indicator was found during the search. | List |
