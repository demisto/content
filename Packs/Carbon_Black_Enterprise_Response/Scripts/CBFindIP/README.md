Search Carbon Black for connection to specified IP addresses.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | carbon-black, endpoint, enhancement |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| ip | CSV list of IP addresses to identify. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ProcessSearch.Results.path | Process path. | String |
| ProcessSearch.Results.id | Process PID. | Number |
| ProcessSearch.Results.process_md5 | Process MD5 hash. | String |
| ProcessSearch.Results.hostname | Process hostname. | String |
| ProcessSearch.Results.process_name | Process name. | String |
| ProcessSearch.Results.segment_id | Carbon Black "segment" where this process instance is stored. Required to fetch additional information for a process. | String |
| ProcessSearch.Results.unique_id | Carbon Black unique ID for this process instance. Required \(together with CbSegmentID\) to fetch additional information for a process. | String |
| ProcessSearch.Results.interface_ip | The endpoint of the process. | String |
