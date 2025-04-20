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
| Process.Path | Process path. | String |
| Process.PID | Process PID. | Number |
| Process.MD5 | Process MD5 hash. | String |
| Process.Hostname | Process hostname. | String |
| Process.Name | Process name. | String |
| Process.CbSegmentID | Carbon Black "segment" where this process instance is stored. Required to fetch additional information for a process. | String |
| Process.CbID | Carbon Black unique ID for this process instance. Required \(together with CbSegmentID\) to fetch additional information for a process. | String |
| Process.Endpoint | The endpoint of the process. | String |
