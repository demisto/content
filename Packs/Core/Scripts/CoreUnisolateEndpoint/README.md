Reverses the isolation of an endpoint.

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
| incident_id | Links the response action to the triggered incident. |
| endpoint_id | The endpoint ID \(string\) to reverse the isolation. Retrieve it from the core-get-endpoints command. |
| suppress_disconnected_endpoint_error | Suppress an error when trying to unisolate a disconnected endpoint. When set to false, an error is be returned. |
| action_id | For polling use. |
| interval_in_seconds | Interval in seconds between each poll. |
| timeout_in_seconds | Polling timeout in seconds. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.UnIsolation.endpoint_id | The unisolated endpoint ID. | String |
