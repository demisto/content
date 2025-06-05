Isolates the specified endpoint.

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
| interval_in_seconds | Interval in seconds between each poll. |
| timeout_in_seconds | Polling timeout in seconds. |
| action_id | For polling use. |
| endpoint_id | The endpoint ID \(string\) to isolate. Retrieve the string from the core-get-endpoints command. |
| suppress_disconnected_endpoint_error | Suppress an error when trying to isolate a disconnected endpoint. When set to false, an error is returned. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.Isolation.endpoint_id | The isolated endpoint ID. | String |
