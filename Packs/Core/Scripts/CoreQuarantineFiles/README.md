Quarantines a file on selected endpoints. You can select up to 1000 endpoints.

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
| endpoint_id_list | List of endpoint IDs where the file will be quarantined. |
| file_path | The file path of the file you want to quarantine on the selected endpoints. |
| file_hash | The SHA256 hash of the file to quarantine. Must be a valid SHA256 hash. |
| action_id | For polling use. Contains the action IDs for polling. |
| interval_in_seconds | Interval \(in seconds\) between each polling attempt. |
| timeout_in_seconds | The timeout \(in seconds\) for polling. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.GetActionStatus.errorDescription | Detailed error description. | String |
| Core.GetActionStatus.ErrorReasons.errorData | Additional error data \(in JSON format\). | String |
| Core.GetActionStatus.ErrorReasons.errorDescription | Detailed error description. | String |
| Core.GetActionStatus.action_id | The ID of the action. | Number |
| Core.GetActionStatus.endpoint_id | The ID of the endpoint. | String |
| Core.GetActionStatus.status | The status of the action. | String |
| Core.quarantineFiles.actionIds.actionId | The quarantine action ID. | Number |
| Core.quarantineFiles.actionIds.endpointIdList | The list of endpoint IDs involved in the quarantine action. | Array |
| Core.quarantineFiles.actionIds.fileHash | The SHA256 hash of the quarantined file. | String |
| Core.quarantineFiles.actionIds.filePath | The path of the quarantined file. | String |
