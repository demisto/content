Terminates a process by its instance ID. Available only for XSIAM 2.4 and above.

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
| agent_id | The agent ID. |
| instance_id | The instance ID. |
| process_name | The process name. |
| incident_id | The incident ID. |
| action_id | The action ID. For polling use. |
| interval_in_seconds | Interval in seconds between each poll. |
| timeout_in_seconds | Polling timeout in seconds. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.TerminateProcess.action_id | The action ID. | String |
| Core.GetActionStatus | The action status command results. | Unknown |
| Core.GetActionStatus.endpoint_id | Endpoint ID. | string |
| Core.GetActionStatus.status | The status of the specific endpoint ID. | string |
| Core.GetActionStatus.action_id | The specified action ID. | number |
| Core.GetActionStatus.ErrorReasons.bucket | The bucket in which the error occurred. | String |
| Core.GetActionStatus.ErrorReasons.file_name | The name of the file that caused the error. | String |
| Core.GetActionStatus.ErrorReasons.file_path | The path of the file that caused the error. | String |
| Core.GetActionStatus.ErrorReasons.file_size | The size of the file that caused the error. | Number |
| Core.GetActionStatus.ErrorReasons.missing_files | The missing files that caused the error. | Unknown |
| Core.GetActionStatus.ErrorReasons.errorData | The error reason data. | String |
| Core.GetActionStatus.ErrorReasons.terminated_by | The instance ID which terminated the action and caused the error. | String |
| Core.GetActionStatus.ErrorReasons.errorDescription | The error reason description. | String |
| Core.GetActionStatus.ErrorReasons.terminate_result | The error reason terminate result. | Unknown |
