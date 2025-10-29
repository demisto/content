ShadowX AI plugin that analyzes security logs and returns response, recommendation, risk/result, and prediction score. Supports API Key (JSON /Api/ endpoints) and cookie (HTML) modes.
This integration was tested against the ShadowX SOCAI cloud service as of October 2025.

## Configure ShadowX SOCAI in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g., https://app.shadowx.ai) | True |
| API Key (recommended). If set, email/password are ignored. | False |
| API Submission Path (optional) | False |
| API Check Path Format (optional, must include {task_id}) | False |
| User Email (cookie mode) | False |
| User Password (cookie mode) | False |
| AI Driver ID (GUID) | False |
| Assigned User ID (GUID) | False |
| Default Policy ID (GUID) | False |
| Default Task Name | False |
| Trust any certificate (insecure) | False |
| Proxy | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### shadowx-submit-task

***
Submit a log to ShadowX for analysis. Supports API Key (Bearer) mode or cookie (HTML) mode. Adds TaskURL and optional polling, and parses results to incident fields.

#### Base Command

`shadowx-submit-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log | The log content to send for analysis. | Required | 
| ip_addr | Optional IP address associated with the log. | Optional | 
| user_name | Optional username associated with the log (used as Subject in cookie mode). | Optional | 
| policy_id | Policy ID to apply for analysis (overrides instance setting). | Optional | 
| wait_seconds | Seconds to wait for completion polling if supported (0 = do not wait). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ShadowxSOCAI.TaskSubmit | unknown | Response after task submission. | 
| ShadowxSOCAI.TaskSubmit.TaskId | string | The created task id \(if available\). | 
| ShadowxSOCAI.TaskSubmit.TaskURL | string | Direct link to the task in the ShadowX UI. | 
| ShadowxSOCAI.TaskResult | unknown | Final task result if wait_seconds &gt; 0 \(API mode\). | 
| ShadowxSOCAI.TaskResult.TaskId | string | Task id. | 
| ShadowxSOCAI.TaskResult.TaskURL | string | Direct link to the task in the ShadowX UI. | 
| ShadowxSOCAI.TaskResult.TaskName | string | Task name. | 
| ShadowxSOCAI.TaskResult.AssignedUserName | string | Assigned user name. | 
| ShadowxSOCAI.TaskResult.AIDriverName | string | AI driver name. | 
| ShadowxSOCAI.TaskResult.PolicyName | string | Policy name. | 
| ShadowxSOCAI.TaskResult.Subject | string | Task subject. | 
| ShadowxSOCAI.TaskResult.SecurityLog | string | Original security log. | 
| ShadowxSOCAI.TaskResult.SanitizedLog | string | Sanitized log. | 
| ShadowxSOCAI.TaskResult.Response | string | AI response. | 
| ShadowxSOCAI.TaskResult.Recommendation | string | AI recommendation. | 
| ShadowxSOCAI.TaskResult.Status | string | Task status. | 
| ShadowxSOCAI.TaskResult.RiskSeverity | string | Risk / result classification. | 
| ShadowxSOCAI.TaskResult.PredictionScore | string | Prediction score. | 

#### Command example
```!shadowx-submit-task log="failed login from 1.1.1.1" ip_addr="192.168.1.100" user_name="svc-admin" policy_id="cf85454c-7374-4106-8995-62ca68f8e651" wait_seconds=10```
#### Context Example
```json
{
    "ShadowxSOCAI": {
        "TaskSubmit": {
            "TaskId": "3aae6b41-f978-4350-995c-2561ec8b65cb",
            "TaskURL": "https://devl01.shadowx.ai/SecurityTasks/Details?taskID=3aae6b41-f978-4350-995c-2561ec8b65cb",
            "message": "Task created successfully.",
            "success": true,
            "taskId": "3aae6b41-f978-4350-995c-2561ec8b65cb"
        }
    }
}
```

#### Human Readable Output

>ShadowX task submitted (API key mode)
>URL: https:<span>//</span>devl01.shadowx.ai/SecurityTasks/Details?taskID=3aae6b41-f978-4350-995c-2561ec8b65cb

### shadowx-get-task

***
Get task details by Task ID (API key mode). Parses the result like the submit command and (if run inside an incident) updates incident custom fields.

#### Base Command

`shadowx-get-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task GUID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ShadowxSOCAI.TaskResult | unknown | Task details \(parsed\). | 
| ShadowxSOCAI.TaskResult.TaskId | string | Task id. | 
| ShadowxSOCAI.TaskResult.TaskURL | string | Direct link to the task in the UI. | 
| ShadowxSOCAI.TaskResult.TaskName | string | Task name. | 
| ShadowxSOCAI.TaskResult.AssignedUserName | string | Assigned user name. | 
| ShadowxSOCAI.TaskResult.AIDriverName | string | AI driver name. | 
| ShadowxSOCAI.TaskResult.PolicyName | string | Policy name. | 
| ShadowxSOCAI.TaskResult.Subject | string | Task subject. | 
| ShadowxSOCAI.TaskResult.SecurityLog | string | Original security log. | 
| ShadowxSOCAI.TaskResult.SanitizedLog | string | Sanitized log. | 
| ShadowxSOCAI.TaskResult.Response | string | AI response. | 
| ShadowxSOCAI.TaskResult.Recommendation | string | AI recommendation. | 
| ShadowxSOCAI.TaskResult.Status | string | Task status. | 
| ShadowxSOCAI.TaskResult.RiskSeverity | string | Risk / result classification. | 
| ShadowxSOCAI.TaskResult.PredictionScore | string | Prediction score. | 

### shadowx-help

***
Show usage instructions for ShadowX SOCAI.

#### Base Command

`shadowx-help`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
