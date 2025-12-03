Analyze security logs with ShadowX SOCAI and return AI-driven guidance and scores (API Key mode only).
This integration was integrated and tested with version xx of ShadowxSOCAI.

## Configure ShadowX SOCAI in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g., https://app.shadowx.ai) | True |
| API Key (service token) | True |
| Subject | True |
| AI Driver ID (GUID) | False |
| Assigned User ID (GUID) | False |
| Default Policy ID (GUID) | False |
| Default Task Name | False |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### shadowx-submit-task

***
Submit a security log to ShadowX SOCAI. Optional polling via wait_seconds.

#### Base Command

`shadowx-submit-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log | Raw log / event text. | Required | 
| ip_addr | Related IP address. | Optional | 
| subject | Subject for the task (e.g., username, asset, etc.). | Optional | 
| policy_id | Overrides the instance's default policy ID for this task. | Optional | 
| wait_seconds | If &gt; 0, poll until completion or timeout. | Optional | 
| interval_seconds | Poll interval (seconds). Default 30. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ShadowxSOCAI.TaskSubmit.TaskId | string | Submitted task ID. | 
| ShadowxSOCAI.TaskSubmit.TaskURL | string | Task URL in ShadowX. | 
| ShadowxSOCAI.TaskResult.TaskId | string | Task ID \(when polled to completion\). | 
| ShadowxSOCAI.TaskResult.TaskName | string | Task name. | 
| ShadowxSOCAI.TaskResult.AssignedUserName | string | The username assigned to the task in ShadowX. | 
| ShadowxSOCAI.TaskResult.AIDriverName | string | The name of the AI driver used for analysis. | 
| ShadowxSOCAI.TaskResult.PolicyName | string | Name of the policy applied. | 
| ShadowxSOCAI.TaskResult.Subject | string | The subject of the task. | 
| ShadowxSOCAI.TaskResult.SecurityLog | string | The original security log submitted. | 
| ShadowxSOCAI.TaskResult.SanitizedLog | string | The log after sanitization. | 
| ShadowxSOCAI.TaskResult.Response | string | The full AI-generated response. | 
| ShadowxSOCAI.TaskResult.Recommendation | string | The AI-generated recommendation. | 
| ShadowxSOCAI.TaskResult.Status | string | The final status of the task \(e.g., Completed\). | 
| ShadowxSOCAI.TaskResult.RiskSeverity | string | The calculated risk severity \(e.g., High\). | 
| ShadowxSOCAI.TaskResult.PredictionScore | number | The numeric prediction score. | 

### shadowx-get-task

***
Fetch task details by ID (API Key mode).

#### Base Command

`shadowx-get-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task GUID returned by shadowx-submit-task. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ShadowxSOCAI.TaskResult.TaskId | string | The unique ID of the task. | 
| ShadowxSOCAI.TaskResult.TaskName | string | The name of the task. | 
| ShadowxSOCAI.TaskResult.AssignedUserName | string | The username assigned to the task in ShadowX. | 
| ShadowxSOCAI.TaskResult.AIDriverName | string | The name of the AI driver used for analysis. | 
| ShadowxSOCAI.TaskResult.PolicyName | string | Name of the policy applied. | 
| ShadowxSOCAI.TaskResult.Subject | string | The subject of the task. | 
| ShadowxSOCAI.TaskResult.SecurityLog | string | The original security log submitted. | 
| ShadowxSOCAI.TaskResult.SanitizedLog | string | The log after sanitization. | 
| ShadowxSOCAI.TaskResult.Response | string | The full AI-generated response. | 
| ShadowxSOCAI.TaskResult.Recommendation | string | The AI-generated recommendation. | 
| ShadowxSOCAI.TaskResult.Status | string | The final status of the task \(e.g., Completed\). | 
| ShadowxSOCAI.TaskResult.RiskSeverity | string | The calculated risk severity \(e.g., High\). | 
| ShadowxSOCAI.TaskResult.PredictionScore | number | The numeric prediction score. | 
