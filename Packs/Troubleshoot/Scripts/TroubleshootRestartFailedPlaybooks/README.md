Scans all non-closed alerts for playbook tasks in Error state and restarts them from the specific failed task.
The script reopens each errored task and re-executes it, allowing the playbook to continue from where it stopped.
Includes throttling support via the group_size and sleep_time arguments: after every group_size task restarts the script pauses for sleep_time seconds to avoid overloading the engine queue when scanning many alerts.

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here:
https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | DemistoAPI, troubleshoot |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| max_alerts | Maximum number of non-closed alerts to scan for failed tasks. The maximum allowed value is 200; any larger value will be clamped to 200. |
| days_back | Only scan non-closed alerts that were modified within this number of days back. Defaults to 3. |
| group_size | Number of tasks to restart before pausing. Helps avoid overwhelming the system. |
| sleep_time | Number of seconds to pause between each group of restarted tasks. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TroubleshootRestartFailedPlaybooks.TotalRestarted | Total number of tasks that were successfully restarted. | Number |
| TroubleshootRestartFailedPlaybooks.TotalFailed | Total number of tasks that failed to restart. | Number |
| TroubleshootRestartFailedPlaybooks.TotalAlerts | Total number of alerts that were scanned. | Number |
| TroubleshootRestartFailedPlaybooks.RestartedTask.IncidentID | The alert ID where the task was restarted. | String |
| TroubleshootRestartFailedPlaybooks.RestartedTask.TaskID | The ID of the restarted task. | String |
| TroubleshootRestartFailedPlaybooks.RestartedTask.TaskName | The name of the restarted task. | String |
| TroubleshootRestartFailedPlaybooks.RestartedTask.PlaybookName | The playbook name containing the restarted task. | String |
| TroubleshootRestartFailedPlaybooks.FailedToRestart.IncidentID | The alert ID where the task failed to restart. | String |
| TroubleshootRestartFailedPlaybooks.FailedToRestart.TaskID | The ID of the task that failed to restart. | String |
| TroubleshootRestartFailedPlaybooks.FailedToRestart.TaskName | The name of the task that failed to restart. | String |
| TroubleshootRestartFailedPlaybooks.FailedToRestart.PlaybookName | The playbook name containing the task that failed to restart. | String |
| TroubleshootRestartFailedPlaybooks.FailedToRestart.Error | The error message explaining why the task failed to restart. | String |
