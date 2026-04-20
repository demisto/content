## TroubleshootRestartFailedPlaybooks

Scans all non-closed alerts for playbook tasks in **Error** state and restarts them from the specific failed task. The script reopens each errored task and re-executes it, allowing the playbook to continue from where it stopped.

### Use Case

When playbook tasks fail due to transient errors (e.g., network timeouts, temporary service unavailability), this script allows you to restart all failed tasks across all alerts in a single operation, without needing to manually find and restart each one.

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `max_alerts` | Maximum number of non-closed alerts to scan for failed tasks. | 500 |
| `group_size` | Number of tasks to restart before pausing. Helps avoid overwhelming the system. | 10 |
| `sleep_time` | Number of seconds to pause between each group of restarted tasks. | 10 |

### Outputs

| Path | Type | Description |
|------|------|-------------|
| `TroubleshootRestartFailedPlaybooks.TotalRestarted` | Number | Total number of tasks that were successfully restarted. |
| `TroubleshootRestartFailedPlaybooks.TotalFailed` | Number | Total number of tasks that failed to restart. |
| `TroubleshootRestartFailedPlaybooks.TotalAlerts` | Number | Total number of alerts that were scanned. |
| `TroubleshootRestartFailedPlaybooks.RestartedTask` | List | Details of each successfully restarted task. |
| `TroubleshootRestartFailedPlaybooks.FailedToRestart` | List | Details of each task that failed to restart, including the error message. |

### Example Usage

```
!TroubleshootRestartFailedPlaybooks
```

```
!TroubleshootRestartFailedPlaybooks max_alerts=100 group_size=5 sleep_time=15
```
