Lists and updates alerts in the Review Exercise Alerts platform.

## Configure Review Exercise Alerts in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Client ID | True |
| Client Secret | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### review-exercise-alert-list

***
Lists alerts, optionally filtered by creation time and severity.

#### Base Command

`review-exercise-alert-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of alerts to return. Default is 50. | Optional |
| since | Return only alerts created after this relative time, for example "3 days" or "12 hours". | Optional |
| severity | Return only alerts with this severity. Possible values are: informational, low, medium, high, critical. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReviewExerciseAlerts.Alert.ID | String | The ID of the alert. |
| ReviewExerciseAlerts.Alert.Title | String | The title of the alert. |
| ReviewExerciseAlerts.Alert.Severity | Number | The severity of the alert. |
| ReviewExerciseAlerts.Alert.Status | String | The status of the alert. |
| ReviewExerciseAlerts.Alert.CreatedAt | Date | The time the alert was created. |

### review-exercise-alert-update

***
Updates the status or severity of an alert.

#### Base Command

`review-exercise-alert-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to update. | Required |
| status | The new status of the alert. Possible values are: open, in_progress, closed. | Optional |
| severity | The new severity of the alert. Possible values are: informational, low, medium, high, critical. | Optional |

#### Context Output

There is no context output for this command.
