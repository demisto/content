Use the Workday IAM Integration as part of the IAM premium pack.
When using the Integration for the first time, run the ***workday-first-run*** command before fetching any incidents.

## Configure WorkdayIAM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for WorkdayIAM.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| credentials | Username | False |
| report_type | Report Type | False |
| report_url | Workday Report URL | True |
| fetch_events_time_minutes | Fetch Events Frequency In minutes | False |
| fetch_limit | Fetch Limit \(Recommended less than 200\) | False |
| email_notification_ids | Email Notification Ids \(Separated by comma\) | False |
| smtp_server | SMTP Server Host | False |
| smtp_port | SMTP Server Port | False |
| from_email | From Email | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| incidentFetchInterval | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### workday-first-run
***
Synchronizes between the workday users and the indicators used in IAM. Creates an indicator for every workday user. Should be run when starting to use the integration, before fetching any incidents.


#### Base Command

`workday-first-run`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```
!workday-first-run 
```

#### Human Readable Output
