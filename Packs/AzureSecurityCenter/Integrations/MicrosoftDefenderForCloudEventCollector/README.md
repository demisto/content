XSIAM collector for Microsoft Defender for Cloud alerts.

## Configure Microsoft Defender for Cloud Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Microsoft Azure Management URL |  | False |
| Client ID | Microsoft Defender for Cloud client ID | True |
| Tenant ID | Microsoft Defender for Cloud Tenant ID | True |
| Client Secret | Microsoft Defender for Cloud Client Secret | True |
| Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp;amp; secrets" page of the app. | False |
| Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
| Subscription ID to use |  | True |
| First fetch time interval | First time to start fetching alerts from. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

## Known limitations

This integration does not have a fetch limit parameter due to the limitations of the API functionality.

1. The collector fetches all events between the current time and the last time it was fetched during every fetch operation.

- If the command is run for the first time, all events from ***first_fetch*** until the current time be fetched in one execution.
It is possible that the above limitations may cause the fetch to take some time. You may need to increase the collector time out value in the server configuration if the collector fetch times out.

### ms-defender-for-cloud-get-events

***
Lists alerts for the subscription according to the specified filters.

#### Base Command

`ms-defender-for-cloud-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required |
| limit | Maximum number of results to return. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftDefenderForCloud.Alert.AlertDisplayName | string | The display name of the alert. |
| MicrosoftDefenderForCloud.Alert.CompromisedEntity | string | The entity on which the incident occurred. |
| MicrosoftDefenderForCloud.Alert.DetectedTimeUtc | date | The time the vendor detected the incident. |
| MicrosoftDefenderForCloud.Alert.ReportedSeverity | string | The estimated severity of this alert. |
| MicrosoftDefenderForCloud.Alert.ID | string | The alert ID. |


### ms-defender-for-cloud-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`ms-defender-for-cloud-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.