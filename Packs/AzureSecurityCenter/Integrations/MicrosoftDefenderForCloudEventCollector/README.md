XSIAM collector for Microsoft Defender for Cloud alerts.
This integration was integrated and tested with version xx of Microsoft Defender for Cloud Event Collector

## Configure Microsoft Defender for Cloud Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for Microsoft Defender for Cloud Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Microsoft Azure Management URL |  | False |
    | ID |  | True |
    | Token |  | True |
    | Key |  | True |
    | Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates & secrets" page of the app. | False |
    | Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
    | Subscription ID to use |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

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
