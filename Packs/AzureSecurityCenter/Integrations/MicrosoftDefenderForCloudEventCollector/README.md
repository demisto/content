Microsoft Defender for Cloud Event Collector integration.

## Configure Microsoft Defender for Cloud Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Defender for Cloud Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Microsoft Azure Management URL |  | False |
    | ID (received from the admin consent - see Detailed Instructions (?) |  | True |
    | Token (received from the admin consent - see Detailed Instructions (?) section) |  | True |
    | Key (received from the admin consent - see Detailed Instructions (?) |  | False |
    | Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp;amp; secrets" page of the app. | False |
    | Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
    | Subscription ID to use |  | False |
    | First fetch time |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
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
| AzureSecurityCenter.Alert.AlertDisplayName | string | The display name of the alert. | 
| AzureSecurityCenter.Alert.CompromisedEntity | string | The entity on which the incident occurred. | 
| AzureSecurityCenter.Alert.DetectedTimeUtc | date | The time the vendor detected the incident. | 
| AzureSecurityCenter.Alert.ReportedSeverity | string | The estimated severity of this alert. | 
| AzureSecurityCenter.Alert.State | string | The alert state \(Active, Dismissed, etc.\). | 
| AzureSecurityCenter.Alert.ID | string | The alert ID. | 
