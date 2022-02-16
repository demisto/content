Varonis DSP Rapidly reduce risk, detect abnormal behavior and prove compliance all-in-one
This integration was integrated and tested with version 1.0 of VaronisDataSecurityPlatform

## Configure Varonis Data Security Platform on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Varonis Data Security Platform.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Instance name | False |
    | The FQDN/IP the integration should connect to. | True |
    | Name of Varonis user | True |
    | Password for Varonis user | True |
    | Whether to use XSOAR�s system proxy settings to connect to the API. | True |
    | Whether to allow connections without verifying SSL certificates validity. | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### varonis-get-alerts
***
Get alerts from Varonis DA


#### Base Command

`varonis-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_model_name | List of requested threat models to retrieve. | Optional | 
| max_results | The max number of alerts to retrieve (up to 50). Default is 50. | Optional | 
| Start time | Start time of the range of alerts. | Optional | 
| End time | End time of the range of alerts. | Optional | 
| Alert Status | List of required alerts status. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Varonis.Alert.ID | Number | Varonis ID for alert | 
| Varonis.Alert.Name | String | Name of the retrieved alert | 
| Varonis.Alert.Time | Date | When the alert was triggered | 
| Varonis.Alert.Severity | String | The alert's severity | 
| Varonis.Alert.Category | String | The category of the alert.
Can be:
- Reconnaissance 
- Intrusion 
- Exploitation 
- Privilege Escalation 
- Lateral Movement  | 
| Varonis.Alert.Country | String | The name of the country from which the event occurred | 
| Varonis.Alert.State | String | The name of the state or regional subdivision from which the event occurred | 
| Varonis.Alert.Status | String | State of the alert. Can be:
- Open
- Under investigation
- Closed | 
| Varonis.Alert.CloseReason | String | The reason the alert was closed. Default options are:
- Resolved
- Misconfiguration
- Threat model disabled or deleted
- Account misclassification
- Legitimate activity
- Other | 
| Varonis.Alert.BlacklistLocation | Boolean | Indicates whether any of the geographical locations from which an alerted activity originated was on the blacklist at the time the activity occurred. | 
| Varonis.Alert.AbnormalLocation | Boolean | Indicates whether any of the geographical locations from which an alerted activity originated is new or abnormal to the organization, the user and peers, or only the user. | 
| Varonis.Alert.NumOfAlertedEvents | Number | The number of events having alerts. | 
| Varonis.Alert.UserName | String | Name of the user\(s\) triggered the alerts | 
| Varonis.Alert.By.SamAccountName | String | The logon name used to support clients and servers running earlier versions of the Windows operating system, such as Windows NT 4.0.
In the dashboards \(other than the Alert dashboard\), this is the SAM account name of the user or group. | 
| Varonis.Alert.By.PreivilegedAccountType | String | The type of privileged account. Options are:
- Service accounts
- Admin accounts
- Executive accounts | 
| Varonis.Alert.By.HasFollowUpIndicators | Boolean | Indicates whether global flags, tags or notes are associated with the user | 
| Varonis.Alert.On.ContainsFlaggedData | Boolean | Indicates whether the data affected by the alerted events has global flags | 
| Varonis.Alert.On.ContainsSensitiveData | Boolean | Filters according to whether the resource on which the event was performed is sensitive \(incl. subfolders\) | 
| Varonis.Alert.On.Platform | String | The type of platform on which the server resides. For example, Windows, Exchange, and SharePoint. | 
| Varonis.Alert.On.Asset | String | The path of the alerted asset | 
| Varonis.Alert.On.FileServerOrDomain | String | Associated file server/domain | 
| Varonis.Alert.Device.Name | String | The name of the device from which the user generated the event. | 
| Varonis.Alert.Device.ContainMaliciousExternalIP | Boolean | Indicates whether the alert contains IPs known to be malicious. | 
| Varonis.Alert.Device.IPThreatTypes | String | Indicates whether the alert contains IPs known to be malicious. | 

### varonis-update-alert-status
***
Updating an alert status


#### Base Command

`varonis-update-alert-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Alert_id | Requested alerts. | Required | 
| Status | Alert new status:<br/>- Open<br/>- Under investigation. | Required | 


#### Context Output

There is no context output for this command.