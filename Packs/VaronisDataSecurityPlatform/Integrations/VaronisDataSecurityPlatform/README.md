Streamline alerts and related forensic information from Varonis DSP
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
    | Password | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

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
| Start_time | Start time of the range of alerts. | Optional | 
| End_time | End time of the range of alerts. | Optional | 
| Alert_Status | List of required alerts status. | Optional | 
| page | Page number. Default is 1. | Optional | 


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
| Varonis.Pagination.Page | Number | Current page number requested by user | 
| Varonis.Pagination.PageSize | Number | Amount of records on the page | 

### varonis-update-alert-status
***
Updating an alert status


#### Base Command

`varonis-update-alert-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Alert_id | Requested alerts. | Required | 
| Status | Alert new status:<br/>- Open<br/>- Under Investigation. | Required | 


#### Context Output

There is no context output for this command.
### varonis-close-alert
***
Closing alert


#### Base Command

`varonis-close-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Alert_id | Requested alerts. | Required | 
| Close_Reason | The reason the alert was closed. Default options are:<br/>- Resolved<br/>- Misconfiguration<br/>- Threat model disabled or deleted<br/>- Account misclassification<br/>- Legitimate activity<br/>- Other. | Required | 


#### Context Output

There is no context output for this command.
### varonis-get-alerted-events
***
Get events applied to specific alerts


#### Base Command

`varonis-get-alerted-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Alert_id | List of alert ids. | Required | 
| max_results | The max number of alerts to retrieve (up to 5k). | Optional | 
| page | Page number. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Varonis.Event.Type | String | Event type | 
| Varonis.Event.UTCTime | Date | Event time in utc format | 
| Varonis.Event.Status | String | Filters according to the status of the event, which can be one of the following:
- Fail
- Success | 
| Varonis.Event.Description | String | Description of the activity | 
| Varonis.Event.Country | String | The name of the country from which the event occurred | 
| Varonis.Event.State | String | The name of the state or regional subdivision from which the event occurred. | 
| Varonis.Event.Details.IsBlacklist | Boolean | Indicates whether any of the geographical locations from which an alerted activity originated was on the blacklist at the time the activity occurred | 
| Varonis.Event.Details.Operation | String | The type of operation that occurred during the event, which can be:
- Accessed
- Added
- Changed
- Removed
- Sent
- Received
- Requested | 
| Varonis.Event.ByUser.Name | String | Name of the user that triggered the event | 
| Varonis.Event.ByUser.UserType | String | Type of account, i.e., user or computer. | 
| Varonis.Event.ByUser.UserAccountType | String | The logon name used to support clients and servers running earlier versions of the Windows operating system, such as Windows NT 4.0.
In the dashboards \(other than the Alert dashboard\), this is the SAM account name of the user or group. | 
| Varonis.Event.ByUser.Domain | String | Domain of the user that triggered the event | 
| Varonis.Event. ByUser.DisabledAccount | Boolean | Indicates whether the account is disabled. | 
| Varonis.Event.ByUser.StaleAccount | Boolean | Indicates whether the account is stale. | 
| Varonis.Event.ByUser.LockoutAccounts | Boolean | Indicates whether the account is lockout. | 
| Varonis.Event.SourceIP | String | Source IP of the device triggered the event | 
| Varonis.Event. IsMaliciousIP | Boolean | Indicates whether the IP is known to be malicious. | 
| Varonis.Event. IPReputation | Number | The reputation score of the IP. The score is a numeric value from 1-100. | 
| Varonis.Event.IPThreatType | String | The list of threat types associated with the IP. | 
| Varonis.Event.OnObject.Name | String | Name of object on which the event was performed. | 
| Varonis.Event.OnObject.ObjectType | String | Type of object on which the event was performed. | 
| Varonis.Event.OnObject.Platform | String | The type of platform on which the server resides. For example, Windows, Exchange, and SharePoint. | 
| Varonis.Event.OnObject.IsSensitive | Boolean | Indicates whether the resource on which the event was performed is sensitive  | 
| Varonis.Event.OnObject.FileServerOrDomain | String | File server of object on which the event was performed. | 
| Varonis.Event.OnObject.IsDisabledAccount | Boolean | Indicates whether the account is disabled | 
| Varonis.Event.OnObject.IsLockOutAccount | Boolean | Indicates whether the account is lockout | 
| Varonis.Event.OnObject.SAMAccountName | String | The logon name used to support clients and servers running earlier versions of the Windows operating system, such as Windows NT 4.0.
In the dashboards \(other than the Alert dashboard\), this is the SAM account name of the user or group. | 
| Varonis.Event.OnObject.UserAccountType | String | The specified type of privileged account. Can be:
- Service accounts
- Admin accounts
- Executive accounts
- Test accounts | 
| Varonis.Event.OnObject.DestinationIP | String | The destination IP address within the organization | 
| Varonis.Event.OnObject.DestinationDevice | String | The destination host name for relevant services. | 
| Varonis.Pagination.Page | Number | Current page number requested by user | 
| Varonis.Pagination.PageSize | Number | Amount of records on the page | 
