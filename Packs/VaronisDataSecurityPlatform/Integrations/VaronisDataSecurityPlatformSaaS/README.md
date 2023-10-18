Streamline alerts and related forensic information from Varonis DSP
This integration was integrated and tested with version 1.0 of VaronisDataSecurityPlatformSaaS

## Configure Varonis Data Security Platform SaaS on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Varonis Data Security Platform SaaS.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | The FQDN/IP the integration should connect to |  | True |
    | X-API-Key |  | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | First fetch time |  | False |
    | Minimum severity of alerts to fetch |  | False |
    | Varonis threat model name | Comma-separated list of threat model names of alerts to fetch | False |
    | Varonis alert status |  | False |

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
| start_time | Start time of alert range. | Optional | 
| end_time | End time of alert range. | Optional | 
| alert_status | List of required alerts status. | Optional | 
| alert_severity | List of required alerts severity. | Optional | 
| device_name | List of required alerts device name. | Optional | 
| last_days | Number of days you want the search to go back to. | Optional | 
| descending_order | Indicates whether alerts should be ordered in newest to oldest order. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Varonis.Alert.ID | Number | Varonis ID for alert | 
| Varonis.Alert.Name | String | Name of retrieved alert | 
| Varonis.Alert.Time | Date | When was the alert triggered | 
| Varonis.Alert.Severity | String | Alert severity | 
| Varonis.Alert.Category | String | Alert category.
Options are:
- Reconnaissance 
- Intrusion 
- Exploitation 
- Privilege Escalation 
- Lateral Movement  | 
| Varonis.Alert.Country | String | Name of the country from which the event occurred | 
| Varonis.Alert.State | String | Name of the state or regional subdivision from which the event occurred | 
| Varonis.Alert.Status | String | Alert state. Options are:
- New
- Under investigation
- Closed
- Action Required
- Auto-Resolved | 
| Varonis.Alert.CloseReason | String | Reason the alert was closed. Options are:
- Resolved
- Misconfiguration
- Threat model disabled or deleted
- Account misclassification
- Legitimate activity
- Other | 
| Varonis.Alert.BlacklistLocation | Boolean | Whether any of the geographical locations from which an alerted activity originated was on the blacklist at the time the activity occurred | 
| Varonis.Alert.AbnormalLocation | Boolean | Whether any of the geographical locations from which an alerted activity originated is new or abnormal to the organization, the user and peers, or only the user | 
| Varonis.Alert.NumOfAlertedEvents | Number | Number of events with alerts | 
| Varonis.Alert.UserName | String | Name of the users triggered alerts | 
| Varonis.Alert.SamAccountName | String | Logon name used to support clients and servers running earlier versions of Windows operating system, such as Windows NT 4.0.
In the dashboards \(other than the Alert dashboard\), this is the SAM account name of the user or group | 
| Varonis.Alert.PrivilegedAccountType | String | Privileged account. Options are:
- Service accounts
- Admin accounts
- Executive accounts | 
| Varonis.Alert.Department | String | User\`s department | 
| Varonis.Alert.ContainsFlaggedData | Boolean | Whether the data affected by the alerted events has global flags | 
| Varonis.Alert.ContainsSensitiveData | Boolean | Filters according to whether the resource on which the event was performed is sensitive \(including subfolders\) | 
| Varonis.Alert.Platform | String | Type of platform on which the server resides. For example, Windows, Exchange, or SharePoint | 
| Varonis.Alert.Asset | String | Path of the alerted asset | 
| Varonis.Alert.FileServerOrDomain | String | Associated file server/domain | 
| Varonis.Alert.DeviceName | String | Name of the device from which the user generated the event | 
| Varonis.Alert.ContainMaliciousExternalIP | Boolean | Whether the alert contains IPs known to be malicious | 
| Varonis.Alert.IPThreatTypes | String | Whether the alert contains IPs known to be malicious | 

### varonis-update-alert-status

***
Update alert status

#### Base Command

`varonis-update-alert-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Requested alerts. | Required | 
| status | Alert new status. Possible values are: New, Under Investigation, Action Required, Auto-Resolved. | Required | 

#### Context Output

There is no context output for this command.
### varonis-close-alert

***
Close the alert

#### Base Command

`varonis-close-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Requested alerts. | Required | 
| close_reason | The reason the alert was closed. Possible values are: Resolved, Misconfiguration, Threat model disabled or deleted, Account misclassification, Legitimate activity, Other. | Required | 

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
| alert_id | List of alert IDs. | Required | 
| descending_order | Indicates whether events should be ordered in newest to oldest order. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Varonis.Event.Type | String | Event type | 
| Varonis.Event.UTCTime | Date | Event time UTC format | 
| Varonis.Event.Status | String | Filters according to the status of the event. Options are:
- Fail
- Success | 
| Varonis.Event.Description | String | Description of the activity | 
| Varonis.Event.Country | String | Name of the country from which the event occurred | 
| Varonis.Event.State | String | Name of the state or regional subdivision from which the event occurred | 
| Varonis.Event.ExternalIP | String | Device external IP | 
| Varonis.Event.IsBlacklist | Boolean | Whether any of the geographical locations from which an alerted activity originated was on the blacklist at the time the activity occurred | 
| Varonis.Event.Operation | String | Type of operation that occurred during the event. Options are:
- Accessed
- Added
- Changed
- Removed
- Sent
- Received
- Requested | 
| Varonis.Event.ByUserName | String | Name of the user that triggered the event | 
| Varonis.Event.ByUserUserType | String | Type of account, i.e., user or computer | 
| Varonis.Event.ByUserUserAccountType | String | Logon name used to support clients and servers running earlier versions of the Windows operating system, such as Windows NT 4.0.
In the dashboards \(other than the Alert dashboard\), this is the SAM account name of the user or group | 
| Varonis.Event.ByUserDomain | String | Domain of the user that triggered the event | 
| Varonis.Event.ByUserDisabledAccount | Boolean | Whether the account is disabled | 
| Varonis.Event.ByUserStaleAccount | Boolean | Whether the account is stale | 
| Varonis.Event.ByUserLockoutAccounts | Boolean | Whether the account is lockout | 
| Varonis.Event.SourceIP | String | Source IP of the device triggered the event | 
| Varonis.Event.IsMaliciousIP | Boolean | Whether the IP is known to be malicious | 
| Varonis.Event.IPReputation | Number | Reputation score of the IP. The score is a numeric value from 1-100 | 
| Varonis.Event.IPThreatType | String | List of threat types associated with the IP | 
| Varonis.Event.OnObjectName | String | Name of object on which the event was performed | 
| Varonis.Event.ObjectType | String | Type of object on which the event was performed | 
| Varonis.Event.Platform | String | Type of platform on which the server resides. For example, Windows, Exchange, or SharePoint | 
| Varonis.Event.IsSensitive | Boolean | Indicates whether the resource on which the event was performed is sensitive  | 
| Varonis.Event.FileServerOrDomain | String | File server of object on which the event was performed | 
| Varonis.Event.IsDisabledAccount | Boolean | Whether the account is disabled | 
| Varonis.Event.IsLockOutAccount | Boolean | Whether the account is lockout | 
| Varonis.Event.SAMAccountName | String | Logon name used to support clients and servers running earlier versions of the Windows operating system, such as Windows NT 4.0.
In the dashboards \(other than the Alert dashboard\), this is the SAM account name of the user or group | 
| Varonis.Event.UserAccountType | String | Specified type of privileged account. Options are:
- Service accounts
- Admin accounts
- Executive accounts
- Test accounts | 
| Varonis.Event.DestinationIP | String | Destination IP address within the organization | 
| Varonis.Event.DestinationDevice | String | Destination host name for relevant services | 
| Varonis.Event.Path | String | Path of asset | 
