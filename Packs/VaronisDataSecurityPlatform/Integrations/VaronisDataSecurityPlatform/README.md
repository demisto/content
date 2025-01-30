Streamline alerts and related forensic information from Varonis DSP
This integration was integrated and tested with version 1.0 of VaronisDataSecurityPlatform

## Configure Varonis Data Security Platform in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch incidents |  | False |
| Incident type |  | False |
| The FQDN/IP the integration should connect to |  | True |
| Name of Varonis user |  | True |
| Password |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Maximum number of incidents per fetch | Maximum value is 100 | False |
| First fetch time |  | False |
| Minimum severity of alerts to fetch |  | False |
| Varonis threat model name | Comma-separated list of threat model names of alerts to fetch | False |
| Varonis alert status |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| start_time | Start time of alert range. | Optional | 
| end_time | End time of alert range. | Optional | 
| alert_status | List of required alerts status. | Optional | 
| alert_severity | List of required alerts severity. | Optional | 
| device_name | List of required alerts device name. | Optional | 
| user_name | List of users (up to 5). | Optional |
| user_domain_name | User domain name (cannot be provided without user_name). | Optional |
| sam_account_name | List of sam account names (up to 5). | Optional |
| email | List of emails (up to 5). | Optional |
| last_days | Number of days you want the search to go back to. | Optional |
| descending_order | Indicates whether alerts should be ordered in newest to oldest order. | Optional |
| page | Page number. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Varonis.Alert.ID | Number | Varonis ID for alert | 
| Varonis.Alert.Name | String | Name of retrieved alert | 
| Varonis.Alert.Time | Date | When was the alert triggered | 
| Varonis.Alert.Severity | String | Alert severity | 
| Varonis.Alert.Category | String | Alert category. <br/>Options are: <br/>- Reconnaissance<br/>- Intrusion<br/>- Exploitation<br/>- Privilege Escalation <br/>- Lateral Movement  | 
| Varonis.Alert.Country | String | Name of the country from which the event occurred | 
| Varonis.Alert.State | String | Name of the state or regional subdivision from which the event occurred | 
| Varonis.Alert.Status | String | Alert state. Options are:<br/>- Open<br/>- Under investigation<br/>- Closed | 
| Varonis.Alert.CloseReason | String | Reason the alert was closed. Options are:<br/>- Resolved<br/>- Misconfiguration<br/>- Threat model disabled or deleted<br/>- Account misclassification<br/>- Legitimate activity<br/>- Other | 
| Varonis.Alert.BlacklistLocation | Boolean | Whether any of the geographical locations from which an alerted activity originated was on the blacklist at the time the activity occurred | 
| Varonis.Alert.AbnormalLocation | Boolean | Whether any of the geographical locations from which an alerted activity originated is new or abnormal to the organization, the user and peers, or only the user | 
| Varonis.Alert.NumOfAlertedEvents | Number | Number of events with alerts | 
| Varonis.Alert.UserName | String | Name of the users triggered alerts | 
| Varonis.Alert.By.SamAccountName | String | Logon name used to support clients and servers running earlier versions of Windows operating system, such as Windows NT 4.0. In the dashboards \(other than the Alert dashboard\), this is the SAM account name of the user or group | 
| Varonis.Alert.By.PrivilegedAccountType | String | Privileged account. Options are:<br/>- Service accounts<br/>- Admin accounts<br/>- Executive accounts | 
| Varonis.Alert.By.Department | String | User`s department | 
| Varonis.Alert.On.ContainsFlaggedData | Boolean | Whether the data affected by the alerted events has global flags | 
| Varonis.Alert.On.ContainsSensitiveData | Boolean | Filters according to whether the resource on which the event was performed is sensitive \(including subfolders\) | 
| Varonis.Alert.On.Platform | String | Type of platform on which the server resides. For example, Windows, Exchange, or SharePoint | 
| Varonis.Alert.On.Asset | String | Path of the alerted asset | 
| Varonis.Alert.On.FileServerOrDomain | String | Associated file server/domain | 
| Varonis.Alert.Device.Name | String | Name of the device from which the user generated the event | 
| Varonis.Alert.Device.ContainMaliciousExternalIP | Boolean | Whether the alert contains IPs known to be malicious | 
| Varonis.Alert.Device.IPThreatTypes | String | Whether the alert contains IPs known to be malicious | 
| Varonis.Pagination.Page | Number | Current page number requested by user | 
| Varonis.Pagination.PageSize | Number | Number of records on the page | 

#### Command example
```!varonis-get-alerts page=1 alert_status=Open max_results=1 start_time=2022-02-16T13:00:00+02:00```
#### Context Example
```json
{
    "Varonis": {
        "Alert": [
            {
                "AbnormalLocation": "",
                "BlacklistLocation": "",
                "By": {
                    "Department": "",
                    "PrivilegedAccountType": "",
                    "SamAccountName": ""
                },
                "Category": "Privilege Escalation",
                "CloseReason": "",
                "Country": "",
                "Device": {
                    "ContainMaliciousExternalIP": "No",
                    "IPThreatTypes": "",
                    "Name": "l1839-zkpr1"
                },
                "ID": "D366A9C5-EF82-413D-BABB-7F04AB358D11",
                "Name": "dns aaaaaalert",
                "NumOfAlertedEvents": "1",
                "On": {
                    "Asset": "",
                    "ContainsFlaggedData": "",
                    "ContainsSensitiveData": "",
                    "FileServerOrDomain": "DNS",
                    "Platform": "DNS"
                },
                "Severity": "Medium",
                "State": "",
                "Status": "Open",
                "Time": "2022-02-15T16:02:00",
                "UserName": ""
            }
        ],
        "Pagination": {
            "Page": 1,
            "PageSize": 1
        }
    }
}
```

#### Human Readable Output

>### Varonis Alerts
>|Name|Severity|Time|Category|UserName|Status|
>|---|---|---|---|---|---|
>| dns aaaaaalert | Medium | 2022-02-15T16:02:00 | Privilege Escalation |  | Open |


### varonis-update-alert-status
***
Update alert status


#### Base Command

`varonis-update-alert-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Requested alerts. | Required | 
| status | Alert new status. Possible values are: Open, Under Investigation. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!varonis-update-alert-status alert_id=72D0D925-0937-4111-AB4A-FFFD4A529A3C status="Under Investigation"```
#### Human Readable Output

>True

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
#### Command example
```!varonis-close-alert alert_id=72D0D925-0937-4111-AB4A-FFFD4A529A3C,0D9D657A-A51F-4674-B49A-FFB1EDD35D51 close_reason=Resolved```
#### Human Readable Output

>True

### varonis-get-alerted-events
***
Get events applied to specific alerts


#### Base Command

`varonis-get-alerted-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | List of alert IDs. | Required | 
| max_results | Maximum number of alerts to retrieve (up to 5k). | Optional | 
| page | Page number. Default is 1. | Optional | 
| descending_order | Indicates whether events should be ordered in newest to oldest order. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Varonis.Event.Type | String | Event type | 
| Varonis.Event.UTCTime | Date | Event time UTC format | 
| Varonis.Event.Status | String | Filters according to the status of the event. Options are:<br/>- Fail<br/>- Success | 
| Varonis.Event.Description | String | Description of the activity | 
| Varonis.Event.Country | String | Name of the country from which the event occurred | 
| Varonis.Event.State | String | Name of the state or regional subdivision from which the event occurred | 
| Varonis.Event.ExternalIP | String | Device external IP | 
| Varonis.Event.Details.IsBlacklist | Boolean | Whether any of the geographical locations from which an alerted activity originated was on the blacklist at the time the activity occurred | 
| Varonis.Event.Details.Operation | String | Type of operation that occurred during the event. Options are:<br/>- Accessed<br/>- Added<br/>- Changed<br/>- Removed<br/>- Sent<br/>- Received<br/>- Requested | 
| Varonis.Event.ByUser.Name | String | Name of the user that triggered the event | 
| Varonis.Event.ByUser.UserType | String | Type of account, i.e., user or computer | 
| Varonis.Event.ByUser.UserAccountType | String | Logon name used to support clients and servers running earlier versions of the Windows operating system, such as Windows NT 4.0. In the dashboards \(other than the Alert dashboard\), this is the SAM account name of the user or group | 
| Varonis.Event.ByUser.Domain | String | Domain of the user that triggered the event | 
| Varonis.Event. ByUser.DisabledAccount | Boolean | Whether the account is disabled | 
| Varonis.Event.ByUser.StaleAccount | Boolean | Whether the account is stale | 
| Varonis.Event.ByUser.LockoutAccounts | Boolean | Whether the account is lockout | 
| Varonis.Event.SourceIP | String | Source IP of the device triggered the event | 
| Varonis.Event. IsMaliciousIP | Boolean | Whether the IP is known to be malicious | 
| Varonis.Event. IPReputation | Number | Reputation score of the IP. The score is a numeric value from 1-100 | 
| Varonis.Event.IPThreatType | String | List of threat types associated with the IP | 
| Varonis.Event.OnObject.Name | String | Name of object on which the event was performed | 
| Varonis.Event.OnObject.ObjectType | String | Type of object on which the event was performed | 
| Varonis.Event.OnObject.Platform | String | Type of platform on which the server resides. For example, Windows, Exchange, or SharePoint | 
| Varonis.Event.OnObject.IsSensitive | Boolean | Indicates whether the resource on which the event was performed is sensitive  | 
| Varonis.Event.OnObject.FileServerOrDomain | String | File server of object on which the event was performed | 
| Varonis.Event.OnObject.IsDisabledAccount | Boolean | Whether the account is disabled | 
| Varonis.Event.OnObject.IsLockOutAccount | Boolean | Whether the account is lockout | 
| Varonis.Event.OnObject.SAMAccountName | String | Logon name used to support clients and servers running earlier versions of the Windows operating system, such as Windows NT 4.0. In the dashboards \(other than the Alert dashboard\), this is the SAM account name of the user or group | 
| Varonis.Event.OnObject.UserAccountType | String | Specified type of privileged account.<br/>Options are:<br/>- Service accounts<br/>- Admin accounts<br/>- Executive accounts<br/>- Test accounts | 
| Varonis.Event.OnObject.DestinationIP | String | Destination IP address within the organization | 
| Varonis.Event.OnObject.DestinationDevice | String | Destination host name for relevant services | 
| Varonis.Event.OnObject.Path | String | Path of asset | 
| Varonis.Pagination.Page | Number | Current page number requested by user | 
| Varonis.Pagination.PageSize | Number | Number of records on the page | 

#### Command example
```!varonis-get-alerted-events page=1 alert_id=72D0D925-0937-4111-AB4A-FFFD4A529A3C max_results=1```
#### Context Example
```json
{
    "Varonis": {
        "Event": [
            {
                "ByUser": {
                    "DisabledAccount": "",
                    "Domain": "",
                    "LockoutAccounts": "",
                    "Name": "",
                    "SAMAccountName": "",
                    "StaleAccount": "",
                    "UserAccountType": "",
                    "UserType": ""
                },
                "Country": "",
                "Description": "The DNS Server has resolved successfully ",
                "Details": {
                    "IsBlacklist": "",
                    "Operation": "Request"
                },
                "ID": "22D3EFC0-E758-4BA0-92C4-EB9566C830AD",
                "IPReputation": "",
                "IPThreatType": "",
                "IsMaliciousIP": "",
                "OnObject": {
                    "DestinationDevice": "",
                    "DestinationIP": "",
                    "FileServerOrDomain": "DNS",
                    "IsDisabledAccount": "",
                    "IsLockOutAccount": "",
                    "IsSensitive": "",
                    "Name": "dns.msftncsi.com",
                    "ObjectType": "Dns",
                    "Platform": "DNS",
                    "SAMAccountName": "",
                    "UserAccountType": ""
                },
                "SourceIP": "10.10.10.10",
                "State": "",
                "Status": "Success",
                "Type": "Client DNS request",
                "UTCTime": "2022-03-17T17:52:14Z"
            }
        ],
        "Pagination": {
            "Page": 1,
            "PageSize": 1
        }
    }
}
```

#### Human Readable Output

>### Varonis Alerted Events
>|ByUser|Country|Description|Details|ID|IPReputation|IPThreatType|IsMaliciousIP|OnObject|SourceIP|State|Status|Type|UTCTime|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Name: <br/>UserType: <br/>UserAccountType: <br/>SAMAccountName: <br/>Domain: <br/>DisabledAccount: <br/>StaleAccount: <br/>LockoutAccounts:  |  | The DNS Server has resolved successfully  | IsBlacklist: <br/>Operation: Request | 22D3EFC0-E758-4BA0-92C4-EB9566C830AD |  |  |  | Name: dns.msftncsi.com<br/>ObjectType: Dns<br/>Platform: DNS<br/>IsSensitive: <br/>FileServerOrDomain: DNS<br/>IsDisabledAccount: <br/>IsLockOutAccount: <br/>SAMAccountName: <br/>UserAccountType: <br/>DestinationIP: <br/>DestinationDevice:  | 10.10.10.10 |  | Success | Client DNS request | 2022-03-17T17:52:14Z |
