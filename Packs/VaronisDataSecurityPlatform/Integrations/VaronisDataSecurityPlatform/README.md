Streamline alerts and related forensic information from Varonis DSP
This integration was integrated and tested with version 1.0 of VaronisDataSecurityPlatform

## Configure Varonis Data Security Platform on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Varonis Data Security Platform.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Instance name | False |
    | Fetch incidents | False |
    | Incident type | False |
    | The FQDN/IP the integration should connect to | True |
    | Name of Varonis user | True |
    | Password | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |
    | Maximum number of incidents per fetch | False |
    | First fetch time | False |
    | Minimum severity of alerts to fetch | False |
    | Varonis threat model name | False |
    | Varonis alert status | False |

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
| Start_time | Start time of alert range. | Optional | 
| End_time | End time of alert range. | Optional | 
| Alert_Status | List of required alerts status. | Optional | 
| page | Page number. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Varonis.Alert.ID | Number | Varonis ID for alert | 
| Varonis.Alert.Name | String | Name of retrieved alert | 
| Varonis.Alert.Time | Date | When was the alert triggered | 
| Varonis.Alert.Severity | String | Alert severity | 
| Varonis.Alert.Category | String | Alert category. Options are:<br />- Reconnaissance <br />- Intrusion <br />- Exploitation <br />- Privilege Escalation <br />- Lateral Movement  | 
| Varonis.Alert.Country | String | Name of the country from which the event occurred | 
| Varonis.Alert.State | String | Name of the state or regional subdivision from which the event occurred | 
| Varonis.Alert.Status | String | Alert state. Options are:<br />- Open<br />- Under investigation<br />- Closed | 
| Varonis.Alert.CloseReason | String | Reason the alert was closed. Options are:<br />- Resolved<br />- Misconfiguration<br />- Threat model disabled or deleted<br />- Account misclassification<br />- Legitimate activity<br />- Other | 
| Varonis.Alert.BlacklistLocation | Boolean | Whether any of the geographical locations from which an alerted activity originated was on the blacklist at the time the activity occurred | 
| Varonis.Alert.AbnormalLocation | Boolean | Whether any of the geographical locations from which an alerted activity originated is new or abnormal to the organization, the user and peers, or only the user | 
| Varonis.Alert.NumOfAlertedEvents | Number | Number of events with alerts | 
| Varonis.Alert.UserName | String | Name of the users triggered alerts | 
| Varonis.Alert.By.SamAccountName | String | Logon name used to support clients and servers running earlier versions of Windows operating system, such as Windows NT 4.0. In the dashboards \(other than the Alert dashboard\), this is the SAM account name of the user or group | 
| Varonis.Alert.By.PrivilegedAccountType | String | Privileged account. Options are:<br />- Service accounts<br />- Admin accounts<br />- Executive accounts | 
| Varonis.Alert.By.HasFollowUpIndicators | Boolean | Whether global flags, tags or notes are associated with the user | 
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
```!varonis-get-alerts page=1 Alert_Status=Open max_results=1 Start_time=2022-02-16T13:00:00+02:00```
#### Context Example
```json
{
    "Varonis": {
        "Alert": [
            {
                "AbnormalLocation": "",
                "BlacklistLocation": "",
                "By": {
                    "HasFollowUpIndicators": "",
                    "PrivilegedAccountType": "",
                    "SamAccountName": ""
                },
                "Category": "Privilege Escalation",
                "CloseReason": "",
                "Country": "",
                "Device": {
                    "ContainMaliciousExternalIP": "No",
                    "IPThreatTypes": "",
                    "Name": "ilhrzrodc01"
                },
                "ID": "11B7609A-4C0E-4771-A1D0-7EA27882C9B6",
                "Name": "dns aaaaaalert",
                "NumOfAlertedEvents": "1",
                "On": {
                    "Asset": "",
                    "ContainsFlaggedData": "",
                    "ContainsSensitiveData": "",
                    "FileServerOrDomain": "DNS",
                    "Platform": "DNS"
                },
                "Severity": "High",
                "State": "",
                "Status": "Open",
                "Time": "2022-03-18T12:08:00",
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

>### Results
>|Alert|Pagination|
>|---|---|
>| {'ID': '11B7609A-4C0E-4771-A1D0-7EA27882C9B6', 'Name': 'dns aaaaaalert', 'Time': '2022-03-18T12:08:00', 'Severity': 'High', 'Category': 'Privilege Escalation', 'Country': '', 'State': '', 'Status': 'Open', 'CloseReason': '', 'BlacklistLocation': '', 'AbnormalLocation': '', 'NumOfAlertedEvents': '1', 'UserName': '', 'By': {'SamAccountName': '', 'PrivilegedAccountType': '', 'HasFollowUpIndicators': ''}, 'On': {'ContainsFlaggedData': '', 'ContainsSensitiveData': '', 'Platform': 'DNS', 'Asset': '', 'FileServerOrDomain': 'DNS'}, 'Device': {'Name': 'ilhrzrodc01', 'ContainMaliciousExternalIP': 'No', 'IPThreatTypes': ''}} | Page: 1<br/>PageSize: 1 |


### varonis-update-alert-status
***
Update alert status


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
Close the alert


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
| Alert_id | List of alert IDs. | Required |
| max_results | Maximum number of alerts to retrieve (up to 5k). | Optional |
| page | Page number. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Varonis.Event.Type | String | Event type | 
| Varonis.Event.UTCTime | Date | Event time UTC format |
| Varonis.Event.Status | String | Filters according to the status of the event. Options are:<br />- Fail<br />- Success | 
| Varonis.Event.Description | String | Description of the activity | 
| Varonis.Event.Country | String | Name of the country from which the event occurred | 
| Varonis.Event.State | String | Name of the state or regional subdivision from which the event occurred | 
| Varonis.Event.Details.IsBlacklist | Boolean | Whether any of the geographical locations from which an alerted activity originated was on the blacklist at the time the activity occurred | 
| Varonis.Event.Details.Operation | String | Type of operation that occurred during the event. Options are:<br />- Accessed<br />- Added<br />- Changed<br />- Removed<br />- Sent<br />- Received<br />- Requested | 
| Varonis.Event.ByUser.Name | String | Name of the user that triggered the event | 
| Varonis.Event.ByUser.UserType | String | Type of account, i.e., user or computer | 
| Varonis.Event.ByUser.UserAccountType | String | Logon name used to support clients and servers running earlier versions of the Windows operating system, such as Windows NT 4.0.
In the dashboards \(other than the Alert dashboard\), this is the SAM account name of the user or group | 
| Varonis.Event.ByUser.Domain | String | Domain of the user that triggered the event | 
| Varonis.Event. ByUser.DisabledAccount | Boolean | Whether the account is disabled | 
| Varonis.Event.ByUser.StaleAccount | Boolean | Whether the account is stale | 
| Varonis.Event.ByUser.LockoutAccounts | Boolean | Wwhether the account is lockout | 
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
| Varonis.Event.OnObject.UserAccountType | String | Specified type of privileged account. Options are:<br />- Service accounts<br />- Admin accounts<br />- Executive accounts<br />- Test accounts | 
| Varonis.Event.OnObject.DestinationIP | String | Destination IP address within the organization | 
| Varonis.Event.OnObject.DestinationDevice | String | Destination host name for relevant services | 
| Varonis.Pagination.Page | Number | Current page number requested by user | 
| Varonis.Pagination.PageSize | Number | Number of records on the page |

#### Command example
```!varonis-get-alerted-events page=1 Alert_id=72D0D925-0937-4111-AB4A-FFFD4A529A3C max_results=1```
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

>### Results
>|Event|Pagination|
>|---|---|
>| {'ID': '22D3EFC0-E758-4BA0-92C4-EB9566C830AD', 'Type': 'Client DNS request', 'UTCTime': '2022-03-17T17:52:14Z', 'Status': 'Success', 'Description': 'The DNS Server has resolved successfully ', 'Country': '', 'State': '', 'Details': {'IsBlacklist': '', 'Operation': 'Request'}, 'ByUser': {'Name': '', 'UserType': '', 'UserAccountType': '', 'SAMAccountName': '', 'Domain': '', 'DisabledAccount': '', 'StaleAccount': '', 'LockoutAccounts': ''}, 'SourceIP': '10.10.10.10', 'IsMaliciousIP': '', 'IPReputation': '', 'IPThreatType': '', 'OnObject': {'Name': 'dns.msftncsi.com', 'ObjectType': 'Dns', 'Platform': 'DNS', 'IsSensitive': '', 'FileServerOrDomain': 'DNS', 'IsDisabledAccount': '', 'IsLockOutAccount': '', 'SAMAccountName': '', 'UserAccountType': '', 'DestinationIP': '', 'DestinationDevice': ''}} | Page: 1<br/>PageSize: 1 |

