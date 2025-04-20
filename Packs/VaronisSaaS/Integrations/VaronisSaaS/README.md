Streamline alerts and related forensic information from Varonis SaaS

## Configure Varonis SaaS in Cortex


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


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### varonis-get-threat-models

***
Get Varonis threat models  

#### Base Command

`varonis-get-threat-models`

#### Input

| **Argument Name** | **Description**                                                                            | **Required** |
| --- |--------------------------------------------------------------------------------------------|--------------|
| name | List of requested threat model names. Pipe (`\|`) separated and wildcards (`*`) supported. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- |----------|----------------------|
| ID | Number    | ID of the threat model | 
| Name | String  | Name of the threat model | 

#### Command example
```!varonis-get-threat-models```  
```!varonis-get-threat-models name="*access to*|Domain controller*"```

#### Context Example
```json
[
    {
        "ThreatModel.Name": "Abnormal service behavior: access to atypical folders",
        "ThreatModel.Category": "Exfiltration",
        "ThreatModel.Severity": "3 - Error",
        "ThreatModel.Source": "Predefined",
        "ThreatModel.ID": 1
    },
    {
        "ThreatModel.Name": "Abnormal service behavior: access to atypical files",
        "ThreatModel.Category": "Exfiltration",
        "ThreatModel.Severity": "3 - Error",
        "ThreatModel.Source": "Predefined",
        "ThreatModel.ID": 2
    }
]
```

#### Human Readable Output

>### Varonis Alerts
>|ID|Name|Category|Severity|Source|
>|---|---|---|---|---|
>| 1 | Abnormal service behavior: access to atypical folders | Exfiltration | 3 - Error | Predefined |\n| 2 | Abnormal service behavior: access to atypical files | Exfiltration | 3 - Error | Predefined |


### varonis-get-alerts

***
Get alerts from Varonis DA

#### Base Command

`varonis-get-alerts`

#### Input

| **Argument Name** | **Description**                                                       | **Required** |
| --- |-----------------------------------------------------------------------| --- |
| threat_model_name | List of requested threat models to retrieve.                          | Optional | 
| start_time | Start time (UTC) of alert range.                                      | Optional | 
| end_time | End time (UTC) of alert range.                                        | Optional | 
| alert_status | List of required alerts status.                                       | Optional | 
| alert_severity | List of required alerts severity.                                     | Optional | 
| device_name | List of required alerts device name.                                  | Optional | 
| user_name | User domain name (cannot be provided without user_name).              | Optional | 
| last_days | Number of days you want the search to go back to.                     | Optional | 
| extra_fields | Extra fields.                                                         | Optional | 
| descending_order | Indicates whether alerts should be ordered in newest to oldest order. | Optional | 

#### Context Output

| **Path** | **Type** | **Description**                                                                                                                                                                                                                      |
| --- | --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Varonis.Alert.ID | Number | Varonis ID for alert                                                                                                                                                                                                                 | 
| Varonis.Alert.Rule.Name | String | Name of retrieved alert                                                                                                                                                                                                              | 
| Varonis.Alert.TimeUTC | Date | When was the alert triggered                                                                                                                                                                                                         | 
| Varonis.Alert.Rule.Severity.Name | String | Alert severity                                                                                                                                                                                                                       | 
| Varonis.Alert.Rule.Category.Name | String | Alert category. <br/>Options are: <br/>- Reconnaissance<br/>- Intrusion<br/>- Exploitation<br/>- Privilege Escalation <br/>- Lateral Movement                                                                                        |
| Varonis.Alert.Location.CountryName | String | Name of the country from which the event occurred                                                                                                                                                                                    | 
| Varonis.Alert.Location.SubdivisionName | String | Name of the state or regional subdivision from which the event occurred                                                                                                                                                              | 
| Varonis.Alert.Status.Name | String | Alert state. Options are:<br/>- New<br/>- Under investigation<br/>- Closed<br/>- Action Required<br/>- Auto-Resolved                                                                                                                 |
| Varonis.Alert.CloseReason.Name | String | Reason the alert was closed. Options are:<br/>- Other<br/>- Benign activity<br/>- True positive<br/>- Environment misconfiguration<br/>- Alert recently customized<br/>- Inaccurate alert logic<br/>- Authorized activity                                        |
| Varonis.Alert.Location.BlacklistedLocation | Boolean | Whether any of the geographical locations from which an alerted activity originated was on the blacklist at the time the activity occurred                                                                                           | 
| Varonis.Alert.Location.AbnormalLocation | Boolean | Whether any of the geographical locations from which an alerted activity originated is new or abnormal to the organization, the user and peers, or only the user                                                                     | 
| Varonis.Alert.EventsCount | Number | Number of events with alerts                                                                                                                                                                                                         | 
| Varonis.Alert.User.Name | String | Name of the users triggered alerts                                                                                                                                                                                                   | 
| Varonis.Alert.User.SamAccountName | String | Logon name used to support clients and servers running earlier versions of Windows operating system, such as Windows NT 4.0. In the dashboards \(other than the Alert dashboard\), this is the SAM account name of the user or group | 
| Varonis.Alert.User.AccountType.Name | String | Privileged account associated with the user in the alert. Options are:<br/>- Service accounts<br/>- Admin accounts<br/>- Executive accounts                                                                                          |
| Varonis.Alert.Data.IsFlagged | Boolean | Whether the data affected by the alerted events has global flags                                                                                                                                                                     | 
| Varonis.Alert.Data.IsSensitive | Boolean | Filters according to whether the resource on which the event was performed is sensitive \(including subfolders\)                                                                                                                     | 
| Varonis.Alert.Filer.Platform.Name | String | Type of platform on which the server resides. For example, Windows, Exchange, or SharePoint                                                                                                                                          | 
| Varonis.Alert.Asset.Path | String | Path of the alerted asset                                                                                                                                                                                                            | 
| Varonis.Alert.Filer.Name | String | Associated file server/domain                                                                                                                                                                                                        | 
| Varonis.Alert.Device.HostName | String | Name of the device from which the user generated the event                                                                                                                                                                           | 
| Varonis.Alert.Device.IsMaliciousExternalIP | Boolean | Whether the alert contains IPs known to be malicious                                                                                                                                                                                 | 
| Varonis.Alert.Device.ExternalIPThreatTypesName | String | Whether the alert contains IPs known to be malicious                                                                                                                                                                                 | 
| Varonis.Alert.Status.ID | String | Id for the status of the alert                                                                                                                                                                                                       | 
| Varonis.Alert.Rule.ID | String | Id for the rule that triggered the alert                                                                                                                                                                                             | 
| Varonis.Alert.Rule.Severity.ID | String | Severity level identifier                                                                                                                                                                                                            | 
| Varonis.Alert.Initial.Event.TimeUTC | Date | UTC time of the initial event that triggered the alert                                                                                                                                                                               | 
| Varonis.Alert.User.SidID | String | Security Identifier \(SID\) of the user associated with the alert                                                                                                                                                                    | 
| Varonis.Alert.IngestTime | Date | Time when the alert was ingested into the system                                                                                                                                                                                     | 

#### Command example
```!varonis-get-alerts start_time="2023-12-01T09:58:00" end_time="2023-12-07T04:16:00" alert_status="New" alert_severity="High" device_name="intfc35adh" threat_model_name="Deletion: Active Directory containers, Foreign Security Principal, or GPO" extra_fields="Alert.MitreTactic.*"```
#### Context Example
```json
[
  {
    "Alert.Rule.Name": "Deletion: Multiple directory service objects",
    "Alert.Rule.Severity.Name": "Medium",
    "Alert.TimeUTC": "2023-12-11T03:50:00",
    "Alert.Rule.Category.Name": "Denial of Service",
    "Alert.User.Name": "varadm (intaf6fb.com)",
    "Alert.Status.Name": "New",
    "Alert.ID": "A5F4B69A-F5C0-494F-B5B4-185185BC3FBE",
    "Alert.Rule.ID": "140",
    "Alert.Rule.Severity.ID": "1",
    "Alert.Location.CountryName": "",
    "Alert.Location.SubdivisionName": "",
    "Alert.Status.ID": "1",
    "Alert.EventsCount": "14",
    "Alert.Initial.Event.TimeUTC": "2023-12-11T03:41:00",
    "Alert.User.SamAccountName": "varadm",
    "Alert.User.AccountType.Name": "Admin,Executive",
    "Alert.Device.HostName": "intaf6fbdh",
    "Alert.Device.IsMaliciousExternalIP": "",
    "Alert.Device.ExternalIPThreatTypesName": "",
    "Alert.Data.IsFlagged": "0",
    "Alert.Data.IsSensitive": "0",
    "Alert.Filer.Platform.Name": "Active Directory",
    "Alert.Asset.Path": "intaf6fb.com(AD-intaf6fb.com)",
    "Alert.Filer.Name": "AD-intaf6fb.com",
    "Alert.CloseReason.Name": "",
    "Alert.Location.BlacklistedLocation": "",
    "Alert.Location.AbnormalLocation": "",
    "Alert.User.SidID": "971",
    "Alert.IngestTime": "2023-12-11T03:52:46",
    "Url": "/#/app/analytics/entity/Alert/A5F4B69A-F5C0-494F-B5B4-185185BC3FBE"
  }
]
```

#### Human Readable Output

>### Varonis Alerts
>|Alert.Rule.Name|Alert.Rule.Severity.Name|Alert.TimeUTC|Alert.Rule.Category.Name|Alert.User.Name|Alert.Status.Name|Alert.ID|
>|---|---|---|--|----------------------------|-------|-------|
>| Deletion: Multiple directory service objects | Medium | 2023-12-11T03:50:00 | Denial of Service | varadm (intaf6fb.com) | New | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE |


### varonis-get-alerted-events

***
Get events applied to specific alerts

#### Base Command

`varonis-get-alerted-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | List of alert IDs. | Required | 
| start_time | Start UTC time of alert range. | Optional | 
| end_time | End UTC time of alert range. | Optional | 
| last_days | Number of days you want the search to go back to. | Optional | 
| extra_fields | Extra fields. | Optional | 
| descending_order | Indicates whether events should be ordered in newest to oldest order. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Varonis.Event.ID | String | Event ID | 
| Varonis.Event.Alert.ID | String | Alert ID | 
| Varonis.Event.Type.Name | String | Event type | 
| Varonis.Event.TimeUTC | Date | Event time in UTC format | 
| Varonis.Event.Status.Name | String | Filters according to the status of the event. Options are:<br/>- Fail<br/>- Success | 
| Varonis.Event.Description | String | Description of the activity | 
| Varonis.Event.Location.Country.Name | String | Name of the country from which the event occurred | 
| Varonis.Event.Location.Subdivision.Name | String | Name of the state or regional subdivision from which the event occurred | 
| Varonis.Event.Device.ExternalIP.IP | String | Device external IP address | 
| Varonis.Event.Location.BlacklistedLocation | Boolean | Indicates whether the geographical location from which the event originated was blacklisted | 
| Varonis.Event.Operation.Name | String | Type of operation that occurred during the event. Options are:<br/>- Accessed<br/>- Added<br/>- Changed<br/>- Removed<br/>- Sent<br/>- Received<br/>- Requested |
| Varonis.Event.ByAccount.Identity.Name | String | Name of the user that triggered the event | 
| Varonis.Event.ByAccount.Type.Name | String | Type of account, i.e., user or computer | 
| Varonis.Event.ByAccount.SamAccountName | String | SAM account name of the user or group for clients and servers running earlier versions of Windows | 
| Varonis.Event.ByAccount.Domain.Name | String | Domain of the user that triggered the event | 
| Varonis.Event.ByAccount.IsDisabled | Boolean | Indicates whether the account is disabled | 
| Varonis.Event.ByAccount.IsStale | Boolean | Indicates whether the account is stale | 
| Varonis.Event.ByAccount.IsLockout | Boolean | Indicates whether the account is locked out | 
| Varonis.Event.IP | String | Source IP address of the device that triggered the event | 
| Varonis.Event.Device.ExternalIP.IsMalicious | Boolean | Indicates whether the external IP is known to be malicious | 
| Varonis.Event.Device.ExternalIP.Reputation.Name | Number | Reputation score of the external IP, a numeric value from 1-100 | 
| Varonis.Event.Device.ExternalIP.ThreatTypes.Name | String | List of threat types associated with the external IP | 
| Varonis.Event.OnObjectName | String | Name of the object on which the event was performed | 
| Varonis.Event.OnResource.ObjectType.Name | String | Type of the object on which the event was performed | 
| Varonis.Event.Filer.Platform.Name | String | Type of platform on which the server resides, like Windows, Exchange, SharePoint | 
| Varonis.Event.OnResource.IsSensitive | Boolean | Indicates whether the resource on which the event was performed is sensitive | 
| Varonis.Event.Filer.Name | String | File server of the object on which the event was performed | 
| Varonis.Event.OnAccount.IsDisabled | Boolean | Indicates whether the account is disabled | 
| Varonis.Event.OnAccount.IsLockout | Boolean | Indicates whether the account is locked out | 
| Varonis.Event.OnAccount.SamAccountName | Boolean | SAM account name of the user or group for clients and servers running earlier versions of Windows | 
| Varonis.Event.Destination.IP | String | Destination IP address within the organization | 
| Varonis.Event.Device.Name | String | Name of the device that triggered the event | 
| Varonis.Event.Destination.DeviceName | String | Destination host name for relevant services | 
| Varonis.Event.OnResource.Path | String | Path of the resource | 


#### Command example
```varonis-get-alerted-events alert_id="C98A3E72-99E9-4E5C-A560-7D04FA60686E,C83D55F0-EC63-41FC-B8C6-A5A66CB51372" last_days=7 extra_fields="Event.ByAccount.DistinguishedName"```
#### Context Example
```json
[
  {
    "Event.Type.Name": "DS object deleted",
    "Event.Description": "Organizational Unit \"CommitOu_a9c42\" was deleted",
    "Event.Filer.Platform.Name": "Active Directory",
    "Event.Filer.Name": "AD-intaf6fb.com",
    "Event.ByAccount.SamAccountName": "varadm",
    "Event.OnObjectName": "CommitOu_a9c42",
    "Event.Alert.ID": "A5F4B69A-F5C0-494F-B5B4-185185BC3FBE",
    "Event.ID": "7D87B6A2-C9C2-4859-A076-DD4D0EFC8276",
    "Event.TimeUTC": "2023-12-11T03:41:08.000Z",
    "Event.Status.Name": "Success",
    "Event.Location.Country.Name": "",
    "Event.Location.Subdivision.Name": "",
    "Event.Location.BlacklistedLocation": "",
    "Event.Operation.Name": "Deleted",
    "Event.ByAccount.Type.Name": "User",
    "Event.ByAccount.Domain.Name": "intaf6fb.com",
    "Event.ByAccount.Identity.Name": "varadm",
    "Event.IP": "",
    "Event.Device.ExternalIP.IP": "",
    "Event.Destination.IP": "",
    "Event.Device.Name": "intaf6fbdh",
    "Event.Destination.DeviceName": "",
    "Event.ByAccount.IsDisabled": "No",
    "Event.ByAccount.IsStale": "No",
    "Event.ByAccount.IsLockout": "No",
    "Event.Device.ExternalIP.ThreatTypes.Name": "",
    "Event.Device.ExternalIP.IsMalicious": "",
    "Event.Device.ExternalIP.Reputation.Name": "",
    "Event.OnResource.ObjectType.Name": "Organizational unit",
    "Event.OnAccount.SamAccountName": "51d4ee86-db4a-4d4a-baaa-1b84e02afd59",
    "Event.OnResource.IsSensitive": "",
    "Event.OnAccount.IsDisabled": "",
    "Event.OnAccount.IsLockout": "",
    "Event.OnResource.Path": "intaf6fb.com\\CommitOu_a9c42"
  }
]
```

#### Human Readable Output

>### Varonis Alerted Events
>|Event.Type.Name|Event.Description|Event.Filer.Platform.Name|Event.Filer.Name|Event.ByAccount.SamAccountName|Event.OnObjectName|Event.Alert.ID|Event.ID|Event.TimeUTC|Event.Status.Name|Event.Location.Country.Name|Event.Location.Subdivision.Name|Event.Location.BlacklistedLocation|Event.Operation.Name|Event.ByAccount.Type.Name|Event.ByAccount.Domain.Name|Event.ByAccount.Identity.Name|Event.IP|Event.Device.ExternalIP.IP|Event.Destination.IP|Event.Device.Name|Event.Destination.DeviceName|Event.ByAccount.IsDisabled|Event.ByAccount.IsStale|Event.ByAccount.IsLockout|Event.Device.ExternalIP.ThreatTypes.Name|Event.Device.ExternalIP.IsMalicious|Event.Device.ExternalIP.Reputation.Name|Event.OnResource.ObjectType.Name|Event.OnAccount.SamAccountName|Event.OnResource.IsSensitive|Event.OnAccount.IsDisabled|Event.OnAccount.IsLockout|Event.OnResource.Path|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| DS object deleted | Organizational Unit "CommitOu_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | CommitOu_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | 7D87B6A2-C9C2-4859-A076-DD4D0EFC8276 | 2023-12-11T03:41:08.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | Organizational unit | 51d4ee86-db4a-4d4a-baaa-1b84e02afd59 |  |  |  | intaf6fb.com\\CommitOu_a9c42 |\n| DS object deleted | User "intaf6fb.com\\PolWinRolU_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | intaf6fb.com\\PolWinRolU_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | B75C4ECE-48BA-4172-BBB1-68B85E3ABB6F | 2023-12-11T03:41:08.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | User | PolWinRolU_a9c42 |  | No | No | intaf6fb.com\\Users\\PolWinRolU_a9c42 |\n| DS object deleted | User "intaf6fb.com\\Add_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | intaf6fb.com\\Add_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | 4800A52F-F8C2-483A-BC39-A68D1AF13D98 | 2023-12-11T03:41:08.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | User | Add_a9c42 |  | No | No | intaf6fb.com\\Users\\Add_a9c42 |\n| DS object deleted | Organizational Unit "CommitOu_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | CommitOu_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE,0AB569DA-B58E-4DC5-9FC2-8793BA118C88 | DFEE2A16-E0DF-4777-BA8A-390DD869D413 | 2023-12-11T03:41:08.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | Organizational unit | 51d4ee86-db4a-4d4a-baaa-1b84e02afd59 |  |  |  | intaf6fb.com\\CommitOu_a9c42 |\n| DS object deleted | "intaf6fb.com\\CommitAdGroup_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | intaf6fb.com\\CommitAdGroup_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | FA2F5005-6EFC-46B9-BC95-E88CD3838D1A | 2023-12-11T03:41:08.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | Group | CommitAdGroup_a9c42 |  |  |  | intaf6fb.com\\Users\\CommitAdGroup_a9c42 |\n| DS object deleted | User "intaf6fb.com\\RollbackRemove_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | intaf6fb.com\\RollbackRemove_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | 0A5A616D-D3CA-4623-A248-18DC0E7AB67A | 2023-12-11T03:41:08.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | User | RollbackRemove_a9c42 |  | No | No | intaf6fb.com\\Users\\RollbackRemove_a9c42 |\n| DS object deleted | User "intaf6fb.com\\Remove_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | intaf6fb.com\\Remove_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | 59E8DE00-7F0F-4637-B5DA-BC8842B2533F | 2023-12-11T03:41:08.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | User | Remove_a9c42 |  | No | No | intaf6fb.com\\Users\\Remove_a9c42 |\n| DS object deleted | "CommitNewGroup_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | CommitNewGroup_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | 5CC0C582-C5D6-4ED2-8596-BBBFD0ABB746 | 2023-12-11T03:41:08.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | Group | a9dde0e5-1346-4d15-a9dc-0c1337ddab2f |  |  |  | intaf6fb.com\\CommitOu_a9c42\\CommitNewGroup_a9c42 |\n| DS object deleted | User "intaf6fb.com\\CommitAdUser_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | intaf6fb.com\\CommitAdUser_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | AD3642A0-B90B-4349-ADB1-206749BF18E8 | 2023-12-11T03:41:08.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | User | CommitAdUser_a9c42 |  | No | No | intaf6fb.com\\Users\\CommitAdUser_a9c42 |\n| DS object deleted | User "intaf6fb.com\\RollbackRemove_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | intaf6fb.com\\RollbackRemove_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | 015579AF-E357-4D16-AAC0-50B76E7D7104 | 2023-12-11T03:41:05.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | User | RollbackRemove_a9c42 |  | No | No | intaf6fb.com\\Users\\RollbackRemove_a9c42 |\n| DS object deleted | User "intaf6fb.com\\Add_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | intaf6fb.com\\Add_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | B38D714B-8D20-4E68-8EFC-709C128C136C | 2023-12-11T03:41:05.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | User | Add_a9c42 |  | No | No | intaf6fb.com\\Users\\Add_a9c42 |\n| DS object deleted | User "intaf6fb.com\\Remove_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | intaf6fb.com\\Remove_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | E5F15080-A7C0-42CF-A911-05627FF26179 | 2023-12-11T03:41:05.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | User | Remove_a9c42 |  | No | No | intaf6fb.com\\Users\\Remove_a9c42 |\n| DS object deleted | User "intaf6fb.com\\CommitAdUser_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | intaf6fb.com\\CommitAdUser_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | A9673047-6CDD-4404-805F-38B5CACAC047 | 2023-12-11T03:41:05.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | User | CommitAdUser_a9c42 |  | No | No | intaf6fb.com\\Users\\CommitAdUser_a9c42 |\n| DS object deleted | User "intaf6fb.com\\PolWinRolU_a9c42" was deleted | Active Directory | AD-intaf6fb.com | varadm | intaf6fb.com\\PolWinRolU_a9c42 | A5F4B69A-F5C0-494F-B5B4-185185BC3FBE | 967A5AA4-391C-4AB6-BB33-592AACCFB4D2 | 2023-12-11T03:41:04.000Z | Success |  |  |  | Deleted | User | intaf6fb.com | varadm |  |  |  | intaf6fbdh |  | No | No | No |  |  |  | User | PolWinRolU_a9c42 |  | No | No | intaf6fb.com\\Users\\PolWinRolU_a9c42 |


### varonis-alert-add-note

***
Add note to alerts

#### Base Command

`varonis-alert-add-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Requested alerts. | Required | 
| note | Note. | Required | 

#### Context Output

There is no context output for this command.

#### Command example
```!varonis-alert-add-note alert_id=C98A3E72-99E9-4E5C-A560-7D04FA60686E note="This needs to be invested ASAP" ```


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
| note | Note. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example
```!varonis-update-alert-status alert_id=C98A3E72-99E9-4E5C-A560-7D04FA60686E status="Action Required" note="Waiting for feedback from security team" ```


### varonis-close-alert

***
Close the alert

#### Base Command

`varonis-close-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Requested alerts. | Required | 
| close_reason | The reason the alert was closed. Possible values are: Other, Benign activity, True positive, Environment misconfiguration, Alert recently customized, Inaccurate alert logic, Authorized activity. | Required | 
| note | Note. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example
```!varonis-close-alert  alert_id=C98A3E72-99E9-4E5C-A560-7D04FA60686E close_reason="Inaccurate alert logic"  note="Alert is irrelevant. Closed" ```


### get-mapping-fields
***
Returns the list of fields to map in outgoing mirroring. This command is only used for debugging purposes.


#### Base Command

`get-mapping-fields`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

## Incident Mirroring

You can enable outgoing incident mirroring between Cortex XSOAR incidents and Varonis alerts (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored (currently only outgoing mirroring is available):

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in Varonis SaaS service (outgoing mirrored fields). |


Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.

### Mirroring Out Notes
The supported fields in the mirroring out process are:
- Varonis Alert Status.
- Varonis Close Reason
- Incident Close Notes

**Important Note:**
You have two options how to close Varonis Alert:
 - The first option is to change the Varonis Alert Status field in the XSOAR incident. In this case, the status of the alert in Varonis SaaS service will be change by the mirroring functionality, but the Incident in XSOAR won't be closed.
 - The second one is to close the incident in XSOAR. In this case, the Varonis Alert will be closed on the Varonis side by the post-processing script.