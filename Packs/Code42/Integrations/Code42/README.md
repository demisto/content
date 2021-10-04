Use the Code42 integration to identify potential data exfiltration from insider threats while speeding investigation and response by providing fast access to file events and metadata across physical and cloud environments.
## Configure Code42 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Code42.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| console_url | Code42 Console URL for your Code42 environment | True |
| credentials | Username | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| alert_severity | Alert severities to fetch when fetching incidents | False |
| fetch_time | First fetch time range \(&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes\) | False |
| fetch_limit | Alerts to fetch per run; note that increasing this value may result in slow performance if too many results are returned at once | False |
| include_files | Include the list of files in returned incidents. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### code42-securitydata-search
***
Searches for a file in Security Data by JSON query, hash, username, device hostname, exfiltration type, or a combination of parameters. At least one argument must be passed in the command. If a JSON argument is passed, it will be used to the exclusion of other parameters, otherwise parameters will be combined with an AND clause.


#### Base Command

`code42-securitydata-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| json | JSON query payload using Code42 query syntax. | Optional |
| hash | MD5 or SHA256 hash of the file to search for. | Optional |
| username | Username to search for. | Optional |
| hostname | Hostname to search for. | Optional |
| exposure | Exposure types to search for. Can be "RemovableMedia", "ApplicationRead", "CloudStorage", "IsPublic", "SharedViaLink", or "SharedViaDomain". | Optional |
| results | The number of results to return. The default is 100. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.SecurityData.EventTimestamp | date | Timestamp for the event. |
| Code42.SecurityData.FileCreated | date | File creation date. |
| Code42.SecurityData.EndpointID | string | Code42 device ID. |
| Code42.SecurityData.DeviceUsername | string | The username that the device is associated with in Code42. |
| Code42.SecurityData.EmailFrom | string | The sender email address for email exfiltration events. |
| Code42.SecurityData.EmailTo | string | The recipient email address for email exfiltration events. |
| Code42.SecurityData.EmailSubject | string | The email subject line for email exfiltration events. |
| Code42.SecurityData.EventID | string | The Security Data event ID. |
| Code42.SecurityData.EventType | string | The type of Security Data event. |
| Code42.SecurityData.FileCategory | string | The file type, as determined by Code42 engine. |
| Code42.SecurityData.FileOwner | string | The owner of the file. |
| Code42.SecurityData.FileName | string | The file name. |
| Code42.SecurityData.FilePath | string | The path to file. |
| Code42.SecurityData.FileSize | number | The size of the file \(in bytes\). |
| Code42.SecurityData.FileModified | date | The date the file was last modified. |
| Code42.SecurityData.FileMD5 | string | MD5 hash of the file. |
| Code42.SecurityData.FileHostname | string | Hostname where the file event was captured. |
| Code42.SecurityData.DevicePrivateIPAddress | string | Private IP addresses of the device where the event was captured. |
| Code42.SecurityData.DevicePublicIPAddress | string | Public IP address of the device where the event was captured. |
| Code42.SecurityData.RemovableMediaType | string | Type of removable media. |
| Code42.SecurityData.RemovableMediaCapacity | number | Total capacity of removable media \(in bytes\). |
| Code42.SecurityData.RemovableMediaMediaName | string | The full name of the removable media. |
| Code42.SecurityData.RemovableMediaName | string | The name of the removable media. |
| Code42.SecurityData.RemovableMediaSerialNumber | string | The serial number for the removable medial device. |
| Code42.SecurityData.RemovableMediaVendor | string | The vendor name for removable device. |
| Code42.SecurityData.FileSHA256 | string | The SHA256 hash of the file. |
| Code42.SecurityData.FileShared | boolean | Whether the file is shared using a cloud file service. |
| Code42.SecurityData.FileSharedWith | string | Accounts that the file is shared with on a cloud file service. |
| Code42.SecurityData.Source | string | The source of the file event. Can be "Cloud" or "Endpoint". |
| Code42.SecurityData.ApplicationTabURL | string | The URL associated with the application read event. |
| Code42.SecurityData.ProcessName | string | The process name for the application read event. |
| Code42.SecurityData.ProcessOwner | string | The process owner for the application read event. |
| Code42.SecurityData.WindowTitle | string | The process name for the application read event. |
| Code42.SecurityData.FileURL | string | The URL of the file on a cloud file service. |
| Code42.SecurityData.Exposure | string | The event exposure type. |
| Code42.SecurityData.SharingTypeAdded | string | The type of sharing added to the file. |
| File.Name | string | The file name. |
| File.Path | string | The file path. |
| File.Size | number | The file size \(in bytes\). |
| File.MD5 | string | The MD5 hash of the file. |
| File.SHA256 | string | The SHA256 hash of the file. |
| File.Hostname | string | The hostname where the file event was captured. |


#### Command Example
```!code42-securitydata-search hash=eef8b12d2ed0d6a69fe77699d5640c7b exposure=CloudStorage,ApplicationRead```

#### Human Readable Output

| **EventType** | **FileName** | **FileSize** | **FileHostname** | **FileOwner** | **FileCategory** |
| --- | --- | --- | --- | --- | --- |
| READ\_BY\_APP | ProductPhoto.jpg | 333114 | DESKTOP-001 | john.user | IMAGE |


### code42-alert-get
***
Retrieve alert details by alert ID


#### Base Command

`code42-alert-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The alert ID to retrieve. Alert IDs are associated with alerts that are fetched via fetch-incidents. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.SecurityAlert.Username | string | The username associated with the alert. |
| Code42.SecurityAlert.Occurred | date | The timestamp when the alert occurred. |
| Code42.SecurityAlert.Description | string | The description of the alert. |
| Code42.SecurityAlert.ID | string | The alert ID. |
| Code42.SecurityAlert.Name | string | The alert rule name that generated the alert. |
| Code42.SecurityAlert.State | string | The alert state. |
| Code42.SecurityAlert.Type | string | The alert type. |
| Code42.SecurityAlert.Severity | string | The severity of the alert. |


#### Command Example
```!code42-alert-get id="a23557a7-8ca9-4ec6-803f-6a46a2aeca62"```

#### Human Readable Output

| **Type** | **Occurred** | **Username** | **Name** | **Description** | **State** | **ID** |
| --- | --- | --- | --- | --- | --- | --- |
| FED\_CLOUD\_SHARE_PERMISSIONS | 2019-10-08T17:38:19.0801650Z | john.user@123.org | Google Drive - Public via Direct Link |  Alert for public Google Drive files | OPEN | a23557a7-8ca9-4ec6-803f-6a46a2aeca62 |


### code42-alert-resolve
***
Resolves a Code42 Security alert.


#### Base Command

`code42-alert-resolve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The alert ID to resolve. Alert IDs are associated with alerts that are fetched via fetch-incidents. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.SecurityAlert.ID | string | The alert ID of the resolved alert. |


#### Command Example
```!code42-alert-resolve id="eb272d18-bc82-4680-b570-ac5d61c6cca6"```

#### Human Readable Output

| **ID** |
| --- |
| eb272d18-bc82-4680-b570-ac5d61c6cca6 |


### code42-departingemployee-add
***
Adds a user to the Departing Employee List.


#### Base Command

`code42-departingemployee-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username to add to the Departing Employee List. | Required |
| departuredate | The departure date for the employee, in the format YYYY-MM-DD. | Optional |
| note | Note to attach to the Departing Employee. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.DepartingEmployee.CaseID | string | Internal Code42 Case ID for the Departing Employee. Deprecated. Use Code42.DepartingEmployee.UserID. |
| Code42.DepartingEmployee.UserID | string | Internal Code42 User ID for the Departing Employee. |
| Code42.DepartingEmployee.Username | string | The username of the Departing Employee. |
| Code42.DepartingEmployee.Note | string | Note associated with the Departing Employee. |
| Code42.DepartingEmployee.DepartureDate | Unknown | The departure date for the Departing Employee. |


#### Command Example
```!code42-departingemployee-add username="john.user@123.org" departuredate="2020-02-28" note="Leaving for competitor"```

#### Human Readable Output

| **UserID** | **DepartureDate** | **Note** | **Username** | **CaseID** |
| --- | --- | --- | --- |
| 123 | 2020-02-28 | Leaving for competitor | john.user@example.com | 123 |


### code42-departingemployee-remove
***
Removes a user from the Departing Employee List.


#### Base Command

`code42-departingemployee-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username to remove from the Departing Employee List. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.DepartingEmployee.CaseID | string | Internal Code42 Case ID for the Departing Employee. Deprecated. Use Code42.DepartingEmployee.UserID. |
| Code42.DepartingEmployee.UserID | string | Internal Code42 User ID for the Departing Employee. |
| Code42.DepartingEmployee.Username | string | The username of the Departing Employee. |


#### Command Example
```!code42-departingemployee-remove username="john.user@example.com"```

#### Human Readable Output

| **UserID** | **Username** |
| --- | --- |
| 123 | john.user@example.com |


### code42-departingemployee-get
***
Retrieve departing employee details.


#### Base Command

`code42-departingemployee-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Email id of the departing employee. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.DepartingEmployee.UserID | string | Internal Code42 User ID for the Departing Employee. |
| Code42.DepartingEmployee.Username | string | The username of the Departing Employee. |
| Code42.DepartingEmployee.Note | string | Note associated with the Departing Employee. |
| Code42.DepartingEmployee.DepartureDate | Unknown | The departure date for the Departing Employee. |


#### Command Example
```!code42-departingemployee-get username="partner.demisto@example.com"```

#### Context Example
```
{
    "Code42": {
        "DepartingEmployee": {
            "DepartureDate": null,
            "Note": "Risky activity",
            "UserID": "942876157732602741",
            "Username": "partner.demisto@example.com"
        }
    }
}
```

#### Human Readable Output

### Retrieve departing employee
|DepartureDate|Note|UserID|Username|
|---|---|---|---|
|  | Risky activity | 942876157732602741 | partner.demisto@example.com |


### code42-departingemployee-get-all
***
Get all employees on the Departing Employee List.


#### Base Command

`code42-departingemployee-get-all`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| results | The number of items to return. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.DepartingEmployee.UserID | string | Internal Code42 User ID for the Departing Employee. |
| Code42.DepartingEmployee.Username | string | The username of the Departing Employee. |
| Code42.DepartingEmployee.Note | string | Note associated with the Departing Employee. |
| Code42.DepartingEmployee.DepartureDate | Unknown | The departure date for the Departing Employee. |


#### Command Example
```!code42-departingemployee-get-all```

#### Context Example
```
{
    "Code42": {
        "DepartingEmployee": [
            {
                "DepartureDate": null,
                "Note": "test",
                "UserID": "921333907298179098",
                "Username": "user1@example.com"
            },
            {
                "DepartureDate": "2020-07-20",
                "Note": "This is added using csv file to test bulk adding of users to high risk employee list",
                "UserID": "948333588694228306",
                "Username": "user2@example.com"
            },
            {
                "DepartureDate": null,
                "Note": "",
                "UserID": "912211111144144039",
                "Username": "user3@example.com"
            }
        ]
    }
}
```

#### Human Readable Output
### All Departing Employees
|DepartureDate|Note|UserID|Username|
|---|---|---|---|
| 2020-07-19 | User added from XSOAR | 921286907298179098 | user1@example.com |
| 2020-07-20 | User added from Jira ticket | 948938588694228306 | user1@example.com |
| 2020-07-20 | No note. | 912249223544144039 | unicode@example.com |
| 2020-07-20 | Lots of suspicious activity | 894165832411107815 | testuser@example.com |
| 2020-07-20 | L3 security risk | 949093399968329042 | user2@example.com |
| 2020-07-21 | Problems with performance | 942897397520286581 | user3@example.com |
| 2020-07-21 | Problems with performance | 906619740182876328 | user4@example.com |
| 2020-07-21 | Was a contract employee | 906619632003387560 | user5@example.com |
| 2020-07-21 | Was a contract employee | 912338501981077099 | user6@example.com |
| 2020-07-25 | Leaving for competitor | 951984198921509692 | user7@example.com.com |
| 2020-07-25 | Leaving for competitor | 895005723650937319 | user8@example.com |


### code42-highriskemployee-add
***
Adds a user from the High Risk Employee List.


#### Base Command

`code42-highriskemployee-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username to add to the High Risk Employee List. | Required |
| note | Note to attach to the High Risk Employee. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.HighRiskEmployee.UserID | string | Internal Code42 User ID for the High Risk Employee. |
| Code42.HighRiskEmployee.Username | string | The username of the High Risk Employee. |
| Code42.HighRiskEmployee.Note | string | Note associated with the High Risk Employee. |


#### Command Example
```!code42-highriskemployee-add username="partner.demisto@example.com" note="Risky activity"```

#### Context Example
```
{
    "Code42": {
        "HighRiskEmployee": {
            "UserID": "942876157732602741",
            "Username": "partner.demisto@example.com"
        }
    }
}
```

#### Human Readable Output
### Code42 High Risk Employee List User Added
|UserID|Username|
|---|---|
| 942876157732602741 | partner.demisto@example.com |


### code42-highriskemployee-remove
***
Removes a user from the High Risk Employee List.


#### Base Command

`code42-highriskemployee-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username to remove from the High Risk Employee List. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.HighRiskEmployee.UserID | Unknown | Internal Code42 User ID for the High Risk Employee. |
| Code42.HighRiskEmployee.Username | Unknown | The username of the High Risk Employee. |


#### Command Example
```!code42-highriskemployee-remove username="partner.demisto@example.com" note="Risky activity"```

#### Context Example
```
{
    "Code42": {
        "HighRiskEmployee": {
            "UserID": "942876157732602741",
            "Username": "partner.demisto@example.com"
        }
    }
}
```

#### Human Readable Output
### Code42 High Risk Employee List User Removed
|UserID|Username|
|---|---|
| 942876157732602741 | partner.demisto@example.com |



### code42-highriskemployee-get
***
Retrieve high risk employee details.


#### Base Command

`code42-highriskemployee-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Email id of the user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.HighRiskEmployee.UserID | string | Internal Code42 User ID for the High Risk Employee. |
| Code42.HighRiskEmployee.Username | string | The username of the High Risk Employee. |
| Code42.HighRiskEmployee.Note | string | Note associated with the High Risk Employee. |


#### Command Example
```!code42-highriskemployee-get username="partner.demisto@example.com"```

#### Context Example
```
{
    "Code42": {
        "HighRiskEmployee": {
            "Note": "Risky activity",
            "UserID": "942876157732602741",
            "Username": "partner.demisto@example.com"
        }
    }
}
```

#### Human Readable Output

### Retrieve high risk employee
|Note|UserID|Username|
|---|---|---|
| Risky activity | 942876157732602741 | partner.demisto@example.com |


### code42-highriskemployee-get-all
***
Get all employees on the High Risk Employee List.


#### Base Command

`code42-highriskemployee-get-all`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| risktags | To filter results by employees who have these risk tags. Space delimited. | Optional |
| results | The number of items to return. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.HighRiskEmployee.UserID | string | Internal Code42 User ID for the High Risk Employee. |
| Code42.HighRiskEmployee.Username | string | The username of the High Risk Employee. |
| Code42.HighRiskEmployee.Note | string | Note associated with the High Risk Employee. |


#### Command Example
```!code42-highriskemployee-get-all```

#### Context Example
```
{
    "Code42": {
        "HighRiskEmployee": [
            {
                "Note": "tests and more tests",
                "UserID": "111117397520286581",
                "Username": "user1@example.com"
            },
            {
                "Note": "Leaving for competitor",
                "UserID": "822222723650937319",
                "Username": "user2@example.com"
            },
            {
                "Note": "Test user addition from XSOAR",
                "UserID": "913333363086307495",
                "Username": "user3@example.com"
            }
        ]
    }
}
```

#### Human Readable Output
### Retrieved All High Risk Employees
|Note|UserID|Username|
|---|---|---|
| Clicked Phishing link | 942897397520286581 | user1@example.com |
| Lots of non-work-related activity | 895005723650937319 | user2@example.com |
| User added using XSOAR | 912098363086307495 | user3@example.com |
| User has performance concerns | 921286907298179098 | user4@example.com |
| Highly demanded employee | 942876157732602741 | user5@example.com |


### code42-highriskemployee-add-risk-tags
***



#### Base Command

`code42-highriskemployee-add-risk-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the High Risk Employee. | Required |
| risktags | Space-delimited risk tags to associate with the High Risk Employee. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.HighRiskEmployee.UserID | string | Internal Code42 User ID for the Departing Employee. |
| Code42.HighRiskEmployee.Username | string | The username of the High Risk Employee. |
| Code42.HighRiskEmployee.RiskTags | Unknown | Risk tags to associate with the High Risk Employee. |


#### Command Example
```!code42-highriskemployee-add-risk-tags username="partner.demisto@example.com" note="PERFORMANCE_CONCERN"```

#### Human Readable Output
### Code42 Risk Tags Added
| RiskTags | UserID | Username |
| -------- | ------ | -------- |
| PERFORMANCE_CONCERNS | 1234567890 | partners.demisto@example.com |


### code42-highriskemployee-remove-risk-tags
***



#### Base Command

`code42-highriskemployee-remove-risk-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the High Risk Employee. | Required |
| risktags | Space-delimited risk tags to disassociate from the High Risk Employee. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.HighRiskEmployee.UserID | string | Internal Code42 User ID for the Departing Employee. |
| Code42.HighRiskEmployee.Username | string | The username of the High Risk Employee. |
| Code42.HighRiskEmployee.RiskTags | Unknown | Risk tags to disassociate from the High Risk Employee. |


#### Command Example
```!code42-highriskemployee-remove-risk-tags username="partner.demisto@example.com" risktags="PERFORMANCE_CONCERNS"```

#### Context Example
```
{
    "Code42": {
        "HighRiskEmployee": [
            {
                "RiskTags": "PERFORMANCE_CONCERNS",
                "UserID": "942876157732602741",
                "Username": "partner.demisto@example.com"
            }
        ]
    }
}
```

#### Human Readable Output
### Code42 Risk Tags Removed
|RiskTags|UserID|Username|
|---|---|---|
| PERFORMANCE_CONCERNS | 942876157732602741 | partner.demisto@example.com |


### code42-user-create
***
Creates a Code42 user.


#### Base Command

`code42-user-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| orgname | The name of the Code42 organization from which to add the user. | Required |
| username | The username to give to the user. | Required |
| email | The email of the user to create. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.User.Username | String | A username for a Code42 user. |
| Code42.User.Email | String | An email for a Code42 user. |
| Code42.User.UserID | String | An ID for a Code42 user. |


#### Command Example
```!code42-user-create orgname="TestOrg" username="new.user@example.com" email="new.user@example.com"```

#### Human Readable Output
### Code42 User Created
| Email | UserID | Username |
| ----- | ------ | -------- |
| created.in.cortex.xsoar@example.com | 1111158111459014270 | created.in.cortex.xsoar@example.com |


### code42-user-block
***
Blocks a user in Code42.  A blocked user is not allowed to log in or restore files. Backups will continue if the user is still active.


#### Base Command

`code42-user-block`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to block. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.User.UserID | String | An ID for a Code42 user. |


#### Command Example
```!code42-user-block username="partner.demisto@example.com"```

#### Human Readable Output
### Code42 User Blocked
|UserID|
| --- |
| C2345 |


### code42-user-unblock
***
Removes a block, if one exists, on the user with the given user ID. Unblocked users are allowed to log in and restore.

#### Base Command

`code42-user-unblock`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to unblock. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.User.UserID | String | An ID for a Code42 user. |


#### Command Example
```!code42-user-unblock username="partner.demisto@example.com"```

#### Human Readable Output
### Code42 User Blocked
|UserID|
| --- |
| C2345 |


### code42-user-deactivate
***
Deactivate a user in Code42; signing them out of their devices. Backups discontinue for a deactivated user, and their archives go to cold storage.


#### Base Command

`code42-user-deactivate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to deactivate. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.User.UserID | String | The ID of a Code42 User. |


#### Command Example
```!code42-user-deactivate username="partner.demisto@example.com"```

#### Human Readable Output
### Code42 User Deactivated
| UserID |
| ------ |
| 123456790 |


### code42-user-reactivate
***
Reactivates the user with the given username.

#### Base Command

`code42-user-reactivate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to reactivate. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.User.UserID | String | The ID of a Code42 User. |


#### Command Example
```!code42-user-reactivate username="partner.demisto@example.com"```

#### Human Readable Output
### Code42 User Reactivated
| UserID |
| ------ |
| 123456790 |

### code42-legalhold-add-user
***
Adds a Code42 user to a legal hold matter.


#### Base Command

`code42-legalhold-add-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to add to the given legal hold matter. | Required | 
| mattername | The name of the legal hold matter to which the user will be added. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.LegalHold.UserID | Unknown | The ID of a Code42 user. | 
| Code42.LegalHold.MatterID | String | The ID of a Code42 legal hold matter. |
| Code42.LegalHold.Username | String | A username for a Code42 user. | 
| Code42.LegalHold.MatterName | String | A name for a Code42 legal hold matter. | 


#### Command Example
```!code42-legalhold-add-user username="partner.demisto@example.com" mattername="test"```

#### Context Example
```
{
    "Code42": {
        "LegalHold": {
            "MatterID": "932880202064992021",
            "MatterName": "test",
            "UserID": "942876157732602741",
            "Username": "partner.demisto@example.com"
        }
    }
}
```

#### Human Readable Output

### Code42 User Added to Legal Hold Matter
|MatterID|MatterName|UserID|Username|
|---|---|---|---|
| 932880202064992021 | test | 942876157732602741 | partner.demisto@example.com |

### code42-legalhold-remove-user
***
Removes a Code42 user from a legal hold matter.


#### Base Command

`code42-legalhold-remove-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to release from the given legal hold matter. | Required | 
| mattername | The name of the legal hold matter from which the user will be released. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.LegalHold.UserID | Unknown | The ID of a Code42 user. | 
| Code42.LegalHold.MatterID | String | The ID of a Code42 legal hold matter. |
| Code42.LegalHold.Username | String | A username for a Code42 user. | 
| Code42.LegalHold.MatterName | String | A name for a Code42 legal hold matter. | 


#### Command Example
```!code42-legalhold-remove-user username="partner.demisto@example.com" mattername="test"```

#### Context Example
```
{
    "Code42": {
        "LegalHold": {
            "MatterID": "932880202064992021",
            "MatterName": "test",
            "UserID": "942876157732602741",
            "Username": "partner.demisto@example.com"
        }
    }
}
```

#### Human Readable Output

### Code42 User Removed from Legal Hold Matter
|MatterID|MatterName|UserID|Username|
|---|---|---|---|
| 932880202064992021 | test | 942876157732602741 | partner.demisto@example.com |

### code42-download-file
***
Downloads a file from Code42.

#### Base Command

`code42-download-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | Either the SHA256 or MD5 hash of the file. | Required |

#### Command Example
```!code42-download-file hash="bf6b326107d4d85eb485eed84b28133a"```

#### Human Readable Output

### Code42 User Deactivated
| Type   | Size | Info | MD5 | SHA1 | SHA256 | SHA512 | SSDeep |
| ------ | ---- | ---- | --- | ---- | ------ | ------ | ------ |
| application/vnd.ms-excel | 41,472 bytes | Composite Document File V2 Document, Little Endian, Os: MacOS, Version 14.10, Code page: 10000, Last Saved By: John Doe, Name of Creating Application: Microsoft Macintosh Excel, Create Time/Date: Fri Feb 21 17:35:19 2020, Last Saved Time/Date: Mon Apr 13 11:54:08 2020, Security: 0 | 2e45562437ec4f41387f2e14c3850dd6 | 59e552e637bfe5254b163bb4e426a2322d10f50d | d3f8566d04df5dc34bf2607ac803a585ac81e06f28afe81f35cc2e5fe63d2ab5 | 776bd9626761cd567a4b498bafe4f5f896c3f4bc9f3c60513ccacd14251a2568fa3ba44060000affa8b57fb768c417cf271500086e4e49272f26b26a90627abb | 768:pudkQzl3ZpWh+QO3uMdS9dSttRJwyE/KtxA1almvy6mhk+GlESOwWoqSY7bTKCUv:siQzl3ZpWh+QO3uMdS9dSttRJwyE/KtF |  
