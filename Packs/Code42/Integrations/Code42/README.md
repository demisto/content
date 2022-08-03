Use the Code42 integration to identify potential data exfiltration from insider threats while speeding investigation and response by providing fast access to file events and metadata across physical and cloud environments.
## Configure Code42 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Code42.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Code42 Console URL for your Code42 environment | True |
    | API Client ID | True |
    | Password | True |
    | Fetch incidents | False |
    | Incident type | False |
    | Alert severities to fetch when fetching incidents | False |
    | First fetch time range (&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes) | False |
    | Alerts to fetch per run; note that increasing this value may result in slow performance if too many results are returned at once | False |
    | Include the list of files in returned incidents. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### code42-securitydata-search
***
Searches for file events by JSON query, hash, username, device hostname, exfiltration type, or a combination of parameters. At least one argument must be passed in the command. If a JSON argument is passed, it will be used to the exclusion of other parameters, otherwise parameters will be combined with an AND clause.


#### Base Command

`code42-securitydata-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| json | JSON query payload using Code42 query syntax. | Optional | 
| hash | MD5 or SHA256 hash of the file to search for. | Optional | 
| username | Username to search for. | Optional | 
| hostname | Hostname to search for. | Optional | 
| exposure | Exposure types to search for. Values can be "All", "RemovableMedia", "ApplicationRead", "CloudStorage", "IsPublic", "SharedViaLink", "SharedViaDomain", or "OutsideTrustedDomains". When "All" is specified with other types, other types would be ignored and filter rule for all types would be applied. Possible values are: All, RemovableMedia, ApplicationRead, CloudStorage, IsPublic, SharedViaLink, SharedViaDomain, OutsideTrustedDomains. | Optional | 
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

#### Command example
```!code42-securitydata-search exposure=All results=3```
#### Context Example
```json
{
    "Code42": {
        "SecurityData": [
            {
                "ApplicationTabURL": "https://drive.google.com/drive/folders/example",
                "DevicePrivateIPAddress": [
                    "127.0.0.1"
                ],
                "DeviceUsername": "user@example.com",
                "EndpointID": "1047677644054752513",
                "EventID": "0_1d71796f-example1",
                "EventTimestamp": "2022-03-11T19:00:28.857Z",
                "EventType": "READ_BY_APP",
                "Exposure": [
                    "ApplicationRead"
                ],
                "FileCategory": "SourceCode",
                "FileCreated": "2021-08-24T15:53:00.925Z",
                "FileHostname": "DESKTOP-H6V9R95",
                "FileMD5": "764f90384e56597e6bba691c75d23875",
                "FileModified": "2021-08-24T15:53:01.111Z",
                "FileName": "revenue_algorithm.py",
                "FileOwner": "user",
                "FilePath": "C:/Users/example/Desktop/",
                "FileSHA256": "5cf3d58f1af8ac32ae74bc75d35132f8151f9826b4e6d79131c68475a53106f9",
                "FileSize": 1000000,
                "ProcessName": "\\Device\\HarddiskVolume3\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                "ProcessOwner": "",
                "Source": "Endpoint",
                "WindowTitle": [
                    "Exfil - Google Drive - Profile 1 - Microsoft\u200b Edge"
                ]
            },
            {
                "ApplicationTabURL": "https://drive.google.com/drive/folders/example"
                "DevicePrivateIPAddress": [
                    "127.0.0.1"
                ],
                "DeviceUsername": "user@example.com",
                "EndpointID": "1047677644054752513",
                "EventID": "0_1d71796f-example2",
                "EventTimestamp": "2022-03-11T19:00:28.819Z",
                "EventType": "READ_BY_APP",
                "Exposure": [
                    "ApplicationRead"
                ],
                "FileCategory": "SourceCode",
                "FileCreated": "2021-08-24T15:53:01.262Z",
                "FileHostname": "DESKTOP-H6V9R95",
                "FileMD5": "953fd5bd78ed02af93f503af8a924fc6",
                "FileModified": "2021-08-24T15:53:01.692Z",
                "FileName": "core_IP.py",
                "FileOwner": "user",
                "FilePath": "C:/Users/example/Desktop/",
                "FileSHA256": "c096682d62c7f4dc8b02dd55e8c595f8374c7b5a5e6f1c87883f6e541f859420",
                "FileSize": 1000000,
                "ProcessName": "\\Device\\HarddiskVolume3\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                "ProcessOwner": "user",
                "Source": "Endpoint",
                "WindowTitle": [
                    "Exfil - Google Drive - Profile 1 - Microsoft\u200b Edge"
                ]
            }
        ]
    },
    "File": [
        {
            "Hostname": "DESKTOP-H6V9R95",
            "MD5": "764f90384e56597e6bba691c75d23875",
            "Name": "revenue_algorithm.py",
            "Path": "C:/Users/example/Desktop/",
            "SHA256": "5cf3d58f1af8ac32ae74bc75d35132f8151f9826b4e6d79131c68475a53106f9",
            "Size": 1000000
        },
        {
            "Hostname": "DESKTOP-H6V9R95",
            "MD5": "953fd5bd78ed02af93f503af8a924fc6",
            "Name": "core_IP.py",
            "Path": "C:/Users/example/Desktop/",
            "SHA256": "c096682d62c7f4dc8b02dd55e8c595f8374c7b5a5e6f1c87883f6e541f859420",
            "Size": 1000000
        }
    ]
}
```

#### Human Readable Output

>### Results
>|Hostname|MD5|Name|Path|SHA256|Size|
>|---|---|---|---|---|---|
>| DESKTOP-H6V9R95 | 764f90384e56597e6bba691c75d23875 | revenue_algorithm.py | C:/Users/example/Desktop/ | 5cf3d58f1af8ac32ae74bc75d35132f8151f9826b4e6d79131c68475a53106f9 | 1000000 |
>| DESKTOP-H6V9R95 | 953fd5bd78ed02af93f503af8a924fc6 | core_IP.py | C:/Users/example/Desktop/ | c096682d62c7f4dc8b02dd55e8c595f8374c7b5a5e6f1c87883f6e541f859420 | 1000000 |


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

#### Command example
```!code42-alert-get id="ec45e919-8dd1-4624-9cc8-98d7f8f84bbf"```
#### Context Example
```json
{
    "Code42": {
        "SecurityAlert": {
            "Description": "Example Alert",
            "ID": "ec45e919-8dd1-4624-9cc8-98d7f8f84bbf",
            "Name": "Example Alerts",
            "Occurred": "2022-03-31T14:48:21.9643340Z",
            "Severity": "HIGH",
            "State": "RESOLVED",
            "Type": "FED_COMPOSITE",
            "Username": "user@example.com"
        }
    }
}
```

#### Human Readable Output

>### Code42 Security Alert Results
>|Type|Occurred|Username|Name|Description|State|ID|
>|---|---|---|---|---|---|---|
>| FED_COMPOSITE | 2022-03-31T14:48:21.9643340Z | user@example.com | Example Alerts | Example Alert | RESOLVED | ec45e919-8dd1-4624-9cc8-98d7f8f84bbf |


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

#### Command example
```!code42-alert-resolve id="ec45e919-8dd1-4624-9cc8-98d7f8f84bbf"```
#### Context Example
```json
{
    "Code42": {
        "SecurityAlert": {
            "Description": "Example Alert",
            "ID": "ec45e919-8dd1-4624-9cc8-98d7f8f84bbf",
            "Name": "Example Alerts",
            "Occurred": "2022-03-31T14:48:21.9643340Z",
            "Severity": "HIGH",
            "State": "RESOLVED",
            "Type": "FED_COMPOSITE",
            "Username": "user@example.com"
        }
    }
}
```

#### Human Readable Output

>### Code42 Security Alert Resolved
>|Type|Occurred|Username|Name|Description|State|ID|
>|---|---|---|---|---|---|---|
>| FED_COMPOSITE | 2022-03-31T14:48:21.9643340Z | user@example.com | Example Alerts | Example Alert | RESOLVED | ec45e919-8dd1-4624-9cc8-98d7f8f84bbf |


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

#### Command example
```!code42-user-create orgname="TestOrg" username="new.user@example.com" email="new.user@example.com"```
#### Context Example
```json
{
    "Code42": {
        "User": {
            "Email": "new.user@example.com",
            "UserID": "1061727696334321549",
            "Username": "new.user@example.com"
        }
    }
}
```

#### Human Readable Output

>### Code42 User Created
>|Email|UserID|Username|
>|---|---|---|
>| new.user@example.com | 1061727696334321549 | new.user@example.com |


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

#### Command example
```!code42-user-block username="user_a@example.com"```
#### Context Example
```json
{
    "Code42": {
        "User": {
            "UserID": 210019
        }
    }
}
```

#### Human Readable Output

>### Code42 User Blocked
>|UserID|
>|---|
>| 210019 |


### code42-user-deactivate
***
Deactivate a user in Code42; signing them out of their devices. Backups discontinue for a deactivated user, and their archives go to cold storage.


#### Base Command

`code42-user-deactivate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to deactivate. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.User.UserID | String | The ID of a Code42 User. | 

#### Command example
```!code42-user-deactivate username="user_a@example.com"```
#### Context Example
```json
{
    "Code42": {
        "User": {
            "UserID": 210019
        }
    }
}
```

#### Human Readable Output

>### Code42 User Deactivated
>|UserID|
>|---|
>| 210019 |


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

#### Command example
```!code42-user-unblock username="user_a@example.com"```
#### Context Example
```json
{
    "Code42": {
        "User": {
            "UserID": 210019
        }
    }
}
```

#### Human Readable Output

>### Code42 User Unblocked
>|UserID|
>|---|
>| 210019 |


### code42-user-reactivate
***
Reactivates the user with the given username.


#### Base Command

`code42-user-reactivate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to reactivate. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.User.UserID | String | The ID of a Code42 User. | 

#### Command example
```!code42-user-reactivate username="user_a@example.com"```
#### Context Example
```json
{
    "Code42": {
        "User": {
            "UserID": 210019
        }
    }
}
```

#### Human Readable Output

>### Code42 User Reactivated
>|UserID|
>|---|
>| 210019 |


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

#### Command example
```!code42-legalhold-add-user username="user_a@example.com" mattername="test"```
#### Context Example
```json
{
    "Code42": {
        "LegalHold": {
            "MatterID": "1034958750641143371",
            "MatterName": "Example Matter",
            "UserID": "942876157732602741",
            "Username": "user_a@example.com"
        }
    }
}
```

#### Human Readable Output

>### Code42 User Added to Legal Hold Matter
>|MatterID|MatterName|UserID|Username|
>|---|---|---|---|
>| 1034958750641143371 | Example Matter | 942876157732602741 | user_a@example.com |


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

#### Command example
```!code42-legalhold-remove-user username="user_a@example.com" mattername="test"```
#### Context Example
```json
{
    "Code42": {
        "LegalHold": {
            "MatterID": "1034958750641143371",
            "MatterName": "Example Matter",
            "UserID": "942876157732602741",
            "Username": "user_a@example.com"
        }
    }
}
```

#### Human Readable Output

>### Code42 User Removed from Legal Hold Matter
>|MatterID|MatterName|UserID|Username|
>|---|---|---|---|
>| 1034958750641143371 | Example Matter | 942876157732602741 | user_a@example.com |


### code42-download-file
***
Downloads a file from Code42.


#### Base Command

`code42-download-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | Either the SHA256 or MD5 hash of the file. | Required | 
| filename | The filename to save the file as. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 

#### Command example
```!code42-download-file hash=764f90384e56597e6bba691c75d23875```
#### Context Example
```json
{
    "File": {
        "EntryID": "1804@6aa7c36e-287b-4b27-840b-7d8d67a9b26b",
        "Info": "text/plain",
        "MD5": "764f90384e56597e6bba691c75d23875",
        "Name": "764f90384e56597e6bba691c75d23875",
        "SHA1": "feadedfc92e7680890f4233432c5eef66ced0584",
        "SHA256": "5cf3d58f1af8ac32ae74bc75d35132f8151f9826b4e6d79131c68475a53106f9",
        "SHA512": "3d2acf4e529b72f6a52aff7dfd067b86044d9df8f7d30b6617f252cc9610828481205628607884d77f67e86b5ce2e80e349e8e048604f6239fb085917ebb75f1",
        "SSDeep": "24576:f1eShVeMNVW13kNkedlsero1lwha2HKiVxIAXo:t9omLlsKKy+",
        "Size": 1000000,
        "Type": "ASCII text"
    }
}
```

#### Human Readable Output



### code42-watchlists-list
***
List all existing watchlists in your environment.


#### Base Command

`code42-watchlists-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.Watchlists.ListType | string | The Type of Watchlist. | 
| Code42.Watchlists.Id | string | The ID of the Watchlist. | 
| Code42.Watchlists.IncludedUserCount | integer | The count of included users on the Watchlist. | 

#### Command example
```!code42-watchlists-list```
#### Context Example
```json
{
    "Code42": {
        "Watchlists": [
            {
                "IncludedUserCount": 3,
                "WatchlistID": "b55978d5-2d50-494d-bec9-678867f3830c",
                "WatchlistType": "DEPARTING_EMPLOYEE"
            },
            {
                "IncludedUserCount": 11,
                "WatchlistID": "2870bd73-ce1f-4704-a7f7-a8d11b19908e",
                "WatchlistType": "SUSPICIOUS_SYSTEM_ACTIVITY"
            },
            {
                "IncludedUserCount": 4,
                "WatchlistID": "d2abb9f2-8c27-4f95-b7e2-252f191a4a1d",
                "WatchlistType": "FLIGHT_RISK"
            },
            {
                "IncludedUserCount": 3,
                "WatchlistID": "a21b2bbb-ed16-42eb-9983-32076ba417c0",
                "WatchlistType": "PERFORMANCE_CONCERNS"
            },
            {
                "IncludedUserCount": 2,
                "WatchlistID": "c9557acf-4141-4162-b767-c129d3e668d4",
                "WatchlistType": "CONTRACT_EMPLOYEE"
            },
            {
                "IncludedUserCount": 4,
                "WatchlistID": "313c388e-4c63-4071-a6fc-d6270e04c350",
                "WatchlistType": "HIGH_IMPACT_EMPLOYEE"
            },
            {
                "IncludedUserCount": 3,
                "WatchlistID": "b49c938f-8f13-45e4-be17-fa88eca616ec",
                "WatchlistType": "ELEVATED_ACCESS_PRIVILEGES"
            },
            {
                "IncludedUserCount": 2,
                "WatchlistID": "534fa6a4-4b4c-4712-9b37-2f81c652c140",
                "WatchlistType": "POOR_SECURITY_PRACTICES"
            },
            {
                "IncludedUserCount": 0,
                "WatchlistID": "5a39abda-c672-418a-82a0-54485bd59b7b",
                "WatchlistType": "NEW_EMPLOYEE"
            }
        ]
    }
}
```

#### Human Readable Output

>### Watchlists
>|IncludedUserCount|WatchlistID|WatchlistType|
>|---|---|---|
>| 3 | b55978d5-2d50-494d-bec9-678867f3830c | DEPARTING_EMPLOYEE |
>| 11 | 2870bd73-ce1f-4704-a7f7-a8d11b19908e | SUSPICIOUS_SYSTEM_ACTIVITY |
>| 4 | d2abb9f2-8c27-4f95-b7e2-252f191a4a1d | FLIGHT_RISK |
>| 3 | a21b2bbb-ed16-42eb-9983-32076ba417c0 | PERFORMANCE_CONCERNS |
>| 2 | c9557acf-4141-4162-b767-c129d3e668d4 | CONTRACT_EMPLOYEE |
>| 4 | 313c388e-4c63-4071-a6fc-d6270e04c350 | HIGH_IMPACT_EMPLOYEE |
>| 3 | b49c938f-8f13-45e4-be17-fa88eca616ec | ELEVATED_ACCESS_PRIVILEGES |
>| 2 | 534fa6a4-4b4c-4712-9b37-2f81c652c140 | POOR_SECURITY_PRACTICES |
>| 0 | 5a39abda-c672-418a-82a0-54485bd59b7b | NEW_EMPLOYEE |


### code42-watchlists-add-user
***
Add a user to a watchlist.


#### Base Command

`code42-watchlists-add-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Email id of the user to add to Watchlist. | Required | 
| watchlist | WatchlistID or WatchlistType to add user to. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.UsersAddedToWatchlists.Watchlist | string | The ID/Type of the watchlist user was added to. | 
| Code42.UsersAddedToWatchlists.Username | string | The username added to watchlist. | 
| Code42.UsersAddedToWatchlists.Success | boolean | If the user was added successfully. | 

#### Command example
```!code42-watchlists-add-user username="user_a@example.com" watchlist="b55978d5-2d50-494d-bec9-678867f3830c"```
#### Context Example
```json
{
    "Code42": {
        "UsersAddedToWatchlists": {
            "Success": true,
            "Username": "user_a@example.com",
            "Watchlist": "b55978d5-2d50-494d-bec9-678867f3830c"
        }
    }
}
```

#### Human Readable Output

>### Results
>|Success|Username|Watchlist|
>|---|---|---|
>| true | user_a@example.com | b55978d5-2d50-494d-bec9-678867f3830c |


### code42-watchlists-remove-user
***
Remove a user from a watchlist.


#### Base Command

`code42-watchlists-remove-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Email id of the user to add to Watchlist. | Required | 
| watchlist | WatchlistID or WatchlistType to remove user from. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.UsersRemovedFromWatchlists.Watchlist | string | The ID/Type of the watchlist user was removed from. | 
| Code42.UsersRemovedFromWatchlists.Username | string | The username removed from watchlist. | 
| Code42.UsersRemovedFromWatchlists.Success | boolean | If the user was removed successfully. | 

#### Command example
```!code42-watchlists-remove-user username="user_a@example.com" watchlist="b55978d5-2d50-494d-bec9-678867f3830c"```
#### Context Example
```json
{
    "Code42": {
        "UsersRemovedFromWatchlists": {
            "Success": true,
            "Username": "user_a@example.com",
            "Watchlist": "b55978d5-2d50-494d-bec9-678867f3830c"
        }
    }
}
```

#### Human Readable Output

>### Results
>|Success|Username|Watchlist|
>|---|---|---|
>| true | user_a@example.com | b55978d5-2d50-494d-bec9-678867f3830c |


### code42-watchlists-list-included-users
***
List all users who have been explicitly added to a given watchlist.


#### Base Command

`code42-watchlists-list-included-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist | The WatchlistID or WatchlistType to get a list of included users for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.WatchlistUsers.WatchlistID | string | The ID of the Watchlist. | 
| Code42.WatchlistUsers.Username | string | The username on the watchlist. | 
| Code42.WatchlistUsers.AddedTime | datetime | The datetime the user was added to the watchlist. | 

#### Command example
```!code42-watchlists-list-included-users watchlist="DEPARTING_EMPLOYEE"```
#### Context Example
```json
{
    "Code42": {
        "WatchlistUsers": [
            {
                "AddedTime": "2022-02-26T18:41:45.766005",
                "Username": "user_a@example.com",
                "WatchlistID": "b55978d5-2d50-494d-bec9-678867f3830c"
            },
            {
                "AddedTime": "2022-03-31T20:41:47.2985",
                "Username": "user_b@example.com",
                "WatchlistID": "b55978d5-2d50-494d-bec9-678867f3830c"
            },
            {
                "AddedTime": "2022-03-31T14:43:48.059325",
                "Username": "user_c@example.com",
                "WatchlistID": "b55978d5-2d50-494d-bec9-678867f3830c"
            }
        ]
    }
}
```

#### Human Readable Output

>### Watchlists
>|AddedTime|Username|WatchlistID|
>|---|---|---|
>| 2022-02-26T18:41:45.766005 | user_a@example.com | b55978d5-2d50-494d-bec9-678867f3830c |
>| 2022-03-31T20:41:47.2985 | user_b@example.com | b55978d5-2d50-494d-bec9-678867f3830c |
>| 2022-03-31T14:43:48.059325 | user_c@example.com | b55978d5-2d50-494d-bec9-678867f3830c |

