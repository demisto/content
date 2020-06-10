## Overview
---

Code42 provides simple, fast detection and response to everyday data loss from insider threats by focusing on customer data on endpoints and the cloud to answer questions like:

* Where is my data?
* Where has my data been?
* When did my data leave?
* What data exactly left my organization?

This integration was integrated and tested with the fully-hosted SaaS implementation of Code42 and requires a Platinum level subscription.

## Code42 Playbook
---

## Use Cases
---

* Ingesting File Exfiltration alerts from Code42
* Management of Departing Employees within Code42
* General file event and metadata search

## Configure Code42 on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Code42.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __credentials__
    * __Code42 Console URL for the pod your Code42 instance is running in__: This defaults to console.us.code42.com for U.S. SaaS Pod customers; replace with the domain that you use to log into your Code42 console if located in a different SaaS pod.
    * __Fetch incidents__: Check this box to enable fetching of incidents
    * __Incident type__: Select which Demisto incident type to map ingested Code42 alerts to
    * __Alert severities to fetch when fetching incidents__: If desired, select which Alert severities to ingest.
    * __First fetch time range (&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes)__: When first run, how long to go back to retrieve alerts.
    * __Alerts to fetch per run; note that increasing this value may result in slow performance if too many results are returned at once__: Alerts to fetch and process per run. Setting this value too high may have a negative impact on performance.
    * __Include the list of files in returned incidents.__: If checked, will also fetch the file events associated with the alert.
4. Click __Test__ to validate the URLs, token, and connection.

## Fetched Incidents Data
---

* ID
* Occurred
* Username
* Name
* Description
* State
* Type
* Severity

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. code42-securitydata-search
2. code42-alert-get
3. code42-departingemployee-add
4. code42-departingemployee-remove
5. code42-alert-resolve

### 1. code42-securitydata-search
---
Search for a file in Security Data by JSON query, hash, username, device hostname, exfiltration type, or a combination of parameters. At least one parameter must be passed to the command. If a JSON parameter is passed, it will be used to the exclusion of other parameters, otherwise parameters will be combined with an AND clause.
##### Required Permissions
This command requires one of the following roles:

* Security Center User 
* Customer Cloud Admin

##### Base Command

`code42-securitydata-search`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| json | JSON query payload using Code42 query syntax | Optional | 
| hash | MD5 or SHA256 hash of file to search for | Optional | 
| username | Username to search for | Optional | 
| hostname | Hostname to search for | Optional | 
| exposure | Exposure types to search for | Optional | 
| results | Number of results to return, default is 100 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.SecurityData.EventTimestamp | date | Timestamp for event | 
| Code42.SecurityData.FileCreated | date | File creation date | 
| Code42.SecurityData.EndpointID | string | Code42 device ID | 
| Code42.SecurityData.DeviceUsername | string | Username that device is associated with in Code42 | 
| Code42.SecurityData.EmailFrom | string | Sender email address for email exfiltration events | 
| Code42.SecurityData.EmailTo | string | Recipient emial address for email exfiltration events | 
| Code42.SecurityData.EmailSubject | string | Email subject line for email exfiltration events | 
| Code42.SecurityData.EventID | string | Security Data event ID | 
| Code42.SecurityData.EventType | string | Type of Security Data event | 
| Code42.SecurityData.FileCategory | string | Type of file as determined by Code42 engine | 
| Code42.SecurityData.FileOwner | string | Owner of file | 
| Code42.SecurityData.FileName | string | File name | 
| Code42.SecurityData.FilePath | string | Path to file | 
| Code42.SecurityData.FileSize | number | Size of file in bytes | 
| Code42.SecurityData.FileModified | date | File modification date | 
| Code42.SecurityData.FileMD5 | string | MD5 hash of file | 
| Code42.SecurityData.FileHostname | string | Hostname where file event was captured | 
| Code42.SecurityData.DevicePrivateIPAddress | string | Private IP addresses of device where event was captured | 
| Code42.SecurityData.DevicePublicIPAddress | string | Public IP address of device where event was captured | 
| Code42.SecurityData.RemovableMediaType | string | Type of removate media | 
| Code42.SecurityData.RemovableMediaCapacity | number | Total capacity of removable media in bytes | 
| Code42.SecurityData.RemovableMediaMediaName | string | Full name of removable media | 
| Code42.SecurityData.RemovableMediaName | string | Name of removable media | 
| Code42.SecurityData.RemovableMediaSerialNumber | string | Serial number for removable medial device | 
| Code42.SecurityData.RemovableMediaVendor | string | Vendor name for removable device | 
| Code42.SecurityData.FileSHA256 | string | SHA256 hash of file | 
| Code42.SecurityData.FileShared | boolean | Whether file is shared using cloud file service | 
| Code42.SecurityData.FileSharedWith | string | Accounts that file is shared with on cloud file service | 
| Code42.SecurityData.Source | string | Source of file event, Cloud or Endpoint | 
| Code42.SecurityData.ApplicationTabURL | string | URL associated with application read event | 
| Code42.SecurityData.ProcessName | string | Process name for application read event | 
| Code42.SecurityData.ProcessOwner | string | Process owner for application read event | 
| Code42.SecurityData.WindowTitle | string | Process name for application read event | 
| Code42.SecurityData.FileURL | string | URL of file on cloud file service | 
| Code42.SecurityData.Exposure | string | Exposure type for event | 
| Code42.SecurityData.SharingTypeAdded | string | Type of sharing added to file | 
| File.Name | string | File name | 
| File.Path | string | File path | 
| File.Size | number | File size in bytes | 
| File.MD5 | string | MD5 hash of file | 
| File.SHA256 | string | FSHA256 hash of file | 
| File.Hostname | string | Hostname where file event was captured | 


##### Command Example
```
!code42-securitydata-search hash=eef8b12d2ed0d6a69fe77699d5640c7b exposure=CloudStorage,ApplicationRead
```

##### Context Example
```
{
    "SecurityData": [
        {
            "ApplicationTabURL": "https://mail.google.com/mail/u/0/?zx=78517y156trj#inbox",
            "DevicePrivateIPAddress": [
                "192.168.7.7",
                "0:0:0:0:0:0:0:1",
                "127.0.0.1"
            ],
            "DeviceUsername": "john.user@123.org",
            "EndpointID": "922302903141234234",
            "EventID": "0_c346c59b-5ea1-4e5d-ac02-92079567a683_922302903141255753_939560749717017940_751",
            "EventTimestamp": "2020-02-03T22:32:10.892Z",
            "EventType": "READ_BY_APP",
            "Exposure": [
                "ApplicationRead"
            ],
            "FileCategory": "IMAGE",
            "FileCreated": "2019-10-07T21:46:09.281Z",
            "FileHostname": "DESKTOP-0004",
            "FileMD5": "eef8b12d2ed0d6a69fe77699d5640c7b",
            "FileModified": "2019-10-07T21:46:09.889Z",
            "FileName": "ProductPhoto.jpg",
            "FileOwner": "john.user",
            "FilePath": "C:/Users/john.user/Documents/",
            "FileSHA256": "5e25e54e1cc43ed07c6e888464cb98e5f5343aa7aa485d174d9649be780a17b9",
            "FileSize": 333114,
            "ProcessName": "\\Device\\HarddiskVolume4\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
            "ProcessOwner": "john.user",
            "Source": "Endpoint",
            "WindowTitle": [
                "Inbox (1) - john.user@c123.org - 123 Org Mail - Google Chrome"
            ]
        },
        {
            "DevicePrivateIPAddress": [
                "192.168.7.7",
                "0:0:0:0:0:0:0:1",
                "127.0.0.1"
            ],
            "DeviceUsername": "john.user@123.org",
            "EndpointID": "922302903141234234",
            "EventID": "0_a2e51c67-8719-4436-a3b5-c7c3724a3144_922302903141255753_939559658795324756_45",
            "EventTimestamp": "2020-02-03T22:22:04.375Z",
            "EventType": "READ_BY_APP",
            "Exposure": [
                "ApplicationRead"
            ],
            "FileCategory": "IMAGE",
            "FileCreated": "2019-10-07T21:46:09.281Z",
            "FileHostname": "DESKTOP-0004",
            "FileMD5": "eef8b12d2ed0d6a69fe77699d5640c7b",
            "FileModified": "2019-10-07T21:46:09.889Z",
            "FileName": "ProductPhoto.jpg",
            "FileOwner": "john.user",
            "FilePath": "C:/Users/john.user/Documents/",
            "FileSHA256": "5e25e54e1cc43ed07c6e888464cb98e5f5343aa7aa485d174d9649be780a17b9",
            "FileSize": 333114,
            "ProcessName": "\\Device\\HarddiskVolume4\\Windows\\System32\\MicrosoftEdgeCP.exe",
            "ProcessOwner": "michelle.goldberg",
            "Source": "Endpoint",
            "WindowTitle": [
                "Inbox (7) - jju12431983@gmail.com - Gmail ‎- Microsoft Edge"
            ]
        }
    ]
}
```

##### Human Readable Output

| **EventType** | **FileName** | **FileSize** | **FileHostname** | **FileOwner** | **FileCategory** |
| --- | --- | --- | --- | --- | --- |
| READ\_BY\_APP | ProductPhoto.jpg | 333114 | DESKTOP-001 | john.user | IMAGE |


### 2. code42-alert-get
---
Retrieve alert details by alert ID
##### Required Permissions

This command requires one of the following roles:

* Security Center User 
* Customer Cloud Admin

##### Base Command

`code42-alert-get`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Alert ID to retrieve | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.SecurityAlert.Username | string | Username associated with alert | 
| Code42.SecurityAlert.Occurred | date | Alert timestamp | 
| Code42.SecurityAlert.Description | string | Description of alert | 
| Code42.SecurityAlert.ID | string | Alert ID | 
| Code42.SecurityAlert.Name | string | Alert rule name that generated alert | 
| Code42.SecurityAlert.State | string | Alert state | 
| Code42.SecurityAlert.Type | string | Type of alert | 
| Code42.SecurityAlert.Severity | string | Severity of alert | 


##### Command Example
```
!code42-alert-get id="a23557a7-8ca9-4ec6-803f-6a46a2aeca62"
```

##### Context Example
```
{
    "SecurityAlert": [
        {
            "ID": "a23557a7-8ca9-4ec6-803f-6a46a2aeca62",
            "Name": "Google Drive - Public via Direct Link",
            "Occurred": "2019-10-08T17:38:19.0801650Z",
            "Severity": "LOW",
            "State": "OPEN",
            "Type": "FED_CLOUD_SHARE_PERMISSIONS",
            "Username": "john.user@123.org"
        }
    ]
}
```

##### Human Readable Output

| **Type** | **Occurred** | **Username** | **Name** | **Description** | **State** | **ID** |
| --- | --- | --- | --- | --- | --- | --- |
| FED\_CLOUD\_SHARE_PERMISSIONS | 2019-10-08T17:38:19.0801650Z | john.user@123.org | Google Drive - Public via Direct Link |  Alert for public Google Drive files | OPEN | a23557a7-8ca9-4ec6-803f-6a46a2aeca62 |


### 3. code42-departingemployee-add
---
Add a user to the Departing Employee Lens
##### Required Permissions

This command requires one of the following roles:
 
* Customer Cloud Admin
* Security Center User + (Org Security Viewer or Cross Org Security Viewer)

##### Base Command

`code42-departingemployee-add`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to add to the Departing Employee Lens | Required | 
| departuredate | Departure date for the employee in YYYY-MM-DD format | Optional | 
| note | Note to attach to Departing Employee | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.DepartingEmployee.CaseID | string | Internal Code42 Case ID for Departing Employee | 
| Code42.DepartingEmployee.Username | string | Username for Departing Employee | 
| Code42.DepartingEmployee.Note | string | Note associated with Departing Employee | 
| Code42.DepartingEmployee.DepartureDate | unknown | Departure date for Departing Employee | 


##### Command Example
```
!code42-departingemployee-add username="john.user@123.org" departuredate="2020-02-28" note="Leaving for competitor" 
```

##### Context Example
```
{
    "DepartingEmployee": {
        "CaseID": "892",
        "DepartureDate": "2020-02-28",
        "Note": "Leaving for competitor",
        "Username": "john.user@123.org"
    }
}
```

##### Human Readable Output

| **CaseID** | **DepartureDate** | **Note** | **Username** |
| --- | --- | --- | --- |
| 123 | 2020-02-28 | Leaving for competitor | john.user@123.org |


### 4. code42-departingemployee-remove
---
Remove a user from the Departing Employee Lens
##### Required Permissions

This command requires one of the following roles:

* Customer Cloud Admin
* Security Center User + (Org Security Viewer or Cross Org Security Viewer)

##### Base Command

`code42-departingemployee-remove`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to remove from the Departing Employee Lens | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.DepartingEmployee.CaseID | unknown | Internal Code42 Case ID for Departing Employee | 
| Code42.DepartingEmployee.Username | unknown | Username for Departing Employee | 


##### Command Example
```
!code42-departingemployee-remove username="john.user@123.org" 
```

##### Context Example
```
{
    "DepartingEmployee": {
        "CaseID": "892",
        "Username": "john.user@123.org"
    }
}
```

##### Human Readable Output

| **CaseID** | **Username** |
| --- | --- | 
| 123 | john.user@123.org |

### 5. code42-alert-resolve
---
Resolve a Code42 Security alert
##### Required Permissions

This command requires one of the following roles:

* Security Center User
* Customer Cloud Admin

##### Base Command

`code42-alert-resolve`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Alert ID to resolve | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.SecurityAlert.ID | string | Alert ID | 


##### Command Example
```
!code42-alert-resolve id="eb272d18-bc82-4680-b570-ac5d61c6cca6"
```

##### Context Example
```
{
    "SecurityAlert": {
        "ID": "eb272d18-bc82-4680-b570-ac5d61c6cca6"
    }
}
```

##### Human Readable Output

| **ID** |
| --- |
| eb272d18-bc82-4680-b570-ac5d61c6cca6 |

## Additional Information
---
For additional infromation on Code42 features and functionality please visit [https://support.code42.com/Administrator/Cloud/Monitoring\_and\_managing](https://support.code42.com/Administrator/Cloud/Monitoring_and_managing)

## Known Limitations
---

## Troubleshooting
---
