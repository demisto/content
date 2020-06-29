## Overview
---

Code42 provides simple, fast detection and response to everyday data loss from insider threats by focusing on customer data on endpoints and the cloud to answer questions like:

* Where is my data?
* Where has my data been?
* When did my data leave?
* What data exactly left my organization?

This integration was integrated and tested with the fully-hosted SaaS implementation of Code42 and requires a Platinum level subscription.

## Use Cases
---

* Ingesting File Exfiltration alerts from Code42
* Management of Departing Employees within Code42
* General file event and metadata search


## Configure Code42 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Code42.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| console_url | Code42 Console URL for the pod your Code42 instance is running in | True |
| credentials |  | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| alert_severity | Alert severities to fetch when fetching incidents | False |
| fetch_time | First fetch time range \(&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes\) | False |
| fetch_limit | Alerts to fetch per run; note that increasing this value may result in slow performance if too many results are returned at once | False |
| include_files | Include the list of files in returned incidents. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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
| Code42.DepartingEmployee.UserID | string | Internal Code42 User ID for the Departing Employee. | 
| Code42.DepartingEmployee.Username | string | The username of the Departing Employee. | 
| Code42.DepartingEmployee.Note | string | Note associated with the Departing Employee. | 
| Code42.DepartingEmployee.DepartureDate | unknown | The departure date for the Departing Employee. | 


#### Command Example
```!code42-departingemployee-add username="john.user@123.org" departuredate="2020-02-28" note="Leaving for competitor"```

#### Human Readable Output

| **UserID** | **DepartureDate** | **Note** | **Username** |
| --- | --- | --- | --- |
| 123 | 2020-02-28 | Leaving for competitor | john.user@example.com |


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
| Code42.DepartingEmployee.UserID | string | Internal Code42 User ID for the Departing Employee. | 
| Code42.DepartingEmployee.Username | string | The username of the Departing Employee. | 


#### Command Example
```!code42-departingemployee-remove username="john.user@example.com"```

#### Human Readable Output

| **UserID** | **Username** |
| --- | --- | 
| 123 | john.user@example.com |


### code42-departingemployee-get-all
***
Get all employees on the Departing Employee List.


#### Base Command

`code42-departingemployee-get-all`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.DepartingEmployee.UserID | string | Internal Code42 User ID for the Departing Employee. | 
| Code42.DepartingEmployee.Username | string | The username of the Departing Employee. | 
| Code42.DepartingEmployee.Note | string | Note associated with the Departing Employee. | 
| Code42.DepartingEmployee.DepartureDate | unknown | The departure date for the Departing Employee. | 


#### Command Example
```!code42-departingemployee-get-all```

#### Human Readable Output

| **UserID** | **DepartureDate** | **Note** | **Username** |
| --- | --- | --- | --- |
| 123 | 2020-02-28 | Leaving for competitor | john.user@example.com |


### code42-highriskemployee-add
***
Removes a user from the High Risk Employee List.


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
```!code42-highriskemployee-add username="john.user@123.org" note="Risky activity"```

#### Human Readable Output

| **UserID** | **Note** | **Username** |
| --- | --- | --- |
| 123 | Leaving for competitor | john.user@example.com |


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
| Code42.HighRiskEmployee.UserID | unknown | Internal Code42 User ID for the High Risk Employee. | 
| Code42.HighRiskEmployee.Username | unknown | The username of the High Risk Employee. | 


#### Command Example
```!code42-highriskemployee-remove username="john.user@example.com"```

#### Human Readable Output

| **UserID** | **Username** |
| --- | --- |
| 123 | john.user@example.com |


### code42-highriskemployee-get-all
***
Get all employees on the High Risk Employee List.


#### Base Command

`code42-highriskemployee-get-all`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| risktags | To filter results by employees who have these risk tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.HighRiskEmployee.UserID | string | Internal Code42 User ID for the High Risk Employee. | 
| Code42.HighRiskEmployee.Username | string | The username of the High Risk Employee. | 
| Code42.HighRiskEmployee.Note | string | Note associated with the High Risk Employee. | 


#### Command Example
```!code42-highriskemployee-get-all risktags="PERFORMANCE_CONCERNS"```

#### Human Readable Output

| **UserID** | **Note** | **Username** |
| --- | --- | --- |
| 123 | Leaving for competitor | john.user@example.com |


### code42-highriskemployee-add-risk-tags
***
 

#### Base Command

`code42-highriskemployee-add-risk-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the High Risk Employee. | Required | 
| risktags | Risk tags to associate with the High Risk Employee. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.HighRiskEmployee.UserID | string | Internal Code42 User ID for the Departing Employee. | 
| Code42.HighRiskEmployee.Username | string | The username of the High Risk Employee. | 
| Code42.HighRiskEmployee.RiskTags | unknown | Risk tags to associate with the High Risk Employee. | 


#### Command Example
```!code42-highriskemployee-add-risk-tags username="john.user@example.com" risktags="PERFORMANCE_CONCERNS"```

#### Human Readable Output

| **UserID** | **RiskTags** | **Username** |
| --- | --- | --- |
| 123 | FLIGHT_RISK | john.user@example.com |


### code42-highriskemployee-remove-risk-tags
***



#### Base Command

`code42-highriskemployee-remove-risk-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the High Risk Employee. | Required | 
| risktags | Risk tags to disassociate from the High Risk Employee. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.HighRiskEmployee.UserID | string | Internal Code42 User ID for the Departing Employee. | 
| Code42.HighRiskEmployee.Username | string | The username of the High Risk Employee. | 
| Code42.HighRiskEmployee.RiskTags | unknown | Risk tags to disassociate from the High Risk Employee. | 


#### Command Example
```!code42-highriskemployee-remove-risk-tags username="john.user@example.com" risktags="PERFORMANCE_CONCERNS"```

#### Human Readable Output

| **UserID** | **RiskTags** | **Username** |
| --- | --- | --- |
| 123 | FLIGHT_RISK | john.user@example.com |



#### Base Command

`code42-highriskemployee-remove-risk-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the High Risk Employee. | Required | 
| risktags | Risk tags to disassociate from the High Risk Employee. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.HighRiskEmployee.UserID | string | Internal Code42 User ID for the Departing Employee. | 
| Code42.HighRiskEmployee.Username | string | The username of the High Risk Employee. | 
| Code42.HighRiskEmployee.RiskTags | unknown | Risk tags to disassociate from the High Risk Employee. | 


#### Command Example
```!code42-highriskemployee-remove-risk-tags username="john.user@example.com" risktags="PERFORMANCE_CONCERNS"```

#### Human Readable Output

| **UserID** | **RiskTags** | **Username** |
| --- | --- | --- |
| 123 | FLIGHT_RISK | john.user@example.com |