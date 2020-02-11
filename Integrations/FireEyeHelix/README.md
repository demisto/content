## Overview
---

FireEye Helix is a security operations platform. FireEye Helix integrates security tools and augments them with next-generation SIEM, orchestration and threat intelligence tools such as alert management, search, analysis, investigations and reporting.

In order to configure this integration you will a FireEye customer ID. Your customer ID is used in your FireEye Helix available in the URL of your FireEye Helix app after /helix/id/. e.g. for the following URL https://apps.fireeye.com/helix/id/helixid the customer ID is helixid.
The API key can be found and generated in the API KEYS section. You can navigate to it from your FireEye Helix app home page by clicking on the user icon on the top right, and choosing HELIX Settings. You'll be redirected to the HELIX Settings page, where API KEYS can be found.

## Configure FireEyeHelix on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for FireEyeHelix.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g. https://apps.fireeye.com)__
    * __Customer ID__
    * __API Token__
    * __First fetch timestamp (<number> <time unit>, e.g., 12 hours, 7 days, 3 months, 1 year)__
    * __Fetch incidents query__
    * __Incident type__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. fireeye-helix-list-alerts
2. fireeye-helix-get-alert-by-id
3. fireeye-helix-alert-create-note
4. fireeye-helix-get-events-by-alert
5. fireeye-helix-get-endpoints-by-alert
6. fireeye-helix-get-cases-by-alert
7. fireeye-helix-get-lists
8. fireeye-helix-get-list-by-id
9. fireeye-helix-create-list
10. fireeye-helix-update-list
11. fireeye-helix-delete-list
12. fireeye-helix-list-sensors
13. fireeye-helix-list-rules
14. fireeye-helix-edit-rule
15. fireeye-helix-alert-get-notes
16. fireeye-helix-alert-delete-note
17. fireeye-helix-search
18. fireeye-helix-add-list-item
19. fireeye-helix-get-list-items
20. fireeye-helix-update-list-item
21. fireeye-helix-remove-list-item
22. fireeye-helix-archive-search-get-results
23. fireeye-helix-archive-search
24. fireeye-helix-archive-search-get-status
### 1. fireeye-helix-list-alerts
---
Returns all alerts.
##### Base Command

`fireeye-helix-list-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Maximum number of results to return per page. | Optional | 
| offset | The initial index from which to return the results. | Optional | 
| headers | Output values to display in the command result (comma separated values (no spaces) as they appear in the context. e.g. ID,Name,Hostname). | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Alert.ID | Number | Primary ID of the alert. | 
| FireEyeHelix.Alert.AlertTypeID | Number | ID of the alert type. | 
| FireEyeHelix.Alert.AlertTypeName | String | Name of the alert type. | 
| FireEyeHelix.Alert.AssigneeID | String | ID of the assignee. | 
| FireEyeHelix.Alert.AssigneeName | String | Assignee display name. | 
| FireEyeHelix.Alert.CreatorID | String | ID of the user who created the alert. | 
| FireEyeHelix.Alert.CreatorName | String | Name of the user who created the alert. | 
| FireEyeHelix.Alert.UpdaterID | String | ID of the user who updated the alert. | 
| FireEyeHelix.Alert.UpdaterName | String | Name of the user who updated the alert. | 
| FireEyeHelix.Alert.CreatedTime | Date | Time the alert was created. | 
| FireEyeHelix.Alert.ModifiedTime | Date | Time the alert was modified. | 
| FireEyeHelix.Alert.ProcessPath | String | Path of the process. | 
| FireEyeHelix.Alert.Confidence | String | FireEye Helix confidence with the result. | 
| FireEyeHelix.Alert.SHA1 | String | SHA1 hash of the file. | 
| FireEyeHelix.Alert.MD5 | String | MD5 hash of the file. | 
| FireEyeHelix.Alert.Hostname | String | Hostname of the alert. | 
| FireEyeHelix.Alert.PID | Number | Process ID. | 
| FireEyeHelix.Alert.Size | Number | Size of the process in bytes. | 
| FireEyeHelix.Alert.Virues | String | Virus name. | 
| FireEyeHelix.Alert.Result | String | Result of the alert. | 
| FireEyeHelix.Alert.MalwareType | String | Malware type. | 
| FireEyeHelix.Alert.Filename | String | Name of the file that contains the virus. | 
| FireEyeHelix.Alert.RegPath | String | Registry key path. | 
| FireEyeHelix.Alert.EventTime | Date | Time of the event. | 
| FireEyeHelix.Alert.IOCNames | String | Indicator of Compromise names. | 
| FireEyeHelix.Alert.Process | String | Name of the process that created the event. | 
| FireEyeHelix.Alert.ParentProcess | String | Name of the parent process of the process that created the event. | 
| FireEyeHelix.Alert.SourceIPv4 | String | Source IP address of the event (IPv4). | 
| FireEyeHelix.Alert.SourceIPv6 | String | Source IP address of the event (IPv6). | 
| FireEyeHelix.Alert.DestinationIPv4 | String | Destination IP address of the event (IPv4). | 
| FireEyeHelix.Alert.DestinationIPv6 | String | Destination IP address of the event (IPv6). | 
| FireEyeHelix.Alert.DestinationPort | String | Destination port of the event. | 
| FireEyeHelix.Alert.URI | String | URI address that created the event. | 
| FireEyeHelix.Alert.HttpMethod | String | HTTP method of the request that was called. | 
| FireEyeHelix.Alert.Domain | String | Domain of the URI that created the event. | 
| FireEyeHelix.Alert.UserAgent | String | User agent related to the event. | 
| FireEyeHelix.Alert.EventsCount | Number | Number of events in the alert. | 
| FireEyeHelix.Alert.NotesCount | Number | Number of notes in the alert. | 
| FireEyeHelix.Alert.ClosedState | String | Status of the alert in regards to it being closed. | 
| FireEyeHelix.Alert.ClosedReason | String | Reason the alert was closed. | 
| FireEyeHelix.Alert.Confidence | String | Helix confidence level of the alert. | 
| FireEyeHelix.Alert.Description | String | Description of the alert. | 
| FireEyeHelix.Alert.FirstEventTime | Date | Time that the first event occurred. | 
| FireEyeHelix.Alert.LastEventTime | Date | Time that the last event occurred. | 
| FireEyeHelix.Alert.ExternalIP | String | External IP addresses for the alert. | 
| FireEyeHelix.Alert.InternalIP | String | Internal IP addresses for the alert. | 
| FireEyeHelix.Alert.Message | String | Message of the alert. | 
| FireEyeHelix.Alert.Products | String | Source of the alert. | 
| FireEyeHelix.Alert.Risk | String | Risk of the events in the alert. | 
| FireEyeHelix.Alert.Severity | String | Severity of the events in the alert. | 
| FireEyeHelix.Alert.State | String | State of the alert. Can be "Open", "Suppressed", "Closed", or "Reopened". | 
| FireEyeHelix.Alert.Tag | String | Tag of the alert. | 
| FireEyeHelix.Alert.Type | String | Alert type. | 
| FireEyeHelix.Alert.Count | String | Number of alerts. | 


##### Command Example
```!fireeye-helix-list-alerts page_size=2```

##### Human Readable Output
### FireEye Helix - List alerts:
### Page 1/58
ID|Name|Description|State|Severity|
|---|---|---|---|---|
| 123 | HX | FireEye HX detected and quarantined malware on this system. | Open | Medium |
| 32 | HX | This rule alerts on IOC. | Open | Medium |

### 2. fireeye-helix-get-alert-by-id
---
Returns alert details, by alert ID.
##### Base Command

`fireeye-helix-get-alert-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the alert. | Required | 
| headers | A comma-separated list (no spaces) of output values to display in the command result, e.g., ID,Name,Hostname. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Alert.ID | Number | Primary ID of the alert. | 
| FireEyeHelix.Alert.AlertTypeID | Number | ID of the alert type. | 
| FireEyeHelix.Alert.AlertTypeName | String | Name of the alert type. | 
| FireEyeHelix.Alert.AssigneeID | String | ID of the alert assignee. | 
| FireEyeHelix.Alert.AssigneeName | String | Assignee display name. | 
| FireEyeHelix.Alert.CreatorID | String | ID of the user who created the alert. | 
| FireEyeHelix.Alert.CreatorName | String | Name of the user who created the alert. | 
| FireEyeHelix.Alert.UpdaterID | String | Name of the user who updated the alert. | 
| FireEyeHelix.Alert.UpdaterName | String | Name of the user who updated the alert. | 
| FireEyeHelix.Alert.CreatedTime | Date | Time the alert was created. | 
| FireEyeHelix.Alert.ModifiedTime | Date | Time the alert was last modified. | 
| FireEyeHelix.Alert.ProcessPath | String | Path of the process. | 
| FireEyeHelix.Alert.Confidence | String | Helix confidence level of the alert. | 
| FireEyeHelix.Alert.SHA1 | String | SHA1 hash of the file. | 
| FireEyeHelix.Alert.MD5 | String | MD5 hash of the file. | 
| FireEyeHelix.Alert.Hostname | String | Hostname of the alert. | 
| FireEyeHelix.Alert.PID | Number | Process ID. | 
| FireEyeHelix.Alert.Size | Number | Size of the process in bytes. | 
| FireEyeHelix.Alert.Virus | String | Virus name. | 
| FireEyeHelix.Alert.Result | String | Result of the alert. | 
| FireEyeHelix.Alert.MalwareType | String | Malware type. | 
| FireEyeHelix.Alert.Filename | String | Name of the file that contains the virus. | 
| FireEyeHelix.Alert.RegPath | String | Registry key path. | 
| FireEyeHelix.Alert.EventTime | Date | Time that the event occurred. | 
| FireEyeHelix.Alert.IOCNames | String | Indicator of Compromise names. | 
| FireEyeHelix.Alert.Process | String | Name of the process that created the event. | 
| FireEyeHelix.Alert.ParentProcess | String | Name of the parent process to the process that created the event. | 
| FireEyeHelix.Alert.SourceIPv4 | String | Source IP address of the event (IPv4). | 
| FireEyeHelix.Alert.SourceIPv6 | String | Source IP address of the event (IPv6). | 
| FireEyeHelix.Alert.DestinationIPv4 | String | Destination IP address of the event (IPv4). | 
| FireEyeHelix.Alert.DestinationIPv6 | String | Destination IP address of the event (IPv6). | 
| FireEyeHelix.Alert.DestinationPort | String | Destination port of the event. | 
| FireEyeHelix.Alert.URI | String | URI address that created the event. | 
| FireEyeHelix.Alert.HttpMethod | String | HTTP method of the request that was called. | 
| FireEyeHelix.Alert.Domain | String | Domain of the URI that created the event. | 
| FireEyeHelix.Alert.UserAgent | String | User agent related to the event. | 
| FireEyeHelix.Alert.EventsCount | Number | Number of events in the alert. | 
| FireEyeHelix.Alert.NotesCount | Number | Number of notes in the alert. | 
| FireEyeHelix.Alert.ClosedState | String | State the alert in regards to it being closed. | 
| FireEyeHelix.Alert.ClosedReason | String | Reason the alert was closed. | 
| FireEyeHelix.Alert.Confidence | String | Helix confidence level of the alert. | 
| FireEyeHelix.Alert.Description | String | Description of the alert. | 
| FireEyeHelix.Alert.FirstEventTime | Date | Time that the first event occurred. | 
| FireEyeHelix.Alert.LastEventTime | Date | Time that the last event occurred. | 
| FireEyeHelix.Alert.ExternalIP | String | External IP addresses for the alert. | 
| FireEyeHelix.Alert.InternalIP | String | Internal IP addresses for the alert. | 
| FireEyeHelix.Alert.Message | String | Message of the alert. | 
| FireEyeHelix.Alert.Products | String | Source of the alert. | 
| FireEyeHelix.Alert.Risk | String | Risk of the events in the alert. | 
| FireEyeHelix.Alert.Severity | String | Severity of the events in the alert. | 
| FireEyeHelix.Alert.State | String | State of the alert. Can be "Open", "Suppressed", "Closed", or "Reopened". | 
| FireEyeHelix.Alert.Tag | String | Tag of the alert. | 
| FireEyeHelix.Alert.Type | String | Alert type. | 
| FireEyeHelix.Alert.Count | String | Number of alerts. | 


##### Command Example
```!fireeye-helix-get-alert-by-id id=3232```

##### Human Readable Output
### FireEye Helix - Alert 3232:|AlertTypeID|ClosedState|Confidence|CreatedTime|CreatorID|CreatorName|Description|EventsCount|FileName|FirstEventTime|Hostname|ID|LastEventTime|MD5|MalwareType|Message|ModifiedTime|Name|NotesCount|PID|ProcessPath|Products|Result|Risk|SHA1|Severity|State|Tags|Type|UpdaterID|UpdaterName|Virus|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1793 | Unknown | high | 2019-03-30T19:40:16.132456Z | id | System User | FireEye HX detected and quarantined malware on this system. | 2 | c:\\users\\demon\\appdata\\local\\temp | 2019-03-30T14:07:34.132456ZZ | helix.apps.fireeye.com | 123 | 2019-03-31T14:08:07.132456ZZ | md5 | malware | FIREEYE H | 2019-10-20T12:35:02.132456Z | HX | 0 | 11 | c:\\windows\\microsoft.net\\framework\\v7.0.30319\\csc.exe | hx: 2 | quarantined | Medium | sha1 | Medium | Open | fireeye | fireeye_rule | id | George | gen:variant.ursu |

### 3. fireeye-helix-alert-create-note
---
Creates an alert note.
##### Base Command

`fireeye-helix-alert-create-note`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | ID of the alert for which the note is being created. | Required | 
| note | The note to add to the alert. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Note.ID | Number | Note ID. | 
| FireEyeHelix.Note.CreatedTime | Date | Time the note was created. | 
| FireEyeHelix.Note.UpdatedTime | Date | Time the note was updated. | 
| FireEyeHelix.Note.Message | String | Message of the note. | 
| FireEyeHelix.Note.CreatorID | String | ID of the note creator. | 
| FireEyeHelix.Note.CreatorName | String | Name of the note creator. | 
| FireEyeHelix.Note.AlertID | Number | ID of the related alert. | 


##### Command Example
```!fireeye-helix-alert-create-note note=This is a note test alert_id=3232```

##### Human Readable Output
### FireEye Helix - Created Note for Alert 3232:
|ID|Creator Name|Message|Created Time|
|---|---|---|---|
| 9 | George | This is a note test | 2019-10-28T07:41:30.396000Z |

### 4. fireeye-helix-get-events-by-alert
---
Lists alert events for a specific alert.
##### Base Command

`fireeye-helix-get-events-by-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID for which to get events. | Required | 
| headers | A comma-separated list (no spaces) of output values to display in the command result, e.g., ID,Type,SourceIPv4). | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Event.ID | String | Event ID. | 
| FireEyeHelix.Event.Type | String | Event type. | 
| FireEyeHelix.Event.Result | String | Event result. | 
| FireEyeHelix.Event.MatchedAt | Date | Time that the event was matched. | 
| FireEyeHelix.Event.Confidence | String | Confidence of the event. Can be "low", "medium", or "high". | 
| FireEyeHelix.Event.Status | String | Status of the event. | 
| FireEyeHelix.Event.EventTime | Date | Time that the event occurred. | 
| FireEyeHelix.Event.DetectedRuleID | String | ID of the detected rule. | 
| FireEyeHelix.Event.PID | String | Process ID. | 
| FireEyeHelix.Event.Process | String | Process details. | 
| FireEyeHelix.Event.ProcessPath | String | Process path. | 
| FireEyeHelix.Event.FileName | String | Name of the file affected by the event. | 
| FireEyeHelix.Event.FilePath | String | Path of the the file affected by the event. | 
| FireEyeHelix.Event.DeviceName | String | Device name. | 
| FireEyeHelix.Event.Size | String | Size of the file (in bytes) that created the event. | 
| FireEyeHelix.Event.Virus | String | Virus that was detected in the event. | 
| FireEyeHelix.Event.MalwareType | String | Malware type of the virus that was detected. | 
| FireEyeHelix.Event.CreatedTime | Date | Time that the event was created. | 
| FireEyeHelix.Event.Class | String | Event class. | 
| FireEyeHelix.Event.MD5 | String | MD5 hash of the affected file. | 
| FireEyeHelix.Event.SHA1 | String | SHA1 hash of the affected file. | 
| FireEyeHelix.Event.Protocol | String | Protocol used in the event. | 
| FireEyeHelix.Event.SourceIPv4 | String | IPv4 address of the event source. | 
| FireEyeHelix.Event.SourceIPv6 | String | IPv6 address of the event source. | 
| FireEyeHelix.Event.SourcePort | String | Port of the event source address. | 
| FireEyeHelix.Event.SourceLongitude | String | Longitude of the event source address. | 
| FireEyeHelix.Event.SourceLatitude | String | Latitude of the event source address. | 
| FireEyeHelix.Event.DestinationIPv4 | String | IPv4 address of the event destination. | 
| FireEyeHelix.Event.DestinationIPv6 | String | IPv6 address of the event destination. | 
| FireEyeHelix.Event.DestinationPort | String | Port of the event destination address. | 
| FireEyeHelix.Event.ReportTime | Date | Time that the event was reported. | 
| FireEyeHelix.Event.FalsePositive | String | Whether the event is a false positive. | 
| FireEyeHelix.Event.Domain | String | Domain of the recipient. | 
| FireEyeHelix.Event.From | String | Source email address. | 
| FireEyeHelix.Event.SourceDomain | String | Domain of the host that created the event. | 
| FireEyeHelix.Event.SourceISP | String | ISP of the source of the event. | 
| FireEyeHelix.Event.DestinationISP | String | ISP of the destination of the event. | 
| FireEyeHelix.Event.To | String | Destination email address. | 
| FireEyeHelix.Event.Attachment | Unknown | Email attachment. | 
| FireEyeHelix.Event.Count | Number | Total number of events. | 


##### Command Example
```!fireeye-helix-get-events-by-alert alert_id=3232```

##### Human Readable Output
### FireEye Helix - Events for alert 3232:
|Class|Detected Rule ID|Event Time|False Positive|ID|MD5|Matched At|PID|Process|Process Path|Report Time|Result|Type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fireeye_hx_alert | 99 | 2019-09-13T06:51:59.000Z | false | 101 | md5 | 2019-08-11t06:51:40.000z | 404 | net1 | c:\\windows\\system32\
et1.exe | 2019-09-13t06:53:08.000 | alert | processevent |

### 5. fireeye-helix-get-endpoints-by-alert
---
Retrieves a specific alert from an helix endpoint.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`fireeye-helix-get-endpoints-by-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | ID of an alert. | Required | 
| offset | Offset to the result. Default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Endpoint.ID | Number | Endpoint ID. | 
| FireEyeHelix.Endpoint.CustomerID | String | Customer ID. | 
| FireEyeHelix.Endpoint.DeviceID | String | Device ID. | 
| FireEyeHelix.Endpoint.Domain | String | Domain of the endpoint. | 
| FireEyeHelix.Endpoint.Hostname | String | Hostname of the endpoint. | 
| FireEyeHelix.Endpoint.MACAddress | String | MAC address of the endpoint. | 
| FireEyeHelix.Endpoint.OS | String | Operating system of the endpoint. | 
| FireEyeHelix.Endpoint.IP | String | IP address of the endpoint. | 
| FireEyeHelix.Endpoint.UpdatedTime | Date | Time the endpoint was last updated. | 
| FireEyeHelix.Endpoint.ContainmentState | String | Containment state of the endpoint. | 
| FireEyeHelix.Endpoint.Count | Number | Total number of endpoints. | 


##### Command Example
```!fireeye-helix-get-endpoints-by-alert alert_id=3232 offset=0```

##### Human Readable Output
### FireEye Helix - Endpoints for alert 3232:
|ID|Device ID|Hostname|IP|MAC Address|Updated Time|
|---|---|---|---|---|---|
| 191 | device_id | Demisto | primary_ip_address | mac_address | updated_at |

### 6. fireeye-helix-get-cases-by-alert
---
Returns cases of an alert.
##### Base Command

`fireeye-helix-get-cases-by-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | ID of an alert. | Required | 
| page_size | Number of results to return per page. | Optional | 
| offset | The initial index from which to return the results. | Optional | 
| order_by | The field by which to order the results. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Case.AlertsCount | Number | Number of alerts related to the case. | 
| FireEyeHelix.Case.AssigneeID | String | ID of the assignee. | 
| FireEyeHelix.Case.AssigneeName | String | Name of the assignee. | 
| FireEyeHelix.Case.CreatorID | String | ID of the case creator. | 
| FireEyeHelix.Case.CreatorName | String | Name of the case creator. | 
| FireEyeHelix.Case.UpdaterID | String | ID of the user who last updated the case. | 
| FireEyeHelix.Case.UpdaterName | String | Name of the user who last updated the case. | 
| FireEyeHelix.Case.CreatedTime | Date | Time that the case was created. | 
| FireEyeHelix.Case.ModifiedTime | Date | Time that the case was last modified. | 
| FireEyeHelix.Case.Description | String | Case description. | 
| FireEyeHelix.Case.EventsCount | Number | Number of events in the case. | 
| FireEyeHelix.Case.ID | Number | ID of the case. | 
| FireEyeHelix.Case.InfoLinks | Unknown | Informational or reference links. | 
| FireEyeHelix.Case.Name | String | Name of the case. | 
| FireEyeHelix.Case.NotesCount | Number | Number of notes in the case. | 
| FireEyeHelix.Case.Priority | String | Provides an indication of the order in which the case should be examined as compared to other cases. Priority can be "Critical", "High", "Medium", or "Low". | 
| FireEyeHelix.Case.PriorityOrder | Number | Provides an indication of the order in which the case should be examined as compared to other cases. Priority order can be "4", "3", "2", or "1". | 
| FireEyeHelix.Case.Severity | Number | The potential impact that the case could have on the organization if it is a true positive. It is calculated based on the risk of the alert. | 
| FireEyeHelix.Case.State | String | State of the case. | 
| FireEyeHelix.Case.Status | String | Cases with the following statuses are considered open: Declared, Scoped, Contained.
Cases with the following statuses are considered closed: Recovered, Improved. | 
| FireEyeHelix.Case.Tags | Unknown | Tags of the case. | 
| FireEyeHelix.Case.TotalDaysUnresolved | Number | The number of days the case has been unresolved. | 
| FireEyeHelix.Case.Count | Number | Total number of cases. | 


##### Command Example
```!fireeye-helix-get-cases-by-alert alert_id=3232 offset=0 page_size=1```

##### Human Readable Output
### FireEye Helix - Cases for alert 3232:
|ID|Name|Priority|Severity|State|Status|ModifiedTime|
|---|---|---|---|---|---|---|
| 35 | demisto test case | Critical | 10 | Testing | Declared | updated_at |

### 7. fireeye-helix-get-lists
---
Returns lists.
##### Base Command

`fireeye-helix-get-lists`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Number of results to return per page. | Optional | 
| offset | The initial index from which to return the results. | Optional | 
| usage | Multiple values may be separated by commas. | Optional | 
| created_at | The date that the list was created. | Optional | 
| description | Description of the list. | Optional | 
| is_active | Whether the list is active. Can be "true" or "false". | Optional | 
| is_internal | Whether the list is internal. Can be "true" or "false". | Optional | 
| is_protected | Whether the list is protected. Can be "true" or "false". | Optional | 
| name | Name of the list. | Optional | 
| short_name | Short name of the list. | Optional | 
| type | List type. | Optional | 
| updated_at | The time the list was last updated. | Optional | 
| order_by | The field by which to order the results. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.List.ID | Number | List ID. | 
| FireEyeHelix.List.Description | Number | List description. | 
| FireEyeHelix.List.ShortName | String | Short name of the list. | 
| FireEyeHelix.List.Name | String | Name of the list. | 
| FireEyeHelix.List.ContentTypes | String | Content types of the list. Can be Email, FQDN, IPv4, Ipv6, SHA1, MD5, or Misc. | 
| FireEyeHelix.List.CreatorID | String | ID of the creator. | 
| FireEyeHelix.List.CreatorName | String | Name of the creator. | 
| FireEyeHelix.List.UpdatedByID | String | ID of the user who last updated the list. | 
| FireEyeHelix.List.CreatedTime | Date | Time that the rule was created. | 
| FireEyeHelix.List.UpdatedTime | Date | Time that the rule was last updated. | 
| FireEyeHelix.List.Type | String | List type. Can be Default, Analytics Whitelist, or Intel Matching. | 
| FireEyeHelix.List.UpdatedByName | String | User who last updated the list. | 
| FireEyeHelix.List.Internal | Boolean | Whether the list is internal. Can be true or false. | 
| FireEyeHelix.List.Protected | Boolean | Whether the list is protected. Can be true or false. | 
| FireEyeHelix.List.Active | Unknown | Whether the list is active. Can be true or false. | 
| FireEyeHelix.List.Count | Number | Total number of lists. | 


### 8. fireeye-helix-get-list-by-id
---
Returns a specific list by list ID.
##### Base Command

`fireeye-helix-get-list-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the list. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.List.ID | Number | List ID. | 
| FireEyeHelix.List.Description | Number | List description. | 
| FireEyeHelix.List.ShortName | String | Short name of the list. | 
| FireEyeHelix.List.Name | String | Name of the list. | 
| FireEyeHelix.List.ContentTypes | String | Content types of the list. Can be Email, FQDN, IPv4, Ipv6, SHA1, MD5, or Misc. | 
| FireEyeHelix.List.CreatorID | String | ID of the creator. | 
| FireEyeHelix.List.CreatorName | String | Name of the creator. | 
| FireEyeHelix.List.UpdatedByID | String | ID of the user who last updated the list. | 
| FireEyeHelix.List.CreatedTime | Date | Time that the rule was created. | 
| FireEyeHelix.List.UpdatedTime | Date | Time that the rule was last updated. | 
| FireEyeHelix.List.Type | String | List type. Can be Default, Analytics Whitelist, or Intel Matching. | 
| FireEyeHelix.List.UpdatedByName | String | Name of the user who last updated the list. | 
| FireEyeHelix.List.Internal | Boolean | Whether the list is internal. Can be true or false. | 
| FireEyeHelix.List.Protected | Boolean | Whether the list is protected. Can be true or false. | 
| FireEyeHelix.List.Active | Unknown | Whether the list is active. Can be true or false. | 


### 9. fireeye-helix-create-list
---
Creates a list.
##### Base Command

`fireeye-helix-create-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the list. | Required | 
| short_name | Short name of the list. | Optional | 
| is_internal | Whether the list is internal. Can be true or false. | Optional | 
| is_active | Whether the list is active. Can be true or false. | Optional | 
| is_protected | Whether the list is protected. Can be true or false. | Optional | 
| usage | A comma-separated list of list uses. | Optional | 
| is_hidden | Whether the list is hiddne. Can be true or false. | Optional | 
| type | List type. | Optional | 
| description | Description of the list. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.List.ID | Number | List ID. | 
| FireEyeHelix.List.Description | Number | List description. | 
| FireEyeHelix.List.ShortName | String | Short name of the list. | 
| FireEyeHelix.List.Name | String | Name of the list. | 
| FireEyeHelix.List.ContentTypes | String | Content types of the list. Can be Email, FQDN, IPv4, IPv6, SHA1, MD5, or Misc. | 
| FireEyeHelix.List.CreatorID | String | ID of the list creator. | 
| FireEyeHelix.List.CreatorName | String | Name of the list creator. | 
| FireEyeHelix.List.UpdatedByID | String | ID of the user who last updated the list. | 
| FireEyeHelix.List.CreatedTime | Date | Time that the rule was created. | 
| FireEyeHelix.List.UpdatedTime | Date | Time that the rule was last updated. | 
| FireEyeHelix.List.Type | String | List type. Can be Default, Analytics Whitelist, or Intel Matching. | 
| FireEyeHelix.List.UpdatedByName | Unknown | Name of the user who last updated the list. | 
| FireEyeHelix.List.Internal | Boolean | Whether the list is internal. Can be true or false. | 
| FireEyeHelix.List.Protected | Boolean | Whether the list is protected. Can be true or false. | 
| FireEyeHelix.List.Active | Unknown | Whether the list is active. Can be true or false. | 

### 10. fireeye-helix-update-list
---
Updates an existing list.
##### Base Command

`fireeye-helix-update-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the list to update. | Optional | 
| short_name | Short name of the list. | Optional | 
| is_internal | Whether the list is internal. Can be true or false. | Optional | 
| is_active | Whether the list is active. Can be true or false. | Optional | 
| is_protected | Whether the list is protected. Can be true or false. | Optional | 
| usage | A comma-separated list of list uses. | Optional | 
| is_hidden | Whether the list is hiddne. Can be true or false. | Optional | 
| type | List type. | Optional | 
| description | Description of the list. | Optional | 
| list_id | ID of the list. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.List.ID | Number | List ID. | 
| FireEyeHelix.List.Description | Number | List description. | 
| FireEyeHelix.List.ShortName | String | Short name of the list. | 
| FireEyeHelix.List.Name | String | Name of the list. | 
| FireEyeHelix.List.ContentTypes | String | Content types of the list. Can be Email, FQDN, IPv4, IPv6, SHA1, MD5, or Misc. | 
| FireEyeHelix.List.CreatorID | String | ID of the creator. | 
| FireEyeHelix.List.CreatorName | String | Name of the creator. | 
| FireEyeHelix.List.UpdatedByID | String | ID of the user who last updated the list. | 
| FireEyeHelix.List.CreatedTime | Date | Time that the rule was created. | 
| FireEyeHelix.List.UpdatedTime | Date | Time that the rule was last updated. | 
| FireEyeHelix.List.Type | String | List type. Can be Default, Analytics Whitelist, Intel Matching. | 
| FireEyeHelix.List.UpdatedByName | Unknown | Name of the user who last updated the list. | 
| FireEyeHelix.List.Internal | Boolean | Whether the list is internal. Can be true or false. | 
| FireEyeHelix.List.Protected | Boolean | Whether the list is protected. Can be true or flase. | 
| FireEyeHelix.List.Active | Unknown | Whether the list is active. Can be true or false. | 

### 11. fireeye-helix-delete-list
---
Deletes a single list by list ID.
##### Base Command

`fireeye-helix-delete-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | ID of the list to delete. | Required | 


##### Context Output

There is no context output for this command.

### 12. fireeye-helix-list-sensors
---
Fetches all sensors.
##### Base Command

`fireeye-helix-list-sensors`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Maximum number of results to return per page. | Optional | 
| offset | The initial index from which to return the results. | Optional | 
| hostname | Host name of the sensor. | Optional | 
| status | Status of the sensor. | Optional | 


##### Context Output

There is no context output for this command.

### 13. fireeye-helix-list-rules
---
Returns all rules.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`fireeye-helix-list-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Maximum number of results to return per page. | Optional | 
| offset | The initial index from which to return the results. | Optional | 
| sort | A comma-separated list of field names by which to sort the results. For example: “createDate” or "-updateDate,riskOrder" | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Rule.ID | String | Rule ID. | 
| FireEyeHelix.Rule.RulePack | String | Rule package version. | 
| FireEyeHelix.Rule.Description | String | Rule description. | 
| FireEyeHelix.Rule.Internal | Boolean | Whether the rule is internal. Can be true or false. | 
| FireEyeHelix.Rule.Deleted | Boolean | Whether the rule was deleted. Can be true or false. | 
| FireEyeHelix.Rule.Enabled | Boolean | Whether the rule is enabled. Can be true or false. | 
| FireEyeHelix.Rule.Supported | Boolean | Whether the rule is supported. Can be true or false. | 
| FireEyeHelix.Rule.CreatorID | String | ID of the rule creator. | 
| FireEyeHelix.Rule.CreatorName | String | Name of the rule creator. | 
| FireEyeHelix.Rule.UpdatedByID | String | ID of the user who updated the rule. | 
| FireEyeHelix.Rule.UpdatedByName | String | Name of the user who updated the rule. | 
| FireEyeHelix.Rule.Risk | String | The risk to your environment when an event matches this rule. Can be low, medium, high, or critical. | 
| FireEyeHelix.Rule.Confidence | String | Confidence that indicates how likely it is that the rule will detect events that correspond to the type of activity anticipated (that is, the likelihood that the rule will produce true positives). Confidence and Severity combine to form the risk attribute of the alert. Can be low, medium, or high. | 
| FireEyeHelix.Rule.Severity | String | Severity that indicates how much of an impact a hit with this rule could have on an organization if
verified to be a true positive. Confidence and Severity combine to form the risk attribute of the alert. Can be low, medium, or high. | 
| FireEyeHelix.Rule.Tags | String | Rule tags. | 
| FireEyeHelix.Rule.Type | String | Rule type. | 


##### Command Example
```!fireeye-helix-list-rules offset=1```

##### Human Readable Output
### FireEye Helix - List rules:
|ID|Type|Description|Risk|Confidence|Severity|Enabled|
|---|---|---|---|---|---|---|
| 1.1.1 | alert | demisto | Medium | Medium | Medium | true |

### 14. fireeye-helix-edit-rule
---
Modifies an existing rule.
##### Base Command

`fireeye-helix-edit-rule`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enabled | Whether the rule is enabled. Can be true or false. | Optional | 
| rule_id | ID of the rule. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!fireeye-helix-edit-rule rule_id=1.1.1 enabled=true```

##### Human Readable Output
### FireEye Helix - Successfully updated rule 1.1.1:
|ID|Type|Description|Risk|Confidence|Severity|
|---|---|---|---|---|---|
| 1.1.1 | alert | demisto | Medium | Medium | Medium |

### 15. fireeye-helix-alert-get-notes
---
Returns all notes related to an alert.
##### Base Command

`fireeye-helix-alert-get-notes`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Note.ID | Number | Note ID. | 
| FireEyeHelix.Note.CreatedTime | Date | Time that the note was created. | 
| FireEyeHelix.Note.UpdatedTime | Date | Time that the note was updated. | 
| FireEyeHelix.Note.Message | String | Message of the note. | 
| FireEyeHelix.Note.CreatorID | String | ID of the note creator. | 
| FireEyeHelix.Note.CreatorName | String | Name of the note creator. | 
| FireEyeHelix.Note.AlertID | Number | ID of the related alert. | 
| FireEyeHelix.Note.Count | Number | Total number of notes for the alert. | 


##### Command Example
```!fireeye-helix-alert-get-notes id=3232```

##### Human Readable Output
### FireEye Helix - Notes for Alert None:
|ID|Creator Name|Message|Created Time|
|---|---|---|---|
| 9 | George | This is a note test | 2019-10-28T07:41:30.396000Z |
| 91 | George | What a great note this is | 2019-10-24T13:52:19.021299Z |

### 16. fireeye-helix-alert-delete-note
---
Deletes an alert note.
##### Base Command

`fireeye-helix-alert-delete-note`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | ID of the alert to delete. | Required | 
| note_id | Note ID. | Required | 


##### Context Output

There is no context output for this command.

### 17. fireeye-helix-search
---
Executes a search in FireEye Helix using MQL.
##### Base Command

`fireeye-helix-search`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Start time of the event in the format yyyy-mm-dd or yyyy-mm. | Optional | 
| end | End time of the event in the format yyyy-mm-dd or yyyy-mm. | Optional | 
| page_size | Maximum number of results to return. | Optional | 
| offset | Offset of the result. | Optional | 
| groupby | Returns the unique values for the specified field and groups them based on the specified frequency. For example, groupby="srcipv4 5 100" will group the top five srcipv4 addresses that have at least 100 occurrences. Supports comma-separated values. | Optional | 
| sort_by | The field by which to sort results. | Optional | 
| sort_order | Controls the order of the results sorted by the sort_by argument. Can be "asc" for ascending or "desc" for descending. Default is "desc". | Optional | 
| query | The query to execute. This is the search clause in an MQL. | Required | 
| limit | The number of events to search. | Optional | 
| headers | A comma-separated list (no spaces) of output values to display in the command result, e.g., ID,Type,SourceIPv4. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixSearch.Result.ID | String | Event ID. | 
| FireEyeHelixSearch.Result.Type | String | Event type. | 
| FireEyeHelixSearch.Result.Result | String | Event result. | 
| FireEyeHelixSearch.Result.MatchedAt | Date | Time that the event was matched. | 
| FireEyeHelixSearch.Result.Confidence | String | Confidence of the event. Can be low, medium, or high. | 
| FireEyeHelixSearch.Result.Status | String | Status of the event. | 
| FireEyeHelixSearch.Result.EventTime | Date | Time that the event took occurred. | 
| FireEyeHelixSearch.Result.DetectedRuleID | String | ID of the detected rule. | 
| FireEyeHelixSearch.Result.PID | String | Process ID. | 
| FireEyeHelixSearch.Result.Process | String | Process details. | 
| FireEyeHelixSearch.Result.ProcessPath | String | Process path. | 
| FireEyeHelixSearch.Result.FileName | String | Name of the file affected by the event. | 
| FireEyeHelixSearch.Result.FilePath | String | Path of the the file affected by the event. | 
| FireEyeHelixSearch.Result.DeviceName | String | Device name. | 
| FireEyeHelixSearch.Result.Size | String | Size of the file (in bytes) that created the event. | 
| FireEyeHelixSearch.Result.Virus | String | Virus that was detected in the event. | 
| FireEyeHelixSearch.Result.MalwareType | String | Malware type of the virus that was detected. | 
| FireEyeHelixSearch.Result.CreatedTime | Date | Time that the event was created. | 
| FireEyeHelixSearch.Result.Class | String | Event class. | 
| FireEyeHelixSearch.Result.MD5 | String | MD5 hash of the affected file. | 
| FireEyeHelixSearch.Result.SHA1 | String | SHA1 hash of the affected file. | 
| FireEyeHelixSearch.Result.Protocol | String | Protocol used in the event. | 
| FireEyeHelixSearch.Result.SourceIPv4 | String | IPv4 address of the event source. | 
| FireEyeHelixSearch.Result.SourceIPv6 | String | IPv6 address of the event source. | 
| FireEyeHelixSearch.Result.SourcePort | String | Port of the event source address. | 
| FireEyeHelixSearch.Result.SourceLongitude | String | Longitude of the event source address. | 
| FireEyeHelixSearch.Result.SourceLatitude | String | Latitude of the event source address. | 
| FireEyeHelixSearch.Result.DestinationIPv4 | String | IPv4 address of the event destination. | 
| FireEyeHelixSearch.Result.DestinationIPv6 | String | IPv6 address of the event destination. | 
| FireEyeHelixSearch.Result.DestinationPort | String | Port of the event destination address. | 
| FireEyeHelixSearch.Result.ReportTime | Date | Time that the event was reported. | 
| FireEyeHelixSearch.Result.FalsePositive | String | Whether the event is a false positive. | 
| FireEyeHelixSearch.Result.Domain | String | Domain of the recepient. | 
| FireEyeHelixSearch.Result.From | String | Source email address. | 
| FireEyeHelixSearch.Result.SourceDomain | String | Domain of the host that created the event. | 
| FireEyeHelixSearch.Result.SourceISP | String | ISP of the source of the event. | 
| FireEyeHelixSearch.Result.DestinationISP | String | ISP of the destination of the event. | 
| FireEyeHelixSearch.Result.To | String | Destination email address. | 
| FireEyeHelixSearch.Result.Attachment | Unknown | Email attachment. | 
| FireEyeHelixSearch.MQL | String | MQL query that created the result. | 
| FireEyeHelixSearch.GroupBy | Unknown | Group by values. | 
| FireEyeHelixSearch.GroupBy.DocCount | Number | Number of matches for the group. | 
| FireEyeHelixSearch.Result.RcpTo | String | Recipient email address. | 
| FireEyeHelixSearch.Result.InReplyTo | String | Reply email address. | 


##### Command Example
```!fireeye-helix-search query=domain:google.com start="4 days ago" groupby=subject limit=1 page_size=2```

##### Human Readable Output
### FireEye Helix - Search result for domain:google.com and meta_ts>=2019-10-25T09:07:43.810Z {page_size:2 offset:1 limit:1} | groupby subject sep=`|%$,$%|`
|Class|Domain|Event Time|From|ID|In Reply To|Source Domain|Source I Pv 4|Source ISP|Source Latitude|Source Longitude|Status|To|Type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fireeye_etp | mx.google.com | 2019-10-28T10:43:11.000Z | de@demisto.com | demisto | demisto | google.com | 8.8.8.8 | google llc | 37.40599060058594 | -122.0785140991211 | delivered | demisto@demisto.com | trace |
| fireeye_etp | gmr-mx.google.com | 2019-10-29T05:08:39.000Z | dem@demisto.com | demisto | demisto@demisto.com | google.com | 8.8.8.8 | google llc | 37.40599060058594 | -122.0785140991211 | delivered | demisto@demisto.com | trace |
### Group By
|subject|DocCount|
|---|---|
| google alert - gold | 3 |
| accepted: meeting | 1 |
| invitation: Declined | 1 |

### 18. fireeye-helix-add-list-item
---
Adds an item to a list.
##### Base Command

`fireeye-helix-add-list-item`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Item type. Can be email, fqdn, ipv4, ipv6, md5, misc, or sha-1. | Required | 
| value | Item value. | Required | 
| list_id | ID of the list. | Required | 
| risk | Risk of the item. Can be Low, Medium, High, or Critical. | Optional | 
| notes | Item notes. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixList.Item.ID | Number | Item ID. | 
| FireEyeHelixList.Item.Value | String | Item value. | 
| FireEyeHelixList.Item.Type | String | Item type. Can be email, fqdn, ipv4, ipv6, md5, misc, or sha-1. | 
| FireEyeHelixList.Item.Risk | String | Risk of the item. Can be Low, Medium, High, or Critical. | 
| FireEyeHelixList.Item.Notes | String | Item notes. | 
| FireEyeHelixList.Item.ListID | String | List ID with which the item is associated. | 


##### Command Example
```!fireeye-helix-add-list-item list_id=3232 value=test type=misc risk=Low```

##### Human Readable Output
### FireEye Helix - List item 163 was added successfully to 3232
|ID|ListID|Notes|Risk|Type|Value|
|---|---|---|---|---|---|
| 163 | 3232 | test ok | Medium | misc | aTest list |

### 19. fireeye-helix-get-list-items
---
Fetches items of a list.
##### Base Command

`fireeye-helix-get-list-items`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | ID of the list for which to fetch items. | Required | 
| offset | Item offset. Default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixList.Item.ID | Number | Item ID. | 
| FireEyeHelixList.Item.Value | String | Item value. | 
| FireEyeHelixList.Item.Type | String | Item type. Can be email, fqdn, ipv4, ipv6, md5, misc, or sha-1. | 
| FireEyeHelixList.Item.Risk | String | Risk of the item. Can be Low, Medium, High, or Critical. | 
| FireEyeHelixList.Item.Notes | String | Item notes. | 
| FireEyeHelixList.Item.ListID | String | List ID with which the item is associated. | 
| FireEyeHelixList.Item.Count | Number | Number of items in the list. | 


##### Command Example
```!fireeye-helix-get-list-items list_id=3232 offset=0```

##### Human Readable Output
### FireEye Helix - List items for list 3232
|ID|ListID|Notes|Risk|Type|Value|
|---|---|---|---|---|---|
| 163 | 3232 |  | Low | misc | Test list |

### 20. fireeye-helix-update-list-item
---
Updates a single list item.
##### Base Command

`fireeye-helix-update-list-item`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | ID of the item to update. | Required | 
| type | Item type. Can be email, fqdn, ipv4, ipv6, md5, misc, or sha-1. | Optional | 
| value | Item value. | Optional | 
| list_id | ID of the list. | Required | 
| risk | Risk of the item. Can be Low, Medium, High, or Critical. | Optional | 
| notes | Item notes. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixList.Item.ID | Number | Item ID. | 
| FireEyeHelixList.Item.Value | String | Item value. | 
| FireEyeHelixList.Item.Type | String | Item type. Can be email, fqdn, ipv4, ipv6, md5, misc, or sha-1. | 
| FireEyeHelixList.Item.Risk | String | Risk of the item. Can be Low, Medium, High, or Critical. | 
| FireEyeHelixList.Item.Notes | String | Item notes. | 
| FireEyeHelixList.Item.ListID | String | List ID with which the item is associated. | 


##### Command Example
```!fireeye-helix-update-list-item list_id=3232 value=test type=misc risk=Low item_id=163```

##### Human Readable Output
### FireEye Helix - List item 163 from list 3232 was updated successfully
|ID|ListID|Notes|Risk|Type|Value|
|---|---|---|---|---|---|
| 163 | 3232 | test ok | Medium | misc | aTest list |

### 21. fireeye-helix-remove-list-item
---
Removes an item from a list.
##### Base Command

`fireeye-helix-remove-list-item`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | ID of the list from which to remove an item. | Required | 
| item_id | Item ID. | Required | 


##### Context Output

There is no context output for this command.

### 22. fireeye-helix-archive-search-get-results
---
Fetches archive search results.

##### Base Command

`fireeye-helix-archive-search-get-results`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | ID of the search for which to return archive results. | Required | 
| headers | A comma-separated list of output values to display in the command result, e.g., ID,Type,SourceIPv4. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixSearch.Result.ID | String | Event ID. | 
| FireEyeHelixSearch.Result.Type | String | Event type. | 
| FireEyeHelixSearch.Result.Result | String | Event result. | 
| FireEyeHelixSearch.Result.MatchedAt | Date | Time that the event was matched. | 
| FireEyeHelixSearch.Result.Confidence | String | Confidence of the event. Can be low, medium, or high. | 
| FireEyeHelixSearch.Result.Status | String | Status of the event. | 
| FireEyeHelixSearch.Result.EventTime | Date | Time that the event occurred. | 
| FireEyeHelixSearch.Result.DetectedRuleID | String | ID of the detected rule. | 
| FireEyeHelixSearch.Result.PID | String | Process ID. | 
| FireEyeHelixSearch.Result.Process | String | Process details. | 
| FireEyeHelixSearch.Result.ProcessPath | String | Process path. | 
| FireEyeHelixSearch.Result.FileName | String | Name of the file affected by the event. | 
| FireEyeHelixSearch.Result.FilePath | String | Path of the the file affected by the event. | 
| FireEyeHelixSearch.Result.DeviceName | String | Device name. | 
| FireEyeHelixSearch.Result.Size | String | Size of the file (in bytes) that created the event. | 
| FireEyeHelixSearch.Result.Virus | String | Virus that was detected in the event. | 
| FireEyeHelixSearch.Result.MalwareType | String | Malware type of the virus that was detected. | 
| FireEyeHelixSearch.Result.CreatedTime | Date | Time that the event was created. | 
| FireEyeHelixSearch.Result.Class | String | Event class. | 
| FireEyeHelixSearch.Result.MD5 | String | MD5 hash of the affected file. | 
| FireEyeHelixSearch.Result.SHA1 | String | SHA1 hash of the affected file. | 
| FireEyeHelixSearch.Result.Protocol | String | Protocol used in the event. | 
| FireEyeHelixSearch.Result.SourceIPv4 | String | IPv4 address of the event source. | 
| FireEyeHelixSearch.Result.SourceIPv6 | String | IPv6 address of the event source. | 
| FireEyeHelixSearch.Result.SourcePort | String | Port of the event source address. | 
| FireEyeHelixSearch.Result.SourceLongitude | String | Longitude of the event source address. | 
| FireEyeHelixSearch.Result.SourceLatitude | String | Latitude of the event source address. | 
| FireEyeHelixSearch.Result.DestinationIPv4 | String | IPv4 address of the event destination. | 
| FireEyeHelixSearch.Result.DestinationIPv6 | String | IPv6 address of the event destination. | 
| FireEyeHelixSearch.Result.DestinationPort | String | Port of the event destination address. | 
| FireEyeHelixSearch.Result.ReportTime | Date | Time that the event was reported. | 
| FireEyeHelixSearch.Result.FalsePositive | String | Whether the event is a false positive. | 
| FireEyeHelixSearch.Result.Domain | String | Domain of the recepient. | 
| FireEyeHelixSearch.Result.From | String | Source email address. | 
| FireEyeHelixSearch.Result.SourceDomain | String | Domain of the host that created the event. | 
| FireEyeHelixSearch.Result.SourceISP | String | ISP of the source of the event. | 
| FireEyeHelixSearch.Result.DestinationISP | String | ISP of the destination of the event. | 
| FireEyeHelixSearch.Result.To | String | Destination email address. | 
| FireEyeHelixSearch.Result.Attachment | Unknown | Email attachment. | 
| FireEyeHelixSearch.MQL | String | MQL query that created the result. | 
| FireEyeHelixSearch.GroupBy | Unknown | Group by values. | 
| FireEyeHelixSearch.GroupBy.DocCount | Number | Number of matches for the group. | 
| FireEyeHelixSearch.Result.RcpTo | String | Recipient email address. | 
| FireEyeHelixSearch.Result.InReplyTo | String | Reply email address. | 


##### Command Example
```!fireeye-helix-archive-search-get-results search_id=82```

##### Human Readable Output
### FireEye Helix - Search result for domain:[google,com] | groupby eventtype sep=`|%$,$%|`
|Class|Domain|Event Time|From|ID|In Reply To|Source Domain|Source I Pv 4|Source ISP|Source Latitude|Source Longitude|Status|To|Type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fireeye_etp | domain.com | 2019-10-06T10:48:13.000Z | squidward@demisto.com | evenid | squidward <squidward@demisto.com> |  | 8.8.8.8 |  | 51.8594 | -0.12574 | delivered | demisto@demisto.com | trace |
| fireeye_etp | demisto.com | 2019-10-06T11:02:01.000Z | squidward@demisto.com | demisto | \"squidward\" <fsquidward@demisto.com> | squidward.com | 8.8.8.8 | squidward | 40.282958 | -75.19625 | delivered | squidward@demisto.com | trace |
| fireeye_etp | demisto.com | 2019-10-06T11:02:18.000Z | squidward@demisto.com | dwasdkffv | squidward <squidward@demisto.com> | demisto.com | 8.8.8.8 | demistos | 33.5 | -93.119 | delivered | squidward@demisto.com | trace |
| fireeye_etp | demisto.com | 2019-10-06T11:03:00.000Z | squidward@demisto.com | 93730 | geroge <hello@demisto.com> | demisto.com | 8.8.8.8 | the demisto group | 33.770843 | -84.377 | delivered | squidward@demisto.com | trace |

### 23. fireeye-helix-archive-search
---
Creates an archive search from a query.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`fireeye-helix-archive-search`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Start time of the event in the format yyyy-mm-dd or yyyy-mm. | Optional | 
| end | End time of the event in the format yyyy-mm-dd or yyyy-mm. | Optional | 
| offset | Offset of the result. | Optional | 
| groupby | Returns the unique values for the specified field and groups them based on the specified frequency. For example groupby="srcipv4 5 100" will group the top five srcipv4 addresses that have at least 100 occurences. Supports comma-separated values. | Optional | 
| sort_by | Sorts results by this field. | Optional | 
| sort_order | Controls the order of the results sorted by the sort_by argument. Can be "asc" for ascending or "desc" for descending. Default is "desc". | Optional | 
| query | The query to execute. This is the search clause in an MQL. | Required | 
| limit | Number of events to search. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixSearch.ID | Number | ID of an archive search. | 
| FireEyeHelixSearch.PercentComplete | String | Percentage of the search that was completed. | 
| FireEyeHelixSearch.Query | String | The search query. | 
| FireEyeHelixSearch.State | String | State of the search. | 


##### Command Example
```!fireeye-helix-archive-search query=domain:google.com start="4 days ago" groupby=subject limit=1 offset=1```

##### Human Readable Output
### FireEye Helix - Successfully created archive search
|ID|Percent Complete|Query|State|
|---|---|---|---|
| 82 | 100.0 | domain:[google,com] \\| groupby eventtype | completed |
| 83 | 100.0 | domain:[google] \\| groupby eventtype | completed |

### 24. fireeye-helix-archive-search-get-status
---
Gets the status of an archive search.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`fireeye-helix-archive-search-get-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | Archive search ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixSearch.ID | Number | ID of an archive search. | 
| FireEyeHelixSearch.PercentComplete | String | Percentage of the search that was completed. | 
| FireEyeHelixSearch.Query | String | The search query. | 
| FireEyeHelixSearch.State | String | State of the search. | 


##### Command Example
```!fireeye-helix-archive-search-get-status search_id=82,83```

##### Human Readable Output
### FireEye Helix - Search status
|ID|Percent Complete|Query|State|
|---|---|---|---|
| 82 | 100.0 | domain:[google,com] \\| groupby eventtype | completed |
| 83 | 100.0 | domain:[google,com] \\| groupby eventtype | completed |
