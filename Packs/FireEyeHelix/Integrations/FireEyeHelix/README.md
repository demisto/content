Use the FireEye Helix integration to integrate security tools and arguments with next-generation SIEM, orchestration and threat intelligence tools such as alert management, search, analysis, investigations and reporting.

In order to configure this integration you must have a FireEye customer ID. Your customer ID will placed in the FireEye Helix URL of your FireEye Helix app after `/helix/id/`. e.g. for the following URL `https://apps.fireeye.com/helix/id/"helixid"` the customer ID is "helixid".

The API key can be found and generated in the **API KEYS** section. You can navigate to it from your FireEye Helix app home page by clicking on the **user icon** on the top right, and choosing **HELIX Settings**. You'll be redirected to the **HELIX Settings** page, where API KEYS can be found.

## Configure FireEyeHelix on Cortex XSOAR

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for FireEyeHelix.
3. Click __Add instance__ to create and configure a new integration instance.

   | **Parameter** | **Description** | **Example** |
   | ---------             | -----------           | -------            |
   | Name | A meaningful name for the integration instance. | FireEyeHelix_instance_1 |
   | Server URL | The URL to the FireEye server, including the scheme. | https:/<span></span>/apps.fireeye<span></span>.com |
   | Customer ID | The ID used by the customer to gain access to the integration. | N/A |
   | API Token  | The private token granting access to the integration. | N/A  |
   | First Fetch Timestamp | The time period for which to fetch incidents in \&lt;number&gt; \&lt;time unit&gt; format. | 12 hours, 7 days, 3 months, 1 year |
   | Fetch Incident Query | Whether to fetch the incidents or not.  | N/A |
   | Incident Type  | The type of incident to select.  |  Phishing |
   | Trust any certificate (not secure) | When selected, certificates are not checked. | N/A |
   | Use System Proxy Settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. |  https:/<span></span>/proxyserver.com |


4. Click __Test__ to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get all alerts
---
Returns all alerts.

##### Base Command

`fireeye-helix-list-alerts`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | The maximum number of results to return per page. | Optional | 
| offset | The initial index from which to return the results. | Optional | 
| headers | The Output values to display in the command result (comma-separated values with no spaces) as they appear in the context. For example, "ID" , "Name", or "Hostname". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Alert.ID | Number | The primary ID of the alert. | 
| FireEyeHelix.Alert.AlertTypeID | Number | The ID of the alert type. | 
| FireEyeHelix.Alert.AlertTypeName | String | The name of the alert type. | 
| FireEyeHelix.Alert.AssigneeID | String | The ID of the assignee. | 
| FireEyeHelix.Alert.AssigneeName | String | The display name of the assignee. | 
| FireEyeHelix.Alert.CreatorID | String | The ID of the user who created the alert. | 
| FireEyeHelix.Alert.CreatorName | String | The name of the user who created the alert. | 
| FireEyeHelix.Alert.UpdaterID | String | The ID of the user who updated the alert. | 
| FireEyeHelix.Alert.UpdaterName | String | The Name of the user who updated the alert. | 
| FireEyeHelix.Alert.CreatedTime | Date | The time the alert was created. | 
| FireEyeHelix.Alert.ModifiedTime | Date | The time the alert was modified. | 
| FireEyeHelix.Alert.ProcessPath | String | The path of the process. | 
| FireEyeHelix.Alert.Confidence | String | The FireEye Helix confidence with the result. | 
| FireEyeHelix.Alert.SHA1 | String | The SHA1 hash of the file. | 
| FireEyeHelix.Alert.MD5 | String | The MD5 hash of the file. | 
| FireEyeHelix.Alert.Hostname | String | The hostname of the alert. | 
| FireEyeHelix.Alert.PID | Number | The process ID. | 
| FireEyeHelix.Alert.Size | Number | The size of the process in bytes. | 
| FireEyeHelix.Alert.Virues | String | THe virus name. | 
| FireEyeHelix.Alert.Result | String | The result of the alert. | 
| FireEyeHelix.Alert.MalwareType | String | The malware type. | 
| FireEyeHelix.Alert.Filename | String | The name of the file that contains the virus. | 
| FireEyeHelix.Alert.RegPath | String | The registry key path. | 
| FireEyeHelix.Alert.EventTime | Date | The time of the event. | 
| FireEyeHelix.Alert.IOCNames | String | The indicator of the compromise names. | 
| FireEyeHelix.Alert.Process | String | The name of the process that created the event. | 
| FireEyeHelix.Alert.ParentProcess | String | The name of the parent process of the process that created the event. | 
| FireEyeHelix.Alert.SourceIPv4 | String | The source IP address of the event (IPv4). | 
| FireEyeHelix.Alert.SourceIPv6 | String | The source IP address of the event (IPv6). | 
| FireEyeHelix.Alert.DestinationIPv4 | String | The destination IP address of the event (IPv4). | 
| FireEyeHelix.Alert.DestinationIPv6 | String | The destination IP address of the event (IPv6). | 
| FireEyeHelix.Alert.DestinationPort | String | The destination port of the event. | 
| FireEyeHelix.Alert.URI | String | The URI address that created the event. | 
| FireEyeHelix.Alert.HttpMethod | String | The HTTP method of the request that was called. | 
| FireEyeHelix.Alert.Domain | String | The domain of the URI that created the event. | 
| FireEyeHelix.Alert.UserAgent | String | The user agent related to the event. | 
| FireEyeHelix.Alert.EventsCount | Number | The number of events in the alert. | 
| FireEyeHelix.Alert.NotesCount | Number | The number of notes in the alert. | 
| FireEyeHelix.Alert.ClosedState | String | The status of the alert in regards to it being closed. | 
| FireEyeHelix.Alert.ClosedReason | String | The reason the alert was closed. | 
| FireEyeHelix.Alert.Confidence | String | The Helix confidence level of the alert. | 
| FireEyeHelix.Alert.Description | String | The description of the alert. | 
| FireEyeHelix.Alert.FirstEventTime | Date | The time that the first event occurred. | 
| FireEyeHelix.Alert.LastEventTime | Date | The time that the last event occurred. | 
| FireEyeHelix.Alert.ExternalIP | String | The external IP addresses for the alert. | 
| FireEyeHelix.Alert.InternalIP | String | The internal IP addresses for the alert. | 
| FireEyeHelix.Alert.Message | String | The message of the alert. | 
| FireEyeHelix.Alert.Products | String | The source of the alert. | 
| FireEyeHelix.Alert.Risk | String | The risk of the events in the alert. | 
| FireEyeHelix.Alert.Severity | String | The severity of the events in the alert. | 
| FireEyeHelix.Alert.State | String | The state of the alert. Can be "Open", "Suppressed", "Closed", or "Reopened". | 
| FireEyeHelix.Alert.Tag | String | The tag of the alert. | 
| FireEyeHelix.Alert.Type | String | The alert type. | 
| FireEyeHelix.Alert.Count | String | The number of alerts. | 


##### Command Example

```
!fireeye-helix-list-alerts page_size=2
```

##### Human Readable Output

##### FireEye Helix - List alerts:
##### Page 1/58
ID|Name|Description|State|Severity|
|---|---|---|---|---|
| 123 | HX | FireEye HX detected and quarantined malware on this system. | Open | Medium |
| 32 | HX | This rule alerts on IOC. | Open | Medium |

### Get alert details by ID
---
Returns alert details, by alert ID.

##### Base Command
`fireeye-helix-get-alert-by-id`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the alert. | Required | 
| headers | A comma-separated list (no spaces) of output values to display in the command result. For example, "ID", "Name" ,or "Hostname". | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Alert.ID | Number | The primary ID of the alert. | 
| FireEyeHelix.Alert.AlertTypeID | Number | The ID of the alert type. | 
| FireEyeHelix.Alert.AlertTypeName | String | The name of the alert type. | 
| FireEyeHelix.Alert.AssigneeID | String | The ID of the alert assignee. | 
| FireEyeHelix.Alert.AssigneeName | String | The Assignee display name. | 
| FireEyeHelix.Alert.CreatorID | String | The ID of the user who created the alert. | 
| FireEyeHelix.Alert.CreatorName | String | The name of the user who created the alert. | 
| FireEyeHelix.Alert.UpdaterID | String | The name of the user who updated the alert. | 
| FireEyeHelix.Alert.UpdaterName | String | The name of the user who updated the alert. | 
| FireEyeHelix.Alert.CreatedTime | Date | The time the alert was created. | 
| FireEyeHelix.Alert.ModifiedTime | Date | The time the alert was last modified. | 
| FireEyeHelix.Alert.ProcessPath | String | The path of the process. | 
| FireEyeHelix.Alert.Confidence | String | The Helix confidence level of the alert. | 
| FireEyeHelix.Alert.SHA1 | String | The SHA1 hash of the file. | 
| FireEyeHelix.Alert.MD5 | String | The MD5 hash of the file. | 
| FireEyeHelix.Alert.Hostname | String | The hostname of the alert. | 
| FireEyeHelix.Alert.PID | Number | The process ID. | 
| FireEyeHelix.Alert.Size | Number | The size of the process in bytes. | 
| FireEyeHelix.Alert.Virus | String | The virus name. | 
| FireEyeHelix.Alert.Result | String | The result of the alert. | 
| FireEyeHelix.Alert.MalwareType | String | THe malware type. | 
| FireEyeHelix.Alert.Filename | String | The name of the file that contains the virus. | 
| FireEyeHelix.Alert.RegPath | String | The registry key path. | 
| FireEyeHelix.Alert.EventTime | Date | The time that the event occurred. | 
| FireEyeHelix.Alert.IOCNames | String | The Indicator of Compromise names. | 
| FireEyeHelix.Alert.Process | String | The name of the process that created the event. | 
| FireEyeHelix.Alert.ParentProcess | String | The name of the parent process to the process that created the event. | 
| FireEyeHelix.Alert.SourceIPv4 | String | The source IP address of the event (IPv4). | 
| FireEyeHelix.Alert.SourceIPv6 | String | THe source IP address of the event (IPv6). | 
| FireEyeHelix.Alert.DestinationIPv4 | String | The destination IP address of the event (IPv4). | 
| FireEyeHelix.Alert.DestinationIPv6 | String | The destination IP address of the event (IPv6). | 
| FireEyeHelix.Alert.DestinationPort | String | The destination port of the event. | 
| FireEyeHelix.Alert.URI | String | The URI address that created the event. | 
| FireEyeHelix.Alert.HttpMethod | String | The HTTP method of the request that was called. | 
| FireEyeHelix.Alert.Domain | String | The domain of the URI that created the event. | 
| FireEyeHelix.Alert.UserAgent | String | The user agent related to the event. | 
| FireEyeHelix.Alert.EventsCount | Number | The number of events in the alert. | 
| FireEyeHelix.Alert.NotesCount | Number | The number of notes in the alert. | 
| FireEyeHelix.Alert.ClosedState | String | The state the alert is in regards to it being closed. | 
| FireEyeHelix.Alert.ClosedReason | String | The reason the alert was closed. | 
| FireEyeHelix.Alert.Confidence | String | The Helix confidence level of the alert. | 
| FireEyeHelix.Alert.Description | String | The description of the alert. | 
| FireEyeHelix.Alert.FirstEventTime | Date | The time that the first event occurred. | 
| FireEyeHelix.Alert.LastEventTime | Date | The time that the last event occurred. | 
| FireEyeHelix.Alert.ExternalIP | String | The external IP addresses for the alert. | 
| FireEyeHelix.Alert.InternalIP | String | The internal IP addresses for the alert. | 
| FireEyeHelix.Alert.Message | String | The message of the alert. | 
| FireEyeHelix.Alert.Products | String | The source of the alert. | 
| FireEyeHelix.Alert.Risk | String | The risk of the events in the alert. | 
| FireEyeHelix.Alert.Severity | String | The severity of the events in the alert. | 
| FireEyeHelix.Alert.State | String | The state of the alert. Can be "Open", "Suppressed", "Closed", or "Reopened". | 
| FireEyeHelix.Alert.Tag | String | The tag of the alert. | 
| FireEyeHelix.Alert.Type | String | The alert type. | 
| FireEyeHelix.Alert.Count | String | The number of alerts. | 

##### Command Example

```
!fireeye-helix-get-alert-by-id id=3232
```

##### Human Readable Output

##### FireEye Helix - Alert 3232:
|AlertTypeID|ClosedState|Confidence|CreatedTime|CreatorID|CreatorName|Description|EventsCount|FileName|FirstEventTime|Hostname|ID|LastEventTime|MD5|MalwareType|Message|ModifiedTime|Name|NotesCount|PID|ProcessPath|Products|Result|Risk|SHA1|Severity|State|Tags|Type|UpdaterID|UpdaterName|Virus|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1793 | Unknown | high | 2019-03-30T19:40:16.132456Z | id | System User | FireEye HX detected and quarantined malware on this system. | 2 | c:\users\demon\appdata\local\temp | 2019-03-30T14:07:34.132456ZZ | helix<span></span>.apps.fireeye<span></span>.com | 123 | 2019-03-31T14:08:07.132456ZZ | md5 | malware | FIREEYE H | 2019-10-20T12:35:02.132456Z | HX | 0 | 11 | c:\windows\microsoft<span></span>.net\framework\v7.0.30319\csc.exe | hx: 2 | quarantined | Medium | sha1 | Medium | Open | fireeye | fireeye_rule | id | George | gen:variant.ursu |

### Create an alert note
---
Creates an alert note.

##### Base Command
`fireeye-helix-alert-create-note`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert for which the note is being created. | Required | 
| note | The note to add to the alert. | Required | 


##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Note.ID | Number | The ID of the note. | 
| FireEyeHelix.Note.CreatedTime | Date | The time the note was created. | 
| FireEyeHelix.Note.UpdatedTime | Date | The time the note was updated. | 
| FireEyeHelix.Note.Message | String | The message of the note. | 
| FireEyeHelix.Note.CreatorID | String | The ID of the note creator. | 
| FireEyeHelix.Note.CreatorName | String | The name of the note creator. | 
| FireEyeHelix.Note.AlertID | Number | The ID of the related alert. | 

##### Command Example
```
!fireeye-helix-alert-create-note note=This is a note test alert_id=3232
```

##### Human Readable Output
##### FireEye Helix - Created Note for Alert 3232:
|ID|Creator Name|Message|Created Time|
|---|---|---|---|
| 9 | George | This is a note test | 2019-10-28T07:41:30.396000Z |

### List event alerts
---
Lists events alerts for a specific alert.

##### Base Command

`fireeye-helix-get-events-by-alert`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID for which to get events. | Required | 
| headers | A comma-separated list (no spaces) of output values to display in the command result. For example, "ID", "Type" , "SourceIPv4". | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Event.ID | String | The ID of the event. | 
| FireEyeHelix.Event.Type | String | The event type. | 
| FireEyeHelix.Event.Result | String | The result of the event. | 
| FireEyeHelix.Event.MatchedAt | Date | The time that the event was matched. | 
| FireEyeHelix.Event.Confidence | String | The confidence of the event. Can be "low", "medium", or "high". | 
| FireEyeHelix.Event.Status | String | The status of the event. | 
| FireEyeHelix.Event.EventTime | Date | The time that the event occurred. | 
| FireEyeHelix.Event.DetectedRuleID | String | The ID of the detected rule. | 
| FireEyeHelix.Event.PID | String | The ID of the process. | 
| FireEyeHelix.Event.Process | String | The process details. | 
| FireEyeHelix.Event.ProcessPath | String | The process path. | 
| FireEyeHelix.Event.FileName | String | The name of the file affected by the event. | 
| FireEyeHelix.Event.FilePath | String | The path of the the file affected by the event. | 
| FireEyeHelix.Event.DeviceName | String | The name of the device. | 
| FireEyeHelix.Event.Size | String | The size of the file (in bytes) that created the event. | 
| FireEyeHelix.Event.Virus | String | The virus that was detected in the event. | 
| FireEyeHelix.Event.MalwareType | String | The malware type of the virus that was detected. | 
| FireEyeHelix.Event.CreatedTime | Date | The time that the event was created. | 
| FireEyeHelix.Event.Class | String | The event class. | 
| FireEyeHelix.Event.MD5 | String | The MD5 hash of the affected file. | 
| FireEyeHelix.Event.SHA1 | String | The SHA1 hash of the affected file. | 
| FireEyeHelix.Event.Protocol | String | The protocol used in the event. | 
| FireEyeHelix.Event.SourceIPv4 | String | The IPv4 address of the event source. | 
| FireEyeHelix.Event.SourceIPv6 | String | The IPv6 address of the event source. | 
| FireEyeHelix.Event.SourcePort | String | The port of the event source address. | 
| FireEyeHelix.Event.SourceLongitude | String | The longitude of the event source address. | 
| FireEyeHelix.Event.SourceLatitude | String | The latitude of the event source address. | 
| FireEyeHelix.Event.DestinationIPv4 | String | The IPv4 address of the event destination. | 
| FireEyeHelix.Event.DestinationIPv6 | String | The IPv6 address of the event destination. | 
| FireEyeHelix.Event.DestinationPort | String | The port of the event destination address. | 
| FireEyeHelix.Event.ReportTime | Date | The time that the event was reported. | 
| FireEyeHelix.Event.FalsePositive | String | Whether the event is a false positive. | 
| FireEyeHelix.Event.Domain | String | The domain of the recipient. | 
| FireEyeHelix.Event.From | String | The source email address. | 
| FireEyeHelix.Event.SourceDomain | String | The domain of the host that created the event. | 
| FireEyeHelix.Event.SourceISP | String | The ISP of the source of the event. | 
| FireEyeHelix.Event.DestinationISP | String | The ISP of the destination of the event. | 
| FireEyeHelix.Event.To | String | The destination email address. | 
| FireEyeHelix.Event.Attachment | Unknown | The email attachment. | 
| FireEyeHelix.Event.Count | Number | The total number of events. | 

##### Command Example

```
!fireeye-helix-get-events-by-alert alert_id=3232
```

##### Human Readable Output

##### FireEye Helix - Events for alert 3232:
|Class|Detected Rule ID|Event Time|False Positive|ID|MD5|Matched At|PID|Process|Process Path|Report Time|Result|Type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fireeye_hx_alert | 99 | 2019-09-13T06:51:59.000Z | false | 101 | md5 | 2019-08-11t06:51:40.000z | 404 | net1 | c:\windows\system32\et1.exe | 2019-09-13t06:53:08.000 | alert | processevent |

### Get a specific alert
---
Retrieves a specific alert from an helix endpoint.

##### Base Command
`fireeye-helix-get-endpoints-by-alert`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of an alert. | Required | 
| offset | The offset to the result. The default is 0. | Optional | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Endpoint.ID | Number | The ID of the endpoint. | 
| FireEyeHelix.Endpoint.CustomerID | String | The ID of the customer. | 
| FireEyeHelix.Endpoint.DeviceID | String | The ID of the device. | 
| FireEyeHelix.Endpoint.Domain | String | The domain of the endpoint. | 
| FireEyeHelix.Endpoint.Hostname | String | The hostname of the endpoint. | 
| FireEyeHelix.Endpoint.MACAddress | String | The MAC address of the endpoint. | 
| FireEyeHelix.Endpoint.OS | String | The operating system of the endpoint. | 
| FireEyeHelix.Endpoint.IP | String | The IP address of the endpoint. | 
| FireEyeHelix.Endpoint.UpdatedTime | Date | The time the endpoint was last updated. | 
| FireEyeHelix.Endpoint.ContainmentState | String | The containment state of the endpoint. | 
| FireEyeHelix.Endpoint.Count | Number | The total number of endpoints. | 

##### Command Example

```
!fireeye-helix-get-endpoints-by-alert alert_id=3232 offset=0
```

##### Human Readable Output
##### FireEye Helix - Endpoints for alert 3232:

|ID|Device ID|Hostname|IP|MAC Address|Updated Time|
|---|---|---|---|---|---|
| 191 | device_id | Demisto | primary_ip_address | mac_address | updated_at |

### Get alert cases
---
Returns cases of an alert.

##### Base Command
`fireeye-helix-get-cases-by-alert`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of an alert. | Required | 
| page_size | The number of results to return per page. | Optional | 
| offset | The initial index from which to return the results. | Optional | 
| order_by | The field by which to order the results. | Optional | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Case.AlertsCount | Number | The number of alerts related to the case. | 
| FireEyeHelix.Case.AssigneeID | String | The ID of the assignee. | 
| FireEyeHelix.Case.AssigneeName | String | The name of the assignee. | 
| FireEyeHelix.Case.CreatorID | String | The ID of the case creator. | 
| FireEyeHelix.Case.CreatorName | String | The name of the case creator. | 
| FireEyeHelix.Case.UpdaterID | String | The ID of the user who last updated the case. | 
| FireEyeHelix.Case.UpdaterName | String | The name of the user who last updated the case. | 
| FireEyeHelix.Case.CreatedTime | Date | The time that the case was created. | 
| FireEyeHelix.Case.ModifiedTime | Date | The time that the case was last modified. | 
| FireEyeHelix.Case.Description | String | The case description. | 
| FireEyeHelix.Case.EventsCount | Number | The number of events in the case. | 
| FireEyeHelix.Case.ID | Number | The ID of the case. | 
| FireEyeHelix.Case.InfoLinks | Unknown | The informational or reference links. | 
| FireEyeHelix.Case.Name | String | The name of the case. | 
| FireEyeHelix.Case.NotesCount | Number | The number of notes in the case. | 
| FireEyeHelix.Case.Priority | String | Provides an indication of the order in which the case should be examined as compared to other cases. Can be, "Critical", "High", "Medium", or "Low". | 
| FireEyeHelix.Case.PriorityOrder | Number | Provides an indication of the order in which the case should be examined as compared to other cases. Can be "4", "3", "2", or "1". | 
| FireEyeHelix.Case.Severity | Number | The potential impact that the case could have on the organization if it is a true positive. This is calculated based on the risk of the alert. | 
| FireEyeHelix.Case.State | String | The state of the case. | 
| FireEyeHelix.Case.Status | String | The cases with the following statuses are considered open, "Declared", "Scoped", or "Contained".
Cases with the following statuses are considered closed, "Recovered", or "Improved". | 
| FireEyeHelix.Case.Tags | Unknown | The tags of the case. | 
| FireEyeHelix.Case.TotalDaysUnresolved | Number | The number of days the case has been unresolved. | 
| FireEyeHelix.Case.Count | Number | The total number of cases. | 

##### Command Example
```
!fireeye-helix-get-cases-by-alert alert_id=3232 offset=0 page_size=1
```

##### Human Readable Output
##### FireEye Helix - Cases for alert 3232:
|ID|Name|Priority|Severity|State|Status|ModifiedTime|
|---|---|---|---|---|---|---|
| 35 | demisto test case | Critical | 10 | Testing | Declared | updated_at |


### Get lists
---
Returns lists.

##### Base Command
`fireeye-helix-get-lists`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | The number of results to return per page. | Optional | 
| offset | The initial index from which to return the results. | Optional | 
| usage | The multiple values. May be separated by commas. | Optional | 
| created_at | The date that the list was created. | Optional | 
| description | The description of the list. | Optional | 
| is_active | Whether the list is active. Can be, "true" or "false". | Optional | 
| is_internal | Whether the list is internal. Can be, "true" or "false". | Optional | 
| is_protected | Whether the list is protected. Can be, "true" or "false". | Optional | 
| name | The name of the list. | Optional | 
| short_name | The short name of the list. | Optional | 
| type | The list type. | Optional | 
| updated_at | The time the list was last updated. | Optional | 
| order_by | The field by which to order the results. | Optional | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.List.ID | Number | The list of IDs. | 
| FireEyeHelix.List.Description | Number | The list's description. | 
| FireEyeHelix.List.ShortName | String | The short name of the list. | 
| FireEyeHelix.List.Name | String | The name of the list. | 
| FireEyeHelix.List.ContentTypes | String | The content types of the list. Can be, "Email", "FQDN", "IPv4", "Ipv6", "SHA1", "MD5", or "Misc". | 
| FireEyeHelix.List.CreatorID | String | The ID of the creator. | 
| FireEyeHelix.List.CreatorName | String | The name of the creator. | 
| FireEyeHelix.List.UpdatedByID | String | The ID of the user who last updated the list. | 
| FireEyeHelix.List.CreatedTime | Date | The time that the rule was created. | 
| FireEyeHelix.List.UpdatedTime | Date | The time that the rule was last updated. | 
| FireEyeHelix.List.Type | String | The list type. Can be "Default", "Analytics Whitelist", or "Intel Matching". | 
| FireEyeHelix.List.UpdatedByName | String | The user who last updated the list. | 
| FireEyeHelix.List.Internal | Boolean | Whether the list is internal. Can be "true" or "false". | 
| FireEyeHelix.List.Protected | Boolean | Whether the list is protected. Can be "true" or "false". | 
| FireEyeHelix.List.Active | Unknown | Whether the list is active. Can be "true" or "false". | 
| FireEyeHelix.List.Count | Number | The total number of lists. | 

### Get a specific list by ID
---
Returns a specific list by list ID.

##### Base Command
`fireeye-helix-get-list-by-id`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the list. | Required | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.List.ID | Number | The ID of the list. | 
| FireEyeHelix.List.Description | Number | The list description. | 
| FireEyeHelix.List.ShortName | String | The short name of the list. | 
| FireEyeHelix.List.Name | String | The name of the list. | 
| FireEyeHelix.List.ContentTypes | String | The content types of the list. Can be "Email", "FQDN", "IPv4", "Ipv6", "SHA1", "MD5", or "Misc". | 
| FireEyeHelix.List.CreatorID | String | The ID of the creator. | 
| FireEyeHelix.List.CreatorName | String | The name of the creator. | 
| FireEyeHelix.List.UpdatedByID | String | The ID of the user who last updated the list. | 
| FireEyeHelix.List.CreatedTime | Date | The time that the rule was created. | 
| FireEyeHelix.List.UpdatedTime | Date | The time that the rule was last updated. | 
| FireEyeHelix.List.Type | String | The list type. Can be "Default", "Analytics Whitelist", or "Intel Matching". | 
| FireEyeHelix.List.UpdatedByName | String | The name of the user who last updated the list. | 
| FireEyeHelix.List.Internal | Boolean | Whether the list is internal. Can be "true" or "false". | 
| FireEyeHelix.List.Protected | Boolean | Whether the list is protected. Can be "true" or "false". | 
| FireEyeHelix.List.Active | Unknown | Whether the list is active. Can be "true" or "false". | 

### Create a list
---
Creates a list.

##### Base Command
`fireeye-helix-create-list`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the list. | Required | 
| short_name | The short name of the list. | Optional | 
| is_internal | Whether the list is internal. Can be "true" or "false". | Optional | 
| is_active | Whether the list is active. Can be "true" or "false". | Optional | 
| is_protected | Whether the list is protected. Can be "true" or "false". | Optional | 
| usage | A comma-separated list of list uses. | Optional | 
| is_hidden | Whether the list is hidden. Can be "true" or "false". | Optional | 
| type | The list type. | Optional | 
| description | The description of the list. | Optional | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.List.ID | Number | The list ID. | 
| FireEyeHelix.List.Description | Number | The list description. | 
| FireEyeHelix.List.ShortName | String | The sShort name of the list. | 
| FireEyeHelix.List.Name | String | The name of the list. | 
| FireEyeHelix.List.ContentTypes | String | The content types of the list. Can be "Email", "FQDN", "IPv4", "IPv6", "SHA1", "MD5", or "Misc". | 
| FireEyeHelix.List.CreatorID | String | The ID of the list creator. | 
| FireEyeHelix.List.CreatorName | String | The name of the list creator. | 
| FireEyeHelix.List.UpdatedByID | String | The ID of the user who last updated the list. | 
| FireEyeHelix.List.CreatedTime | Date | The time that the rule was created. | 
| FireEyeHelix.List.UpdatedTime | Date | The time that the rule was last updated. | 
| FireEyeHelix.List.Type | String | The list type. Can be "Default", "Analytics Whitelist", or "Intel Matching". | 
| FireEyeHelix.List.UpdatedByName | Unknown | The name of the user who last updated the list. | 
| FireEyeHelix.List.Internal | Boolean | Whether the list is internal. Can be "true" or "false". | 
| FireEyeHelix.List.Protected | Boolean | Whether the list is protected. Can be "true" or "false". | 
| FireEyeHelix.List.Active | Unknown | Whether the list is active. Can be "true" or "false". | 

### Update a list
---
Updates an existing list.

##### Base Command
`fireeye-helix-update-list`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the list to update. | Optional | 
| short_name | The short name of the list. | Optional | 
| is_internal | Whether the list is internal. Can be "true" or "false". | Optional | 
| is_active | Whether the list is active. Can be "true" or "false". | Optional | 
| is_protected | Whether the list is protected. Can be "true" or "false". | Optional | 
| usage | A comma-separated list of list uses. | Optional | 
| is_hidden | Whether the list is hidden. Can be "true" or "false". | Optional | 
| type | The list type. | Optional | 
| description | The description of the list. | Optional | 
| list_id | The ID of the list. | Required | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.List.ID | Number | The ID of the list. | 
| FireEyeHelix.List.Description | Number | The list description. | 
| FireEyeHelix.List.ShortName | String | The short name of the list. | 
| FireEyeHelix.List.Name | String | The name of the list. | 
| FireEyeHelix.List.ContentTypes | String | The content types of the list. Can be "Email", "FQDN", "IPv4", "IPv6", "SHA1", "MD5", or "Misc". | 
| FireEyeHelix.List.CreatorID | String | The ID of the creator. | 
| FireEyeHelix.List.CreatorName | String | The name of the creator. | 
| FireEyeHelix.List.UpdatedByID | String | The ID of the user who last updated the list. | 
| FireEyeHelix.List.CreatedTime | Date | The time that the rule was created. | 
| FireEyeHelix.List.UpdatedTime | Date | The time that the rule was last updated. | 
| FireEyeHelix.List.Type | String | The list type. Can be "Default", "Analytics Whitelist", or "Intel Matching". | 
| FireEyeHelix.List.UpdatedByName | Unknown | The name of the user who last updated the list. | 
| FireEyeHelix.List.Internal | Boolean | Whether the list is internal. Can be "true" or "false". | 
| FireEyeHelix.List.Protected | Boolean | Whether the list is protected. Can be "true" or "false". | 
| FireEyeHelix.List.Active | Unknown | Whether the list is active. Can be "true" or "false". |

### Delete a list
---
Deletes a single list by list ID.

##### Base Command
`fireeye-helix-delete-list`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The ID of the list to delete. | Required | 

##### Context Output
There is no context output for this command.

### Fetch all sensors
---
Fetches all sensors.
##### Base Command
`fireeye-helix-list-sensors`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | The maximum number of results to return per page. | Optional | 
| offset | The initial index from which to return the results. | Optional | 
| hostname | The host name of the sensor. | Optional | 
| status | The status of the sensor. | Optional | 

##### Context Output
There is no context output for this command.

### Get all rules
---
Returns all rules.

##### Base Command
`fireeye-helix-list-rules`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | The maximum number of results to return per page. | Optional | 
| offset | The initial index from which to return the results. | Optional | 
| sort | A comma-separated list of field names by which to sort the results. For example, “createDate” or "-updateDate,riskOrder" | Optional | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Rule.ID | String | The rule ID. | 
| FireEyeHelix.Rule.RulePack | String | The rule package version. | 
| FireEyeHelix.Rule.Description | String | The rule description. | 
| FireEyeHelix.Rule.Internal | Boolean | Whether the rule is internal. Can be "true" or "false". | 
| FireEyeHelix.Rule.Deleted | Boolean | Whether the rule was deleted. Can be "true" or "false". | 
| FireEyeHelix.Rule.Enabled | Boolean | Whether the rule is enabled. Can be "true" or "false". | 
| FireEyeHelix.Rule.Supported | Boolean | Whether the rule is supported. Can be "true" or "false". | 
| FireEyeHelix.Rule.CreatorID | String | The ID of the rule creator. | 
| FireEyeHelix.Rule.CreatorName | String | The name of the rule creator. | 
| FireEyeHelix.Rule.UpdatedByID | String | The ID of the user who updated the rule. | 
| FireEyeHelix.Rule.UpdatedByName | String | The name of the user who updated the rule. | 
| FireEyeHelix.Rule.Risk | String | The risk to your environment when an event matches this rule. Can be "low", "medium", "high", or "critical". | 
| FireEyeHelix.Rule.Confidence | String | The confidence that indicates how likely it is that the rule will detect events that correspond to the type of activity anticipated. (The likelihood that the rule will produce true positives). Confidence and Severity combine to form the risk attribute of the alert. Can be "low", "medium", or "high". | 
| FireEyeHelix.Rule.Severity | String | The severity that indicates how much of an impact a hit with this rule could have on an organization if
verified to be a true positive. Confidence and Severity combine to form the risk attribute of the alert. Can be "low", "medium", or "high". | 
| FireEyeHelix.Rule.Tags | String | The tags of the rule. | 
| FireEyeHelix.Rule.Type | String | The type of the rule. | 

##### Command Example
```
!fireeye-helix-list-rules offset=1
```

##### Human Readable Output
##### FireEye Helix - List rules:
|ID|Type|Description|Risk|Confidence|Severity|Enabled|
|---|---|---|---|---|---|---|
| 1.1.1 | alert | demisto | Medium | Medium | Medium | true |

### Edit an existing rule
---
Modifies an existing rule.

##### Base Command
`fireeye-helix-edit-rule`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enabled | Whether the rule is enabled. Can be "true" or "false". | Optional | 
| rule_id | The ID of the rule. | Required | 

##### Context Output
There is no context output for this command.

##### Command Example
```
!fireeye-helix-edit-rule rule_id=1.1.1 enabled=true
```

##### Human Readable Output
##### FireEye Helix - Successfully updated rule 1.1.1:
|ID|Type|Description|Risk|Confidence|Severity|
|---|---|---|---|---|---|
| 1.1.1 | alert | demisto | Medium | Medium | Medium |

### Get all notes related to an alert
---
Returns all notes related to an alert.

##### Base Command
`fireeye-helix-alert-get-notes`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert. | Required | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelix.Note.ID | Number | The ID of the note. | 
| FireEyeHelix.Note.CreatedTime | Date | The time that the note was created. | 
| FireEyeHelix.Note.UpdatedTime | Date | The time that the note was updated. | 
| FireEyeHelix.Note.Message | String | The message of the note. | 
| FireEyeHelix.Note.CreatorID | String | The ID of the note creator. | 
| FireEyeHelix.Note.CreatorName | String | The name of the note creator. | 
| FireEyeHelix.Note.AlertID | Number | The ID of the related alert. | 
| FireEyeHelix.Note.Count | Number | The total number of notes for the alert. | 

##### Command Example
```
!fireeye-helix-alert-get-notes id=3232
```

##### Human Readable Output
##### FireEye Helix - Notes for Alert None:
|ID|Creator Name|Message|Created Time|
|---|---|---|---|
| 9 | George | This is a note test | 2019-10-28T07:41:30.396000Z |
| 91 | George | What a great note this is | 2019-10-24T13:52:19.021299Z |

### Delete a note's alert
---
Deletes a note's alert.

##### Base Command
`fireeye-helix-alert-delete-note`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to delete. | Required | 
| note_id | The ID of the note. | Required | 

##### Context Output
There is no context output for this command.

### Preform a search
---
Executes a search in FireEye Helix using MQL.

##### Base Command
`fireeye-helix-search`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start time of the event in the format yyyy-mm-dd or yyyy-mm. | Optional | 
| end | The end time of the event in the format yyyy-mm-dd or yyyy-mm. | Optional | 
| page_size | The maximum number of results to return. | Optional | 
| offset | The offset of the result. | Optional | 
| groupby | Returns the unique values for the specified field and groups them based on the specified frequency. For example, `groupby="srcipv4 5 100"` will group the top five srcipv4 addresses that have at least 100 occurrences. Supports comma-separated values. | Optional | 
| sort_by | The field by which to sort the results. | Optional | 
| sort_order | The order of the results sorted by the `sort_by` argument. Can be "asc" for ascending, or "desc" for descending. The default is "desc". | Optional | 
| query | The query to execute. This is the search clause in an MQL. | Required | 
| limit | The number of events to search. | Optional | 
| headers | A comma-separated list (no spaces) of output values to display in the command result. For example, "ID", "Type", or "SourceIPv4". | Optional | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixSearch.Result.ID | String | The ID of the event. | 
| FireEyeHelixSearch.Result.Type | String | The event type. | 
| FireEyeHelixSearch.Result.Result | String | The event result. | 
| FireEyeHelixSearch.Result.MatchedAt | Date | The time that the event was matched. | 
| FireEyeHelixSearch.Result.Confidence | String | The confidence of the event. Can be "low", "medium", or "high". | 
| FireEyeHelixSearch.Result.Status | String | The status of the event. | 
| FireEyeHelixSearch.Result.EventTime | Date | The time that the event occurred. | 
| FireEyeHelixSearch.Result.DetectedRuleID | String | The ID of the detected rule. | 
| FireEyeHelixSearch.Result.PID | String | The process ID. | 
| FireEyeHelixSearch.Result.Process | String | The process details. | 
| FireEyeHelixSearch.Result.ProcessPath | String | The process path. | 
| FireEyeHelixSearch.Result.FileName | String | The name of the file affected by the event. | 
| FireEyeHelixSearch.Result.FilePath | String | The path of the the file affected by the event. | 
| FireEyeHelixSearch.Result.DeviceName | String | The device name. | 
| FireEyeHelixSearch.Result.Size | String | The size of the file (in bytes) that created the event. | 
| FireEyeHelixSearch.Result.Virus | String | The virus that was detected in the event. | 
| FireEyeHelixSearch.Result.MalwareType | String | The malware type of the virus that was detected. | 
| FireEyeHelixSearch.Result.CreatedTime | Date | The time that the event was created. | 
| FireEyeHelixSearch.Result.Class | String | The event class. | 
| FireEyeHelixSearch.Result.MD5 | String | The MD5 hash of the affected file. | 
| FireEyeHelixSearch.Result.SHA1 | String | The SHA1 hash of the affected file. | 
| FireEyeHelixSearch.Result.Protocol | String | The protocol used in the event. | 
| FireEyeHelixSearch.Result.SourceIPv4 | String | The IPv4 address of the event source. | 
| FireEyeHelixSearch.Result.SourceIPv6 | String | The IPv6 address of the event source. | 
| FireEyeHelixSearch.Result.SourcePort | String | The port of the event source address. | 
| FireEyeHelixSearch.Result.SourceLongitude | String | The longitude of the event source address. | 
| FireEyeHelixSearch.Result.SourceLatitude | String | The latitude of the event source address. | 
| FireEyeHelixSearch.Result.DestinationIPv4 | String | The IPv4 address of the event destination. | 
| FireEyeHelixSearch.Result.DestinationIPv6 | String | The IPv6 address of the event destination. | 
| FireEyeHelixSearch.Result.DestinationPort | String | The port of the event destination address. | 
| FireEyeHelixSearch.Result.ReportTime | Date | The time that the event was reported. | 
| FireEyeHelixSearch.Result.FalsePositive | String | Whether the event is a false positive. | 
| FireEyeHelixSearch.Result.Domain | String | The domain of the recipient. | 
| FireEyeHelixSearch.Result.From | String | The source email address. | 
| FireEyeHelixSearch.Result.SourceDomain | String | The domain of the host that created the event. | 
| FireEyeHelixSearch.Result.SourceISP | String | The ISP of the source of the event. | 
| FireEyeHelixSearch.Result.DestinationISP | String | The ISP of the destination of the event. | 
| FireEyeHelixSearch.Result.To | String | The destination email address. | 
| FireEyeHelixSearch.Result.Attachment | Unknown | The email attachment. | 
| FireEyeHelixSearch.MQL | String | The MQL query that created the result. | 
| FireEyeHelixSearch.GroupBy | Unknown | The group by values. | 
| FireEyeHelixSearch.GroupBy.DocCount | Number | The number of matches for the group. | 
| FireEyeHelixSearch.Result.RcpTo | String | The recipient email address. | 
| FireEyeHelixSearch.Result.InReplyTo | String | The reply email address. | 

##### Command Example
```
!fireeye-helix-search query=domain:google.com start="4 days ago" groupby=subject limit=1 page_size=2
```

##### Human Readable Output
##### FireEye Helix - Search result for domain:google.com and meta_ts>=2019-10-25T09:07:43.810Z {page_size:2 offset:1 limit:1} | groupby subject sep=`|%$,$%|`
|Class|Domain|Event Time|From|ID|In Reply To|Source Domain|Source I Pv 4|Source ISP|Source Latitude|Source Longitude|Status|To|Type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fireeye_etp | mx.google<span></span>.com | 2019-10-28T10:43:11.000Z | de@demisto<span></span>.com | demisto | demisto | google<span></span>.com | 8.8.8.8 | google llc | 37.40599060058594 | -122.0785140991211 | delivered | demisto@demisto<span></span>.com | trace |
| fireeye_etp | gmr-mx.google<span></span>.com | 2019-10-29T05:08:39.000Z | dem@demisto<span></span>.com | demisto | demisto@demisto<span></span>.com | google<span></span>.com | 8.8.8.8 | google llc | 37.40599060058594 | -122.0785140991211 | delivered | demisto@demisto<span></span>.com | trace |

##### Group By
|subject|DocCount|
|---|---|
| google alert - gold | 3 |
| accepted: meeting | 1 |
| invitation: Declined | 1 |

### Add an item to a list
---
Adds an item to a list.

##### Base Command
`fireeye-helix-add-list-item`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The item type. Can be, "email", "fqdn", "ipv4", "ipv6", "md5", "misc", or "sha-1". | Required | 
| value | The item value. | Required | 
| list_id | The ID of the list. | Required | 
| risk | The risk of the item. Can be, "Low", "Medium", "High", or "Critical". | Optional | 
| notes | The item notes. | Optional | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixList.Item.ID | Number | The ID of the item. | 
| FireEyeHelixList.Item.Value | String | The value of the item. | 
| FireEyeHelixList.Item.Type | String | The type of the item. Can be "email", "fqdn", "ipv4", "ipv6", "md5", "misc", or "sha-1". | 
| FireEyeHelixList.Item.Risk | String | The risk of the item. Can be "Low", "Medium", "High", or "Critical". | 
| FireEyeHelixList.Item.Notes | String | The notes of the item. | 
| FireEyeHelixList.Item.ListID | String | The list ID with which the item is associated. | 

##### Command Example
```
!fireeye-helix-add-list-item list_id=3232 value=test type=misc risk=Low
```

##### Human Readable Output
##### FireEye Helix - List item 163 was added successfully to 3232
|ID|ListID|Notes|Risk|Type|Value|
|---|---|---|---|---|---|
| 163 | 3232 | test ok | Medium | misc | aTest list |

### Fetch list items
---
Fetches the items of a list.

##### Base Command
`fireeye-helix-get-list-items`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The ID of the list for which to fetch items. | Required | 
| offset | THe item offset. The default is 0. | Optional | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixList.Item.ID | Number | The ID of the item. | 
| FireEyeHelixList.Item.Value | String | The value of the item. | 
| FireEyeHelixList.Item.Type | String | The type of the item. Can be "email", "fqdn", "ipv4", "ipv6", "md5", "misc", or "sha-1". | 
| FireEyeHelixList.Item.Risk | String | The risk of the item. Can be "Low", "Medium", "High", or "Critical". | 
| FireEyeHelixList.Item.Notes | String | The notes of the item. | 
| FireEyeHelixList.Item.ListID | String | The list ID with which the item is associated. | 
| FireEyeHelixList.Item.Count | Number | The number of items in the list. | 

##### Command Example
```
!fireeye-helix-get-list-items list_id=3232 offset=0
```

##### Human Readable Output
##### FireEye Helix - List items for list 3232
|ID|ListID|Notes|Risk|Type|Value|
|---|---|---|---|---|---|
| 163 | 3232 |  | Low | misc | Test list |

### Update an item on a list 
---
Updates a single list item.

##### Base Command
`fireeye-helix-update-list-item`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The ID of the item to update. | Required | 
| type | The item type. Can be "email", "fqdn", "ipv4", "ipv6", "md5", "misc", or "sha-1". | Optional | 
| value | The value of the item. | Optional | 
| list_id | The ID of the list. | Required | 
| risk | The risk of the item. Can be "Low", "Medium", "High", or "Critical". | Optional | 
| notes | The notes of the item. | Optional | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixList.Item.ID | Number | The ID of the item. | 
| FireEyeHelixList.Item.Value | String | The value of the item. | 
| FireEyeHelixList.Item.Type | String | The item type. Can be "email", "fqdn", "ipv4", "ipv6", "md5", "misc", or "sha-1". | 
| FireEyeHelixList.Item.Risk | String |The risk of the item. Can be, "Low", "Medium", "High", or "Critical". | 
| FireEyeHelixList.Item.Notes | String | The notes of the item. | 
| FireEyeHelixList.Item.ListID | String | The list ID with which the item is associated. | 

##### Command Example
```
!fireeye-helix-update-list-item list_id=3232 value=test type=misc risk=Low item_id=163
```

##### Human Readable Output
##### FireEye Helix - List item 163 from list 3232 was updated successfully
|ID|ListID|Notes|Risk|Type|Value|
|---|---|---|---|---|---|
| 163 | 3232 | test ok | Medium | misc | aTest list |


### Remove an item from a list
---
Removes an item from a list.

##### Base Command
`fireeye-helix-remove-list-item`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The ID of the list from which to remove an item. | Required | 
| item_id | The ID of the item. | Required | 

##### Context Output
There is no context output for this command.

### Fetch archive search results
---
Fetches archive search results.

##### Base Command
`fireeye-helix-archive-search-get-results`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The ID of the search for which to return archive results. | Required | 
| headers | A comma-separated list of output values to display in the command result. For example, "ID", "Type", and "SourceIPv4". | Optional | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixSearch.Result.ID | String | The ID of the event. | 
| FireEyeHelixSearch.Result.Type | String | The type of the event. | 
| FireEyeHelixSearch.Result.Result | String | The result of the event. | 
| FireEyeHelixSearch.Result.MatchedAt | Date | The time that the event was matched. | 
| FireEyeHelixSearch.Result.Confidence | String | The confidence of the event. Can be "low", "medium", or "high". | 
| FireEyeHelixSearch.Result.Status | String | The status of the event. | 
| FireEyeHelixSearch.Result.EventTime | Date | The time that the event occurred. | 
| FireEyeHelixSearch.Result.DetectedRuleID | String | The ID of the detected rule. | 
| FireEyeHelixSearch.Result.PID | String | The ID of the process. | 
| FireEyeHelixSearch.Result.Process | String | The details of the process. | 
| FireEyeHelixSearch.Result.ProcessPath | String | The path of the process. | 
| FireEyeHelixSearch.Result.FileName | String | The name of the file affected by the event. | 
| FireEyeHelixSearch.Result.FilePath | String | The path of the the file affected by the event. | 
| FireEyeHelixSearch.Result.DeviceName | String | The name of the device. | 
| FireEyeHelixSearch.Result.Size | String | The size of the file (in bytes) that created the event. | 
| FireEyeHelixSearch.Result.Virus | String | The virus that was detected in the event. | 
| FireEyeHelixSearch.Result.MalwareType | String | The malware type of the virus that was detected. | 
| FireEyeHelixSearch.Result.CreatedTime | Date | The time that the event was created. | 
| FireEyeHelixSearch.Result.Class | String | The class of the event. | 
| FireEyeHelixSearch.Result.MD5 | String | The MD5 hash of the affected file. | 
| FireEyeHelixSearch.Result.SHA1 | String | The SHA1 hash of the affected file. | 
| FireEyeHelixSearch.Result.Protocol | String | The protocol used in the event. | 
| FireEyeHelixSearch.Result.SourceIPv4 | String | The IPv4 address of the event source. | 
| FireEyeHelixSearch.Result.SourceIPv6 | String | The IPv6 address of the event source. | 
| FireEyeHelixSearch.Result.SourcePort | String | The port of the event source address. | 
| FireEyeHelixSearch.Result.SourceLongitude | String | The longitude of the event source address. | 
| FireEyeHelixSearch.Result.SourceLatitude | String | The latitude of the event source address. | 
| FireEyeHelixSearch.Result.DestinationIPv4 | String | The IPv4 address of the event destination. | 
| FireEyeHelixSearch.Result.DestinationIPv6 | String | The IPv6 address of the event destination. | 
| FireEyeHelixSearch.Result.DestinationPort | String | The port of the event destination address. | 
| FireEyeHelixSearch.Result.ReportTime | Date | The time that the event was reported. | 
| FireEyeHelixSearch.Result.FalsePositive | String | Whether the event is a false positive. | 
| FireEyeHelixSearch.Result.Domain | String | The domain of the recipient. | 
| FireEyeHelixSearch.Result.From | String | The email address of the source. | 
| FireEyeHelixSearch.Result.SourceDomain | String | The domain of the host that created the event. | 
| FireEyeHelixSearch.Result.SourceISP | String | The ISP of the source of the event. | 
| FireEyeHelixSearch.Result.DestinationISP | String | The ISP of the destination of the event. | 
| FireEyeHelixSearch.Result.To | String | The destination email address. | 
| FireEyeHelixSearch.Result.Attachment | Unknown | The email attachment. | 
| FireEyeHelixSearch.MQL | String | The MQL query that created the result. | 
| FireEyeHelixSearch.GroupBy | Unknown | The group by values. | 
| FireEyeHelixSearch.GroupBy.DocCount | Number | The number of matches for the group. | 
| FireEyeHelixSearch.Result.RcpTo | String | The recipient email address. | 
| FireEyeHelixSearch.Result.InReplyTo | String | The reply email address. | 

##### Command Example
```
!fireeye-helix-archive-search-get-results search_id=82
```

##### Human Readable Output
##### FireEye Helix - Search result for domain:[google,com] | groupby eventtype sep=`|%$,$%|`
|Class|Domain|Event Time|From|ID|In Reply To|Source Domain|Source I Pv 4|Source ISP|Source Latitude|Source Longitude|Status|To|Type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fireeye_etp | domain<span></span>.com | 2019-10-06T10:48:13.000Z | squidward@demisto<span></span>.com | evenid | squidward squidward@demisto<span></span>.com |  | 8.8.8.8 |  | 51.8594 | -0.12574 | delivered | demisto@demisto<span></span>.com | trace |
| fireeye_etp | demisto<span></span>.com | 2019-10-06T11:02:01.000Z | squidward@demisto<span></span>.com | demisto | \"squidward\" &lt;fsquidward@demisto<span></span>.com&gt; | squidward<span></span>.com | 8.8.8.8 | squidward | 40.282958 | -75.19625 | delivered | squidward@demisto.com | trace |
| fireeye_etp | demisto<span></span>.com | 2019-10-06T11:02:18.000Z | squidward@demisto<span></span>.com | dwasdkffv | squidward &lt;squidward@demisto<span></span>.com&gt; | demisto<span></span>.com | 8.8.8.8 | demistos | 33.5 | -93.119 | delivered | squidward@demisto<span></span>.com | trace |
| fireeye_etp | demisto<span></span>.com | 2019-10-06T11:03:00.000Z | squidward@demisto<span></span>.com | 93730 | geroge &lt;hello@demisto<span></span>.com&gt; | demisto<span></span>.com | 8.8.8.8 | the demisto group | 33.770843 | -84.377 | delivered | squidward@demisto<span></span>.com | trace |

### Create an archive from a query
---
Creates an archive search from a query.


##### Base Command
`fireeye-helix-archive-search`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start time of the event in the format yyyy-mm-dd or yyyy-mm. | Optional | 
| end | The end time of the event in the format yyyy-mm-dd or yyyy-mm. | Optional | 
| offset | The offset of the result. | Optional | 
| groupby | The unique values for the specified field. This groups them based on the specified frequency. For example, `groupby="srcipv4 5 100"` will group the top five srcipv4 addresses that have at least 100 occurrences. Supports comma-separated values. | Optional | 
| sort_by | Sorts results by this field. | Optional | 
| sort_order | Controls the order of the results sorted by the `sort_by` argument. Can be "asc" for ascending, or "desc" for descending. The default is "desc". | Optional | 
| query | The query to execute. This is the search clause in an MQL. | Required | 
| limit | The number of events to search. | Optional | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixSearch.ID | Number | The ID of an archive search. | 
| FireEyeHelixSearch.PercentComplete | String | The percentage of the search that was completed. | 
| FireEyeHelixSearch.Query | String | The search query. | 
| FireEyeHelixSearch.State | String | The state of the search. | 

##### Command Example
```
!fireeye-helix-archive-search query=domain:google.com start="4 days ago" groupby=subject limit=1 offset=1
```

##### Human Readable Output
##### FireEye Helix - Successfully created archive search
|ID|Percent Complete|Query|State|
|---|---|---|---|
| 82 | 100.0 | domain:[google,com] \| groupby eventtype | completed |
| 83 | 100.0 | domain:[google] \| groupby eventtype | completed |

### Get the status of an archive search
---
Gets the status of an archive search.

##### Base Command
`fireeye-helix-archive-search-get-status`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The archive search's ID. | Required | 

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHelixSearch<span></span>.ID | Number | The archive search's ID. | 
| FireEyeHelixSearch.PercentComplete | String | The percentage of the search that was completed. | 
| FireEyeHelixSearch.Query | String | The search query. | 
| FireEyeHelixSearch.State | String | The state of the search. | 

##### Command Example
```!fireeye-helix-archive-search-get-status search_id=82,83```

##### Human Readable Output
##### FireEye Helix - Search status
|ID|Percent Complete|Query|State|
|---|---|---|---|
| 82 | 100.0 | domain:[google,com] \| groupby eventtype | completed |
| 83 | 100.0 | domain:[google,com] \| groupby eventtype | completed |
