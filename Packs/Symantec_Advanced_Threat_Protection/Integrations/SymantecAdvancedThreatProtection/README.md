Advanced protection capabilities from Symantec
This integration was integrated and tested with Symantec Advanced Threat Protection v3.0.

## Configure Symantec Advanced Threat Protection in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (i.e. https://host:port) |  | True |
| Client ID as generated in the ATP console |  | True |
| Password |  | True |
| Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
| Use system proxy settings | Use system proxy settings. | False |
| Incident data source |  | False |
| Maximum number of events per fetch. |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). Maximum is 30 days. |  | False |
| Query string for fetch incidents. For example - "updated&gt;='2020-06-06T15:39:55.616Z' and updated&lt;'2020-08-07T00:00:00.000Z' " |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### satp-appliances
***
Retrieve the appliances configured with the versions


#### Base Command

`satp-appliances`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ATPAppliance.appliance_id | unknown | ID of the ATP appliance | 
| ATPAppliance.appliance_name | unknown | Name of the ATP appliance | 
| ATPAppliance.software_version | unknown | Version of the ATP appliance | 
| ATPAppliance.appliance_time | unknown | Current time on the appliance in UTC | 
| ATPAppliance.role | unknown | The roles of the appliance | 


#### Command Example
``` !satp-appliances ```

#### Human Readable Output
|appliance_id|appliance_name|appliance_time|software_version|role|
|---|---|---|---|---|
| 56123234-132F-123344-C8EF-1234 | test-atd | 2021-11-11T05:52:20.063Z | 3.0.0-123 | endpoint, network scanner, management | 


### satp-command
***
Issue commands to endpoints managed by Symantec Endpoint Protection


#### Base Command

`satp-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The action to perform on the endpoints. Possible values are: isolate_endpoint, rejoin_endpoint, delete_endpoint_file. | Required | 
| targets | For isolate and rejoin a list of endpoint ids (array or comma-separated). For delete, array of objects, each with hash and device_uid attributes (supports comma-delimited hash:uid,hash:uid as well). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ATPCommand.ID | unknown | The ID of the executing command | 
| ATPCommand.Action | unknown | The requested action for the command | 


#### Command Example
``` !satp-command action=isolate_endpoint targets="123e4567-e89b-12d3-a456-426614174000"```

#### Human Readable Output

|ID|Action|
|---|---|
| 56123234-132F-123344-C8EF-1234 | isolate_endpoint |



### satp-command-state
***
Retrieve the command state


#### Base Command

`satp-command-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command | The command ID to retrieve state for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ATPCommand.ID | unknown | The ID of the executing command | 
| ATPCommand.Action | unknown | The requested action for the command | 
| ATPCommand.Status.target | unknown | The target for the state | 
| ATPCommand.Status.state | unknown | The state of the command | 
| ATPCommand.Status.error_code | unknown | Error code for the target | 
| ATPCommand.Status.message | unknown | Message for the target | 


#### Command Example
``` !satp-command-state command="command_id"" ```

#### Human Readable Output

#### Symantec ATP Command ID: command_id

|ID|Action|
|---|---|
| command_id | command_name |


### satp-command-cancel
***
Cancel the given command


#### Base Command

`satp-command-cancel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command | The command ID to cancel. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ATPCommand.ID | unknown | The ID of the executing command | 
| ATPCommand.ErrorCode | unknown | Error code for cancelling - 0 if successful | 
| ATPCommand.Message | unknown | Message for the cancellation | 


#### Command Example
``` !satp-command-cancel command=command_id ```

#### Symantec ATP Command Cancel

#### Symantec ATP Command ID: command_id

|ID|Action|ErrorCode|Message|
|---|---|---|---|
| command_id | command_name | 0 | Message for the cancellation


### satp-events
***
Accepts search requests over a specified time range and returns events that match the search condition. You must specify the time range using the start_time parameter and the end_time parameter (the maximum time range is 7 days). The time in the result schema and is typically the event creation time. This API supports search conditions (such as logical operators and special characters) to narrow the events to be retrieved. See examples at https://help.symantec.com/api-doc/atp_2.2/EN_US/#_events_query_api_example.


#### Base Command

`satp-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Specifies a search condition. See full details at https://help.symantec.com/api-doc/atp_2.2/EN_US/#_eventqueryrequest. | Optional | 
| start_time | ISO8601 date format - 2017-01-01T00:00:00.000Z. Also accepts milliseconds since epoch. | Optional | 
| end_time | ISO8601 date format - 2017-01-01T00:00:00.000Z. Also accepts milliseconds since epoch. | Optional | 
| limit | Maximum number of events to return. Default is 100 and max is 1000. Default is 100. | Optional | 
| next | Used for events cursoring. Retrieve the next batch of events. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ATPEvents.Total | unknown | Total number of results | 
| ATPEvents.Next | unknown | Next batch ID | 
| ATPEvents.Result.type_id | unknown | The unique identifier for an event type. | 
| ATPEvents.Result.uuid | unknown | The unique id for this event | 
| ATPEvents.Result.message | unknown | Human-readable event message or description of the event | 
| ATPEvents.Result.severity_id | unknown | Severity between 1 \(info\) and 6 \(fatal\). | 
| ATPEvents.Result.device_time | unknown | The timestamp \(in ISO 8601 format\) that specifies the time at which the event occurred. | 
| ATPEvents.Result.device_uid | unknown | Unique ID of the device that originated the event. | 
| ATPEvents.Result.device_name | unknown | The device name \(i.e., the name of the endpoint or appliance associated with an event\). | 
| ATPEvents.Result.device_ip | unknown | The IPv6 or IPv4 address of the device that originated the event. | 
| ATPEvents.Result.device_type | unknown | The type of the device that originated the event. | 
| ATPEvents.Result.device_os_name | unknown | The operating system running on the device_type that originated the event. | 
| ATPEvents.Result.device_os_ver | unknown | The version of the operating system that is running on the device_type that originated the event. | 
| ATPEvents.Result.user_uid | unknown | Unique ID of the user that originated the event or the user on whose behalf the event occurred. | 
| ATPEvents.Result.user_name | unknown | The user name or ID that originated or caused the event. | 
| ATPEvents.Result.action_id | unknown | Action taken with respect to the underlying cause of the event. Possible values are: 0 = BLOCK 1 = MONITOR | 
| ATPEvents.Result.internal_hostname | unknown | The host name of the internal device/machine for the connection | 
| ATPEvents.Result.scanner_name | unknown | The name of the ATP scanner that generated this event | 
| ATPEvents.Result.internal_ip | unknown | The IP address of the internal device/machine for the connection | 
| ATPEvents.Result.internal_port | unknown | The port number identified as the source port in traffic sent to the target device | 
| ATPEvents.Result.external_ip | unknown | The IP address of the device/machine that accepted the connection | 
| ATPEvents.Result.external_port | unknown | The port number identified as the target port in traffic sent to the target device | 
| ATPEvents.Result.data_source_url | unknown | The URL that the traffic came from | 
| ATPEvents.Result.data_source_url_domain | unknown | The domain from which the file was downloaded. The domain is extracted from the URL for the query performance. | 
| ATPEvents.Result.data_source_url_referer | unknown | The referer URL used in the download | 
| ATPEvents.Result.sep_installed | unknown | Indicates whether SEP was installed when the event was generated | 
| ATPEvents.Result.data_direction | unknown | The direction of the data source. Possible values are: 1 = Inbound. Traffic flow from WAN to LAN. 2 = Outbound. Traffic flow from LAN to WAN. | 
| ATPEvents.Result.network_scanner_type | unknown | The type of network scanner that detected the event. Possible values are: 0 = ATP-N Scanner \(default\) 1 = WSS .cloud Scanner | 
| ATPEvents.Result.vlan_id | unknown | Indicates the VLAN ID \(between 0 and 4095\) on which the endpoint is deployed. If the value is 0 or missing, the endpoint is deployed in a non-VLAN setup | 
| ATPEvents.Result.device_end_time | unknown | The end time of an event \(in format yyyy-MM-dd’T’HH:mm:ss.SSSZ\). This is used with the aggregation count field. | 
| ATPEvents.Result.host_name | unknown | The host name of the client computer | 
| ATPEvents.Result.domain_name | unknown | The domain name of the client computer | 
| ATPEvents.Result.data_source_ip | unknown | The source IP address that the file came from \(either IPv4 or IPv6\). | 
| ATPEvents.Result.target_ip | unknown | The local \(victim\) IP address \(IPv4 or IPv6\) | 
| ATPEvents.Result.target_port | unknown | The local \(victim\) port number | 
| ATPEvents.Result.source_ip | unknown | The remote IP address \(IPv4 or IPv6\). | 
| ATPEvents.Result.source_port | unknown | The remote port number | 
| ATPEvents.Result.parent_file_sha2 | unknown | The SHA256 of the parent file | 
| ATPEvents.Result.reason | unknown | This field is overloaded and has following possible interpretations \(depending on the corresponding type_id\).  For type_id 4118, it specifies the Blacklist hash function that was used to identify the file. This field has following possible values: 0 = BY_FILE_BLACKLIST_SHA2 1 = BY_FILE_BLACKLIST_MD5  For type_id 4112, it specifies the Blacklist criteria that identify the traffic. This field has following possible values: 0 = BY_SOURCE_IP 1 = BY_DEST_IP 2 = BY_DEST_URL | 
| ATPEvents.Result.manual_submit | unknown | Indicates whether the file was manually submitted for analysis | 
| ATPEvents.Result.signature_id | unknown | The NDC signature ID. | 
| ATPEvents.Result.signature_name | unknown | The name of the signature | 
| ATPEvents.Result.categories | unknown | A list of categories an intrusion event may belong to | 
| ATPEvents.Result.intrusion_url | unknown | The URL from where a malicious script was loaded | 
| ATPEvents.Result.infected | unknown | Indicates whether the customer machine is infected | 
| ATPEvents.Result.count | unknown | Event aggregation count | 
| ATPEvents.Result.severity | unknown | The seriousness of the event. 0 indicates most serious. | 
| ATPEvents.Result.local_host_mac | unknown | The MAC address of the local computer | 
| ATPEvents.Result.remote_host_mac | unknown | The MAC address of the remote computer | 
| ATPEvents.Result.app_name | unknown | The full path of the application involved | 
| ATPEvents.Result.event_desc | unknown | A description of the event. Usually, the first line of the description is treated as summary | 
| ATPEvents.Result.network_protocol | unknown | Network protocol as reported by SEP. Possible values are: 1 = Other 2 = TCP 3 = UDP 4 = ICMP | 
| ATPEvents.Result.source | unknown | This field is overloaded and has possible interpretations \(depending on the corresponding type_id\). | 
| ATPEvents.Result.no_of_viruses | unknown | The number of events for the aggregated event record. This number can be due to client-side aggregation, server-side compression, or both | 
| ATPEvents.Result.actual_action_idx | unknown | This is the ID of action taken on the risk | 
| ATPEvents.Result.actual_action | unknown | This is the string version of the action taken on the risk \(in actual_action_idx\). | 
| ATPEvents.Result.virus_name | unknown | Name of the virus | 
| ATPEvents.Result.virus_def | unknown | The virus definition version number | 
| ATPEvents.Result.agent_version | unknown | The version of the client software | 
| ATPEvents.Result.MessageId | unknown | The unique ID of the email message | 
| ATPEvents.Result.OrigMessageHeaderId | unknown | The message header ID | 
| ATPEvents.Result.EmailReceivedDate | unknown | The time when the mail transfer agent received the email. The format is: yyyy-MM-dd’T’HH:mm:ss.SSSZ | 
| ATPEvents.Result.EmailSubject | unknown | Email subject | 
| ATPEvents.Result.EmailAction | unknown | The action executed on the email. Possible values are: - blocked - delivered - released | 
| ATPEvents.Result.Direction | unknown | Indication direction of the email. Possible values are: 0 = Outbound 1 = Inbound | 
| ATPEvents.Result.incident | unknown | The unique ID of the incident that is related to this event | 
| ATPEvents.Result.event_id | unknown | The event ID as reported by Symantec Endpoint Protection security log | 
| ATPEvents.Result.file | unknown | The file object | 
| ATPEvents.Result.threat | unknown | The threat object | 
| ATPEvents.Result.av | unknown | The AV object | 
| ATPEvents.Result.cynic | unknown | Cynic object | 
| ATPEvents.Result.scan | unknown | Scan object | 
| ATPEvents.Result.bash | unknown | Bash object | 
| ATPEvents.Result.Sender | unknown | Email sender object | 
| ATPEvents.Result.Receivers | unknown | Email receivers array of objects | 
| ATPEvents.Result.intrusion | unknown | Intrusion object | 


#### Command Example
``` !satp-events ```

#### Human Readable Output



### satp-files
***
Retrieve details about file based on given hash


#### Base Command

`satp-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | Hash of the file. Supports either SHA256 or MD5. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | unknown | File MD5 | 
| File.SHA256 | unknown | File SHA256 | 
| File.Instances.name | unknown | Name of file | 
| File.Instances.path | unknown | Path of file | 
| File.Type | unknown | MIME type of the file | 
| File.Size | unknown | Size of file in bytes | 
| File.SignatureCompany | unknown | The company that signed the file | 
| File.SignatureIssuer | unknown | The signature issuer | 
| File.Age | unknown | A code between 1 and 4 representing the file’s global age defined by the time the file was first reported to Symantec. This data is collected from telemetry sent to Symantec by in-field endpoint clients like Symantec Endpoint Protection and Norton. Possible values are: 1 = Years ago 2 = Months ago 3 = Weeks ago 4 = Days ago | 
| File.Threat | unknown | Name of the threat if the file is determined to be a malware | 
| File.Cynic | unknown | A code between 0 and 2 representing the verdict given by Symantec’s Cynic sandbox analysis. Possible values are: 0 = Malware 1 = Good 2 = Unknown | 
| File.TargetedAttack | unknown | A flag that indicates whether this file is a part of targeted attack launched against an organization | 
| File.ReputationBand | unknown | A code between 1 and 6 representing the file’s reputation. This data is generated by Symantec’s analysis engines based on the telemetry sent to Symantec by in-field endpoint clients like Symantec Endpoint Protection and Norton. Possible values are: 1 = Symantec-trusted 2 = Good 3 = Trending Good 4 = Unproven 5 = Poor 6 = Untrusted | 
| File.PrevalenceBand | unknown | A code between 1 and 8 representing the file’s prevalence. This data is collected from telemetry sent to Symantec by in-field endpoint clients like Symantec Endpoint Protection and Norton. Possible values are: 1 = Fewer than 5 users 2 = Fewer than 50 users 3 = Fewer than 100 users 4 = Hundreds of users 5 = Thousands of users 6 = Tens of thousands of users 7 = Hundreds of thousands of users 8 = Millions of users | 
| File.Health | unknown | A code between 0 and 3 representing the file’s health. Possible values are: 0 = Good 1 = Neutral 2 = Suspicious 3 = Bad 4 = Analyzing | 


#### Command Example
``` !satp-events ```

#### Human Readable Output

### Symantec ATP Events
data_direction|data_source_ip|data_source_url|data_source_url_domain|device_ip|device_name|device_time|device_uid|external_ip|file|log_name|log_time|sep_installed|type_id|uuid
---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
inbound | 62.324.344.170 | path_to_source | test.123 | 1234.1234.1234.1234 | 1234.1234.1234.1234 | 2021-11-10T23:42:15.779Z | 712da396-2dc6-44a9-bb8f-e1234124 | 1234.1234.1234.1234 | {"sha2":"b75aa777","md5":"4c2e3","name":"AM_Delta.exe","folder":"CSIDL_WINDOWS\\","size":2413000,"signature_company_name":"test","signature_issuer":"test","signature_serial_number":"1234","reputation_band":1344,"prevalence_band":04354} | test | 2021-11-10T23:42:16.706Z | true | 4096 | 345345-427f-11ec-345345-4t4554

### satp-incident-events
***
Get events that are related to incidents


#### Base Command

`satp-incident-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Specifies a search condition. | Optional | 
| start_time | ISO8601 date format - 2017-01-01T00:00:00.000Z. Also accepts milliseconds since epoch. | Optional | 
| end_time | ISO8601 date format - 2017-01-01T00:00:00.000Z. Also accepts milliseconds since epoch. | Optional | 
| limit | Maximum number of events to return. Default is 20 and max is 1000. Default is 20. | Optional | 
| next | Used for events cursoring. Retrieve the next batch of events. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ATPIncidentEvents.Total | unknown | Total number of results | 
| ATPIncidentEvents.Next | unknown | Next batch ID | 
| ATPIncidentEvents.Result.type_id | unknown | The unique identifier for an event type. | 
| ATPIncidentEvents.Result.uuid | unknown | The unique id for this event | 
| ATPIncidentEvents.Result.message | unknown | Human-readable event message or description of the event | 
| ATPIncidentEvents.Result.severity_id | unknown | Severity between 1 \(info\) and 6 \(fatal\). | 
| ATPIncidentEvents.Result.device_time | unknown | The timestamp \(in ISO 8601 format\) that specifies the time at which the event occurred. | 
| ATPIncidentEvents.Result.device_uid | unknown | Unique ID of the device that originated the event. | 
| ATPIncidentEvents.Result.device_name | unknown | The device name \(i.e., the name of the endpoint or appliance associated with an event\). | 
| ATPIncidentEvents.Result.device_ip | unknown | The IPv6 or IPv4 address of the device that originated the event. | 
| ATPIncidentEvents.Result.device_type | unknown | The type of the device that originated the event. | 
| ATPIncidentEvents.Result.device_os_name | unknown | The operating system running on the device_type that originated the event. | 
| ATPIncidentEvents.Result.device_os_ver | unknown | The version of the operating system that is running on the device_type that originated the event. | 
| ATPIncidentEvents.Result.user_uid | unknown | Unique ID of the user that originated the event or the user on whose behalf the event occurred. | 
| ATPIncidentEvents.Result.user_name | unknown | The user name or ID that originated or caused the event. | 
| ATPIncidentEvents.Result.action_id | unknown | Action taken with respect to the underlying cause of the event. Possible values are: 0 = BLOCK 1 = MONITOR | 
| ATPIncidentEvents.Result.internal_hostname | unknown | The host name of the internal device/machine for the connection | 
| ATPIncidentEvents.Result.scanner_name | unknown | The name of the ATP scanner that generated this event | 
| ATPIncidentEvents.Result.internal_ip | unknown | The IP address of the internal device/machine for the connection | 
| ATPIncidentEvents.Result.internal_port | unknown | The port number identified as the source port in traffic sent to the target device | 
| ATPIncidentEvents.Result.external_ip | unknown | The IP address of the device/machine that accepted the connection | 
| ATPIncidentEvents.Result.external_port | unknown | The port number identified as the target port in traffic sent to the target device | 
| ATPIncidentEvents.Result.data_source_url | unknown | The URL that the traffic came from | 
| ATPIncidentEvents.Result.data_source_url_domain | unknown | The domain from which the file was downloaded. The domain is extracted from the URL for the query performance. | 
| ATPIncidentEvents.Result.data_source_url_referer | unknown | The referer URL used in the download | 
| ATPIncidentEvents.Result.sep_installed | unknown | Indicates whether SEP was installed when the event was generated | 
| ATPIncidentEvents.Result.data_direction | unknown | The direction of the data source. Possible values are: 1 = Inbound. Traffic flow from WAN to LAN. 2 = Outbound. Traffic flow from LAN to WAN. | 
| ATPIncidentEvents.Result.network_scanner_type | unknown | The type of network scanner that detected the event. Possible values are: 0 = ATP-N Scanner \(default\) 1 = WSS .cloud Scanner | 
| ATPIncidentEvents.Result.vlan_id | unknown | Indicates the VLAN ID \(between 0 and 4095\) on which the endpoint is deployed. If the value is 0 or missing, the endpoint is deployed in a non-VLAN setup | 
| ATPIncidentEvents.Result.device_end_time | unknown | The end time of an event \(in format yyyy-MM-dd’T’HH:mm:ss.SSSZ\). This is used with the aggregation count field. | 
| ATPIncidentEvents.Result.host_name | unknown | The host name of the client computer | 
| ATPIncidentEvents.Result.domain_name | unknown | The domain name of the client computer | 
| ATPIncidentEvents.Result.data_source_ip | unknown | The source IP address that the file came from \(either IPv4 or IPv6\). | 
| ATPIncidentEvents.Result.target_ip | unknown | The local \(victim\) IP address \(IPv4 or IPv6\) | 
| ATPIncidentEvents.Result.target_port | unknown | The local \(victim\) port number | 
| ATPIncidentEvents.Result.source_ip | unknown | The remote IP address \(IPv4 or IPv6\). | 
| ATPIncidentEvents.Result.source_port | unknown | The remote port number | 
| ATPIncidentEvents.Result.parent_file_sha2 | unknown | The SHA256 of the parent file | 
| ATPIncidentEvents.Result.reason | unknown | This field is overloaded and has following possible interpretations \(depending on the corresponding type_id\).  For type_id 4118, it specifies the Blacklist hash function that was used to identify the file. This field has following possible values: 0 = BY_FILE_BLACKLIST_SHA2 1 = BY_FILE_BLACKLIST_MD5  For type_id 4112, it specifies the Blacklist criteria that identify the traffic. This field has following possible values: 0 = BY_SOURCE_IP 1 = BY_DEST_IP 2 = BY_DEST_URL | 
| ATPIncidentEvents.Result.manual_submit | unknown | Indicates whether the file was manually submitted for analysis | 
| ATPIncidentEvents.Result.signature_id | unknown | The NDC signature ID. | 
| ATPIncidentEvents.Result.signature_name | unknown | The name of the signature | 
| ATPIncidentEvents.Result.categories | unknown | A list of categories an intrusion event may belong to | 
| ATPIncidentEvents.Result.intrusion_url | unknown | The URL from where a malicious script was loaded | 
| ATPIncidentEvents.Result.infected | unknown | Indicates whether the customer machine is infected | 
| ATPIncidentEvents.Result.count | unknown | Event aggregation count | 
| ATPIncidentEvents.Result.severity | unknown | The seriousness of the event. 0 indicates most serious. | 
| ATPIncidentEvents.Result.local_host_mac | unknown | The MAC address of the local computer | 
| ATPIncidentEvents.Result.remote_host_mac | unknown | The MAC address of the remote computer | 
| ATPIncidentEvents.Result.app_name | unknown | The full path of the application involved | 
| ATPIncidentEvents.Result.event_desc | unknown | A description of the event. Usually, the first line of the description is treated as summary | 
| ATPIncidentEvents.Result.network_protocol | unknown | Network protocol as reported by SEP. Possible values are: 1 = Other 2 = TCP 3 = UDP 4 = ICMP | 
| ATPIncidentEvents.Result.source | unknown | This field is overloaded and has possible interpretations \(depending on the corresponding type_id\). | 
| ATPIncidentEvents.Result.no_of_viruses | unknown | The number of events for the aggregated event record. This number can be due to client-side aggregation, server-side compression, or both | 
| ATPIncidentEvents.Result.actual_action_idx | unknown | This is the ID of action taken on the risk | 
| ATPIncidentEvents.Result.actual_action | unknown | This is the string version of the action taken on the risk \(in actual_action_idx\). | 
| ATPIncidentEvents.Result.virus_name | unknown | Name of the virus | 
| ATPIncidentEvents.Result.virus_def | unknown | The virus definition version number | 
| ATPIncidentEvents.Result.agent_version | unknown | The version of the client software | 
| ATPIncidentEvents.Result.MessageId | unknown | The unique ID of the email message | 
| ATPIncidentEvents.Result.OrigMessageHeaderId | unknown | The message header ID | 
| ATPIncidentEvents.Result.EmailReceivedDate | unknown | The time when the mail transfer agent received the email. The format is: yyyy-MM-dd’T’HH:mm:ss.SSSZ | 
| ATPIncidentEvents.Result.EmailSubject | unknown | Email subject | 
| ATPIncidentEvents.Result.EmailAction | unknown | The action executed on the email. Possible values are: - blocked - delivered - released | 
| ATPIncidentEvents.Result.Direction | unknown | Indication direction of the email. Possible values are: 0 = Outbound 1 = Inbound | 
| ATPIncidentEvents.Result.incident | unknown | The unique ID of the incident that is related to this event | 
| ATPIncidentEvents.Result.event_id | unknown | The event ID as reported by Symantec Endpoint Protection security log | 
| ATPIncidentEvents.Result.file | unknown | The file object | 
| ATPIncidentEvents.Result.threat | unknown | The threat object | 
| ATPIncidentEvents.Result.av | unknown | The AV object | 
| ATPIncidentEvents.Result.cynic | unknown | Cynic object | 
| ATPIncidentEvents.Result.scan | unknown | Scan object | 
| ATPIncidentEvents.Result.bash | unknown | Bash object | 
| ATPIncidentEvents.Result.Sender | unknown | Email sender object | 
| ATPIncidentEvents.Result.Receivers | unknown | Email receivers array of objects | 
| ATPIncidentEvents.Result.intrusion | unknown | Intrusion object | 


#### Command Example
``` !satp-incident-events  ```

### satp-incidents
***
Query incidents from ATP


#### Base Command

`satp-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Specifies a search condition. | Optional | 
| start_time | ISO8601 date format - 2017-01-01T00:00:00.000Z. Also accepts milliseconds since epoch. | Optional | 
| end_time | ISO8601 date format - 2017-01-01T00:00:00.000Z. Also accepts milliseconds since epoch. | Optional | 
| limit | Maximum number of events to return. Default is 20 and max is 1000. Default is 20. | Optional | 
| next | Used for events cursoring. Retrieve the next batch of events. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ATPIncidents.Result.atp_incident_id | unknown | A unique identifier for this incident | 
| ATPIncidents.Result.priority_level | unknown | Priority level of the incident. 1 = LOW, 2 = MED, 3 = HIGH | 
| ATPIncidents.Result.state | unknown | The state of the incident. 1 = OPEN,2 = WAITING,3 = IN_WORK,4 = CLOSED | 
| ATPIncidents.Result.recommended_action | unknown | Recommended action for this incident | 
| ATPIncidents.Result.first_event_seen | unknown | When the first event associated with the incident was created | 
| ATPIncidents.Result.last_event_seen | unknown | When the last event associated with the incident was created | 
| ATPIncidents.Result.event_count | unknown | The number of events associated with the incident | 
| ATPIncidents.Result.device_time | unknown | The timestamp that specifies the time at which the event occurred | 
| ATPIncidents.Result.deviceUid | unknown | A list of ATP endpoint devices UID on which the events occurred | 
| ATPIncidents.Result.scanners | unknown | A list of ATP scanners that discovered the threat | 
| ATPIncidents.Result.filehash | unknown | A list of SHA256 hashes associated with this incident | 
| ATPIncidents.Result.domainid | unknown | A list of domains associated with this incident | 
| ATPIncidents.Result.summary | unknown | Summary information about the incident | 
| ATPIncidents.Result.time | unknown | The creation time \(in ISO 8601 format\) of the incident | 
| ATPIncidents.Result.updated | unknown | The time \(in ISO 8601 format\) of last modification | 
| ATPIncidents.Result.log_name | unknown | The index/type of the originating event | 
| ATPIncidents.Result.uuid | unknown | The GUID assigned for this incident | 


#### Command Example
``` !satp-incidents ```


