Queries Symantec EDR endpoints help to detect threats on your network (on-premise) by filter endpoints data to find Indicators of Compromise (IoCs) and take actions to remediate the threat(s)
This integration was integrated and tested with version xx of SymantecEDRDev

## Configure Symantec Endpoint Detection and Response (EDR) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Symantec Endpoint Detection and Response (EDR).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Symantec-EDR URL (e.g. https://1.1.1.1) | Symantec EDR Appliance Console URL | True |
    | Client ID | OAuth Client ID and Client Secret for authorizes third-party applications to communicate with Symantec EDR | True |
    | Password |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incident type |  | False |
    | Fetch incidents |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### symantec-edr-endpoint-command
***
Isolates endpoints by cutting connections that the endpoint(s) has to internal networks and external networks, based on the endpoint IDs

Rejoins endpoints by re-establishing connections that the endpoint(s) has to internal networks and external networks, based on the endpoint IDs

Deletes a file, i.e. deletes all instances of the file, based on the file hash that you have specified from the endpoint that you have specified using the Device ID.


#### Base Command

`symantec-edr-endpoint-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The action to perform on the endpoints. Possible values are: isolate_endpoint, rejoin_endpoint, delete_endpoint_file. Possible values are: isolate_endpoint, rejoin_endpoint, delete_endpoint_file. | Required | 
| targets | The targets field is specific to the tttype of command For isolate_endpoint and rejoin_endpoint the field is an array of strings each representing a device_uid of the target computer. <br/>For delete, array of object, each with hash and device_uid attributes (supports comma-delimited hash:uid, hash:uid as well). Possible values are: . | Required | 


#### Context Output

There is no context output for this command.
### symantec-edr-domain-file-association-list
***
Get associations Between domains and files


#### Base Command

`symantec-edr-domain-file-association-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verb |  Request verb. Currently, only query verb is supported. example: query. Possible values are: query. Default is query. | Required | 
| limit | Maximum number of events to return, Default is 1. | Optional | 
| query | example: first_seen:[2017-01-01T00:00:00.000Z TO 2017-01-08T00:00:00.000Z]. | Optional | 


#### Context Output

There is no context output for this command.
### symantec-edr-endpoint-domain-association-list
***
Get Associations between endpooints and domains


#### Base Command

`symantec-edr-endpoint-domain-association-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verb |  Request verb. Currently, only query verb is supported. example: query. Possible values are: query. Default is query. | Required | 
| limit | Maximum number of events to return, Default is 1. | Optional | 
| query | example: first_seen:[2017-01-01T00:00:00.000Z TO 2017-01-08T00:00:00.000Z] . | Optional | 


#### Context Output

There is no context output for this command.
### symantec-edr-endpoint-file-association-list
***
Get Associations between domains and files


#### Base Command

`symantec-edr-endpoint-file-association-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verb |  Request verb. Currently, only query verb is supported. example: query. Possible values are: query. Default is query. | Required | 
| limit | Maximum number of events to return, Default is 1. Default is 1. | Optional | 
| query |  Request verb. Currently, only query verb is supported. example: query. | Optional | 


#### Context Output

There is no context output for this command.
### symantec-edr-domain-instance-get
***
Get Domain Instances


#### Base Command

`symantec-edr-domain-instance-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verb | Specify a search condition. Possible values are: query. Default is query. | Optional | 
| limit | Maximum number of events to return, Default is 20. Default is 20. | Optional | 


#### Context Output

There is no context output for this command.
### symantec-edr-endpoint-instance-get
***
Get Endpoint Instances


#### Base Command

`symantec-edr-endpoint-instance-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verb | Specify a search condition. Possible values are: query. Default is query. | Optional | 
| limit | Maximum number of events to return, Default is 20. Default is 20. | Optional | 


#### Context Output

There is no context output for this command.
### symantec-edr-file-instance-get
***
Get File Instances


#### Base Command

`symantec-edr-file-instance-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verb | Specify a search condition. Possible values are: query. Default is query. | Optional | 
| limit | Maximum number of events to return, Default is 20. Default is 20. | Optional | 
| sha2 | Get File Instances for specific SHA2. | Optional | 


#### Context Output

There is no context output for this command.
### symantec-edr-system-activity-get
***
Get System Activities


#### Base Command

`symantec-edr-system-activity-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verb | Default verb parameter. Default is query. | Optional | 
| limit | Number of records returns Maximum limit 5000 minimum 100. Default is 1. | Optional | 


#### Context Output

There is no context output for this command.
### symantec-edr-audit-event-get
***
Get  Audit Events


#### Base Command

`symantec-edr-audit-event-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verb | Default verb parameter. Default is query. | Optional | 
| limit | Number of records returns Maximum limit 5000 minimum 100. Default is 1. | Optional | 


#### Context Output

There is no context output for this command.
### symantec-edr-event-list
***
Command is used to get events from EDR


#### Base Command

`symantec-edr-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Specifes the number of records displayed on the XSOAR console.<br/><br/>Default:  50. | Optional | 
| query | Specifies a search query as Lucene query string.<br/><br/>Example:<br/>query="type_id:(4096 OR 4098 OR 4123)". | Optional | 
| from | Specifes the beginning of the search time frame. The value should be back in time. <br/>The maximum  time range between "start_time" and "end_time" parameter  is "7 days".<br/>Example: -&lt;nn&gt;days OR -&lt;nn&gt;mins -&lt;n&gt;weeks, -&lt;nn&gt;hours<br/><br/>. Possible values are: -5mins, -10mins, -15mins, -1weeks, -1hours, -1days. | Optional | 
| to | Specifes the ending of the search time frame. The value should be either current time or back in time.<br/>The maximum  time range between "start_time" and "end_time" parameter  is "7 days".<br/>Example: now,-&lt;nn&gt;days OR -&lt;nn&gt;mins -&lt;n&gt;weeks, -&lt;nn&gt;hours<br/><br/>. Possible values are: now, -1mins, -10mins, -15mins, -1weeks, -1hours, -1days. | Optional | 
| page | Specifies the page number <br/><br/>Default: 1. | Optional | 
| limit | Specifes the maximum number of records to return. <br/>Limit range should be between 1 and 5000. <br/><br/>Default: 100. | Optional | 
| verb | Currently, only the "query" verb is supported.<br/>Default: query. Possible values are: query. Default is query. | Required | 


#### Context Output

There is no context output for this command.
### symantec-edr-incident-event-list
***
Command is used to get evetnts for incidents


#### Base Command

`symantec-edr-incident-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verb | Request verb. Currently, only the query verb is supported.<br/>. Possible values are: query. Default is query. | Required | 
| page_size | Specifes the number of records display on the XSOAR console, Limit range is betwen 1 and 1000<br/> If no limit is specifed, then the limit value is set to the default limit e.g. 50. | Optional | 
| page | Page Number to . | Optional | 
| query | Specifes a search condition as Lucene query string. | Optional | 
| from | Specifes the beginning of the search time frame.<br/>- The value should either epoch or go back in time e.g. -7days<br/>- Default -7days. Possible values are: . | Optional | 
| to | Specifes the end of the search time frame. <br/>- The value should either epoch<br/>- Default value  now. Default is now. | Optional | 


#### Context Output

There is no context output for this command.
### symantec-edr-incident-list
***
Command is used to get incidents from Symantec-EDR API


#### Base Command

`symantec-edr-incident-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verb | Currently, only the "query" verb is supported.<br/>Default: query. Possible values are: query. Default is query. | Required | 
| page_size | Specifes the number of records displayed on the XSOAR console.<br/><br/>Default:  50. | Optional | 
| query | Specifies a search query as Lucene query string.<br/><br/>Example:<br/>query="type_id:(4096 OR 4098 OR 4123)". | Optional | 
| from | Specifes the beginning of the search time frame. The value should be back in time. The maximum  time range between "start_time" and "end_time" parameter  is "30 days" .<br/>Example: -&lt;nn&gt;days OR -&lt;nn&gt;mins -&lt;n&gt;weeks, -&lt;nn&gt;hours<br/><br/>. Possible values are: -5mins, -10mins, -15mins, -1weeks, -1hours, -1days, -1days. | Optional | 
| to | Specifes the ending of the search time frame. The value should be either current time or back in time. <br/>The maximum  time range between "start_time" and "end_time" parameter  is "30 days" .<br/>Example: now,-&lt;nn&gt;days OR -&lt;nn&gt;mins -&lt;n&gt;weeks, -&lt;nn&gt;hours<br/><br/>. Possible values are: now, -1mins, -10mins, -15mins, -1weeks, -1hours, -1days. | Optional | 
| page | Specifies the page number <br/><br/>Default: 1. Default is 1. | Optional | 
| limit | Specifes the maximum number of records to return. <br/>Limit range should be between 1 and 5000. <br/><br/>Default: 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.IncidentList.atp_incident_id | Number | A unique identifer for this incident. | 
| SymantecEDR.IncidentList.log_name | String | The index of the incident.
Note: This is for informational purpose and cannot be used as a flter.
Use time as start_time to query for incidents. Example : "epmp_incident-2018-03-01" | 
| SymantecEDR.IncidentList.summary | String | Summary information about the incident. | 
| SymantecEDR.IncidentList.priority_level | Number | Priority level of the incident. Possible values are:
1 = LOW
2 = MED
3 =HIGH | 
| SymantecEDR.IncidentList.last_event_seen | Date | The creation time \(in ISO 8601 format\) when the last event associated
with the incident was created. Matches the last event’s time feld. | 
| SymantecEDR.IncidentList.time | Date | The creation time \(in ISO 8601 format\) of the incident. | 
| SymantecEDR.IncidentList.rule_name | String | The name of the rule that triggered this incident. | 
| SymantecEDR.IncidentList.first_event_seen | Date | The creation time \(in ISO 8601 format\) when the frst event associated
with the incident was created. Matches the frst event’s time feld. This
is likely before the incident’s creation time feld given incidents are
created after their frst event is seen. | 
| SymantecEDR.IncidentList.state | Number | The current state of the incident. Possible values are:
1 = OPEN
2 =WAITING
3 = IN_WORK
4 = CLOSED | 
| SymantecEDR.IncidentList.detection_type | String | Incident Detection Type | 
| SymantecEDR.IncidentList.device_time | Date | The timestamp \(in ISO 8601 format\) that specifes the time at which the
event occurred | 
| SymantecEDR.IncidentList.recommended_action | String | Recommended action for this incident. Possible actions could be
isolating an endpoint, deleting fle from endpoint, blacklist URL, or
domain, etc. | 
| SymantecEDR.IncidentList.updated | Date | The time \(in ISO 8601 format\) of last modifcation. | 
| SymantecEDR.IncidentList.uuid | String | The GUID assigned for this incident.
Example : "483e3fde-4556-4800-81b1-e8da5ee394b6" | 
| SymantecEDR.IncidentList.atp_rule_id | String | The textual representation of the rule that triggered this incident. | 
| SymantecEDR.IncidentList.resolution | Number | The resolution of the closed incident. Possible values are:
0 =INSUFFICIENT_DATA. The incident does not have sufcient information to make a determination.
1 = SECURITY_RISK. The incident indicates a true security threat.
2 = FALSE_POSITIVE. The incident has been incorrectly reported as a security threat.
3 =MANAGED_EXTERNALLY. The incident was exported to an external application and will be triaged there.
4 = NOT_SET. The incident resolution was not set.
5 = BENIGN. The incident detected the activity as expected but is not a security threat.
6 = TEST. The incident was generated due to internal security testing. | 

#### Command example
```!symantec-edr-incident-list verb=query limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "IncidentList": {
            "atp_incident_id": 100000,
            "atp_rule_id": "AdvancedAttackTechniqueIncident",
            "detection_type": "Advanced Attack Techniques",
            "device_time": "2022-10-31T09:40:27.353Z",
            "first_event_seen": "2022-10-31T22:10:52.000Z",
            "last_event_seen": "2022-10-31T22:10:57.000Z",
            "log_name": "epmp_incident-2022-10-31",
            "priority_level": 3,
            "recommended_action": "Remove or blacklist developer utilities that aren't needed on target systems.\nEnsure Symantec Endpoint Protection's SONAR behavioral protection and Network Intrusion Prevention are enabled and blocking.\nRemove, blacklist, or use Symantec Endpoint Protection's Application Control to lock down host applications that aren't needed in your environment.",
            "rule_name": "Advanced Attack Technique",
            "state": 1,
            "summary": "win-tfb8l7bi77h: Trusted Developer Utilities Proxy Execution, Deobfuscate/Decode Files or Information, Signed Binary Proxy Execution",
            "time": "2022-10-31T09:40:27.353Z",
            "updated": "2022-10-31T09:41:59.455Z",
            "uuid": "0d219490-5900-11ed-f646-000000000001"
        }
    }
}
```

#### Human Readable Output

>### Incident List
>Showing page 1
>Current page size: 50
>|ATP INCIDENT ID|PRIORITY LEVEL|STATE|FIRST EVENT SEEN|LAST EVENT SEEN|DEVICE TIME|TIME|UPDATED|ATP RULE ID|RULE NAME|DETECTION TYPE|UUID|LOG NAME|RECOMMENDED ACTION|SUMMARY|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 100000 | 3 | 1 | 2022-10-31T22:10:52.000Z | 2022-10-31T22:10:57.000Z | 2022-10-31T09:40:27.353Z | 2022-10-31T09:40:27.353Z | 2022-10-31T09:41:59.455Z | AdvancedAttackTechniqueIncident | Advanced Attack Technique | Advanced Attack Techniques | 0d219490-5900-11ed-f646-000000000001 | epmp_incident-2022-10-31 | Remove or blacklist developer utilities that aren't needed on target systems.<br/>Ensure Symantec Endpoint Protection's SONAR behavioral protection and Network Intrusion Prevention are enabled and blocking.<br/>Remove, blacklist, or use Symantec Endpoint Protection's Application Control to lock down host applications that aren't needed in your environment. | win-tfb8l7bi77h: Trusted Developer Utilities Proxy Execution, Deobfuscate/Decode Files or Information, Signed Binary Proxy Execution |


### symantec-edr-incident-comment-get
***
Get Incident Comments


#### Base Command

`symantec-edr-incident-comment-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verb | Parameter verb default query. Default is query. | Optional | 
| page_size | Specifes the number of records display on the XSOAR console, Limit range is betwen 1 and 1000<br/> If no limit is specifed, then the limit value is set to the default limit e.g. 50. Default is 50. | Optional | 
| uuid | Incidents UUID (example :  "uuid": "0d219490-5900-11ed-f646-000000000001"). | Required | 
| page | Page Number to. | Optional | 
| query | Specifes a search query as Lucene query string. | Optional | 
| start_time | Specifes the beginning of the search time frame.<br/>- The value should follow ISO 8601 date stamp standard format: yyyy-MMdd’T’HH:mm:ss.SSSXXX. Possible values are: . | Optional | 
| end_time | Specifes the end of the search time frame. <br/>- The value should follow ISO 8601 date stamp standard format: yyyy-MM-dd’T’HH:mm:ss.SSSXXX . | Optional | 


#### Context Output

There is no context output for this command.
### symantec-edr-deny-list-policy-get
***
Get Deny List Policies


#### Base Command

`symantec-edr-deny-list-policy-get`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### symantec-edr-black-list-policy-get
***
Get Blacklist Policies


#### Base Command

`symantec-edr-black-list-policy-get`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### symantec-edr-allow-list-policy-get
***
Get Allowlist Policies


#### Base Command

`symantec-edr-allow-list-policy-get`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### file
***
Issue Sandbox Command, Query Sandbox Command Status, Get Sandbox Verdict of specific SHA2


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Specifies the tttype of action to take on the specified target(s) <br/>action value: "analyze"  . Possible values are: analyze. Default is analyze. | Required | 
| targets | The targets field is specific to the tttype of command. <br/>For analyze, the field is an array of strings each representing a SHA256 of the target file. . | Optional | 
| command_id | Command ID to query to Query Sandbox Command Status. | Optional | 
| sha2 | Query unique file identifier (SHA2) to get  Verdict . | Optional | 
| type | File Sandbox command tttypes issue,status,verdict. Possible values are: issue, status, verdict. | Required | 
| file | . | Required | 


#### Context Output

There is no context output for this command.
### symantec-edr-incident-update
***
Incidents Patch command for the close incident, update resolution of closed incident or add comments to incident.


#### Base Command

`symantec-edr-incident-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation | Specifes the operation to take on specifed incident.<br/>- For close incident, the operation must be "replace".<br/>- For update resolution of closed incident, the operation must be "replace".<br/>- For add comments, the operation must be "add". Possible values are: add, replace. | Required | 
| path | String containing a JSON-pointer value that references a location within the incident document where the operation is performed.<br/>- For close incident, the path must be /{uuid}/state.<br/>- For update resolution of closed incident, the path must be /{uuid}/resolution.<br/>- For add comments, the path must be /{uuid}/comments.<br/>- The uuid is the UUID assigned for the incident. Possible values are: . | Required | 
| value | New value for the feld being patched.<br/>- The maximum length of comment is 512 characters.<br/>- For close incident, the value must be 4. The type is integer.<br/>- For update resolution of closed incident, the value must be a supported incident resolution value. See resolution feld in the incident defnition for supported values. The type is integer.<br/>- For add comments, the value should contain user defned comment. The type is string. | Required | 


#### Context Output

There is no context output for this command.