RSA Security Analytics is a distributed and modular system that enables highly flexible deployment architectures that scale with the needs of the organization. Security Analytics allows administrators to collect two types of data from the network infrastructure, packet data and log data.
This integraitons should work with RSA Netwitness older than v11. For versions v11 and above use the integration RSA NetWitness v11.1.

## Configure RSA NetWitness Security Analytics in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server Url \(192.168.56.101\) | True |
| username | Username | True |
| password | Password | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nw-login
***
Logins to the system and returns valid sessionId


#### Base Command

`nw-login`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.


### fetch-incidents
***
Simulates fetching incidents. Returns array of incidents from NetWitness.


#### Base Command

`fetch-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.


### netwitness-im-list-incidents
***
Fetches incidents by filter


#### Base Command

`netwitness-im-list-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | If query provided all other parameters ignored. Query should contain page, limit, start, sort and filter, joined by &amp;, For example: page=1&amp;start=0&amp;limit=100&amp;sort=[{"property":"created","direction":"DESC"}]&amp;filter=[{"property":"created","value":[851171984031,1482323984031]}] | Optional | 
| page | The default is 1. Indicates the page number of incidents | Optional | 
| start | The default is 0. Indicates the start index of incident in page | Optional | 
| limit | The default is 100. Limits the number of incidents per page | Optional | 
| sort | By default sorts by "created" field in "DESC" order. Example: "[{\"property\":\"created\",\"direction\":\"DESC\"}]" | Optional | 
| filter | By default filters by "created" from 1996 to this date. Example: "[{\"property\":\"id\", \"value\":\"INC-21\"}]" | Optional | 
| incidentManagementId | [optional number] This is the id of NetWitness INCIDENT_MANAGEMENT device/component id. It can be received by running netwitness-im-get-component command. If this argument is not filled/passed, the script will automatically get the first device of type INCIDENT_MANAGEMENT from the SA server. | Optional | 
| loadAlerts | [optinal boolean] By default alerts and events related to incident not loaded. If loadAlerts is true, then command will load all alerts and their events from SA. Please be noticed THIS IS HAS PERFORMANCE IMPACT! For each alert XHR request send to SA. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netwitness.Incident.Id | unknown | Netwitness Incident ID | 
| Netwitness.Incident.Name | unknown | Netwitness Incident Name | 
| Netwitness.Incident.Priority | unknown | Netwitness Incident Priority | 
| Netwitness.Incident.CreatedBy | unknown | User who created Netwitness Incident | 
| Netwitness.Incident.Summary | unknown | Netwitness Incident Summary | 
| Netwitness.Incident.Assignee | unknown | User Assigned To Incident | 
| Netwitness.Incident.Created | unknown | Time of Incident Creation | 
| Netwitness.Incident.FirstAlertTime | unknown | Time of Incident Creation | 
| Netwitness.Incident.LastUpdatedByUserName | unknown | User who was last to update Incident | 
| Netwitness.Incident.RiskScore | unknown | Netwitness Incident Risk Score | 
| Netwitness.Incident.AverageAlertRiskScore | unknown | Netwitness Incident Average Risk Score | 
| Netwitness.Incident.Categories | unknown | Netwitness Incident Category | 
| Netwitness.Incident.AlertCount | unknown | Netwitness Incident Alerts Counts | 


### netwitness-im-login
***
Logins to the system and returns valid sessionId


#### Base Command

`netwitness-im-login`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.


### netwitness-im-get-components
***
Returns all the components in the system


#### Base Command

`netwitness-im-get-components`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | [optional string] Query must contain page, start, limit | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netwitness.Component.Id | unknown | Netwitness Component ID | 
| Netwitness.Component.DisplayName | unknown | Netwitness Component DisplayName | 
| Netwitness.Component.DeviceVersion | unknown | Netwitness Component Device Version | 
| Netwitness.Component.DisplayType | unknown | Netwitness Component Device Type | 
| Netwitness.Component.Host | unknown | Netwitness Component Device Host | 
| Netwitness.Component.Port | unknown | Netwitness Component Device Port | 
| Netwitness.Component.Validated | unknown | Netwitness Component is passed validation | 
| Netwitness.Component.Licensed | unknown | Netwitness Component license | 
| Netwitness.Component.Username | unknown | Netwitness Component User Name | 
| Netwitness.Component.EnableSSL | unknown | Netwitness Component Enable SSL | 



### netwitness-im-get-events
***
Returns all the events in defined time range


#### Base Command

`netwitness-im-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeRangeType | Filter of time range in which events occured | Required | 
| deviceId | [number] Id of the device where the events stored/occurred. In order to get list of available devices/components run command netwitness-im-get-components | Required | 
| collectionName | [optional] | Optional | 
| predicateIds | [optional] | Optional | 
| startDate | [optional datetime] If timeRangeType defined as CUSTOM, set this argument | Optional | 
| endDate | [optional datetime] If timeRangeType defined as CUSTOM, set this argument | Optional | 
| lastCollectionTime | [optional datetime] Last collection time | Optional | 
| mid1 | The unique meta id for this field. If nw-get-events was called this will be your starting id for this distinct value | Optional | 
| mid2 | The unique meta id for this field. If nw-get-events was called this will be your ending id for this distinct value. | Optional | 
| investigationToken | [optional guid] Investigation id token | Optional | 
| page | [optional number] Default set to 1. The page number | Optional | 
| start | [optional number] Default set to 0. The starting index of event in page. | Optional | 
| limit | [optional number] Default set to 25. Limits the number of events per page | Optional | 
| sort | By default sorts by "id" field in "ASC" order. Example: "[{\"property\":\"id\",\"direction\":\"ASC\"}]" | Optional | 
| filter | &lt;string&gt; Must provide key value pairs of fieldName and their value separated by comma. Example: "ip.src=1.1.1.1,meta.device.type=\"crowdstrike\"" | Optional | 


#### Context Output

There is no context output for this command.



### netwitness-im-get-available-assignees
***
Returns the available users to be assigned to incidents


#### Base Command

`netwitness-im-get-available-assignees`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netwitness.Account.Id | unknown | Netwitness Account ID | 
| Netwitness.Account.Name | unknown | Netwitness Account Name | 
| Netwitness.Account.Login | unknown | Netwitness Account Login Name | 
| Netwitness.Account.EmailAddress | unknown | Netwitness Account Email Address | 



### netwitness-im-create-incident
***
Creating new incident


#### Base Command

`netwitness-im-create-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertSummary | [string] Short summary of the alert which will be attached to incident | Required | 
| severity | [optional string] Default set to "50".  | Optional | 
| name | [string] The name of the incident. | Required | 
| assigned | [optional string] Set assignee login name if assignee has changed. You can execute netwitness-im-get-available-assignees to get the list of users. Example: demisto123 | Optional | 
| eventList | List of event ids separated by comma [,] must not include spaces in it. In order to get list of events you can use netwitness-im-get-events | Required | 
| deviceId | The id of the device/component (Concentrator, Log Decoder, Packet Decoder, etc.) from which the events are. You can view the list of devices by executing the command netwitness-im-get-components | Required | 
| priority | Priority of the incident | Required | 
| summary | Summary of the incident | Optional | 
| incidentManagementId | [optional number] This is the id of NetWitness INCIDENT_MANAGEMENT device/component id. It can be received by running netwitness-im-get-component command. If this argument is not filled/passed, the script will automatically get the first device of type INCIDENT_MANAGEMENT from the SA server. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netwitness.Incident.Id | unknown | Netwitness Incident ID | 
| Netwitness.Incident.Name | unknown | Netwitness Incident Name | 
| Netwitness.Incident.Priority | unknown | Netwitness Incident Priority | 
| Netwitness.Incident.CreatedBy | unknown | User who created Netwitness.Incident | 
| Netwitness.Incident.AlertIDList | unknown | Alerts which rised by incident | 


### netwitness-im-add-events-to-incident
***
This command will add new events to existing incident


#### Base Command

`netwitness-im-add-events-to-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | [string] Existing incident id.  | Required | 
| eventList | [array of strings] List of event ids separated by comma [,] must not include spaces in it. In order to get list of events you can use netwitness-im-get-events. Example: "23,12,3" | Required | 
| alertSummary | [string] Short summary of the alert which will be attached to incident | Required | 
| severity | [number] Severity of the incident. Example: 50 | Required | 
| deviceId | [number] The id of the device/component (Concentrator, Log Decoder, Packet Decoder, etc.) from which the events are. You can view the list of devices by executing the command netwitness-im-get-components | Required | 
| incidentManagementId | [optional number] This is the id of NetWitness INCIDENT_MANAGEMENT device/component id. It can be received by running netwitness-im-get-component command. If this argument is not filled/passed, the script will automatically get the first device of type INCIDENT_MANAGEMENT from the SA server. | Optional | 


#### Context Output

There is no context output for this command.


### netwitness-im-update-incident
***
Updates incident


#### Base Command

`netwitness-im-update-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| idList | List of incident ids which will be updated, separated by comma [,]. Must not contain spaces. Example: "INC-13,INC-15,INC-23" | Required | 
| name | [optional string] Set name if incident name has been changed | Optional | 
| summary | [optional string] Updated incident summary | Optional | 
| assignee | [optional string] Set assignee login name if assignee has changed. You can execute netwitness-im-get-available-assignees to get the list of users. Example: demisto123 | Optional | 
| comment | [optional string] Add a journal entry describing your changes | Optional | 
| status | [optional status] Set status if changed | Optional | 
| priority | [optional priority] Set priority if incident priority has been changed | Optional | 
| categories | List of categories. | Optional | 
| incidentManagementId | [optional number] This is the id of NetWitness INCIDENT_MANAGEMENT device/component id. It can be received by running netwitness-im-get-component command. If this argument is not filled/passed, the script will automatically get the first device of type INCIDENT_MANAGEMENT from the SA server. | Optional | 


#### Context Output

There is no context output for this command.



### netwitness-im-get-alerts
***
Return all the alerts filtered by filter.


#### Base Command

`netwitness-im-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The default is 1. Indicates the page number of incidents | Optional | 
| start | The default is 0. Indicates the start index of incident in page | Optional | 
| limit | The default is 100. Limits the number of incidents per page | Optional | 
| sort | By default sorts by "alert.timestamp" field in "DESC" order. Example: "[{\"property\":\"alert.timestamp\",\"direction\":\"DESC\"}]" | Optional | 
| filter | By default filters by "alert.timestamp" from 1996 to this date. Example: "[{\"property\":\"incidentId\", \"value\":\"INC-21\"}]" | Optional | 


#### Context Output

There is no context output for this command.


### netwitness-im-get-alert-details
***
Return single alert by id


#### Base Command

`netwitness-im-get-alert-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | Alert id | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netwitness.Alert.Id | unknown | Netwitness Alert ID | 
| Netwitness.Alert.Name | unknown | Netwitness Alert Name | 
| Netwitness.Alert.IncidentId | unknown | Id of Incident which caused to Alert | 
| Netwitness.Alert.Timestamp | unknown | Time of Alert | 
| Netwitness.Alert.HostSummary | unknown | Netwitness Alert Summary | 
| Netwitness.Alert.SignatureId | unknown | Singnature Id of Alert | 
| Netwitness.Alert.Source | unknown | Score of Alert | 
| Netwitness.Alert.Type | unknown | Type of Alert | 
| Netwitness.Alert.RiskScore | unknown | Risk score of Alert | 
| Netwitness.Alert.SourceCountry | unknown | Netwitness Alert Source Country | 
| Netwitness.Alert.DestinationCountry | unknown | Netwitness Alert Destination Country | 
| Netwitness.Alert.NumEvents | unknown | Netwitness Alert Evevts Number | 
| Netwitness.Alert.SourceIp | unknown | Netwitness Alert Source Ip | 
| Netwitness.Alert.DestonationIp | unknown | Netwitness Alert Destonation Ip | 
| Netwitness.Alert.DestonationPort | unknown | Netwitness Alert Destonation Port | 


### netwitness-im-get-event-details
***
Returns two entries. One is event details json and the second is


#### Base Command

`netwitness-im-get-event-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deviceId | [number] Id of the device where the events stored/occurred. In order to get list of available devices/components run command netwitness-im-get-components | Required | 
| eventId | [number] Id of the event | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netwitness.Event.EventId | unknown | Netwitness Event ID | 
| Netwitness.Event.DeviceId | unknown | Netwitness Event Device Id | 
| Netwitness.Event.ReconstructedContentType | unknown | Netwitness Event Reconstructed Content | 
| Netwitness.Event.PacketsTotal | unknown | Total Packets Netwitness Event | 
| Netwitness.Event.PacketsProcessed | unknown | Packets Processed in Current Event |


### netwitness-im-get-incident-details
***
Returns incident json by id


#### Base Command

`netwitness-im-get-incident-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | [number] ID of incident. Example: "INC-12" | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netwitness.Incident.Id | unknown | Netwitness Incident ID | 
| Netwitness.Incident.Name | unknown | Netwitness Incident Name | 
| Netwitness.Incident.Priority | unknown | Netwitness Incident Priority | 
| Netwitness.Incident.CreatedBy | unknown | User who created Netwitness Incident | 
| Netwitness.Incident.Summary | unknown | Netwitness Incident Summary | 
| Netwitness.Incident.Assignee | unknown | User Assigned To Incident | 
| Netwitness.Incident.Created | unknown | Time of Incident Creation | 
| Netwitness.Incident.FirstAlertTime | unknown | Time of Incident Creation | 
| Netwitness.Incident.LastUpdatedByUserName | unknown | User who was last to update Incident | 
| Netwitness.Incident.RiskScore | unknown | Netwitness Incident Risk Score | 
| Netwitness.Incident.AverageAlertRiskScore | unknown | Netwitness Incident Average Risk Score | 
| Netwitness.Incident.Categories | unknown | Netwitness Incident Category | 
| Netwitness.Incident.AlertCount | unknown | Netwitness Incident Alerts Counts |


### netwitness-im-get-alert-original
***
Returns the original events which this alert contains


#### Base Command

`netwitness-im-get-alert-original`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | Id of the alert | Required