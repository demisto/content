## Overview
---
The Illusive Attack Management API allows customers to retrieve detected incidents with a forensics timeline, attack surface insights, collect forensics on-demand, and manage a variety of operations with regard to deceptive entities, deception policies, and more.
This integration was integrated and tested with version 130 of IllusiveNetworks
## Configure IllusiveNetworks on Cortex XSOAR
## Use Cases
* Automatically collect data and forensics from new incidents detected by Illusive
* Enrich SOC data by retrieving a rich set of incident and forensics information, including: 1) host details and forensics from a potentially compromised host, 2) a forensics timeline, 3) forensics analysis, 4) additional data
* Auto-analyze collected data and calculate incident severity to speed up SOC response times
* Collect forensics from any compromised host and retrieve a forensics timeline
* Retrieve detailed lists of approved and suggested deceptive servers and users
* Approve, delete, and query deceptive entities
* Manage deception policy assignments per host
* Retrieve attack surface insights for Crown Jewels and specific hosts

## Configure IllusiveNetworks on Demisto
---
####Illusive Console
1. Open the Illusive Management console, navigate to Settings > General, and locate the API KEYS section. Generate a new API key with all permissions and copy the token at the end of the process.

####Demisto Console
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IllusiveNetworks.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| api_token | API Token | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| fetch_time | The initial time to fetch from | False |
| has_forensics | Fetch only incidents with forensics | True |

4. Click **Test** to validate the URLs, token, and connection.

## Fetched Incidents Data
---
{
 "sourceIp": "10.90.10.25", 
 "sourceOperatingSystem": null,
 "policyName": null,
 "incidentTypes": ["DECEPTION"],
 "riskInsights": {"stepsToDomainAdmin": null, "stepsToCrownJewel": null},
 "deceptionFamilies": ["FAMILY_TYPE_BROWSERS"],
 "lastSeenUser": null,
 "closed": false,
 "unread": true,
 "flagged": false,
 "hasForensics": false,
 "incidentId": 32,
 "incidentTimeUTC": "2020-05-04T11:37:10.231Z",
 "sourceHostname": null,
 "userNotes": null
 }
 
## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. illusive-get-forensics-timeline
2. illusive-get-asm-host-insight
3. illusive-get-asm-cj-insight
4. illusive-get-deceptive-users
5. illusive-get-deceptive-servers
6. illusive-is-deceptive-user
7. illusive-is-deceptive-server
8. illusive-add-deceptive-users
9. illusive-add-deceptive-servers
10. illusive-delete-deceptive-users
11. illusive-delete-deceptive-servers
12. illusive-assign-host-to-policy
13. illusive-remove-host-from-policy
14. illusive-run-forensics-on-demand
15. illusive-get-incidents
16. illusive-get-event-incident-id
17. illusive-get-incident-events
18. illusive-get-forensics-analyzers
19. illusive-get-forensics-triggering-process-info
20. illusive-get-forensics-artifacts

### illusive-get-forensics-timeline
***
Retrieve forensics timeline for a specific incident


#### Base Command

`illusive-get-forensics-timeline`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The desired incident ID | Required | 
| start_date | The starting date of the forensics timeline. | Optional | 
| end_date | The last date of the forensics timeline. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.Forensics.Evidence.details | String | The forensics evidence details | 
| Illusive.Forensics.Evidence.eventId | String | The event ID | 
| Illusive.Forensics.Evidence.id | String | The forensics evidence ID | 
| Illusive.Forensics.Evidence.source | String | The Evidence source | 
| Illusive.Forensics.Evidence.starred | Boolean | Whether the forensics evidence has been starred | 
| Illusive.Forensics.Evidence.time | Date | Date and time of the forensics evidence  | 
| Illusive.Forensics.Evidence.title | String | The forensics evidence description | 
| Illusive.Forensics.IncidentId | String | The Incident Id | 
| Illusive.Forensics.Status | String | The process progress \( Done, InProgress\) | 
| Illusive.Forensics.Evidence.date | Date | The forensics evidence date | 


#### Command Example
illusive-get-forensics-timeline incident_id=80 start_date="10 days" end_date="3 hours"

#### Human Readable Output
|date|details|eventId|id|source|starred|time|title|type|
|---|---|---|---|---|---|---|---|---|
| 2020-06-29 09:16:17.480 | id: 4<br/>date: 2020-06-29 09:16:17.480<br/>type: LOGIN<br/>sourceIP: 172.27.102.12<br/>trap: hr<br/>injectedUserName: dgffg<br/>injectedPassword: **********<br/>destinationIpAddress: 172.27.102.6<br/>serviceType: WEB<br/>data: Is Successful Login: false,<br/>Accept-language: en-US,en;q=0.9,<br/>Web Protocol: HTTP,<br/>Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,<br/>Web Host: 172.27.102.6,<br/>Web Url: /,<br/>Authorization: Digest username="dgffg", realm="Domain Name", nonce="1593422172658:ad3f7cc0c86b52747fba1d68583c3827", uri="/", response="9f5d4174395c7d09460fc88e454713aa", opaque="9AC5ADA4A6317F9FB4F2B1211D8A7EFE", qop=auth, nc=00000002, cnonce="b000143183c56904",<br/>Web Body: ,<br/>Web Method: GET,<br/>Upgrade-insecure-requests: 1,<br/>Web User Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36,<br/>Connection: keep-alive,<br/>Cache-control: max-age=0,<br/>Accept-encoding: gzip, deflate<br/>hasForensics: No<br/>title: WEB login attempt with the username dgffg to the deceptive URL 172.27.102.6/ | 4 | d59f0b0a-4a66-40d0-9565-563adc7534f1 | MANAGEMENT | false | 1593422177480 | WEB login attempt with the username dgffg to the deceptive URL 172.27.102.6/ | EVENT |

### illusive-get-asm-host-insight
***
Retrieve the specified host insights from Attack Surface Manager


#### Base Command

`illusive-get-asm-host-insight`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostnameOrIp | The hostname or IP address of the desired host | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.AttackSurfaceInsightsHost.DomainName | String | The host domain | 
| Illusive.AttackSurfaceInsightsHost.HostName | String | The host hostname | 
| Illusive.AttackSurfaceInsightsHost.HostType | String | The host type \(Server, Workstation, Other\) | 
| Illusive.AttackSurfaceInsightsHost.IpAddresses | String | The host IP address | 
| Illusive.AttackSurfaceInsightsHost.OperatingSystemName | String | The host operating system name | 
| Illusive.AttackSurfaceInsightsHost.OperatingSystemVersion | String | The host operating system version | 
| Illusive.AttackSurfaceInsightsHost.OrganizationalUnit | String | The host Active Directory Organizational Unit | 
| Illusive.AttackSurfaceInsightsHost.SourceConnectivityExposure | Number | The host Source Connectivity Exposure to crown jewels and domain user credentials | 


##### Command Example
---
illusive-get-asm-host-insight hostnameOrIp=172.27.139.12

##### Human Readable Output
### Illusive ASM Host Insights
|domainName|hostName|hostType|ipAddresses|operatingSystemName|operatingSystemVersion|organizationalUnit|sourceConnectivityExposure|
|---|---|---|---|---|---|---|---|
| illusive.com | win5.illusive.com | Workstation | 172.27.139.12,::1,fe80::ffff:ffff:fffe,fe80::2d2d:5763:8c1a:7b9 | Windows 10 |  | clients | 0.0 |

### illusive-get-asm-cj-insight
***
Retrieve Crown-Jewels insights from Attack Surface Manager


#### Base Command

`illusive-get-asm-cj-insight`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.AttackSurfaceInsightsCrownJewel.data | Unknown | The number of connections to this Crown Jewel per service type | 
| Illusive.AttackSurfaceInsightsCrownJewel.hostname | String | The crown jewel hostname | 
| Illusive.AttackSurfaceInsightsCrownJewel.machineTagAndSubTags.tag | String | The List of a crown jewel category and subcategory couplings | 
| Illusive.AttackSurfaceInsightsCrownJewel.MachineTagAndSubTags.subTag | String | The List of a crown jewel category and subcategory couplings | 
| Illusive.AttackSurfaceInsightsCrownJewel.targetExposureRank | Number | The crown jewel target exposure | 


##### Command Example
illusive-get-asm-cj-insight

##### Human Readable Output
### Illusive ASM Crown Jewels Insights
|data|hostname|machineTagAndSubTags|targetExposureRank|
|---|---|---|---|
| {'key': 'RDP', 'value': 1} | 172.27.139.12 | {'tag': 'Mainframe', 'subTag': 'MAINFRAME'} | 0.0 |


### illusive-get-deceptive-users
***
Retrieve a list of all deceptive users


#### Base Command

`illusive-get-deceptive-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The status of the desired deceptive users (APPROVED, SUGGESTED, ALL) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.DeceptiveUser.userName | String | The deceptive user name | 
| Illusive.DeceptiveUser.domainName | String | The deceptive user domain | 
| Illusive.DeceptiveUser.policyNames | Unknown | The deception policies the deceptive user is assigned to | 
| Illusive.DeceptiveUser.password | String | The deceptive user password | 
| Illusive.DeceptiveUser.deceptiveState | String | The deceptive user state \(APPROVED, SUGGESTED, ALL\) | 
| Illusive.DeceptiveUser.adUser | Boolean | Whether the deceptive user is a genuine user in Active Directory | 
| Illusive.DeceptiveUser.activeUser | Boolean | In case the deceptive user is a real AD user, indicates whether he is active | 


##### Command Example
!illusive-get-deceptive-users type=APPROVED

##### Human Readable Output
### Illusive Deceptive Users
|activeUser|adUser|deceptiveState|domainName|password|policyNames|username|
|---|---|---|---|---|---|---|
| false | false | APPROVED | illusive.com | Password | Full Protection | user1 |
| false | false | APPROVED | illusive.com | Password | Full Protection | user2 |


### illusive-get-deceptive-servers
***
Retrieve a list of all deceptive servers


#### Base Command

`illusive-get-deceptive-servers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The status of the desired deceptive servers (APPROVED, SUGGESTED, ALL) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.DeceptiveServer.host | String | The deceptive server hostname | 
| Illusive.DeceptiveServer.policyNames | String | The deception policies the deceptive server is assigned to | 
| Illusive.DeceptiveServer.adHost | Boolean | Whether the deceptive server is a genuine machine in Active Directory | 
| Illusive.DeceptiveServer.deceptiveState | String | The deceptive server state \(APPROVED, SUGGESTED, ALL\) | 
| Illusive.DeceptiveServer.serviceTypes | String | The deception services the deceptive server is assigned to | 


##### Command Example
!illusive-get-deceptive-servers type=APPROVED

##### Human Readable Output
### Illusive Deceptive Servers
|adHost|deceptiveState|host|policyNames|serviceTypes|
|---|---|---|---|---|
| false | APPROVED | server1.illusive.com | adiPo,<br/>Full Protection | SHARE,<br/>DB |
| false | APPROVED | server2.illusive.com | Full Protection | WEB,<br/>DB |
| false | APPROVED | server3.illusive.com | adiPo,<br/>Full Protection | FTP,<br/>SHARE,<br/>DB |


### illusive-is-deceptive-user
***
Retrieve whether a specified user is deceptive


#### Base Command

`illusive-is-deceptive-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username to be verified | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.IsDeceptive.Username | String | The checked username | 
| Illusive.IsDeceptive.IsDeceptiveUser | Boolean | Is the specified user conducted as a deceptive user | 


##### Command Example
!illusive-is-deceptive-user username=user1

##### Human Readable Output
### Illusive Is Deceptive
|IsDeceptiveUser|Username|
|---|---|
| true | user1 |


### illusive-is-deceptive-server
***
Retrieve whether a specified server is deceptive


#### Base Command

`illusive-is-deceptive-server`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The server hostname to be verified | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.IsDeceptive.IsDeceptiveServer | Boolean | Is the specified server conducted as a deceptive server | 
| Illusive.IsDeceptive.Hostname | String | The checked server hostname | 


##### Command Example
!illusive-is-deceptive-server hostname=server5.illusive.com

##### Human Readable Output
### Illusive Is Deceptive
|Hostname|IsDeceptiveServer|
|---|---|
| server5.illusive.com | false |


### illusive-add-deceptive-users
***
Add or approve deceptive users


#### Base Command

`illusive-add-deceptive-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | The deceptive user domain | Required | 
| password | The deceptive user password | Required | 
| policy_names | The deception policies to be assigned to the new deceptive user | Optional | 
| username | The deceptive user name | Required | 


#### Context Output

There is no context output for this command.

##### Command Example
!illusive-add-deceptive-users domain_name=illusive.com password=pass username=user3

##### Human Readable Output
### Illusive Add Deceptive User Succeeded
|domainName|password|policyNames|userName|
|---|---|---|---|
| illusive.com | pass | All Policies | user3 |


### illusive-add-deceptive-servers
***
Add or approve deceptive servers


#### Base Command

`illusive-add-deceptive-servers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The deceptive server hostname | Required | 
| policy_names | The deception policies to be assigned to the new deceptive server | Optional | 
| service_types | The deception services to be assigned to the new deceptive server | Required | 


#### Context Output

There is no context output for this command.

##### Command Example
!Set key="serviceTypes" value="FTP"

!Set key="serviceTypes" value="SSH" append=true

!illusive-add-deceptive-servers host=server4.illusive.com service_types=${serviceTypes}

##### Human Readable Output
### Illusive Add Deceptive Server Succeeded
|host|policyNames|serviceTypes|
|---|---|---|
| server4.illusive.com | All Policies | FTP,<br/>SSH |


### illusive-delete-deceptive-users
***
Delete deceptive users


#### Base Command

`illusive-delete-deceptive-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deceptive_users | The list of deceptive users to delete | Required | 


#### Context Output

There is no context output for this command.

##### Command Example
!illusive-delete-deceptive-users deceptive_users=user3

##### Human Readable Output
###  Deceptive User ['user3'] was successfully Deleted



### illusive-delete-deceptive-servers
***
Delete deceptive servers


#### Base Command

`illusive-delete-deceptive-servers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deceptive_hosts | The list of deceptive servers to delete | Required | 


#### Context Output

There is no context output for this command.

##### Command Example

!Set key="servers" value="server5.illusive.com"

!Set key="servers" value="server1.illusive.com" append=true

!illusive-delete-deceptive-servers deceptive_hosts=${servers}

##### Human Readable Output
###Deceptive Servers ['server5.illusive.com', 'server1.illusive.com'] were successfully Deleted



### illusive-assign-host-to-policy
***
Assign a deception policy to domain hosts


#### Base Command

`illusive-assign-host-to-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy name to assign | Required | 
| hosts | List of hosts to assign, in the following format: machine@domain.<br/>Maximum number of hosts is 1000. | Required | 


#### Context Output

There is no context output for this command.

##### Command Example
!illusive-assign-host-to-policy hosts=WIN7@illusive.com policy_name="Full Protection"

##### Human Readable Output
### Illusive Assign Machines to Policy Succeeded
|hosts|isAssigned|policy_name|
|---|---|---|
| WIN7@illusive.com | true | Full Protection |


### illusive-remove-host-from-policy
***
Remove deception policy assignment from domain hosts


#### Base Command

`illusive-remove-host-from-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hosts | List of hosts to remove policy assignment from, in the following format: machine@domain.<br/>Maximum number of hosts is 1000 | Required | 


#### Context Output

There is no context output for this command.

##### Command Example
!illusive-remove-host-from-policy hosts=WIN7@illusive.com

##### Human Readable Output
### Illusive Remove Machines from All Policies Succeeded
|hosts|isAssigned|policy_name|
|---|---|---|
| WIN7@illusive.com | false |  |


### illusive-run-forensics-on-demand
***
Collect forensics on a specified host and retrieve the forensics timeline


#### Base Command

`illusive-run-forensics-on-demand`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fqdn_or_ip | The host fqdn or IP address on which to collect forensics | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.Event.eventId | Number | The created event ID of the operation  | 



##### Command Example
!illusive-run-forensics-on-demand fqdn_or_ip=172.27.139.12

##### Human Readable Output
### Illusive Run Forensics On Demand
|eventId|
|---|
| 123 |


### illusive-get-incidents
***
Retrieve incidents


#### Base Command

`illusive-get-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The desired incident ID to retrieve.<br/>If specified - other arguments are ignored and only a single incident can be retrieved<br/> | Optional | 
| hostnames | The list of hostnames to retrieve incidents | Optional | 
| has_forensics | Whether to retrieve incidents with forensics only | Optional | 
| limit | Use offset and limit for pagination.<br/>The maximum limit is 100. | Optional | 
| offset | Use offset and limit for pagination. | Optional | 
| start_date | start date | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.Incident.closed | Boolean | Whether the incident has been closed | 
| Illusive.Incident.deceptionFamilies | String | The deception families of the
deceptions used to trigger
the incident | 
| Illusive.Incident.flagged | Boolean | Whether the incident has been flagged | 
| Illusive.Incident.hasForensics | Boolean | Whether incident has forensics | 
| Illusive.Incident.incidentId | Number | The Incident ID | 
| Illusive.Incident.incidentTimeUTC | Date | Date and time of the incident | 
| Illusive.Incident.incidentTypes | Unknown | Type of events detected | 
| Illusive.Incident.lastSeenUser | String | The user who last reviewed the incident | 
| Illusive.Incident.policyName | String | The compromised host's policy | 
| Illusive.Incident.riskInsights.stepsToCrownJewel | Number | The compromised host's lateral distance from Crown Jewels | 
| Illusive.Incident.riskInsights.stepsToDomainAdmin | Number | The compromised host's lateral distance from domain admin accounts | 
| Illusive.Incident.sourceHostname | String | The compromised host's name | 
| Illusive.Incident.sourceIp | String | The compromised host's IP address | 
| Illusive.Incident.sourceOperatingSystem | String | The compromised host's operating system | 
| Illusive.Incident.unread | Boolean | Whether the incident has been read | 
| Illusive.Incident.userNotes | String | The analyst's comments | 


##### Command Example
!illusive-get-incidents incident_id=28

##### Human Readable Output
### Illusive Incidents
|closed|deceptionFamilies|flagged|hasForensics|incidentId|incidentTimeUTC|incidentTypes|lastSeenUser|policyName|riskInsights|sourceHostname|sourceIp|sourceOperatingSystem|unread|userNotes|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| false | FAMILY_TYPE_BROWSERS | false | false | 28 | 2020-04-20T06:44:33.207Z | DECEPTION |  |  | stepsToDomainAdmin: null<br/>stepsToCrownJewel: null |  | 172.27.139.14 |  | false |  |


### illusive-get-event-incident-id
***
Retrieve the incident ID of an event


#### Base Command

`illusive-get-event-incident-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The Event id | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.Event.incidentId | Number | The Incident ID | 
| Illusive.Event.eventId | Number | The given event ID | 
| Illusive.Event.status | String | The status command \( Done, InProgress\) | 


##### Command Example
!illusive-get-event-incident-id event_id=80

##### Human Readable Output
### Illusive Get Incident
|eventId|incidentId|status|
|---|---|---|
| 80 | 72 | Done |


### illusive-get-incident-events
***
Retrieve all the events that are associated with an incident


#### Base Command

`illusive-get-incident-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID on which to retrieve the associated events | Required | 
| limit | The maximum number of events to retrieve | Optional | 
| offset | Use offset and limit for pagination | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.Incident.incidentId | Number | The corresponding incident ID | 
| Illusive.Incident.eventsNumber | Number | The number of associated events | 
| Illusive.Incident.Event.eventId | Number | The event ID | 
| Illusive.Incident.Event.eventTimeUTC | Date | The event time | 
| Illusive.Incident.Event.hasForensics | Boolean | Whether the event has forensics | 


#### Command Example
!illusive-get-incident-events incident_id=2

#### Human Readable Output
### Illusive get incident's events
|eventId|eventTimeUTC|hasForensics|
|---|---|---|
| 4 | 2020-06-29T09:16:17.480Z | false |
| 3 | 2020-06-29T09:16:17.464Z | false |
| 2 | 2020-06-29T09:16:12.673Z | false |



### illusive-get-forensics-analyzers
***
Retrieve Illusive's forensics analyzers on a certain event


#### Base Command

`illusive-get-forensics-analyzers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The event ID to retrieve the forensics analyzers from | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.Event.incidentId | Number | The corresponding incident ID | 
| Illusive.Event.eventId | Number | The corresponding event ID | 
| Illusive.Event.ForensicsAnalyzers.analyzerName | String | The forensics analyzer name | 
| Illusive.Event.ForensicsAnalyzers.analyzerValue | String | The forensics analyzer description | 


#### Command Example
!illusive-get-forensics-analyzers event_id=2

#### Human Readable Output
### Illusive Forensics Analyzers
|analyzerName|analyzerValue|
|---|---|
| Summary | An attempt to browse to the deceptive URL hr (172.27.102.6) was detected from 172.27.102.12 |
| Event Source And Destination | Event ID: 2<br/>Event time: 2020-06-29T09:16:12.673Z<br/>Event originated from 172.27.102.12<br/>Event targeted hr (172.27.102.6)<br/> |
| Web | A GET request was made to the url `http://172.27.102.6/` |
| Forensics Failure Reason | No resolving for host 172.27.102.12 |



### illusive-get-forensics-triggering-process-info
***
Retrieve the triggering process information from Illusive's forensics


#### Base Command

`illusive-get-forensics-triggering-process-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The event ID to retrieve the triggering process information from | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illusive.Event.incidentId | Number | The corresponding incident ID | 
| Illusive.Event.eventId | Number | The corresponding event ID | 
| Illusive.Event.ForensicsTriggeringProcess.commandLine | String | The triggering process command line | 
| Illusive.Event.ForensicsTriggeringProcess.connectionsNum | Number | The triggering process active connections | 
| Illusive.Event.ForensicsTriggeringProcess.md5 | String | The triggering process md5 | 
| Illusive.Event.ForensicsTriggeringProcess.sha256 | String | The triggering process sha256 | 
| Illusive.Event.ForensicsTriggeringProcess.name | String | The triggering process name | 
| Illusive.Event.ForensicsTriggeringProcess.parent | String | The parent process of the triggering process | 
| Illusive.Event.ForensicsTriggeringProcess.path | String | The triggering process path | 
| Illusive.Event.ForensicsTriggeringProcess.startTime | Date | The triggering process start time | 


#### Command Example
!illusive-get-forensics-triggering-process-info event_id=5

#### Human Readable Output
### Illusive Triggering Processes Info
|commandLine|connectionsNum|md5|name|parent|path|sha256|startTime|
|---|---|---|---|---|---|---|---|
| "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=utility --field-trial-handle=1472,8764100348922490764,5250110531070070503,131072 --lang=en-US --service-sandbox-type=network --enable-audio-service-sandbox --mojo-platform-channel-handle=1900 /prefetch:8 | 15 | 9E46D108805A743D2D88D04019370A05 | chrome.exe | chrome.exe(7848) | C:\Program Files (x86)\Google\Chrome\Application\chrome.exe | D7771E5F5090EF37BE554D5DD9E1C24C8CD83EBF284C48CC5D1EF45D02C0E77F | 2020-06-29T09:16:47.245+00:00 |


### illusive-get-forensics-artifacts
***
Retrieve forensics artifacts from Illusive's forensics


#### Base Command

`illusive-get-forensics-artifacts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The event ID to retrieve the forensics artifacts from | Required | 
| artifact_type | The type of forensics artifact to retrieve  | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
!illusive-get-forensics-artifacts event_id=2

#### Human Readable Output
### event id 2 has no artifacts

