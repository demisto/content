Freeing the analyst with autonomous decisions
This integration was integrated and tested with version 1.0.0 of SumoLogicSEC
## Configure SumoLogicSEC on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SumoLogicSEC.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Sumo Logic API Endpoint | https://api.&amp;lt;deployment&amp;gt;.sumologic.com/api/ | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Access ID |  | True |
    | Access Key |  | True |
    | Incidents Fetch Interval |  | False |
    | Fetch Limit | Fetch limit must not be greater than 20 | False |
    | Override default fetch query | Default fetch query is status:in\("new", "inprogress"\) | False |
    | First fetch time |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sumologic-sec-insight-get-details
***
Get Insight details for a specific Insight ID.


#### Base Command

`sumologic-sec-insight-get-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insight-id | The insight to retrieve details for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Id | unknown | The insight ID | 


#### Command Example
`!sumologic-sec-insight-get-details insight-id=INSIGHT-116`

#### Human Readable Output
Insight Details:
|Id|ReadableId|Name|Action|Status|Assignee|Description|LastUpdated|LastUpdatedBy|Severity|Closed|ClosedBy|Timestamp|Entity|Resolution|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| c6c97d84-983d-303e-a03b-86f53d657fc8 | INSIGHT-116 | Lateral Movement with Discovery and Credential Access |  | Closed |  | Initial Access, Lateral Movement, Discovery, Initial Access, Credential Access | 2021-05-10T23:48:10.016204 |  | HIGH | 2021-05-10T23:48:09.961023 | obfuscated@email.com | 2021-02-18T22:04:08.330000 | 1.2.3.4 | No Action |



### sumologic-sec-insight-get-comments
***
Get comments for a specific Insight ID. (Users can post and update comments on the Sumo Logic Cloud SIEM portal for any Insight ID.)


#### Base Command

`sumologic-sec-insight-get-comments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insight-id | The insight ID for which to retrieve comments. . | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
`!sumologic-sec-insight-get-comments insight-id=INSIGHT-116`

#### Human Readable Output
Insight Comments:
|Id|InsightId|Author|Body|LastUpdated|Timestamp|
|---|---|---|---|---|---|
| 2 | INSIGHT-116 | obfuscated@email.com | This is an example comment |  | 2021-04-23T00:38:43.977543 |



### sumologic-sec-signal-get-details
***
Get Signal details for a specific Signal ID. Signal details command references signals in Sumo Logic Cloud SIEM which are created when records exhibit suspicious properties and mate with patterns or other detection logic.


#### Base Command

`sumologic-sec-signal-get-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| signal-id | The signal to retrieve details for. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
`!sumologic-sec-signal-get-details signal-id=e0e7096b-2f91-5b72-b1a2-db48ce882dfc`

#### Human Readable Output
Signal Details:
|Id|Name|RuleId|Description|Severity|ContentType|Timestamp|Entity
|---|---|---|---|---|---|---|---|
| e0e7096b-2f91-5b72-b1a2-db48ce882dfc | Potential malicious JVM download | LEGACY-S00062 | A document was downloaded and opened followed by a file download using a Java user-agent. | 4 | RULE | 2021-02-18T22:04:08.230000 | 1.2.3.4


### sumologic-sec-entity-get-details
***
Get entity details for a specific entity ID


#### Base Command

`sumologic-sec-entity-get-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity-id | The entity to retrieve details for. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
`!sumologic-sec-entity-get-details entity-id=_hostname-win10--admin.obfuscated`

#### Human Readable Output
### Entity Details:
|Id|Name|FirstSeen|LastSeen|ActivityScore|IsWhitelisted|OperatingSystem|InventoryData
|---|---|---|---|---|---|---|---|
| _hostname-win10--admin.obfuscated | win10-admin.obfuscated |  | 2021-04-21T14:43:38.526000 | 9 | false | Windows 10 Enterprise | true |



### sumologic-sec-insight-search
***
Search insights using available filters


#### Base Command

`sumologic-sec-insight-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query string to search. | Optional | 
| offset | The number of items to skip before starting to collect the result set. Default is 0. | Optional | 
| limit | The maximum number of items to return. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
`!sumologic-sec-insight-search query="timestamp:>\"2021-02-01T05:00:00+00:00\" status:\"closed\" AND severity:>\"MEDIUM\"" limit=3`

#### Human Readable Output
Insights:
|Id|ReadableId|Name|Action|Status|Assignee|Description|LastUpdated|LastUpdatedBy|Severity|Closed|ClosedBy|Timestamp|Entity|Resolution|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 00853cdd-763e-3e31-a2e4-f74277922f9f | INSIGHT-220 | Command and Control with Defense Evasion and Execution |  | Closed |  | Initial Access, Command and Control, Defense Evasion, Execution | 2021-03-23T20:06:51.565599 |  | HIGH | 2021-03-23T20:06:51.511505 | obfuscated@email.com | 2021-02-22T16:27:51 | testcomputer.somedomain.net | No Action |
| eefdff8d-7447-3b47-83e0-66a0b210d618 | INSIGHT-219 | Discovery with Credential Access and Execution |  | Closed |  | Initial Access, Credential Access, Initial Access, Execution, Discovery, Credential Access | 2021-03-23T21:21:55.029798 |  | HIGH | 2021-03-23T21:21:54.914061 | obfuscated@email.com | 2021-02-22T16:24:07.959000 | 1.2.3.4 | No Action |
| 8a77d12e-5905-3401-ae7c-2e17b1fd3060 | INSIGHT-221 | Privilege Escalation with Persistence and Execution |  | Closed | obfuscated@email.com | Execution, Privilege Escalation, Persistence, Execution | 2021-05-12T21:47:08.297222 |  | HIGH | 2021-05-12T21:47:08.132251 | obfuscated@email.com | 2021-02-22T16:24:07.959000 | 5.6.7.8 | No Action |



### sumologic-sec-signal-search
***
Search signals using available filters


#### Base Command

`sumologic-sec-signal-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query string to search. | Optional | 
| offset | The number of items to skip before starting to collect the result set. Default is 0. | Optional | 
| limit | The maximum number of items to return. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
`!sumologic-sec-signal-search query="timestamp:NOW-7D..NOW name:contains(\"Internal\")"`

#### Human Readable Output
Signals:
|Id|Name|Entity|RuleId|Description|Severity|Stage|Timestamp|ContentType|Tags|
|---|---|---|---|---|---|---|---|---|---|
| b50fd570-341b-576d-85b5-8b5cd17c0aee | IP Address Scan - Internal | 1.2.3.4 | LEGACY-S00050 | A scan of IP addresses | 3 | Discovery | 2021-04-22T04:08:13.514000 | RULE | _mitreAttackTactic:TA0007,<br>_mitreAttackTactic:TA0043,<br>_mitreAttackTechnique:T1046,<br>_mitreAttackTechnique:T1595 |


### sumologic-sec-entity-search
***
Search entities using the available filters


#### Base Command

`sumologic-sec-entity-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query string to search. | Optional | 
| offset | The number of items to skip before starting to collect the result set. Default is 0. | Optional | 
| limit | The maximum number of items to return. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
`!sumologic-sec-entity-search query="type:\"ip\" activityScore:>=3"`

#### Human Readable Output
Entities:
|Id|Name|FirstSeen|LastSeen|ActivityScore|IsWhitelisted|OperatingSystem|InventoryData|
|---|---|---|---|---|---|---|---|
| _ip-specops_analysis_lab-1.2.3.4 | 1.2.3.4 |  | 2021-04-22T04:08:13.514000 | 3 | false |  | false |



### sumologic-sec-insight-set-status
***
Change status of Insight


#### Base Command

`sumologic-sec-insight-set-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insight-id | The insight to change status for. | Required | 
| status | The desired Insight status. Possible values are: new, inprogress, closed. Default is in-progress. | Optional | 
| resolution | Resolution for closing Insight. Valid values are: "Resolved", "False Positive", "No Action", "Duplicate". Possible values are: Resolved, False_Positive, No_Action, Duplicate. Default is Resolved. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
`!sumologic-sec-insight-set-status insight-id=INSIGHT-116 status=closed resolution="No Action"`

#### Human Readable Output
Insight Details:
|Id|ReadableId|Name|Action|Status|Assignee|Description|LastUpdated|LastUpdatedBy|Severity|Closed|ClosedBy|Timestamp|Entity|Resolution|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| c6c97d84-983d-303e-a03b-86f53d657fc8 | INSIGHT-116 | Lateral Movement with Discovery and Credential Access |  | Closed |  | Initial Access, Lateral Movement, Discovery, Initial Access, Credential Access | 2021-05-13T01:28:32.648352 |  | HIGH | 2021-05-13T01:28:32.580039 | obfuscated@email.com | 2021-02-18T22:04:08.330000 | 1.2.3.4 | No Action |


### sumologic-sec-match-list-get
***
Get match lists


#### Base Command

`sumologic-sec-match-list-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The number of items to skip before starting to collect the result set. Default is 0. | Optional | 
| limit | Number of match lists returned. Default is 10. | Optional | 
| sort | Sort expression. Default is name. | Optional | 
| sortDir | Sort direction. Possible values are: ASC, DESC. Default is ASC. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
`!sumologic-sec-match-list-get limit=3`

#### Human Readable Output
Match lists:
|Id|Name|TargetColumn|DefaultTtl|
|---|---|---|---|
| 173 | admin_ips | SrcIp | 0 |
| 24 | auth_servers | Ip |  |
| 162 | auth_servers_dst | DstIp |  |



### sumologic-sec-match-list-update
***
Add item to match list


#### Base Command

`sumologic-sec-match-list-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| match-list-id | ID of match list. | Required | 
| active | Item active or disabled. | Required | 
| description | Description of match list item. | Required | 
| expiration | Expiration of match list item, e.g. "2021-03-25T23:52:23.508Z". | Required | 
| value | Value of match list item. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
`!sumologic-sec-match-list-update match-list-id=166 description="My description" expiration=2021-04-25T22:36:10.925Z value="10.20.30.40" active=true`

#### Human Readable Output
Result:
|Result|Server response|
|---|---|
| Success | true |



### sumologic-sec-threat-intel-search-indicators
***
Search Threat Intel Indicators


#### Base Command

`sumologic-sec-threat-intel-search-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | A query string used to filter results. | Optional | 
| value | The value to search for. | Required | 
| offset | The number of items to skip before starting to collect the result set. Default is 0. | Optional | 
| limit | The numbers of items to return. Default is 10. | Optional | 
| sourceIds | Comma separated list of threat intelligence source IDs to search, e.g. 1,2,3. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
`!sumologic-sec-threat-intel-search-indicators value=1.2.3.4 sourceIds=54`

#### Human Readable Output
Threat Intel Indicators:
|Id|Value|Active|Expiration|
|---|---|---|---|
| f396ae69aa223c049ff639b3649ba1dd6465ec74397c3126916786bbcd6d76017468726561745f49705f44656d6973746f5f54657374 | 1.2.3.4 | true | 2021-04-29T00:00:00 |



### sumologic-sec-threat-intel-get-sources
***
Get Threat Intel Sources


#### Base Command

`sumologic-sec-threat-intel-get-sources`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The number of items to skip before starting to collect the result set. Default is 0. | Optional | 
| limit | The numbers of items to return. Default is 10. | Optional | 
| sort | Sort expression. Default is name. | Optional | 
| sortDir | Sort direction. Possible values are: ASC, DESC. Default is ASC. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
`!sumologic-sec-threat-intel-get-sources limit=3`

#### Human Readable Output
Threat intel sources:
|Id|Name|Description|SourceType|
|---|---|---|---|
| 35 | abuse.ch |  | CUSTOM |
| 25 | Alienvault OTX | Alienvault | TAXII |
| 24 | Anomali |  | TAXII |



### sumologic-sec-threat-intel-update-source
***
Add Threat Intel Indicator to Threat Intel Source


#### Base Command

`sumologic-sec-threat-intel-update-source`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat-intel-source-id | ID of Threat Intel Source. | Required | 
| active | Indicator active or disabled. Default is true. | Required | 
| description | Description of indicator. | Required | 
| expiration | Expiration of match list item, e.g. "2021-03-25T23:52:23.508Z". | Required | 
| value | Indicator value. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
`!sumologic-sec-threat-intel-update-source threat-intel-source-id=54 active=true value=1.2.3.4 description=test expiration=2021-04-29T00:00:00.000Z`

#### Human Readable Output
Result:
|Result|Server response|
|---|---|
| Success | true |
