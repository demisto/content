Freeing the analyst with autonomous decisions.
This integration was integrated and tested with version 6.1.0 of SumoLogicSEC.

## Prerequisites
Only use this integration if your Cloud SIEM portal url ends with `.sumologic.com` - this can be verified via the url in your browser when logged into Cloud SIEM.

You'll need an access key in order to complete the instance setup. Instructions on how to generate access keys can be found [here](https://help.sumologic.com/Manage/Security/Access-Keys).

## Configure SumoLogicSEC in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Sumo Logic API Endpoint | https://api.&amp;lt;deployment&amp;gt;.sumologic.com/api/ | True |
| Sumo Logic Instance Endpoint | For the incident field sumoURL link to work, e.g: https://&amp;lt;yoursubdomain&amp;gt;.&amp;lt;deployment&amp;gt;.sumologic.com | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Access ID |  | True |
| Access Key |  | True |
| Incidents Fetch Interval |  | False |
| Fetch Limit | Fetch limit of Sumo Logic insights | False |
| Override default fetch query | Default fetch query is status:in\("new", "inprogress"\) | False |
| First fetch time |  | False |
| Pull associated Sumo Logic signals | Whether to pull the Sumo Logic Signals associated with the Insights as Cortex XSOAR incidents | False |
| Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from Sumo Logic SIEM to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to Sumo Logic SIEM\), or Incoming and Outgoing \(from/to Cortex XSOAR and Sumo Logic SIEM\). | False |
| Close Mirrored Cortex XSOAR Incident (Incoming Mirroring) | When selected, closing the Sumo Logic Insight with a "Closed" status will close the Cortex XSOAR incident. | False |
| Close Mirrored Sumo Logic Insight (Outgoing Mirroring) | When selected, closing the Cortex XSOAR incident will close the Sumo Logic Insight in SIEM. | False |
| Override Record Summary Fields | Record Summary Fields included when fetching Insights (override default) | False |


## API documentation and query examples

For commands with query parameter input the available fields and operators are documented in API docs. These docs are useful when executing queries using the following commands:
- `sumologic-sec-insight-search`
- `sumologic-sec-signal-search`
- `sumologic-sec-entity-search`

To access the API documentation, select the link for your deployment from [here](https://help.sumologic.com/APIs#documentation). Add `sec` to the end of the url to access Cloud SIEM API docs - e.g. `https://api.us2.sumologic.com/docs/sec/`.

Example: Insight search query ['q' parameter](https://api.us2.sumologic.com/docs/sec/#/paths/~1insights/get): 

> The search query string in our custom DSL that is used to filter the results.
> 
> Operators:
> - `exampleField:"bar"`: The value of the field is equal to "bar".
> - `exampleField:in("bar", "baz", "qux")`: The value of the field > is equal to either "bar", "baz", or "qux".
> - `exampleTextField:contains("foo bar")`: The value of the field > contains the phrase "foo bar".
> - `exampleNumField:>5`: The value of the field is greater than 5. There are similar `<`, `<=`, and `>=` operators.
> - `exampleNumField:5..10`: The value of the field is between 5 and 10 (inclusive).
> - `exampleDateField:>2019-02-01T05:00:00+00:00`: The value of the date field is after 5 a.m. UTC time on February 2, 2019.
> - `exampleDateField:2019-02-01T05:00:00+00:00..2019-02-01T08:00:00+00:00`: The value of the date field is between 5 a.m. and 8 a.m. UTC time on February 2, 2019.
> 
> Fields:
> - `id`
> - `readableId`
> - `status`
> - `name`
> - `insightId`
> - `description`
> - `created`
> - `timestamp`
> - `closed`
> - `assignee`
> - `entity.ip`
> - `entity.hostname`
> - `entity.username`
> - `entity.type`
> - `enrichment`
> - `tag`
> - `severity`
> - `resolution`
> - `ruleId`
> - `records`

## Migrating from JASK content pack

The table below shows differences between this integration and the legacy JASK integration:

| JASK (legacy) | Sumo Logic Cloud SIEM | Notes |
| - | - | - |
| jask-get-insight-details | sumologic-sec-insight-get-details | |
| jask-get-insight-comments | sumologic-sec-insight-get-comments | |
| jask-get-signal-details | sumologic-sec-signal-get-details | |
| jask-get-entity-details | sumologic-sec-entity-get-details | |
| ~~jask-get-related-entities~~ | | Deprecated |
| ~~jask-get-whitelisted-entities~~ | | Deprecated - use command `sumologic-sec-entity-search` with filter `whitelisted:"true"` |
| jask-search-insights | sumologic-sec-insight-search | |
| jask-search-entities | sumologic-sec-entity-search | |
| jask-search-signals | sumologic-sec-signal-search | |

### New commands introduced in Sumo Logic Cloud SIEM pack

 - `sumologic-sec-insight-set-status`
 - `sumologic-sec-match-list-get`
 - `sumologic-sec-match-list-update`
 - `sumologic-sec-threat-intel-search-indicators`
 - `sumologic-sec-threat-intel-get-sources`
 - `sumologic-sec-threat-intel-update-source`


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sumologic-sec-insight-get-details
***
Get Insight details for a specific Insight ID.


#### Base Command

`sumologic-sec-insight-get-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insight_id | The insight to retrieve details for. | Required | 
| record_summary_fields | Record Summary Fields to include in the output (override default fields). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.Insight.Assignee | string | User or team assigned to the Insight | 
| SumoLogicSec.Insight.Closed | Date | Closed date | 
| SumoLogicSec.Insight.ClosedBy | String | Closed by user | 
| SumoLogicSec.Insight.Created | Date | Created date | 
| SumoLogicSec.Insight.Description | String | Description of the Insight | 
| SumoLogicSec.Insight.Entity | String | Entity name associated with the Insight | 
| SumoLogicSec.Insight.Id | String | The ID of the Insight | 
| SumoLogicSec.Insight.LastUpdated | Date | The time the Insight was last updated | 
| SumoLogicSec.Insight.LastUpdatedBy | string | The last user to update the Insight | 
| SumoLogicSec.Insight.Name | String | The name of the Insight | 
| SumoLogicSec.Insight.ReadableId | String | The ID of the Insight in readable form | 
| SumoLogicSec.InsightList.RecordSummaryFields | Array | Record Summary Fields associated with the Insight | 
| SumoLogicSec.Insight.Resolution | String | Resolution for closed Insight | 
| SumoLogicSec.Insight.Severity | String | The severity of the Insight | 
| SumoLogicSec.Insight.Signals.contentType | String | Type of content that triggered the Signal | 
| SumoLogicSec.Insight.Signals.description | String | Description of the Signal | 
| SumoLogicSec.Insight.Signals.id | String | The ID of the Signal | 
| SumoLogicSec.Insight.Signals.name | String | The name of the Signal | 
| SumoLogicSec.Insight.Signals.recordCount | Number | Number of records associated with the Signal | 
| SumoLogicSec.Insight.Signals.ruleId | String | Rule ID associated with the Signal | 
| SumoLogicSec.Insight.Signals.severity | Number | The severity of the Signal | 
| SumoLogicSec.Insight.Signals.stage | String | The stage of the Signal | 
| SumoLogicSec.Insight.Signals.timestamp | Date | Signal timestamp | 
| SumoLogicSec.Insight.Source | String | The source of the Insight | 
| SumoLogicSec.Insight.Status | String | The status of the Insight | 
| SumoLogicSec.Insight.TimeToDetection | Number | Insight time to detection | 
| SumoLogicSec.Insight.TimeToRemediation | Number | Insight time to remediation | 
| SumoLogicSec.Insight.TimeToResponse | Number | Insight time to response | 
| SumoLogicSec.Insight.Timestamp | Date | Insight timestamp | 


#### Command Example
`!sumologic-sec-insight-get-details insight-id=INSIGHT-116`

#### Human Readable Output
Insight Details:
|Id|Readable Id|Name|Action|Status|Assignee|Description|Last Updated|Last Updated By|Severity|Closed|Closed By|Timestamp|Entity|Resolution|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| c6c97d84-983d-303e-a03b-86f53d657fc8 | INSIGHT-116 | Lateral Movement with Discovery and Credential Access |  | Closed |  | Initial Access, Lateral Movement, Discovery, Initial Access, Credential Access | 2021-05-10T23:48:10.016204 |  | HIGH | 2021-05-10T23:48:09.961023 | obfuscated@email.com | 2021-02-18T22:04:08.330000 | 1.2.3.4 | No Action |



### sumologic-sec-insight-get-comments
***
Get comments for a specific Insight ID. (Users can post and update comments on the Sumo Logic Cloud SIEM portal for any Insight ID.)


#### Base Command

`sumologic-sec-insight-add-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insight_id | The insight ID for which to add a comment. | Required |
| comment | The comment to be added. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.InsightComments.Id | String | ID of comment |
| SumoLogicSec.InsightComments.Body | String | Comment contents |
| SumoLogicSec.InsightComments.Author | String | User that created the comment |
| SumoLogicSec.InsightComments.Timestamp | Date | Comment created timestamp |
| SumoLogicSec.InsightComments.InsightId | String | The ID of the Insight |


#### Command Example
`!sumologic-sec-insight-add-comment insight-id=INSIGHT-116 comment="This is an example comment"`

#### Human Readable Output
Insight Comment:
|Id|Insight Id|Author|Body|Last Updated|Timestamp|
|---|---|---|---|---|---|
| 2 | INSIGHT-116 | obfuscated@email.com | This is an example comment |  | 2021-04-23T00:38:43.977543 |



### sumologic-sec-insight-get-comments
***
Get comments for a specific Insight ID. (Users can post and update comments on the Sumo Logic Cloud SIEM portal for any Insight ID.)


#### Base Command

`sumologic-sec-insight-get-comments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insight_id | The insight ID for which to retrieve comments. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.InsightComments.Id | String | ID of comment | 
| SumoLogicSec.InsightComments.Body | String | Comment contents | 
| SumoLogicSec.InsightComments.Author | String | User that created the comment | 
| SumoLogicSec.InsightComments.Timestamp | Date | Comment created timestamp | 
| SumoLogicSec.InsightComments.InsightId | String | The ID of the Insight | 


#### Command Example
`!sumologic-sec-insight-get-comments insight-id=INSIGHT-116`

#### Human Readable Output
Insight Comments:
|Id|Insight Id|Author|Body|Last Updated|Timestamp|
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
| signal_id | The signal to retrieve details for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.Signal.ContentType | String | Type of content that triggered the Signal | 
| SumoLogicSec.Signal.Description | String | Description of the Signal | 
| SumoLogicSec.Signal.Entity | String | Entity name associated with the Signal | 
| SumoLogicSec.Signal.Id | String | The ID of the Signal | 
| SumoLogicSec.Signal.Name | String | The name of the Signal | 
| SumoLogicSec.Signal.RecordCount | Number | Number of records associated with the Signal | 
| SumoLogicSec.Signal.RuleId | String | Rule ID associated with the Signal | 
| SumoLogicSec.Signal.Severity | Number | The severity of the Signal | 
| SumoLogicSec.Signal.Stage | String | The stage of the Signal | 
| SumoLogicSec.Signal.Suppressed | Boolean | Whether or not the Signal was suppressed | 
| SumoLogicSec.Signal.Timestamp | Date | Signal timestamp | 


#### Command Example
`!sumologic-sec-signal-get-details signal-id=e0e7096b-2f91-5b72-b1a2-db48ce882dfc`

#### Human Readable Output
Signal Details:
|Id|Name|Rule Id|Description|Severity|Content Type|Timestamp|Entity
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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.Entity.ActivityScore | Number | Entity Activity Score | 
| SumoLogicSec.Entity.FirstSeen | Date | When the Entity was first seen | 
| SumoLogicSec.Entity.Hostname | String | Entity hostname | 
| SumoLogicSec.Entity.Id | String | Entity ID | 
| SumoLogicSec.Entity.IsWhitelisted | Boolean | Whether or not the Entity is on allow list | 
| SumoLogicSec.Entity.LastSeen | Date | When the Entity was last seen | 
| SumoLogicSec.Entity.Name | String | The Entity name | 
| SumoLogicSec.Entity.OperatingSystem | String | Entity Operating System \(observed or from inventory\) | 
| SumoLogicSec.Entity.InventoryData | Boolean | Whether or not this Entity was ingested from inventory e.g. Active Directory | 


#### Command Example
`!sumologic-sec-entity-get-details entity-id=_hostname-win10--admin.obfuscated`

#### Human Readable Output
### Entity Details:
|Id|Name|First Seen|Last Seen|Activity Score|Is Whitelisted|Operating System|Inventory Data
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
| query | Use a query string to search, see API documentation for more details. | Optional | 
| created | When the insight was created. Defaults to 'All time' if no time arguments are specified. Possible values are: All time, Last week, Last 48 hours, Last 24 hours. | Optional | 
| status | Comma separated list of values from the options: new,inprogress,closed. | Optional | 
| asignee | User assigned to Insights. | Optional | 
| offset | The number of items to skip before starting to collect the result set. Default is 0. | Optional | 
| limit | The maximum number of items to return. Default is 10. | Optional | 
| record_summary_fields | Record Summary Fields to include in the output (override default fields). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.InsightList.Assignee | String | User or team assigned to the Insight | 
| SumoLogicSec.InsightList.Closed | Date | Closed date | 
| SumoLogicSec.InsightList.ClosedBy | String | Closed by user | 
| SumoLogicSec.InsightList.Created | Date | Created date | 
| SumoLogicSec.InsightList.Description | String | Description of the Insight | 
| SumoLogicSec.InsightList.Entity | String | Entity name associated with the Insight | 
| SumoLogicSec.InsightList.Id | String | The ID of the Insight | 
| SumoLogicSec.InsightList.LastUpdated | Date | The time the Insight was last updated | 
| SumoLogicSec.InsightList.LastUpdatedBy | String | The last user to update the Insight | 
| SumoLogicSec.InsightList.Name | String | The name of the Insight | 
| SumoLogicSec.InsightList.ReadableId | String | The ID of the Insight in readable form | 
| SumoLogicSec.InsightList.RecordSummaryFields | Array | Record Summary Fields associated with the Insight | 
| SumoLogicSec.InsightList.Resolution | String | Resolution for closed Insight | 
| SumoLogicSec.InsightList.Severity | String | The severity of the Insight | 
| SumoLogicSec.InsightList.Signals.contentType | String | Type of content that triggered the Signal | 
| SumoLogicSec.InsightList.Signals.description | String | Description of the Signal | 
| SumoLogicSec.InsightList.Signals.id | String | The ID of the Signal | 
| SumoLogicSec.InsightList.Signals.name | String | The name of the Signal | 
| SumoLogicSec.InsightList.Signals.recordCount | Number | Number of records associated with the Signal | 
| SumoLogicSec.InsightList.Signals.ruleId | String | Rule ID associated with the Signal | 
| SumoLogicSec.InsightList.Signals.severity | Number | The severity of the Signal | 
| SumoLogicSec.InsightList.Signals.stage | String | The stage of the Signal | 
| SumoLogicSec.InsightList.Signals.timestamp | Date | Signal timestamp | 
| SumoLogicSec.InsightList.Source | String | The source of the Insight | 
| SumoLogicSec.InsightList.Status | String | The status of the Insight | 
| SumoLogicSec.InsightList.TimeToDetection | Number | Insight time to detection | 
| SumoLogicSec.InsightList.TimeToRemediation | Number | Insight time to remediation | 
| SumoLogicSec.InsightList.TimeToResponse | Number | Insight time to response | 
| SumoLogicSec.InsightList.Timestamp | Date | Insight timestamp | 


#### Command Example
`!sumologic-sec-insight-search query="timestamp:>\"2021-02-01T05:00:00+00:00\" status:\"closed\" AND severity:>\"MEDIUM\"" limit=3`

#### Human Readable Output
Insights:
|Id|Readable Id|Name|Action|Status|Assignee|Description|Last Updated|Last Updated By|Severity|Closed|Closed By|Timestamp|Entity|Resolution|
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
| query | Use a query string to search, see API documentation for more details. | Optional | 
| created | When the Signal was created. Defaults to 'All time' if no time arguments are specified. Possible values are: All time, Last week, Last 48 hours, Last 24 hours. Default is All time. | Optional | 
| contentType | Content type associated with the signals. Options: ANOMALY, DEFAULT, THREATINTEL, RULE. Possible values are: ANOMALY, DEFAULT, THREATINTEL, RULE. | Optional | 
| offset | The number of items to skip before starting to collect the result set. Default is 0. | Optional | 
| limit | The maximum number of items to return. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.SignalList.ContentType | String | Type of content that triggered the Signal | 
| SumoLogicSec.SignalList.Description | String | Description of the Signal | 
| SumoLogicSec.SignalList.Entity | String | Entity name associated with the Signal | 
| SumoLogicSec.SignalList.Id | String | The ID of the Signal | 
| SumoLogicSec.SignalList.Name | String | The name of the Signal | 
| SumoLogicSec.SignalList.RecordCount | Number | Number of records associated with the Signal | 
| SumoLogicSec.SignalList.RuleId | String | Rule ID associated with the Signal | 
| SumoLogicSec.SignalList.Severity | Number | The severity of the Signal | 
| SumoLogicSec.SignalList.Stage | String | The stage of the Signal | 
| SumoLogicSec.SignalList.Suppressed | Boolean | Whether or not the Signal was suppressed | 
| SumoLogicSec.SignalList.Timestamp | Date | Signal timestamp | 


#### Command Example
`!sumologic-sec-signal-search query="timestamp:NOW-7D.NOW name:contains(\"Internal\")"`

#### Human Readable Output
Signals:
|Id|Name|Entity|Rule Id|Description|Severity|Stage|Timestamp|Content Type|Tags|
|---|---|---|---|---|---|---|---|---|---|
| b50fd570-341b-576d-85b5-8b5cd17c0aee | IP Address Scan - Internal | 1.2.3.4 | LEGACY-S00050 | A scan of IP addresses | 3 | Discovery | 2021-04-22T04:08:13.514000 | RULE | _mitreAttackTactic:TA0007,<br/>_mitreAttackTactic:TA0043,<br/>_mitreAttackTechnique:T1046,<br/>_mitreAttackTechnique:T1595 |



### sumologic-sec-entity-search
***
Search entities using the available filters


#### Base Command

`sumologic-sec-entity-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Use a query string to search, see API documentation for more details. | Optional | 
| ip | IP Address to search for e.g. 1.2.3.4. | Optional | 
| hostname | Hostname to search for e.g. host.example.com. | Optional | 
| username | Username to search for e.g. admin. | Optional | 
| type | Entity type to search for. Options: username, hostname, ip, mac. Possible values are: username, hostname, ip, mac. | Optional | 
| whitelisted | Is the Entity whitelisted? true/false. Possible values are: true, false. | Optional | 
| tag | Tag contains value. | Optional | 
| offset | The number of items to skip before starting to collect the result set. Default is 0. | Optional | 
| limit | The maximum number of items to return. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.EntityList.ActivityScore | Number | Entity Activity Score | 
| SumoLogicSec.EntityList.FirstSeen | Date | When the Entity was first seen | 
| SumoLogicSec.EntityList.Id | String | Entity ID | 
| SumoLogicSec.EntityList.IpHostname | String | Hostname associated with IP Entity | 
| SumoLogicSec.EntityList.IsWhitelisted | Boolean | Whether or not the Entity is on allow list | 
| SumoLogicSec.EntityList.LastSeen | Date | When the Entity was last seen | 
| SumoLogicSec.EntityList.Name | String | The Entity name | 
| SumoLogicSec.EntityList.OperatingSystem | String | Entity Operating System \(observed or from inventory\) | 
| SumoLogicSec.EntityList.InventoryData | Boolean | Whether or not this Entity was ingested from inventory e.g. Active Directory | 
| SumoLogicSec.EntityList.Hostname | String | Entity hostname | 
| SumoLogicSec.EntityList.Department | String | Username Entity department | 
| SumoLogicSec.EntityList.EmployeeId | String | Username Entity employee ID | 


#### Command Example
`!sumologic-sec-entity-search query="type:\"ip\" activityScore:>=3"`

#### Human Readable Output
Entities:
|Id|Name|First Seen|Last Seen|Activity Score|Is Whitelisted|Operating System|Inventory Data|
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
| insight_id | The insight to change status for. | Required | 
| status | The desired Insight status. Possible values are: new, inprogress, closed. Default is in-progress. | Optional | 
| resolution | Resolution for closing Insight. Valid values are: "Resolved", "False Positive", "No Action", "Duplicate". Possible values are: Resolved, False Positive, No Action, Duplicate. Default is Resolved. | Optional | 
| sub_resolution | Custom sub resolution for closing Insight. If populated, it will override the resolution field. Please make sure the resolution matches exactly your Sumo Resolutions | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.Insight.Assignee | String | User or team assigned to the Insight | 
| SumoLogicSec.Insight.Closed | Date | Closed date | 
| SumoLogicSec.Insight.ClosedBy | String | Closed by user | 
| SumoLogicSec.Insight.Created | Date | Created date | 
| SumoLogicSec.Insight.Description | String | Description of the Insight | 
| SumoLogicSec.Insight.Entity | String | Entity name associated with the Insight | 
| SumoLogicSec.Insight.Id | String | The ID of the Insight | 
| SumoLogicSec.Insight.LastUpdated | Date | The time the Insight was last updated | 
| SumoLogicSec.Insight.LastUpdatedBy | String | The last user to update the Insight | 
| SumoLogicSec.Insight.Name | String | The name of the Insight | 
| SumoLogicSec.Insight.ReadableId | String | The ID of the Insight in readable form | 
| SumoLogicSec.Insight.Resolution | String | Resolution for closed Insight | 
| SumoLogicSec.Insight.Severity | String | The severity of the Insight | 
| SumoLogicSec.Insight.Signals.contentType | String | Type of content that triggered the Signal | 
| SumoLogicSec.Insight.Signals.description | String | Description of the Signal | 
| SumoLogicSec.Insight.Signals.id | String | The ID of the Signal | 
| SumoLogicSec.Insight.Signals.name | String | The name of the Signal | 
| SumoLogicSec.Insight.Signals.recordCount | Number | Number of records associated with the Signal | 
| SumoLogicSec.Insight.Signals.ruleId | String | Rule ID associated with the Signal | 
| SumoLogicSec.Insight.Signals.severity | Number | The severity of the Signal | 
| SumoLogicSec.Insight.Signals.stage | String | The stage of the Signal | 
| SumoLogicSec.Insight.Signals.timestamp | Date | Signal timestamp | 
| SumoLogicSec.Insight.Source | String | The source of the Insight | 
| SumoLogicSec.Insight.Status | String | The status of the Insight | 
| SumoLogicSec.Insight.TimeToDetection | Number | Insight time to detection | 
| SumoLogicSec.Insight.TimeToRemediation | Number | Insight time to remediation | 
| SumoLogicSec.Insight.TimeToResponse | Number | Insight time to response | 
| SumoLogicSec.Insight.Timestamp | Date | Insight timestamp | 


#### Command Example
`!sumologic-sec-insight-set-status insight-id=INSIGHT-116 status=closed resolution="No Action"`

#### Human Readable Output
Insight Details:
|Id|Readable Id|Name|Action|Status|Assignee|Description|Last Updated|Last Updated By|Severity|Closed|Closed By|Timestamp|Entity|Resolution|
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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.MatchLists.Created | String | When the Match List was created | 
| SumoLogicSec.MatchLists.CreatedBy | String | User that created the Match List | 
| SumoLogicSec.MatchLists.DefaultTtl | Number | Default TTL for entries in the Match List | 
| SumoLogicSec.MatchLists.Description | String | Description of the Match List | 
| SumoLogicSec.MatchLists.Id | String | ID of the Match List | 
| SumoLogicSec.MatchLists.LastUpdated | String | When the Match List was last updated | 
| SumoLogicSec.MatchLists.LastUpdatedBy | String | The last user to update the Match List | 
| SumoLogicSec.MatchLists.Name | String | Name of Match List | 
| SumoLogicSec.MatchLists.TargetColumn | String | Match List Target Column | 


#### Command Example
`!sumologic-sec-match-list-get limit=3`

#### Human Readable Output
Match lists:
|Id|Name|Target Column|Default Ttl|
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
| match_list_id | ID of match list. | Required | 
| active | Item active or disabled. | Required | 
| description | Description of match list item. | Required | 
| expiration | Expiration of match list item, e.g. "2021-03-25T23:52:23.508Z". | Required | 
| value | Value of match list item. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.UpdateResult.Result | String | Result \(Success or Failed\) | 
| SumoLogicSec.UpdateResult.Server response | Boolean | Server response \(True or False\) | 


#### Command Example
`!sumologic-sec-match-list-update match-list-id=166 description="My description" expiration=2021-04-25T22:36:10.925Z value="10.20.30.40" active=true`

#### Human Readable Output
Result:
|Result|Server Response|
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
| q | Use a query string to search, see API documentation for more details. | Optional | 
| value | The value to search for. | Required | 
| offset | The number of items to skip before starting to collect the result set. Default is 0. | Optional | 
| limit | The numbers of items to return. Default is 10. | Optional | 
| sourceIds | Comma separated list of threat intelligence source IDs to search, e.g. 1,2,3. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.ThreatIntelIndicators.Active | Boolean | Whether or not the Threat Intel Indicator is Active | 
| SumoLogicSec.ThreatIntelIndicators.Expiration | Date | Date and time the Threat Intel Indicator is set to expire | 
| SumoLogicSec.ThreatIntelIndicators.Id | String | ID of Threat Intel Indicator | 
| SumoLogicSec.ThreatIntelIndicators.Meta.created.username | String | User that created the Threat Intel Indicator | 
| SumoLogicSec.ThreatIntelIndicators.Meta.created.when | Date | When the Threat Intel Indicator was created | 
| SumoLogicSec.ThreatIntelIndicators.Meta.description | String | Description of Threat Intel Indicator | 
| SumoLogicSec.ThreatIntelIndicators.Meta.updated | Date | When the Threat Intel Indicator was last updated | 
| SumoLogicSec.ThreatIntelIndicators.Value | String | Value of Threat Intel Indicator | 


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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.ThreatIntelSources.Created | String | When the Threat Intel Source was created | 
| SumoLogicSec.ThreatIntelSources.CreatedBy | String | User that created the Threat Intel Source | 
| SumoLogicSec.ThreatIntelSources.Description | String | Description of Threat Intel Source | 
| SumoLogicSec.ThreatIntelSources.Id | String | ID of Threat Intel Source | 
| SumoLogicSec.ThreatIntelSources.LastUpdated | String | When the Threat Intel Source was last updated | 
| SumoLogicSec.ThreatIntelSources.LastUpdatedBy | String | User that last updated the Threat Intel Source | 
| SumoLogicSec.ThreatIntelSources.Name | String | Name of Threat Intel Source | 
| SumoLogicSec.ThreatIntelSources.SourceType | String | Source type of Threat Intel Source | 


#### Command Example
`!sumologic-sec-threat-intel-get-sources limit=3`

#### Human Readable Output
Threat intel sources:
|Id|Name|Description|Source Type|
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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SumoLogicSec.UpdateResult.Result | String | Result \(Success or Failed\) | 
| SumoLogicSec.UpdateResult.Server response | Boolean | Server response \(True or False\) | 


#### Command Example
`!sumologic-sec-threat-intel-update-source threat-intel-source-id=54 active=true value=1.2.3.4 description=test expiration=2021-04-29T00:00:00.000Z`

#### Human Readable Output
Result:
|Result|Server Response|
|---|---|
| Success | true |