RSA NetWitness Platform provides systems Logs, Network, and endpoint visibility for real-time collection, detection, and automated response with the XSOAR Enterprise platform.
This integration was integrated and tested with version 11.5 of RSANetWitness
The integration supports version 11.5 and higher.
Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

## Configure RSA NetWitness v11.5 (Beta) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RSA NetWitness v11.5 (Beta).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g https://192.168.0.1) |  | True |
    | User name |  | True |
    | Password |  | True |
    | Service Id | The service id that will be automatically used in every command where service id is required. retrieve all service id's with rsa-nw-services-list command. to overwrite with another service id use the command argument 'service_id'. | False |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Fetch Limit | the maximum number of incidents to fetch | False |
    | Fetch Time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days\) | False |
    | Incident type |  | False |
    | Fetch incidents |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### rsa-nw-list-incidents
***
Retrieve a single incident by id or multiple incidents by the date and time they were created using the start time ('since') or end time ('until'). you can limit the results using the limit argument or the page size argument. If no arguments are entered the last 50 results will be returned.


#### Base Command

`rsa-nw-list-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| until | A timestamp in the following format 2020-01-18T14:00:00.000Z. Retrieve incidents created on and before this timestamp. | Optional | 
| since | A timestamp in the following format 2020-01-18T14:00:00.000Z. Retrieve incidents created on and after this timestamp. | Optional | 
| page_size | The maximum number of items to return in a single page. cannot be supplied with the limit argument. | Optional | 
| page_number | The requested page number, first page is 0. cannot be supplied with the limit argument. | Optional | 
| limit | Maximum number of results to be returned, if not set the first 50 results will be returned. cannot be supplied with a page_size/page_number arguments. | Optional | 
| id | Enter an incident's id to receive it's full details. e.g 'INC-40'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.Incidents.id | String | The unique identifier of the incident. | 
| RSANetWitness115.Incidents.title | String | The title of the incident. | 
| RSANetWitness115.Incidents.summary | Unknown | The summary of the incident. | 
| RSANetWitness115.Incidents.priority | String | The incident priority can be Low,Medium,High or Critical | 
| RSANetWitness115.Incidents.riskScore | Number | The incident risk score is calculated based on the associated alert’s risk score. Risk score ranges from 0 \(no risk\) to 100 \(highest risk\). | 
| RSANetWitness115.Incidents.status | String | The current status. | 
| RSANetWitness115.Incidents.alertCount | Number | The number of alerts associated with an incident. | 
| RSANetWitness115.Incidents.averageAlertRiskScore | Number | The average risk score of the alerts associated with the incident. Risk score ranges from 0 \(no risk\) to 100 \(highest risk\). | 
| RSANetWitness115.Incidents.sealed | Boolean | Indicates if additional alerts can be associated with an incident. A sealed incident cannot be associated with additional alerts. | 
| RSANetWitness115.Incidents.totalRemediationTaskCount | Number | The number of total remediation tasks for an incident. | 
| RSANetWitness115.Incidents.openRemediationTaskCount | Number | The number of open remediation tasks for an incident. | 
| RSANetWitness115.Incidents.created | Date | The timestamp of when the incident is created. | 
| RSANetWitness115.Incidents.lastUpdated | Date | The timestamp of when the incident was last updated. | 
| RSANetWitness115.Incidents.lastUpdatedBy | Unknown | The NetWitness user identifier of the user who last updated the incident. | 
| RSANetWitness115.Incidents.assignee | String | The NetWitness user identifier of the user currently working on the incident. | 
| RSANetWitness115.Incidents.sources | String | Unique set of sources for all of the alerts in an incident. | 
| RSANetWitness115.Incidents.ruleId | Unknown | The unique identifier of the rule that created the incident. | 
| RSANetWitness115.Incidents.firstAlertTime | Unknown | The timestamp of the earliest occurring Alert in this incident. | 
| RSANetWitness115.Incidents.categories | Unknown | The list of categories this incident is categorized under. | 
| RSANetWitness115.Incidents.journalEntries | Unknown | Set of notes about the incident investigation, also known as the JournalEntry. | 
| RSANetWitness115.Incidents.createdBy | String | The NetWitness user id or name of the rule that created the incident. | 
| RSANetWitness115.Incidents.deletedAlertCount | Number | The number of alerts that are deleted from the incident. | 
| RSANetWitness115.Incidents.eventCount | Number | The number of events associated with incident. | 
| RSANetWitness115.Incidents.alertMeta.SourceIp | String | Unique source IP addresses. | 
| RSANetWitness115.Incidents.alertMeta.DestinationIp | String | Unique destination IP addresses. | 
| RSANetWitness115.Incidents.journalEntries.id | String | The unique journal entry identifier. | 
| RSANetWitness115.Incidents.journalEntries.author | String | The author of this entry. | 
| RSANetWitness115.Incidents.journalEntries.notes | String | Notes and observations about the incident. | 
| RSANetWitness115.Incidents.journalEntries.created | Date | The timestamp of the journal entry created date. | 
| RSANetWitness115.Incidents.journalEntries.lastUpdated | Date | The timestamp of the journal entry last updated date. | 
| RSANetWitness115.Incidents.journalEntries.milestone | String | Incident milestone classifier. | 
| RSANetWitness115.Incidents.page_number | Number | The requested page number. | 
| RSANetWitness115.Incidents.page_size | Number | The requested number of items to return in a single page. | 
| RSANetWitness115.Incidents.totalPages | Number | The total number of pages available. | 
| RSANetWitness115.Incidents.totalItems | Number | The total number of items available. | 
| RSANetWitness115.Incidents.hasNext | Boolean | Indicates if there is a page containing results after this page. | 
| RSANetWitness115.Incidents.hasPrevious | Boolean | Indicates if there is a page containing results before this page. | 
| RSANetWitness115.Incidents.categories.id | Unknown | The unique category identifier. | 
| RSANetWitness115.Incidents.categories.parent | Unknown | The parent name of the category. | 
| RSANetWitness115.Incidents.categories.name | Unknown | The friendly name of the category. | 
| RSANetWitness115.paging.Incidents.hasNext | Unknown | Indicates if there is a page containing results after this page. | 
| RSANetWitness115.paging.Incidents.hasPrevious | Boolean | Indicates if there is a page containing results before this page. | 
| RSANetWitness115.paging.Incidents.pageNumber | Number | The requested page number | 
| RSANetWitness115.paging.Incidents.pageSize | Number | The requested number of items to return in a single page. | 
| RSANetWitness115.paging.Incidents.totalPages | Number | The total number of pages available. | 
| RSANetWitness115.paging.Incidents.totalItems | Number | The total number of items available. | 

#### Command example
```!rsa-nw-list-incidents limit=1```
#### Context Example
```json
{
    "RSANetWitness115": {
        "Incidents": {
            "alertCount": 1,
            "alertMeta": {
                "DestinationIp": [
                    "1.1.1.1"
                ],
                "SourceIp": [
                    ""
                ]
            },
            "assignee": null,
            "averageAlertRiskScore": 70,
            "categories": null,
            "created": "2021-11-15T07:30:49.670Z",
            "createdBy": "Admin",
            "deletedAlertCount": 0,
            "eventCount": 1,
            "firstAlertTime": null,
            "id": "INC-49",
            "journalEntries": [
                {
                    "author": "Admin",
                    "created": "2021-12-26T16:10:21.810Z",
                    "id": "48",
                    "lastUpdated": "2021-12-26T16:10:21.810Z",
                    "milestone": null,
                    "notes": "great inc for demo"
                }
            ],
            "lastUpdated": "2022-01-10T13:50:14.312Z",
            "lastUpdatedBy": "Admin",
            "openRemediationTaskCount": 0,
            "priority": "Low",
            "riskScore": 70,
            "ruleId": null,
            "sealed": false,
            "sources": [
                "Reporting Engine"
            ],
            "status": "Assigned",
            "summary": null,
            "title": "Fetch_testing",
            "totalRemediationTaskCount": 0
        },
        "paging": {
            "Incidents": {
                "hasNext": true,
                "hasPrevious": false,
                "pageNumber": 0,
                "pageSize": 1,
                "totalItems": 28,
                "totalPages": 28
            }
        }
    }
}
```

#### Human Readable Output

>### Total Retrieved Incidents : 1
> Page number 0 out of 28 
>|Id|Title|Summary|Priority|RiskScore|Status|AlertCount|Created|LastUpdated|Assignee|Sources|Categories|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| INC-49 | Fetch_testing |  | Low | 70 | Assigned | 1 | 2021-11-15T07:30:49.670Z | 2022-01-10T13:50:14.312Z |  | Reporting Engine |  |


### rsa-nw-update-incident
***
Update an incident’s status and assignee


#### Base Command

`rsa-nw-update-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The incident's id. | Required | 
| status | The new status of the incident. Possible values are: New, Assigned, InProgress, RemediationRequested, RemediationComplete, Closed, ClosedFalsePositive. | Optional | 
| assignee | The NetWitness user identifier of the user currently working on the incident. You can find the list of asignees in the RSA Net Witness interface. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.Incidents.id | String | The unique identifier of the incident. | 
| RSANetWitness115.Incidents.title | String | The title of the incident. | 
| RSANetWitness115.Incidents.summary | Unknown | The summary of the incident. | 
| RSANetWitness115.Incidents.priority | String | The incident priority | 
| RSANetWitness115.Incidents.riskScore | Number | The incident risk score is calculated based on the associated alert’s risk score. Risk score ranges from 0 \(no risk\) to 100 \(highest risk\). | 
| RSANetWitness115.Incidents.status | String | The current status | 
| RSANetWitness115.Incidents.alertCount | Number | The number of alerts associated with an incident. | 
| RSANetWitness115.Incidents.averageAlertRiskScore | Number | The average risk score of the alerts associated with the incident. Risk score ranges from 0 \(no risk\) to 100 \(highest risk\). | 
| RSANetWitness115.Incidents.sealed | Boolean | Indicates if additional alerts can be associated with an incident. A sealed incident cannot be associated with additional alerts. | 
| RSANetWitness115.Incidents.totalRemediationTaskCount | Number | The number of total remediation tasks for an incident. | 
| RSANetWitness115.Incidents.openRemediationTaskCount | Number | The number of open remediation tasks for an incident. | 
| RSANetWitness115.Incidents.created | Date | The timestamp of when the incident is created. | 
| RSANetWitness115.Incidents.lastUpdated | Date | The timestamp of when the incident was last updated. | 
| RSANetWitness115.Incidents.lastUpdatedBy | String | The NetWitness user identifier of the user who last updated the incident. | 
| RSANetWitness115.Incidents.assignee | Unknown | The NetWitness user identifier of the user currently working on the incident. | 
| RSANetWitness115.Incidents.sources | String | Unique set of sources for all of the alerts in an incident. | 
| RSANetWitness115.Incidents.ruleId | Unknown | The unique identifier of the rule that created the incident. | 
| RSANetWitness115.Incidents.firstAlertTime | Unknown | The timestamp of the earliest occurring Alert in this incident. | 
| RSANetWitness115.Incidents.categories.id | String | The unique category identifier. | 
| RSANetWitness115.Incidents.categories.parent | String | The parent name of the category. | 
| RSANetWitness115.Incidents.categories.name | String | The friendly name of the category. | 
| RSANetWitness115.Incidents.journalEntries.id | String | The unique journal entry identifier. | 
| RSANetWitness115.Incidents.journalEntries.author | String | The author of this entry. | 
| RSANetWitness115.Incidents.journalEntries.notes | String | Notes and observations about the incident. | 
| RSANetWitness115.Incidents.journalEntries.created | Date | The timestamp of the journal entry created date. | 
| RSANetWitness115.Incidents.journalEntries.lastUpdated | Date | The timestamp of the journal entry last updated date. | 
| RSANetWitness115.Incidents.journalEntries.milestone | String | Incident milestone classifier. | 
| RSANetWitness115.Incidents.createdBy | String | The NetWitness user id or name of the rule that created the incident. | 
| RSANetWitness115.Incidents.deletedAlertCount | Number | The number of alerts that are deleted from the incident. | 
| RSANetWitness115.Incidents.eventCount | Number | The number of events associated with incident. | 
| RSANetWitness115.Incidents.alertMeta.SourceIp | String | Unique source IP addresses. | 
| RSANetWitness115.Incidents.alertMeta.DestinationIp | String | Unique destination IP addresses. | 

#### Command example
```!rsa-nw-update-incident id=INC-49 status=Assigned```
#### Context Example
```json
{
    "RSANetWitness115": {
        "Incidents": {
            "alertCount": 1,
            "alertMeta": {
                "DestinationIp": [
                    "1.1.1.1"
                ],
                "SourceIp": [
                    ""
                ]
            },
            "assignee": null,
            "averageAlertRiskScore": 70,
            "categories": null,
            "created": "2021-11-15T07:30:49.670Z",
            "createdBy": "Admin",
            "deletedAlertCount": 0,
            "eventCount": 1,
            "firstAlertTime": null,
            "id": "INC-49",
            "journalEntries": [
                {
                    "author": "Admin",
                    "created": "2021-12-26T16:10:21.810Z",
                    "id": "48",
                    "lastUpdated": "2021-12-26T16:10:21.810Z",
                    "milestone": null,
                    "notes": "great inc for demo"
                }
            ],
            "lastUpdated": "2022-01-10T14:12:35.992Z",
            "lastUpdatedBy": "Admin",
            "openRemediationTaskCount": 0,
            "priority": "Low",
            "riskScore": 70,
            "ruleId": null,
            "sealed": false,
            "sources": [
                "Reporting Engine"
            ],
            "status": "Assigned",
            "summary": null,
            "title": "Fetch_testing",
            "totalRemediationTaskCount": 0
        }
    }
}
```

#### Human Readable Output

>### Updated Incident INC-49
>|Id|Title|Summary|Priority|RiskScore|Status|AlertCount|Created|LastUpdated|Assignee|Sources|Categories|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| INC-49 | Fetch_testing |  | Low | 70 | Assigned | 1 | 2021-11-15T07:30:49.670Z | 2022-01-10T14:12:35.992Z |  | Reporting Engine |  |


### rsa-nw-remove-incident
***
Remove a single incident using the incident’s unique identifier.


#### Base Command

`rsa-nw-remove-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The unique identifier of the incident. | Required | 


#### Context Output

There is no context output for this command.
### rsa-nw-incident-add-journal-entry
***
Add a journal entry to an existing incident.


#### Base Command

`rsa-nw-incident-add-journal-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The unique identifier of the incident. | Required | 
| author | The NetWitness user id of the user creating the journal entry. Can be found in the RSA platform. In case no author is provided the command will list the user from the integration configuration as the author. | Optional | 
| notes | Notes and observations about the incident. | Required | 
| milestone | The incident milestone classifier. Possible values are: Reconnaissance, Delivery, Exploitation, Installation, CommandAndControl, ActionOnObjective, Containment, Eradication, Closure. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!rsa-nw-incident-add-journal-entry id=INC-24 notes="adding entry"```
#### Human Readable Output

>Journal entry added successfully for incident INC-24 

### rsa-nw-incident-list-alerts
***
Retrieve all the alerts that are associated with an incident based on the incident's id. you can limit the results using the limit argument or the page size argument. the default is 50 results.


#### Base Command

`rsa-nw-incident-list-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The unique identifier of the incident. | Required | 
| page_number | The requested page number, first page is 0. cannot be supllied with the limit argument. | Optional | 
| page_size | The maximum number of items to return in a single page. cannot be supllied with the limit argument. | Optional | 
| limit | Maximum number of results to be returned, if not set the first 50 results will be returned. cannot be supllied with a page_size/page_number arguments. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.IncidentAlerts.id | String | The unique alert identifier. | 
| RSANetWitness115.IncidentAlerts.title | String | The title or name of the rule that created the alert. | 
| RSANetWitness115.IncidentAlerts.detail | Unknown | The details of the alert. This can be the module name or meta that the module included. | 
| RSANetWitness115.IncidentAlerts.created | Date | The timestamp of the alert created date. | 
| RSANetWitness115.IncidentAlerts.source | String | The source of this alert. For example, "Event Stream Analysis", "Malware Analysis", etc. | 
| RSANetWitness115.IncidentAlerts.riskScore | Number | The risk score of this alert, usually in the range 0 - 100. | 
| RSANetWitness115.IncidentAlerts.type | String | The type of alert, "Network", "Log", etc. | 
| RSANetWitness115.IncidentAlerts.events.source.device.ipAddress | Unknown | The IP address. | 
| RSANetWitness115.IncidentAlerts.events.source.device.port | Unknown | The port. | 
| RSANetWitness115.IncidentAlerts.events.source.device.macAddress | Unknown | The ethernet MAC address. | 
| RSANetWitness115.IncidentAlerts.events.source.device.dnsHostname | Unknown | The DNS resolved hostname. | 
| RSANetWitness115.IncidentAlerts.events.source.device.dnsDomain | Unknown | The top-level domain from the DNS resolved hostname. | 
| RSANetWitness115.IncidentAlerts.events.source.user.username | String | The unique username. | 
| RSANetWitness115.IncidentAlerts.events.source.user.emailAddress | Unknown | An email address. | 
| RSANetWitness115.IncidentAlerts.events.source.user.adUsername | Unknown | An Active Directory \(AD\) username. | 
| RSANetWitness115.IncidentAlerts.events.source.user.adDomain | Unknown | An Active Directory \(AD\) domain. | 
| RSANetWitness115.IncidentAlerts.events.destination.device.ipAddress | Unknown | The IP address. | 
| RSANetWitness115.IncidentAlerts.events.destination.device.port | Unknown | The port. | 
| RSANetWitness115.IncidentAlerts.events.destination.device.macAddress | Unknown | The ethernet MAC address. | 
| RSANetWitness115.IncidentAlerts.events.destination.device.dnsHostname | Unknown | The DNS resolved hostname. | 
| RSANetWitness115.IncidentAlerts.events.destination.device.dnsDomain | Unknown | The top-level domain from the DNS resolved hostname. | 
| RSANetWitness115.IncidentAlerts.events.destination.user.username | Unknown | The unique username. | 
| RSANetWitness115.IncidentAlerts.events.destination.user.emailAddress | Unknown | An email address. | 
| RSANetWitness115.IncidentAlerts.events.destination.user.adUsername | Unknown | An Active Directory \(AD\) username. | 
| RSANetWitness115.IncidentAlerts.events.destination.user.adDomain | Unknown | An Active Directory \(AD\) domain. | 
| RSANetWitness115.IncidentAlerts.events.domain | String | The top-level domain or Windows domain. | 
| RSANetWitness115.IncidentAlerts.events.eventSource | Unknown | The source of the event. This may be a fully- qualified hostname with a port, or simple name. | 
| RSANetWitness115.IncidentAlerts.events.eventSourceId | String | The unique identifier of the event on the source. For Network and Log events, this is the Nextgen Session ID. | 
| RSANetWitness115.paging.IncidentAlerts.pageNumber | Number | The requested page number. | 
| RSANetWitness115.paging.IncidentAlerts.pageSize | Number | The requested number of items to return in a single page. | 
| RSANetWitness115.paging.IncidentAlerts.totalPages | Number | The total number of pages available. | 
| RSANetWitness115.paging.IncidentAlerts.totalItems | Number | The total number of items available. | 
| RSANetWitness115.paging.IncidentAlerts.hasNext | Boolean | Indicates if there is a page containing results after this page. | 
| RSANetWitness115.paging.IncidentAlerts.hasPrevious | Boolean | Indicates if there is a page containing results before this page. | 

#### Command example
```!rsa-nw-incident-list-alerts id=INC-49```
#### Context Example
```json
{
    "RSANetWitness115": {
        "IncidentAlerts": {
            "IncidentId": "INC-49",
            "created": "2021-03-02T17:46:06Z",
            "detail": null,
            "events": [
                {
                    "destination": {
                        "device": {
                            "dnsDomain": null,
                            "dnsHostname": null,
                            "ipAddress": "1.1.1.1",
                            "macAddress": "111::111:11:111:11",
                            "port": null
                        },
                        "user": {
                            "adDomain": null,
                            "adUsername": null,
                            "emailAddress": null,
                            "username": null
                        }
                    },
                    "domain": "ADONIS",
                    "eventSource": "1.1.1.1",
                    "eventSourceId": "1",
                    "source": {
                        "device": {
                            "dnsDomain": null,
                            "dnsHostname": null,
                            "ipAddress": null,
                            "macAddress": null,
                            "port": null
                        },
                        "user": {
                            "adDomain": null,
                            "adUsername": null,
                            "emailAddress": null,
                            "username": null
                        }
                    }
                }
            ],
            "id": "1",
            "riskScore": null,
            "source": "Reporting Engine",
            "title": "Rule",
            "type": "Log"
        },
        "paging": {
            "IncidentAlerts": {
                "hasNext": false,
                "hasPrevious": false,
                "pageNumber": 0,
                "pageSize": 50,
                "totalItems": 1,
                "totalPages": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Total Retrieved Alerts : 1 for incident INC-49
> Page number 0 out of 1
>|Id|Title|Created|Source|Type|Events|
>|---|---|---|---|---|---|
>| 1 | Rule | 2021-03-02T17:46:06Z | Reporting Engine | Log | {'source': {'device': {'ipAddress': None, 'port': None, 'macAddress': None, 'dnsHostname': None, 'dnsDomain': None}, 'user': {'username': None, 'emailAddress': None, 'adUsername': None, 'adDomain': None}}, 'destination': {'device': {'ipAddress': '1.1.1.1', 'port': None, 'macAddress': '111::111:11:111:11', 'dnsHostname': None, 'dnsDomain': None}, 'user': {'username': None, 'emailAddress': None, 'adUsername': None, 'adDomain': None}}, 'domain': 'ADONIS', 'eventSource': '1.1.1.1', 'eventSourceId': '1'} |


### rsa-nw-services-list
***
Retrieve a list of all services, or filter by name


#### Base Command

`rsa-nw-services-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the service. For example, endpoint-server. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.ServicesList.id | String | Unique identifier of each service installed in the RSA NetWitness suite. | 
| RSANetWitness115.ServicesList.name | String | Name of the service. For example, endpoint- server. | 
| RSANetWitness115.ServicesList.displayName | String | Display name of the service. | 
| RSANetWitness115.ServicesList.host | String | Host details of the service. | 
| RSANetWitness115.ServicesList.version | String | Version of the service. | 

#### Command example
```!rsa-nw-services-list```
#### Context Example
```json
{
    "RSANetWitness115": {
        "ServicesList":
            {
                "displayName": "ELD",
                "host": "1.1.1.1",
                "id": "1",
                "name": "server",
                "version": "1"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|displayName|host|id|name|version|
>|---|---|---|---|---|
>| ELD | 1.1.1.1 | 1 | server | 1 |


### rsa-nw-hosts-list
***
lists all hosts' information from a particular Endpoint Server. filter the results using the supplied arguments (list can be supplied) or use the 'filter' argument. more info in the integration documentation. you can limit the results using the limit argument or the page size argument. the default is 50 results.


#### Base Command

`rsa-nw-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | service ID of the specific Endpoint Server. view all service ID's using the 'rsa-nw-services-list' command. If none is given the service ID configured in the integration configuration will be used. | Optional | 
| page_number | The requested page number, first page is 0. cannot be supllied with the limit argument. | Optional | 
| page_size | The maximum number of items to return in a single page. cannot be supllied with the limit argument. | Optional | 
| limit | Maximum number of results to be returned, if not set the first 50 results will be returned.  cannot be supllied with a page_size/page_number arguments. | Optional | 
| agent_id | Agent ID of the host. can be supllied as a list of agent ids. | Optional | 
| host_name | Name of the host. can be supplied as a list. | Optional | 
| risk_score | Risk score of the host. will return all results with risk score greather or equal. | Optional | 
| ip | IPV4 in the network interface. can be supplied as a list of ip's. | Optional | 
| filter | Custom filter in a JSON format. More details in the integration documentation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.HostsList.agentId | String | Agent ID of the host. | 
| RSANetWitness115.HostsList.hostName | String | Name of the host. | 
| RSANetWitness115.HostsList.riskScore | Number | Risk score of the host. | 
| RSANetWitness115.HostsList.networkInterfaces.name | String | Name of the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.macAddress | String | MAC Address of the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.ipv4 | String | List of IPV4 in the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.ipv6 | String | List of IPV6 in the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.networkIdv6 | String | List of network IDV6 in the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.gateway | String | List of gateway in the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.dns | String | List of DNS in the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.promiscuous | Boolean | Specifies if the network interface is in the promiscuous mode. | 
| RSANetWitness115.HostsList.lastSeenTime | Date | Agent last seen time. | 
| RSANetWitness115.paging.HostsList.pageNumber | Number | The requested page number. | 
| RSANetWitness115.paging.HostsList.pageSize | Number | The requested number of items to return in a single page. | 
| RSANetWitness115.paging.HostsList.totalPages | Number | The total number of pages available. | 
| RSANetWitness115.paging.HostsList.totalItems | Number | The total number of items available. | 
| RSANetWitness115.paging.HostsList.hasNext | Boolean | Indicates if there is a page containing results after this page. | 
| RSANetWitness115.paging.HostsList.hasPrevious | Boolean | Indicates if there is a page containing results before this page. | 

#### Command example
```!rsa-nw-hosts-list limit=1```
#### Context Example
```json
{
    "RSANetWitness115": {
        "HostsList": {
            "agentId": "1",
            "hostName": "hostName",
            "lastSeenTime": "2022-01-10T14:12:30.197Z",
            "networkInterfaces": [
                {
                    "dns": [
                        "1.1.1.1"
                    ],
                    "gateway": [
                        "1.1.1.1"
                    ],
                    "ipv4": [
                        "1.1.1.1"
                    ],
                    "ipv6": [
                        "111::111:11:111:11"
                    ],
                    "macAddress": "111::111:11:111:11",
                    "name": "AWS PV Network Device #0",
                    "networkIdv6": [
                        "1"
                    ],
                    "promiscuous": false
                }
            ],
            "riskScore": 0
        },
        "paging": {
            "HostsList": {
                "hasNext": false,
                "hasPrevious": false,
                "pageNumber": 0,
                "pageSize": 1,
                "totalItems": 1,
                "totalPages": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Total Retrieved Hosts : 1 
> Page number 0 out of 1
>|agentId|hostName|riskScore|networkInterfaces|lastSeenTime|
>|---|---|---|---|---|
>| 1 | hostName | 0 | {'name': 'AWS PV Network Device #0', 'macAddress': '111::111:11:111:11', 'ipv4': ['1.1.1.10'], 'ipv6': ['111::111:11:111:11'], 'networkIdv6': ['1'], 'gateway': ['1.1.1.1'], 'dns': ['1.1.1.1'], 'promiscuous': False} | 2022-01-10T14:12:30.197Z |


### endpoint
***
Retrieve host information for a specific endpoint. In order to use this command service id must be set in the integration configuration.


#### Base Command

`endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The endpoint ID. | Optional | 
| ip | The endpoint ip. | Optional | 
| hostname | The endpoint hostname. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The endpoint's hostname. | 
| Endpoint.Relationships.EntityA | string | The source of the relationship. | 
| Endpoint.Relationships.EntityB | string | The destination of the relationship. | 
| Endpoint.Relationships.Relationship | string | The name of the relationship. | 
| Endpoint.Relationships.EntityAType | string | The type of the source of the relationship. | 
| Endpoint.Relationships.EntityBType | string | The type of the destination of the relationship. | 
| Endpoint.OS | String | The endpoint's operation system. | 
| Endpoint.IPAddress | String | The endpoint's IP address. | 
| Endpoint.ID | String | The endpoint's ID. | 
| Endpoint.Status | String | The endpoint's status. | 
| Endpoint.IsIsolated | String | The endpoint's isolation status. | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 
| Endpoint.Domain | String | The endpoint's domain. | 
| Endpoint.DHCPServer | String | The DHCP server of the endpoint. | 
| Endpoint.OSVersion | String | The endpoint's operation system version. | 
| Endpoint.BIOSVersion | String | The endpoint's BIOS version. | 
| Endpoint.Model | String | The model of the machine or device. | 
| Endpoint.Memory | Int | Memory on this endpoint. | 
| Endpoint.Processors | Int | The number of processors. | 
| Endpoint.Processor | String | The model of the processor. | 

#### Command example
```!endpoint```
#### Context Example
```json
{
    "Endpoint": {
        "Hostname": "hostName",
        "ID": "1",
        "IPAddress": [
            [
                "1.1.1.1"
            ]
        ],
        "MACAddress": [
            "111::111:11:111:11"
        ],
        "Vendor": "RSA NetWitness 11.5 Response"
    }
}
```

#### Human Readable Output

>### RSA NetWitness 11.5 -  Endpoint: 1
>|Hostname|ID|IPAddress|MACAddress|Vendor|
>|---|---|---|---|---|
>| hostName | 1 | ['1.1.1.1'] | 111::111:11:111:11 | RSA NetWitness 11.5 Response |


### rsa-nw-snapshots-list-for-host
***
Retrieve a list os snapshot ID's for a given host.


#### Base Command

`rsa-nw-snapshots-list-for-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent ID of the host. | Required | 
| service_id | service ID of the specific Endpoint Server. view all service ID's using the 'rsa-nw-services-list' command. If none is given the service ID configured in the integration configuration will be used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.SnapshotsListForHost | Date | List of snapshot timestamps. | 

#### Command example
```!rsa-nw-snapshots-list-for-host agent_id=1```
#### Context Example
```json
{
    "RSANetWitness115": {
        "SnapshotsListForHost": [
            "2022-01-09T16:42:45.661Z",
            "2022-01-09T16:12:41.840Z",
            "2022-01-09T15:51:44.870Z",
            "2022-01-02T13:21:24.655Z",
            "2021-12-30T09:32:48.740Z",
            "2021-12-16T14:23:38.357Z"
        ]
    }
}
```

#### Human Readable Output

>### Snapshot list for agent id 1-
>|Snapshot Id|
>|---|
>| 2022-01-09T16:42:45.661Z |
>| 2022-01-09T16:12:41.840Z |
>| 2022-01-09T15:51:44.870Z |
>| 2022-01-02T13:21:24.655Z |
>| 2021-12-30T09:32:48.740Z |
>| 2021-12-16T14:23:38.357Z |


### rsa-nw-snapshot-details-get
***
Provides snapshot details of the given host for the provided snapshot time. using categories to filter the reults is highly reccomended, as data recieved from this command may be very large.


#### Base Command

`rsa-nw-snapshot-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent ID of the host. | Required | 
| snapshot_timestamp | Start time of the scan snapshot, can be retrieved using the 'rsa-nw-snapshots-list-for-host' command. | Required | 
| service_id | service ID of the specific Endpoint Server. View all service ID's using the 'rsa-nw-services-list' command. If none is given the service ID configured in the integration configuration will be used. | Optional | 
| categories | filter the results based on categories. enter a single category name or a list divided by commas. for example - PROCESSES,SERVICES. . Possible values are: PROCESSES, LOADED_LIBRARIES, SERVICES, AUTORUNS, TASKS, DRIVERS, THREADS, IMAGE_HOOKS, KERNEL_HOOKS.. | Optional | 
| limit | The maximun amount of results returned by the command. Default is 50. | Optional | 
| offset | the offset to recieve results from. e.g offse =3 will return results from the 3rd results and onwards. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.SnapshotDetailsGet.machineOsType | String | Type of operating system \(Windows, Mac, Linux\). | 
| RSANetWitness115.SnapshotDetailsGet.hostName | String | Name of the host. | 
| RSANetWitness115.SnapshotDetailsGet.agentId | String | Agent ID of the host. | 
| RSANetWitness115.SnapshotDetailsGet.agentVersion | String | Version of the agent. | 
| RSANetWitness115.SnapshotDetailsGet.scanStartTime | Date | Start time of the scan snapshot. | 
| RSANetWitness115.SnapshotDetailsGet.directory | String | Directory of the file. | 
| RSANetWitness115.SnapshotDetailsGet.fileName | String | Name of the file. | 
| RSANetWitness115.SnapshotDetailsGet.owner.username | String | User name of the owner of the file. | 
| RSANetWitness115.SnapshotDetailsGet.owner.groupname | String | Group name of the owner of the file. | 
| RSANetWitness115.SnapshotDetailsGet.owner.uid | String | UID of the user name. | 
| RSANetWitness115.SnapshotDetailsGet.owner.gid | String | GID of the user name. | 
| RSANetWitness115.SnapshotDetailsGet.timeCreated | Date | Time when file was created. | 
| RSANetWitness115.SnapshotDetailsGet.timeModified | Date | Time when file was modified. | 
| RSANetWitness115.SnapshotDetailsGet.timeAccessed | Date | Time when file was last accessed. | 
| RSANetWitness115.SnapshotDetailsGet.attributes | String | List of file attributes. | 
| RSANetWitness115.SnapshotDetailsGet.accessMode | Number | Access mode of the file. | 
| RSANetWitness115.SnapshotDetailsGet.sameDirectoryFileCounts.nonExe | Number | Number of non-exe files in the same directory of the file. | 
| RSANetWitness115.SnapshotDetailsGet.sameDirectoryFileCounts.exe | Number | Number of exe files in the same directory of the file. | 
| RSANetWitness115.SnapshotDetailsGet.sameDirectoryFileCounts.subFolder | Number | Number of sub-folders in the same directory of the file | 
| RSANetWitness115.SnapshotDetailsGet.sameDirectoryFileCounts.exeSameCompany | Number | Number of executables with the same company name in the same directory of the file. | 
| RSANetWitness115.SnapshotDetailsGet.sameDirectoryFileCounts.hiddenFiles | Number | Count of hidden files in the same directory of the file | 
| RSANetWitness115.SnapshotDetailsGet.fileContext | String | List of file context. | 
| RSANetWitness115.SnapshotDetailsGet.directoryContext | String | List of directory context. | 
| RSANetWitness115.SnapshotDetailsGet.autorunContext | Unknown | List of autorun context. | 
| RSANetWitness115.SnapshotDetailsGet.networkContext | Unknown | List of network context. | 
| RSANetWitness115.SnapshotDetailsGet.kernelModeContext | Unknown | List of kernel mode context. | 
| RSANetWitness115.SnapshotDetailsGet.userModeContext | String | List of user mode context. | 
| RSANetWitness115.SnapshotDetailsGet.processContext | Unknown | List of process context. | 
| RSANetWitness115.SnapshotDetailsGet.rpm.packageName | String | RPM package name to which the file belongs. | 
| RSANetWitness115.SnapshotDetailsGet.rpm.category | String | Category to which the rpm package belongs. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.pid | Number | ID of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.parentPid | Number | ID of the parent process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.imageBase | Number | Base address of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.createUtcTime | Unknown | Creation time of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.owner | String | Name of the user. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.launchArguments | String | Launch arguments of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.threadCount | Number | Number of threads running in the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.eprocess | String | Identifier of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.sessionId | Number | Session ID of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.parentPath | Unknown | Directory of the parent process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.imageSize | Number | Size of the process image. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.integrityLevel | Number | Integrity level of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.context | String | List of process context. | 
| RSANetWitness115.SnapshotDetailsGet.windows.dlls.createTime | Date | Creation time of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.dlls.eprocess | String | Identity of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.dlls.imageSize | Number | Size of the DLL image in memory. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.processName | String | Name of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.processTime | String | Creation time of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.eprocess | String | Identifier of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.pid | Number | PID of the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.ethread | String | Identifier of the thread. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.tid | Number | ID of the thread. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.teb | String | Address of thread environment block. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.startAddress | String | Start address of the thread in memory. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.state | Unknown | Thread state. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.behaviorKey | String | Floating behavior resolution of the thread. | 
| RSANetWitness115.SnapshotDetailsGet.windows.drivers.imageBase | Number | Base address of the driver image. | 
| RSANetWitness115.SnapshotDetailsGet.windows.drivers.imageSize | Number | Size of the driver image. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.serviceName | String | Service name as identified by the system. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.displayName | String | Display name for the service. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.description | String | Description of the service. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.account | String | Name of the user the service executes as. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.launchArguments | String | Launch arguments of the service. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.serviceMain | String | Service’s main. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.hostingPid | Number | Service’s hosting process ID. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.state | Unknown | Current state of the service. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.win32ErrorCode | Number | Last Windows 32 error code from registry. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.context | Unknown | List of service context. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.name | String | Name of the task. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.executeUser | String | Name of the user the task executes as. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.creatorUser | String | Name of the user who created the task. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.launchArguments | String | Launch arguments of the task. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.status | Unknown | Status of the task. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.lastRunTime | Unknown | Time when the task was last run. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.nextRunTime | Unknown | Next scheduled time of the task. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.triggerString | Unknown | Textual trigger string of the task. | 
| RSANetWitness115.SnapshotDetailsGet.windows.autoruns.type | String | Type of the autorun. | 
| RSANetWitness115.SnapshotDetailsGet.windows.autoruns.registryPath | String | Registry path where autorun is located. | 
| RSANetWitness115.SnapshotDetailsGet.windows.autoruns.launchArguments | String | Launch argument of the autorun. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.process.pid | String | PID of the process in which hook was detected. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.process.fileName | String | Filename of the process in which hook was detected. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.process.createUtcTime | String | Creation time of the process in which hook was  detected. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.hookLocation.section | String | Name of the image section that was modified by the hook. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.hookLocation.sectionBase | String | Base of the image section that was modified by the hook. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.hookLocation.symbol | String | Closest symbol name to the memory location that was modified. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.hookLocation.symbolOffset | Number | Closest symbol \+/- offset to the hook location when relevant. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.inlinePatch.originalBytes | String | Hexadecimal bytes which were replaced. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.inlinePatch.originalAsm | Unknown | Array of decoded ASM instructions that were replaced. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.inlinePatch.currentBytes | String | Hexadecimal bytes which have overwritten the original code. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.inlinePatch.currentAsm | Unknown | Array of decoded ASM instructions that have  overwritten the original code. | 
| RSANetWitness115.SnapshotDetailsGet.windows.kernelHooks.hookLocation.objectName | String | Name of the object that was hooked in kernel. | 
| RSANetWitness115.SnapshotDetailsGet.windows.kernelHooks.hookLocation.objectFunction | String | Name of the object function that was hooked in kernel. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.priority | Number | Priority of the process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.flags | Number | Process flags. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.nice | Number | Nice value of process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.openFilesCount | Number | Number of open files by process at scan time. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.context | Unknown | Process context. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.pid | Number | ID of the process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.parentPid | Number | ID of the parent process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.imageBase | Number | Base address of the process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.createUtcTime | String | Creation time of the process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.owner | String | Name of the user. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.launchArguments | String | Launch arguments of the process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.threadCount | Number | Number of threads running in the process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.dylibs.pid | Number | Process ID in dylib which is loaded. | 
| RSANetWitness115.SnapshotDetailsGet.mac.dylibs.processName | String | Name of the process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.dylibs.imageBase | String | Base address of image in the process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.drivers.preLinked | Boolean | True if Kext bundle is prelinked. | 
| RSANetWitness115.SnapshotDetailsGet.mac.drivers.numberOfReferences | Number | Number of references. | 
| RSANetWitness115.SnapshotDetailsGet.mac.drivers.dependencies | Unknown | List of kexts\(name\) the driver is linked against. | 
| RSANetWitness115.SnapshotDetailsGet.mac.drivers.imageBase | String | Base address of the driver image. | 
| RSANetWitness115.SnapshotDetailsGet.mac.drivers.imageSize | String | Size of the driver image. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.name | String | Label of the daemon. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.sessionName | String | Name of the session in which daemon runs. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.user | String | Name of the user under which the daemon runs. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.pid | Number | ID of the process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.onDemand | Boolean | True if daemon is configured to run on demand. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.lastExitCode | Number | Last exit code. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.timeout | Number | Time out value. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.daemons.launchArguments | String | Launch argument of the daemon. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.daemons.config | String | Full path of the configuration file used to File configure this daemon. | 
| RSANetWitness115.SnapshotDetailsGet.mac.tasks.name | String | Name of the task. | 
| RSANetWitness115.SnapshotDetailsGet.mac.tasks.cronJob | Boolean | True if the task is cron job, else launchd. | 
| RSANetWitness115.SnapshotDetailsGet.mac.tasks.launchArguments | String | Launch argument of the task. | 
| RSANetWitness115.SnapshotDetailsGet.mac.tasks.user | String | Name of the user under which this task will run. | 
| RSANetWitness115.SnapshotDetailsGet.mac.tasks.triggerString | String | Trigger string of the task. | 
| RSANetWitness115.SnapshotDetailsGet.mac.tasks.configFile | String | Full path of the configuration file used to configure this task. | 
| RSANetWitness115.SnapshotDetailsGet.mac.autoruns.type | String | Type of autorun. | 
| RSANetWitness115.SnapshotDetailsGet.mac.autoruns.user | String | Name of the user under which the autorun is run. | 
| RSANetWitness115.SnapshotDetailsGet.mac.autoruns.name | String | Label of the autorun. | 
| RSANetWitness115.SnapshotDetailsGet.mac.autoruns.detail | String | Details of the autorun. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.priority | Number | Priority of the process. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.uid | Number | UID of the user. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.environment | String | Environment variables. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.nice | Number | Nice value of the process. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.securityContext | String | Security context. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.pid | Number | ID of the process. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.parentPid | Number | ID of the parent process. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.imageBase | Number | Base address of the process. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.createUtcTime | String | Time of creation of the process. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.owner | String | Name of the user. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.launchArguments | String | Launch arguments of the process. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.threadCount | Number | Number of threads running in the process. | 
| RSANetWitness115.SnapshotDetailsGet.linux.loadedLibraries.pid | String | Process ID in which library is loaded. | 
| RSANetWitness115.SnapshotDetailsGet.linux.loadedLibraries.process | String | Name of the process. Name | 
| RSANetWitness115.SnapshotDetailsGet.linux.loadedLibraries.imageBase | String | Base address of image in the process. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.numberOfInstances | Number | Number of instances loaded in memory. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.loadState | String | Load state of the driver. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.dependencies | Unknown | Dependent driver names. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.author | String | Name of the author of driver. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.description | String | Description of the driver. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.sourceVersion | String | Source version of the driver. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.versionMagic | String | Version magic of the driver. | 
| RSANetWitness115.SnapshotDetailsGet.linux.initds.initdHashSha256 | String | Hash of the init-d script file. | 
| RSANetWitness115.SnapshotDetailsGet.linux.initds.initdPaths | String | Path of the init-d script file. | 
| RSANetWitness115.SnapshotDetailsGet.linux.initds.pid | Number | ID of the process. | 
| RSANetWitness115.SnapshotDetailsGet.linux.initds.description | String | Description of the init-d. | 
| RSANetWitness115.SnapshotDetailsGet.linux.initds.status | String | Status of the init-d. | 
| RSANetWitness115.SnapshotDetailsGet.linux.initds.runLevels | Unknown | List of run levels in which the init-d is enabled. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.systemdHashSha256 | String | Hash value of the systemd script file. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.systemdPaths | String | Path value of the systemd script file. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.name | String | Name of the systemd. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.description | String | Description of the systemd. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.state | String | State of the systemd. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.launchArguments | String | Launch argument of the systemd. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.pid | Number | ID of the process. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.triggeredBy | Unknown | Triggered by list of the systemd. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.triggerStrings | Unknown | Trigger strings of the systemd. | 
| RSANetWitness115.SnapshotDetailsGet.linux.autoruns.type | String | Type of autorun. | 
| RSANetWitness115.SnapshotDetailsGet.linux.autoruns.label | String | Label of the autorun. | 
| RSANetWitness115.SnapshotDetailsGet.linux.autoruns.comments | String | Comments of the autorun. | 
| RSANetWitness115.SnapshotDetailsGet.linux.crons.user | String | User account under which cron job was created. | 
| RSANetWitness115.SnapshotDetailsGet.linux.crons.triggerString | String | Trigger string that would launch the cron job. | 
| RSANetWitness115.SnapshotDetailsGet.linux.crons.launchArguments | String | Launch arguments of the cron job. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.firstFileName | String | First name of the file sent by the agent. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.reputationStatus | String | Reputation status of the file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.globalRiskScore | String | Global risk score. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.firstSeenTime | String | Time when the file was first seen by the Endpoint Server. | 
| RSANetWitness115.SnapshotDetailsGet.machineOsType | String | Type of operating system \(Windows, Mac, Linux\). | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.signature | Object | Signatory information of the file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.signature.timeStamp | String | Timestamp of the signature. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.signature.thumbprint | String | Thumbprint of the certificate. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.signature.context | Unknown | Context information of the certificate. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.signature.signer | String | Signer information of the certificate. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.size | String | Size of the file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.checksumMd5 | String | MD5 of the file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.checksumSha1 | String | SHA1 of the file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.checksumSha256 | String | SHA256 of the file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe | Object | PE information of the file. This is applicable for Windows files. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.timeStamp | String | Timestamp of the PE File. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.imageSize | String | Image size of the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.numberOfExportedFunctions | String | Number of exported function in the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.numberOfNamesExported | String | Number of names exported in the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.numberOfExecuteWriteSections | String | Number of execute write sections in the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.context | Unknown | Context information of the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.resources | Object | Resources of the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.resources.originalFileName | String | Original filename as per PE information. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.resources.company | String | Company name as per PE information. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.resources.description | String | Description of the file as per PE information. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.resources.version | String | Version of the file as per PE information. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.sectionNames | Unknown | List of section names in the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.importedLibraries | Unknown | List of imported libraries in the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.elf | Object | ELF information of the file. This is applicable for Linux files. | 
| RSANetWitness115.SnapshotDetailsGet.elf.classType | String | Class type of the ELF file. | 
| RSANetWitness115.SnapshotDetailsGet.elf.data | String | Data of ELF file. | 
| RSANetWitness115.SnapshotDetailsGet.elf.entryPoint | String | Entry point for the ELF file. | 
| RSANetWitness115.SnapshotDetailsGet.elf.context | Unknown | Context information of ELF file. | 
| RSANetWitness115.SnapshotDetailsGet.elf.type | String | Type of ELF file. | 
| RSANetWitness115.SnapshotDetailsGet.elf.sectionNames | Unknown | List of section names in ELF file. | 
| RSANetWitness115.SnapshotDetailsGet.elf.importedLibraries | Unknown | List of imported libraries in ELF file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.macho | Object | Macho information of the file. This is applicable for Mac files. | 
| RSANetWitness115.SnapshotDetailsGet.macho.uuid | String | UUID of the Macho file. | 
| RSANetWitness115.SnapshotDetailsGet.macho.identifier | String | Identifier of the Macho file. | 
| RSANetWitness115.SnapshotDetailsGet.macho.minOsxVersion | String | Minimum OSx version for the Macho file. | 
| RSANetWitness115.SnapshotDetailsGet.macho.context | Unknown | Context information of the Macho file. | 
| RSANetWitness115.SnapshotDetailsGet.macho.flags | String | Flags of Macho file. | 
| RSANetWitness115.SnapshotDetailsGet.macho.numberOfLoadCommands | String | Number of load commands for the Macho file. | 
| RSANetWitness115.SnapshotDetailsGet.macho.version | String | Version of the Macho file. | 
| RSANetWitness115.SnapshotDetailsGet.macho.sectionNames | Unknown | Section names in the Macho file. | 
| RSANetWitness115.SnapshotDetailsGet.macho.importedLibraries | Unknown | Imported libraries list in the Macho file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.entropy | String | Entropy of the file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.format | String | Format of the file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.fileStatus | String | Status of the file as assigned by the analyst. \(Whitelist, Blacklist, Neutral, and Graylist\). | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.remediationAction | String | Remediation action as assigned by the analyst. For example, Blocked. | 
| RSANetWitness115.SnapshotDetailsGet.localRiskScore | Number | File’s score based on alerts triggered in the given agent. | 

#### Command example
```!rsa-nw-snapshot-details-get agent_id=1 snapshot_timestamp=2022-01-09T16:42:45.661Z categories=AUTORUNS```
#### Context Example
```json
{
    "RSANetWitness115": {
        "SnapshotDetailsGet": [
            {
                "accessMode": 0,
                "agentId": "1",
                "agentVersion": "1",
                "attributes": [
                    "file.attribute.archive"
                ],
                "autorunContext": null,
                "directory": "C:\\Windows\\System32\\",
                "directoryContext": [
                    "windows",
                    "windowsSystem32"
                ],
                "fileContext": [
                    "file.autorun",
                    "file.found",
                    "file.protected"
                ],
                "fileName": "cmd.exe",
                "fileProperties": {
                    "checksumMd5": "1",
                    "checksumSha1": "1",
                    "checksumSha256": "1",
                    "elf": null,
                    "entropy": 1,
                    "fileStatus": "Neutral",
                    "firstFileName": "cmd.exe",
                    "firstSeenTime": "2021-07-27T07:18:36.416Z",
                    "format": "pe",
                    "globalRiskScore": 0,
                    "machineOsType": "windows",
                    "macho": null,
                    "pe": {
                        "context": [
                            "file.exe
                        ],
                        "imageSize": 413696,
                        "importedLibraries": [
                            "msvcrt.dll"
                        ],
                        "numberOfExecuteWriteSections": 0,
                        "numberOfExportedFunctions": 0,
                        "numberOfNamesExported": 0,
                        "resources": {
                            "company": "Microsoft Corporation",
                            "description": "Windows Command Processor",
                            "originalFileName": "Cmd.Exe",
                            "version": null
                        },
                        "sectionNames": [
                            ".text",
                            ".rdata",
                            ".data",
                            ".pdata",
                            ".didat",
                            ".rsrc",
                            ".reloc"
                        ],
                        "timeStamp": "2008-05-30T00:32:37.000Z"
                    },
                    "remediationAction": "Unblock",
                    "reputationStatus": null,
                    "signature": {
                        "context": [
                            "microsoft",
                            "signed",
                            "valid",
                            "catalog"
                        ],
                        "signer": "Microsoft Windows",
                        "thumbprint": "1",
                        "timeStamp": "2021-07-04T12:36:11.241Z"
                    },
                    "size": 278528
                },
                "hostName": "hostName",
                "kernelModeContext": null,
                "linux": null,
                "localRiskScore": 0,
                "mac": null,
                "machineOsType": "windows",
                "networkContext": null,
                "owner": null,
                "processContext": null,
                "rpm": null,
                "sameDirectoryFileCounts": {
                    "exe": 3280,
                    "exeSameCompany": 3248,
                    "hiddenFiles": 0,
                    "nonExe": 563,
                    "subFolder": 121
                },
                "scanStartTime": "2022-01-09T16:42:45.661Z",
                "timeAccessed": "2021-01-13T21:15:45.606Z",
                "timeCreated": "2021-01-13T21:15:45.574Z",
                "timeModified": "2021-01-13T21:15:45.606Z",
                "userModeContext": null,
                "windows": {
                    "autoruns": [
                        {
                            "launchArguments": "",
                            "registryPath": "",
                            "type": "logon"
                        }
                    ],
                    "dlls": [],
                    "drivers": [],
                    "imageHooks": [],
                    "kernelHooks": [],
                    "processes": [],
                    "services": [],
                    "tasks": [
                        {
                            "creatorUser": "",
                            "executeUser": "Author",
                            "lastRunTime": "2021-07-15T12:04:04.000+0000",
                            "launchArguments": "/C C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Unrestricted -File \"C:\\ProgramData\\Amazon\\EC2-Windows\\Launch\\Scripts\\InitializeInstance.ps1\"",
                            "name": "\\Amazon Ec2 Launch - Instance Initialization",
                            "nextRunTime": "1899-12-30T00:00:00.000+0000",
                            "status": [
                                "disabled",
                                "startOnDemand",
                                "dontStartOnBatteries"
                            ],
                            "triggerString": "Starts the task when the task is registered."
                        },
                        {
                            "creatorUser": "",
                            "executeUser": "LocalSystem",
                            "lastRunTime": "1999-11-30T00:00:00.000+0000",
                            "launchArguments": "/d /c %systemroot%\\system32\\silcollector.cmd publish",
                            "name": "\\Microsoft\\Windows\\Software Inventory Logging\\Collection",
                            "nextRunTime": "2022-01-09T17:04:38.000+0000",
                            "status": [
                                "disabled",
                                "dontStartOnBatteries",
                                "hidden"
                            ],
                            "triggerString": "Triggers the task at a specific time of day."
                        },
                        {
                            "creatorUser": "",
                            "executeUser": "LocalSystem",
                            "lastRunTime": "2021-07-27T07:16:33.000+0000",
                            "launchArguments": "/d /c %systemroot%\\system32\\silcollector.cmd configure",
                            "name": "\\Microsoft\\Windows\\Software Inventory Logging\\Configuration",
                            "nextRunTime": "1899-12-30T00:00:00.000+0000",
                            "status": [
                                "ready",
                                "dontStartOnBatteries",
                                "hidden"
                            ],
                            "triggerString": "Starts the task when the task is registered."
                        }
                    ],
                    "threads": []
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Snapshot details for agent id 1- 
>showing 2 results out of 2
>|hostName|agentId|scanStartTime|directory|fileName|
>|---|---|---|---|---|
>| hostName | 1 | 2022-01-09T16:42:45.661Z | C:\Windows\System32\ | cmd.exe |


### rsa-nw-files-list
***
lists all related information of files from a specific Endpoint Server. you can limit the results using the limit argument or the page size argument. the default is 10 results.


#### Base Command

`rsa-nw-files-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | service ID of the specific Endpoint Server. View all service ID's using the 'rsa-nw-services-list' command. If none is given the service ID configured in the integration configuration will be used. | Optional | 
| page_number | The requested page number, first page is number 0. cannot be supllied with the limit argument. | Optional | 
| page_size | The maximum number of items to return in a single page. cannot be supllied with the limit argument. | Optional | 
| limit | Maximum number of results to be returned, if not set the first 10 results will be returned.  cannot be supllied with a page_size/page_number arguments. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.FilesList.windows.autoruns.type | String | Type of the autorun. | 
| RSANetWitness115.FilesList.windows.autoruns.registryPath | String | Registry path where autorun is located. | 
| RSANetWitness115.FilesList.windows.autoruns.launchArguments | String | Launch argument of the autorun. | 
| RSANetWitness115.FilesList.windows.imageHooks.process.pid | String | PID of the process in which hook was detected. | 
| RSANetWitness115.FilesList.windows.imageHooks.process.fileName | String | Filename of the process in which hook was detected. | 
| RSANetWitness115.FilesList.windows.imageHooks.process.createUtcTime | String | Creation time of the process in which hook was  detected. | 
| RSANetWitness115.FilesList.windows.imageHooks.hookLocation.section | String | Name of the image section that was modified by the hook. | 
| RSANetWitness115.FilesList.windows.imageHooks.hookLocation.sectionBase | String | Base of the image section that was modified by the hook. | 
| RSANetWitness115.FilesList.windows.imageHooks.hookLocation.symbol | String | Closest symbol name to the memory location that was modified. | 
| RSANetWitness115.FilesList.windows.imageHooks.hookLocation.symbolOffset | Number | Closest symbol \+/- offset to the hook location when relevant. | 
| RSANetWitness115.FilesList.windows.imageHooks.inlinePatch.originalBytes | String | Hexadecimal bytes which were replaced. | 
| RSANetWitness115.FilesList.windows.imageHooks.inlinePatch.originalAsm | Unknown | Array of decoded ASM instructions that were replaced. | 
| RSANetWitness115.FilesList.windows.imageHooks.inlinePatch.currentBytes | String | Hexadecimal bytes which have overwritten the original code. | 
| RSANetWitness115.FilesList.windows.imageHooks.inlinePatch.currentAsm | Unknown | Array of decoded ASM instructions that have  overwritten the original code. | 
| RSANetWitness115.FilesList.windows.kernelHooks.hookLocation.objectName | String | Name of the object that was hooked in kernel. | 
| RSANetWitness115.FilesList.windows.kernelHooks.hookLocation.objectFunction | String | Name of the object function that was hooked in kernel. | 
| RSANetWitness115.FilesList.mac.processes.priority | Number | Priority of the process. | 
| RSANetWitness115.FilesList.mac.processes.flags | Number | Process flags. | 
| RSANetWitness115.FilesList.mac.processes.nice | Number | Nice value of process. | 
| RSANetWitness115.FilesList.mac.processes.openFilesCount | Number | Number of open files by process at scan time. | 
| RSANetWitness115.FilesList.mac.processes.context | Unknown | Process context. | 
| RSANetWitness115.FilesList.mac.processes.pid | Number | ID of the process. | 
| RSANetWitness115.FilesList.mac.processes.parentPid | Number | ID of the parent process. | 
| RSANetWitness115.FilesList.mac.processes.imageBase | Number | Base address of the process. | 
| RSANetWitness115.FilesList.mac.processes.createUtcTime | String | Creation time of the process. | 
| RSANetWitness115.FilesList.mac.processes.owner | String | Name of the user. | 
| RSANetWitness115.FilesList.mac.processes.launchArguments | String | Launch arguments of the process. | 
| RSANetWitness115.FilesList.mac.processes.threadCount | Number | Number of threads running in the process. | 
| RSANetWitness115.FilesList.mac.dylibs.pid | Number | Process ID in dylib which is loaded. | 
| RSANetWitness115.FilesList.mac.dylibs.processName | String | Name of the process. | 
| RSANetWitness115.FilesList.mac.dylibs.imageBase | String | Base address of image in the process. | 
| RSANetWitness115.FilesList.mac.drivers.preLinked | Boolean | True if Kext bundle is prelinked. | 
| RSANetWitness115.FilesList.mac.drivers.numberOfReferences | Number | Number of references. | 
| RSANetWitness115.FilesList.mac.drivers.dependencies | Unknown | List of kexts\(name\) the driver is linked against. | 
| RSANetWitness115.FilesList.mac.drivers.imageBase | String | Base address of the driver image. | 
| RSANetWitness115.FilesList.mac.drivers.imageSize | String | Size of the driver image. | 
| RSANetWitness115.FilesList.mac.daemons.name | String | Label of the daemon. | 
| RSANetWitness115.FilesList.mac.daemons.sessionName | String | Name of the session in which daemon runs. | 
| RSANetWitness115.FilesList.mac.daemons.user | String | Name of the user under which the daemon runs. | 
| RSANetWitness115.FilesList.mac.daemons.pid | Number | ID of the process. | 
| RSANetWitness115.FilesList.mac.daemons.onDemand | Boolean | True if daemon is configured to run on demand. | 
| RSANetWitness115.FilesList.mac.daemons.lastExitCode | Number | Last exit code. | 
| RSANetWitness115.FilesList.mac.daemons.timeout | Number | Time out value. | 
| RSANetWitness115.FilesList.mac.daemons.daemons.launchArguments | String | Launch argument of the daemon. | 
| RSANetWitness115.FilesList.mac.daemons.daemons.config | String | Full path of the configuration file used to File configure this daemon. | 
| RSANetWitness115.FilesList.mac.tasks.name | String | Name of the task. | 
| RSANetWitness115.FilesList.mac.tasks.cronJob | Boolean | True if the task is cron job, else launchd. | 
| RSANetWitness115.FilesList.mac.tasks.launchArguments | String | Launch argument of the task. | 
| RSANetWitness115.FilesList.mac.tasks.user | String | Name of the user under which this task will run. | 
| RSANetWitness115.FilesList.mac.tasks.triggerString | String | Trigger string of the task. | 
| RSANetWitness115.FilesList.mac.tasks.configFile | String | Full path of the configuration file used to configure this task. | 
| RSANetWitness115.FilesList.mac.autoruns.type | String | Type of autorun. | 
| RSANetWitness115.FilesList.mac.autoruns.user | String | Name of the user under which the autorun is run. | 
| RSANetWitness115.FilesList.mac.autoruns.name | String | Label of the autorun. | 
| RSANetWitness115.FilesList.mac.autoruns.detail | String | Details of the autorun. | 
| RSANetWitness115.FilesList.linux.processes.priority | Number | Priority of the process. | 
| RSANetWitness115.FilesList.linux.processes.uid | Number | UID of the user. | 
| RSANetWitness115.FilesList.linux.processes.environment | String | Environment variables. | 
| RSANetWitness115.FilesList.linux.processes.nice | Number | Nice value of the process. | 
| RSANetWitness115.FilesList.linux.processes.securityContext | String | Security context. | 
| RSANetWitness115.FilesList.linux.processes.pid | Number | ID of the process. | 
| RSANetWitness115.FilesList.linux.processes.parentPid | Number | ID of the parent process. | 
| RSANetWitness115.FilesList.linux.processes.imageBase | Number | Base address of the process. | 
| RSANetWitness115.FilesList.linux.processes.createUtcTime | String | Time of creation of the process. | 
| RSANetWitness115.FilesList.linux.processes.owner | String | Name of the user. | 
| RSANetWitness115.FilesList.linux.processes.launchArguments | String | Launch arguments of the process. | 
| RSANetWitness115.FilesList.linux.processes.threadCount | Number | Number of threads running in the process. | 
| RSANetWitness115.FilesList.linux.loadedLibraries.pid | String | Process ID in which library is loaded. | 
| RSANetWitness115.FilesList.linux.loadedLibraries.process | String | Name of the process. Name | 
| RSANetWitness115.FilesList.linux.loadedLibraries.imageBase | String | Base address of image in the process. | 
| RSANetWitness115.FilesList.linux.drivers.numberOfInstances | Number | Number of instances loaded in memory. | 
| RSANetWitness115.FilesList.linux.drivers.loadState | String | Load state of the driver. | 
| RSANetWitness115.FilesList.linux.drivers.dependencies | Unknown | Dependent driver names. | 
| RSANetWitness115.FilesList.linux.drivers.author | String | Name of the author of driver. | 
| RSANetWitness115.FilesList.linux.drivers.description | String | Description of the driver. | 
| RSANetWitness115.FilesList.linux.drivers.sourceVersion | String | Source version of the driver. | 
| RSANetWitness115.FilesList.linux.drivers.versionMagic | String | Version magic of the driver. | 
| RSANetWitness115.FilesList.linux.initds.initdHashSha256 | String | Hash of the init-d script file. | 
| RSANetWitness115.FilesList.linux.initds.initdPaths | String | Path of the init-d script file. | 
| RSANetWitness115.FilesList.linux.initds.pid | Number | ID of the process. | 
| RSANetWitness115.FilesList.linux.initds.description | String | Description of the init-d. | 
| RSANetWitness115.FilesList.linux.initds.status | String | Status of the init-d. | 
| RSANetWitness115.FilesList.linux.initds.runLevels | Unknown | List of run levels in which the init-d is enabled. | 
| RSANetWitness115.FilesList.linux.systemds.systemdHashSha256 | String | Hash value of the systemd script file. | 
| RSANetWitness115.FilesList.linux.systemds.systemdPaths | String | Path value of the systemd script file. | 
| RSANetWitness115.FilesList.linux.systemds.name | String | Name of the systemd. | 
| RSANetWitness115.FilesList.linux.systemds.description | String | Description of the systemd. | 
| RSANetWitness115.FilesList.linux.systemds.state | String | State of the systemd. | 
| RSANetWitness115.FilesList.linux.systemds.launchArguments | String | Launch argument of the systemd. | 
| RSANetWitness115.FilesList.linux.systemds.pid | Number | ID of the process. | 
| RSANetWitness115.FilesList.linux.systemds.triggeredBy | Unknown | Triggered by list of the systemd. | 
| RSANetWitness115.FilesList.linux.systemds.triggerStrings | Unknown | Trigger strings of the systemd. | 
| RSANetWitness115.FilesList.linux.autoruns.type | String | Type of autorun. | 
| RSANetWitness115.FilesList.linux.autoruns.label | String | Label of the autorun. | 
| RSANetWitness115.FilesList.linux.autoruns.comments | String | Comments of the autorun. | 
| RSANetWitness115.FilesList.linux.crons.user | String | User account under which cron job was created. | 
| RSANetWitness115.FilesList.linux.crons.triggerString | String | Trigger string that would launch the cron job. | 
| RSANetWitness115.FilesList.linux.crons.launchArguments | String | Launch arguments of the cron job. | 
| RSANetWitness115.FilesList.firstFileName | String | First name of the file sent by the agent. | 
| RSANetWitness115.FilesList.reputationStatus | String | Reputation status of the file. | 
| RSANetWitness115.FilesList.globalRiskScore | String | Global risk score. | 
| RSANetWitness115.FilesList.firstSeenTime | String | Time when the file was first seen by the Endpoint Server. | 
| RSANetWitness115.FilesList.fileProperties.machineOsType | String | Type of operating system \(Windows, Mac, Linux\). | 
| RSANetWitness115.FilesList.signature | Object | Signatory information of the file. | 
| RSANetWitness115.FilesList.signature.timeStamp | String | Timestamp of the signature. | 
| RSANetWitness115.FilesList.signature.thumbprint | String | Thumbprint of the certificate. | 
| RSANetWitness115.FilesList.signature.context | Unknown | Context information of the certificate. | 
| RSANetWitness115.FilesList.signature.signer | String | Signer information of the certificate. | 
| RSANetWitness115.FilesList.size | String | Size of the file. | 
| RSANetWitness115.FilesList.checksumMd5 | String | MD5 of the file. | 
| RSANetWitness115.FilesList.checksumSha1 | String | SHA1 of the file. | 
| RSANetWitness115.FilesList.checksumSha256 | String | SHA256 of the file. | 
| RSANetWitness115.FilesList.pe | Object | PE information of the file. This is applicable for Windows files. | 
| RSANetWitness115.FilesList.pe.timeStamp | String | Timestamp of the PE File. | 
| RSANetWitness115.FilesList.pe.imageSize | String | Image size of the PE file. | 
| RSANetWitness115.FilesList.pe.numberOfExportedFunctions | String | Number of exported function in the PE file. | 
| RSANetWitness115.FilesList.pe.numberOfNamesExported | String | Number of names exported in the PE file. | 
| RSANetWitness115.FilesList.pe.numberOfExecuteWriteSections | String | Number of execute write sections in the PE file. | 
| RSANetWitness115.FilesList.pe.context | Unknown | Context information of the PE file. | 
| RSANetWitness115.FilesList.pe.resources | Object | Resources of the PE file. | 
| RSANetWitness115.FilesList.pe.resources.originalFileName | String | Original filename as per PE information. | 
| RSANetWitness115.FilesList.pe.resources.company | String | Company name as per PE information. | 
| RSANetWitness115.FilesList.pe.resources.description | String | Description of the file as per PE information. | 
| RSANetWitness115.FilesList.pe.resources.version | String | Version of the file as per PE information. | 
| RSANetWitness115.FilesList.pe.sectionNames | Unknown | List of section names in the PE file. | 
| RSANetWitness115.FilesList.pe.importedLibraries | Unknown | List of imported libraries in the PE file. | 
| RSANetWitness115.FilesList.elf | Object | ELF information of the file. This is applicable for Linux files. | 
| RSANetWitness115.FilesList.elf.classType | String | Class type of the ELF file. | 
| RSANetWitness115.FilesList.elf.data | String | Data of ELF file. | 
| RSANetWitness115.FilesList.elf.entryPoint | String | Entry point for the ELF file. | 
| RSANetWitness115.FilesList.elf.context | Unknown | Context information of ELF file. | 
| RSANetWitness115.FilesList.elf.type | String | Type of ELF file. | 
| RSANetWitness115.FilesList.elf.sectionNames | Unknown | List of section names in ELF file. | 
| RSANetWitness115.FilesList.elf.importedLibraries | Unknown | List of imported libraries in ELF file. | 
| RSANetWitness115.FilesList.macho | Object | Macho information of the file. This is applicable for Mac files. | 
| RSANetWitness115.FilesList.macho.uuid | String | UUID of the Macho file. | 
| RSANetWitness115.FilesList.macho.identifier | String | Identifier of the Macho file. | 
| RSANetWitness115.FilesList.macho.minOsxVersion | String | Minimum OSx version for the Macho file. | 
| RSANetWitness115.FilesList.macho.context | Unknown | Context information of the Macho file. | 
| RSANetWitness115.FilesList.macho.flags | String | Flags of Macho file. | 
| RSANetWitness115.FilesList.macho.numberOfLoadCommands | String | Number of load commands for the Macho file. | 
| RSANetWitness115.FilesList.macho.version | String | Version of the Macho file. | 
| RSANetWitness115.FilesList.macho.sectionNames | Unknown | Section names in the Macho file. | 
| RSANetWitness115.FilesList.macho.importedLibraries | Unknown | Imported libraries list in the Macho file. | 
| RSANetWitness115.FilesList.entropy | String | Entropy of the file. | 
| RSANetWitness115.FilesList.format | String | Format of the file. | 
| RSANetWitness115.FilesList.fileStatus | String | Status of the file as assigned by the analyst. \(Whitelist, Blacklist, Neutral, and Graylist\). | 
| RSANetWitness115.FilesList.remediationAction | String | Remediation action as assigned by the analyst. For example, Blocked. | 
| RSANetWitness115.FilesList.localRiskScore | Number | File’s score based on alerts triggered in the given agent. | 

#### Command example
```!rsa-nw-files-list limit=1```
#### Context Example
```json
{
    "RSANetWitness115": {
        "FilesList": {
            "checksumMd5": "1",
            "checksumSha1": "1",
            "checksumSha256": "1",
            "elf": null,
            "entropy": 7.940328994398384,
            "fileStatus": "Neutral",
            "firstFileName": "AM_Delta_Patch_1.355.1597.0.exe",
            "firstSeenTime": "2022-01-09T08:31:01.525Z",
            "format": "pe",
            "globalRiskScore": 0,
            "machineOsType": "windows",
            "macho": null,
            "pe": {
                "context": [
                    "file.exe",
                    "file.arch64",
                    "file.versionInfoPresent",
                    "file.resourceDirectoryPresent",
                    "file.relocationDirectoryPresent",
                    "file.debugDirectoryPresent",
                    "file.tlsDirectoryPresent",
                    "file.richSignaturePresent",
                    "file.companyNameContainsText",
                    "file.descriptionContainsText",
                    "file.versionContainsText",
                    "file.internalNameContainsText",
                    "file.legalCopyrightContainsText",
                    "file.originalFilenameContainsText",
                    "file.productNameContainsText",
                    "file.productVersionContainsText",
                    "file.standardVersionMetaPresent"
                ],
                "imageSize": 2617344,
                "importedLibraries": [
                    "ADVAPI32.dll",
                    "KERNEL32.dll",
                    "RPCRT4.dll",
                    "ntdll.dll"
                ],
                "numberOfExecuteWriteSections": 0,
                "numberOfExportedFunctions": 0,
                "numberOfNamesExported": 0,
                "resources": {
                    "company": "Microsoft Corporation",
                    "description": "Microsoft Antimalware WU Stub",
                    "originalFileName": "AM_Delta_Patch_1.355.1597.0.exe",
                    "version": null
                },
                "sectionNames": [
                    ".text",
                    ".rdata",
                    ".data",
                    ".pdata",
                    ".rsrc",
                    ".reloc"
                ],
                "timeStamp": "2022-01-09T03:25:21.000Z"
            },
            "remediationAction": "Unblock",
            "reputationStatus": null,
            "signature": {
                "context": [
                    "microsoft",
                    "signed",
                    "valid"
                ],
                "signer": "Microsoft Corporation",
                "thumbprint": "1",
                "timeStamp": "2022-01-09T03:30:35.633Z"
            },
            "size": 2618848
        },
        "paging": {
            "FilesList": {
                "hasNext": true,
                "hasPrevious": false,
                "pageNumber": 0,
                "pageSize": 1,
                "totalItems": 1449,
                "totalPages": 1449
            }
        }
    }
}
```

#### Human Readable Output

>### Total Retrieved Files : 1 
> Page number 0 out of 1449
>|File Name|Risk Score|First Seen Time|Size|Signature|PE Resources|File Status|Remediation|
>|---|---|---|---|---|---|---|---|
>| AM_Delta_Patch_1.355.1597.0.exe | 0 | 2022-01-09T08:31:01.525Z | 2618848 | timeStamp: 2022-01-09T03:30:35.633Z<br/>thumbprint: 1<br/>context: microsoft,<br/>signed,<br/>valid<br/>signer: Microsoft Corporation | originalFileName: AM_Delta_Patch_1.355.1597.0.exe<br/>company: Microsoft Corporation<br/>description: Microsoft Antimalware WU Stub<br/>version: null | Neutral | Unblock |


### rsa-nw-scan-request
***
starts a scan for the host with the specified agent ID. Each scan produces a snapshot, the full detailed can be seen using 'rsa-nw-snapshot-details-get' command


#### Base Command

`rsa-nw-scan-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent ID of the host. | Required | 
| service_id | service ID of the specific Endpoint Server. View all service ID's using the 'rsa-nw-services-list' command. If none is given the service ID configured in the integration configuration will be used. | Optional | 
| cpu_max | You can use cpuMax to specify the amount of CPU the agent can use to run the scan. You can choose a value from 5 to 100. If you do not specify a value, the agent uses the default 25% CPU for the scan. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!rsa-nw-scan-request agent_id=1```
#### Human Readable Output

>Scan request for host 1 Sent Successfully

### rsa-nw-scan-stop-request
***
stop a scan for the host with the specified agent ID.


#### Base Command

`rsa-nw-scan-stop-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Unique identifier of the host. | Required | 
| service_id | service ID of the specific Endpoint Server. view all service ID's using the 'rsa-nw-services-list' command. If none is given the service ID configured in the integration configuration will be used. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!rsa-nw-scan-stop-request agent_id=1```
#### Human Readable Output

>Scan cancellation request for host 1, sent successfully

### rsa-nw-host-alerts-list
***
Get all alerts triggered for a given host.


#### Base Command

`rsa-nw-host-alerts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Unique identifier of the host. | Required | 
| service_id | service ID of the specific Endpoint Server. view all service ID's using the 'rsa-nw-services-list' command. If none is given the service ID configured in the integration configuration will be used. | Optional | 
| alert_category |  filter alerts based on the category. Possible values are: Critical, High, Medium, Low. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.HostAlerts.id | String | ID of the entity for which score needs to be queried. Agent ID in case of host and checksum in case of files. | 
| RSANetWitness115.HostAlerts.distinctAlertCount.critical | Number | Number of critical alerts. | 
| RSANetWitness115.HostAlerts.distinctAlertCount.high | Number | Number of high alerts. | 
| RSANetWitness115.HostAlerts.distinctAlertCount.medium | Number | Number of medium alerts. | 
| RSANetWitness115.HostAlerts.distinctAlertCount.low | Number | Number of low alerts. | 
| RSANetWitness115.HostAlerts.categorizedAlerts | String | Count of alert and events for a file/host, categorized by severity. | 

#### Command example
```!rsa-nw-host-alerts-list agent_id=1```
#### Context Example
```json
{
    "RSANetWitness115": {
        "HostAlerts": {
            "categorizedAlerts": {},
            "distinctAlertCount": {
                "critical": 0,
                "high": 0,
                "low": 0,
                "medium": 0
            },
            "id": "1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|categorizedAlerts|distinctAlertCount|id|
>|---|---|---|
>|  | critical: 0<br/>high: 0<br/>medium: 0<br/>low: 0 | 1 |


### rsa-nw-file-alerts-list
***
Get all alerts triggered for a given file


#### Base Command

`rsa-nw-file-alerts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| check_sum | The file hash, either md5 or sha256. Possible values are: . | Required | 
| service_id | service ID of the specific Endpoint Server. view all service ID's using the 'rsa-nw-services-list' command. If none is given the service ID configured in the integration configuration will be used. | Optional | 
| alert_category |  filter alerts based on the category. Possible values are: Critical, High, Medium, Low. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.FileAlerts.id | String | ID of the entity for which score needs to be queried. Agent ID in case of host and checksum in case of files. | 
| RSANetWitness115.FileAlerts.distinctAlertCount.critical | Number | Number of critical alerts. | 
| RSANetWitness115.FileAlerts.distinctAlertCount.high | Number | Number of high alerts. | 
| RSANetWitness115.FileAlerts.distinctAlertCount.medium | Number | Number of medium alerts. | 
| RSANetWitness115.FileAlerts.distinctAlertCount.low | Number | Number of low alerts. | 
| RSANetWitness115.FileAlerts.categorizedAlerts | String | Count of alert and events for a file/host, categorized by severity. | 

#### Command example
```!rsa-nw-file-alerts-list check_sum=5dad5b58ad14d95b29ef7fc2e685fa3270e9c3a347d4183c84b1cbbf29ab2510```
#### Context Example
```json
{
    "RSANetWitness115": {
        "FileAlerts": {
            "categorizedAlerts": {},
            "distinctAlertCount": {
                "critical": 0,
                "high": 0,
                "low": 0,
                "medium": 0
            },
            "id": "1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|categorizedAlerts|distinctAlertCount|id|
>|---|---|---|
>|  | critical: 0<br/>high: 0<br/>medium: 0<br/>low: 0 | 1 |


### rsa-nw-file-download
***
Initiate file download for a single file, or multiple files, to the Endpoint Server


#### Base Command

`rsa-nw-file-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent ID of the host. | Required | 
| service_id | service ID of the specific Endpoint Server. view all service ID's using the 'rsa-nw-services-list' command. If none is given the service ID configured in the integration configuration will be used. | Optional | 
| path | Path where the files may be present, either specify a single file path or use a wildcard. for example - "C:\Users\sample\*" . To see scanned files paths use the command 'rsa-nw-snapshot-details-get'. | Required | 
| count_files | Maximum number of files returned by the host matching the wildcard path (default 10). Default is 10. | Optional | 
| max_file_size | Maximum size of each file (in MB) when using a wildcard path (default 100 MB). Default is 100. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!rsa-nw-file-download agent_id=1 path=path/to/file```
#### Human Readable Output

>Request for download path/to/file sent successfully

### rsa-nw-mft-download-request
***
initiatesthe download of MFT to the Endpoint Server.


#### Base Command

`rsa-nw-mft-download-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent ID of the host. | Required | 
| service_id | Service ID of the Endpoint Server to be connected. | Optional | 


#### Context Output

There is no context output for this command.
### rsa-nw-system-dump-download-request
***
initiate the download of the system dump to the Endpoint Server.


#### Base Command

`rsa-nw-system-dump-download-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent ID of the host. | Required | 
| service_id | Service ID of the Endpoint Server to be connected. | Optional | 


#### Context Output

There is no context output for this command.
### rsa-nw-process-dump-download-request
***
initiate the download of the process dump to the Endpoint Server. You can find the process details by using the 'rsa-nw-snapshot-details-get' and filter by category=PROCESSES, or use the RSA NW UI.


#### Base Command

`rsa-nw-process-dump-download-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent ID of the host. | Required | 
| service_id | Service ID of the Endpoint Server to be connected. | Optional | 
| process_id | ID of the process. | Required | 
| eprocess | Identifier of the process in windows. | Required | 
| file_name | the file's name. | Required | 
| path | path to the file. | Optional | 
| hash | the hash (sha256 or md5) of the file. can be found in the 'rsa-nw-snapshot-details-get' command response under field fileProperties.checksumSha256 or fileProperties.checksumMd5. | Required | 
| process_create_utctime | The process created time in UTC. can be found in the 'rsa-nw-snapshot-details-get' response under  field windows.processes.createUtcTime. | Required | 


#### Context Output

There is no context output for this command.
### rsa-nw-endpoint-isolate-from-network
***
Isolates the host with the specified agent ID from the network.


#### Base Command

`rsa-nw-endpoint-isolate-from-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Unique identifier of the host. | Required | 
| service_id | Service ID of the Endpoint Server to be connected. | Optional | 
| allow_dns_only_by_system | Allow DNS communication. Possible values are: True, False. | Optional | 
| exclusion_list | Comma separated list of IPv4 or IPv6 addresses to excluded from isolation. For example - 1.2.3.4,11:22:33:44. | Optional | 
| comment | additional information. | Required | 


#### Context Output

There is no context output for this command.
### rsa-nw-endpoint-update-exclusions
***
Update the network isolation exclusion list for the host with the specified agent ID


#### Base Command

`rsa-nw-endpoint-update-exclusions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Unique identifier of the host. | Required | 
| service_id | Service ID of the Endpoint Server to be connected. | Optional | 
| allow_dns_only_by_system | Allow DNS communication. | Optional | 
| exclusion_list |  Comma separated list of IPv4 or IPv6 addresses to excluded from isolation. For example - 1.2.3.4,11:22:33:44. | Required | 
| comment | additional information. | Required | 


#### Context Output

There is no context output for this command.
### rsa-nw-endpoint-isolation-remove
***
restore the network connection and removes IP addresses added to the exclusion list for the host with the specified agent ID.


#### Base Command

`rsa-nw-endpoint-isolation-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Unique identifier of the host. | Required | 
| service_id | Service ID of the Endpoint Server to be connected. | Optional | 
| allow_dns_only_by_system | Allow DNS communication. | Optional | 
| comment | Additional information. | Required | 


#### Context Output

There is no context output for this command.