RSA NetWitness Platform provides systems Logs, Network, and endpoint visibility for real-time collection, detection, and automated response with the XSOAR Enterprise platform.

This integration was integrated and tested with version 12.2 of RSANetWitness.

The integration supports version 11.5 and higher.

## Changes compared to V11.1

### Changes in commands

- ***rsa-nw-remove-incident*** replaces the ***netwitness-delete-incident*** command.
- ***rsa-nw-incident-list-alerts*** replaces the ***netwitness-get-alerts*** command with an added limit option and new pagination options.
- ***rsa-nw-list-incidents*** replaces the ***netwitness-get-incident*** and ***netwitness-get-incidents*** commands.
- ***rsa-nw-update-incident*** replaces the ***netwitness-update-incident*** command.

### New commands

- ***endpoint*** 
- ***rsa-nw-endpoint-isolate-from-network*** 
- ***rsa-nw-endpoint-isolation-remove*** 
- ***rsa-nw-endpoint-update-exclusions*** 
- ***rsa-nw-file-alerts-list*** 
- ***rsa-nw-file-download*** 
- ***rsa-nw-files-list*** 
- ***rsa-nw-host-alerts-list*** 
- ***rsa-nw-hosts-list*** 
- ***rsa-nw-incident-add-journal-entry*** 
- ***rsa-nw-incident-list-alerts*** 
- ***rsa-nw-mft-download-request*** 
- ***rsa-nw-process-dump-download-request*** 
- ***rsa-nw-scan-request*** 
- ***rsa-nw-scan-stop-request*** 
- ***rsa-nw-services-list*** 
- ***rsa-nw-snapshot-details-get*** 
- ***rsa-nw-snapshots-list-for-host*** 
- ***rsa-nw-system-dump-download-request*** 

# API Limitations

Commands that require actions within a hostonly  return the status of the request received by our RSA server and not our host.
Whether the desired action was preformed successfully within the host is not reported back.

For example, for our ***rsa-nw-scan-request*** command a success message returned only confirms the request has been received by RSA NetWitness,
but does not indicate the scan has been preformed successfully in the requested host.
Commands affected by this limitation are: 

- ***rsa-nw-endpoint-isolate-from-network***
- ***rsa-nw-endpoint-isolation-remove*** 
- ***rsa-nw-endpoint-update-exclusions*** 
- ***rsa-nw-file-download*** 
- ***rsa-nw-mft-download-request***
- ***rsa-nw-process-dump-download-request***
- ***rsa-nw-scan-request***
- ***rsa-nw-scan-stop-request***
- ***rsa-nw-system-dump-download-request***

## Configure RSA NetWitness in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., <https://192.168.0.1>) |  | True |
| User name |  | True |
| Password |  | True |
| Service Id | The service ID that is automatically used in every command where service ID is required. Retrieve all service IDs with the rsa-nw-services-list command. To overwrite with another service ID, use the command argument 'service_id'. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Fetch Limit | The maximum number of incidents to fetch | False |
| Fetch Time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, for example, 12 hours, 7 days\) | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| On 'Fetch incidents' import all alerts related to the incident | | False |

### Configure incident mirroring
 
You can enable incident mirroring between Cortex XSOAR incidents and RSA NetWitness incidents (available from Cortex XSOAR version 6.0.0).

To setup the mirroring follow these instructions:

1. Navigate to **Settings** > **Integrations** > **Instances**.
2. Search for **RSANetWitness v11.5** and select your integration instance.
3. Enable **Fetches incidents**.
4. Under **Incident type**, select NetWitness Incident.
5. Under **Mapper (incoming)**, select RSA NetWitness v11.5 - incoming mapper.
6. In the *Incident Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:
    - Incoming - Any changes in RSA NetWitness incidents will be reflected in Cortex XSOAR incidents.
    - Outgoing - Any changes in XSOAR incidents will be reflected in RSA Netwitness incidents (`status`).
    - Incoming And Outgoing - Changes in Cortex XSOAR incidents and RSA NetWitness incidents will be reflected in both directions.
    - None - Turns off incident mirroring.
7. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding incident is closed in RSA NetWitness.

Newly fetched incidents will be mirrored in the chosen direction.  However, this selection does not affect existing incidents.

**Important Notes**

- When *mirroring in* incidents from RSA NetWitness to Cortex XSOAR, if the *Close Mirrored XSOAR Incident* integration parameter is enabled, the `status` field in RSA NetWitness determines whether the incident was closed.
- Journal entries, tasks, and assignees are currently not mirrored.
- Because of the implementation of the RSA API (you can get 1 incident by ID or every incident using a time interval), incidents are mirrored for a maximum of 24 days within a limit of 1500 incidents.


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### rsa-nw-list-incidents

***
Retrieves a single incident by ID or multiple incidents by the date and time they were created using the start time ('since') or end time ('until'). You can limit the results using the limit argument or the page size argument. If no arguments are entered the last 50 results are returned.


#### Base Command

`rsa-nw-list-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| until | A timestamp in the format 2020-01-18T14:00:00.000Z. Retrieve incidents created on and before this timestamp. | Optional | 
| since | A timestamp in the format 2020-01-18T14:00:00.000Z. Retrieve incidents created on and after this timestamp. | Optional | 
| page_size | The maximum number of items to return in a single page. Cannot be supplied with the limit argument. | Optional | 
| page_number | The requested page number, first page is 0. Cannot be supplied with the limit argument. | Optional | 
| limit | Maximum number of results to be returned. If not set, the first 50 results are returned. Cannot be supplied with page_size/page_number arguments. | Optional | 
| id | Enter an incident ID to receive its full details. For example, 'INC-40'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.Incidents.id | String | The unique incident identifier. | 
| RSANetWitness115.Incidents.title | String | The incident title. | 
| RSANetWitness115.Incidents.summary | String | The incident summary. | 
| RSANetWitness115.Incidents.priority | String | The incident priority. Can be Low, Medium, High, or Critical. | 
| RSANetWitness115.Incidents.riskScore | Number | The incident risk score is calculated based on the associated alert’s risk score. Risk score ranges from 0 \(no risk\) to 100 \(highest risk\). | 
| RSANetWitness115.Incidents.status | String | The current incident status. | 
| RSANetWitness115.Incidents.alertCount | Number | The number of alerts associated with an incident. | 
| RSANetWitness115.Incidents.averageAlertRiskScore | Number | The average risk score of the alerts associated with the incident. Risk score ranges from 0 \(no risk\) to 100 \(highest risk\). | 
| RSANetWitness115.Incidents.sealed | Boolean | Indicates if additional alerts can be associated with an incident. A sealed incident cannot be associated with additional alerts. | 
| RSANetWitness115.Incidents.totalRemediationTaskCount | Number | The number of total remediation tasks for an incident. | 
| RSANetWitness115.Incidents.openRemediationTaskCount | Number | The number of open remediation tasks for an incident. | 
| RSANetWitness115.Incidents.created | Date | The timestamp when the incident was created. | 
| RSANetWitness115.Incidents.lastUpdated | Date | The timestamp when the incident was last updated. | 
| RSANetWitness115.Incidents.lastUpdatedBy | String | The NetWitness user identifier of the user who last updated the incident. | 
| RSANetWitness115.Incidents.assignee | String | The NetWitness user identifier of the user currently working on the incident. | 
| RSANetWitness115.Incidents.sources | String | Unique set of sources for all the alerts in an incident. | 
| RSANetWitness115.Incidents.ruleId | String | The unique identifier of the rule that created the incident. | 
| RSANetWitness115.Incidents.firstAlertTime | String | The timestamp of the earliest occurring Alert in this incident. | 
| RSANetWitness115.Incidents.categories.id | String | The unique category identifier. | 
| RSANetWitness115.Incidents.categories.parent | String | The parent name of the category. | 
| RSANetWitness115.Incidents.categories.name | String | The friendly name of the category. | 
| RSANetWitness115.Incidents.journalEntries.id | String | The unique journal entry identifier. | 
| RSANetWitness115.Incidents.journalEntries.author | String | The author of this entry. | 
| RSANetWitness115.Incidents.journalEntries.notes | String | Notes and observations about the incident. | 
| RSANetWitness115.Incidents.journalEntries.created | String | The timestamp of the journal entry created date. | 
| RSANetWitness115.Incidents.journalEntries.lastUpdated | String | The timestamp of the journal entry last updated date. | 
| RSANetWitness115.Incidents.journalEntries.milestone | String | Incident milestone classifier. | 
| RSANetWitness115.Incidents.createdBy | String | The NetWitness user ID or name of the rule that created the incident. | 
| RSANetWitness115.Incidents.deletedAlertCount | Number | The number of alerts that are deleted from the incident. | 
| RSANetWitness115.Incidents.eventCount | Number | The number of events associated with incident. | 
| RSANetWitness115.Incidents.alertMeta.SourceIp | String | The unique source IP addresses. | 
| RSANetWitness115.Incidents.alertMeta.DestinationIp | String | The unique destination IP addresses. | 
| RSANetWitness115.paging.Incidents.hasNext | Boolean | Indicates if there is a page containing results after this page. | 
| RSANetWitness115.paging.Incidents.hasPrevious | Boolean | Indicates if there is a page containing results before this page. | 
| RSANetWitness115.paging.Incidents.pageNumber | Number | The requested page number. | 
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
Updates incident status and assignee.


#### Base Command

`rsa-nw-update-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The incident ID. | Required | 
| status | The new incident status. Can be New, Assigned, InProgress, RemediationRequested, RemediationComplete, Closed, ClosedFalsePositive. Possible values are: New, Assigned, InProgress, RemediationRequested, RemediationComplete, Closed, ClosedFalsePositive. | Optional | 
| assignee | The NetWitness user identifier of the user currently working on the incident. You can find the list of assignees in the RSA Net Witness interface. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.Incidents.id | String | The unique incident identifier. | 
| RSANetWitness115.Incidents.title | String | The incident title. | 
| RSANetWitness115.Incidents.summary | String | The incident summary. | 
| RSANetWitness115.Incidents.priority | String | The incident priority. Can be Low, Medium, High, or Critical. | 
| RSANetWitness115.Incidents.riskScore | Number | The incident risk score is calculated based on the associated alert’s risk score. Risk score ranges from 0 \(no risk\) to 100 \(highest risk\). | 
| RSANetWitness115.Incidents.status | String | The current incident status. | 
| RSANetWitness115.Incidents.alertCount | Number | The number of alerts associated with an incident. | 
| RSANetWitness115.Incidents.averageAlertRiskScore | Number | The average risk score of the alerts associated with the incident. Risk score ranges from 0 \(no risk\) to 100 \(highest risk\). | 
| RSANetWitness115.Incidents.sealed | Boolean | Indicates if additional alerts can be associated with an incident. A sealed incident cannot be associated with additional alerts. | 
| RSANetWitness115.Incidents.totalRemediationTaskCount | Number | The number of total remediation tasks for an incident. | 
| RSANetWitness115.Incidents.openRemediationTaskCount | Number | The number of open remediation tasks for an incident. | 
| RSANetWitness115.Incidents.created | Date | The timestamp when the incident was created. | 
| RSANetWitness115.Incidents.lastUpdated | Date | The timestamp when the incident was last updated. | 
| RSANetWitness115.Incidents.lastUpdatedBy | String | The NetWitness user identifier of the user who last updated the incident. | 
| RSANetWitness115.Incidents.assignee | String | The NetWitness user identifier of the user currently working on the incident. | 
| RSANetWitness115.Incidents.sources | String | Unique set of sources for all the alerts in an incident. | 
| RSANetWitness115.Incidents.ruleId | String | The unique identifier of the rule that created the incident. | 
| RSANetWitness115.Incidents.firstAlertTime | String | The timestamp of the earliest occurring Alert in this incident. | 
| RSANetWitness115.Incidents.categories.id | String | The unique category identifier. | 
| RSANetWitness115.Incidents.categories.parent | String | The parent name of the category. | 
| RSANetWitness115.Incidents.categories.name | String | The friendly name of the category. | 
| RSANetWitness115.Incidents.journalEntries.id | String | The unique journal entry identifier. | 
| RSANetWitness115.Incidents.journalEntries.author | String | The author of this entry. | 
| RSANetWitness115.Incidents.journalEntries.notes | String | Notes and observations about the incident. | 
| RSANetWitness115.Incidents.journalEntries.created | String | The timestamp of the journal entry created date. | 
| RSANetWitness115.Incidents.journalEntries.lastUpdated | String | The timestamp of the journal entry last updated date. | 
| RSANetWitness115.Incidents.journalEntries.milestone | String | Incident milestone classifier. | 
| RSANetWitness115.Incidents.createdBy | String | The NetWitness user ID or name of the rule that created the incident. | 
| RSANetWitness115.Incidents.deletedAlertCount | Number | The number of alerts that are deleted from the incident. | 
| RSANetWitness115.Incidents.eventCount | Number | The number of events associated with incident. | 
| RSANetWitness115.Incidents.alertMeta.SourceIp | String | The unique source IP addresses. | 
| RSANetWitness115.Incidents.alertMeta.DestinationIp | String | The unique destination IP addresses. |

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
| id | The unique incident identifier. | Required | 


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
| id | The unique incident identifier. | Required | 
| author | The NetWitness user ID of the user creating the journal entry. Can be found in the RSA platform. If no author is provided the command lists the user from the integration configuration as the author. | Optional | 
| notes | Notes and observations about the incident. | Required | 
| milestone | The incident milestone classifier. Can be Reconnaissance, Delivery, Exploitation, Installation, CommandAndControl, ActionOnObjective, Containment, Eradication, Closure. Possible values are: Reconnaissance, Delivery, Exploitation, Installation, CommandAndControl, ActionOnObjective, Containment, Eradication, Closure. | Optional | 


#### Context Output

There is no context output for this command.

#### Command example

```!rsa-nw-incident-add-journal-entry id=INC-24 notes="adding entry"```

#### Human Readable Output

>Journal entry added successfully for incident INC-24 

### rsa-nw-incident-list-alerts

***
Retrieves all the alerts that are associated with an incident based on the incident ID. you can limit the results using the limit argument or the page size argument.


#### Base Command

`rsa-nw-incident-list-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The unique incident identifier. | Required | 
| page_number | The requested page number, first page is 0. Cannot be supplied with the limit argument. | Optional | 
| page_size | The maximum number of items to return in a single page. Cannot be supplied with the limit argument. | Optional | 
| limit | The maximum number of results to be returned. If not set, the first 50 results are returned. cannot be supplied with page_size/page_number arguments. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.IncidentAlerts.id | String | The unique alert identifier. | 
| RSANetWitness115.IncidentAlerts.title | String | The title or name of the rule that created the alert. | 
| RSANetWitness115.IncidentAlerts.detail | String | The details of the alert. This can be the module name or meta that the module included. | 
| RSANetWitness115.IncidentAlerts.created | Date | The timestamp of the alert created date. | 
| RSANetWitness115.IncidentAlerts.source | String | The source of this alert. For example, Event Stream Analysis or Malware Analysis. | 
| RSANetWitness115.IncidentAlerts.riskScore | Number | The risk score of this alert, usually in the range 0 - 100. | 
| RSANetWitness115.IncidentAlerts.type | String | The type alert type. For example, Network or Log. | 
| RSANetWitness115.IncidentAlerts.events.source.device.ipAddress | String | The source IP address. | 
| RSANetWitness115.IncidentAlerts.events.source.device.port | Number | The source port. | 
| RSANetWitness115.IncidentAlerts.events.source.device.macAddress | String | The source ethernet MAC address. | 
| RSANetWitness115.IncidentAlerts.events.source.device.dnsHostname | String | The source DNS resolved hostname. | 
| RSANetWitness115.IncidentAlerts.events.source.device.dnsDomain | String | The source top-level domain from the DNS resolved hostname. | 
| RSANetWitness115.IncidentAlerts.events.source.user.username | String | The source unique username. | 
| RSANetWitness115.IncidentAlerts.events.source.user.emailAddress | String | The source email address. | 
| RSANetWitness115.IncidentAlerts.events.source.user.adUsername | String | The source Active Directory \(AD\) username. | 
| RSANetWitness115.IncidentAlerts.events.source.user.adDomain | String | The source Active Directory \(AD\) domain. | 
| RSANetWitness115.IncidentAlerts.events.destination.device.ipAddress | String | The destination IP address. | 
| RSANetWitness115.IncidentAlerts.events.destination.device.port | Number | The destination port. | 
| RSANetWitness115.IncidentAlerts.events.destination.device.macAddress | String | The destination ethernet MAC address. | 
| RSANetWitness115.IncidentAlerts.events.destination.device.dnsHostname | String | The destination DNS resolved hostname. | 
| RSANetWitness115.IncidentAlerts.events.destination.device.dnsDomain | String | The destination top-level domain from the DNS resolved hostname. | 
| RSANetWitness115.IncidentAlerts.events.destination.user.username | String | The destination unique username. | 
| RSANetWitness115.IncidentAlerts.events.destination.user.emailAddress | String | The destination email address. | 
| RSANetWitness115.IncidentAlerts.events.destination.user.adUsername | String | The destination Active Directory \(AD\) username. | 
| RSANetWitness115.IncidentAlerts.events.destination.user.adDomain | String | An destination Active Directory \(AD\) domain. | 
| RSANetWitness115.IncidentAlerts.events.domain | String | The destination top-level domain or Windows domain. | 
| RSANetWitness115.IncidentAlerts.events.eventSource | String | The source of the event. This may be a fully-qualified hostname with a port, or simple name. | 
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
Retrieves a list of all services, or filter by name.


#### Base Command

`rsa-nw-services-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the service. For example, endpoint-server. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.ServicesList.id | String | The unique identifier of each service installed in the RSA NetWitness suite. | 
| RSANetWitness115.ServicesList.name | String | The name of the service. For example, endpoint- server. | 
| RSANetWitness115.ServicesList.displayName | String | The display name of the service. | 
| RSANetWitness115.ServicesList.host | String | The host details of the service. | 
| RSANetWitness115.ServicesList.version | String | The version of the service. | 


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
Lists all host information from a specific endpoint server. Filter the results using the supplied arguments (can be a list) or use the 'filter' argument. You can limit the results using the limit argument or the page size argument.


#### Base Command

`rsa-nw-hosts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | The service ID of the specific endpoint server. View all service IDs using the 'rsa-nw-services-list' command. If none is given, the service ID configured in the integration configuration is used. | Optional | 
| page_number | The requested page number, first page is 0. Cannot be supplied with the limit argument. | Optional | 
| page_size | The maximum number of items to return in a single page. Cannot be supplied with the limit argument. | Optional | 
| limit | The maximum number of results to be returned. If not set, the first 50 results are returned. Cannot be supplied with page_size/page_number arguments. | Optional | 
| agent_id | A comma-separated list of host agent IDs. | Optional | 
| host_name | A comma-separated list of host names. | Optional | 
| risk_score | The host risk score. Returns all results with risk score greater than or equal to. | Optional | 
| ip | A comma-separated list of IPV4 in the network interface. | Optional | 
| filter | Custom filter in JSON format. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.HostsList.agentId | String | The host agent ID. | 
| RSANetWitness115.HostsList.hostName | String | The host name. | 
| RSANetWitness115.HostsList.riskScore | Number | The host risk score. | 
| RSANetWitness115.HostsList.networkInterfaces.name | String | The name of the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.macAddress | String | The MAC Address of the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.ipv4 | String | The list of IPV4 in the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.ipv6 | String | The list of IPV6 in the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.networkIdv6 | String | The list of network IDV6 in the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.gateway | String | The list of gateways in the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.dns | String | The list of DNS in the network interface. | 
| RSANetWitness115.HostsList.networkInterfaces.promiscuous | Boolean | Specifies if the network interface is in promiscuous mode. | 
| RSANetWitness115.HostsList.lastSeenTime | Date | The agent last seen time. | 
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
Retrieves host information for a specific endpoint. To use this command, service ID must be set in the integration configuration.


#### Base Command

`endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The endpoint ID. | Optional | 
| ip | The endpoint IP. | Optional | 
| hostname | The endpoint hostname. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The endpoint hostname. | 
| Endpoint.Relationships.EntityA | string | The relationship source. | 
| Endpoint.Relationships.EntityB | string | The relationship destination. | 
| Endpoint.Relationships.Relationship | string | The relationship name. | 
| Endpoint.Relationships.EntityAType | string | The relationship source type. | 
| Endpoint.Relationships.EntityBType | string | The relationship destination type. | 
| Endpoint.OS | String | The endpoint operation system. | 
| Endpoint.IPAddress | String | The endpoint IP address. | 
| Endpoint.ID | String | The endpoint ID. | 
| Endpoint.Status | String | The endpoint status. | 
| Endpoint.IsIsolated | String | The endpoint isolation status. | 
| Endpoint.MACAddress | String | The endpoint MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 
| Endpoint.Domain | String | The endpoint domain. | 
| Endpoint.DHCPServer | String | The endpoint DHCP server. | 
| Endpoint.OSVersion | String | The endpoint operation system version. | 
| Endpoint.BIOSVersion | String | The endpoint BIOS version. | 
| Endpoint.Model | String | The model of the machine or device. | 
| Endpoint.Memory | Int | The memory on this endpoint. | 
| Endpoint.Processors | Int | The number of processors. | 
| Endpoint.Processor | String | The processor model. | 


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

>### RSA NetWitness -  Endpoint: 1

>|Hostname|ID|IPAddress|MACAddress|Vendor|
>|---|---|---|---|---|
>| hostName | 1 | ['1.1.1.1'] | 111::111:11:111:11 | RSA NetWitness 11.5 Response |


### rsa-nw-snapshots-list-for-host

***
Retrieve a list os snapshot IDs for a given host.


#### Base Command

`rsa-nw-snapshots-list-for-host`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | The host agent ID. | Required | 
| service_id | The service ID of the specific endpoint server. View all service IDs using the 'rsa-nw-services-list' command. If none is given, the service ID configured in the integration configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.SnapshotsListForHost | Date | The list of snapshot timestamps. | 


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
Provides snapshot details of the given host for the specified snapshot time. It is recommended to use categories to filter the results since this command returns a large amount of data.


#### Base Command

`rsa-nw-snapshot-details-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | The host agent ID. | Required | 
| snapshot_timestamp | The start time of the scan snapshot. Can be retrieved using the 'rsa-nw-snapshots-list-for-host' command. | Required | 
| service_id | The service ID of the specific endpoint server. View all service IDs using the 'rsa-nw-services-list' command. If none is given, the service ID configured in the integration configuration is used. | Optional | 
| categories | A comma-separated list of categories to filter the results. For example, PROCESSES,SERVICES. Possible values are: PROCESSES, LOADED_LIBRARIES, SERVICES, AUTORUNS, TASKS, DRIVERS, THREADS, IMAGE_HOOKS, KERNEL_HOOKS.. | Optional | 
| limit | The maximum number of results returned by the command. Default is 50. | Optional | 
| offset | The offset to receive results from. For example, offset=3 returns results from the 3rd result onward. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.SnapshotDetailsGet.machineOsType | String | The operating system type \(Windows, Mac, Linux\). | 
| RSANetWitness115.SnapshotDetailsGet.hostName | String | The host name. | 
| RSANetWitness115.SnapshotDetailsGet.agentId | String | The host agent ID. | 
| RSANetWitness115.SnapshotDetailsGet.agentVersion | String | The agent version. | 
| RSANetWitness115.SnapshotDetailsGet.scanStartTime | Date | The start time of the scan snapshot. | 
| RSANetWitness115.SnapshotDetailsGet.directory | String | The file directory. | 
| RSANetWitness115.SnapshotDetailsGet.fileName | String | The file name. | 
| RSANetWitness115.SnapshotDetailsGet.owner.username | String | The user name of the file owner. | 
| RSANetWitness115.SnapshotDetailsGet.owner.groupname | String | The group name of the file owner. | 
| RSANetWitness115.SnapshotDetailsGet.owner.uid | String | The UID of the user name. | 
| RSANetWitness115.SnapshotDetailsGet.owner.gid | String | The GID of the user name. | 
| RSANetWitness115.SnapshotDetailsGet.timeCreated | Date | The timestamp when the file was created. | 
| RSANetWitness115.SnapshotDetailsGet.timeModified | Date | The timestamp when the file was modified. | 
| RSANetWitness115.SnapshotDetailsGet.timeAccessed | Date | The timestamp when the file was last accessed. | 
| RSANetWitness115.SnapshotDetailsGet.attributes | String | The list of file attributes. | 
| RSANetWitness115.SnapshotDetailsGet.accessMode | Number | The file access mode. | 
| RSANetWitness115.SnapshotDetailsGet.sameDirectoryFileCounts.nonExe | Number | The number of non-exe files in the same directory as the file. | 
| RSANetWitness115.SnapshotDetailsGet.sameDirectoryFileCounts.exe | Number | The number of exe files in the same directory as the file. | 
| RSANetWitness115.SnapshotDetailsGet.sameDirectoryFileCounts.subFolder | Number | The number of sub-folders in the same directory as the file. | 
| RSANetWitness115.SnapshotDetailsGet.sameDirectoryFileCounts.exeSameCompany | Number | The number of executables with the same company name in the same directory as the file. | 
| RSANetWitness115.SnapshotDetailsGet.sameDirectoryFileCounts.hiddenFiles | Number | The count of hidden files in the same directory as the file. | 
| RSANetWitness115.SnapshotDetailsGet.fileContext | String | The list of file context. | 
| RSANetWitness115.SnapshotDetailsGet.directoryContext | String | The list of directory context. | 
| RSANetWitness115.SnapshotDetailsGet.autorunContext | Unknown | The list of autorun context. | 
| RSANetWitness115.SnapshotDetailsGet.networkContext | Unknown | The list of network context. | 
| RSANetWitness115.SnapshotDetailsGet.kernelModeContext | Unknown | The list of kernel mode context. | 
| RSANetWitness115.SnapshotDetailsGet.userModeContext | Unknown | The list of user mode context. | 
| RSANetWitness115.SnapshotDetailsGet.processContext | Unknown | The list of process context. | 
| RSANetWitness115.SnapshotDetailsGet.rpm.packageName | String | The RPM package name to which the file belongs. | 
| RSANetWitness115.SnapshotDetailsGet.rpm.category | String | The category to which the RPM package belongs. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.pid | Number | The process ID. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.parentPid | Number | The parent process ID. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.imageBase | Number | The process image base address. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.createUtcTime | String | The process creation time. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.owner | String | The user name. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.launchArguments | String | The process launch arguments. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.threadCount | Number | The number of threads running in the process. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.eprocess | String | The process identifier. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.sessionId | Number | The process session ID. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.parentPath | String | The parent process directory. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.imageSize | Number | The process image size. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.integrityLevel | Number | The process integrity level. | 
| RSANetWitness115.SnapshotDetailsGet.windows.processes.context | String | The list of process context. | 
| RSANetWitness115.SnapshotDetailsGet.windows.dlls.createTime | Date | The process creation timestamp. | 
| RSANetWitness115.SnapshotDetailsGet.windows.dlls.eprocess | String | The process identity. | 
| RSANetWitness115.SnapshotDetailsGet.windows.dlls.imageSize | Number | The size of the DLL image in memory. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.processName | String | The process name. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.processTime | Date | The process creation timestamp. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.eprocess | String | The process identifier. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.pid | Number | The process ID. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.ethread | String | The thread identifier. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.tid | Number | The thread ID. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.teb | String | The address of the thread environment block. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.startAddress | String | The start address of the thread in memory. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.state | Unknown | The thread state. | 
| RSANetWitness115.SnapshotDetailsGet.windows.threads.behaviorKey | String | The floating behavior resolution of the thread. | 
| RSANetWitness115.SnapshotDetailsGet.windows.drivers.imageBase | Number | The driver image base address. | 
| RSANetWitness115.SnapshotDetailsGet.windows.drivers.imageSize | Number | The driver image size. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.serviceName | String | The service name as identified by the system. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.displayName | String | The service display name. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.description | String | The service description. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.account | String | The name of the user the service executes as. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.launchArguments | String | The launch arguments of the service. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.serviceMain | String | The service main. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.hostingPid | Number | The service hosting process ID. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.state | String | The service current state. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.win32ErrorCode | Number | The last Windows 32 error code from registry. | 
| RSANetWitness115.SnapshotDetailsGet.windows.services.context | Unknown | The list of service context. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.name | String | The task name. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.executeUser | String | The name of the user the task executes as. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.creatorUser | String | The name of the user who created the task. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.launchArguments | String | The launch arguments of the task. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.status | Unknown | The task status. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.lastRunTime | String | The time the task was last run. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.nextRunTime | String | The next scheduled time of the task. | 
| RSANetWitness115.SnapshotDetailsGet.windows.tasks.triggerString | String | The textual trigger string of the task. | 
| RSANetWitness115.SnapshotDetailsGet.windows.autoruns.type | String | The autorun type. | 
| RSANetWitness115.SnapshotDetailsGet.windows.autoruns.registryPath | String | The registry path where the autorun is located. | 
| RSANetWitness115.SnapshotDetailsGet.windows.autoruns.launchArguments | String | the autorun launch argument. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.process.pid | String | The PID of the process in which the hook was detected. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.process.fileName | String | The filename of the process in which the hook was detected. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.process.createUtcTime | String | The creation time of the process in which the hook was detected. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.hookLocation.section | String | The name of the image section that was modified by the hook. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.hookLocation.sectionBase | String | The base of the image section that was modified by the hook. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.hookLocation.symbol | String | The closest symbol name to the memory location that was modified. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.hookLocation.symbolOffset | Number | The closest symbol \+/- offset to the hook location when relevant. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.inlinePatch.originalBytes | String | The hexadecimal bytes which were replaced. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.inlinePatch.originalAsm | Unknown | The array of decoded ASM instructions that were replaced. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.inlinePatch.currentBytes | String | The hexadecimal bytes that overwrote the original code. | 
| RSANetWitness115.SnapshotDetailsGet.windows.imageHooks.inlinePatch.currentAsm | Unknown | The array of decoded ASM instructions that overwrote the original code. | 
| RSANetWitness115.SnapshotDetailsGet.windows.kernelHooks.hookLocation.objectName | String | Name of the object that was hooked in kernel. | 
| RSANetWitness115.SnapshotDetailsGet.windows.kernelHooks.hookLocation.objectFunction | String | The name of the object function that was hooked in the kernel. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.priority | Number | The process priority. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.flags | Number | The process flags. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.nice | Number | The nice value of the process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.openFilesCount | Number | The number of open files by process at scan time. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.context | Unknown | The process context. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.pid | Number | The process ID. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.parentPid | Number | The parent process ID. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.imageBase | Number | The process image base address. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.createUtcTime | String | The process UTC creation time. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.owner | String | The user name. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.launchArguments | String | The process launch arguments. | 
| RSANetWitness115.SnapshotDetailsGet.mac.processes.threadCount | Number | The number of threads running in the process. | 
| RSANetWitness115.SnapshotDetailsGet.mac.dylibs.pid | Number | The process ID in dylibs which is loaded. | 
| RSANetWitness115.SnapshotDetailsGet.mac.dylibs.processName | String | The process name in dylibs. | 
| RSANetWitness115.SnapshotDetailsGet.mac.dylibs.imageBase | String | The process image base address in dylibs. | 
| RSANetWitness115.SnapshotDetailsGet.mac.drivers.preLinked | Boolean | True if the kext bundle is prelinked. | 
| RSANetWitness115.SnapshotDetailsGet.mac.drivers.numberOfReferences | Number | The number of references. | 
| RSANetWitness115.SnapshotDetailsGet.mac.drivers.dependencies | Unknown | The list of kexts \(name\) the driver is linked against. | 
| RSANetWitness115.SnapshotDetailsGet.mac.drivers.imageBase | String | The driver image base address. | 
| RSANetWitness115.SnapshotDetailsGet.mac.drivers.imageSize | String | The driver image size. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.name | String | The daemon label. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.sessionName | String | The name of the session in which the daemon runs. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.user | String | The name of the user under which the daemon runs. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.pid | Number | The daemon PID. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.onDemand | Boolean | True if the daemon is configured to run on demand. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.lastExitCode | Number | The daemon last exit code. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.timeout | Number | The daemon timeout value. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.daemons.launchArguments | String | The daemon launch argument. | 
| RSANetWitness115.SnapshotDetailsGet.mac.daemons.daemons.config | String | The full path of the configuration file used to configure the daemon. | 
| RSANetWitness115.SnapshotDetailsGet.mac.tasks.name | String | The task name. | 
| RSANetWitness115.SnapshotDetailsGet.mac.tasks.cronJob | Boolean | True if the task is a cron job, else launchd. | 
| RSANetWitness115.SnapshotDetailsGet.mac.tasks.launchArguments | String | The task launch argument. | 
| RSANetWitness115.SnapshotDetailsGet.mac.tasks.user | String | The name of the user under which the task runs. | 
| RSANetWitness115.SnapshotDetailsGet.mac.tasks.triggerString | String | The task trigger string. | 
| RSANetWitness115.SnapshotDetailsGet.mac.tasks.configFile | String | The full path of the configuration file used to configure the task. | 
| RSANetWitness115.SnapshotDetailsGet.mac.autoruns.type | String | The autorun type. | 
| RSANetWitness115.SnapshotDetailsGet.mac.autoruns.user | String | The name of the user under which the autorun is run. | 
| RSANetWitness115.SnapshotDetailsGet.mac.autoruns.name | String | The autorun label. | 
| RSANetWitness115.SnapshotDetailsGet.mac.autoruns.detail | String | The autorun details. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.priority | Number | The process priority. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.uid | Number | The user UID. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.environment | String | The process environment variables. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.nice | Number | The process nice value. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.securityContext | String | The process security context. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.pid | Number | The process ID. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.parentPid | Number | The parent process ID. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.imageBase | Number | The process base address. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.createUtcTime | String | The process UTC creation time. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.owner | String | The user name. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.launchArguments | String | The process launch arguments. | 
| RSANetWitness115.SnapshotDetailsGet.linux.processes.threadCount | Number | The number of threads running in the process. | 
| RSANetWitness115.SnapshotDetailsGet.linux.loadedLibraries.pid | String | The process ID in the loaded library. | 
| RSANetWitness115.SnapshotDetailsGet.linux.loadedLibraries.processName | String | The process name in the loaded library. | 
| RSANetWitness115.SnapshotDetailsGet.linux.loadedLibraries.imageBase | String | The process image base address in the loaded library. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.numberOfInstances | Number | The number of instances loaded in memory. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.loadState | String | The driver load state. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.dependencies | Unknown | The dependent driver names. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.author | String | The driver author name. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.description | String | The driver description. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.sourceVersion | String | The driver source version. | 
| RSANetWitness115.SnapshotDetailsGet.linux.drivers.versionMagic | String | The driver version magic. | 
| RSANetWitness115.SnapshotDetailsGet.linux.initds.initdHashSha256 | String | The hash of the init-d script file. | 
| RSANetWitness115.SnapshotDetailsGet.linux.initds.initdPaths | String | The path of the init-d script file. | 
| RSANetWitness115.SnapshotDetailsGet.linux.initds.pid | Number | The process ID of the init-d script file. | 
| RSANetWitness115.SnapshotDetailsGet.linux.initds.description | String | The init-d script file description. | 
| RSANetWitness115.SnapshotDetailsGet.linux.initds.status | String | The init-d script file status. | 
| RSANetWitness115.SnapshotDetailsGet.linux.initds.runLevels | Unknown | The list of run levels in which the init-d script file is enabled. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.systemdHashSha256 | String | The systemd script file hash value. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.systemdPaths | String | The systemd script file path value. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.name | String | The systemd script file name. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.description | String | The systemd script file description. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.state | String | The systemd script file state. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.launchArguments | String | The systemd script file launch argument. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.pid | Number | The process ID. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.triggeredBy | Unknown | The systemd script file triggered by list. | 
| RSANetWitness115.SnapshotDetailsGet.linux.systemds.triggerStrings | Unknown | The systemd script file trigger strings. | 
| RSANetWitness115.SnapshotDetailsGet.linux.autoruns.type | String | The autorun type. | 
| RSANetWitness115.SnapshotDetailsGet.linux.autoruns.label | String | The autorun label. | 
| RSANetWitness115.SnapshotDetailsGet.linux.autoruns.comments | String | The autorun comments. | 
| RSANetWitness115.SnapshotDetailsGet.linux.crons.user | String | The user account under which cron job was created. | 
| RSANetWitness115.SnapshotDetailsGet.linux.crons.triggerString | String | The trigger string that launches the cron job. | 
| RSANetWitness115.SnapshotDetailsGet.linux.crons.launchArguments | String | The cron job launch arguments. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.firstFileName | String | The first name of the file sent by the agent. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.reputationStatus | String | The reputation status of the file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.globalRiskScore | String | The global risk score. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.firstSeenTime | String | The time the file was first seen by the endpoint server. | 
| RSANetWitness115.SnapshotDetailsGet.machineOsType | String | The operating system type \(Windows, Mac, Linux\). | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.signature | Object | The file signatory information. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.signature.timeStamp | String | The signature timestamp. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.signature.thumbprint | String | The certificate thumbprint. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.signature.context | Unknown | The certificate context information. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.signature.signer | String | The certificate signer information. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.size | String | The file size. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.checksumMd5 | String | The file MD5. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.checksumSha1 | String | The file SHA1. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.checksumSha256 | String | The file SHA256. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe | Object | The file PE information. This is applicable for Windows files. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.timeStamp | String | The PE file timestamp. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.imageSize | String | The PE file image size. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.numberOfExportedFunctions | String | The number of exported functions in the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.numberOfNamesExported | String | The number of names exported in the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.numberOfExecuteWriteSections | String | The number of execute write sections in the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.context | Unknown | The PE file context information. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.resources | Object | The PE file resources. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.resources.originalFileName | String | The original filename as per PE information. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.resources.company | String | The company name as per PE information. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.resources.description | String | The description of the file as per PE information. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.resources.version | String | The version of the file as per PE information. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.sectionNames | Unknown | The list of section names in the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.pe.importedLibraries | Unknown | The list of imported libraries in the PE file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.elf | Object | The ELF information of the file. This is applicable for Linux files. | 
| RSANetWitness115.SnapshotDetailsGet.elf.classType | String | The ELF file class type. | 
| RSANetWitness115.SnapshotDetailsGet.elf.data | String | The ELF file data. | 
| RSANetWitness115.SnapshotDetailsGet.elf.entryPoint | String | The ELF file entry point. | 
| RSANetWitness115.SnapshotDetailsGet.elf.context | Unknown | The ELF file context information. | 
| RSANetWitness115.SnapshotDetailsGet.elf.type | String | The ELF file type. | 
| RSANetWitness115.SnapshotDetailsGet.elf.sectionNames | Unknown | The list of section names in the ELF file. | 
| RSANetWitness115.SnapshotDetailsGet.elf.importedLibraries | Unknown | The list of imported libraries in the ELF file. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.macho | Object | The Macho file information. This is applicable for Mac files. | 
| RSANetWitness115.SnapshotDetailsGet.macho.uuid | String | The Macho file UUID. | 
| RSANetWitness115.SnapshotDetailsGet.macho.identifier | String | The Macho file identifier. | 
| RSANetWitness115.SnapshotDetailsGet.macho.minOsxVersion | String | The minimum OSx version for the Macho file. | 
| RSANetWitness115.SnapshotDetailsGet.macho.context | Unknown | The Macho file context information. | 
| RSANetWitness115.SnapshotDetailsGet.macho.flags | String | The Macho file flags. | 
| RSANetWitness115.SnapshotDetailsGet.macho.numberOfLoadCommands | String | The number of Macho file load commands. | 
| RSANetWitness115.SnapshotDetailsGet.macho.version | String | The Macho file version. | 
| RSANetWitness115.SnapshotDetailsGet.macho.sectionNames | Unknown | The Macho file section names. | 
| RSANetWitness115.SnapshotDetailsGet.macho.importedLibraries | Unknown | The Macho file imported libraries list. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.entropy | String | The file entropy. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.format | String | The file format. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.fileStatus | String | The file status as assigned by the analyst. Can be Whitelist, Blacklist, Neutral, or Graylist. | 
| RSANetWitness115.SnapshotDetailsGet.fileProperties.remediationAction | String | The remediation action as assigned by the analyst. For example, Blocked. | 
| RSANetWitness115.SnapshotDetailsGet.localRiskScore | Number | The file score based on alerts triggered in the given agent. | 

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
Lists all related file information from a specific endpoint server. You can limit the results using the limit argument or the page size argument.


#### Base Command

`rsa-nw-files-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | The service ID of the specific endpoint Server. View all service IDs using the 'rsa-nw-services-list' command. If none is given, the service ID configured in the integration configuration is used. | Optional | 
| page_number | The requested page number, first page is number 0. Cannot be supplied with the limit argument. | Optional | 
| page_size | The maximum number of items to return in a single page. Cannot be supplied with the limit argument. | Optional | 
| limit | The maximum number of results to be returned. If not set, the first 10 results are returned.  Cannot be supplied with page_size/page_number arguments. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.FilesList.windows.autoruns.type | String | The autorun type. | 
| RSANetWitness115.FilesList.windows.autoruns.registryPath | String | The registry path where autorun is located. | 
| RSANetWitness115.FilesList.windows.autoruns.launchArguments | String | The autorun launch argument. | 
| RSANetWitness115.FilesList.windows.imageHooks.process.pid | String | The PID of the process the hook was detected in. | 
| RSANetWitness115.FilesList.windows.imageHooks.process.fileName | String | The file name of the process the hook was detected in. | 
| RSANetWitness115.FilesList.windows.imageHooks.process.createUtcTime | String | The creation time of the process the hook was detected in. | 
| RSANetWitness115.FilesList.windows.imageHooks.hookLocation.section | String | The name of the image section modified by the hook. | 
| RSANetWitness115.FilesList.windows.imageHooks.hookLocation.sectionBase | String | The image section base modified by the hook. | 
| RSANetWitness115.FilesList.windows.imageHooks.hookLocation.symbol | String | The closest symbol name to the memory location that was modified. | 
| RSANetWitness115.FilesList.windows.imageHooks.hookLocation.symbolOffset | Number | The closest symbol \+/- offset to the hook location when relevant. | 
| RSANetWitness115.FilesList.windows.imageHooks.inlinePatch.originalBytes | String | The hexadecimal bytes that were replaced. | 
| RSANetWitness115.FilesList.windows.imageHooks.inlinePatch.originalAsm | Unknown | The array of decoded ASM instructions that were replaced. | 
| RSANetWitness115.FilesList.windows.imageHooks.inlinePatch.currentBytes | String | The hexadecimal bytes that overwrote the original code. | 
| RSANetWitness115.FilesList.windows.imageHooks.inlinePatch.currentAsm | Unknown | The array of decoded ASM instructions that overwrote the original code. | 
| RSANetWitness115.FilesList.windows.kernelHooks.hookLocation.objectName | String | The name of the object that was hooked in the kernel. | 
| RSANetWitness115.FilesList.windows.kernelHooks.hookLocation.objectFunction | String | The name of the object function that was hooked in the kernel. | 
| RSANetWitness115.FilesList.mac.processes.priority | Number | The process priority. | 
| RSANetWitness115.FilesList.mac.processes.flags | Number | The process flags. | 
| RSANetWitness115.FilesList.mac.processes.nice | Number | The process nice value. | 
| RSANetWitness115.FilesList.mac.processes.openFilesCount | Number | The number of open files by the process at scan time. | 
| RSANetWitness115.FilesList.mac.processes.context | Unknown | The process context. | 
| RSANetWitness115.FilesList.mac.processes.pid | Number | The process ID. | 
| RSANetWitness115.FilesList.mac.processes.parentPid | Number | The parent process ID. | 
| RSANetWitness115.FilesList.mac.processes.imageBase | Number | The process image base address. | 
| RSANetWitness115.FilesList.mac.processes.createUtcTime | String | The process UTC creation time. | 
| RSANetWitness115.FilesList.mac.processes.owner | String | The user name. | 
| RSANetWitness115.FilesList.mac.processes.launchArguments | String | The process launch arguments. | 
| RSANetWitness115.FilesList.mac.processes.threadCount | Number | The number of threads running in the process. | 
| RSANetWitness115.FilesList.mac.dylibs.pid | Number | The process ID in dylibs which is loaded. | 
| RSANetWitness115.FilesList.mac.dylibs.processName | String | The process name in dylibs. | 
| RSANetWitness115.FilesList.mac.dylibs.imageBase | String | The process image base address in dylibs. | 
| RSANetWitness115.FilesList.mac.drivers.preLinked | Boolean | True if the kext bundle is prelinked. | 
| RSANetWitness115.FilesList.mac.drivers.numberOfReferences | Number | The number of references. | 
| RSANetWitness115.FilesList.mac.drivers.dependencies | Unknown | The list of kexts\(name\) the driver is linked against. | 
| RSANetWitness115.FilesList.mac.drivers.imageBase | String | The driver image base address. | 
| RSANetWitness115.FilesList.mac.drivers.imageSize | String | The driver image size. | 
| RSANetWitness115.FilesList.mac.daemons.name | String | The daemon label. | 
| RSANetWitness115.FilesList.mac.daemons.sessionName | String | The name of the session in which daemon runs. | 
| RSANetWitness115.FilesList.mac.daemons.user | String | The name of the user under which the daemon runs. | 
| RSANetWitness115.FilesList.mac.daemons.pid | Number | The daemon ID. | 
| RSANetWitness115.FilesList.mac.daemons.onDemand | Boolean | True if the daemon is configured to run on demand. | 
| RSANetWitness115.FilesList.mac.daemons.lastExitCode | Number | The daemon last exit code. | 
| RSANetWitness115.FilesList.mac.daemons.timeout | Number | The daemon timeout value. | 
| RSANetWitness115.FilesList.mac.daemons.daemons.launchArguments | String | The daemon launch argument. | 
| RSANetWitness115.FilesList.mac.daemons.daemons.config | String | The full path of the configuration file used to configure the daemon. | 
| RSANetWitness115.FilesList.mac.tasks.name | String | The task name. | 
| RSANetWitness115.FilesList.mac.tasks.cronJob | Boolean | True if the task is a cron job, else launchd. | 
| RSANetWitness115.FilesList.mac.tasks.launchArguments | String | The task launch argument. | 
| RSANetWitness115.FilesList.mac.tasks.user | String | The name of the user under which this task will run. | 
| RSANetWitness115.FilesList.mac.tasks.triggerString | String | The task trigger string. | 
| RSANetWitness115.FilesList.mac.tasks.configFile | String | The full path of the configuration file used to configure the task. | 
| RSANetWitness115.FilesList.mac.autoruns.type | String | The autorun type. | 
| RSANetWitness115.FilesList.mac.autoruns.user | String | The name of the user under which the autorun is run. | 
| RSANetWitness115.FilesList.mac.autoruns.name | String | The autorun label. | 
| RSANetWitness115.FilesList.mac.autoruns.detail | String | The autorun details. | 
| RSANetWitness115.FilesList.linux.processes.priority | Number | The process priority. | 
| RSANetWitness115.FilesList.linux.processes.uid | Number | The user UID. | 
| RSANetWitness115.FilesList.linux.processes.environment | String | The environment variables. | 
| RSANetWitness115.FilesList.linux.processes.nice | Number | The process nice value. | 
| RSANetWitness115.FilesList.linux.processes.securityContext | String | The process security context. | 
| RSANetWitness115.FilesList.linux.processes.pid | Number | The process ID. | 
| RSANetWitness115.FilesList.linux.processes.parentPid | Number | The parent process ID. | 
| RSANetWitness115.FilesList.linux.processes.imageBase | Number | The process base address. | 
| RSANetWitness115.FilesList.linux.processes.createUtcTime | String | The process UTC creation time. | 
| RSANetWitness115.FilesList.linux.processes.owner | String | The user name. | 
| RSANetWitness115.FilesList.linux.processes.launchArguments | String | The process launch arguments. | 
| RSANetWitness115.FilesList.linux.processes.threadCount | Number | The number of threads running in the process. | 
| RSANetWitness115.FilesList.linux.loadedLibraries.pid | String | The process ID in the loaded library. | 
| RSANetWitness115.FilesList.linux.loadedLibraries.processName | String | The process name in the loaded library. | 
| RSANetWitness115.FilesList.linux.loadedLibraries.imageBase | String | The process image base address in the loaded library. | 
| RSANetWitness115.FilesList.linux.drivers.numberOfInstances | Number | The number of instances loaded in memory. | 
| RSANetWitness115.FilesList.linux.drivers.loadState | String | The driver load state. | 
| RSANetWitness115.FilesList.linux.drivers.dependencies | Unknown | The dependent driver names. | 
| RSANetWitness115.FilesList.linux.drivers.author | String | The driver author name. | 
| RSANetWitness115.FilesList.linux.drivers.description | String | The driver description. | 
| RSANetWitness115.FilesList.linux.drivers.sourceVersion | String | The driver source version. | 
| RSANetWitness115.FilesList.linux.drivers.versionMagic | String | The driver version magic. | 
| RSANetWitness115.FilesList.linux.initds.initdHashSha256 | String | The init-d script file hash. | 
| RSANetWitness115.FilesList.linux.initds.initdPaths | String | The init-d script file path. | 
| RSANetWitness115.FilesList.linux.initds.pid | Number | The init-d script file process ID. | 
| RSANetWitness115.FilesList.linux.initds.description | String | The init-d script file description. | 
| RSANetWitness115.FilesList.linux.initds.status | String | The init-d script file status. | 
| RSANetWitness115.FilesList.linux.initds.runLevels | Unknown | The ist of run levels in which the init-d script file is enabled. | 
| RSANetWitness115.FilesList.linux.systemds.systemdHashSha256 | String | The systemd script file hash value. | 
| RSANetWitness115.FilesList.linux.systemds.systemdPaths | String | The systemd script file path value. | 
| RSANetWitness115.FilesList.linux.systemds.name | String | The systemd script file name. | 
| RSANetWitness115.FilesList.linux.systemds.description | String | The systemd script file description. | 
| RSANetWitness115.FilesList.linux.systemds.state | String | The systemd script file state. | 
| RSANetWitness115.FilesList.linux.systemds.launchArguments | String | The systemd script file launch argument. | 
| RSANetWitness115.FilesList.linux.systemds.pid | Number | The systemd script file process ID. | 
| RSANetWitness115.FilesList.linux.systemds.triggeredBy | Unknown | The systemd script file triggered by list. | 
| RSANetWitness115.FilesList.linux.systemds.triggerStrings | Unknown | The systemd script file trigger strings. | 
| RSANetWitness115.FilesList.linux.autoruns.type | String | The autorun type. | 
| RSANetWitness115.FilesList.linux.autoruns.label | String | The autorun label. | 
| RSANetWitness115.FilesList.linux.autoruns.comments | String | The autorun comments. | 
| RSANetWitness115.FilesList.linux.crons.user | String | The user account under which cron job was created. | 
| RSANetWitness115.FilesList.linux.crons.triggerString | String | The trigger string that launches the cron job. | 
| RSANetWitness115.FilesList.linux.crons.launchArguments | String | The cron job launch arguments. | 
| RSANetWitness115.FilesList.firstFileName | String | The first name of the file sent by the agent. | 
| RSANetWitness115.FilesList.reputationStatus | String | The file reputation status. | 
| RSANetWitness115.FilesList.globalRiskScore | String | The global risk score. | 
| RSANetWitness115.FilesList.firstSeenTime | String | The time the file was first seen by the endpoint server. | 
| RSANetWitness115.FilesList.fileProperties.machineOsType | String | The operating system type \(Windows, Mac, Linux\). | 
| RSANetWitness115.FilesList.signature | Object | The file signatory information. | 
| RSANetWitness115.FilesList.signature.timeStamp | String | The signature timestamp. | 
| RSANetWitness115.FilesList.signature.thumbprint | String | The certificate thumbprint. | 
| RSANetWitness115.FilesList.signature.context | Unknown | The certificate context information. | 
| RSANetWitness115.FilesList.signature.signer | String | The certificate signer information. | 
| RSANetWitness115.FilesList.size | String | The file size. | 
| RSANetWitness115.FilesList.checksumMd5 | String | The file MD5. | 
| RSANetWitness115.FilesList.checksumSha1 | String | The file SHA1. | 
| RSANetWitness115.FilesList.checksumSha256 | String | The file SHA256. | 
| RSANetWitness115.FilesList.pe | Object | The file PE information. This is applicable for Windows files. | 
| RSANetWitness115.FilesList.pe.timeStamp | String | The PE file timestamp. | 
| RSANetWitness115.FilesList.pe.imageSize | String | The PE file image size. | 
| RSANetWitness115.FilesList.pe.numberOfExportedFunctions | String | The number of exported functions in the PE file. | 
| RSANetWitness115.FilesList.pe.numberOfNamesExported | String | The number of names exported in the PE file. | 
| RSANetWitness115.FilesList.pe.numberOfExecuteWriteSections | String | The number of execute write sections in the PE file. | 
| RSANetWitness115.FilesList.pe.context | Unknown | The PE file context information. | 
| RSANetWitness115.FilesList.pe.resources | Object | The PE file resources. | 
| RSANetWitness115.FilesList.pe.resources.originalFileName | String | The original filename as per PE information. | 
| RSANetWitness115.FilesList.pe.resources.company | String | The company name as per PE information. | 
| RSANetWitness115.FilesList.pe.resources.description | String | The file description as per PE information. | 
| RSANetWitness115.FilesList.pe.resources.version | String | The file version as per PE information. | 
| RSANetWitness115.FilesList.pe.sectionNames | Unknown | The list of section names in the PE file. | 
| RSANetWitness115.FilesList.pe.importedLibraries | Unknown | The list of imported libraries in the PE file. | 
| RSANetWitness115.FilesList.elf | Object | The file ELF information. This is applicable for Linux files. | 
| RSANetWitness115.FilesList.elf.classType | String | The ELF file Class type. | 
| RSANetWitness115.FilesList.elf.data | String | The ELF file data. | 
| RSANetWitness115.FilesList.elf.entryPoint | String | The ELF file entry point. | 
| RSANetWitness115.FilesList.elf.context | Unknown | The ELF file context information. | 
| RSANetWitness115.FilesList.elf.type | String | The ELF file type. | 
| RSANetWitness115.FilesList.elf.sectionNames | Unknown | The list of section names in the ELF file. | 
| RSANetWitness115.FilesList.elf.importedLibraries | Unknown | The list of imported libraries in the ELF file. | 
| RSANetWitness115.FilesList.macho | Object | The file Macho information. This is applicable for Mac files. | 
| RSANetWitness115.FilesList.macho.uuid | String | The Macho file UUID. | 
| RSANetWitness115.FilesList.macho.identifier | String | The Macho file identifier. | 
| RSANetWitness115.FilesList.macho.minOsxVersion | String | The minimum OSx version for the Macho file. | 
| RSANetWitness115.FilesList.macho.context | Unknown | The Macho file context information. | 
| RSANetWitness115.FilesList.macho.flags | String | The Macho file flags. | 
| RSANetWitness115.FilesList.macho.numberOfLoadCommands | String | The number of load commands for the Macho file. | 
| RSANetWitness115.FilesList.macho.version | String | The Macho file version. | 
| RSANetWitness115.FilesList.macho.sectionNames | Unknown | The Macho file section names. | 
| RSANetWitness115.FilesList.macho.importedLibraries | Unknown | The Macho file imported libraries list. | 
| RSANetWitness115.FilesList.entropy | String | The file entropy. | 
| RSANetWitness115.FilesList.format | String | The file format. | 
| RSANetWitness115.FilesList.fileStatus | String | The file status as assigned by the analyst. Can be Whitelist, Blacklist, Neutral, or Graylist. | 
| RSANetWitness115.FilesList.remediationAction | String | The remediation action as assigned by the analyst. For example, Blocked. | 
| RSANetWitness115.FilesList.localRiskScore | Number | The file score based on alerts triggered in the given agent. | 


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
Starts a scan for the host with the specified agent ID. Each scan produces a snapshot, the full details can be seen using the 'rsa-nw-snapshot-details-get' command.


#### Base Command

`rsa-nw-scan-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | The host agent ID. | Required | 
| service_id | The service ID of the specific endpoint server. View all service IDs using the 'rsa-nw-services-list' command. If none is given, the service ID configured in the integration configuration is used. | Optional | 
| cpu_max | You can use cpuMax to specify the amount of CPU the agent can use to run the scan. You can choose a value from 5 to 100. If you do not specify a value, the agent uses the default 25% CPU for the scan. | Optional | 


#### Context Output

There is no context output for this command.

#### Command example

```!rsa-nw-scan-request agent_id=1```

#### Human Readable Output

>Scan request for host 1 Sent Successfully

### rsa-nw-scan-stop-request

***
Stop a scan for the host with the specified agent ID.


#### Base Command

`rsa-nw-scan-stop-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Unique identifier of the host. | Required | 
| service_id | The service ID of the specific endpoint server. View all service IDs using the 'rsa-nw-services-list' command. If none is given, the service ID configured in the integration configuration is used. | Optional | 


#### Context Output

There is no context output for this command.

#### Command example

```!rsa-nw-scan-stop-request agent_id=1```

#### Human Readable Output

>Scan cancellation request for host 1, sent successfully

### rsa-nw-host-alerts-list

***
Gets all alerts triggered for a given host.


#### Base Command

`rsa-nw-host-alerts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Unique host identifier. | Required | 
| service_id | The service ID of the specific endpoint server. View all service IDs using the 'rsa-nw-services-list' command. If none is given, the service ID configured in the integration configuration is used. | Optional | 
| alert_category | Filter alerts based on the category. Can be Critical, High, Medium, or Low. Possible values are: Critical, High, Medium, Low. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.HostAlerts.id | String | The entity ID for which the score needs to be queried. Use agent ID for hosts and checksum for files. | 
| RSANetWitness115.HostAlerts.distinctAlertCount.critical | Number | The number of critical alerts. | 
| RSANetWitness115.HostAlerts.distinctAlertCount.high | Number | The number of high alerts. | 
| RSANetWitness115.HostAlerts.distinctAlertCount.medium | Number | The number of medium alerts. | 
| RSANetWitness115.HostAlerts.distinctAlertCount.low | Number | The number of low alerts. | 
| RSANetWitness115.HostAlerts.categorizedAlerts | String | The alert and event count for a file/host, categorized by severity. | 

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
Gets all alerts triggered for a given file.


#### Base Command

`rsa-nw-file-alerts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| check_sum | The file hash, either md5 or sha256. Possible values are: . | Required | 
| service_id | The service ID of the specific endpoint server. View all service IDs using the 'rsa-nw-services-list' command. If none is given, the service ID configured in the integration configuration is used. | Optional | 
| alert_category | Filter alerts based on the category.  Can be Critical, High, Medium, or Low. Possible values are: Critical, High, Medium, Low. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RSANetWitness115.FileAlerts.id | String | The entity ID for which score needs to be queried. Use agent ID for hosts and checksum for files. | 
| RSANetWitness115.FileAlerts.distinctAlertCount.critical | Number | The number of critical alerts. | 
| RSANetWitness115.FileAlerts.distinctAlertCount.high | Number | The number of high alerts. | 
| RSANetWitness115.FileAlerts.distinctAlertCount.medium | Number | The number of medium alerts. | 
| RSANetWitness115.FileAlerts.distinctAlertCount.low | Number | The number of low alerts. | 
| RSANetWitness115.FileAlerts.categorizedAlerts | String | The alert and event count for a file/host, categorized by severity. | 

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
Initiate file download for a single file or multiple files to the endpoint server.


#### Base Command

`rsa-nw-file-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | The host agent ID. | Required | 
| service_id | The service ID of the specific endpoint server. View all service IDs using the 'rsa-nw-services-list' command. If none is given, the service ID configured in the integration configuration is used. | Optional | 
| path | The path where the files may be present, either specify a single file path or use a wild card. for example - "C:\Users\sample\*" . To see scanned files paths use the command 'rsa-nw-snapshot-details-get'. | Required | 
| count_files | The maximum number of files returned by the host matching the wild card path. Default is 10. | Optional | 
| max_file_size | The maximum size of each file (in MB) when using a wild card path. Default is 100. | Optional | 


#### Context Output

There is no context output for this command.

#### Command example

```!rsa-nw-file-download agent_id=1 path=path/to/file```

#### Human Readable Output

>Request for download path/to/file sent successfully

### rsa-nw-mft-download-request

***
Initiates the MFT download to the endpoint server.


#### Base Command

`rsa-nw-mft-download-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | The host agent ID. | Required | 
| service_id | The service ID of the endpoint server to be connected. | Optional |
| path | Drive or NTFS mount path for which MFT is requested. | Optional |


#### Context Output

There is no context output for this command.

### rsa-nw-system-dump-download-request

***
Initiates the download of the system dump to the endpoint server.


#### Base Command

`rsa-nw-system-dump-download-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | The host agent ID. | Required | 
| service_id | The service ID of the endpoint server to be connected. | Optional | 


#### Context Output

There is no context output for this command.

### rsa-nw-process-dump-download-request

***
Initiates the download of the process dump to the endpoint server. You can find the process details by using the 'rsa-nw-snapshot-details-get' and filter by category=PROCESSES, or use the RSA NW UI.


#### Base Command

`rsa-nw-process-dump-download-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | The host agent ID. | Required | 
| service_id | The service ID of the endpoint server to be connected. | Optional | 
| process_id | The process ID. | Required | 
| eprocess | The process identifier in Windows. | Required | 
| file_name | the file name. | Required | 
| path | The file path. | Optional | 
| hash | The hash (sha256 or md5) of the file. Can be found in the 'rsa-nw-snapshot-details-get' command response under field fileProperties.checksumSha256 or fileProperties.checksumMd5. | Required | 
| process_create_utctime | The process UTC created time. Can be found in the 'rsa-nw-snapshot-details-get' response under field windows.processes.createUtcTime. | Required | 


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
| agent_id | The unique host identifier. | Required | 
| service_id | The service ID of the endpoint server to be connected. | Optional | 
| allow_dns_only_by_system | Allow DNS communication. Possible values are: True, False. | Optional | 
| exclusion_list | A comma-separated list of IPv4 or IPv6 addresses to excluded from isolation. For example, 1.2.3.4,11:22:33:44. | Optional | 
| comment | Additional information. | Required | 


#### Context Output

There is no context output for this command.

### rsa-nw-endpoint-update-exclusions

***
Updates the network isolation exclusion list for the host with the specified agent ID.


#### Base Command

`rsa-nw-endpoint-update-exclusions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | The unique host identifier. | Required | 
| service_id | The service ID of the endpoint server to be connected. | Optional | 
| allow_dns_only_by_system | Allows DNS communication. | Optional | 
| exclusion_list |  A comma-separated list of IPv4 or IPv6 addresses to excluded from isolation. For example, 1.2.3.4,11:22:33:44. | Required | 
| comment | Additional information. | Required | 


#### Context Output

There is no context output for this command.

### rsa-nw-endpoint-isolation-remove

***
Restores the network connection and removes IP addresses added to the exclusion list for the host with the specified agent ID.


#### Base Command

`rsa-nw-endpoint-isolation-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | The unique host identifier. | Required | 
| service_id | The service ID of the endpoint server to be connected. | Optional | 
| allow_dns_only_by_system | Allows DNS communication. | Optional | 
| comment | Additional information. | Required | 


#### Context Output

There is no context output for this command.

# Create a filter for hosts-list command

You can create a custom filter for the ras-nw-hosts-list command, here is a short explanation.
The basic filter that can be used is of this format - 

    '{

    "criteria": {

            "criteriaList": [
            {
            "expressionList": [{ "propertyName": "agentId", "restrictionType":
                                "EQUAL","propertyValues": [{"value": "2F53FC2C-A737-B34B-6813-12E48379C15D"}]}]
    } ]

    }'

The following are the supported 'restrictionType' 

• Operators that require no value: IS_NULL, IS_NOT_NULL. 

• Operators that require one value: LIKE, NOT_LIKE, EQUAL, NOT_EQUAL, LESS_THAN,LESS_THAN_OR_EQUAL_TO, GREATER_THAN, GREATER_THAN_OR_EQUAL_TO.

• Operators that require two value: BETWEEN, NOT_BETWEEN.

• Operators that uses multiple value: IN, NOT_IN.

The following are the supported 'predicateType' - AND, OR, NOT.

a more complex example -

    {

    "criteria": {

        "criteriaList": [
    
          {
    
            "criteriaList": [],
    
            "expressionList": [
    
              {
    
                "propertyName": "hostName",
    
                "restrictionType": "LIKE",
    
                "propertyValues": [
    
                  {
    
                    "value": "WIN-854PACLCQ07-VC",
    
                    "relative": false
    
                  }
    
                ]
    
              }
    
            ],
    
            "predicateType": "AND"
    
          },
    
          {
    
            "criteriaList": [],
    
            "expressionList": [
    
              {
    
                "propertyName": "riskScore",
    
                "restrictionType": "BETWEEN",
    
                "propertyValues": [
    
                  {
    
                    "value": 0,
    
                    "relative": false
    
                  },
    
                  {
    
                    "value": 100,
    
                    "relative": false
    
                  }
    
                ]
    
              }
    
            ],
    
            "predicateType": "OR"
    
          }
    
        ],
    
        "expressionList": [],
    
        "predicateType": "AND"
    
        },
    
        "sort": {
    
        "keys": [
    
          "riskScore"
    
        ],
    
        "descending": true
    
        }

    }
