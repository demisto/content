Facilitates mirroring of Cortex XSOAR incidents between different Cortex XSOAR tenants.
This integration is compatible with Cortex XSOAR versions 6.x and 8.x, and it has been tested for interoperability across the range of Cortex XSOAR versions from 6.12 and lower and 8.4 and lower.

## Configure XSOAR Mirroring on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for XSOAR Mirroring.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Incident type |  | False |
    | XSOAR Server URL | The URL of the Cortex XSOAR server to which you are connecting. | True |
    | API Key | The API key to access the server. The key must be provided by the server to which you are connecting. | False |
    | API Key ID | The API key to access the server. The key must be provided by the server to which you are connecting. When the target server is XSOAR 8.X, the API Key ID is required as well \(not relevant for XSOAR 6.X\). | False |
    | Fetch incidents |  | False |
    | Maximum number of incidents to pull per fetch |  | False |
    | Fetch only incidents that match the query | Don't add created time to the query as this field will be addressed in the "First fetch time". | False |
    | First fetch time | Date or relative timestamp to start fetching incidents from, in the format of &lt;number&gt; &lt;time unit&gt;. For example, 2 minutes, 12 hours, 6 days, 2 weeks, 3 months, 1 year, ISO timestamp. Default is 3 days. | False |
    | Entry Categories | Which entries to retrieve from the Cortex XSOAR server. The available options are notes, comments \(chats\), and files. \(attachments\). | False |
    | Incoming Entry tags | Only entries with these tags are retrieved from the Cortex XSOAR server. If no tags are listed, no entries are retrieved. | False |
    | Outgoing Entry Tags | Choose the tags to filter the entries you want to send to the other Cortex XSOAR instance. If no tags are listed, no entries will be sent. | False |
    | Incident Mirroring Direction |  | False |
    | Disable fetching for incidents that came from this integration | Enable this option to disable mirroring of incidents that came from the integration of XSOAR Mirroring. This adds \`-sourceBrand:“XSOAR Mirroring”\` to your query. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Debug mode (will print debug logs to info) |  | False |
    | Mirror Playbook ID | A parameter integration that removes the playbook ID field from incoming incidents. Note: When set to true \(default\), the instance will attempt to run a playbook according to the incoming ID. When set to false, the instance will run the default playbook for the incident type \(if configured locally\). | False |
    | Fetch incident history | Will mirror historical notes,tags and attachments in case their corresponding incidents were deleted. Notice can impact performance if combined with "Reset the "last run" timestamp" and multiple incidents in system.<br/> | False |

4. To set up the mirroring, enable *Fetching incidents* in your instance configuration.
5. In the *Incident Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in XSOAR Mirroring events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in XSOAR Mirroring events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and XSOAR Mirroring events will be reflected in both directions. 
   Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.

   **Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and XSOAR Mirroring.

6. Click **Test** to ensure that you can communicate with the Cortex XSOAR tenant.


## Important notes:

- In order to mirror custom fields, you need to create an incoming mapper for the integration and explicitly specify them in it.
- In order to mirror custom fields in both directions, the custom fields in both Cortex XSOAR instances must have the same CLI name.
- Mirrored incidents include the playbook ID. The receiving side will attempt to run a playbook with a matching ID, if one exists locally. To have the machine run the default playbook for the mirrored incident, set the `Mirror Playbook ID` to `false`. Otherwise (default), the machine will attempt to run a playbook whose ID matches the `playbookId` field in the mirrored incident.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### xsoar-search-incidents

***
Search remote Cortex XSOAR for incidents.

#### Base Command

`xsoar-search-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Which incidents to retrieve. Default is -status:closed -category:job. | Optional | 
| start_time | From when to search. Default is 3 days. | Optional | 
| max_results | How many incidents to retrieve. Default is 10. | Optional | 
| columns | Which columns to display. Default is 'id,name,type,status,severity,owner,occured'. To display all columns, insert 'all'. Default is id,name,type,status,severity,owner,occured. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!xsoar-search-incidents query="-status:closed -category:job"```

#### Context Example

```json
{
    "XSOAR": {
        "Incident": {
            "CustomFields": {
                "containmentsla": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 30,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "detectionsla": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 20,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "endpoint": [
                    {}
                ],
                "filerelationships": [
                    {},
                    {},
                    {}
                ],
                "isactive": "true",
                "numberofrelatedincidents": 0,
                "numberofsimilarfiles": 0,
                "remediationsla": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 7200,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "similarincidentsdbot": [
                    {}
                ],
                "timetoassignment": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 0,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "triagesla": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 30,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "urlsslverification": []
            },
            "account": "",
            "activated": "0001-01-01T00:00:00Z",
            "attachment": null,
            "autime": 1678010808446441500,
            "cacheVersn": 0,
            "canvases": null,
            "category": "",
            "changeStatus": "new",
            "closeNotes": "",
            "closeReason": "",
            "closed": "0001-01-01T00:00:00Z",
            "closingUserId": "",
            "created": "2023-03-05T10:06:48.446441591Z",
            "dbotCreatedBy": "admin",
            "dbotCurrentDirtyFields": null,
            "dbotDirtyFields": null,
            "dbotMirrorDirection": "",
            "dbotMirrorId": "",
            "dbotMirrorInstance": "",
            "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
            "dbotMirrorTags": null,
            "details": "This is the new details",
            "droppedCount": 0,
            "dueDate": "2023-03-15T10:06:48.446441591Z",
            "feedBased": false,
            "id": "4",
            "insights": 0,
            "investigationId": "4",
            "isDebug": false,
            "isPlayground": false,
            "labels": [
                {
                    "type": "Instance",
                    "value": "admin"
                },
                {
                    "type": "Brand",
                    "value": "Manual"
                }
            ],
            "lastJobRunTime": "0001-01-01T00:00:00Z",
            "lastOpen": "0001-01-01T00:00:00Z",
            "linkedCount": 0,
            "linkedIncidents": null,
            "modified": "2023-03-05T14:43:22.319158041Z",
            "name": "testing",
            "notifyTime": "2023-03-05T10:06:50.261155172Z",
            "occurred": "2023-03-05T10:06:48.446441435Z",
            "openDuration": 0,
            "owner": "admin",
            "parent": "",
            "phase": "",
            "playbookId": "playbook0",
            "rawCategory": "",
            "rawCloseReason": "",
            "rawJSON": "",
            "rawName": "testing",
            "rawPhase": "",
            "rawType": "Unclassified",
            "reason": "",
            "reminder": "0001-01-01T00:00:00Z",
            "runStatus": "waiting",
            "severity": 0,
            "sla": 0,
            "sortValues": [],
            "sourceBrand": "Manual",
            "sourceInstance": "admin",
            "status": 1,
            "type": "Unclassified",
            "version": 13
        }
    }
}
```

#### Human Readable Output

>### Search Results:

>|id|name|type|status|severity|owner|occured|
>|---|---|---|---|---|---|---|
>| 4 | testing | Unclassified | 1 | 0 | admin |  |


### xsoar-get-incident

***
Retrieve incident and entries from the remote Cortex XSOAR server.

#### Base Command

`xsoar-get-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident ID. | Required | 
| from_date | Retrieve entries that were created after the last update. Default is 3 days. | Optional | 
| categories | Retrieve only the entries from these categories. Default is chats,notes. | Optional | 
| tags | Only entries with these tags are retrieved from the Cortex XSOAR server. If no tags are listed, no entries are retrieved. | Optional | 
| max_results | Max number of entries to retrieve. Default is 10. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!xsoar-get-incident id=4```

#### Context Example

```json
{
    "XSOAR": {
        "Incident": {
            "CustomFields": {
                "containmentsla": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 30,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "detectionsla": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 20,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "endpoint": [
                    {}
                ],
                "filerelationships": [
                    {},
                    {},
                    {}
                ],
                "isactive": "true",
                "numberofrelatedincidents": 0,
                "numberofsimilarfiles": 0,
                "remediationsla": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 7200,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "similarincidentsdbot": [
                    {}
                ],
                "timetoassignment": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 0,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "triagesla": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 30,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "urlsslverification": []
            },
            "account": "",
            "activated": "0001-01-01T00:00:00Z",
            "attachment": null,
            "autime": 1678010808446441500,
            "cacheVersn": 0,
            "canvases": null,
            "category": "",
            "closeNotes": "",
            "closeReason": "",
            "closed": "0001-01-01T00:00:00Z",
            "closingUserId": "",
            "created": "2023-03-05T10:06:48.446441591Z",
            "dbotCreatedBy": "admin",
            "dbotCurrentDirtyFields": null,
            "dbotDirtyFields": null,
            "dbotMirrorDirection": "",
            "dbotMirrorId": "",
            "dbotMirrorInstance": "",
            "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
            "dbotMirrorTags": null,
            "details": "This is the new details",
            "droppedCount": 0,
            "dueDate": "2023-03-15T10:06:48.446441591Z",
            "feedBased": false,
            "id": "4",
            "investigationId": "4",
            "isDebug": false,
            "isPlayground": false,
            "labels": [
                {
                    "type": "Instance",
                    "value": "admin"
                },
                {
                    "type": "Brand",
                    "value": "Manual"
                }
            ],
            "lastJobRunTime": "0001-01-01T00:00:00Z",
            "lastOpen": "0001-01-01T00:00:00Z",
            "linkedCount": 0,
            "linkedIncidents": null,
            "modified": "2023-03-05T14:43:22.319158041Z",
            "name": "testing",
            "notifyTime": "2023-03-05T10:06:50.261155172Z",
            "occurred": "2023-03-05T10:06:48.446441435Z",
            "openDuration": 0,
            "owner": "admin",
            "parent": "",
            "phase": "",
            "playbookId": "playbook0",
            "rawCategory": "",
            "rawCloseReason": "",
            "rawJSON": "",
            "rawName": "testing",
            "rawPhase": "",
            "rawType": "Unclassified",
            "reason": "",
            "reminder": "0001-01-01T00:00:00Z",
            "runStatus": "waiting",
            "severity": 0,
            "sla": 0,
            "sourceBrand": "Manual",
            "sourceInstance": "admin",
            "status": 1,
            "type": "Unclassified",
            "version": 13
        }
    }
}
```

#### Human Readable Output

>### Incident testing

>|CustomFields|account|activated|attachment|autime|cacheVersn|canvases|category|closeNotes|closeReason|closed|closingUserId|created|dbotCreatedBy|dbotCurrentDirtyFields|dbotDirtyFields|dbotMirrorDirection|dbotMirrorId|dbotMirrorInstance|dbotMirrorLastSync|dbotMirrorTags|details|droppedCount|dueDate|feedBased|id|investigationId|isDebug|isPlayground|labels|lastJobRunTime|lastOpen|linkedCount|linkedIncidents|modified|name|notifyTime|occurred|openDuration|owner|parent|phase|playbookId|rawCategory|rawCloseReason|rawJSON|rawName|rawPhase|rawType|reason|reminder|runStatus|severity|sla|sourceBrand|sourceInstance|status|type|version|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| containmentsla: {"accumulatedPause": 0, "breachTriggered": false, "dueDate": "0001-01-01T00:00:00Z", "endDate": "0001-01-01T00:00:00Z", "lastPauseDate": "0001-01-01T00:00:00Z", "runStatus": "idle", "sla": 30, "slaStatus": -1, "startDate": "0001-01-01T00:00:00Z", "totalDuration": 0}<br/>detectionsla: {"accumulatedPause": 0, "breachTriggered": false, "dueDate": "0001-01-01T00:00:00Z", "endDate": "0001-01-01T00:00:00Z", "lastPauseDate": "0001-01-01T00:00:00Z", "runStatus": "idle", "sla": 20, "slaStatus": -1, "startDate": "0001-01-01T00:00:00Z", "totalDuration": 0}<br/>endpoint: {}<br/>filerelationships: {},<br/>{},<br/>{}<br/>isactive: true<br/>numberofrelatedincidents: 0<br/>numberofsimilarfiles: 0<br/>remediationsla: {"accumulatedPause": 0, "breachTriggered": false, "dueDate": "0001-01-01T00:00:00Z", "endDate": "0001-01-01T00:00:00Z", "lastPauseDate": "0001-01-01T00:00:00Z", "runStatus": "idle", "sla": 7200, "slaStatus": -1, "startDate": "0001-01-01T00:00:00Z", "totalDuration": 0}<br/>similarincidentsdbot: {}<br/>timetoassignment: {"accumulatedPause": 0, "breachTriggered": false, "dueDate": "0001-01-01T00:00:00Z", "endDate": "0001-01-01T00:00:00Z", "lastPauseDate": "0001-01-01T00:00:00Z", "runStatus": "idle", "sla": 0, "slaStatus": -1, "startDate": "0001-01-01T00:00:00Z", "totalDuration": 0}<br/>triagesla: {"accumulatedPause": 0, "breachTriggered": false, "dueDate": "0001-01-01T00:00:00Z", "endDate": "0001-01-01T00:00:00Z", "lastPauseDate": "0001-01-01T00:00:00Z", "runStatus": "idle", "sla": 30, "slaStatus": -1, "startDate": "0001-01-01T00:00:00Z", "totalDuration": 0}<br/>urlsslverification:  |  | 0001-01-01T00:00:00Z |  | 1678010808446441591 | 0 |  |  |  |  | 0001-01-01T00:00:00Z |  | 2023-03-05T10:06:48.446441591Z | admin |  |  |  |  |  | 0001-01-01T00:00:00Z |  | This is the new details | 0 | 2023-03-15T10:06:48.446441591Z | false | 4 | 4 | false | false | {'value': 'admin', 'type': 'Instance'},<br/>{'value': 'Manual', 'type': 'Brand'} | 0001-01-01T00:00:00Z | 0001-01-01T00:00:00Z | 0 |  | 2023-03-05T14:43:22.319158041Z | testing | 2023-03-05T10:06:50.261155172Z | 2023-03-05T10:06:48.446441435Z | 0 | admin |  |  | playbook0 |  |  |  | testing |  | Unclassified |  | 0001-01-01T00:00:00Z | waiting | 0 | 0 | Manual | admin | 1 | Unclassified | 13 |
>
>
>### Last entries since 2023-03-02T14:44:47.000Z

>|brand|cacheVersn|category|contents|contentsSize|created|cronView|dbotCreatedBy|endingDate|format|id|incidentCreationTime|investigationId|isTodo|mirrored|modified|note|parentEntryTruncated|pinned|recurrent|reputationSize|retryTime|scheduled|startDate|times|timezoneOffset|type|user|version|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| none | 0 | chat | done | 4 | 2023-03-05T10:38:21.895125832Z | false | admin | 0001-01-01T00:00:00Z | text | 52@4 | 0001-01-01T00:00:00Z | 4 | false | false | 2023-03-05T10:38:21.895153311Z | false | false | false | false | 0 | 0001-01-01T00:00:00Z | false | 0001-01-01T00:00:00Z | 0 | 0 | 1 | admin | 1 |


### get-remote-data

***
Get remote data from a remote incident. Note that this method will not update the current incident. It is used for debugging purposes only.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident ID. | Required | 
| lastUpdate | Retrieve entries that were created after the last update. | Optional | 

#### Context Output

There is no context output for this command.
### get-mapping-fields

***
Retrieves the mapping schema from a remote incident.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and XSOAR Mirroring corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in XSOAR Mirroring events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in XSOAR Mirroring events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and XSOAR Mirroring events will be reflected in both directions. |


Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and XSOAR Mirroring.
