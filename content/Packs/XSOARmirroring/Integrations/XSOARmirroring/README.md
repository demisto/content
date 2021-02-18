Allows mirroring of XSOAR incidents between different Cortex XSOAR tenants.

This integration was integrated and tested with version 6.0 of XSOAR

## Configure XSOAR Mirroring on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for XSOAR Mirroring.
3. Click **Add instance** to create and configure a new integration instance.
4. Go to the tenant to which you want to mirror the content and install the XSOAR Mirroring pack. This is where you can define which content you want to ingest from the Cortex XSOAR tenant. 

The mirroring instance in the first tenant contains a new incident type, called Ping. You can use the following query to ingest those incidents into the XSOAR mirroring client tenant `-status:closed and type:Ping and -frompong:true`

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| incidentType | Incident type | False |
| url | URL of the XSOAR tenant from which you are ingesting the Ping incidents. You should add the full server address, for example, https://cortexXSOARMainAccount:8443/acc_MyTenant#/ | True |
| apikey | The API key to access the server. The key must be provided by the server to which you are connecting. | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |
| max_fetch | Maximum number of incidents per fetch | False |
| query | Fetch only incidents that match the query | False |
| first_fetch | First fetch time | False |
| categories | Entry Categories | False |
| tags | Incoming Entry tags | False |
| mirror_tag | Outgoing Entry Tag | False |
| mirror_identically | Mirror to identical incident type | False |
| disable_from_same_integration | Disable mirroring for incidents came from this integration | False |

4. Click **Test** to ensure that you can communicate with the Cortex XSOAR tenant.


## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### xsoar-search-incidents
***
Search remote XSOAR for incidents


#### Base Command

`xsoar-search-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Which incidents to retrieve | Optional | 
| start_time | From when to search | Optional | 
| max_results | How many incidents to bring | Optional | 
| columns | Which columns to display | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!xsoar-search-incidents query="-status:closed -category:job"```

#### Human Readable Output
| CustomFields |ShardID|account|activated|attachment|autime|canvases|category|changeStatus|closeNotes|closeReason|closed|closingUserId|created|dbotCreatedBy|dbotCurrentDirtyFields|dbotDirtyFields|dbotMirrorDirection|dbotMirrorId|dbotMirrorInstance|dbotMirrorLastSync|dbotMirrorTags|details|droppedCount|dueDate|feedBased|hasRole|id|insights|investigationId|isPlayground|labels|lastJobRunTime|lastOpen|linkedCount|linkedIncidents|modified|name|notifyTime|occurred|openDuration|owner|parent|phase|playbookId|previousRoles|rawCategory|rawCloseReason|rawJSON|rawName|rawPhase|rawType|reason|reminder|roles|runStatus|severity|sla|sortValues|sourceBrand|sourceInstance|status|type|version|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|  | 0 | Ping | 0001-01-01T00:00:00Z |  | 1594654220814726000 |  |  | new |  |  | 0001-01-01T00:00:00Z |  | 2020-07-13T18:30:20.814726+03:00 | admin |  |  |  |  |  | 0001-01-01T00:00:00Z |  |  | 0 | 2020-07-23T18:30:20.814726+03:00 | false | false | 35 | 0 |  | false | {'value': 'admin', 'type': 'Instance'},\u003cbr\u003e{'value': 'Manual', 'type': 'Brand'} | 0001-01-01T00:00:00Z | 0001-01-01T00:00:00Z | 0 |  | 2020-07-13T18:30:20.816159+03:00 | testing | 0001-01-01T00:00:00Z | 2020-07-13T18:30:20.814725+03:00 | 0 | admin |  |  |  |  |  |  |  | testing |  | Unclassified |  | 0001-01-01T00:00:00Z |  |  | 0 | 0 | _score | Manual | admin | 0 | Unclassified | 1 |


### xsoar-get-incident
***
Retrieve incident and entries from remote XSOAR


#### Base Command

`xsoar-get-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident id | Required | 
| from_date | Retrieve entries that were created after last_update | Optional | 
| categories | Retrieve only the entries of these categories | Optional | 
| tags | Only entries with these tags are retrieved from the XSOAR server. If no tags are listed, no entries are retrieved. | Optional | 
| max_results | Max number of entries to retrieve | Optional | 


#### Context Output

```buildoutcfg
{
  "XSOAR.Incident(val.incident_id == obj.incident_id)": {
    "CustomFields": {
      "testdict": [
        {},
        {},
        {}
      ]
    },
    "ShardID": 0,
    "account": "Ping",
    "activated": "0001-01-01T00:00:00Z",
    "attachment": null,
    "autime": 1594125574034437000,
    "canvases": null,
    "category": "",
    "closeNotes": "",
    "closeReason": "",
    "closed": "0001-01-01T00:00:00Z",
    "closingUserId": "",
    "created": "2020-07-07T15:39:34.034437+03:00",
    "dbotCreatedBy": "admin",
    "dbotCurrentDirtyFields": null,
    "dbotDirtyFields": null,
    "dbotMirrorDirection": "",
    "dbotMirrorId": "",
    "dbotMirrorInstance": "",
    "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
    "dbotMirrorTags": null,
    "details": "this is the new details",
    "droppedCount": 0,
    "dueDate": "2020-07-10T15:39:34.034437+03:00",
    "feedBased": false,
    "hasRole": false,
    "id": "34",
    "investigationId": "34",
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
    "modified": "2020-07-07T15:42:18.436987+03:00",
    "name": "testing",
    "notifyTime": "0001-01-01T00:00:00Z",
    "occurred": "2020-07-07T15:39:34.034436+03:00",
    "openDuration": 0,
    "owner": "admin",
    "parent": "",
    "phase": "",
    "playbookId": "",
    "previousRoles": null,
    "rawCategory": "",
    "rawCloseReason": "",
    "rawJSON": "",
    "rawName": "testing",
    "rawPhase": "",
    "rawType": "Ping",
    "reason": "",
    "reminder": "0001-01-01T00:00:00Z",
    "roles": null,
    "runStatus": "",
    "severity": 0,
    "sla": 0,
    "sortValues": null,
    "sourceBrand": "Manual",
    "sourceInstance": "admin",
    "status": 1,
    "type": "Ping",
    "version": 5
  }
}
```

#### Command Example
```!xsoar-get-incident id=34```

#### Human Readable Output
|CustomFields|ShardID|account|activated|attachment|autime|canvases|category|closeNotes|closeReason|closed|closingUserId|created|dbotCreatedBy|dbotCurrentDirtyFields|dbotDirtyFields|dbotMirrorDirection|dbotMirrorId|dbotMirrorInstance|dbotMirrorLastSync|dbotMirrorTags|details|droppedCount|dueDate|feedBased|hasRole|id|investigationId|isPlayground|labels|lastJobRunTime|lastOpen|linkedCount|linkedIncidents|modified|name|notifyTime|occurred|openDuration|owner|parent|phase|playbookId|previousRoles|rawCategory|rawCloseReason|rawJSON|rawName|rawPhase|rawType|reason|reminder|roles|runStatus|severity|sla|sortValues|sourceBrand|sourceInstance|status|type|version|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| testdict: {},\u003cbr\u003e{},\u003cbr\u003e{} | 0 | Ping | 0001-01-01T00:00:00Z |  | 1594125574034437000 |  |  |  |  | 0001-01-01T00:00:00Z |  | 2020-07-07T15:39:34.034437+03:00 | admin |  |  |  |  |  | 0001-01-01T00:00:00Z |  | this is the new details | 0 | 2020-07-10T15:39:34.034437+03:00 | false | false | 34 | 34 | false | {'value': 'admin', 'type': 'Instance'},\u003cbr\u003e{'value': 'Manual', 'type': 'Brand'} | 0001-01-01T00:00:00Z | 0001-01-01T00:00:00Z | 0 |  | 2020-07-07T15:42:18.436987+03:00 | testing | 0001-01-01T00:00:00Z | 2020-07-07T15:39:34.034436+03:00 | 0 | admin |  |  |  |  |  |  |  | testing |  | Ping |  | 0001-01-01T00:00:00Z |  |  | 0 | 0 |  | Manual | admin | 1 | Ping | 5 |\n\n\n### Last entries since 2020-07-10T15:33:41.000Z\n**No entries.**


### get-remote-data
***
Get remote data from a remote incident. Please note that this method will not update the current incident, it's here for debugging purposes.


#### Base Command

`get-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident id | Required | 
| lastUpdate | Retrieve entries that were created after lastUpdate | Optional | 


#### Command Example
```!get-remote-data id=34 lastUpdate="18:00 July 12th, 2020"```



### get-mapping-fields
***
Get mapping fields from remote incident.


#### Base Command

`get-mapping-fields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
```!get-mapping-fields ```


