Tanium Threat Response - This Integration works with Tanium Threat Response version below 3.0.159. In order to use Tanium Threat Response version 3.0.159 and above, use Tanium Threat Response V2 Integration.

## Configure Tanium Threat Response in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| url | Hostname, IP address, or server URL | True |
| credentials | Username | True |
| insecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |
| fetch_time | First fetch timestamp ({number} {time unit}, e.g., 12 hours, 7 days) | False |
| filter_alerts_by_state | A comma-separated list of alert states to filter by in fetch incidents command. Possible options are: unresolved, in progress, resolved or suppressed. Empty list won't filter the incidents by state. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### tanium-tr-get-intel-doc-by-id
***
Returns an intel document object based on ID.


##### Base Command

`tanium-tr-get-intel-doc-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel-doc-id | The intel document ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.IntelDoc.AlertCount | Number | The number of alerts that currently exist for this intel. | 
| Tanium.IntelDoc.CreatedAt | Date | The date at which this intel was first added to the system. | 
| Tanium.IntelDoc.Description | String | The description of the intel, as declared in the document or as updated by a user. | 
| Tanium.IntelDoc.ID | Number | The unique identifier for this intel in this instance of the system. | 
| Tanium.IntelDoc.LabelIds | Number | The IDs of all labels applied to this intel. | 
| Tanium.IntelDoc.Name | String | The name of the intel, as declared in the document or as updated by a user. | 
| Tanium.IntelDoc.UnresolvedAlertCount | Number | The number of unresolved alerts that currently exist for this intel. | 
| Tanium.IntelDoc.UpdatedAt | Date | The date when this intel was last updated. | 


##### Command Example
```!tanium-tr-get-intel-doc-by-id intel-doc-id=2```

##### Context Example
```
{
    "Tanium": {
        "IntelDoc": {
            "AlertCount": 0,
            "CreatedAt": "2019-07-31T18:46:28.814Z",
            "Description": "Detects usage of the NET.EXE utility to enumerate members of the local Administrators or Domain Administrators groups. Often used during post-compromise reconnaissance.",
            "ID": 2,
            "LabelIds": [
                2,
                3,
                9,
                16
            ],
            "Name": "Administrator Account Enumeration",
            "UnresolvedAlertCount": 0,
            "UpdatedAt": "2020-01-14T21:37:30.934Z"
        }
    }
}
```

##### Human Readable Output
### Intel Doc information
|ID|Name|Description|Type|Alert Count|Unresolved Alert Count|Created At|Updated At|Label Ids|
|---|---|---|---|---|---|---|---|---|
| 2 | Administrator Account Enumeration | Detects usage of the NET.EXE utility to enumerate members of the local Administrators or Domain Administrators groups. Often used during post-compromise reconnaissance. |  | 0 | 0 | 2019-07-31T18:46:28.814Z | 2020-01-14T21:37:30.934Z | 2, 3, 9, 16 |


### tanium-tr-list-intel-docs
***
Returns a list of all intel documents.


##### Base Command

`tanium-tr-list-intel-docs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of intel documents to return. | Optional | 
| offset | The offset number to begin listing intel documents. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.IntelDoc.AlertCount | Number | The number of alerts that currently exist for this intel. | 
| Tanium.IntelDoc.CreatedAt | Date | The date at which this intel was first added to the system. | 
| Tanium.IntelDoc.Description | String | The description of the intel, as declared in the document or as updated by a user. | 
| Tanium.IntelDoc.ID | Number | The unique identifier for this intel in this instance of the system. | 
| Tanium.IntelDoc.LabelIds | Number | The IDs of all labels applied to this intel. | 
| Tanium.IntelDoc.Name | String | The name of the intel, as declared in the document or as updated by a user. | 
| Tanium.IntelDoc.UnresolvedAlertCount | Number | The number of unresolved alerts that currently exist for this intel. | 
| Tanium.IntelDoc.UpdatedAt | Date | The date when this intel was last updated. | 


##### Command Example
```!tanium-tr-list-intel-docs limit=2```

##### Context Example
```
{
    "Tanium": {
        "IntelDoc": [
            {
                "AlertCount": 0,
                "CreatedAt": "2020-01-14T21:37:32.263Z",
                "ID": 99,
                "LabelIds": [
                    2,
                    7,
                    11,
                    16
                ],
                "Name": "Spooler Service Creating or Spawning Executables",
                "UnresolvedAlertCount": 0,
                "UpdatedAt": "2020-01-14T21:37:32.263Z"
            },
            {
                "AlertCount": 0,
                "CreatedAt": "2020-01-14T21:37:32.075Z",
                "ID": 98,
                "LabelIds": [
                    2,
                    8,
                    16
                ],
                "Name": "RunDll Creating MiniDump",
                "UnresolvedAlertCount": 0,
                "UpdatedAt": "2020-01-14T21:37:32.075Z"
            }
        ]
    }
}
```

##### Human Readable Output
### Intel docs
|ID|Name|Alert Count|Unresolved Alert Count|Created At|Updated At|Label Ids|
|---|---|---|---|---|---|---|
| 99 | Spooler Service Creating or Spawning Executables | 0 | 0 | 2020-01-14T21:37:32.263Z | 2020-01-14T21:37:32.263Z | 2, 7, 11, 16 |
| 98 | RunDll Creating MiniDump | 0 | 0 | 2020-01-14T21:37:32.075Z | 2020-01-14T21:37:32.075Z | 2, 8, 16 |


### tanium-tr-list-alerts
***
Returns a list of all alerts.


##### Base Command

`tanium-tr-list-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of alerts to return. The default value is 5. | Optional | 
| offset | The offset number to begin listing alerts. | Optional | 
| computer-ip-address | Filter alerts by the specified computer IP addresses. | Optional | 
| computer-name | Filter alerts by the specified computer name. | Optional | 
| scan-config-id | Filter alerts by the specified scan config ID. | Optional | 
| intel-doc-id | Filter alerts by the specified intel document ID. | Optional | 
| severity | Filter alerts by the specified severity. | Optional | 
| priority | Filter alerts by the specified priority. | Optional | 
| type | Filter alerts by the specified type. | Optional | 
| state | Filter alerts by the specified state. Can be "Unresolved", "In Progress", "Ignored", or "Resolved". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Alert.Priority | String | The priority of the alert. | 
| Tanium.Alert.ComputerName | String | The hostname of the computer that generated the alert. | 
| Tanium.Alert.GUID | String | A globally unique identifier for this alert in the customer environment. | 
| Tanium.Alert.AlertedAt | Date | The moment that the alert was generated. | 
| Tanium.Alert.UpdatedAt | Date | The last time the alert state was updated. | 
| Tanium.Alert.State | String | The current state of the alert. For example, "unresolved", "inprogress", and so on. | 
| Tanium.Alert.ComputerIpAddress | String | The IP address of the computer that generated the alert. | 
| Tanium.Alert.Type | String | The name of the alert type. For example, "detect.endpoint.match". | 
| Tanium.Alert.ID | Number | The ID of the alert. For example, "123". | 
| Tanium.Alert.CreatedAt | Date | The date when the alert was received by the Detect product. | 
| Tanium.Alert.IntelDocId | Number | The intel document revision, if intelDocId is present. | 
| Tanium.Alert.Severity | String | The severity of the alert. | 


##### Command Example
```!tanium-tr-list-alerts limit=1```

##### Context Example
```
{
    "Tanium": {
        "Alert": {
            "AlertedAt": "2019-09-22T14:01:31.000Z",
            "ComputerIpAddress": "172.0.0.0",
            "ComputerName": "HOST_NAME",
            "CreatedAt": "2019-09-22T14:01:59.768Z",
            "GUID": "a33e3482-556e-4e9d-bbbd-2fdbe330d492",
            "ID": 1,
            "IntelDocId": 64,
            "Priority": "high",
            "Severity": "info",
            "State": "Unresolved",
            "Type": "detect.match",
            "UpdatedAt": "2020-02-05T14:55:41.440Z"
        }
    }
}
```

##### Human Readable Output
### Alerts
|ID|Type|Severity|Priority|Alerted At|Created At|Updated At|Computer Ip Address|Computer Name|GUID|State|Intel Doc Id|
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | detect.match | info | high | 2019-09-22T14:01:31.000Z | 2019-09-22T14:01:59.768Z | 2020-02-05T14:55:41.440Z | 172.0.0.0 | HOST_NAME | a33e3482-556e-4e9d-bbbd-2fdbe330d492 | Unresolved | 64 |


### tanium-tr-get-alert-by-id
***
Returns an alert object based on alert ID.


##### Base Command

`tanium-tr-get-alert-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The alert ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Alert.Priority | String | The priority of the alert. | 
| Tanium.Alert.ComputerName | String | The hostname of the computer that generated the alert. | 
| Tanium.Alert.GUID | String | A globally unique identifier for this alert in the customer environment. | 
| Tanium.Alert.AlertedAt | Date | The date when the alert was generated. | 
| Tanium.Alert.UpdatedAt | Date | The date when the alert state was last updated. | 
| Tanium.Alert.State | String | The current state of the alert. For example, "unresolved", "inprogress". | 
| Tanium.Alert.ComputerIpAddress | String | The IP address of the computer that generated the alert. | 
| Tanium.Alert.Type | String | The name of the alert type. For example, "detect.endpoint.match". | 
| Tanium.Alert.ID | Number | The ID of the alert. For example, "123". | 
| Tanium.Alert.CreatedAt | Date | The date when the alert was received by the Detect product. | 
| Tanium.Alert.IntelDocId | Number | The intel document revision, if intelDocId is present. | 
| Tanium.Alert.Severity | String | The severity of the alert. | 


##### Command Example
```!tanium-tr-get-alert-by-id alert-id=1```

##### Context Example
```
{
    "Tanium": {
        "Alert": {
            "AlertedAt": "2019-09-22T14:01:31.000Z",
            "ComputerIpAddress": "172.0.0.0",
            "ComputerName": "HOST_NAME",
            "CreatedAt": "2019-09-22T14:01:59.768Z",
            "GUID": "a33e3482-556e-4e9d-bbbd-2fdbe330d492",
            "ID": 1,
            "IntelDocId": 64,
            "Priority": "high",
            "Severity": "info",
            "State": "Unresolved",
            "Type": "detect.match",
            "UpdatedAt": "2020-02-05T14:55:41.440Z"
        }
    }
}
```

##### Human Readable Output
### Alert information
|ID|Type|Severity|Priority|Alerted At|Created At|Updated At|Computer Ip Address|Computer Name|GUID|State|Intel Doc Id|
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | detect.match | info | high | 2019-09-22T14:01:31.000Z | 2019-09-22T14:01:59.768Z | 2020-02-05T14:55:41.440Z | 172.0.0.0 | HOST_NAME | a33e3482-556e-4e9d-bbbd-2fdbe330d492 | Unresolved | 64 |


### tanium-tr-alert-update-state
***
Updates the state of a single alert.


##### Base Command

`tanium-tr-alert-update-state`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert to update. | Required | 
| state | The new state for the alert. Can be "Unresolved", "In Progress", "Ignored", or "Resolved". | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Alert.Priority | String | The priority of the alert. | 
| Tanium.Alert.ComputerName | String | The hostname of the computer that generated the alert. | 
| Tanium.Alert.GUID | String | A globally unique identifier for this alert in the customer environment. | 
| Tanium.Alert.AlertedAt | Date | The date when the alert was generated. | 
| Tanium.Alert.UpdatedAt | Date | The date when the alert state was last updated. | 
| Tanium.Alert.State | String | The current state of the alert. For example, "unresolved", "inprogress". | 
| Tanium.Alert.ComputerIpAddress | String | The IP address of the computer that generated the alert. | 
| Tanium.Alert.Type | String | The name of the alert type. For example, "detect.endpoint.match". | 
| Tanium.Alert.ID | Number | The ID of the alert. For example, "123". | 
| Tanium.Alert.CreatedAt | Date | The date when the alert was received by the Detect product. | 
| Tanium.Alert.IntelDocId | Number | The intel document revision, if intelDocId is present. | 
| Tanium.Alert.Severity | String | The severity of the alert. | 


##### Command Example
```!tanium-tr-alert-update-state alert-id=1 state=Unresolved```

##### Context Example
```
{
    "Tanium": {
        "Alert": {
            "AlertedAt": "2019-09-22T14:01:31.000Z",
            "ComputerIpAddress": "172.0.0.0",
            "ComputerName": "HOST_NAME",
            "CreatedAt": "2019-09-22T14:01:59.768Z",
            "GUID": "a33e3482-556e-4e9d-bbbd-2fdbe330d492",
            "ID": 1,
            "IntelDocId": 64,
            "Priority": "high",
            "Severity": "info",
            "State": "Unresolved",
            "Type": "detect.match",
            "UpdatedAt": "2020-02-05T14:55:41.440Z"
        }
    }
}
```

##### Human Readable Output
### Alert state updated to Unresolved
|ID|Type|Severity|Priority|Alerted At|Created At|Updated At|Computer Ip Address|Computer Name|GUID|State|Intel Doc Id|
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | detect.match | info | high | 2019-09-22T14:01:31.000Z | 2019-09-22T14:01:59.768Z | 2020-02-05T14:55:41.440Z | 172.0.0.0 | HOST_NAME | a33e3482-556e-4e9d-bbbd-2fdbe330d492 | Unresolved | 64 |


### tanium-tr-list-snapshots-by-connection
***
Returns all snapshots of a single connection.


##### Base Command

`tanium-tr-list-snapshots-by-connection`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of snapshots to return. | Optional | 
| offset | The offset number to begin listing snapshots. | Optional | 
| connection-name | The connection name. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Snapshot.ConnectionName | String | The snapshot connection name. | 
| Tanium.Snapshot.Error | String | The snapshot error message. | 
| Tanium.Snapshot.ID | String | The snapshot id. | 
| Tanium.Snapshot.Started | Date | The date when the snapshot was created. | 
| Tanium.Snapshot.State | String | The current state of the snapshot. | 


##### Command Example
```!tanium-tr-list-snapshots-by-connection connection-name=HOST_NAME limit=2```

##### Context Example
```
{
    "Tanium": {
        "Snapshot": [
            {
                "ConnectionName": "HOST_NAME",
                "FileName": "2020_02_06T15.54.43.600Z.db",
                "Started": "2020-02-06T15:54:43.600Z",
                "State": "complete"
            },
            {
                "ConnectionName": "HOST_NAME",
                "Error": "Error checkpointing remote database",
                "FileName": "2020_02_06T15.54.46.795Z.db",
                "Started": "2020-02-06T15:54:46.795Z",
                "State": "error"
            }
        ]
    }
}
```

##### Human Readable Output
### Snapshots
|File Name|Connection Name|State|Started|Error|
|---|---|---|---|---|
| 2020_02_06T15.54.43.600Z.db | HOST_NAME | complete | 2020-02-06T15:54:43.600Z |  |
| 2020_02_06T15.54.46.795Z.db | HOST_NAME | error | 2020-02-06T15:54:46.795Z | Error checkpointing remote database |


### tanium-tr-create-snapshot
***
Captures a new snapshot by connection name.


##### Base Command

`tanium-tr-create-snapshot`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The connection name. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!tanium-tr-create-snapshot connection-name=HOST_NAME```

##### Human Readable Output
Initiated snapshot creation request for HOST_NAME.


### tanium-tr-delete-snapshot
***
Deletes a snapshot by connection name and snapshot ID.


##### Base Command

`tanium-tr-delete-snapshot`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The connection name. | Required | 
| snapshot-id | The snapshot ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Snapshot.ID | String | The snapshot ID. | 
| Tanium.Snapshot.ConnectionName | String | The connection name. | 
| Tanium.Snapshot.Deleted | Boolean | Whether the snapshot has been deleted. | 


##### Command Example
```!tanium-tr-delete-snapshot connection-name=HOST_NAME snapshot-id=2020_02_06T15.54.43.600Z.db```

##### Context Example
```
{
    "Tanium": {
        "LocalSnapshot": {
            "ConnectionName": "HOST_NAME",
            "Deleted": True,
            "FileName": "2020_02_06T15.54.43.600Z.db"
        }
    }
}
```

##### Human Readable Output
Snapshot 2020_02_06T15.54.43.600Z.db deleted successfully.


### tanium-tr-list-local-snapshots-by-connection
***
Returns all local snapshots of a single connection.


##### Base Command

`tanium-tr-list-local-snapshots-by-connection`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of local snapshots to return. The default value is 50. | Optional | 
| offset | The offset number to begin listing local snapshots. | Optional | 
| connection-name | The connection name. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.LocalSnapshot.ConnectionName | String | The snapshot connection name. | 
| Tanium.LocalSnapshot.FileName | String | The snapshot file name. | 


##### Command Example
```!tanium-tr-list-local-snapshots-by-connection connection-name=HOST_NAME limit=2```

##### Context Example
```
{
    "Tanium": {
        "LocalSnapshot": [
            {
                "ConnectionName": "HOST_NAME",
                "Deleted": false,
                "FileName": "2020_02_06T15.54.43.600Z.db"
            },
            {
                "ConnectionName": "HOST_NAME",
                "Deleted": false,
                "FileName": "2020_01_09T15.25.13.535Z.db"
            }
        ]
    }
}
```

##### Human Readable Output
### Local snapshots
|File Name|Connection Name|
|---|---|
| 2020_02_06T15.54.43.600Z.db | HOST_NAME |
| 2020_01_09T15.25.13.535Z.db | HOST_NAME |


### tanium-tr-delete-local-snapshot
***
Deletes a local snapshot by directory name and file name.


##### Base Command

`tanium-tr-delete-local-snapshot`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The connection name. | Required | 
| file-name | The file name. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.LocalSnapshot.FileName | String | The snapshot file name. | 
| Tanium.LocalSnapshot.Deleted | Boolean | Whether the local snapshot has been deleted. | 


##### Command Example
```!tanium-tr-delete-local-snapshot connection-name=HOST_NAME file-name=2020_02_06T15.54.43.600Z.db```

##### Context Example
```
{
    "Tanium": {
        "LocalSnapshot": {
            "ConnectionName": "HOST_NAME",
            "Deleted": true,
            "FileName": "2020_02_06T15.54.43.600Z.db"
        }
    }
}
```

##### Human Readable Output
Local snapshot from Directory HOST_NAME and File 2020_02_06T15.54.43.600Z.db is deleted successfully.


### tanium-tr-list-connections
***
Returns all connections.


##### Base Command

`tanium-tr-list-connections`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of connections to return. | Optional | 
| offset | The offset number to begin listing connections. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Connection.CreateTime | Date | Time when the connection was first created. | 
| Tanium.Connection.Name | String | The connection name. | 
| Tanium.Connection.Remote | Boolean | Whether it is a remote connection. | 
| Tanium.Connection.State | String | Current connection state. Can be "closed", "pending", "active", "timeout", or "migrating". | 
| Tanium.Connection.Deleted | Boolean | Whether the connection has been deleted. | 
| Tanium.Connection.DestionationType | String | The destionation type (computer_name or ip_address). | 
| Tanium.Connection.DST | String | The connection's DST. | 
| Tanium.Connection.OSName | String | The connection's operating system. | 


##### Command Example
```!tanium-tr-list-connections limit=2```

##### Context Example
```
{
    "Tanium": {
        "Connection": [
            {
                "DST": "HOST_NAME",
                "Name": "HOST_NAME",
                "State": "timeout",
                "Deleted": false,
                "DestionationType": "computer-name",
                "OSName": "Linux"
            },
            {
                "DST": "HOST_NAME-2020_01_09T15.25.13.535Z.db",
                "Name": "HOST_NAME-2020_01_09T15.25.13.535Z.db",
                "State": "timeout",
                "Deleted": false,
                "DestionationType": "computer-name"
                "OSName": "Linux"
            }
        ]
    }
}
```

##### Human Readable Output
### Connections
|Name|State|DST|OS Name|
|---|---|---|---|
| HOST_NAME | timeout | HOST_NAME | Linux |
| HOST_NAME-2020_01_09T15.25.13.535Z.db | timeout | HOST_NAME-2020_01_09T15.25.13.535Z.db | Linux |


### tanium-tr-get-connection-by-name
***
Returns a connection object based on connection name.


##### Base Command

`tanium-tr-get-connection-by-name`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The connection name. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Connection.CreateTime | Date | Time when the connection was first created. | 
| Tanium.Connection.Name | String | The connection name. | 
| Tanium.Connection.Remote | Boolean | Whether it is a remote connection. | 
| Tanium.Connection.State | String | Current connection state. Can be "closed", "pending", "active", "timeout", or "migrating". | 
| Tanium.Connection.Deleted | Boolean | Whether the connection has been deleted. | 
| Tanium.Connection.DestionationType | String | The destionation type (computer_name or ip_address). | 
| Tanium.Connection.DST | String | The connection's DST. | 
| Tanium.Connection.OSName | String | The connection's operating system. | 


##### Command Example
```!tanium-tr-get-connection-by-name connection-name=HOST_NAME```

##### Context Example
```
{
    "Tanium": {
        "Connection": {
            "CreateTime": "2020-02-06T15:54:40.830Z",
            "Name": "HOST_NAME",
            "Deleted": false,
            "OSName": "Windows",
            "Remote": true,
            "State": "active"
        }
    }
}
```

##### Human Readable Output
### Connection information
|Name|State|Remote|Create Time|OS Name|
|---|---|---|---|---|
| HOST_NAME | active | true | 2020-02-06T15:54:40.830Z | Windows |


### tanium-tr-create-connection
***
Creates a local or remote connection.


##### Base Command

`tanium-tr-create-connection`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| remote | Whether it is a remote connection. Can be "True" or "False". | Required | 
| destination-type | Type of destination. Can be "ip_address" or "computer_name". | Required | 
| destination | Computer name or IP address. | Required | 
| connection-timeout | connection timeout, in milliseconds. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!tanium-tr-create-connection destination=HOST_NAME destination-type=computer_name remote=False```

##### Human Readable Output
Initiated connection request to HOST_NAME.


### tanium-tr-delete-connection
***
Deletes a connection by connection name.


##### Base Command

`tanium-tr-delete-connection`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The name of the connection. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Connection.Name | String | The connection name. | 
| Tanium.Connection.Deleted | Boolean | Whether the connection has been deleted. | 


##### Command Example
```!tanium-tr-delete-connection connection-name=HOST_NAME```

##### Context Example
```
{
    "Tanium": {
        "Connection": {
            "Name": "HOST_NAME",
            "Deleted": true
        }
    }
}
```

##### Human Readable Output
Connection HOST_NAME deleted successfully.


### tanium-tr-list-labels
***
Returns all available labels in the system.


##### Base Command

`tanium-tr-list-labels`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of labels to return. | Optional | 
| offset | The offset number to begin listing labels. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Label.CreatedAt | Date | The date when this label was created. | 
| Tanium.Label.Description | String | An extended description of the label. | 
| Tanium.Label.ID | Number | The unique identifier for this label. | 
| Tanium.Label.IndicatorCount | Number | The number of indicator-based intel documents associated with this label, not including Tanium Signals. | 
| Tanium.Label.Name | String | The display name of the label. | 
| Tanium.Label.SignalCount | Number | The number of Tanium Signal documents associated with this label. | 
| Tanium.Label.UpdatedAt | Date | The date when this label was last updated, not including the intel and signal counts. | 


##### Command Example
```!tanium-tr-list-labels limit=2```

##### Context Example
```
{
    "Tanium": {
        "Label": [
            {
                "CreatedAt": "2019-07-31T18:46:28.629Z",
                "Description": "These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed.",
                "ID": 1,
                "IndicatorCount": 0,
                "Name": "Alpha",
                "SignalCount": 0,
                "UpdatedAt": "2019-07-31T18:46:28.629Z"
            },
            {
                "CreatedAt": "2019-07-31T18:46:28.629Z",
                "Description": "These signals have been tested and reviewed internally for syntax. Internal testing of expected alert generation has been verified. Testing on internal systems for false positives has been conducted and tuned if necessary. These signals are included on the external feed.",
                "ID": 2,
                "IndicatorCount": 0,
                "Name": "Beta",
                "SignalCount": 97,
                "UpdatedAt": "2019-07-31T18:46:28.629Z"
            }
        ]
    }
}
```

##### Human Readable Output
### Labels
|Name|Description|ID|Indicator Count|Signal Count|Created At|Updated At|
|---|---|---|---|---|---|---|
| Alpha | These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed. | 1 | 0 | 0 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |
| Beta | These signals have been tested and reviewed internally for syntax. Internal testing of expected alert generation has been verified. Testing on internal systems for false positives has been conducted and tuned if necessary. These signals are included on the external feed. | 2 | 0 | 97 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |



### tanium-tr-get-label-by-id
***
Returns a label object based on label ID.


##### Base Command

`tanium-tr-get-label-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label-id | The label ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Label.CreatedAt | Date | The date when this label was created. | 
| Tanium.Label.Description | String | An extended description of the label. | 
| Tanium.Label.ID | Number | The unique identifier for this label. | 
| Tanium.Label.IndicatorCount | Number | The number of indicator-based intel documents associated with this label, not including Tanium Signals. | 
| Tanium.Label.Name | String | The display name of the label. | 
| Tanium.Label.SignalCount | Number | The number of Tanium Signal documents associated with this label. | 
| Tanium.Label.UpdatedAt | Date | The date this label was last updated, not including the intel and signal counts. | 


##### Command Example
```!tanium-tr-get-label-by-id label-id=1```

##### Context Example
```
{
    "Tanium": {
        "Label": {
            "CreatedAt": "2019-07-31T18:46:28.629Z",
            "Description": "These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed.",
            "ID": 1,
            "IndicatorCount": 0,
            "Name": "Alpha",
            "SignalCount": 0,
            "UpdatedAt": "2019-07-31T18:46:28.629Z"
        }
    }
}
```

##### Human Readable Output
### Label information
|Name|Description|ID|Indicator Count|Signal Count|Created At|Updated At|
|---|---|---|---|---|---|---|
| Alpha | These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed. | 1 | 0 | 0 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |


### tanium-tr-list-file-downloads
***
Returns all downloaded files in the system.


##### Base Command

`tanium-tr-list-file-downloads`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of files to return. The default value is 50. | Optional | 
| offset | Offset to start getting file downloads. The default is 0. | Optional | 
| host | Filter downloaded files by host. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.FileDownload.Size | Number | The size of the file, in bytes. | 
| Tanium.FileDownload.Path | String | The path of the file. | 
| Tanium.FileDownload.Downloaded | Date | The date when this file was downloaded. | 
| Tanium.FileDownload.Host | String | The hostname of the downloaded file. | 
| Tanium.FileDownload.Created | Date | The date when the file was created. | 
| Tanium.FileDownload.Hash | String | The file hash. | 
| Tanium.FileDownload.SPath | String | The file SPath. | 
| Tanium.FileDownload.ID | Number | The downloaded file ID. | 
| Tanium.FileDownload.LastModified | Date | The date when the file was last modified. | 
| Tanium.FileDownload.CreatedBy | String | The user that created this file. | 
| Tanium.FileDownload.CreatedByProc | String | The process path that created this file. | 
| Tanium.FileDownload.LastModifiedBy | String | The user that last modified this file. | 
| Tanium.FileDownload.LastModifiedByProc | String | The process path that modified this file. | 
| Tanium.FileDownload.Comments | String | Additional comments for the downloaded file. | 
| Tanium.FileDownload.Tags | String | The downloaded file tags. | 
| Tanium.FileDownload.Deleted | Boolean | Whether the file download has been deleted. | 


##### Command Example
```!tanium-tr-list-file-downloads host=HOST_NAME limit=2 offset=1```

##### Context Example
```
{
    "Tanium": {
        "FileDownload": [
            {
                "Created": "2020-01-02 15:39:57.289",
                "CreatedBy": "NT AUTHORITY\\LOCAL SERVICE",
                "CreatedByProc": "C:\\Windows\\System32\\svchost.exe",
                "Downloaded": "2020-01-02 15:40:29.003",
                "Hash": "2ae2da9237309b13b9a9d52d1358c826",
                "Host": "HOST_NAME",
                "ID": 4,
                "LastModified": "2020-01-02 15:39:57.289",
                "LastModifiedBy": "NT AUTHORITY\\LOCAL SERVICE",
                "LastModifiedByProc": "C:\\Windows\\System32\\svchost.exe",
                "Path": "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\lastalive1.dat",
                "SPath": "6ae86937-611f-45e9-900c-3ba57298f264.zip",
                "Size": 2048,
                "Deleted": false
            },
            {
                "Created": "Tue, 03 Sep 2019 17:51:40 GMT",
                "Downloaded": "2020-01-15 13:04:02.827",
                "Hash": "99297a0e626ca092ff1884ad28f54453",
                "Host": "HOST_NAME",
                "ID": 6,
                "LastModified": "Wed, 15 Jan 2020 08:57:19 GMT",
                "Path": "C:\\Program Files (x86)\\Tanium\\Tanium Client\\Logs\\log1.txt",
                "SPath": "c0531415-87a6-4d28-a226-b485784b1881.zip",
                "Size": 10485904,
                "Deleted": true
            }
        ]
    }
}
```

##### Human Readable Output
### File downloads
|ID|Host|Path|Hash|Downloaded|Size|Created|Created By|Created By Proc|Last Modified|Last Modified By|Last Modified By Proc|S Path|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 4 | HOST_NAME | C:\Windows\ServiceProfiles\LocalService\AppData\Local\lastalive1.dat | 2ae2da9237309b13b9a9d52d1358c826 | 2020-01-02 15:40:29.003 | 2048 | 2020-01-02 15:39:57.289 | NT AUTHORITY\LOCAL SERVICE | C:\Windows\System32\svchost.exe | 2020-01-02 15:39:57.289 | NT AUTHORITY\LOCAL SERVICE | C:\Windows\System32\svchost.exe | 6ae86937-611f-45e9-900c-3ba57298f264.zip |
| 6 | HOST_NAME | C:\Program Files (x86)\Tanium\Tanium Client\Logs\log1.txt | 99297a0e626ca092ff1884ad28f54453 | 2020-01-15 13:04:02.827 | 10485904 | Tue, 03 Sep 2019 17:51:40 GMT |  |  | Wed, 15 Jan 2020 08:57:19 GMT |  |  | c0531415-87a6-4d28-a226-b485784b1881.zip |



### tanium-tr-get-downloaded-file
***
Gets the actual content of a downloaded file by file ID.


##### Base Command

`tanium-tr-get-downloaded-file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file-id | The file ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!tanium-tr-get-downloaded-file file-id=4```

##### Context Example
```
{
    "File": {
        "EntryID": "8389@b32fdf18-1c65-43af-8918-7f85a1fab951",
        "Extension": "zip",
        "Info": "application/zip",
        "MD5": "216923cc567afe1009e7c90c105450f5",
        "Name": "lastalive1.dat.zip",
        "SHA1": "f7d257dc94ea0b650f62cc87264861b593a341c8",
        "SHA256": "5d0051b4c596e06217bdb3e48196b0515a7983f18a8ea7477bc33c837e0202e5",
        "SHA512": "269669cda90658e1bfea8ff85f27f8f68320ccd3b54c64a00037204fa3b5422634d9107806ddad585fa0d5c7fe7aa7fa240afb4142c6ff02537b039d176bd482",
        "SSDeep": "6:5jPRX/CSkILyratwQte+zetPYwCRXgLrCDh/+loUn:5jtCCPtTzep33vCDJaoUn",
        "Size": 253,
        "Type": "Zip archive data, at least v2.0 to extract"
    }
}
```

##### Human Readable Output


### tanium-tr-list-events-by-connection
***
Queries events for a connection.


##### Base Command

`tanium-tr-list-events-by-connection`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The connection name. | Required | 
| event-type | The type of event. Can be "File", "Network", "Registry", "Process", "Driver", "Security", "Combined", "DNS", or "Image". The default is "Combined". | Required | 
| limit | The maximum number of events to return. The default value is 50. | Optional | 
| offset | Offset to start getting the result set. The default is 0. | Optional | 
| filter | Advanced search that filters according to event fields. For example: [['process_id', 'gt', '30'], ['username', 'ne', 'administrator']]. Optional fields: process_id, process_name, process_hash, process_command_line, username, process_name, create_time (UTC). Optional operators: eq (equals), ne (does not equal); for integers/date: gt (greater than), gte (greater than or equals), ls (less than), lse (less than or equals); for strings: co (contains), nc (does not contain).  | Optional | 
| match | Whether the results should fit all filters or at least one filter. | Optional | 
| sort | A comma-separated list of fields to sort on prefixed by +/- for ascending or descending and ordered by priority left to right. Optional fields: process_id, process_name, process_hash, process_command_line, username, process_name, create_time (UTC). | Optional | 
| fields | A comma-separated list of fields on which to search. Optional fields: process_id, process_name, process_hash, process_command_line, username, process_name, create_time. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TaniumEvent.Domain | String | The domain of the event. | 
| TaniumEvent.File | String | The path of the file in the event. | 
| TaniumEvent.Operation | String | The event operation. | 
| TaniumEvent.ProcessID | Number | The ID of the process. | 
| TaniumEvent.ProcessName | String | The name of the process. | 
| TaniumEvent.ProcessTableID | Number | The ID of the process table. | 
| TaniumEvent.Timestamp | Date | The date when the event was created. | 
| TaniumEvent.Username | String | The username associated with the event. | 
| TaniumEvent.DestinationAddress | String | The network event destination address. | 
| TaniumEvent.DestinationPort | Number | The network event destination port. | 
| TaniumEvent.SourceAddress | String | The network event source address. | 
| TaniumEvent.SourcePort | Number | The network event source port. | 
| TaniumEvent.KeyPath | String | The registry key path. | 
| TaniumEvent.ValueName | String | The registry value name. | 
| TaniumEvent.ExitCode | Number | The process exit code. | 
| TaniumEvent.ProcessCommandLine | String | The process command line. | 
| TaniumEvent.ProcessHash | String | The hash value of the process. | 
| TaniumEvent.SID | Number | The process SID. | 
| TaniumEvent.Hashes | String | The hashes of the driver. | 
| TaniumEvent.ImageLoaded | String | The image loaded path of the driver. | 
| TaniumEvent.Signature | String | The signature of the driver. | 
| TaniumEvent.Signed | Boolean | Whether the driver is signed. | 
| TaniumEvent.EventID | Number | The ID of the event. | 
| TaniumEvent.EventOpcode | Number | The event opcode. | 
| TaniumEvent.EventRecordID | Number | The ID of the event record. | 
| TaniumEvent.EventTaskID | Number | The ID of the event task. | 
| TaniumEvent.Query | String | The query of the DNS. | 
| TaniumEvent.Response | String | The response of the DNS. | 
| TaniumEvent.ImagePath | String | The image path. | 
| TaniumEvent.CreationTime | Date | The process creation time | 
| TaniumEvent.EndTime | Date | The process end time. | 
| TaniumEvent.EventTaskName | String | The name of the event task. | 
| TaniumEvent.Property.Name | String | The name of the event's property | 
| TaniumEvent.Property.Value | String | The value of the event's property | 


##### Command Example
```!tanium-tr-list-events-by-connection connection-name=HOST_NAME event-type=Process limit=2```

##### Context Example
```
{
    "Tanium": {
        "Event": [
            {
                "Domain": "root",
                "Type": "Process",
                "CreationTime": "2020-03-02 16:05:37.574",
                "EndTime": "2020-03-03 11:28:28.413",
                "ExitCode": 0,
                "ProcessCommandLine": "sleep 0.1",
                "ProcessID": 13136,
                "ProcessName": "/usr/bin/sleep",
                "ProcessTableID": 17191168,
                "SID": 5,
                "Username": "root"
            },
            {
                "Domain": "root",
                "Type": "Process",
                "CreationTime": "2020-03-02 23:09:33.153",
                "EndTime": "2020-03-03 08:48:05.624",
                "ExitCode": 0,
                "ProcessCommandLine": "sleep 0.1",
                "ProcessHash": "BEA3A5351BBE28622A560FF5F18C805E",
                "ProcessID": 4229,
                "ProcessName": "/usr/bin/sleep",
                "ProcessTableID": 17232881,
                "SID": 5,
                "Username": "root"
            }
        ]
    }
}
```

##### Human Readable Output
### Events for HOST_NAME
|Domain|Type|Process Table ID|Process Command Line|Process ID|Process Name|Exit Code|SID|Username|Creation Time|End Time|
|---|---|---|---|---|---|---|---|---|---|---|
| root | Process | 17191168 | sleep 0.1 | 13136 | /usr/bin/sleep | 0 | 5 | root | 2020-03-02 16:05:37.574 | 2020-03-03 11:28:28.413 |
| root | Process | 17232881 | sleep 0.1 | 4229 | /usr/bin/sleep | 0 | 5 | root | 2020-03-02 23:09:33.153 | 2020-03-03 08:48:05.624 |

### tanium-tr-get-file-download-info
***
Gets the metadata of a file download. You must supply either the `path` or `id` agument for the command to run successfully.


##### Base Command

`tanium-tr-get-file-download-info`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The hostname of the downloaded file. | Required | 
| path | The path of the file. | Optional | 
| id | File download ID. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.FileDownload.Size | Number | The size of the file, in bytes. | 
| Tanium.FileDownload.Path | String | The path of the file. | 
| Tanium.FileDownload.Downloaded | Date | The date when this file was downloaded. | 
| Tanium.FileDownload.Host | String | The hostname of the downloaded file. | 
| Tanium.FileDownload.Created | Date | The date when the file was created. | 
| Tanium.FileDownload.Hash | String | The file hash. | 
| Tanium.FileDownload.SPath | String | The file SPath. | 
| Tanium.FileDownload.ID | Number | The downloaded file ID. | 
| Tanium.FileDownload.LastModified | Date | The date when the file was last modified. | 
| Tanium.FileDownload.CreatedBy | String | The user that created this file. | 
| Tanium.FileDownload.CreatedByProc | String | The process path that created this file. | 
| Tanium.FileDownload.LastModifiedBy | String | The user that last modified this file. | 
| Tanium.FileDownload.LastModifiedByProc | String | The process path that modified this file. | 
| Tanium.FileDownload.Comments | String | The downloaded file comments. | 
| Tanium.FileDownload.Tags | String | The downloaded file tags. | 
| Tanium.FileDownload.Deleted | Boolean | Whether the file download has been deleted. | 


##### Command Example
```!tanium-tr-get-file-download-info host=HOST_NAME id=4```

##### Context Example
```
{
    "Tanium": {
        "FileDownload": {
            "Created": "2020-01-02 15:39:57.289",
            "CreatedBy": "NT AUTHORITY\\LOCAL SERVICE",
            "CreatedByProc": "C:\\Windows\\System32\\svchost.exe",
            "Downloaded": "2020-01-02 15:40:29.003",
            "Hash": "2ae2da9237309b13b9a9d52d1358c826",
            "Host": "HOST_NAME",
            "ID": 4,
            "LastModified": "2020-01-02 15:39:57.289",
            "LastModifiedBy": "NT AUTHORITY\\LOCAL SERVICE",
            "LastModifiedByProc": "C:\\Windows\\System32\\svchost.exe",
            "Path": "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\lastalive1.dat",
            "SPath": "6ae86937-611f-45e9-900c-3ba57298f264.zip",
            "Size": 2048,
            "Deleted": false
        }
    }
}
```

##### Human Readable Output
### File download metadata for file `C:\Windows\ServiceProfiles\LocalService\AppData\Local\lastalive1.dat`
|ID|Host|Path|Hash|Downloaded|Size|Created|Created By|Created By Proc|Last Modified|Last Modified By|Last Modified By Proc|S Path|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 4 | HOST_NAME | C:\Windows\ServiceProfiles\LocalService\AppData\Local\lastalive1.dat | 2ae2da9237309b13b9a9d52d1358c826 | 2020-01-02 15:40:29.003 | 2048 | 2020-01-02 15:39:57.289 | NT AUTHORITY\LOCAL SERVICE | C:\Windows\System32\svchost.exe | 2020-01-02 15:39:57.289 | NT AUTHORITY\LOCAL SERVICE | C:\Windows\System32\svchost.exe | 6ae86937-611f-45e9-900c-3ba57298f264.zip |


### tanium-tr-get-process-info
***
Get information for a process.


##### Base Command

`tanium-tr-get-process-info`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The connection name. | Required | 
| ptid | The process instance ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Process.CreateTime | Date | Time when the process was created. | 
| Tanium.Process.Domain | String | The domain of the process. | 
| Tanium.Process.ExitCode | Number | The process exit code. | 
| Tanium.Process.ProcessCommandLine | String | The process command line. | 
| Tanium.Process.ProcessID | Number | The ID of the process. | 
| Tanium.Process.ProcessName | String | File of the process. | 
| Tanium.Process.ProcessTableId | Number | The ID of the process table. | 
| Tanium.Process.SID | String | The security ID of the process. | 
| Tanium.Process.Username | String | The username who created the process. | 


##### Command Example
```!tanium-tr-get-process-info ptid=667680 connection-name=HOST_NAME limit=5```

##### Context Example
```
{
    "Tanium": {
        "Process": {
            "CreateTime": "2020-01-22 16:16:07.553",
            "Domain": "NT AUTHORITY",
            "ExitCode": 0,
            "ProcessCommandLine": "System",
            "ProcessID": 4,
            "ProcessName": "System",
            "ProcessTableId": 667680,
            "SID": "S-1-5-18",
            "Username": "SYSTEM"
        }
    }
}
```

##### Human Readable Output
### Process information for process with PTID 667680
|Process ID|Process Name|Process Command Line|Process Table Id|SID|Username|Domain|Exit Code|Create Time|
|---|---|---|---|---|---|---|---|---|
| 4 | System | System | 667680 | S-1-5-18 | SYSTEM | NT AUTHORITY | 0 | 2020-01-22 16:16:07.553 |


### tanium-tr-get-events-by-process
***
Gets the events for a process.


##### Base Command

`tanium-tr-get-events-by-process`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The connection name. | Required | 
| ptid | The process instance ID. | Required | 
| limit | The maximum number of events to return. | Optional | 
| offset | The offset number to begin listing events. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ProcessEvent.ID | Number | The ID of the event. | 
| Tanium.ProcessEvent.Detail | Unknown | The event details. | 
| Tanium.ProcessEvent.Operation | String | The event operation. | 
| Tanium.ProcessEvent.Timestamp | Date | Time when the event was created. | 
| Tanium.ProcessEvent.Type | String | The event type. | 


##### Command Example
```!tanium-tr-get-events-by-process ptid=667680 connection-name=HOST_NAME limit=1```

##### Context Example
```
{
    "Tanium": {
        "ProcessEvent": {
            "Detail": "4: System",
            "ID": 667680,
            "Operation": "CreateProcess",
            "Timestamp": "2020-01-22 16:16:07.553",
            "Type": "Process"
        }
    }
}
```

##### Human Readable Output
### Events for process 667680
|ID|Detail|Type|Timestamp|Operation|
|---|---|---|---|---|
| 667680 | 4: System | Process | 2020-01-22 16:16:07.553 | CreateProcess |


### tanium-tr-get-process-children
***
Gets the children of this process instance.


##### Base Command

`tanium-tr-get-process-children`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The connection name. | Required | 
| ptid | The process instance ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ProcessChildren.ID | Number | The ID of the process. | 
| Tanium.ProcessChildren.Name | String | File of the process. | 
| Tanium.ProcessChildren.PID | Number | The PID of the process. | 
| Tanium.ProcessChildren.PTID | Number | The process instance ID. | 
| Tanium.ProcessChildren.Parent | String | The parent process name. | 


##### Command Example
```!tanium-tr-get-process-children ptid=667680 connection-name=HOST_NAME```

##### Context Example
```
{
    "Tanium": {
        "ProcessChildren": [
            {
                "ID": 667681,
                "Name": "0: Unknown Process",
                "PID": 0,
                "PTID": 667681,
                "Parent": "4: System"
            },
            {
                "ID": 667682,
                "Name": "1: Pruned Process",
                "PID": 1,
                "PTID": 667682,
                "Parent": "4: System"
            },
            {
                "ID": 667683,
                "Name": "392: smss.exe",
                "PID": 392,
                "PTID": 667683,
                "Parent": "4: System"
            }
        ]
    }
}
```

##### Human Readable Output
### Children for process with PTID 667680
|ID|Name|PID|PTID|Parent|Children Count|
|---|---|---|---|---|---|
| 667681 | 0: Unknown Process | 0 | 667681 | 4: System | 0 |
| 667682 | 1: Pruned Process | 1 | 667682 | 4: System | 0 |
| 667683 | 392: smss.exe | 392 | 667683 | 4: System | 0 |


### tanium-tr-get-parent-process
***
Gets information for the parent process.


##### Base Command

`tanium-tr-get-parent-process`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The connection name. | Required | 
| ptid | The process instance ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Process.CreateTime | Date | Time when the process was created. | 
| Tanium.Process.Domain | String | The domain of the process. | 
| Tanium.Process.ExitCode | Number | The process exit code. | 
| Tanium.Process.ProcessCommandLine | String | The process command line. | 
| Tanium.Process.ProcessID | Number | The ID of the process. | 
| Tanium.Process.ProcessName | String | File of the process. | 
| Tanium.Process.ProcessTableId | Number | The ID of the process table. | 
| Tanium.Process.SID | String | The security ID of the process. | 
| Tanium.Process.Username | String | The username who created the process. | 


##### Command Example
```!tanium-tr-get-parent-process ptid=667681 connection-name=HOST_NAME```

##### Context Example
```
{
    "Tanium": {
        "ParentProcess": {
            "CreateTime": "2020-01-22 16:16:07.553",
            "Domain": "NT AUTHORITY",
            "ExitCode": 0,
            "ProcessCommandLine": "System",
            "ProcessID": 4,
            "ProcessName": "System",
            "ProcessTableId": 667680,
            "SID": "S-1-5-18",
            "Username": "SYSTEM"
        }
    }
}
```

##### Human Readable Output
### Process information for process with PTID 667681
|Process ID|Process Name|Process Command Line|Process Table Id|SID|Username|Domain|Exit Code|Create Time|
|---|---|---|---|---|---|---|---|---|
| 4 | System | System | 667680 | S-1-5-18 | SYSTEM | NT AUTHORITY | 0 | 2020-01-22 16:16:07.553 |


### tanium-tr-get-parent-process-tree
***
Gets the parent process tree for the process instance.


##### Base Command

`tanium-tr-get-parent-process-tree`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The connection name. | Required | 
| ptid | The process instance ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ParentProcessTree.ID | Number | The parent process ID. | 
| Tanium.ParentProcessTree.Name | String | File of the parent process. | 
| Tanium.ParentProcessTree.PID | Number | The parent process PID. | 
| Tanium.ParentProcessTree.PTID | Number | The parent process instance ID. | 
| Tanium.ParentProcessTree.Parent | String | The parent process name. | 
| Tanium.ParentProcessTree.Children | Unknown | The parent process children. | 


##### Command Example
```!tanium-tr-get-parent-process-tree ptid=667681 connection-name=HOST_NAME```

##### Context Example
```
{
    "Tanium": {
        "ParentProcessTree": {
            "Children": [
                {
                    "Children": [],
                    "ID": 667681,
                    "Name": "0: Unknown Process",
                    "PID": 0,
                    "PTID": 667681,
                    "Parent": "4: System"
                },
                {
                    "Children": [],
                    "ID": 667682,
                    "Name": "1: Pruned Process",
                    "PID": 1,
                    "PTID": 667682,
                    "Parent": "4: System"
                },
                {
                    "Children": [],
                    "ID": 667683,
                    "Name": "392: smss.exe",
                    "PID": 392,
                    "PTID": 667683,
                    "Parent": "4: System"
                }
            ],
            "ID": 667680,
            "Name": "4: System",
            "PID": 4,
            "PTID": 667680
        }
    }
}
```

##### Human Readable Output
### Parent process for process with PTID 667681
|ID|Name|PID|PTID|
|---|---|---|---|
| 667680 | 4: System | 4 | 667680 |
### Processes with the same parent
|ID|Name|PID|PTID|Parent|Children Count|
|---|---|---|---|---|---|
| 667681 | 0: Unknown Process | 0 | 667681 | 4: System | 0 |
| 667682 | 1: Pruned Process | 1 | 667682 | 4: System | 0 |
| 667683 | 392: smss.exe | 392 | 667683 | 4: System | 0 |


### tanium-tr-get-process-tree
***
Gets the process tree for the process instance.


##### Base Command

`tanium-tr-get-process-tree`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The connection name. | Required | 
| ptid | The process instance ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ProcessTree.ID | Number | The process ID. | 
| Tanium.ProcessTree.Name | String | File of the process. | 
| Tanium.ProcessTree.PID | Number | The process PID. | 
| Tanium.ProcessTree.PTID | Number | The process instance ID. | 
| Tanium.ProcessTree.Parent | String | The parent process name. | 
| Tanium.ProcessTree.Children | Unknown | The process children. | 


##### Command Example
```!tanium-tr-get-process-tree ptid=667680 connection-name=HOST_NAME```

##### Context Example
```
{
    "Tanium": {
        "ProcessTree": {
            "Children": [
                {
                    "Children": [],
                    "ID": 667681,
                    "Name": "0: Unknown Process",
                    "PID": 0,
                    "PTID": 667681,
                    "Parent": "4: System"
                },
                {
                    "Children": [],
                    "ID": 667682,
                    "Name": "1: Pruned Process",
                    "PID": 1,
                    "PTID": 667682,
                    "Parent": "4: System"
                },
                {
                    "Children": [],
                    "ID": 667683,
                    "Name": "392: smss.exe",
                    "PID": 392,
                    "PTID": 667683,
                    "Parent": "4: System"
                }
            ],
            "ID": 667680,
            "Name": "4: System",
            "PID": 4,
            "PTID": 667680
        }
    }
}
```

##### Human Readable Output
### Process information for process with PTID 667680
|ID|Name|PID|PTID|
|---|---|---|---|
| 667680 | 4: System | 4 | 667680 |
### Children for process with PTID 667680
|ID|Name|PID|PTID|Parent|Children Count|
|---|---|---|---|---|---|
| 667681 | 0: Unknown Process | 0 | 667681 | 4: System | 0 |
| 667682 | 1: Pruned Process | 1 | 667682 | 4: System | 0 |
| 667683 | 392: smss.exe | 392 | 667683 | 4: System | 0 |


### tanium-tr-list-evidence
***
Returns a list of all available evidence in the system.


##### Base Command

`tanium-tr-list-evidence`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of evidences to return. The default value is 50. | Optional | 
| offset | Offset to start getting the events result set. The default is 0. | Optional | 
| sort | A comma-separated list of fields by which to sort, using +/- prefixes for ascending/descending, in order of priority (left to right). | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Evidence.ID | Number | The evidence ID. | 
| Tanium.Evidence.CreatedAt | Date | Time when the process was created. | 
| Tanium.Evidence.LastModified | Date | The date that the file was last modified. | 
| Tanium.Evidence.User | String | The user of the evidence. | 
| Tanium.Evidence.ConnectionName | String | The evidence connection name. | 
| Tanium.Evidence.Type | Number | The evidence type. | 
| Tanium.Evidence.ProcessTableId | Number | The evidence process table ID. | 
| Tanium.Evidence.Timestamp | Date | The evidence timestamp. | 
| Tanium.Evidence.Summary | String | The evidence summary. | 
| Tanium.Evidence.Comments | String | The evidence comments. | 
| Tanium.Evidence.Tags | String | The evidence tags. | 
| Tanium.Evidence.Deleted | Boolean | Whether the evident has been deleted. | 


##### Command Example
```!tanium-tr-list-evidence limit=2 offset=1 sort=+id```

##### Context Example
```
{
    "Tanium": {
        "Evidence": [
            {
                "ConnectionName": "HOST_NAME",
                "CreatedAt": "2020-01-02 15:40:03",
                "ID": 2,
                "ProcessTableId": 45632561,
                "Summary": "CreateProcess: C:\\Windows\\SysWOW64\\cmd.exe",
                "Timestamp": "2020-01-02 15:39:28.809",
                "Type": 2,
                "UpdatedAt": "2020-01-02 15:40:03",
                "User": "actionapprover",
                "Deleted": false
            },
            {
                "ConnectionName": "HOST_NAME",
                "CreatedAt": "2020-01-13 18:02:01",
                "ID": 13,
                "ProcessTableId": 4563722,
                "Summary": "CreateProcess: C:\\Windows\\System32\\wsqmcons.exe",
                "Timestamp": "2020-01-13 18:00:01.010",
                "Type": 2,
                "UpdatedAt": "2020-01-13 18:02:01",
                "User": "HOST_NAME\\administrator",
                "Deleted": false
            }
        ]
    }
}
```

##### Human Readable Output
### Evidence List
|ID|Timestamp|Conntection Name|User|Summary|Type|Created At|Updated At|Process Table Id|
|---|---|---|---|---|---|---|---|---|
| 2 | 2020-01-02 15:39:28.809 | HOST_NAME | actionapprover | CreateProcess: C:\Windows\SysWOW64\cmd.exe | 2 | 2020-01-02 15:40:03 | 2020-01-02 15:40:03 | 45632561 |
| 13 | 2020-01-13 18:00:01.010 | HOST_NAME | HOST_NAME\administrator | CreateProcess: C:\Windows\System32\wsqmcons.exe | 2 | 2020-01-13 18:02:01 | 2020-01-13 18:02:01 | 4563722 |


### tanium-tr-get-evidence-by-id
***
Gets evidence by evidence ID.


##### Base Command

`tanium-tr-get-evidence-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| evidence-id | The ID of the evidence. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Evidence.ID | Number | The evidence ID. | 
| Tanium.Evidence.CreatedAt | Date | Time when the process was created. | 
| Tanium.Evidence.LastModified | Date | The date that the file was last modified. | 
| Tanium.Evidence.User | String | The user of the evidence. | 
| Tanium.Evidence.ConnectionName | String | The evidence connection name. | 
| Tanium.Evidence.Type | Number | The evidence type. | 
| Tanium.Evidence.ProcessTableId | Number | The evidence process table ID. | 
| Tanium.Evidence.Timestamp | Date | The evidence timestamp. | 
| Tanium.Evidence.Summary | String | The evidence summary. | 
| Tanium.Evidence.Comments | String | The evidence comments. | 
| Tanium.Evidence.Tags | String | The evidence tags. | 
| Tanium.Evidence.Deleted | Boolean | Whether the evident has been deleted. | 


##### Command Example
```!tanium-tr-get-evidence-by-id evidence-id=2```

##### Context Example
```
{
    "Tanium": {
        "Evidence": {
            "CreatedAt": "2020-01-02 15:40:03",
            "ConnectionName": "HOST_NAME",
            "ProcessTableId": 45632561,
            "ID": 2,
            "Summary": "CreateProcess: C:\\Windows\\SysWOW64\\cmd.exe",
            "Timestamp": "2020-01-02 15:39:28.809",
            "Type": 2,
            "UpdatedAt": "2020-01-02 15:40:03",
            "User": "actionapprover",
            "Deleted": false
        }
    }
}
```

##### Human Readable Output
### Label information
|ID|Timestamp|Connection Name|User|Summary|Type|Created At|Updated At|Process Table Id|
|---|---|---|---|---|---|---|---|---|
| 2 | 2020-01-02 15:39:28.809 | HOST_NAME | actionapprover | CreateProcess: C:\Windows\SysWOW64\cmd.exe | 2 | 2020-01-02 15:40:03 | 2020-01-02 15:40:03 | 45632561 |


### tanium-tr-create-evidence
***
Creates an evidence.


##### Base Command

`tanium-tr-create-evidence`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The name of the connection. | Required | 
| ptid | The process instance ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!tanium-tr-create-evidence connection-name=HOST_NAME connection-name=HOST_NAME ptid=13538572```

##### Human Readable Output
Evidence have been created.


### tanium-tr-delete-evidence
***
Deletes an evidence.


##### Base Command

`tanium-tr-delete-evidence`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| evidence-id | The ID of the evidence. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Evidence.ID | String | The evidence ID. | 
| Tanium.Evidence.Deleted | Boolean | Whether the evidence has been deleted. | 


##### Command Example
```!tanium-tr-delete-evidence evidence-id=1```

##### Context Example
```
{
    "Tanium": {
        "Evidence": {
            "ID": 2,
            "Deleted": true
        }
    }
}
```

##### Human Readable Output
Evidence 1 has been deleted successfully.


### tanium-tr-request-file-download
***
Requests a new file download.


##### Base Command

`tanium-tr-request-file-download`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | Path to file. | Required | 
| connection-name | Connection name. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.FileDownload.Path | String | The file download path. | 
| Tanium.FileDownload.ConnectionName | String | The file download connection name. | 
| Tanium.FileDownload.Downloaded | Date | Date of the download request. | 
| Tanium.FileDownload.Status | String | Status of the file download request. | 
| Tanium.FileDownload.ID | Number | ID of the file download. | 


##### Command Example
```!tanium-tr-request-file-download connection-name=HOST_NAME path=dev/autofs```

##### Context Example
```
{
    "Tanium": {
        "FileDownload": {
            "Downloaded": "2020-02-06 16:05:40.227674",
            "ConnectionName": "HOST_NAME",
            "Path": "dev/autofs"
        }
    }
}
```

##### Human Readable Output
Download request of file autofs has been sent successfully.


### tanium-tr-delete-file-download
***
Deletes a file download.


##### Base Command

`tanium-tr-delete-file-download`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file-id | File download ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.FileDownload.ID | String | The file download ID. | 
| Tanium.FileDownload.Deleted | Boolean | Whether the file download has been deleted. | 


##### Command Example
```!tanium-tr-delete-file-download file-id=3```

##### Context Example
```
{
    "Tanium": {
        "FileDownload": {
            "ID": 3,
            "Deleted": true
        }
    }
}
```

##### Human Readable Output
Delete request of file with ID 3 has been sent successfully.


### tanium-tr-list-files-in-directory
***
Gets a list of files in the given directory.


##### Base Command

`tanium-tr-list-files-in-directory`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | Path to the directory. | Required | 
| connection-name | Connection name. | Required | 
| limit | The maximum number of files to return. The default value is 50. | Optional | 
| offset | Offset to start getting files. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.File.Created | Date | Time the file was created. | 
| Tanium.File.Size | Number | The file size. | 
| Tanium.File.IsDirectory | Boolean | Whether or not the file is a directory. | 
| Tanium.File.LastModified | Date | The date that the file was last modified. | 
| Tanium.File.Path | Boolean | The file path. | 
| Tanium.File.Permissions | Date | The file permissions. | 
| Tanium.File.ConnectionName | String | The host of the file. | 
| Tanium.File.Deleted | Boolean | Whether the file has been deleted. | 


##### Command Example
```!tanium-tr-list-files-in-directory path=`C:\Program Files (x86)\Tanium\Tanium Client\` connection-name=HOST_NAME limit=2```

##### Context Example
```
{
    "Tanium": {
        "File": [
            {
                "Created": "1970-01-19 03:25:44",
                "IsDirectory": false,
                "LastModified": "1970-01-19 03:25:44",
                "Path": ".detect-engine.lock",
                "Permissions": "rw-rw-rw-",
                "Size": 0,
                "Deleted": false
            },
            {
                "Created": "1970-01-18 21:02:12",
                "IsDirectory": true,
                "LastModified": "1970-01-19 07:10:05",
                "Path": "Downloads",
                "Permissions": "rw-rw-rw-",
                "Size": 393216,
                "Deleted": false
            }
        ]
    }
}
```

##### Human Readable Output
### Files in directory `C:\Program Files (x86)\Tanium\Tanium Client\`
|Path|Size|Created|Last Modified|Permissions|Is Directory|
|---|---|---|---|---|---|
| .detect-engine.lock | 0 | 1970-01-19 03:25:44 | 1970-01-19 03:25:44 | rw-rw-rw- | false |
| Downloads | 393216 | 1970-01-18 21:02:12 | 1970-01-19 07:10:05 | rw-rw-rw- | true |


### tanium-tr-get-file-info
***
Gets information about a file from a remote connection.


##### Base Command

`tanium-tr-get-file-info`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The name of the connection. | Required | 
| path | The path to the file. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.File.Created | Date | The file creation timestamp. | 
| Tanium.File.Size | Number | The file size. | 
| Tanium.File.IsDirectory | Boolean | Whether or not the file is a directory. | 
| Tanium.File.LastModified | Date | The date that the file was last modified. | 
| Tanium.File.Path | String | The file path. | 
| Tanium.File.ConnectionName | String | The host of the file. | 
| Tanium.File.Deleted | Boolean | Whether the file has been deleted. | 


##### Command Example
```!tanium-tr-get-file-info connection-name=HOST_NAME path=`C:\Program Files (x86)\Tanium\Tanium Client\TaniumClient.exe` ```

##### Context Example
```
{
    "Tanium": {
        "File": {
            "Created": "1970-01-18 20:01:58",
            "IsDirectory": false,
            "LastModified": "1970-01-18 20:01:58",
            "Size": 4938736
            "Path": "C:\Program Files (x86)\Tanium\Tanium Client\TaniumClient.exe",
            "ConnectionName": "HOST_NAME",
            "Deleted": false
        }
    }
}
```

##### Human Readable Output
### Information for file `C:\Program Files (x86)\Tanium\Tanium Client\TaniumClient.exe`
|Path|Size|Created|Last Modified|Is Directory|Connection Name|
|---|---|---|---|---|---|
| C:\Program Files (x86)\Tanium\Tanium Client\TaniumClient.exe | 4938736 | 1970-01-18 20:01:58 | 1970-01-18 20:01:58 | false | HOST_NAME |


### tanium-tr-delete-file-from-endpoint
***
Deletes a file from the given endpoint.


##### Base Command

`tanium-tr-delete-file-from-endpoint`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | Connection name. | Required | 
| path | Path to file. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.File.Path | String | The file path. | 
| Tanium.File.ConnectionName | String | The host of the file. | 
| Tanium.File.Deleted | Boolean | Whether the file has been deleted. | 


##### Command Example
```!tanium-tr-delete-file-from-endpoint path=`C:\Program Files (x86)\Tanium\Tanium Client\Logs\log0.txt` connection-name=HOST_NAME```

##### Context Example
```
{
    "Tanium": {
        "File": {
            "Path": "C:\Program Files (x86)\Tanium\Tanium Client\Logs\log0.txt",
            "ConnectionName": "HOST_NAME",
            "Deleted": true
        }
    }
}
```

##### Human Readable Output
Delete request of file C:\Program Files (x86)\Tanium\Tanium Client\Logs\log0.txt from endpoint HOST_NAME has been sent successfully.



### tanium-tr-get-process-timeline
***
Gets the process timeline.


##### Base Command

`tanium-tr-get-process-timeline`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | Connection name. | Required | 
| ptid | Process table ID. | Required | 
| category | The event categories to retrieve. Can be "File", "DNS", "Registry", "Network", "Image", or "Process". | Required | 
| limit | The maximum number of events to return. The default value is 50. | Optional | 
| offset | Offset to start getting the events. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ProcessTimeline.ProcessTableID | Number | The process instance ID. | 
| Tanium.ProcessTimeline.ConnectionName | String | The connection name of the process. | 
| Tanium.ProcessTimeline.Date | Date | Events date of the process. | 
| Tanium.ProcessTimeline.Event | String | Event of the process. | 
| Tanium.ProcessTimeline.Category | String | The event category of the process. | 


##### Command Example
```!tanium-tr-get-process-timeline ptid=13530396 connection-name=HOST_NAME category=Process limit=2```

##### Context Example
```
{
    "Tanium": {
        "ProcessTimeline": [
            {
                "Category": "Process",
                "Date": "2020-02-05 10:16:02.319000",
                "Event": [
                    "Process started by root\\root"
                ]
            },
            {
                "Category": "Process",
                "Date": "2020-02-05 10:17:00.000000",
                "Event": [
                    "Process ended"
                ]
            }
        ]
    }
}
```

##### Human Readable Output
### Timeline data for process with PTID `13530396`
|Date|Event|Category|
|---|---|---|
| 2020-02-05 10:16:02.319000 | Process started by root\root | Process |
| 2020-02-05 10:17:00.000000 | Process ended | Process |


### tanium-tr-get-download-file-request-status
***
Gets the status of the download file request.


##### Base Command

`tanium-tr-get-download-file-request-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request-date | Date of the download file request, or example: 2019-09-23T12:55:08.622 | Required | 
| connection-name | The connection to which the request was made. | Optional | 
| path | The file path. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.DownloadFile.ID | Number | ID of the file download. | 
| Tanium.DownloadFile.ConnectionName | String | Host of the file. | 
| Tanium.DownloadFile.Path | String | Path of the file. | 
| Tanium.DownloadFile.Status | String | Status of the file download request. | 
| Tanium.DownloadFile.Downloaded | Date | The date of the download request. | 


##### Command Example
```!tanium-tr-get-download-file-request-status request-date=2019-09-23T12:55:08.622```

##### Context Example
```
{
    "Tanium": {
        "FileDownload": {
            "Downloaded": "2020-01-02 15:40:18.052",
            "ID": 3,
            "Status": "Completed",
            "Path": "C:\Program Files (x86)\Tanium\Tanium Client\Logs\log1.txt",
            "ConnectionName": "HOST_NAME"
        }
    }
}
```

##### Human Readable Output
### File download request status
|ID|Connection Name|Status|Path|Downloaded|
|---|---|---|---|---|
| 3 | HOST_NAME | Completed | C:\Program Files (x86)\Tanium\Tanium Client\Logs\log1.txt | 2020-01-02 15:40:18.052 |


### tanium-tr-intel-doc-create
***
Add a new intel document to the system by providing its document contents.


##### Base Command

`tanium-tr-intel-doc-create`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry-id | The file entry ID. | Required |
| file_extension | The suffix at the end of a filename. (Available file types - yara, stix, ioc) | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.IntelDoc.AlertCount | Number | The number of alerts that currently exist for this intel. |
| Tanium.IntelDoc.CreatedAt | Date | The date at which this intel was first added to the system. |
| Tanium.IntelDoc.Description | String | The description of the intel, as declared in the document or as updated by a user. |
| Tanium.IntelDoc.ID | Number | The unique identifier for this intel in this instance of the system. |
| Tanium.IntelDoc.LabelIds | Number | The IDs of all labels applied to this intel. |
| Tanium.IntelDoc.Name | String | The name of the intel, as declared in the document or as updated by a user. |
| Tanium.IntelDoc.Type | String | The shortened type name of the intel. For example, "openioc", "stix", "yara". |
| Tanium.IntelDoc.UnresolvedAlertCount | Number | The number of unresolved alerts that currently exist for this intel. |
| Tanium.IntelDoc.UpdatedAt | Date | The date when this intel was last updated. |


##### Command Example
```!tanium-tr-intel-doc-create entry-id=7173@e99f97d1-7225-4c75-896c-3c960febbe8c file_extension=ioc```
##### Context Example
```
{
    "Tanium": {
        "IntelDoc": {
            "AlertCount": 0,
            "CreatedAt": "2019-07-31T18:46:28.814Z",
            "Description": "Detects usage of the NET.EXE utility to enumerate members of the local Administrators or Domain Administrators groups. Often used during post-compromise reconnaissance.",
            "ID": 2,
            "LabelIds": [
                2,
                3,
                9,
                16
            ],
            "Name": "Administrator Account Enumeration",
            "Type": "openioc",
            "UnresolvedAlertCount": 0,
            "UpdatedAt": "2020-01-14T21:37:30.934Z"
        }
    }
}
```
##### Human Readable Output
### Intel Doc uploaded
|ID|Name|Description|Type|Alert Count|Unresolved Alert Count|Created At|Updated At|Label Ids|
|---|---|---|---|---|---|---|---|---|
| 2 | Administrator Account Enumeration | Detects usage of the NET.EXE utility to enumerate members of the local Administrators or Domain Administrators groups. Often used during post-compromise reconnaissance. | openioc | 0 | 0 | 2019-07-31T18:46:28.814Z | 2020-01-14T21:37:30.934Z | 2, 3, 9, 16 |


### tanium-tr-start-quick-scan
***
Scan a computer group for hashes in intel document. Computer groups can be viewed by navigating to `Administration -> Computer Groups` in the UI. Computer group names and IDs can also be retrieved by using the ***tn-list-groups*** command in the `Tanium` integration.


##### Base Command

`tanium-tr-start-quick-scan`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel-doc-id | The intel document ID. | Required |
| computer-group-name | The name of a Tanium computer group. See command description for possible ways to retrieve this value. | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.QuickScan.AlertCount | Number | The number of alerts returned from the quick scan. |
| Tanium.QuickScan.ComputerGroupId | Number | The ID of a Tanium computer group. |
| Tanium.QuickScan.CreatedAt | Date | The date the quick scan was created. |
| Tanium.QuickScan.ID | Number | The ID of the quick scan. |
| Tanium.QuickScan.IntelDocId | Number | The unique identifier for this intel in the instance of the system. |
| Tanium.QuickScan.QuestionID | Number | The ID of the quick scan question. |
| Tanium.QuickScan.UserID | Number | The user ID which initiated the quick scan. |


##### Command Example
```!tanium-tr-start-quick-scan intel-doc-id=2 computer-group-name="All Computers"```
##### Context Example
```
{
    "Tanium": {
        "QuickScan": {
            "AlertCount": 0,
            "ComputerGroupId": 1
            "CreatedAt": "2019-07-31T18:46:28.814Z",
            "ID": 5,
            "IntelDocId": 2
            "QuestionID": 4,
            "UserID": 3
        }
    }
}
```
##### Human Readable Output
### Quick Scan started
Alert Count|ComputerGroupId|CreatedAt|ID|IntelDocId|QuestionID|UserID|
|---|---|---|---|---|---|---|
| 0 | 1 | 2019-07-31T18:46:28.814Z | 5 | 2 | 4 | 3 |
