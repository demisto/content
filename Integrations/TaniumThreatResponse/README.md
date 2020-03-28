Tanium Threat Response
This integration was integrated and tested with version 5.5.0 of Tanium Threat Response
## Configure Tanium Threat Response on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Tanium Threat Response.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Hostname, IP address, or server URL. | True |
| credentials | Credentials | True |
| insecure | Trust any certificate (not secure) | True |
| proxy | Use system proxy settings | False |
| fetch_time | First fetch timestamp (<number> <time unit>, e.g., 12 hours, 7 days) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### tanium-tr-get-intel-doc-by-id
***
Returns a intel document object based on ID.
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
|ID|Name|Description|Type|AlertCount|UnresolvedAlertCount|CreatedAt|UpdatedAt|LabelIds|
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
|ID|Name|Description|Type|AlertCount|UnresolvedAlertCount|CreatedAt|UpdatedAt|LabelIds|
|---|---|---|---|---|---|---|---|---|
| 99 | Spooler Service Creating or Spawning Executables |  |  | 0 | 0 | 2020-01-14T21:37:32.263Z | 2020-01-14T21:37:32.263Z | 2, 7, 11, 16 |
| 98 | RunDll Creating MiniDump |  |  | 0 | 0 | 2020-01-14T21:37:32.075Z | 2020-01-14T21:37:32.075Z | 2, 8, 16 |


### tanium-tr-list-alerts
***
Returns a list of all alerts.
##### Base Command

`tanium-tr-list-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of alerts to return. | Optional | 
| offset | The offset number to begin listing alerts. | Optional | 
| computer-ip-address | Filter alerts by the specified computer IP Addresses. | Optional | 
| computer-name | Filter alerts by the specified computer name. | Optional | 
| scan-config-id | Filter alerts by the specified scan config ID. | Optional | 
| intel-doc-id | Filter alerts by the specified intel document ID. | Optional | 
| severity | Filter alerts by the specified severity. | Optional | 
| priority | Filter alerts by the specified priority. | Optional | 
| type | Filter alerts by the specified type. | Optional | 
| state | Filter alerts by the specified state. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Alert.Priority | String | The priority of the alert. | 
| Tanium.Alert.ComputerName | String | The hostname of the computer that generated the alert. | 
| Tanium.Alert.GUID | String | A globally unique identifier for this alert in the customer environment. | 
| Tanium.Alert.AlertedAt | Date | The moment that the alert was generated. | 
| Tanium.Alert.UpdatedAt | Date | The last time the alert state was updated. | 
| Tanium.Alert.State | String | The current state of the alert. For example, "unresolved", "inprogress", etc. | 
| Tanium.Alert.ComputerIpAddress | String | The IP address of the computer that generated the alert. | 
| Tanium.Alert.Type | String | The type name of the alert. For example, "detect.endpoint.match", etc. | 
| Tanium.Alert.ID | Number | The type name of the alert. For example, "detect.endpoint.match", etc. | 
| Tanium.Alert.CreatedAt | Date | The moment that the alert was received by the Detect product. | 
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
|ID|Name|Type|Severity|Priority|AlertedAt|CreatedAt|UpdatedAt|ComputerIpAddress|ComputerName|GUID|State|IntelDocId|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 |  | detect.match | info | high | 2019-09-22T14:01:31.000Z | 2019-09-22T14:01:59.768Z | 2020-02-05T14:55:41.440Z | 172.0.0.0 | HOST_NAME | a33e3482-556e-4e9d-bbbd-2fdbe330d492 | Unresolved | 64 |


### tanium-tr-get-alert-by-id
***
Returns alert object based on ID.
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
| Tanium.Alert.AlertedAt | Date | The moment that the alert was generated. | 
| Tanium.Alert.UpdatedAt | Date | The last time the alert state was updated. | 
| Tanium.Alert.State | String | The current state of the alert. For example, "unresolved", "inprogress", etc. | 
| Tanium.Alert.ComputerIpAddress | String | The IP address of the computer that generated the alert. | 
| Tanium.Alert.Type | String | The type name of the alert. For example, "detect.endpoint.match", etc. | 
| Tanium.Alert.ID | Number | The type name of the alert. For example, "detect.endpoint.match", etc. | 
| Tanium.Alert.CreatedAt | Date | The moment that the alert was received by the Detect product. | 
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
|ID|Name|Type|Severity|Priority|AlertedAt|CreatedAt|UpdatedAt|ComputerIpAddress|ComputerName|GUID|State|IntelDocId|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 |  | detect.match | info | high | 2019-09-22T14:01:31.000Z | 2019-09-22T14:01:59.768Z | 2020-02-05T14:55:41.440Z | 172.0.0.0 | HOST_NAME | a33e3482-556e-4e9d-bbbd-2fdbe330d492 | Unresolved | 64 |


### tanium-tr-alert-update-state
***
Update the state of a single alert.
##### Base Command

`tanium-tr-alert-update-state`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert to update. | Required | 
| state | The new state for the alert. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Alert.Priority | String | The priority of the alert. | 
| Tanium.Alert.ComputerName | String | The hostname of the computer that generated the alert. | 
| Tanium.Alert.GUID | String | A globally unique identifier for this alert in the customer environment. | 
| Tanium.Alert.AlertedAt | Date | The moment that the alert was generated. | 
| Tanium.Alert.UpdatedAt | Date | The last time the alert state was updated. | 
| Tanium.Alert.State | String | The current state of the alert. For example, "unresolved", "inprogress", etc. | 
| Tanium.Alert.ComputerIpAddress | String | The IP address of the computer that generated the alert. | 
| Tanium.Alert.Type | String | The type name of the alert. For example, "detect.endpoint.match", etc. | 
| Tanium.Alert.ID | Number | The type name of the alert. For example, "detect.endpoint.match", etc. | 
| Tanium.Alert.CreatedAt | Date | The moment that the alert was received by the Detect product. | 
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
|ID|Name|Type|Severity|Priority|AlertedAt|CreatedAt|UpdatedAt|ComputerIpAddress|ComputerName|GUID|State|IntelDocId|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 |  | detect.match | info | high | 2019-09-22T14:01:31.000Z | 2019-09-22T14:01:59.768Z | 2020-02-05T14:55:41.440Z | 172.0.0.0 | HOST_NAME | a33e3482-556e-4e9d-bbbd-2fdbe330d492 | Unresolved | 64 |


### tanium-tr-list-snapshots
***
Returns all snapshots.
##### Base Command

`tanium-tr-list-snapshots`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximin number of snapshots to return. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Snapshot.DirectoryName | String | The snapshot directory name. | 
| Tanium.Snapshot.Error | String | The snapshot error message. | 
| Tanium.Snapshot.FileName | String | The snapshot file name. | 
| Tanium.Snapshot.Started | Date | The moment that the snapshot was created. | 
| Tanium.Snapshot.State | String | The current state of the snapshot. | 


##### Command Example
```!tanium-tr-list-snapshots limit=2```

##### Context Example
```
{
    "Tanium": {
        "Snapshot": [
            {
                "DirectoryName": "HOST_NAME",
                "FileName": "2020_02_06T15.54.43.600Z.db",
                "Started": "2020-02-06T15:54:43.600Z",
                "State": "complete"
            },
            {
                "DirectoryName": "HOST_NAME",
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
|FileName|DirectoryName|State|Started|Error|
|---|---|---|---|---|
| 2020_02_06T15.54.43.600Z.db | HOST_NAME | complete | 2020-02-06T15:54:43.600Z |  |
| 2020_02_06T15.54.46.795Z.db | HOST_NAME | error | 2020-02-06T15:54:46.795Z | Error checkpointing remote database |


### tanium-tr-create-snapshot
***
Capture a new snapshot by connection ID.
##### Base Command

`tanium-tr-create-snapshot`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-id | The connection ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!tanium-tr-create-snapshot connection-id=HOST_NAME```

##### Human Readable Output
Initiated snapshot creation request for HOST_NAME.

### tanium-tr-delete-snapshot
***
Delete a snapshot by connection ID and snapshot ID.
##### Base Command

`tanium-tr-delete-snapshot`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-id | The connection ID. | Required | 
| snapshot-id | The snapshot ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!tanium-tr-delete-snapshot connection-id=HOST_NAME snapshot-id=2020_02_06T15.54.43.600Z.db```

##### Human Readable Output
Snapshot 2020_02_06T15.54.43.600Z.db deleted successfully.

### tanium-tr-list-local-snapshots
***
Returns all local snapshots.
##### Base Command

`tanium-tr-list-local-snapshots`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximin number of local snapshots to return. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.LocalSnapshot.DirectoryName | String | The snapshot directory name. | 
| Tanium.LocalSnapshot.FileName | String | The snapshot file name. | 


##### Command Example
```!tanium-tr-list-local-snapshots limit=2```

##### Context Example
```
{
    "Tanium": {
        "LocalSnapshot": {
            "DirectoryName": [
                {
                    "DirectoryName": "HOST_NAME",
                    "FileName": "2020_02_06T15.54.43.600Z.db"
                },
                {
                    "DirectoryName": "HOST_NAME",
                    "FileName": "2020_01_09T15.25.13.535Z.db"
                }
            ]
        }
    }
}
```

##### Human Readable Output
### Local snapshots
|FileName|DirectoryName|
|---|---|
| 2020_02_06T15.54.43.600Z.db | HOST_NAME |
| 2020_01_09T15.25.13.535Z.db | HOST_NAME |


### tanium-tr-delete-local-snapshot
***
Delete a local snapshot by directory name and file name.
##### Base Command

`tanium-tr-delete-local-snapshot`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| directory-name | The directory name. | Required | 
| file-name | The file name. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!tanium-tr-delete-local-snapshot directory-name=HOST_NAME file-name=2020_02_06T15.54.43.600Z.db```

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


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Connection.CreateTime | Date | Time when the connection was first created. | 
| Tanium.Connection.Name | String | The connection name. | 
| Tanium.Connection.Remote | Boolean | True if remote connection. | 
| Tanium.Connection.State | String | Current connection state ('closed', 'pending', 'active', 'timeout', 'migrating'). | 


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
                "State": "timeout"
            },
            {
                "DST": "HOST_NAME-2020_01_09T15.25.13.535Z.db",
                "Name": "HOST_NAME-2020_01_09T15.25.13.535Z.db",
                "State": "timeout"
            }
        ]
    }
}
```

##### Human Readable Output
### Connections
|Name|State|Remote|CreateTime|DST|OsName|
|---|---|---|---|---|---|
| HOST_NAME | timeout |  |  | HOST_NAME |  |
| HOST_NAME-2020_01_09T15.25.13.535Z.db | timeout |  |  | HOST_NAME-2020_01_09T15.25.13.535Z.db |  |

### tanium-tr-get-connection-by-name
***
Returns a connection object based on name.
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
| Tanium.Connection.Remote | Boolean | True if remote connection. | 
| Tanium.Connection.State | String | Current connection state ('closed', 'pending', 'active', 'timeout', 'migrating'). | 


##### Command Example
```!tanium-tr-get-connection-by-name connection-name=HOST_NAME```

##### Context Example
```
{
    "Tanium": {
        "Connection": {
            "CreateTime": "2020-02-06T15:54:40.830Z",
            "Name": "HOST_NAME",
            "OsName": "Windows",
            "Remote": true,
            "State": "active"
        }
    }
}
```

##### Human Readable Output
### Connection information
|Name|State|Remote|CreateTime|DST|OsName|
|---|---|---|---|---|---|
| HOST_NAME | active | true | 2020-02-06T15:54:40.830Z |  | Windows |


### tanium-tr-create-connection
***
Creates a local or remote connection.
##### Base Command

`tanium-tr-create-connection`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| remote | True if remote connection. | Required | 
| destination-type | Type of destination: ip_address or computer_name. | Required | 
| destination | computer name or IP address. | Required | 
| connection-timeout | connection timeout, in milliseconds. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!tanium-tr-create-connection destination=HOST_NAME destination-type=computer_name remote=False```

##### Human Readable Output
Initiated connection request to HOST_NAME.

### tanium-tr-delete-connection
***
Delete a connection by connection name.
##### Base Command

`tanium-tr-delete-connection`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The name of the connection. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!tanium-tr-delete-connection connection-name=HOST_NAME```

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
| limit | The maximin number of labels to return. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Label.CreatedAt | Date | The date this label was created. | 
| Tanium.Label.Description | String | An extended description of the label. | 
| Tanium.Label.ID | Number | The unique identifier for this label. | 
| Tanium.Label.IndicatorCount | Number | The number of indicator-based intel documents associated with this label, not including Tanium Signals. | 
| Tanium.Label.Name | String | The display name of the label. | 
| Tanium.Label.SignalCount | Number | The number of Tanium Signal documents associated with this label. | 
| Tanium.Label.UpdatedAt | Date | The date this label was last updated, not including the intel and signal counts. | 


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
|Name|Description|ID|IndicatorCount|SignalCount|CreatedAt|UpdatedAt|
|---|---|---|---|---|---|---|
| Alpha | These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed. | 1 | 0 | 0 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |
| Beta | These signals have been tested and reviewed internally for syntax. Internal testing of expected alert generation has been verified. Testing on internal systems for false positives has been conducted and tuned if necessary. These signals are included on the external feed. | 2 | 0 | 97 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |

### tanium-tr-get-label-by-id
***
Returns label object based on ID.
##### Base Command

`tanium-tr-get-label-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label-id | The label ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Label.CreatedAt | Date | The date this label was created. | 
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
|Name|Description|ID|IndicatorCount|SignalCount|CreatedAt|UpdatedAt|
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
| limit | The maximin number of files to return. | Optional | 
| offset | Offset to start getting file downloads. | Optional | 
| host | Filter by host. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.FileDownload.Size | Number | The size of the file, in bytes. | 
| Tanium.FileDownload.Path | String | The path of the file. | 
| Tanium.FileDownload.Downloaded | Date | The date this file was downloaded. | 
| Tanium.FileDownload.Host | String | The hostname of the dowloaded file. | 
| Tanium.FileDownload.Created | Date | The file creation timestamp. | 
| Tanium.FileDownload.Hash | String | The file hash. | 
| Tanium.FileDownload.SPath | String | The file SPath. | 
| Tanium.FileDownload.ID | Number | The downloaded file ID. | 
| Tanium.FileDownload.LastModified | Date | The date that the file was last modified. | 
| Tanium.FileDownload.CreatedBy | String | User that created this file. | 
| Tanium.FileDownload.CreatedByProc | String | The process path that created this file. | 
| Tanium.FileDownload.LastModifiedBy | String | The last user that modified this file. | 
| Tanium.FileDownload.LastModifiedByProc | String | The process path that modified this file. | 
| Tanium.FileDownload.Comments | String | The downloaded file comments. | 
| Tanium.FileDownload.Tags | String | The downloaded file tags. | 


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
                "Host": "EHOST_NAME",
                "ID": 4,
                "LastModified": "2020-01-02 15:39:57.289",
                "LastModifiedBy": "NT AUTHORITY\\LOCAL SERVICE",
                "LastModifiedByProc": "C:\\Windows\\System32\\svchost.exe",
                "Path": "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\lastalive1.dat",
                "SPath": "6ae86937-611f-45e9-900c-3ba57298f264.zip",
                "Size": 2048
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
                "Size": 10485904
            }
        ]
    }
}
```

##### Human Readable Output
### File downloads
|ID|Host|Path|Hash|Downloaded|Size|Created|CreatedBy|CreatedByProc|LastModified|LastModifiedBy|LastModifiedByProc|SPath|Comments|Tags|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 4 | HOST_NAME | C:\Windows\ServiceProfiles\LocalService\AppData\Local\lastalive1.dat | 2ae2da9237309b13b9a9d52d1358c826 | 2020-01-02 15:40:29.003 | 2048 | 2020-01-02 15:39:57.289 | NT AUTHORITY\LOCAL SERVICE | C:\Windows\System32\svchost.exe | 2020-01-02 15:39:57.289 | NT AUTHORITY\LOCAL SERVICE | C:\Windows\System32\svchost.exe | 6ae86937-611f-45e9-900c-3ba57298f264.zip |  |  |
| 6 | HOST_NAME | C:\Program Files (x86)\Tanium\Tanium Client\Logs\log1.txt | 99297a0e626ca092ff1884ad28f54453 | 2020-01-15 13:04:02.827 | 10485904 | Tue, 03 Sep 2019 17:51:40 GMT |  |  | Wed, 15 Jan 2020 08:57:19 GMT |  |  | c0531415-87a6-4d28-a226-b485784b1881.zip |  |  |

### tanium-tr-get-downloaded-file
***
Get the actual content of a downloaded file by file ID.
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
| event-type | The type of event. | Required | 
| limit | The maximin number of events to return. | Optional | 
| offset | Offset into the result set. | Optional | 
| filter | Advanced search by filtering according to event fields. For example: [['process_id', 'gt', '30'], ['username', 'ne', 'administrator']]. Optional fields: process_id, process_name, process_hash, process_command_line, username, process_name, create_time (UTC). Optional operators: eq (equals), ne (does not equal); for integers/date: gt (greater than), gte (greater than or equals), ls (less than), lse (less than or equals); for strings: co (contains), nc (does not contain).  | Optional | 
| match | If you filter the search results, choose whether the results should fit all of the constrains or to at least one of them. | Optional | 
| sort | Comma-separated list of fields to sort on prefixed by +/- for ascending or descending and ordered by priority left to right. Optional fields: process_id, process_name, process_hash, process_command_line, username, process_name, create_time (UTC). | Optional | 
| fields | Comma-separated list of fields to search on. Optional fields: process_id, process_name, process_hash, process_command_line, username, process_name, create_time. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Event.Domain | String | The domain of the event. | 
| Tanium.Event.File | String | The path of the file in the event. | 
| Tanium.Event.Operation | String | The event operation. | 
| Tanium.Event.ProcessID | Number | The ID of the process. | 
| Tanium.Event.ProcessName | String | The name of the process. | 
| Tanium.Event.ProcessTableID | Number | The ID of the process table. | 
| Tanium.Event.Timestamp | Date | The moment that the event was created. | 
| Tanium.Event.Username | String | The username of the event. | 
| Tanium.Event.DestinationAddress | String | The network event destinetion address. | 
| Tanium.Event.DestinationPort | Number | The network event destinetion port. | 
| Tanium.Event.SourceAddress | String | The network event source address. | 
| Tanium.Event.SourcePort | Number | The network event source port. | 
| Tanium.Event.KeyPath | String | The registry key path. | 
| Tanium.Event.ValueName | String | The registry value name. | 
| Tanium.Event.EndTime | Date | The process end time. | 
| Tanium.Event.ExitCode | Number | The process exit code. | 
| Tanium.Event.ProcessCommandLine | String | The process command line. | 
| Tanium.Event.ProcessHash | String | The hash value of the process. | 
| Tanium.Event.SID | Number | The process SID. | 
| Tanium.Event.Hashes | String | The hashes of the driver. | 
| Tanium.Event.ImageLoaded | String | The image loaded path of the driver. | 
| Tanium.Event.Signature | String | The signature of the driver. | 
| Tanium.Event.Signed | Boolean | If the value is true, The driver is signed. | 
| Tanium.Event.EventId | Number | The ID of the event. | 
| Tanium.Event.EventOpcode | Number | The event opcode. | 
| Tanium.Event.EventRecordID | Number | The ID of the event record. | 
| Tanium.Event.EventTaskID | Number | The ID of the event task. | 
| Tanium.Event.Query | String | The query of the DNS. | 
| Tanium.Event.Response | String | The response of the DNS. | 


##### Command Example
```!tanium-tr-list-events-by-connection connection-name=HOST_NAME event-type=Process limit=2```

##### Context Example
```
{
    "Tanium": {
        "Event": [
            {
                "Domain": "root",
                "EndTime": "2020-01-11 04:19:21.134",
                "ExitCode": 0,
                "ProcessCommandLine": "mkdir -p /opt/Tanium/TaniumClient/Tools/Detect3/tmp",
                "ProcessID": 15210,
                "ProcessName": "/usr/bin/mkdir",
                "ProcessTableID": 9938787,
                "SID": 5,
                "Type": "Process",
                "Username": "root"
            },
            {
                "Domain": "root",
                "EndTime": "2020-01-11 02:50:38.609",
                "ExitCode": 0,
                "ProcessCommandLine": "/sbin/auditctl -l",
                "ProcessHash": "BEA3A5351BBE28622A560FF5F18C805E",
                "ProcessID": 10583,
                "ProcessName": "/usr/sbin/auditctl",
                "ProcessTableID": 10045546,
                "SID": 5,
                "Type": "Process",
                "Username": "root"
            }
        ]
    }
}
```

##### Human Readable Output
### Events for HOST_NAME
|ID|Timestamp|Domain|ProcessTableID|ProcessCommandLine|ProcessID|ProcessName|ProcessHash|ExitCode|SID|Username|Hashes|Operation|File|DestinationAddress|DestinationPort|SourceAddress|SourcePort|KeyPath|ValueName|EndTime|ImageLoaded|Signature|Signed|EventId|EventOpcode|EventRecordID|EventTaskID|Query|Response|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|  |  | root | 9938787 | mkdir -p /opt/Tanium/TaniumClient/Tools/Detect3/tmp | 15210 | /usr/bin/mkdir |  | 0 | 5 | root |  |  |  |  |  |  |  |  |  | 2020-01-11 04:19:21.134 |  |  |  |  |  |  |  |  |  |
|  |  | root | 10045546 | /sbin/auditctl -l | 10583 | /usr/sbin/auditctl | BEA3A5351BBE28622A560FF5F18C805E | 0 | 5 | root |  |  |  |  |  |  |  |  |  | 2020-01-11 02:50:38.609 |  |  |  |  |  |  |  |  |  |

### tanium-tr-get-file-download-info
***
Get file download metadata. At least one of the arguments `path` or `id` must be set in order to run the command successfully.
##### Base Command

`tanium-tr-get-file-download-info`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The hostname of the dowloaded file. | Required | 
| path | The path of the file. | Optional | 
| id | File download ID. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.FileDownload.Size | Number | The size of the file, in bytes. | 
| Tanium.FileDownload.Path | String | The path of the file. | 
| Tanium.FileDownload.Downloaded | Date | The date this file was downloaded. | 
| Tanium.FileDownload.Host | String | The hostname of the dowloaded file. | 
| Tanium.FileDownload.Created | Date | The file creation timestamp. | 
| Tanium.FileDownload.Hash | String | The file hash. | 
| Tanium.FileDownload.SPath | String | The file SPath. | 
| Tanium.FileDownload.ID | Number | The downloaded file ID. | 
| Tanium.FileDownload.LastModified | Date | The date that the file was last modified. | 
| Tanium.FileDownload.CreatedBy | String | User that created this file. | 
| Tanium.FileDownload.CreatedByProc | String | The process path that created this file. | 
| Tanium.FileDownload.LastModifiedBy | String | The last user that modified this file. | 
| Tanium.FileDownload.LastModifiedByProc | String | The process path that modified this file. | 
| Tanium.FileDownload.Comments | String | The downloaded file comments. | 
| Tanium.FileDownload.Tags | String | The downloaded file tags. | 


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
            "Size": 2048
        }
    }
}
```

##### Human Readable Output
### File download metadata for file `C:\Windows\ServiceProfiles\LocalService\AppData\Local\lastalive1.dat`
|ID|Host|Path|Hash|Downloaded|Size|Created|CreatedBy|CreatedByProc|LastModified|LastModifiedBy|LastModifiedByProc|SPath|Comments|Tags|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 4 | HOST_NAME | C:\Windows\ServiceProfiles\LocalService\AppData\Local\lastalive1.dat | 2ae2da9237309b13b9a9d52d1358c826 | 2020-01-02 15:40:29.003 | 2048 | 2020-01-02 15:39:57.289 | NT AUTHORITY\LOCAL SERVICE | C:\Windows\System32\svchost.exe | 2020-01-02 15:39:57.289 | NT AUTHORITY\LOCAL SERVICE | C:\Windows\System32\svchost.exe | 6ae86937-611f-45e9-900c-3ba57298f264.zip |  |  |


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
|ProcessID|ProcessName|ProcessCommandLine|ProcessTableId|SID|Username|Domain|ExitCode|CreateTime|
|---|---|---|---|---|---|---|---|---|
| 4 | System | System | 667680 | S-1-5-18 | SYSTEM | NT AUTHORITY | 0 | 2020-01-22 16:16:07.553 |


### tanium-tr-get-events-by-process
***
Get events for a process.
##### Base Command

`tanium-tr-get-events-by-process`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The connection name. | Required | 
| ptid | The process instance ID. | Required | 
| limit | The maximin number of events to return. | Optional | 


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
Get children of this process instance.
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
                "Name": "0: <Unknown Process>",
                "PID": 0,
                "PTID": 667681,
                "Parent": "4: System"
            },
            {
                "ID": 667682,
                "Name": "1: <Pruned Process>",
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
|ID|Name|PID|PTID|Parent|Children|ChildrenCount|
|---|---|---|---|---|---|---|
| 667681 | 0: <Unknown Process> | 0 | 667681 | 4: System |  | 0 |
| 667682 | 1: <Pruned Process> | 1 | 667682 | 4: System |  | 0 |
| 667683 | 392: smss.exe | 392 | 667683 | 4: System |  | 0 |


### tanium-tr-get-parent-process
***
Get parent process information.
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
|ProcessID|ProcessName|ProcessCommandLine|ProcessTableId|SID|Username|Domain|ExitCode|CreateTime|
|---|---|---|---|---|---|---|---|---|
| 4 | System | System | 667680 | S-1-5-18 | SYSTEM | NT AUTHORITY | 0 | 2020-01-22 16:16:07.553 |


### tanium-tr-get-parent-process-tree
***
Get parent process tree for process instance.
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
                    "Name": "0: <Unknown Process>",
                    "PID": 0,
                    "PTID": 667681,
                    "Parent": "4: System"
                },
                {
                    "Children": [],
                    "ID": 667682,
                    "Name": "1: <Pruned Process>",
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
|ID|Name|PID|PTID|Parent|Children|ChildrenCount|
|---|---|---|---|---|---|---|
| 667680 | 4: System | 4 | 667680 |  |  |  |
### Processes with the same parent
|ID|Name|PID|PTID|Parent|Children|ChildrenCount|
|---|---|---|---|---|---|---|
| 667681 | 0: <Unknown Process> | 0 | 667681 | 4: System |  | 0 |
| 667682 | 1: <Pruned Process> | 1 | 667682 | 4: System |  | 0 |
| 667683 | 392: smss.exe | 392 | 667683 | 4: System |  | 0 |


### tanium-tr-get-process-tree
***
Get process tree for process instance.
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
                    "Name": "0: <Unknown Process>",
                    "PID": 0,
                    "PTID": 667681,
                    "Parent": "4: System"
                },
                {
                    "Children": [],
                    "ID": 667682,
                    "Name": "1: <Pruned Process>",
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
|ID|Name|PID|PTID|Parent|Children|ChildrenCount|
|---|---|---|---|---|---|---|
| 667680 | 4: System | 4 | 667680 |  |  |  |
### Children for process with PTID 667680
|ID|Name|PID|PTID|Parent|Children|ChildrenCount|
|---|---|---|---|---|---|---|
| 667681 | 0: <Unknown Process> | 0 | 667681 | 4: System |  | 0 |
| 667682 | 1: <Pruned Process> | 1 | 667682 | 4: System |  | 0 |
| 667683 | 392: smss.exe | 392 | 667683 | 4: System |  | 0 |


### tanium-tr-list-evidence
***
Returns a list of all available evidence in the system.
##### Base Command

`tanium-tr-list-evidence`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of evidences to return. | Optional | 
| offset | Offset into the evidence results | Optional | 
| sort | Comma-separated list of fields to sort by with +/- prefixes for ascending/descending, in order of priority left to right | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Evidence.ID | Number | The evidence ID. | 
| Tanium.Evidence.CreatedAt | Date | Time when the process was created. | 
| Tanium.Evidence.LastModified | Date | The date that the file was last modified. | 
| Tanium.Evidence.User | String | The user of the evidence. | 
| Tanium.Evidence.Host | String | The evidence host. | 
| Tanium.Evidence.ConnectionID | String | The evidence connection ID. | 
| Tanium.Evidence.Type | Number | The evidence type. | 
| Tanium.Evidence.ProcessTableId | Number | The evidence process table ID. | 
| Tanium.Evidence.Timestamp | Date | The evidence timestamp. | 
| Tanium.Evidence.Summary | String | The evidence summary. | 
| Tanium.Evidence.Comments | String | The evidence comments. | 
| Tanium.Evidence.Tags | String | The evidence tags. | 


##### Command Example
```!tanium-tr-list-evidence limit=2 offset=1 sort=+id```

##### Context Example
```
{
    "Tanium": {
        "Evidence": [
            {
                "ConnectionID": "HOST_NAME",
                "CreatedAt": "2020-01-02 15:40:03",
                "Host": "HOST_NAME",
                "ID": 2,
                "Summary": "CreateProcess: C:\\Windows\\SysWOW64\\cmd.exe",
                "Timestamp": "2020-01-02 15:39:28.809",
                "Type": 2,
                "UpdatedAt": "2020-01-02 15:40:03",
                "User": "actionapprover"
            },
            {
                "ConnectionID": "HOST_NAME",
                "CreatedAt": "2020-01-13 18:02:01",
                "Host": "HOST_NAME",
                "ID": 13,
                "Summary": "CreateProcess: C:\\Windows\\System32\\wsqmcons.exe",
                "Timestamp": "2020-01-13 18:00:01.010",
                "Type": 2,
                "UpdatedAt": "2020-01-13 18:02:01",
                "User": "HOST_NAME\\administrator"
            }
        ]
    }
}
```

##### Human Readable Output
### Evidences
|ID|Timestamp|Host|User|Summary|ConntectionID|Type|CreatedAt|UpdatedAt|ProcessTableId|Comments|Tags|
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2 | 2020-01-02 15:39:28.809 | HOST_NAME | actionapprover | CreateProcess: C:\Windows\SysWOW64\cmd.exe |  | 2 | 2020-01-02 15:40:03 | 2020-01-02 15:40:03 |  |  |  |
| 13 | 2020-01-13 18:00:01.010 | HOST_NAME | HOST_NAME\administrator | CreateProcess: C:\Windows\System32\wsqmcons.exe |  | 2 | 2020-01-13 18:02:01 | 2020-01-13 18:02:01 |  |  |  |


### tanium-tr-get-evidence-by-id
***
Retrive the evidence by it's ID.
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
| Tanium.Evidence.Host | String | The evidence host. | 
| Tanium.Evidence.ConnectionID | String | The evidence connection ID. | 
| Tanium.Evidence.Type | Number | The evidence type. | 
| Tanium.Evidence.ProcessTableId | Number | The evidence process table ID. | 
| Tanium.Evidence.Timestamp | Date | The evidence timestamp. | 
| Tanium.Evidence.Summary | String | The evidence summary. | 
| Tanium.Evidence.Comments | String | The evidence comments. | 
| Tanium.Evidence.Tags | String | The evidence tags. | 


##### Command Example
```!tanium-tr-get-evidence-by-id evidence-id=2```

##### Context Example
```
{
    "Tanium": {
        "Evidence": {
            "ConnectionID": "HOST_NAME",
            "CreatedAt": "2020-01-02 15:40:03",
            "Host": "HOST_NAME",
            "ID": 2,
            "Summary": "CreateProcess: C:\\Windows\\SysWOW64\\cmd.exe",
            "Timestamp": "2020-01-02 15:39:28.809",
            "Type": 2,
            "UpdatedAt": "2020-01-02 15:40:03",
            "User": "actionapprover"
        }
    }
}
```

##### Human Readable Output
### Label information
|ID|Timestamp|Host|User|Summary|ConntectionID|Type|CreatedAt|UpdatedAt|ProcessTableId|Comments|Tags|
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2 | 2020-01-02 15:39:28.809 | HOST_NAME | actionapprover | CreateProcess: C:\Windows\SysWOW64\cmd.exe |  | 2 | 2020-01-02 15:40:03 | 2020-01-02 15:40:03 |  |  |  |



### tanium-tr-create-evidence
***
Create an evidence.
##### Base Command

`tanium-tr-create-evidence`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-name | The name of the connection. | Required | 
| host | The host. | Required | 
| ptid | The process instance ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!tanium-tr-create-evidence connection-name=HOST_NAME host=HOST_NAME ptid=13538572```

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

There is no context output for this command.

##### Command Example
```!tanium-tr-delete-evidence evidence-id=1```

##### Human Readable Output
Evidence 1 has been deleted successfully.

### tanium-tr-request-file-download
***
Request a new file download
##### Base Command

`tanium-tr-request-file-download`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | Path to file. | Required | 
| connection-id | Connection ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.FileDownload.Path | String | File download path. | 
| Tanium.FileDownload.Host | String | File download host. | 
| Tanium.FileDownload.Downloaded | Date | Date of the download request. | 
| Tanium.FileDownload.Status | String | Status of the file download request. | 
| Tanium.FileDownload.ID | Number | ID of the file download. | 


##### Command Example
```!tanium-tr-request-file-download connection-id=HOST_NAME path=dev/autofs```

##### Context Example
```
{
    "Tanium": {
        "FileDownload": {
            "Downloaded": "2020-02-06 16:05:40.227674",
            "Host": "HOST_NAME",
            "Path": "dev/autofs"
        }
    }
}
```

##### Human Readable Output
Download request of file autofs has been sent successfully.

### tanium-tr-delete-file-download
***
Delete a file download.
##### Base Command

`tanium-tr-delete-file-download`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file-id | File download ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!tanium-tr-delete-file-download file-id=3```

##### Human Readable Output
Delete request of file with ID 3 has been sent successfully.

### tanium-tr-list-files-in-directory
***
List files in the given directory.
##### Base Command

`tanium-tr-list-files-in-directory`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | Path to directory. | Required | 
| connection-id | Connection ID. | Required | 
| limit | Max number of files to return. | Optional | 
| offset | Offset to start getting files. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.File.Created | Date | The file creation time. | 
| Tanium.File.Size | Number | The file size. | 
| Tanium.File.IsDirectory | Boolean | Whether or not the file is a directory. | 
| Tanium.File.LastModified | Date | The date that the file was last modified. | 
| Tanium.File.Path | Boolean | The file path. | 
| Tanium.File.Permissions | Date | The file permissions. | 


##### Command Example
```!tanium-tr-list-files-in-directory path=`C:\Program Files (x86)\Tanium\Tanium Client\` connection-id=HOST_NAME limit=2```

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
                "Size": 0
            },
            {
                "Created": "1970-01-18 21:02:12",
                "IsDirectory": true,
                "LastModified": "1970-01-19 07:10:05",
                "Path": "Downloads",
                "Permissions": "rw-rw-rw-",
                "Size": 393216
            }
        ]
    }
}
```

##### Human Readable Output
### Files in directory `C:\Program Files (x86)\Tanium\Tanium Client\`
|Path|Size|Created|LastModified|Permissions|IsDirectory|
|---|---|---|---|---|---|
| .detect-engine.lock | 0 | 1970-01-19 03:25:44 | 1970-01-19 03:25:44 | rw-rw-rw- | false |
| Downloads | 393216 | 1970-01-18 21:02:12 | 1970-01-19 07:10:05 | rw-rw-rw- | true |


### tanium-tr-get-file-info
***
Get information about file from a remote connection.
##### Base Command

`tanium-tr-get-file-info`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-id | The ID of the connection. | Required | 
| path | The path to the file. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.File.Created | Date | The file creation timestamp. | 
| Tanium.File.Size | Number | The file size. | 
| Tanium.File.IsDirectory | Boolean | Whether or not the file is a directory. | 
| Tanium.File.LastModified | Date | The date that the file was last modified. | 


##### Command Example
```!tanium-tr-get-file-info connection-id=HOST_NAME path=`C:\Program Files (x86)\Tanium\Tanium Client\TaniumClient.exe````

##### Context Example
```
{
    "Tanium": {
        "File": {
            "Created": "1970-01-18 20:01:58",
            "IsDirectory": false,
            "LastModified": "1970-01-18 20:01:58",
            "Size": 4938736
        }
    }
}
```

##### Human Readable Output
### Information for file `C:\Program Files (x86)\Tanium\Tanium Client\TaniumClient.exe`
|Path|Size|Created|LastModified|Permissions|IsDirectory|
|---|---|---|---|---|---|
|  | 4938736 | 1970-01-18 20:01:58 | 1970-01-18 20:01:58 |  | false |


### tanium-tr-delete-file-from-endpoint
***
Delete file from endpoint
##### Base Command

`tanium-tr-delete-file-from-endpoint`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-id | Connection ID. | Required | 
| path | Path to file. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!tanium-tr-delete-file-from-endpoint path=`C:\Program Files (x86)\Tanium\Tanium Client\Logs\log0.txt` connection-id=HOST_NAME```

##### Human Readable Output
Delete request of file C:\Program Files (x86)\Tanium\Tanium Client\Logs\log0.txt from endpoint HOST_NAME has been sent successfully.

### tanium-tr-get-process-timeline
***
Get process timeline.
##### Base Command

`tanium-tr-get-process-timeline`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection-id | Connection ID. | Required | 
| ptid | Process table ID. | Required | 
| category | Select category of events to retrieve. | Required | 
| limit | Max number of events to return. | Optional | 
| offset | Offset to start getting events. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ProcessTimeline.ProcessTableID | Number | The process instance ID. | 
| Tanium.ProcessTimeline.ConnectionID | String | The connection ID of the process. | 
| Tanium.ProcessTimeline.Date | Date | Events date of the process. | 
| Tanium.ProcessTimeline.Event | String | Event of the process | 
| Tanium.ProcessTimeline.Category | String | The event category of the process | 


##### Command Example
```!tanium-tr-get-process-timeline ptid=13530396 connection-id=HOST_NAME category=Process limit=2```

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
Get the status of the download file request.
##### Base Command

`tanium-tr-get-download-file-request-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request-date | Date of the download file request, For example: 2019-09-23T12:55:08.622 | Required | 
| host | The host to which the request was made. | Optional | 
| path | The file path. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.DownloadFile.ID | Number | ID of the file download. | 
| Tanium.DownloadFile.Host | String | Host of the file. | 
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
            "Status": "Completed"
        }
    }
}
```

##### Human Readable Output
### File download request status
|ID|Host|Status|Path|Downloaded|
|---|---|---|---|---|
| 3 |  | Completed |  | 2020-01-02 15:40:18.052 |


## Additional Information

## Known Limitations
