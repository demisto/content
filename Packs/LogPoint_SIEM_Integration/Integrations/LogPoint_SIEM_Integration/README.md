Use this Content Pack to fetch incident logs from LogPoint, analyze them for underlying threats, and respond to these threats in real-time.

## Use Cases

* Retrieve incidents using available filters.
* Get data of particular incidents, their state, user, and user groups.
* Resolve, Close, Re-open, Re-assign, and add comments to the incidents.
* Act accordingly to the incidents using LogPoint provided and/or custom playbooks.

## Configure LogPoint on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for LogPoint SIEM Integration.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | LogPoint URL | True |
    | username | LogPoint Username | True |
    | apikey | API Key | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | first_fetch | First fetch timestamp \(\<number\> \<time unit\>, e.g., 6 hours, 1 day\) | False |
    | incidentType | Incident type | False |
    | isFetch | Fetch incidents | False |
    | max_fetch | Fetch limit (Max value is 200, Recommended value is 50 or less) | False

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### lp-get-incidents
***
Gets first 50 incidents between the provided two Timestamps. If ts_from and ts_to is not provided, this command will display incident data of past 24 hours.


#### Base Command

`lp-get-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ts_from | From Timestamp. | Optional | 
| ts_to | To Timestamp. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogPoint.Incidents.name | String | LogPoint Incident Name | 
| LogPoint.Incidents.type | String | LogPoint Incident Type | 
| LogPoint.Incidents.incident_id | String | LogPoint Incident ID | 
| LogPoint.Incidents.assigned_to | String | LogPoint Incidents Assigned To | 
| LogPoint.Incidents.status | String | LogPoint Incidents Status | 
| LogPoint.Incidents.id | String | LogPoint Incident Object ID | 
| LogPoint.Incidents.detection_timestamp | Number | LogPoint Incidents Detection Timestamp | 
| LogPoint.Incidents.username | String | LogPoint Incident Username | 
| LogPoint.Incidents.user_id | String | LogPoint Incidents User ID | 
| LogPoint.Incidents.assigned_to | String | LogPoint Incidents Assigned To | 
| LogPoint.Incidents.visible_to | String | LogPoint Incidents Visible To | 
| LogPoint.Incidents.tid | String | LogPoint Incidents Tid | 
| LogPoint.Incidents.rows_count | String | LogPoint Incidents Rows Count | 
| LogPoint.Incidents.risk_level | String | LogPoint Incidents Risk Level | 
| LogPoint.Incidents.detection_timestamp | String | LogPoint Incidents Detection Timestamp | 
| LogPoint.Incidents.loginspect_ip_dns | String | LogPoint Incidents Loginspect IP DNS | 
| LogPoint.Incidents.status | String | LogPoint Incidents Status | 
| LogPoint.Incidents.comments | String | LogPoint Incidents Comments | 
| LogPoint.Incidents.commentscount | Number | LogPoint Incidents Comments Count | 
| LogPoint.Incidents.query | String | LogPoint Incidents Query | 
| LogPoint.Incidents.repos | String | LogPoint Incidents Repos | 
| LogPoint.Incidents.time_range | String | LogPoint Incidents Time Range | 
| LogPoint.Incidents.alert_obj_id | String | LogPoint Incidents Alert Obj Id | 
| LogPoint.Incidents.throttle_enabled | Boolean | LogPoint Incidents Throttle Enabled | 
| LogPoint.Incidents.lastaction | String | LogPoint Incidents Last Action | 
| LogPoint.Incidents.description | String | LogPoint Incidents Description | 


#### Command Example
```!lp-get-incidents ts_from=1608284280 ts_to=1608284400```

#### Context Example
```json
{
    "LogPoint": {
        "Incidents": [
            {
                "alert_obj_id": "5fc8b1743dee69827459bc70",
                "assigned_to": "5fd9d95769d3a4ea5684fccf",
                "comments": [
                    {
                        "comment": "Example comment",
                        "time": 1608284475,
                        "title": "admin"
                    }
                ],
                "commentscount": 0,
                "description": "",
                "detection_timestamp": 1608284302.3569734,
                "id": "5fdc788ecf35d7ae0f6b791b",
                "incident_id": "cff43115719e19cd04ddf5a7e61d982d",
                "lastaction": {
                    "comment": "Reassigned",
                    "time": 1608286422,
                    "title": "admin"
                },
                "loginspect_ip_dns": "127.0.0.1",
                "logpoint_name": "LogPoint",
                "name": "Test Incident",
                "query": "\"col_type\"=\"filesystem\" use>60",
                "repos": [
                    "127.0.0.1:5504"
                ],
                "risk_level": "medium",
                "rows_count": 5,
                "status": "unresolved",
                "throttle_enabled": false,
                "tid": "",
                "time_range": [
                    1608283560,
                    1608284160
                ],
                "type": "Alert",
                "user_id": null,
                "username": "5bebd9fdd8aaa42840edc853",
                "visible_to": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Incidents
>|type|incident_id|name|description|username|user_id|assigned_to|visible_to|tid|rows_count|risk_level|detection_timestamp|loginspect_ip_dns|logpoint_name|status|comments|commentscount|query|repos|time_range|alert_obj_id|throttle_enabled|lastaction|id|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Alert | cff43115719e19cd04ddf5a7e61d982d | Test Incident |  | 5bebd9fdd8aaa42840edc853 |  | 5fd9d95769d3a4ea5684fccf |  |  | 5 | medium | 1608284302.3569734 | 127.0.0.1 | LogPoint | unresolved | {'title': 'admin', 'comment': 'Example comment', 'time': 1608284475} | 0 | "col_type"="filesystem" use>60 | 127.0.0.1:5504 | 1608283560,<br/>1608284160 | 5fc8b1743dee69827459bc70 | false | title: admin<br/>comment: Reassigned<br/>time: 1608286422 | 5fdc788ecf35d7ae0f6b791b |


### lp-get-incident-data
***
Retrieves a Particular Incident's Data


#### Base Command

`lp-get-incident-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_obj_id | Object ID of a particular incident. It is the value contained in 'id' key of the incidents obtained from 'lp-get-incidents' command. | Required | 
| incident_id | Incident Id of a particular incident. It is the value contained in 'incident_id' key of the incidents obtained from 'lp-get-incidents' command. | Required | 
| date | Incident Detection TImestamp. It is the value contained in 'detection_timestamp' key of the incidents obtained from 'lp-get-incidents' command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogPoint.Incidents.data.use | String | LogPoint Incidents Data Use | 
| LogPoint.Incidents.data.used | String | LogPoint Incidents Data Used | 
| LogPoint.Incidents.data.log_ts | Number | LogPoint Incidents Data Log Ts | 
| LogPoint.Incidents.data._type_str | String | LogPoint Incidents Data Type Str | 
| LogPoint.Incidents.data.msg | String | LogPoint Incidents Data Msg | 
| LogPoint.Incidents.data.total | String | LogPoint Incidents Data Total | 
| LogPoint.Incidents.data.device_name | String | LogPoint Incidents Data Device Name | 
| LogPoint.Incidents.data._offset | String | LogPoint Incidents Data Offset | 
| LogPoint.Incidents.data.logpoint_name | String | LogPoint Incidents Data LogPoint Name | 
| LogPoint.Incidents.data.repo_name | String | LogPoint Incidents Data Repo Name | 
| LogPoint.Incidents.data.free | String | LogPoint Incidents Data Free | 
| LogPoint.Incidents.data.source_name | String | LogPoint Incidents Data Source Name | 
| LogPoint.Incidents.data.col_ts | Number | LogPoint Incidents Data Col Ts | 
| LogPoint.Incidents.data._tz | String | LogPoint Incidents Data Tz | 
| LogPoint.Incidents.data.norm_id | String | LogPoint Incidents Data Norm Id | 
| LogPoint.Incidents.data._identifier | String | LogPoint Incidents Data Identifier | 
| LogPoint.Incidents.data.collected_at | String | LogPoint Incidents Data Collected At | 
| LogPoint.Incidents.data.device_ip | String | LogPoint Incidents Data Device IP | 
| LogPoint.Incidents.data._fromV550 | String | LogPoint Incidents Data From V550 | 
| LogPoint.Incidents.data._enrich_policy | String | LogPoint Incidents Data Enrich Policy | 
| LogPoint.Incidents.data._type_num | String | LogPoint Incidents Data Type Num | 
| LogPoint.Incidents.data._type_ip | String | LogPoint Incidents Data Type IP | 
| LogPoint.Incidents.data.sig_id | String | LogPoint Incidents Data Sig Id | 
| LogPoint.Incidents.data.col_type | String | LogPoint Incidents Data Col Type | 
| LogPoint.Incidents.data.object | String | LogPoint Incidents Data Object | 
| LogPoint.Incidents.data._labels | String | LogPoint Incidents Data Labels | 


#### Command Example
```!lp-get-incident-data date=1608284302.3569734 incident_id=cff43115719e19cd04ddf5a7e61d982d incident_obj_id=5fdc788ecf35d7ae0f6b791b```

#### Context Example
```json
{
    "LogPoint": {
        "Incidents": {
            "data": [
                {
                    "_enrich_policy": "None",
                    "_fromV550": "t",
                    "_identifier": "0",
                    "_labels": [
                        "Metrics",
                        "Usage",
                        "Memory",
                        "LogPoint"
                    ],
                    "_offset": 6112,
                    "_type_ip": "device_ip",
                    "_type_num": "log_ts col_ts free total use used sig_id _offset _identifier",
                    "_type_str": "msg col_type device_name collected_at device_ip source_name _tz _enrich_policy label norm_id object _fromV550 repo_name logpoint_name",
                    "_tz": "UTC",
                    "col_ts": 1608284135,
                    "col_type": "filesystem",
                    "collected_at": "LogPoint",
                    "device_ip": "127.0.0.1",
                    "device_name": "localhost",
                    "free": "1749",
                    "log_ts": 1608284133,
                    "logpoint_name": "LogPoint",
                    "msg": "2020-12-18_09:35:33 Metrics; Physical Memory; total=7977 MB; use=73.8%; used=5889 MB; free=1749 MB",
                    "norm_id": "LogPoint",
                    "object": "Physical Memory",
                    "repo_name": "_logpoint",
                    "sig_id": "10507",
                    "source_name": "/opt/immune/var/log/system_metrics/system_metrics.log",
                    "total": "7977",
                    "use": "73.8",
                    "used": "5889"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Incident Data
>|msg|use|used|log_ts|_type_str|total|device_name|_offset|logpoint_name|repo_name|free|source_name|col_ts|_tz|norm_id|_identifier|collected_at|device_ip|_fromV550|_enrich_policy|_type_num|_type_ip|sig_id|col_type|object|_labels|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-12-18_09:35:33 Metrics; Physical Memory; total=7977 MB; use=73.8%; used=5889 MB; free=1749 MB | 73.8 | 5889 | 1608284133 | msg col_type device_name collected_at device_ip source_name _tz _enrich_policy label norm_id object _fromV550 repo_name logpoint_name | 7977 | localhost | 6112 | LogPoint | _logpoint | 1749 | /opt/immune/var/log/system_metrics/system_metrics.log | 1608284135 | UTC | LogPoint | 0 | LogPoint | 127.0.0.1 | t | None | log_ts col_ts free total use used sig_id _offset _identifier | device_ip | 10507 | filesystem | Physical Memory | Metrics,<br/>Usage,<br/>Memory,<br/>LogPoint |


### lp-get-incident-states
***
Gets the first 50 Incident States. Arguments are optional. If ts_from and ts_to arguments are not provided, it will get incidents of the past 24 hours.


#### Base Command

`lp-get-incident-states`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ts_from | From Timestamp. | Optional | 
| ts_to | To Timestamp. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogPoint.Incidents.states.id | String | LogPoint Incidents States Id | 
| LogPoint.Incidents.states.status | String | LogPoint Incidents States Status | 
| LogPoint.Incidents.states.assigned_to | String | LogPoint Incidents States Assigned To | 
| LogPoint.Incidents.states.comments | String | LogPoint Incidents States Comments | 


#### Command Example
```!lp-get-incident-states ts_from="1608281509" ts_to="1608281523"```

#### Context Example
```json
{
    "LogPoint": {
        "Incidents": {
            "states": [
            {
              "id": "5a62bd8cce983de89085429b", 
              "status": "resolved",
              "assigned_to": "59b0eecfd8aaa4334ee41707",
              "title": "sample title 1",
              "time": 1516420000,
              "comment": "sample comment 1"
            }
          ]
        }
    }
}
```

#### Human Readable Output

>### Incident States

>|id|status|assigned_to|title|time|comment|
>|---|---|---|---|---|---|
>| 5a62bd8cce983de89085429b | resolved | 59b0eecfd8aaa4334ee41707 | sample title 1 | 1516420000 | sample comment 1 |


### lp-add-incident-comment
***
Add comments to the incidents


#### Base Command

`lp-add-incident-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_obj_id | Object ID of a particular incident. It is the value contained in 'id' key of the incidents obtained from 'lp-get-incidents' command. | Required | 
| comment | Comment to be added to the incidents. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogPoint.Incidents.comment | String | LogPoint Incidents Comment | 


#### Command Example
```!lp-add-incident-comment comment="Example comment" incident_obj_id=5fdc788ecf35d7ae0f6b791b```

#### Context Example
```json
{
    "LogPoint": {
        "Incidents": {
            "comment": "Comments added"
        }
    }
}
```

#### Human Readable Output

>### Comments added

### lp-assign-incidents
***
Assigning/Re-assigning Incidents


#### Base Command

`lp-assign-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_obj_ids | Object ID of a particular incident. It is the value contained in 'id' key of the incidents obtained from 'lp-get-incidents' command. Multiple id can be provided by separating them using comma. | Required | 
| new_assignee | Id of the user whom the incidents are assigned.  It can be displayed using 'lp-get-users' command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogPoint.Incidents.assign | String | LogPoint Incidents Assign | 


#### Command Example
```!lp-assign-incidents incident_obj_ids="5fdc788ecf35d7ae0f6b791b,5fdc788ecf35d7ae0f6b791c" new_assignee=5fd9d95769d3a4ea5684fccf```

#### Context Example
```json
{
    "LogPoint": {
        "Incidents": {
            "assign": "Incidents re-assigned"
        }
    }
}
```

#### Human Readable Output

>### Incidents re-assigned

### lp-resolve-incidents
***
Resolves the Incidents.


#### Base Command

`lp-resolve-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_obj_ids | Object ID of a particular incident. It is the value contained in 'id' key of the incidents obtained from 'lp-get-incidents' command. Multiple id can be provided by separating them using comma. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogPoint.Incidents.resolve | String | LogPoint Incidents Resolve | 


#### Command Example
```!lp-resolve-incidents incident_obj_ids="5fdc788ecf35d7ae0f6b791c,5fdc788ecf35d7ae0f6b791d"```

#### Context Example
```json
{
    "LogPoint": {
        "Incidents": {
            "resolve": "Incidents resolved"
        }
    }
}
```

#### Human Readable Output

>### Incidents resolved

### lp-close-incidents
***
Closes the Incidents.


#### Base Command

`lp-close-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_obj_ids | Object ID of a particular incident. It is the value contained in 'id' key of the incidents obtained from 'lp-get-incidents' command. Multiple id can be provided by separating them using comma. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogPoint.Incidents.close | String | LogPoint Incidents Close | 


#### Command Example
```!lp-close-incidents incident_obj_ids="5fdc788ecf35d7ae0f6b791c,5fdc788ecf35d7ae0f6b791d"```

#### Context Example
```json
{
    "LogPoint": {
        "Incidents": {
            "close": "Incidents closed"
        }
    }
}
```

#### Human Readable Output

>### Incidents closed

### lp-reopen-incidents
***
Re-opens the closed incidents


#### Base Command

`lp-reopen-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_obj_ids | Object ID of a particular incident. It is the value contained in 'id' key of the incidents obtained from 'lp-get-incidents' command. Multiple id can be provided by separating them using comma. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogPoint.Incidents.reopen | String | LogPoint Incidents Reopen | 


#### Command Example
```!lp-reopen-incidents incident_obj_ids="5fdc788ecf35d7ae0f6b791c,5fdc788ecf35d7ae0f6b791d"```

#### Context Example
```json
{
    "LogPoint": {
        "Incidents": {
            "reopen": "Incidents reopened"
        }
    }
}
```

#### Human Readable Output

>### Incidents reopened

### lp-get-users
***
Gets Incident users and user groups.


#### Base Command

`lp-get-users`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogPoint.Incidents.users.id | String | LogPoint Incidents Users Id | 
| LogPoint.Incidents.users.name | String | LogPoint Incidents Users Name | 
| LogPoint.Incidents.users.usergroups | String | LogPoint Incidents Users Usergroups | 


#### Command Example
```!lp-get-users```

#### Context Example
```json
{
    "LogPoint": {
        "Incidents": {
            "users": [
                {
                    "id": "5bebd9fdd8aaa42840edc853",
                    "name": "admin",
                    "usergroups": [
                        {
                            "id": "5bebd9fdd8aaa42840edc84f",
                            "name": "LogPoint Administrator"
                        }
                    ]
                },
                {
                    "id": "5fd9d95769d3a4ea5684fccf",
                    "name": "sbs",
                    "usergroups": [
                        {
                            "id": "5bebd9fdd8aaa42840edc850",
                            "name": "User Account Administrator"
                        },
                        {
                            "id": "5bebd9fdd8aaa42840edc84f",
                            "name": "LogPoint Administrator"
                        }
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Incident Users
>|id|name|usergroups|
>|---|---|---|
>| 5bebd9fdd8aaa42840edc853 | admin | {'id': '5bebd9fdd8aaa42840edc84f', 'name': 'LogPoint Administrator'} |
>| 5fd9d95769d3a4ea5684fccf | sbs | {'id': '5bebd9fdd8aaa42840edc850', 'name': 'User Account Administrator'},<br/>{'id': '5bebd9fdd8aaa42840edc84f', 'name': 'LogPoint Administrator'} |

