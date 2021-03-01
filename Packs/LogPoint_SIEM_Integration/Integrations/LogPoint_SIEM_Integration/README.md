Use this Content Pack to fetch incident logs from LogPoint, analyze them for underlying threats, and respond to these threats in real-time.
This integration was integrated and tested with version 6.7.4 of LogPoint.

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
    | first_fetch | First fetch timestamp  (\<number\> \<time unit\>, e.g., 6 hours, 1 day) | False |
    | incidentType | Incident type | False |
    | isFetch | Fetch incidents | False |
    | max_fetch | Fetch limit \(Max value is 200, Recommended value is 50 or less\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### lp-get-incidents
***
Displays incidents between the provided two Timestamps ts_from and ts_to. By default, this command will display first 50 incidents of the past 24 hours but limit can be set to get desired number of incidents.


#### Base Command

`lp-get-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ts_from | From Timestamp. | Optional | 
| ts_to | To Timestamp. | Optional | 
| limit | Number of incidents to fetch. Accepts integer value. | Optional | 


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
```!lp-get-incidents ts_from=1610700720 ts_to=1610700900 limit=5```

#### Context Example
```json
{
    "LogPoint": {
        "Incidents": [
            {
                "alert_obj_id": "5fc8b1743dee69827459bc70",
                "assigned_to": "5bebd9fdd8aaa42840edc853",
                "comments": [],
                "commentscount": 0,
                "description": "",
                "detection_timestamp": 1610700740.2248185,
                "id": "600157c44a2018070b627f6a",
                "incident_id": "8a676c39450e099b3512961d71ec4f7d",
                "loginspect_ip_dns": "127.0.0.1",
                "logpoint_name": "LogPoint",
                "name": "Memory usages is greater than 50 percent",
                "query": "\"col_type\"=\"filesystem\" use>=50",
                "repos": [
                    "127.0.0.1:5504"
                ],
                "risk_level": "medium",
                "rows_count": 5,
                "status": "unresolved",
                "throttle_enabled": false,
                "tid": "",
                "time_range": [
                    1610700000,
                    1610700600
                ],
                "type": "Alert",
                "user_id": null,
                "username": "5bebd9fdd8aaa42840edc853",
                "visible_to": []
            },
            {
                "alert_obj_id": "5fc8b1743dee69827459bc70",
                "assigned_to": "5bebd9fdd8aaa42840edc853",
                "comments": [
                    {
                        "comment": "Example Incident",
                        "time": 1610700910,
                        "title": "admin"
                    }
                ],
                "commentscount": 0,
                "description": "",
                "detection_timestamp": 1610700860.245085,
                "id": "6001583c4a2018070b627f6b",
                "incident_id": "8a676c39450e099b3512961d71ec4f7d",
                "lastaction": {
                    "action": "Commented",
                    "time": 1610700910,
                    "title": "admin"
                },
                "loginspect_ip_dns": "127.0.0.1",
                "logpoint_name": "LogPoint",
                "name": "Memory usages is greater than 50 percent",
                "query": "\"col_type\"=\"filesystem\" use>=50",
                "repos": [
                    "127.0.0.1:5504"
                ],
                "risk_level": "medium",
                "rows_count": 5,
                "status": "unresolved",
                "throttle_enabled": false,
                "tid": "",
                "time_range": [
                    1610700120,
                    1610700720
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

>### Displaying all 2 incidents between 1610700720 and 1610700900
>|type|incident_id|name|description|username|user_id|assigned_to|visible_to|tid|rows_count|risk_level|detection_timestamp|loginspect_ip_dns|logpoint_name|status|comments|commentscount|query|repos|time_range|alert_obj_id|throttle_enabled|id|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Alert | 8a676c39450e099b3512961d71ec4f7d | Memory usages is greater than 50 percent |  | 5bebd9fdd8aaa42840edc853 |  | 5bebd9fdd8aaa42840edc853 |  |  | 5 | medium | 1610700740.2248185 | 127.0.0.1 | LogPoint | unresolved |  | 0 | "col_type"="filesystem" use>=50 | 127.0.0.1:5504 | 1610700000,<br/>1610700600 | 5fc8b1743dee69827459bc70 | false | 600157c44a2018070b627f6a |
>| Alert | 8a676c39450e099b3512961d71ec4f7d | Memory usages is greater than 50 percent |  | 5bebd9fdd8aaa42840edc853 |  | 5bebd9fdd8aaa42840edc853 |  |  | 5 | medium | 1610700860.245085 | 127.0.0.1 | LogPoint | unresolved | {'title': 'admin', 'comment': 'Example Incident', 'time': 1610700910} | 0 | "col_type"="filesystem" use>=50 | 127.0.0.1:5504 | 1610700120,<br/>1610700720 | 5fc8b1743dee69827459bc70 | false | 6001583c4a2018070b627f6b |


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
| LogPoint.Incidents.data.source_address | String | Source Address | 
| LogPoint.Incidents.data.destination_address | String | Destination Address | 
| LogPoint.Incidents.data.workstation | String | Workstation | 
| LogPoint.Incidents.data.domain | String | Domain | 
| LogPoint.Incidents.data.user | String | User | 
| LogPoint.Incidents.data.caller_user | String | Caller User | 
| LogPoint.Incidents.data.target_user | String | Target User | 
| LogPoint.Incidents.data.source_machine_id | String | Source Machie Id | 
| LogPoint.Incidents.data.destination_machine_id | String | Destination Machine Id | 
| LogPoint.Incidents.data.destination_port | String | Destination Port | 
| LogPoint.Incidents.data.event_type | String | Event Type | 
| LogPoint.Incidents.data.share_path | String | Share Path | 
| LogPoint.Incidents.data.object_name | String | Object Name | 
| LogPoint.Incidents.data.sub_status_code | String | Sub Status Code | 
| LogPoint.Incidents.data.object_type | String | Object Type | 
| LogPoint.Incidents.data.request_method | String | Request Method | 
| LogPoint.Incidents.data.status_code | String | Status Code | 
| LogPoint.Incidents.data.received_datasize | String | Received Datasize | 
| LogPoint.Incidents.data.received_packet | String | Received Packet | 
| LogPoint.Incidents.data.user_agent | String | User Agent | 
| LogPoint.Incidents.data.sent_datasize | String | Sent Datasize | 
| LogPoint.Incidents.data.sender | String | Sender | 
| LogPoint.Incidents.data.receiver | String | Receiver | 
| LogPoint.Incidents.data.datasize | String | Datasize | 
| LogPoint.Incidents.data.file | String | File | 
| LogPoint.Incidents.data.subject | String | Subject | 
| LogPoint.Incidents.data.status | String | Status | 
| LogPoint.Incidents.data.file_count | String | File Count | 
| LogPoint.Incidents.data.protocol_id | String | Protocol Id | 
| LogPoint.Incidents.data.sent_packet | String | Sent Packet | 
| LogPoint.Incidents.data.service | String | Service | 
| LogPoint.Incidents.data.printer | String | Printer | 
| LogPoint.Incidents.data.print_count | String | Print Count | 
| LogPoint.Incidents.data.event_id | String | Event Id | 
| LogPoint.Incidents.data.country_name | String | Country Name | 
| LogPoint.Incidents.data.host | String | Host | 
| LogPoint.Incidents.data.hash | String | Hash | 
| LogPoint.Incidents.data.hash_sha1 | String | Hash SHA1 | 
| LogPoint.Incidents.data.agent_address | String | Agent Address | 
| LogPoint.Incidents.data.attacker_address | String | Attacker Address | 
| LogPoint.Incidents.data.broadcast_address | String | Broadcast Address | 
| LogPoint.Incidents.data.client_address | String | Client Address | 
| LogPoint.Incidents.data.client_hardware_address | String | Client Hardware Address | 
| LogPoint.Incidents.data.destination_hardware_address | String | Destination Hardware Address | 
| LogPoint.Incidents.data.destination_nat_address | String | Destination NAT Address | 
| LogPoint.Incidents.data.device_address | String | Device Address | 
| LogPoint.Incidents.data.external_address | String | External Address | 
| LogPoint.Incidents.data.gateway_address | String | Gateway Address | 
| LogPoint.Incidents.data.hardware_address | String | Hardware Address | 
| LogPoint.Incidents.data.host_address | String | Host Address | 
| LogPoint.Incidents.data.interface_address | String | Interface Address | 
| LogPoint.Incidents.data.lease_address | String | Lease Address | 
| LogPoint.Incidents.data.local_address | String | Local Address | 
| LogPoint.Incidents.data.nas_address | String | Nas ddress | 
| LogPoint.Incidents.data.nas_ipv6_address | String | Nas_IPV6 Address | 
| LogPoint.Incidents.data.nat_address | String | NAT Address | 
| LogPoint.Incidents.data.nat_source_address | String | NAT Source Address | 
| LogPoint.Incidents.data.network_address | String | Network Address | 
| LogPoint.Incidents.data.new_hardware_address | String | New Hardware Address | 
| LogPoint.Incidents.data.old_hardware_address | String | Old Hardware Address | 
| LogPoint.Incidents.data.original_address | String | Original Address | 
| LogPoint.Incidents.data.original_client_address | String | Original Client Address | 
| LogPoint.Incidents.data.original_destination_address | String | Original Destination Address | 
| LogPoint.Incidents.data.original_server_address | String | Original Server Address | 
| LogPoint.Incidents.data.original_source_address | String | Original Source Address | 
| LogPoint.Incidents.data.originating_address | String | Originating Address | 
| LogPoint.Incidents.data.peer_address | String | Peer Address | 
| LogPoint.Incidents.data.private_address | String | Private Address | 
| LogPoint.Incidents.data.proxy_address | String | Proxy Address | 
| LogPoint.Incidents.data.proxy_source_address | String | Proxy Source Address | 
| LogPoint.Incidents.data.relay_address | String | Relay Address | 
| LogPoint.Incidents.data.remote_address | String | Remote Address | 
| LogPoint.Incidents.data.resolved_address | String | Resolved Address | 
| LogPoint.Incidents.data.route_address | String | Route Address | 
| LogPoint.Incidents.data.scanner_address | String | Scanner Address | 
| LogPoint.Incidents.data.server_address | String | Server Address | 
| LogPoint.Incidents.data.server_hardware_address | String | Server Hardware Address | 
| LogPoint.Incidents.data.source_hardware_address | String | Source Hardware Address | 
| LogPoint.Incidents.data.start_address | String | Start Address | 
| LogPoint.Incidents.data.supplier_address | String | Supplier Address | 
| LogPoint.Incidents.data.switch_address | String | Switch Address | 
| LogPoint.Incidents.data.translated_address | String | Translated Address | 
| LogPoint.Incidents.data.virtual_address | String | Virtual Address | 
| LogPoint.Incidents.data.virtual_server_address | String | Virtual Server Address | 
| LogPoint.Incidents.data.vpn_address | String | VPN Address | 
| LogPoint.Incidents.data.hash_length | String | Hash Length | 
| LogPoint.Incidents.data.hash_sha256 | String | Hash SHA256 | 
| LogPoint.Incidents.data.alternate_user | String | Alternate User | 
| LogPoint.Incidents.data.authenticated_user | String | Authenticated User | 
| LogPoint.Incidents.data.authorized_user | String | Authorized User | 
| LogPoint.Incidents.data.certificate_user | String | Certificate User | 
| LogPoint.Incidents.data.current_user | String | Current User | 
| LogPoint.Incidents.data.database_user | String | Database User | 
| LogPoint.Incidents.data.destination_user | String | Destination User | 
| LogPoint.Incidents.data.logon_user | String | Logon User | 
| LogPoint.Incidents.data.new_max_user | String | New Max User | 
| LogPoint.Incidents.data.new_user | String | New User | 
| LogPoint.Incidents.data.old_max_user | String | Old Max User | 
| LogPoint.Incidents.data.os_user | String | OS User | 
| LogPoint.Incidents.data.remote_user | String | Remote User | 
| LogPoint.Incidents.data.source_user | String | Source User | 
| LogPoint.Incidents.data.system_user | String | System User | 
| LogPoint.Incidents.data.target_logon_user | String | Target Logon User | 
| LogPoint.Incidents.data.zone_user | String | Zone User | 


#### Command Example
```!lp-get-incident-data date=1610700740.2248185 incident_id=8a676c39450e099b3512961d71ec4f7d incident_obj_id=600157c44a2018070b627f6a```

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
                    "_offset": 195673,
                    "_type_ip": "device_ip",
                    "_type_num": "log_ts col_ts free total use used sig_id _offset _identifier",
                    "_type_str": "msg col_type device_name collected_at device_ip source_name _tz _enrich_policy label norm_id object _fromV550 repo_name logpoint_name",
                    "_tz": "UTC",
                    "col_ts": 1610700549,
                    "col_type": "filesystem",
                    "collected_at": "LogPoint",
                    "device_ip": "127.0.0.1",
                    "device_name": "localhost",
                    "free": "1963",
                    "log_ts": 1610700541,
                    "logpoint_name": "LogPoint",
                    "msg": "2021-01-15_08:49:01 Metrics; Physical Memory; total=7977 MB; use=71.0%; used=5664 MB; free=1963 MB",
                    "norm_id": "LogPoint",
                    "object": "Physical Memory",
                    "repo_name": "_logpoint",
                    "sig_id": "10507",
                    "source_name": "/opt/immune/var/log/system_metrics/system_metrics.log",
                    "total": "7977",
                    "use": "71.0",
                    "used": "5664"
                },
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
                    "_offset": 101372,
                    "_type_ip": "device_ip",
                    "_type_num": "log_ts col_ts free total use used sig_id _offset _identifier",
                    "_type_str": "msg col_type device_name collected_at device_ip source_name _tz _enrich_policy label norm_id object _fromV550 repo_name logpoint_name",
                    "_tz": "UTC",
                    "col_ts": 1610700428,
                    "col_type": "filesystem",
                    "collected_at": "LogPoint",
                    "device_ip": "127.0.0.1",
                    "device_name": "localhost",
                    "free": "1965",
                    "log_ts": 1610700421,
                    "logpoint_name": "LogPoint",
                    "msg": "2021-01-15_08:47:01 Metrics; Physical Memory; total=7977 MB; use=71.0%; used=5662 MB; free=1965 MB",
                    "norm_id": "LogPoint",
                    "object": "Physical Memory",
                    "repo_name": "_logpoint",
                    "sig_id": "10507",
                    "source_name": "/opt/immune/var/log/system_metrics/system_metrics.log",
                    "total": "7977",
                    "use": "71.0",
                    "used": "5662"
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
>| 2021-01-15_08:49:01 Metrics; Physical Memory; total=7977 MB; use=71.0%; used=5664 MB; free=1963 MB | 71.0 | 5664 | 1610700541 | msg col_type device_name collected_at device_ip source_name _tz _enrich_policy label norm_id object _fromV550 repo_name logpoint_name | 7977 | localhost | 195673 | LogPoint | _logpoint | 1963 | /opt/immune/var/log/system_metrics/system_metrics.log | 1610700549 | UTC | LogPoint | 0 | LogPoint | 127.0.0.1 | t | None | log_ts col_ts free total use used sig_id _offset _identifier | device_ip | 10507 | filesystem | Physical Memory | Metrics,<br/>Usage,<br/>Memory,<br/>LogPoint |
>| 2021-01-15_08:47:01 Metrics; Physical Memory; total=7977 MB; use=71.0%; used=5662 MB; free=1965 MB | 71.0 | 5662 | 1610700421 | msg col_type device_name collected_at device_ip source_name _tz _enrich_policy label norm_id object _fromV550 repo_name logpoint_name | 7977 | localhost | 101372 | LogPoint | _logpoint | 1965 | /opt/immune/var/log/system_metrics/system_metrics.log | 1610700428 | UTC | LogPoint | 0 | LogPoint | 127.0.0.1 | t | None | log_ts col_ts free total use used sig_id _offset _identifier | device_ip | 10507 | filesystem | Physical Memory | Metrics,<br/>Usage,<br/>Memory,<br/>LogPoint |

### lp-get-incident-states
***
Displays incident states data between the provided two Timestamps ts_from and ts_to. By default, this command will display first 50 data of the past 24 hours but limit can be set to get desired number of incident states data.


#### Base Command

`lp-get-incident-states`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ts_from | From Timestamp. | Optional | 
| ts_to | To Timestamp. | Optional | 
| limit | Number of incident states data to fetch. Accepts integer value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogPoint.Incidents.states.id | String | LogPoint Incidents States Id | 
| LogPoint.Incidents.states.status | String | LogPoint Incidents States Status | 
| LogPoint.Incidents.states.assigned_to | String | LogPoint Incidents States Assigned To | 
| LogPoint.Incidents.states.comments | String | LogPoint Incidents States Comments | 


#### Command Example
```!lp-get-incident-states ts_from="1610700720" ts_to="1610700900" limit=5```

#### Context Example
```json
{
    "LogPoint": {
        "Incidents": {
            "states": [
                {
                    "assigned_to": "5fd9d95769d3a4ea5684fccf",
                    "comments": [
                        {
                            "comment": "Example comment",
                            "time": 1610700740,
                            "title": "admin"
                        },
                        {
                            "comment": "Reassigned",
                            "time": 1610700745,
                            "title": "admin"
                        }
                    ],
                    "id": "5fdc788ecf35d7ae0f6b791b",
                    "name": "Greater than 60",
                    "status": "unresolved"
                },
                {
                    "assigned_to": "5fd9d95769d3a4ea5684fccf",
                    "comments": [
                        {
                            "comment": "Reassigned",
                            "time": 1610700745,
                            "title": "admin"
                        }
                    ],
                    "id": "5fdc788ecf35d7ae0f6b791c",
                    "name": "Memory use greater than 50",
                    "status": "unresolved"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Displaying all 2 incident states data.
>|id|name|assigned_to|status|comments|
>|---|---|---|---|---|
>| 5fdc788ecf35d7ae0f6b791b | Greater than 60 | 5fd9d95769d3a4ea5684fccf | unresolved | {'title': 'admin', 'comment': 'Example comment', 'time': 1610700740},<br/>{'title': 'admin', 'comment': 'Reassigned', 'time': 1610700745} |
>| 5fdc788ecf35d7ae0f6b791c | Memory use greater than 50 | 5fd9d95769d3a4ea5684fccf | unresolved | {'title': 'admin', 'comment': 'Reassigned', 'time': 1610700745} |


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
```!lp-add-incident-comment comment="Example comment" incident_obj_id=600157c44a2018070b627f6a```

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
```!lp-assign-incidents incident_obj_ids="600157c44a2018070b627f6a,6001583c4a2018070b627f6b" new_assignee=5bebd9fdd8aaa42840edc853```

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
```!lp-resolve-incidents incident_obj_ids="600157c44a2018070b627f6a,6001583c4a2018070b627f6b"```

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
```!lp-close-incidents incident_obj_ids="600157c44a2018070b627f6a,6001583c4a2018070b627f6b"```

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
```!lp-reopen-incidents incident_obj_ids="600157c44a2018070b627f6a,6001583c4a2018070b627f6b"```

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

