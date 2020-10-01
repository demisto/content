Integration with Graylog
This integration was integrated and tested with version xx of Graylog
## Configure Graylog on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Graylog.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://serverurl:9000\) | True |
| credentials | Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### graylog-cluster-status
***
Get Cluster nodes status


#### Base Command

`graylog-cluster-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Graylog.ClusterStatus | String | Status of nodes in the Cluster | 


#### Command Example
```!graylog-cluster-status```

#### Context Example
```json
{
    "Graylog": {
        "ClusterStatus": {
            "95ba5102-13c9-4520-ac75-c8736f206953": {
                "cluster_id": "70a69af5-7368-4244-ac12-cf5b87c83ac2",
                "codename": "Sloth Rocket",
                "facility": "graylog-server",
                "hostname": "graylog",
                "is_processing": true,
                "lb_status": "alive",
                "lifecycle": "running",
                "node_id": "95ba5102-13c9-4520-ac75-c8736f206953",
                "operating_system": "Linux 4.15.0-118-generic",
                "started_at": "2020-10-01T06:44:50.169Z",
                "timezone": "UTC",
                "version": "3.3.6+92fb41e"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|95ba5102-13c9-4520-ac75-c8736f206953|
>|---|
>| facility: graylog-server<br/>codename: Sloth Rocket<br/>node_id: 95ba5102-13c9-4520-ac75-c8736f206953<br/>cluster_id: 70a69af5-7368-4244-ac12-cf5b87c83ac2<br/>version: 3.3.6+92fb41e<br/>started_at: 2020-10-01T06:44:50.169Z<br/>hostname: graylog<br/>lifecycle: running<br/>lb_status: alive<br/>timezone: UTC<br/>operating_system: Linux 4.15.0-118-generic<br/>is_processing: true |


### graylog-cluster-node-jvm
***
Get JVM status of a node in cluster


#### Base Command

`graylog-cluster-node-jvm`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nodeId | Node ID of the cluster member | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Graylog.ClusterNodeJVM | String | JVM info of Node | 


#### Command Example
```!graylog-cluster-node-jvm nodeId=95ba5102-13c9-4520-ac75-c8736f206953	```

#### Context Example
```json
{
    "Graylog": {
        "ClusterNodeJVM": {
            "free_memory": {
                "bytes": 631814072,
                "kilobytes": 617005,
                "megabytes": 602
            },
            "info": "Private Build 1.8.0_265 on Linux 4.15.0-118-generic",
            "max_memory": {
                "bytes": 1020067840,
                "kilobytes": 996160,
                "megabytes": 972
            },
            "node_id": "95ba5102-13c9-4520-ac75-c8736f206953",
            "pid": "657",
            "total_memory": {
                "bytes": 1020067840,
                "kilobytes": 996160,
                "megabytes": 972
            },
            "used_memory": {
                "bytes": 388253768,
                "kilobytes": 379154,
                "megabytes": 370
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|free_memory|info|max_memory|node_id|pid|total_memory|used_memory|
>|---|---|---|---|---|---|---|
>| bytes: 123123123<br/>kilobytes: 617005<br/>megabytes: 602 | Private Build 1.8.0_265 on Linux 4.15.0-118-generic | bytes: 1020067840<br/>kilobytes: 996160<br/>megabytes: 972 | 95ba5102-13c9-4520-ac75-c8736f206953 | 657 | bytes: 1020067840<br/>kilobytes: 996160<br/>megabytes: 972 | bytes: 388253768<br/>kilobytes: 379154<br/>megabytes: 370 |


### graylog-cluster-inputstates
***
Get input states of the cluster


#### Base Command

`graylog-cluster-inputstates`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Graylog.ClusterInputStates | String | Input states of the cluster | 


#### Command Example
```!graylog-cluster-inputstates```

#### Context Example
```json
{
    "Graylog": {
        "ClusterInputStates": {
            "95ba5102-13c9-4520-ac75-c8736f206953": [
                {
                    "detailed_message": null,
                    "id": "5f7433f60f4d9c360092a070",
                    "message_input": {
                        "attributes": {
                            "bind_address": "0.0.0.0",
                            "max_message_size": 2097152,
                            "number_worker_threads": 2,
                            "port": 5555,
                            "recv_buffer_size": 1048576,
                            "store_full_message": false,
                            "tcp_keepalive": false,
                            "tls_cert_file": "",
                            "tls_client_auth": "disabled",
                            "tls_client_auth_cert_file": "",
                            "tls_enable": false,
                            "tls_key_file": "",
                            "tls_key_password": "",
                            "use_null_delimiter": false
                        },
                        "content_pack": null,
                        "created_at": "2020-09-30T07:29:58.169Z",
                        "creator_user_id": "user",
                        "global": true,
                        "id": "5f7433f60f4d9c360092a070",
                        "name": "Palo Alto Networks TCP (PAN-OS v9.x)",
                        "node": null,
                        "static_fields": {},
                        "title": "PAN-OS-input",
                        "type": "org.graylog.integrations.inputs.paloalto9.PaloAlto9xInput"
                    },
                    "started_at": "2020-10-01T06:45:16.675Z",
                    "state": "RUNNING"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|95ba5102-13c9-4520-ac75-c8736f206953|
>|---|
>| {'id': '5f7433f60f4d9c360092a070', 'state': 'RUNNING', 'started_at': '2020-10-01T06:45:16.675Z', 'detailed_message': None, 'message_input': {'title': 'PAN-OS-input', 'global': True, 'name': 'Palo Alto Networks TCP (PAN-OS v9.x)', 'content_pack': None, 'created_at': '2020-09-30T07:29:58.169Z', 'type': 'org.graylog.integrations.inputs.paloalto9.PaloAlto9xInput', 'creator_user_id': 'user', 'attributes': {'recv_buffer_size': 1048576, 'tcp_keepalive': False, 'use_null_delimiter': False, 'number_worker_threads': 2, 'tls_client_auth_cert_file': '', 'bind_address': '0.0.0.0', 'tls_cert_file': '', 'store_full_message': False, 'port': 5555, 'tls_key_file': '', 'tls_enable': False, 'tls_key_password': '', 'max_message_size': 2097152, 'tls_client_auth': 'disabled'}, 'static_fields': {}, 'node': None, 'id': '5f7433f60f4d9c360092a070'}} |


### graylog-cluster-processing-status
***
Shows the processing status of the cluster


#### Base Command

`graylog-cluster-processing-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Graylog.ClusterProcessingStatus | String | Processing status of the cluster | 


#### Command Example
```!graylog-cluster-processing-status```

#### Context Example
```json
{
    "Graylog": {
        "ClusterProcessingStatus": {
            "95ba5102-13c9-4520-ac75-c8736f206953": {
                "receive_times": {
                    "ingest": "2020-10-01T11:22:16.355Z",
                    "post_indexing": "2020-10-01T11:22:16.355Z",
                    "post_processing": "2020-10-01T11:22:16.355Z"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|95ba5102-13c9-4520-ac75-c8736f206953|
>|---|
>| receive_times: {"ingest": "2020-10-01T11:22:16.355Z", "post_processing": "2020-10-01T11:22:16.355Z", "post_indexing": "2020-10-01T11:22:16.355Z"} |


### graylog-indexer-cluster-health
***
Get health of the indexer


#### Base Command

`graylog-indexer-cluster-health`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Graylog.IndexerHealth | String | Health of Indexer | 


#### Command Example
```!graylog-indexer-cluster-health```

#### Context Example
```json
{
    "Graylog": {
        "IndexerHealth": {
            "shards": {
                "active": 20,
                "initializing": 0,
                "relocating": 0,
                "unassigned": 0
            },
            "status": "green"
        }
    }
}
```

#### Human Readable Output

>### Results
>|shards|status|
>|---|---|
>| active: 20<br/>initializing: 0<br/>relocating: 0<br/>unassigned: 0 | green |


### graylog-search
***
Search for messages in a relative timerange, specified as seconds from now. Example: 300 means search from 5 minutes ago to now.


#### Base Command

`graylog-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query (Lucene syntax) | Required | 
| range | Relative timeframe to search in. Default 300s | Optional | 
| limit | Maximum number of messages to return. Default 20 | Optional | 
| offset | offset (integer) | Optional | 
| filter | filter | Optional | 
| fields | Comma separated list of fields to return | Optional | 
| sort | Sorting (field:asc / field:desc) | Optional | 
| decorate | Run decorators on search result (default True) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Graylog.Search | String | Search results | 


#### Command Example
```!graylog-search query=<query here> limit=2```

#### Context Example
```json
{
    "Graylog": {
        "Search": {
            "built_query": "{\n  \"from\" : 0,\n  \"size\" : 2,\n  \"query\" : {\n    \"bool\" : {\n      \"must\" : [\n        {\n          \"query_string\" : {\n            \"query\" : \"<query here>\",\n            \"fields\" : [ ],\n            \"use_dis_max\" : true,\n            \"tie_breaker\" : 0.0,\n            \"default_operator\" : \"or\",\n            \"auto_generate_phrase_queries\" : false,\n            \"max_determinized_states\" : 10000,\n            \"allow_leading_wildcard\" : false,\n            \"enable_position_increments\" : true,\n            \"fuzziness\" : \"AUTO\",\n            \"fuzzy_prefix_length\" : 0,\n            \"fuzzy_max_expansions\" : 50,\n            \"phrase_slop\" : 0,\n            \"escape\" : false,\n            \"split_on_whitespace\" : true,\n            \"boost\" : 1.0\n          }\n        }\n      ],\n      \"filter\" : [\n        {\n          \"bool\" : {\n            \"must\" : [\n              {\n                \"range\" : {\n                  \"timestamp\" : {\n                    \"from\" : \"2020-10-01 11:17:36.855\",\n                    \"to\" : \"2020-10-01 11:22:36.855\",\n                    \"include_lower\" : true,\n                    \"include_upper\" : true,\n                    \"boost\" : 1.0\n                  }\n                }\n              }\n            ],\n            \"disable_coord\" : false,\n            \"adjust_pure_negative\" : true,\n            \"boost\" : 1.0\n          }\n        }\n      ],\n      \"disable_coord\" : false,\n      \"adjust_pure_negative\" : true,\n      \"boost\" : 1.0\n    }\n  },\n  \"sort\" : [\n    {\n      \"timestamp\" : {\n        \"order\" : \"desc\"\n      }\n    }\n  ]\n}",
            "decoration_stats": null,
            "fields": [
                "event_received_time",
                "pan_log_subtype",
                "pan_dev_group_level_4",
                "pan_dev_group_level_3",
                "network_interface_out",
                "source",
                "pan_url_index",
                "vendor_event_action",
                "pan_dev_group_level_2",
                "source_ip",
                "pan_dev_group_level_1",
                "host_virtfw_id",
                "destination_ip",
                "application_name",
                "pan_ppid",
                "alert_indicator",
                "host_hostname",
                "source_location_name",
                "alert_signature_id",
                "rule_name",
                "source_zone",
                "gl2_message_id",
                "network_protocol",
                "network_tunnel_type",
                "alert_definitions_version",
                "destination_nat_ip",
                "pan_log_action",
                "pan_http2",
                "source_nat_ip",
                "destination_nat_port",
                "http_url_category",
                "policy_uid",
                "destination_port",
                "pan_log_panorama",
                "pan_tunnel_id",
                "pan_alert_direction",
                "vendor_alert_severity",
                "event_uid",
                "destination_location_name",
                "source_port",
                "event_log_name",
                "event_repeat_count",
                "timestamp",
                "event_source_product",
                "source_nat_port",
                "destination_zone",
                "session_id",
                "message",
                "alert_category",
                "pan_parent_session_id",
                "host_id",
                "network_interface_in",
                "pan_wildfire_report_id",
                "pan_pcap_id",
                "pan_flags",
                "pan_assoc_id",
                "pan_monitor_tag"
            ],
            "from": "2020-10-01T11:17:36.855Z",
            "messages": [
                {
                    "decoration_stats": null,
                    "highlight_ranges": {},
                    "index": "graylog_0",
                    "message": {
                        "_id": "5b3e4940-03d8-11eb-a2d0-000c29d42d8e",
                        "alert_category": "web-based-email",
                        "alert_definitions_version": "AppThreat-0-0",
                        "alert_indicator": "<URL here>:993/",
                        "alert_signature_id": "(9999)",
                        "application_name": "gmail-base",
                        "destination_ip": "xxx.xxx.xxx.xxx",
                        "destination_location_name": "United States",
                        "destination_nat_ip": "xxx.xxx.xxx.xxx",
                        "destination_nat_port": 993,
                        "destination_port": 993,
                        "destination_zone": "Untrust-L3",
                        "event_log_name": "THREAT",
                        "event_received_time": "2020/10/01 14:22:13",
                        "event_repeat_count": 1,
                        "event_source_product": "PAN",
                        "event_uid": "7538644",
                        "gl2_accounted_message_size": 2103,
                        "gl2_message_id": "AAA",
                        "gl2_remote_ip": "yyy.yyy.yyy.yyy",
                        "gl2_remote_port": 44548,
                        "gl2_source_input": "5f7433f60f4d9c360092a070",
                        "gl2_source_node": "95ba5102-13c9-4520-ac75-c8736f206953",
                        "host_hostname": "PA-220",
                        "host_id": "012801077297",
                        "host_virtfw_id": "vsys1",
                        "http_url_category": "web-based-email,low-risk",
                        "message": "1,2020/10/01 14:22:13,012801077297,THREAT,url,2560,2020/10/01 14:22:13,abc.abc.abc.abc,xxx.xxx.xxx.xxx,zzz.zzz.zzz.zzz,xxx.xxx.xxx.xxx,FromTrust,,,gmail-base,vsys1,Trust-L3,Untrust-L3,ethernet1/3,ethernet1/4,default,2020/10/01 14:22:13,58621,1,38424,993,21721,993,0x816400,tcp,alert,\"<URL here>:993/\",(9999),web-based-email,informational,client-to-server,7538644,0xa000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,0,0,0,0,0,,PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,,\"web-based-email,low-risk\",4093544d-2f66-4d80-af2d-17f361609984,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2020-10-01T14:22:14.350+03:00,,,",
                        "network_interface_in": "ethernet1/3",
                        "network_interface_out": "ethernet1/4",
                        "network_protocol": "tcp",
                        "network_tunnel_type": "N/A",
                        "pan_alert_direction": "client-to-server",
                        "pan_assoc_id": 0,
                        "pan_dev_group_level_1": 0,
                        "pan_dev_group_level_2": 0,
                        "pan_dev_group_level_3": 0,
                        "pan_dev_group_level_4": 0,
                        "pan_flags": "0x816400",
                        "pan_http2": "0",
                        "pan_log_action": "default",
                        "pan_log_panorama": "0xa000000000000000",
                        "pan_log_subtype": "url",
                        "pan_monitor_tag": 0,
                        "pan_parent_session_id": "0",
                        "pan_pcap_id": "0",
                        "pan_ppid": 4294967295,
                        "pan_tunnel_id": "0",
                        "pan_url_index": 0,
                        "pan_wildfire_report_id": 0,
                        "policy_uid": "4093544d-2f66-4d80-af2d-17f361609984",
                        "rule_name": "FromTrust",
                        "session_id": 58621,
                        "source": "PA-220",
                        "source_ip": "abc.abc.abc.abc",
                        "source_location_name": "192.168.0.0-192.168.255.255",
                        "source_nat_ip": "zzz.zzz.zzz.zzz",
                        "source_nat_port": 21721,
                        "source_port": 38424,
                        "source_zone": "Trust-L3",
                        "streams": [
                            "000000000000000000000001"
                        ],
                        "timestamp": "2020-10-01T11:22:14.727Z",
                        "vendor_alert_severity": "informational",
                        "vendor_event_action": "alert"
                    }
                },
                {
                    "decoration_stats": null,
                    "highlight_ranges": {},
                    "index": "graylog_0",
                    "message": {
                        "_id": "395e4230-03d8-11eb-a2d0-000c29d42d8e",
                        "alert_category": "web-based-email",
                        "alert_definitions_version": "AppThreat-0-0",
                        "alert_indicator": "<URL here>:993/",
                        "alert_signature_id": "(9999)",
                        "application_name": "gmail-base",
                        "destination_ip": "xxx.xxx.xxx.xxx",
                        "destination_location_name": "United States",
                        "destination_nat_ip": "xxx.xxx.xxx.xxx",
                        "destination_nat_port": 993,
                        "destination_port": 993,
                        "destination_zone": "Untrust-L3",
                        "event_log_name": "THREAT",
                        "event_received_time": "2020/10/01 14:21:17",
                        "event_repeat_count": 1,
                        "event_source_product": "PAN",
                        "event_uid": "7538632",
                        "gl2_accounted_message_size": 2103,
                        "gl2_message_id": "BBB",
                        "gl2_remote_ip": "yyy.yyy.yyy.yyy",
                        "gl2_remote_port": 44548,
                        "gl2_source_input": "5f7433f60f4d9c360092a070",
                        "gl2_source_node": "95ba5102-13c9-4520-ac75-c8736f206953",
                        "host_hostname": "PA-220",
                        "host_id": "012801077297",
                        "host_virtfw_id": "vsys1",
                        "http_url_category": "web-based-email,low-risk",
                        "message": "1,2020/10/01 14:21:17,012801077297,THREAT,url,2560,2020/10/01 14:21:17,abc.abc.abc.abc,xxx.xxx.xxx.xxx,zzz.zzz.zzz.zzz,xxx.xxx.xxx.xxx,FromTrust,,,gmail-base,vsys1,Trust-L3,Untrust-L3,ethernet1/3,ethernet1/4,default,2020/10/01 14:21:17,54274,1,38416,993,41336,993,0x816400,tcp,alert,\"<URL here>:993/\",(9999),web-based-email,informational,client-to-server,7538632,0xa000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,0,0,0,0,0,,PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,,\"web-based-email,low-risk\",4093544d-2f66-4d80-af2d-17f361609984,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2020-10-01T14:21:17.516+03:00,,,",
                        "network_interface_in": "ethernet1/3",
                        "network_interface_out": "ethernet1/4",
                        "network_protocol": "tcp",
                        "network_tunnel_type": "N/A",
                        "pan_alert_direction": "client-to-server",
                        "pan_assoc_id": 0,
                        "pan_dev_group_level_1": 0,
                        "pan_dev_group_level_2": 0,
                        "pan_dev_group_level_3": 0,
                        "pan_dev_group_level_4": 0,
                        "pan_flags": "0x816400",
                        "pan_http2": "0",
                        "pan_log_action": "default",
                        "pan_log_panorama": "0xa000000000000000",
                        "pan_log_subtype": "url",
                        "pan_monitor_tag": 0,
                        "pan_parent_session_id": "0",
                        "pan_pcap_id": "0",
                        "pan_ppid": 4294967295,
                        "pan_tunnel_id": "0",
                        "pan_url_index": 0,
                        "pan_wildfire_report_id": 0,
                        "policy_uid": "4093544d-2f66-4d80-af2d-17f361609984",
                        "rule_name": "FromTrust",
                        "session_id": 54274,
                        "source": "PA-220",
                        "source_ip": "abc.abc.abc.abc",
                        "source_location_name": "192.168.0.0-192.168.255.255",
                        "source_nat_ip": "zzz.zzz.zzz.zzz",
                        "source_nat_port": 41336,
                        "source_port": 38416,
                        "source_zone": "Trust-L3",
                        "streams": [
                            "000000000000000000000001"
                        ],
                        "timestamp": "2020-10-01T11:21:17.728Z",
                        "vendor_alert_severity": "informational",
                        "vendor_event_action": "alert"
                    }
                }
            ],
            "query": "<query here>",
            "time": 4,
            "to": "2020-10-01T11:22:36.855Z",
            "total_results": 7,
            "used_indices": [
                {
                    "begin": "1970-01-01T00:00:00.000Z",
                    "calculated_at": "2020-09-30T07:24:40.163Z",
                    "end": "1970-01-01T00:00:00.000Z",
                    "index_name": "graylog_0",
                    "took_ms": 0
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|built_query|decoration_stats|fields|from|messages|query|time|to|total_results|used_indices|
>|---|---|---|---|---|---|---|---|---|---|
>| {<br/>  "from" : 0,<br/>  "size" : 2,<br/>  "query" : {<br/>    "bool" : {<br/>      "must" : [<br/>        {<br/>          "query_string" : {<br/>            "query" : "gmail",<br/>            "fields" : [ ],<br/>            "use_dis_max" : true,<br/>            "tie_breaker" : 0.0,<br/>            "default_operator" : "or",<br/>            "auto_generate_phrase_queries" : false,<br/>            "max_determinized_states" : 10000,<br/>            "allow_leading_wildcard" : false,<br/>            "enable_position_increments" : true,<br/>            "fuzziness" : "AUTO",<br/>            "fuzzy_prefix_length" : 0,<br/>            "fuzzy_max_expansions" : 50,<br/>            "phrase_slop" : 0,<br/>            "escape" : false,<br/>            "split_on_whitespace" : true,<br/>            "boost" : 1.0<br/>          }<br/>        }<br/>      ],<br/>      "filter" : [<br/>        {<br/>          "bool" : {<br/>            "must" : [<br/>              {<br/>                "range" : {<br/>                  "timestamp" : {<br/>                    "from" : "2020-10-01 11:17:36.855",<br/>                    "to" : "2020-10-01 11:22:36.855",<br/>                    "include_lower" : true,<br/>                    "include_upper" : true,<br/>                    "boost" : 1.0<br/>                  }<br/>                }<br/>              }<br/>            ],<br/>            "disable_coord" : false,<br/>            "adjust_pure_negative" : true,<br/>            "boost" : 1.0<br/>          }<br/>        }<br/>      ],<br/>      "disable_coord" : false,<br/>      "adjust_pure_negative" : true,<br/>      "boost" : 1.0<br/>    }<br/>  },<br/>  "sort" : [<br/>    {<br/>      "timestamp" : {<br/>        "order" : "desc"<br/>      }<br/>    }<br/>  ]<br/>} |  | event_received_time,<br/>pan_log_subtype,<br/>pan_dev_group_level_4,<br/>pan_dev_group_level_3,<br/>network_interface_out,<br/>source,<br/>pan_url_index,<br/>vendor_event_action,<br/>pan_dev_group_level_2,<br/>source_ip,<br/>pan_dev_group_level_1,<br/>host_virtfw_id,<br/>destination_ip,<br/>application_name,<br/>pan_ppid,<br/>alert_indicator,<br/>host_hostname,<br/>source_location_name,<br/>alert_signature_id,<br/>rule_name,<br/>source_zone,<br/>gl2_message_id,<br/>network_protocol,<br/>network_tunnel_type,<br/>alert_definitions_version,<br/>destination_nat_ip,<br/>pan_log_action,<br/>pan_http2,<br/>source_nat_ip,<br/>destination_nat_port,<br/>http_url_category,<br/>policy_uid,<br/>destination_port,<br/>pan_log_panorama,<br/>pan_tunnel_id,<br/>pan_alert_direction,<br/>vendor_alert_severity,<br/>event_uid,<br/>destination_location_name,<br/>source_port,<br/>event_log_name,<br/>event_repeat_count,<br/>timestamp,<br/>event_source_product,<br/>source_nat_port,<br/>destination_zone,<br/>session_id,<br/>message,<br/>alert_category,<br/>pan_parent_session_id,<br/>host_id,<br/>network_interface_in,<br/>pan_wildfire_report_id,<br/>pan_pcap_id,<br/>pan_flags,<br/>pan_assoc_id,<br/>pan_monitor_tag | 2020-10-01T11:17:36.855Z | {'highlight_ranges': {}, 'message': {'event_received_time': '2020/10/01 14:22:13', 'pan_log_subtype': 'url', 'gl2_remote_ip': 'yyy.yyy.yyy.yyy', 'gl2_remote_port': 44548, 'pan_dev_group_level_4': 0, 'pan_dev_group_level_3': 0, 'network_interface_out': 'ethernet1/4', 'source': 'PA-220', 'gl2_source_input': '5f7433f60f4d9c360092a070', 'pan_url_index': 0, 'vendor_event_action': 'alert', 'pan_dev_group_level_2': 0, 'source_ip': 'abc.abc.abc.abc', 'pan_dev_group_level_1': 0, 'host_virtfw_id': 'vsys1', 'destination_ip': 'xxx.xxx.xxx.xxx', 'application_name': 'gmail-base', 'pan_ppid': 4294967295, 'gl2_source_node': '95ba5102-13c9-4520-ac75-c8736f206953', 'alert_indicator': '<URL here>:993/', 'host_hostname': 'PA-220', 'source_location_name': '192.168.0.0-192.168.255.255', 'gl2_accounted_message_size': 2103, 'alert_signature_id': '(9999)', 'rule_name': 'FromTrust', 'source_zone': 'Trust-L3', 'streams': ['000000000000000000000001'], 'gl2_message_id': 'AAA', 'network_protocol': 'tcp', 'network_tunnel_type': 'N/A', 'alert_definitions_version': 'AppThreat-0-0', 'destination_nat_ip': 'xxx.xxx.xxx.xxx', 'pan_log_action': 'default', 'pan_http2': '0', 'source_nat_ip': 'zzz.zzz.zzz.zzz', '_id': '5b3e4940-03d8-11eb-a2d0-000c29d42d8e', 'destination_nat_port': 993, 'http_url_category': 'web-based-email,low-risk', 'policy_uid': '4093544d-2f66-4d80-af2d-17f361609984', 'destination_port': 993, 'pan_log_panorama': '0xa000000000000000', 'pan_tunnel_id': '0', 'pan_alert_direction': 'client-to-server', 'vendor_alert_severity': 'informational', 'event_uid': '7538644', 'destination_location_name': 'United States', 'source_port': 38424, 'event_log_name': 'THREAT', 'event_repeat_count': 1, 'timestamp': '2020-10-01T11:22:14.727Z', 'event_source_product': 'PAN', 'source_nat_port': 21721, 'destination_zone': 'Untrust-L3', 'session_id': 58621, 'message': '1,2020/10/01 14:22:13,012801077297,THREAT,url,2560,2020/10/01 14:22:13,abc.abc.abc.abc,xxx.xxx.xxx.xxx,zzz.zzz.zzz.zzz,xxx.xxx.xxx.xxx,FromTrust,,,gmail-base,vsys1,Trust-L3,Untrust-L3,ethernet1/3,ethernet1/4,default,2020/10/01 14:22:13,58621,1,38424,993,21721,993,0x816400,tcp,alert,"<URL here>:993/",(9999),web-based-email,informational,client-to-server,7538644,0xa000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,0,0,0,0,0,,PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,,"web-based-email,low-risk",4093544d-2f66-4d80-af2d-17f361609984,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2020-10-01T14:22:14.350+03:00,,,', 'alert_category': 'web-based-email', 'pan_parent_session_id': '0', 'host_id': '012801077297', 'network_interface_in': 'ethernet1/3', 'pan_wildfire_report_id': 0, 'pan_pcap_id': '0', 'pan_flags': '0x816400', 'pan_assoc_id': 0, 'pan_monitor_tag': 0}, 'index': 'graylog_0', 'decoration_stats': None},<br/>{'highlight_ranges': {}, 'message': {'event_received_time': '2020/10/01 14:21:17', 'pan_log_subtype': 'url', 'gl2_remote_ip': 'yyy.yyy.yyy.yyy', 'gl2_remote_port': 44548, 'pan_dev_group_level_4': 0, 'pan_dev_group_level_3': 0, 'network_interface_out': 'ethernet1/4', 'source': 'PA-220', 'gl2_source_input': '5f7433f60f4d9c360092a070', 'pan_url_index': 0, 'vendor_event_action': 'alert', 'pan_dev_group_level_2': 0, 'source_ip': 'abc.abc.abc.abc', 'pan_dev_group_level_1': 0, 'host_virtfw_id': 'vsys1', 'destination_ip': 'xxx.xxx.xxx.xxx', 'application_name': 'gmail-base', 'pan_ppid': 4294967295, 'gl2_source_node': '95ba5102-13c9-4520-ac75-c8736f206953', 'alert_indicator': '<URL here>:993/', 'host_hostname': 'PA-220', 'source_location_name': '192.168.0.0-192.168.255.255', 'gl2_accounted_message_size': 2103, 'alert_signature_id': '(9999)', 'rule_name': 'FromTrust', 'source_zone': 'Trust-L3', 'streams': ['000000000000000000000001'], 'gl2_message_id': 'BBB', 'network_protocol': 'tcp', 'network_tunnel_type': 'N/A', 'alert_definitions_version': 'AppThreat-0-0', 'destination_nat_ip': 'xxx.xxx.xxx.xxx', 'pan_log_action': 'default', 'pan_http2': '0', 'source_nat_ip': 'zzz.zzz.zzz.zzz', '_id': '395e4230-03d8-11eb-a2d0-000c29d42d8e', 'destination_nat_port': 993, 'http_url_category': 'web-based-email,low-risk', 'policy_uid': '4093544d-2f66-4d80-af2d-17f361609984', 'destination_port': 993, 'pan_log_panorama': '0xa000000000000000', 'pan_tunnel_id': '0', 'pan_alert_direction': 'client-to-server', 'vendor_alert_severity': 'informational', 'event_uid': '7538632', 'destination_location_name': 'United States', 'source_port': 38416, 'event_log_name': 'THREAT', 'event_repeat_count': 1, 'timestamp': '2020-10-01T11:21:17.728Z', 'event_source_product': 'PAN', 'source_nat_port': 41336, 'destination_zone': 'Untrust-L3', 'session_id': 54274, 'message': '1,2020/10/01 14:21:17,012801077297,THREAT,url,2560,2020/10/01 14:21:17,abc.abc.abc.abc,xxx.xxx.xxx.xxx,zzz.zzz.zzz.zzz,xxx.xxx.xxx.xxx,FromTrust,,,gmail-base,vsys1,Trust-L3,Untrust-L3,ethernet1/3,ethernet1/4,default,2020/10/01 14:21:17,54274,1,38416,993,41336,993,0x816400,tcp,alert,"<URL here>:993/",(9999),web-based-email,informational,client-to-server,7538632,0xa000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,0,0,0,0,0,,PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,,"web-based-email,low-risk",4093544d-2f66-4d80-af2d-17f361609984,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2020-10-01T14:21:17.516+03:00,,,', 'alert_category': 'web-based-email', 'pan_parent_session_id': '0', 'host_id': '012801077297', 'network_interface_in': 'ethernet1/3', 'pan_wildfire_report_id': 0, 'pan_pcap_id': '0', 'pan_flags': '0x816400', 'pan_assoc_id': 0, 'pan_monitor_tag': 0}, 'index': 'graylog_0', 'decoration_stats': None} | gmail | 4 | 2020-10-01T11:22:36.855Z | 7 | {'index_name': 'graylog_0', 'begin': '1970-01-01T00:00:00.000Z', 'end': '1970-01-01T00:00:00.000Z', 'calculated_at': '2020-09-30T07:24:40.163Z', 'took_ms': 0} |


### graylog-events-search
***
Events overview and search


#### Base Command

`graylog-events-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query to use | Optional | 
| filter | filter to use | Optional | 
| page | number of pages as integer | Optional | 
| sort_direction | Sorting direction | Optional | 
| per_page | how many per page (integer) | Optional | 
| timerange | timerange to use | Optional | 
| sort_by | how to sort | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Graylog.EventsSearch | String | Result of Events Search | 


#### Command Example
```!graylog-events-search query=<query here>```

#### Context Example
```json
{
    "Graylog": {
        "EventsSearch": {
            "context": {
                "event_definitions": {
                    "5f7436c60f4d9c360092a3ac": {
                        "description": "",
                        "id": "5f7436c60f4d9c360092a3ac",
                        "title": "<query here>"
                    }
                },
                "streams": {
                    "000000000000000000000002": {
                        "description": "Stream containing all events created by Graylog",
                        "id": "000000000000000000000002",
                        "title": "All events"
                    }
                }
            },
            "duration": 6,
            "events": [
                {
                    "event": {
                        "alert": false,
                        "event_definition_id": "5f7436c60f4d9c360092a3ac",
                        "event_definition_type": "aggregation-v1",
                        "fields": {},
                        "id": "CCC",
                        "key": null,
                        "key_tuple": [],
                        "message": "<query here>",
                        "origin_context": "urn:graylog:message:es:graylog_0:395e4230-03d8-11eb-a2d0-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-01T11:21:17.728Z",
                        "timestamp_processing": "2020-10-01T11:22:04.000Z"
                    },
                    "index_name": "gl-events_1",
                    "index_type": "message"
                },
                {
                    "event": {
                        "alert": false,
                        "event_definition_id": "5f7436c60f4d9c360092a3ac",
                        "event_definition_type": "aggregation-v1",
                        "fields": {},
                        "id": "AAA",
                        "key": null,
                        "key_tuple": [],
                        "message": "<query here>",
                        "origin_context": "urn:graylog:message:es:graylog_0:13b7e451-03d8-11eb-a2d0-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-01T11:20:14.728Z",
                        "timestamp_processing": "2020-10-01T11:22:04.000Z"
                    },
                    "index_name": "gl-events_1",
                    "index_type": "message"
                },
                {
                    "event": {
                        "alert": false,
                        "event_definition_id": "5f7436c60f4d9c360092a3ac",
                        "event_definition_type": "aggregation-v1",
                        "fields": {},
                        "id": "BBB",
                        "key": null,
                        "key_tuple": [],
                        "message": "<query here>",
                        "origin_context": "urn:graylog:message:es:graylog_0:ef73d590-03d7-11eb-a2d0-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-01T11:19:13.727Z",
                        "timestamp_processing": "2020-10-01T11:22:04.000Z"
                    },
                    "index_name": "gl-events_1",
                    "index_type": "message"
                },
                {
                    "event": {
                        "alert": false,
                        "event_definition_id": "5f7436c60f4d9c360092a3ac",
                        "event_definition_type": "aggregation-v1",
                        "fields": {},
                        "id": "01EKHYBMV0MW0Q2PMJJP2PTC2K",
                        "key": null,
                        "key_tuple": [],
                        "message": "<query here>",
                        "origin_context": "urn:graylog:message:es:graylog_0:ccce5ba0-03d7-11eb-a2d0-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-01T11:18:15.728Z",
                        "timestamp_processing": "2020-10-01T11:22:04.000Z"
                    },
                    "index_name": "gl-events_1",
                    "index_type": "message"
                },
                {
                    "event": {
                        "alert": false,
                        "event_definition_id": "5f7436c60f4d9c360092a3ac",
                        "event_definition_type": "aggregation-v1",
                        "fields": {},
                        "id": "CCC",
                        "key": null,
                        "key_tuple": [],
                        "message": "<query here>",
                        "origin_context": "urn:graylog:message:es:graylog_0:a7d52db0-03d7-11eb-a2d0-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-01T11:17:13.728Z",
                        "timestamp_processing": "2020-10-01T11:22:04.000Z"
                    },
                    "index_name": "gl-events_1",
                    "index_type": "message"
                },
                {
                    "event": {
                        "alert": false,
                        "event_definition_id": "5f7436c60f4d9c360092a3ac",
                        "event_definition_type": "aggregation-v1",
                        "fields": {},
                        "id": "CCC",
                        "key": null,
                        "key_tuple": [],
                        "message": "<query here>",
                        "origin_context": "urn:graylog:message:es:graylog_0:84279291-03d7-11eb-a2d0-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-01T11:16:14.728Z",
                        "timestamp_processing": "2020-10-01T11:17:03.767Z"
                    },
                    "index_name": "gl-events_1",
                    "index_type": "message"
                },
                {
                    "event": {
                        "alert": false,
                        "event_definition_id": "5f7436c60f4d9c360092a3ac",
                        "event_definition_type": "aggregation-v1",
                        "fields": {},
                        "id": "'",
                        "key": null,
                        "key_tuple": [],
                        "message": "<query here>",
                        "origin_context": "urn:graylog:message:es:graylog_0:60245d61-03d7-11eb-a2d0-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-01T11:15:14.728Z",
                        "timestamp_processing": "2020-10-01T11:17:03.767Z"
                    },
                    "index_name": "gl-events_1",
                    "index_type": "message"
                },
                {
                    "event": {
                        "alert": false,
                        "event_definition_id": "5f7436c60f4d9c360092a3ac",
                        "event_definition_type": "aggregation-v1",
                        "fields": {},
                        "id": "BBB",
                        "key": null,
                        "key_tuple": [],
                        "message": "<query here>",
                        "origin_context": "urn:graylog:message:es:graylog_0:3d23cb21-03d7-11eb-a2d0-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-01T11:14:14.727Z",
                        "timestamp_processing": "2020-10-01T11:17:03.767Z"
                    },
                    "index_name": "gl-events_1",
                    "index_type": "message"
                },
                {
                    "event": {
                        "alert": false,
                        "event_definition_id": "5f7436c60f4d9c360092a3ac",
                        "event_definition_type": "aggregation-v1",
                        "fields": {},
                        "id": "CCC",
                        "key": null,
                        "key_tuple": [],
                        "message": "<query here>",
                        "origin_context": "urn:graylog:message:es:graylog_0:18c7eea1-03d7-11eb-a2d0-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-01T11:13:13.727Z",
                        "timestamp_processing": "2020-10-01T11:17:03.767Z"
                    },
                    "index_name": "gl-events_1",
                    "index_type": "message"
                },
                {
                    "event": {
                        "alert": false,
                        "event_definition_id": "5f7436c60f4d9c360092a3ac",
                        "event_definition_type": "aggregation-v1",
                        "fields": {},
                        "id": "AAA",
                        "key": null,
                        "key_tuple": [],
                        "message": "<query here>",
                        "origin_context": "urn:graylog:message:es:graylog_0:f5091570-03d6-11eb-a2d0-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-01T11:12:14.728Z",
                        "timestamp_processing": "2020-10-01T11:17:03.767Z"
                    },
                    "index_name": "gl-events_1",
                    "index_type": "message"
                }
            ],
            "parameters": {
                "filter": {
                    "alerts": "include",
                    "event_definitions": []
                },
                "page": 1,
                "per_page": 10,
                "query": "<query here>",
                "sort_by": "timestamp",
                "sort_direction": "desc",
                "timerange": {
                    "range": 3600,
                    "type": "relative"
                }
            },
            "total_events": 59,
            "used_indices": [
                "gl-events_1",
                "gl-system-events_1"
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|context|duration|events|parameters|total_events|used_indices|
>|---|---|---|---|---|---|
>| event_definitions: {"5f7436c60f4d9c360092a3ac": {"id": "5f7436c60f4d9c360092a3ac", "title": "<query here>", "description": ""}}<br/>streams: {"000000000000000000000002": {"id": "000000000000000000000002", "title": "All events", "description": "Stream containing all events created by Graylog"}} | 6 | {'event': {'id': 'CCC', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:395e4230-03d8-11eb-a2d0-000c29d42d8e', 'timestamp': '2020-10-01T11:21:17.728Z', 'timestamp_processing': '2020-10-01T11:22:04.000Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': '<query here>', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'AAA', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:13b7e451-03d8-11eb-a2d0-000c29d42d8e', 'timestamp': '2020-10-01T11:20:14.728Z', 'timestamp_processing': '2020-10-01T11:22:04.000Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': '<query here>', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'BBB', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:ef73d590-03d7-11eb-a2d0-000c29d42d8e', 'timestamp': '2020-10-01T11:19:13.727Z', 'timestamp_processing': '2020-10-01T11:22:04.000Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': '<query here>', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': '01EKHYBMV0MW0Q2PMJJP2PTC2K', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:ccce5ba0-03d7-11eb-a2d0-000c29d42d8e', 'timestamp': '2020-10-01T11:18:15.728Z', 'timestamp_processing': '2020-10-01T11:22:04.000Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': '<query here>', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'CCC', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:a7d52db0-03d7-11eb-a2d0-000c29d42d8e', 'timestamp': '2020-10-01T11:17:13.728Z', 'timestamp_processing': '2020-10-01T11:22:04.000Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': '<query here>', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'CCC', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:84279291-03d7-11eb-a2d0-000c29d42d8e', 'timestamp': '2020-10-01T11:16:14.728Z', 'timestamp_processing': '2020-10-01T11:17:03.767Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': '<query here>', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'AAA', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:60245d61-03d7-11eb-a2d0-000c29d42d8e', 'timestamp': '2020-10-01T11:15:14.728Z', 'timestamp_processing': '2020-10-01T11:17:03.767Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': '<query here>', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'BBB', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:3d23cb21-03d7-11eb-a2d0-000c29d42d8e', 'timestamp': '2020-10-01T11:14:14.727Z', 'timestamp_processing': '2020-10-01T11:17:03.767Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': '<query here>', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'CCC', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:18c7eea1-03d7-11eb-a2d0-000c29d42d8e', 'timestamp': '2020-10-01T11:13:13.727Z', 'timestamp_processing': '2020-10-01T11:17:03.767Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': '<query here>', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'AAA', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:f5091570-03d6-11eb-a2d0-000c29d42d8e', 'timestamp': '2020-10-01T11:12:14.728Z', 'timestamp_processing': '2020-10-01T11:17:03.767Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': '<query here>', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'} | page: 1<br/>per_page: 10<br/>timerange: {"type": "relative", "range": 3600}<br/>query: <query here><br/>filter: {"alerts": "include", "event_definitions": []}<br/>sort_by: timestamp<br/>sort_direction: desc | 59 | gl-events_1,<br/>gl-system-events_1 |

