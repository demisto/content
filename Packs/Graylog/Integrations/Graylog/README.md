Integration with Graylog to search for logs and events
This integration was integrated and tested with version 3.3.6 of Graylog
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
| fetch_time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days\) | False |
| fetch_query | The query that is used to fetch events as incidents \(lucene syntax\) | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |

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
                "started_at": "2020-10-07T16:04:07.506Z",
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
>| facility: graylog-server<br/>codename: Sloth Rocket<br/>node_id: 95ba5102-13c9-4520-ac75-c8736f206953<br/>cluster_id: 70a69af5-7368-4244-ac12-cf5b87c83ac2<br/>version: 3.3.6+92fb41e<br/>started_at: 2020-10-07T16:04:07.506Z<br/>hostname: graylog<br/>lifecycle: running<br/>lb_status: alive<br/>timezone: UTC<br/>operating_system: Linux 4.15.0-118-generic<br/>is_processing: true |


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
                "bytes": 387725360,
                "kilobytes": 378638,
                "megabytes": 369
            },
            "info": "Private Build 1.8.0_265 on Linux 4.15.0-118-generic",
            "max_memory": {
                "bytes": 1020067840,
                "kilobytes": 996160,
                "megabytes": 972
            },
            "node_id": "95ba5102-13c9-4520-ac75-c8736f206953",
            "pid": "550",
            "total_memory": {
                "bytes": 1020067840,
                "kilobytes": 996160,
                "megabytes": 972
            },
            "used_memory": {
                "bytes": 632342480,
                "kilobytes": 617521,
                "megabytes": 603
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|free_memory|info|max_memory|node_id|pid|total_memory|used_memory|
>|---|---|---|---|---|---|---|
>| bytes: 387725360<br/>kilobytes: 378638<br/>megabytes: 369 | Private Build 1.8.0_265 on Linux 4.15.0-118-generic | bytes: 1020067840<br/>kilobytes: 996160<br/>megabytes: 972 | 95ba5102-13c9-4520-ac75-c8736f206953 | 550 | bytes: 1020067840<br/>kilobytes: 996160<br/>megabytes: 972 | bytes: 632342480<br/>kilobytes: 617521<br/>megabytes: 603 |


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
                        "creator_user_id": "harri",
                        "global": true,
                        "id": "5f7433f60f4d9c360092a070",
                        "name": "Palo Alto Networks TCP (PAN-OS v9.x)",
                        "node": null,
                        "static_fields": {},
                        "title": "PAN-OS-input",
                        "type": "org.graylog.integrations.inputs.paloalto9.PaloAlto9xInput"
                    },
                    "started_at": "2020-10-07T16:04:28.814Z",
                    "state": "RUNNING"
                },
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|95ba5102-13c9-4520-ac75-c8736f206953|
>|---|
>| {'id': '5f7433f60f4d9c360092a070', 'state': 'RUNNING', 'started_at': '2020-10-07T16:04:28.814Z', 'detailed_message': None, 'message_input': {'title': 'PAN-OS-input', 'global': True, 'name': 'Palo Alto Networks TCP (PAN-OS v9.x)', 'content_pack': None, 'created_at': '2020-09-30T07:29:58.169Z', 'type': 'org.graylog.integrations.inputs.paloalto9.PaloAlto9xInput', 'creator_user_id': 'harri', 'attributes': {'recv_buffer_size': 1048576, 'tcp_keepalive': False, 'use_null_delimiter': False, 'number_worker_threads': 2, 'tls_client_auth_cert_file': '', 'bind_address': '0.0.0.0', 'tls_cert_file': '', 'store_full_message': False, 'port': 5555, 'tls_key_file': '', 'tls_enable': False, 'tls_key_password': '', 'max_message_size': 2097152, 'tls_client_auth': 'disabled'}, 'static_fields': {}, 'node': None, 'id': '5f7433f60f4d9c360092a070'}} |


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
                    "ingest": "2020-10-08T10:08:29.353Z",
                    "post_indexing": "2020-10-08T10:08:29.353Z",
                    "post_processing": "2020-10-08T10:08:29.353Z"
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
>| receive_times: {"ingest": "2020-10-08T10:08:29.353Z", "post_processing": "2020-10-08T10:08:29.353Z", "post_indexing": "2020-10-08T10:08:29.353Z"} |


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
```!graylog-search query=\<query here\>```

#### Context Example
```json
{
    "Graylog": {
        "Search": {
            "built_query": "{\n  \"from\" : 0,\n  \"size\" : 20,\n  \"query\" : {\n    \"bool\" : {\n      \"must\" : [\n        {\n          \"query_string\" : {\n            \"query\" : \"\<query here\>\",\n            \"fields\" : [ ],\n            \"use_dis_max\" : true,\n            \"tie_breaker\" : 0.0,\n            \"default_operator\" : \"or\",\n            \"auto_generate_phrase_queries\" : false,\n            \"max_determinized_states\" : 10000,\n            \"allow_leading_wildcard\" : false,\n            \"enable_position_increments\" : true,\n            \"fuzziness\" : \"AUTO\",\n            \"fuzzy_prefix_length\" : 0,\n            \"fuzzy_max_expansions\" : 50,\n            \"phrase_slop\" : 0,\n            \"escape\" : false,\n            \"split_on_whitespace\" : true,\n            \"boost\" : 1.0\n          }\n        }\n      ],\n      \"filter\" : [\n        {\n          \"bool\" : {\n            \"must\" : [\n              {\n                \"range\" : {\n                  \"timestamp\" : {\n                    \"from\" : \"2020-10-08 00:08:57.306\",\n                    \"to\" : \"2020-10-08 10:08:57.306\",\n                    \"include_lower\" : true,\n                    \"include_upper\" : true,\n                    \"boost\" : 1.0\n                  }\n                }\n              }\n            ],\n            \"disable_coord\" : false,\n            \"adjust_pure_negative\" : true,\n            \"boost\" : 1.0\n          }\n        }\n      ],\n      \"disable_coord\" : false,\n      \"adjust_pure_negative\" : true,\n      \"boost\" : 1.0\n    }\n  },\n  \"sort\" : [\n    {\n      \"timestamp\" : {\n        \"order\" : \"desc\"\n      }\n    }\n  ]\n}",
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
                "pan_dev_group_level_1",
                "source_ip",
                "host_virtfw_id",
                "application_name",
                "destination_ip",
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
            "from": "2020-10-08T00:08:57.306Z",
            "messages": [
                {
                    "decoration_stats": null,
                    "highlight_ranges": {},
                    "index": "graylog_0",
                    "message": {
                        "_id": "1acb0472-0923-11eb-a959-000c29d42d8e",
                        "alert_category": "news",
                        "alert_definitions_version": "AppThreat-0-0",
                        "alert_indicator": "\<query here\>/",
                        "alert_signature_id": "(9999)",
                        "application_name": "ssl",
                        "destination_ip": "aaa.aaa.aaa.aaa",
                        "destination_location_name": "United States",
                        "destination_nat_ip": "aaa.aaa.aaa.aaa",
                        "destination_nat_port": 443,
                        "destination_port": 443,
                        "destination_zone": "Untrust-L3",
                        "event_log_name": "THREAT",
                        "event_received_time": "2020/10/08 07:59:53",
                        "event_repeat_count": 1,
                        "event_source_product": "PAN",
                        "event_uid": "7665475",
                        "gl2_accounted_message_size": 2027,
                        "gl2_message_id": "ABCD",
                        "gl2_remote_ip": "bbb.bbb.bbb.bbb",
                        "gl2_remote_port": 51371,
                        "gl2_source_input": "5f7433f60f4d9c360092a070",
                        "gl2_source_node": "95ba5102-13c9-4520-ac75-c8736f206953",
                        "host_hostname": "PA-220",
                        "host_id": "ABCDEFGHIJK",
                        "host_virtfw_id": "vsys1",
                        "http_url_category": "news,low-risk",
                        "message": "1,2020/10/08 07:59:53,ABCDEFGHIJK,THREAT,url,2560,2020/10/08 07:59:53,ccc.ccc.ccc.ccc,aaa.aaa.aaa.aaa,ddd.ddd.ddd.ddd,aaa.aaa.aaa.aaa,FromTrust,,,ssl,vsys1,Trust-L3,Untrust-L3,ethernet1/3,ethernet1/4,default,2020/10/08 07:59:53,23366,1,61323,443,48189,443,0x816400,tcp,alert,\"\<query here\>/\",(9999),news,informational,client-to-server,7665475,0xa000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,0,0,0,0,0,,PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,,\"news,low-risk\",4093544d-2f66-4d80-af2d-17f361609984,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2020-10-08T07:59:54.289+03:00,,,",
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
                        "session_id": 23366,
                        "source": "PA-220",
                        "source_ip": "ccc.ccc.ccc.ccc",
                        "source_location_name": "192.168.0.0-192.168.255.255",
                        "source_nat_ip": "ddd.ddd.ddd.ddd",
                        "source_nat_port": 48189,
                        "source_port": 61323,
                        "source_zone": "Trust-L3",
                        "streams": [
                            "000000000000000000000001"
                        ],
                        "timestamp": "2020-10-08T04:59:55.169Z",
                        "vendor_alert_severity": "informational",
                        "vendor_event_action": "alert"
                    }
                },
                {
                    "decoration_stats": null,
                    "highlight_ranges": {},
                    "index": "graylog_0",
                    "message": {
                        "_id": "1acb0470-0923-11eb-a959-000c29d42d8e",
                        "alert_category": "news",
                        "alert_definitions_version": "AppThreat-0-0",
                        "alert_indicator": "\<query here\>/",
                        "alert_signature_id": "(9999)",
                        "application_name": "ssl",
                        "destination_ip": "aaa.aaa.aaa.aaa",
                        "destination_location_name": "United States",
                        "destination_nat_ip": "aaa.aaa.aaa.aaa",
                        "destination_nat_port": 443,
                        "destination_port": 443,
                        "destination_zone": "Untrust-L3",
                        "event_log_name": "THREAT",
                        "event_received_time": "2020/10/08 07:59:53",
                        "event_repeat_count": 1,
                        "event_source_product": "PAN",
                        "event_uid": "7665473",
                        "gl2_accounted_message_size": 2027,
                        "gl2_message_id": "ABCD",
                        "gl2_remote_ip": "bbb.bbb.bbb.bbb",
                        "gl2_remote_port": 51371,
                        "gl2_source_input": "5f7433f60f4d9c360092a070",
                        "gl2_source_node": "95ba5102-13c9-4520-ac75-c8736f206953",
                        "host_hostname": "PA-220",
                        "host_id": "ABCDEFGHIJK",
                        "host_virtfw_id": "vsys1",
                        "http_url_category": "news,low-risk",
                        "message": "1,2020/10/08 07:59:53,ABCDEFGHIJK,THREAT,url,2560,2020/10/08 07:59:53,ccc.ccc.ccc.ccc,aaa.aaa.aaa.aaa,ddd.ddd.ddd.ddd,aaa.aaa.aaa.aaa,FromTrust,,,ssl,vsys1,Trust-L3,Untrust-L3,ethernet1/3,ethernet1/4,default,2020/10/08 07:59:53,24085,1,61322,443,29959,443,0x816400,tcp,alert,\"\<query here\>/\",(9999),news,informational,client-to-server,7665473,0xa000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,0,0,0,0,0,,PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,,\"news,low-risk\",4093544d-2f66-4d80-af2d-17f361609984,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2020-10-08T07:59:54.289+03:00,,,",
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
                        "session_id": 24085,
                        "source": "PA-220",
                        "source_ip": "ccc.ccc.ccc.ccc",
                        "source_location_name": "192.168.0.0-192.168.255.255",
                        "source_nat_ip": "ddd.ddd.ddd.ddd",
                        "source_nat_port": 29959,
                        "source_port": 61322,
                        "source_zone": "Trust-L3",
                        "streams": [
                            "000000000000000000000001"
                        ],
                        "timestamp": "2020-10-08T04:59:55.169Z",
                        "vendor_alert_severity": "informational",
                        "vendor_event_action": "alert"
                    }
                }
            ],
            "query": "\<query here\>",
            "time": 11,
            "to": "2020-10-08T10:08:57.306Z",
            "total_results": 2,
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
>| {<br/>  "from" : 0,<br/>  "size" : 20,<br/>  "query" : {<br/>    "bool" : {<br/>      "must" : [<br/>        {<br/>          "query_string" : {<br/>            "query" : "\<query here\>",<br/>            "fields" : [ ],<br/>            "use_dis_max" : true,<br/>            "tie_breaker" : 0.0,<br/>            "default_operator" : "or",<br/>            "auto_generate_phrase_queries" : false,<br/>            "max_determinized_states" : 10000,<br/>            "allow_leading_wildcard" : false,<br/>            "enable_position_increments" : true,<br/>            "fuzziness" : "AUTO",<br/>            "fuzzy_prefix_length" : 0,<br/>            "fuzzy_max_expansions" : 50,<br/>            "phrase_slop" : 0,<br/>            "escape" : false,<br/>            "split_on_whitespace" : true,<br/>            "boost" : 1.0<br/>          }<br/>        }<br/>      ],<br/>      "filter" : [<br/>        {<br/>          "bool" : {<br/>            "must" : [<br/>              {<br/>                "range" : {<br/>                  "timestamp" : {<br/>                    "from" : "2020-10-08 00:08:57.306",<br/>                    "to" : "2020-10-08 10:08:57.306",<br/>                    "include_lower" : true,<br/>                    "include_upper" : true,<br/>                    "boost" : 1.0<br/>                  }<br/>                }<br/>              }<br/>            ],<br/>            "disable_coord" : false,<br/>            "adjust_pure_negative" : true,<br/>            "boost" : 1.0<br/>          }<br/>        }<br/>      ],<br/>      "disable_coord" : false,<br/>      "adjust_pure_negative" : true,<br/>      "boost" : 1.0<br/>    }<br/>  },<br/>  "sort" : [<br/>    {<br/>      "timestamp" : {<br/>        "order" : "desc"<br/>      }<br/>    }<br/>  ]<br/>} |  | event_received_time,<br/>pan_log_subtype,<br/>pan_dev_group_level_4,<br/>pan_dev_group_level_3,<br/>network_interface_out,<br/>source,<br/>pan_url_index,<br/>vendor_event_action,<br/>pan_dev_group_level_2,<br/>pan_dev_group_level_1,<br/>source_ip,<br/>host_virtfw_id,<br/>application_name,<br/>destination_ip,<br/>pan_ppid,<br/>alert_indicator,<br/>host_hostname,<br/>source_location_name,<br/>alert_signature_id,<br/>rule_name,<br/>source_zone,<br/>gl2_message_id,<br/>network_protocol,<br/>network_tunnel_type,<br/>alert_definitions_version,<br/>destination_nat_ip,<br/>pan_log_action,<br/>pan_http2,<br/>source_nat_ip,<br/>destination_nat_port,<br/>http_url_category,<br/>policy_uid,<br/>destination_port,<br/>pan_log_panorama,<br/>pan_tunnel_id,<br/>pan_alert_direction,<br/>vendor_alert_severity,<br/>event_uid,<br/>destination_location_name,<br/>source_port,<br/>event_log_name,<br/>event_repeat_count,<br/>timestamp,<br/>event_source_product,<br/>source_nat_port,<br/>destination_zone,<br/>session_id,<br/>message,<br/>alert_category,<br/>pan_parent_session_id,<br/>host_id,<br/>network_interface_in,<br/>pan_wildfire_report_id,<br/>pan_pcap_id,<br/>pan_flags,<br/>pan_assoc_id,<br/>pan_monitor_tag | 2020-10-08T00:08:57.306Z | {'highlight_ranges': {}, 'message': {'event_received_time': '2020/10/08 07:59:53', 'pan_log_subtype': 'url', 'gl2_remote_ip': 'bbb.bbb.bbb.bbb', 'gl2_remote_port': 51371, 'pan_dev_group_level_4': 0, 'pan_dev_group_level_3': 0, 'network_interface_out': 'ethernet1/4', 'source': 'PA-220', 'gl2_source_input': '5f7433f60f4d9c360092a070', 'pan_url_index': 0, 'vendor_event_action': 'alert', 'pan_dev_group_level_2': 0, 'pan_dev_group_level_1': 0, 'source_ip': 'ccc.ccc.ccc.ccc', 'host_virtfw_id': 'vsys1', 'application_name': 'ssl', 'destination_ip': 'aaa.aaa.aaa.aaa', 'pan_ppid': 4294967295, 'gl2_source_node': '95ba5102-13c9-4520-ac75-c8736f206953', 'alert_indicator': '\<query here\>/', 'host_hostname': 'PA-220', 'source_location_name': '192.168.0.0-192.168.255.255', 'gl2_accounted_message_size': 2027, 'alert_signature_id': '(9999)', 'rule_name': 'FromTrust', 'source_zone': 'Trust-L3', 'streams': ['000000000000000000000001'], 'gl2_message_id': 'ABCD', 'network_protocol': 'tcp', 'network_tunnel_type': 'N/A', 'alert_definitions_version': 'AppThreat-0-0', 'destination_nat_ip': 'aaa.aaa.aaa.aaa', 'pan_log_action': 'default', 'pan_http2': '0', 'source_nat_ip': 'ddd.ddd.ddd.ddd', '_id': '1acb0472-0923-11eb-a959-000c29d42d8e', 'destination_nat_port': 443, 'http_url_category': 'news,low-risk', 'policy_uid': '4093544d-2f66-4d80-af2d-17f361609984', 'destination_port': 443, 'pan_log_panorama': '0xa000000000000000', 'pan_tunnel_id': '0', 'pan_alert_direction': 'client-to-server', 'vendor_alert_severity': 'informational', 'event_uid': '7665475', 'destination_location_name': 'United States', 'source_port': 61323, 'event_log_name': 'THREAT', 'event_repeat_count': 1, 'timestamp': '2020-10-08T04:59:55.169Z', 'event_source_product': 'PAN', 'source_nat_port': 48189, 'destination_zone': 'Untrust-L3', 'session_id': 23366, 'message': '1,2020/10/08 07:59:53,ABCDEFGHIJK,THREAT,url,2560,2020/10/08 07:59:53,ccc.ccc.ccc.ccc,aaa.aaa.aaa.aaa,ddd.ddd.ddd.ddd,aaa.aaa.aaa.aaa,FromTrust,,,ssl,vsys1,Trust-L3,Untrust-L3,ethernet1/3,ethernet1/4,default,2020/10/08 07:59:53,23366,1,61323,443,48189,443,0x816400,tcp,alert,"\<query here\>/",(9999),news,informational,client-to-server,7665475,0xa000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,0,0,0,0,0,,PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,,"news,low-risk",4093544d-2f66-4d80-af2d-17f361609984,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2020-10-08T07:59:54.289+03:00,,,', 'alert_category': 'news', 'pan_parent_session_id': '0', 'host_id': 'ABCDEFGHIJK', 'network_interface_in': 'ethernet1/3', 'pan_wildfire_report_id': 0, 'pan_pcap_id': '0', 'pan_flags': '0x816400', 'pan_assoc_id': 0, 'pan_monitor_tag': 0}, 'index': 'graylog_0', 'decoration_stats': None},<br/>{'highlight_ranges': {}, 'message': {'event_received_time': '2020/10/08 07:59:53', 'pan_log_subtype': 'url', 'gl2_remote_ip': 'bbb.bbb.bbb.bbb', 'gl2_remote_port': 51371, 'pan_dev_group_level_4': 0, 'pan_dev_group_level_3': 0, 'network_interface_out': 'ethernet1/4', 'source': 'PA-220', 'gl2_source_input': '5f7433f60f4d9c360092a070', 'pan_url_index': 0, 'vendor_event_action': 'alert', 'pan_dev_group_level_2': 0, 'pan_dev_group_level_1': 0, 'source_ip': 'ccc.ccc.ccc.ccc', 'host_virtfw_id': 'vsys1', 'application_name': 'ssl', 'destination_ip': 'aaa.aaa.aaa.aaa', 'pan_ppid': 4294967295, 'gl2_source_node': '95ba5102-13c9-4520-ac75-c8736f206953', 'alert_indicator': '\<query here\>/', 'host_hostname': 'PA-220', 'source_location_name': '192.168.0.0-192.168.255.255', 'gl2_accounted_message_size': 2027, 'alert_signature_id': '(9999)', 'rule_name': 'FromTrust', 'source_zone': 'Trust-L3', 'streams': ['000000000000000000000001'], 'gl2_message_id': 'ABCD', 'network_protocol': 'tcp', 'network_tunnel_type': 'N/A', 'alert_definitions_version': 'AppThreat-0-0', 'destination_nat_ip': 'aaa.aaa.aaa.aaa', 'pan_log_action': 'default', 'pan_http2': '0', 'source_nat_ip': 'ddd.ddd.ddd.ddd', '_id': '1acb0470-0923-11eb-a959-000c29d42d8e', 'destination_nat_port': 443, 'http_url_category': 'news,low-risk', 'policy_uid': '4093544d-2f66-4d80-af2d-17f361609984', 'destination_port': 443, 'pan_log_panorama': '0xa000000000000000', 'pan_tunnel_id': '0', 'pan_alert_direction': 'client-to-server', 'vendor_alert_severity': 'informational', 'event_uid': '7665473', 'destination_location_name': 'United States', 'source_port': 61322, 'event_log_name': 'THREAT', 'event_repeat_count': 1, 'timestamp': '2020-10-08T04:59:55.169Z', 'event_source_product': 'PAN', 'source_nat_port': 29959, 'destination_zone': 'Untrust-L3', 'session_id': 24085, 'message': '1,2020/10/08 07:59:53,ABCDEFGHIJK,THREAT,url,2560,2020/10/08 07:59:53,ccc.ccc.ccc.ccc,aaa.aaa.aaa.aaa,ddd.ddd.ddd.ddd,aaa.aaa.aaa.aaa,FromTrust,,,ssl,vsys1,Trust-L3,Untrust-L3,ethernet1/3,ethernet1/4,default,2020/10/08 07:59:53,24085,1,61322,443,29959,443,0x816400,tcp,alert,"\<query here\>/",(9999),news,informational,client-to-server,7665473,0xa000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,0,0,0,0,0,,PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,,"news,low-risk",4093544d-2f66-4d80-af2d-17f361609984,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2020-10-08T07:59:54.289+03:00,,,', 'alert_category': 'news', 'pan_parent_session_id': '0', 'host_id': 'ABCDEFGHIJK', 'network_interface_in': 'ethernet1/3', 'pan_wildfire_report_id': 0, 'pan_pcap_id': '0', 'pan_flags': '0x816400', 'pan_assoc_id': 0, 'pan_monitor_tag': 0}, 'index': 'graylog_0', 'decoration_stats': None} | \<query here\> | 11 | 2020-10-08T10:08:57.306Z | 2 | {'index_name': 'graylog_0', 'begin': '1970-01-01T00:00:00.000Z', 'end': '1970-01-01T00:00:00.000Z', 'calculated_at': '2020-09-30T07:24:40.163Z', 'took_ms': 0} |


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
| sort_direction | Ascending or Descending | Optional | 
| per_page | how many per page (integer) | Optional | 
| timerange | Relative timerange to search in seconds | Optional | 
| sort_by | how to sort | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Graylog.EventsSearch | String | Result of Events Search | 


#### Command Example
```!graylog-events-search query=gmail timerange=1000```

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
                        "title": "Gmail"
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
            "duration": 4,
            "events": [
                {
                    "event": {
                        "alert": false,
                        "event_definition_id": "5f7436c60f4d9c360092a3ac",
                        "event_definition_type": "aggregation-v1",
                        "fields": {},
                        "id": "ABCD",
                        "key": null,
                        "key_tuple": [],
                        "message": "Gmail",
                        "origin_context": "urn:graylog:message:es:graylog_0:e6befc60-094d-11eb-a959-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-08T10:06:16.169Z",
                        "timestamp_processing": "2020-10-08T10:07:04.269Z"
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
                        "id": "ABCD",
                        "key": null,
                        "key_tuple": [],
                        "message": "Gmail",
                        "origin_context": "urn:graylog:message:es:graylog_0:c265df01-094d-11eb-a959-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-08T10:05:15.169Z",
                        "timestamp_processing": "2020-10-08T10:07:04.269Z"
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
                        "id": "ABCD",
                        "key": null,
                        "key_tuple": [],
                        "message": "Gmail",
                        "origin_context": "urn:graylog:message:es:graylog_0:9e9e0521-094d-11eb-a959-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-08T10:04:15.169Z",
                        "timestamp_processing": "2020-10-08T10:07:04.269Z"
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
                        "id": "ABCD",
                        "key": null,
                        "key_tuple": [],
                        "message": "Gmail",
                        "origin_context": "urn:graylog:message:es:graylog_0:7ad9d4c1-094d-11eb-a959-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-08T10:03:15.169Z",
                        "timestamp_processing": "2020-10-08T10:07:04.269Z"
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
                        "id": "ABCD",
                        "key": null,
                        "key_tuple": [],
                        "message": "Gmail",
                        "origin_context": "urn:graylog:message:es:graylog_0:571c5b22-094d-11eb-a959-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-08T10:02:16.169Z",
                        "timestamp_processing": "2020-10-08T10:07:04.269Z"
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
                        "id": "ABCD",
                        "key": null,
                        "key_tuple": [],
                        "message": "Gmail",
                        "origin_context": "urn:graylog:message:es:graylog_0:3351e930-094d-11eb-a959-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-08T10:01:16.169Z",
                        "timestamp_processing": "2020-10-08T10:02:04.510Z"
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
                        "id": "ABCD",
                        "key": null,
                        "key_tuple": [],
                        "message": "Gmail",
                        "origin_context": "urn:graylog:message:es:graylog_0:10cb68f1-094d-11eb-a959-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-08T10:00:17.169Z",
                        "timestamp_processing": "2020-10-08T10:02:04.510Z"
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
                        "id": "ABCD",
                        "key": null,
                        "key_tuple": [],
                        "message": "Gmail",
                        "origin_context": "urn:graylog:message:es:graylog_0:ef65e911-094c-11eb-a959-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-08T09:59:21.169Z",
                        "timestamp_processing": "2020-10-08T10:02:04.510Z"
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
                        "id": "ABCD",
                        "key": null,
                        "key_tuple": [],
                        "message": "Gmail",
                        "origin_context": "urn:graylog:message:es:graylog_0:c805f451-094c-11eb-a959-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-08T09:58:15.169Z",
                        "timestamp_processing": "2020-10-08T10:02:04.510Z"
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
                        "id": "ABCD",
                        "key": null,
                        "key_tuple": [],
                        "message": "Gmail",
                        "origin_context": "urn:graylog:message:es:graylog_0:a441c3f0-094c-11eb-a959-000c29d42d8e",
                        "priority": 1,
                        "source": "graylog",
                        "source_streams": [],
                        "streams": [
                            "000000000000000000000002"
                        ],
                        "timerange_end": null,
                        "timerange_start": null,
                        "timestamp": "2020-10-08T09:57:15.169Z",
                        "timestamp_processing": "2020-10-08T10:02:04.510Z"
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
                "query": "gmail",
                "sort_by": "timestamp",
                "sort_direction": "desc",
                "timerange": {
                    "range": 1000,
                    "type": "relative"
                }
            },
            "total_events": 14,
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
>| event_definitions: {"5f7436c60f4d9c360092a3ac": {"id": "5f7436c60f4d9c360092a3ac", "title": "Gmail", "description": ""}}<br/>streams: {"000000000000000000000002": {"id": "000000000000000000000002", "title": "All events", "description": "Stream containing all events created by Graylog"}} | 4 | {'event': {'id': 'ABCD', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:e6befc60-094d-11eb-a959-000c29d42d8e', 'timestamp': '2020-10-08T10:06:16.169Z', 'timestamp_processing': '2020-10-08T10:07:04.269Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': 'Gmail', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'ABCD', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:c265df01-094d-11eb-a959-000c29d42d8e', 'timestamp': '2020-10-08T10:05:15.169Z', 'timestamp_processing': '2020-10-08T10:07:04.269Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': 'Gmail', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'ABCD', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:9e9e0521-094d-11eb-a959-000c29d42d8e', 'timestamp': '2020-10-08T10:04:15.169Z', 'timestamp_processing': '2020-10-08T10:07:04.269Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': 'Gmail', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'ABCD', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:7ad9d4c1-094d-11eb-a959-000c29d42d8e', 'timestamp': '2020-10-08T10:03:15.169Z', 'timestamp_processing': '2020-10-08T10:07:04.269Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': 'Gmail', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'ABCD', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:571c5b22-094d-11eb-a959-000c29d42d8e', 'timestamp': '2020-10-08T10:02:16.169Z', 'timestamp_processing': '2020-10-08T10:07:04.269Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': 'Gmail', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'ABCD', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:3351e930-094d-11eb-a959-000c29d42d8e', 'timestamp': '2020-10-08T10:01:16.169Z', 'timestamp_processing': '2020-10-08T10:02:04.510Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': 'Gmail', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'ABCD', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:10cb68f1-094d-11eb-a959-000c29d42d8e', 'timestamp': '2020-10-08T10:00:17.169Z', 'timestamp_processing': '2020-10-08T10:02:04.510Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': 'Gmail', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'ABCD', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:ef65e911-094c-11eb-a959-000c29d42d8e', 'timestamp': '2020-10-08T09:59:21.169Z', 'timestamp_processing': '2020-10-08T10:02:04.510Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': 'Gmail', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'ABCD', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:c805f451-094c-11eb-a959-000c29d42d8e', 'timestamp': '2020-10-08T09:58:15.169Z', 'timestamp_processing': '2020-10-08T10:02:04.510Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': 'Gmail', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'},<br/>{'event': {'id': 'ABCD', 'event_definition_type': 'aggregation-v1', 'event_definition_id': '5f7436c60f4d9c360092a3ac', 'origin_context': 'urn:graylog:message:es:graylog_0:a441c3f0-094c-11eb-a959-000c29d42d8e', 'timestamp': '2020-10-08T09:57:15.169Z', 'timestamp_processing': '2020-10-08T10:02:04.510Z', 'timerange_start': None, 'timerange_end': None, 'streams': ['000000000000000000000002'], 'source_streams': [], 'message': 'Gmail', 'source': 'graylog', 'key_tuple': [], 'key': None, 'priority': 1, 'alert': False, 'fields': {}}, 'index_name': 'gl-events_1', 'index_type': 'message'} | page: 1<br/>per_page: 10<br/>timerange: {"type": "relative", "range": 1000}<br/>query: gmail<br/>filter: {"alerts": "include", "event_definitions": []}<br/>sort_by: timestamp<br/>sort_direction: desc | 14 | gl-events_1,<br/>gl-system-events_1 |


### graylog-search-absolute
***
Search with absolute times


#### Base Command

`graylog-search-absolute`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query in lucene syntax | Required | 
| from | Search for messages using an absolute timerange, specified as from/to with format yyyy-MM-ddTHH:mm:ss.SSSZ (e.g. 2014-01-23T15:34:49.000Z) or yyyy-MM-dd HH:mm:ss. | Required | 
| to | Search for messages using an absolute timerange, specified as from/to with format yyyy-MM-ddTHH:mm:ss.SSSZ (e.g. 2014-01-23T15:34:49.000Z) or yyyy-MM-dd HH:mm:ss. | Required | 
| limit | Maximum number of messages to return. | Optional | 
| offset | Offset | Optional | 
| filter | Filter | Optional | 
| fields | Comma separated list of fields to return | Optional | 
| sort | Sorting (field:asc / field:desc) | Optional | 
| decorate | Run decorators on search result | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Graylog.SearchAbsolute | String | Search results of Absolute search | 


#### Command Example
```!graylog-search-absolute query="\<query here\>" from=<timefrom> to=<timeto>```

#### Context Example
```json
{
    "Graylog": {
        "SearchAbsolute": {
            "built_query": "{\n  \"from\" : 0,\n  \"size\" : 20,\n  \"query\" : {\n    \"bool\" : {\n      \"must\" : [\n        {\n          \"query_string\" : {\n            \"query\" : \"\<query here\>\",\n            \"fields\" : [ ],\n            \"use_dis_max\" : true,\n            \"tie_breaker\" : 0.0,\n            \"default_operator\" : \"or\",\n            \"auto_generate_phrase_queries\" : false,\n            \"max_determinized_states\" : 10000,\n            \"allow_leading_wildcard\" : false,\n            \"enable_position_increments\" : true,\n            \"fuzziness\" : \"AUTO\",\n            \"fuzzy_prefix_length\" : 0,\n            \"fuzzy_max_expansions\" : 50,\n            \"phrase_slop\" : 0,\n            \"escape\" : false,\n            \"split_on_whitespace\" : true,\n            \"boost\" : 1.0\n          }\n        }\n      ],\n      \"filter\" : [\n        {\n          \"bool\" : {\n            \"must\" : [\n              {\n                \"range\" : {\n                  \"timestamp\" : {\n                    \"from\" : \"2020-10-04 15:34:49.000\",\n                    \"to\" : \"2020-10-08 15:34:49.000\",\n                    \"include_lower\" : true,\n                    \"include_upper\" : true,\n                    \"boost\" : 1.0\n                  }\n                }\n              }\n            ],\n            \"disable_coord\" : false,\n            \"adjust_pure_negative\" : true,\n            \"boost\" : 1.0\n          }\n        }\n      ],\n      \"disable_coord\" : false,\n      \"adjust_pure_negative\" : true,\n      \"boost\" : 1.0\n    }\n  },\n  \"sort\" : [\n    {\n      \"timestamp\" : {\n        \"order\" : \"desc\"\n      }\n    }\n  ]\n}",
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
                "pan_dev_group_level_1",
                "source_ip",
                "host_virtfw_id",
                "application_name",
                "destination_ip",
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
            "from": "2020-10-04T15:34:49.000Z",
            "messages": [
                {
                    "decoration_stats": null,
                    "highlight_ranges": {},
                    "index": "graylog_0",
                    "message": {
                        "_id": "1acb0472-0923-11eb-a959-000c29d42d8e",
                        "alert_category": "news",
                        "alert_definitions_version": "AppThreat-0-0",
                        "alert_indicator": "\<query here\>/",
                        "alert_signature_id": "(9999)",
                        "application_name": "ssl",
                        "destination_ip": "aaa.aaa.aaa.aaa",
                        "destination_location_name": "United States",
                        "destination_nat_ip": "aaa.aaa.aaa.aaa",
                        "destination_nat_port": 443,
                        "destination_port": 443,
                        "destination_zone": "Untrust-L3",
                        "event_log_name": "THREAT",
                        "event_received_time": "2020/10/08 07:59:53",
                        "event_repeat_count": 1,
                        "event_source_product": "PAN",
                        "event_uid": "7665475",
                        "gl2_accounted_message_size": 2027,
                        "gl2_message_id": "ABCD",
                        "gl2_remote_ip": "bbb.bbb.bbb.bbb",
                        "gl2_remote_port": 51371,
                        "gl2_source_input": "5f7433f60f4d9c360092a070",
                        "gl2_source_node": "95ba5102-13c9-4520-ac75-c8736f206953",
                        "host_hostname": "PA-220",
                        "host_id": "ABCDEFGHIJK",
                        "host_virtfw_id": "vsys1",
                        "http_url_category": "news,low-risk",
                        "message": "1,2020/10/08 07:59:53,ABCDEFGHIJK,THREAT,url,2560,2020/10/08 07:59:53,ccc.ccc.ccc.ccc,aaa.aaa.aaa.aaa,ddd.ddd.ddd.ddd,aaa.aaa.aaa.aaa,FromTrust,,,ssl,vsys1,Trust-L3,Untrust-L3,ethernet1/3,ethernet1/4,default,2020/10/08 07:59:53,23366,1,61323,443,48189,443,0x816400,tcp,alert,\"\<query here\>/\",(9999),news,informational,client-to-server,7665475,0xa000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,0,0,0,0,0,,PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,,\"news,low-risk\",4093544d-2f66-4d80-af2d-17f361609984,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2020-10-08T07:59:54.289+03:00,,,",
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
                        "session_id": 23366,
                        "source": "PA-220",
                        "source_ip": "ccc.ccc.ccc.ccc",
                        "source_location_name": "192.168.0.0-192.168.255.255",
                        "source_nat_ip": "ddd.ddd.ddd.ddd",
                        "source_nat_port": 48189,
                        "source_port": 61323,
                        "source_zone": "Trust-L3",
                        "streams": [
                            "000000000000000000000001"
                        ],
                        "timestamp": "2020-10-08T04:59:55.169Z",
                        "vendor_alert_severity": "informational",
                        "vendor_event_action": "alert"
                    }
                },
                {
                    "decoration_stats": null,
                    "highlight_ranges": {},
                    "index": "graylog_0",
                    "message": {
                        "_id": "1acb0470-0923-11eb-a959-000c29d42d8e",
                        "alert_category": "news",
                        "alert_definitions_version": "AppThreat-0-0",
                        "alert_indicator": "\<query here\>/",
                        "alert_signature_id": "(9999)",
                        "application_name": "ssl",
                        "destination_ip": "aaa.aaa.aaa.aaa",
                        "destination_location_name": "United States",
                        "destination_nat_ip": "aaa.aaa.aaa.aaa",
                        "destination_nat_port": 443,
                        "destination_port": 443,
                        "destination_zone": "Untrust-L3",
                        "event_log_name": "THREAT",
                        "event_received_time": "2020/10/08 07:59:53",
                        "event_repeat_count": 1,
                        "event_source_product": "PAN",
                        "event_uid": "7665473",
                        "gl2_accounted_message_size": 2027,
                        "gl2_message_id": "ABCD",
                        "gl2_remote_ip": "bbb.bbb.bbb.bbb",
                        "gl2_remote_port": 51371,
                        "gl2_source_input": "5f7433f60f4d9c360092a070",
                        "gl2_source_node": "95ba5102-13c9-4520-ac75-c8736f206953",
                        "host_hostname": "PA-220",
                        "host_id": "ABCDEFGHIJK",
                        "host_virtfw_id": "vsys1",
                        "http_url_category": "news,low-risk",
                        "message": "1,2020/10/08 07:59:53,ABCDEFGHIJK,THREAT,url,2560,2020/10/08 07:59:53,ccc.ccc.ccc.ccc,aaa.aaa.aaa.aaa,ddd.ddd.ddd.ddd,aaa.aaa.aaa.aaa,FromTrust,,,ssl,vsys1,Trust-L3,Untrust-L3,ethernet1/3,ethernet1/4,default,2020/10/08 07:59:53,24085,1,61322,443,29959,443,0x816400,tcp,alert,\"\<query here\>/\",(9999),news,informational,client-to-server,7665473,0xa000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,0,0,0,0,0,,PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,,\"news,low-risk\",4093544d-2f66-4d80-af2d-17f361609984,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2020-10-08T07:59:54.289+03:00,,,",
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
                        "session_id": 24085,
                        "source": "PA-220",
                        "source_ip": "ccc.ccc.ccc.ccc",
                        "source_location_name": "192.168.0.0-192.168.255.255",
                        "source_nat_ip": "ddd.ddd.ddd.ddd",
                        "source_nat_port": 29959,
                        "source_port": 61322,
                        "source_zone": "Trust-L3",
                        "streams": [
                            "000000000000000000000001"
                        ],
                        "timestamp": "2020-10-08T04:59:55.169Z",
                        "vendor_alert_severity": "informational",
                        "vendor_event_action": "alert"
                    }
                },
            ],
            "query": "\<query here\>",
            "time": 2,
            "to": "2020-10-08T15:34:49.000Z",
            "total_results": 2,
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
>| {<br/>  "from" : 0,<br/>  "size" : 20,<br/>  "query" : {<br/>    "bool" : {<br/>      "must" : [<br/>        {<br/>          "query_string" : {<br/>            "query" : "\<query here\>",<br/>            "fields" : [ ],<br/>            "use_dis_max" : true,<br/>            "tie_breaker" : 0.0,<br/>            "default_operator" : "or",<br/>            "auto_generate_phrase_queries" : false,<br/>            "max_determinized_states" : 10000,<br/>            "allow_leading_wildcard" : false,<br/>            "enable_position_increments" : true,<br/>            "fuzziness" : "AUTO",<br/>            "fuzzy_prefix_length" : 0,<br/>            "fuzzy_max_expansions" : 50,<br/>            "phrase_slop" : 0,<br/>            "escape" : false,<br/>            "split_on_whitespace" : true,<br/>            "boost" : 1.0<br/>          }<br/>        }<br/>      ],<br/>      "filter" : [<br/>        {<br/>          "bool" : {<br/>            "must" : [<br/>              {<br/>                "range" : {<br/>                  "timestamp" : {<br/>                    "from" : "2020-10-04 15:34:49.000",<br/>                    "to" : "2020-10-08 15:34:49.000",<br/>                    "include_lower" : true,<br/>                    "include_upper" : true,<br/>                    "boost" : 1.0<br/>                  }<br/>                }<br/>              }<br/>            ],<br/>            "disable_coord" : false,<br/>            "adjust_pure_negative" : true,<br/>            "boost" : 1.0<br/>          }<br/>        }<br/>      ],<br/>      "disable_coord" : false,<br/>      "adjust_pure_negative" : true,<br/>      "boost" : 1.0<br/>    }<br/>  },<br/>  "sort" : [<br/>    {<br/>      "timestamp" : {<br/>        "order" : "desc"<br/>      }<br/>    }<br/>  ]<br/>} |  | event_received_time,<br/>pan_log_subtype,<br/>pan_dev_group_level_4,<br/>pan_dev_group_level_3,<br/>network_interface_out,<br/>source,<br/>pan_url_index,<br/>vendor_event_action,<br/>pan_dev_group_level_2,<br/>pan_dev_group_level_1,<br/>source_ip,<br/>host_virtfw_id,<br/>application_name,<br/>destination_ip,<br/>pan_ppid,<br/>alert_indicator,<br/>host_hostname,<br/>source_location_name,<br/>alert_signature_id,<br/>rule_name,<br/>source_zone,<br/>gl2_message_id,<br/>network_protocol,<br/>network_tunnel_type,<br/>alert_definitions_version,<br/>destination_nat_ip,<br/>pan_log_action,<br/>pan_http2,<br/>source_nat_ip,<br/>destination_nat_port,<br/>http_url_category,<br/>policy_uid,<br/>destination_port,<br/>pan_log_panorama,<br/>pan_tunnel_id,<br/>pan_alert_direction,<br/>vendor_alert_severity,<br/>event_uid,<br/>destination_location_name,<br/>source_port,<br/>event_log_name,<br/>event_repeat_count,<br/>timestamp,<br/>event_source_product,<br/>source_nat_port,<br/>destination_zone,<br/>session_id,<br/>message,<br/>alert_category,<br/>pan_parent_session_id,<br/>host_id,<br/>network_interface_in,<br/>pan_wildfire_report_id,<br/>pan_pcap_id,<br/>pan_flags,<br/>pan_assoc_id,<br/>pan_monitor_tag | 2020-10-04T15:34:49.000Z | {'highlight_ranges': {}, 'message': {'event_received_time': '2020/10/08 07:59:53', 'pan_log_subtype': 'url', 'gl2_remote_ip': 'bbb.bbb.bbb.bbb', 'gl2_remote_port': 51371, 'pan_dev_group_level_4': 0, 'pan_dev_group_level_3': 0, 'network_interface_out': 'ethernet1/4', 'source': 'PA-220', 'gl2_source_input': '5f7433f60f4d9c360092a070', 'pan_url_index': 0, 'vendor_event_action': 'alert', 'pan_dev_group_level_2': 0, 'pan_dev_group_level_1': 0, 'source_ip': 'ccc.ccc.ccc.ccc', 'host_virtfw_id': 'vsys1', 'application_name': 'ssl', 'destination_ip': 'aaa.aaa.aaa.aaa', 'pan_ppid': 4294967295, 'gl2_source_node': '95ba5102-13c9-4520-ac75-c8736f206953', 'alert_indicator': '\<query here\>/', 'host_hostname': 'PA-220', 'source_location_name': '192.168.0.0-192.168.255.255', 'gl2_accounted_message_size': 2027, 'alert_signature_id': '(9999)', 'rule_name': 'FromTrust', 'source_zone': 'Trust-L3', 'streams': ['000000000000000000000001'], 'gl2_message_id': 'ABCD', 'network_protocol': 'tcp', 'network_tunnel_type': 'N/A', 'alert_definitions_version': 'AppThreat-0-0', 'destination_nat_ip': 'aaa.aaa.aaa.aaa', 'pan_log_action': 'default', 'pan_http2': '0', 'source_nat_ip': 'ddd.ddd.ddd.ddd', '_id': '1acb0472-0923-11eb-a959-000c29d42d8e', 'destination_nat_port': 443, 'http_url_category': 'news,low-risk', 'policy_uid': '4093544d-2f66-4d80-af2d-17f361609984', 'destination_port': 443, 'pan_log_panorama': '0xa000000000000000', 'pan_tunnel_id': '0', 'pan_alert_direction': 'client-to-server', 'vendor_alert_severity': 'informational', 'event_uid': '7665475', 'destination_location_name': 'United States', 'source_port': 61323, 'event_log_name': 'THREAT', 'event_repeat_count': 1, 'timestamp': '2020-10-08T04:59:55.169Z', 'event_source_product': 'PAN', 'source_nat_port': 48189, 'destination_zone': 'Untrust-L3', 'session_id': 23366, 'message': '1,2020/10/08 07:59:53,ABCDEFGHIJK,THREAT,url,2560,2020/10/08 07:59:53,ccc.ccc.ccc.ccc,aaa.aaa.aaa.aaa,ddd.ddd.ddd.ddd,aaa.aaa.aaa.aaa,FromTrust,,,ssl,vsys1,Trust-L3,Untrust-L3,ethernet1/3,ethernet1/4,default,2020/10/08 07:59:53,23366,1,61323,443,48189,443,0x816400,tcp,alert,"\<query here\>/",(9999),news,informational,client-to-server,7665475,0xa000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,0,0,0,0,0,,PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,,"news,low-risk",4093544d-2f66-4d80-af2d-17f361609984,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2020-10-08T07:59:54.289+03:00,,,', 'alert_category': 'news', 'pan_parent_session_id': '0', 'host_id': 'ABCDEFGHIJK', 'network_interface_in': 'ethernet1/3', 'pan_wildfire_report_id': 0, 'pan_pcap_id': '0', 'pan_flags': '0x816400', 'pan_assoc_id': 0, 'pan_monitor_tag': 0}, 'index': 'graylog_0', 'decoration_stats': None},<br/>{'highlight_ranges': {}, 'message': {'event_received_time': '2020/10/08 07:59:53', 'pan_log_subtype': 'url', 'gl2_remote_ip': 'bbb.bbb.bbb.bbb', 'gl2_remote_port': 51371, 'pan_dev_group_level_4': 0, 'pan_dev_group_level_3': 0, 'network_interface_out': 'ethernet1/4', 'source': 'PA-220', 'gl2_source_input': '5f7433f60f4d9c360092a070', 'pan_url_index': 0, 'vendor_event_action': 'alert', 'pan_dev_group_level_2': 0, 'pan_dev_group_level_1': 0, 'source_ip': 'ccc.ccc.ccc.ccc', 'host_virtfw_id': 'vsys1', 'application_name': 'ssl', 'destination_ip': 'aaa.aaa.aaa.aaa', 'pan_ppid': 4294967295, 'gl2_source_node': '95ba5102-13c9-4520-ac75-c8736f206953', 'alert_indicator': '\<query here\>/', 'host_hostname': 'PA-220', 'source_location_name': '192.168.0.0-192.168.255.255', 'gl2_accounted_message_size': 2027, 'alert_signature_id': '(9999)', 'rule_name': 'FromTrust', 'source_zone': 'Trust-L3', 'streams': ['000000000000000000000001'], 'gl2_message_id': 'ABCD', 'network_protocol': 'tcp', 'network_tunnel_type': 'N/A', 'alert_definitions_version': 'AppThreat-0-0', 'destination_nat_ip': 'aaa.aaa.aaa.aaa', 'pan_log_action': 'default', 'pan_http2': '0', 'source_nat_ip': 'ddd.ddd.ddd.ddd', '_id': '1acb0470-0923-11eb-a959-000c29d42d8e', 'destination_nat_port': 443, 'http_url_category': 'news,low-risk', 'policy_uid': '4093544d-2f66-4d80-af2d-17f361609984', 'destination_port': 443, 'pan_log_panorama': '0xa000000000000000', 'pan_tunnel_id': '0', 'pan_alert_direction': 'client-to-server', 'vendor_alert_severity': 'informational', 'event_uid': '7665473', 'destination_location_name': 'United States', 'source_port': 61322, 'event_log_name': 'THREAT', 'event_repeat_count': 1, 'timestamp': '2020-10-08T04:59:55.169Z', 'event_source_product': 'PAN', 'source_nat_port': 29959, 'destination_zone': 'Untrust-L3', 'session_id': 24085, 'message': '1,2020/10/08 07:59:53,ABCDEFGHIJK,THREAT,url,2560,2020/10/08 07:59:53,ccc.ccc.ccc.ccc,aaa.aaa.aaa.aaa,ddd.ddd.ddd.ddd,aaa.aaa.aaa.aaa,FromTrust,,,ssl,vsys1,Trust-L3,Untrust-L3,ethernet1/3,ethernet1/4,default,2020/10/08 07:59:53,24085,1,61322,443,29959,443,0x816400,tcp,alert,"\<query here\>/",(9999),news,informational,client-to-server,7665473,0xa000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,0,0,0,0,0,,PA-220,,,,,0,,0,,N/A,unknown,AppThreat-0-0,0x0,0,4294967295,,"news,low-risk",4093544d-2f66-4d80-af2d-17f361609984,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2020-10-08T07:59:54.289+03:00,,,', 'alert_category': 'news', 'pan_parent_session_id': '0', 'host_id': 'ABCDEFGHIJK', 'network_interface_in': 'ethernet1/3', 'pan_wildfire_report_id': 0, 'pan_pcap_id': '0', 'pan_flags': '0x816400', 'pan_assoc_id': 0, 'pan_monitor_tag': 0}, 'index': 'graylog_0', 'decoration_stats': None} | \<query here\> | 2 | 2020-10-08T15:34:49.000Z | 2 | {'index_name': 'graylog_0', 'begin': '1970-01-01T00:00:00.000Z', 'end': '1970-01-01T00:00:00.000Z', 'calculated_at': '2020-09-30T07:24:40.163Z', 'took_ms': 0} |

