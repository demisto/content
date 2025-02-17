This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Netskope Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API token |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Max events per fetch | The maximum amount of events to retrieve per each event type. For more information about event types see the help section. | False |


## Fetch Events Limitation

The collector can handle up to 35K events per minute on average. 

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### netskope-get-events

***
Returns events extracted from SaaS traffic and or logs.


#### Base Command

`netskope-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of alerts to return (maximum value - 10000). | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. | Optional | 


#### Context Output

There is no context output for this command.

#### Command example

```!netskope-get-events limit=1```

#### Context Example

```json
{
    "Netskope": {
        "Event": [
            {
                "_category_id": "8",
                "_correlation_id": "c66ef426-b403-4be5-8052-05d2c81ed321",
                "_ef_received_at": 1658102836562,
                "_event_id": "bd1074e2-fcbc-4c02-98f1-357aeb57f6c8",
                "_forwarded_by": "service-event-forwarder",
                "_gef_src_dp": "NL-AAA",
                "_id": "23a372c433381a6a11798123",
                "_insertion_epoch_timestamp": 1658102843,
                "_raw_event_inserted_at": 1658102836720,
                "_service_identifier": "service-test",
                "access_method": "API Connector",
                "acked": "false",
                "action": "anomaly_detection",
                "activity": "Login Successful",
                "alert": "yes",
                "alert_id": "62d4a3c35b8bdd69ad5e1234",
                "alert_name": "Alert Name",
                "alert_type": "test",
                "anomalyData": {
                    "_t": "CategoricalModeling",
                    "binCount": 6,
                    "convergenceFactor": 0.9863013699,
                    "featureValue": "1.1.1.1",
                    "histo": [
                        {
                            "bin": "2.2.2.2",
                            "count": 205
                        },
                        {
                            "bin": "3.3.3.3",
                            "count": 30
                        },
                        {
                            "bin": "4.4.4.4",
                            "count": 1
                        }
                    ],
                    "modelId": "test",
                    "observationCount": 0,
                    "percentileThresholdCount": 6,
                    "probability": 0,
                    "sampleCount": 438,
                    "scope": "User"
                },
                "anomaly_type": "test-type",
                "app": "Microsoft Office 365 Sharepoint Online",
                "appcategory": "Collaboration",
                "category": "Collaboration",
                "cci": 91,
                "ccl": "excellent",
                "count": 1,
                "createdTime": "2022-07-18 00:05:23.321000",
                "event_type": "alert",
                "instance_id": "test-instance",
                "organization_unit": "test",
                "other_categories": [],
                "score": 75,
                "severity": "Low",
                "site": "Microsoft Office 365 Sharepoint Sites",
                "src_country": "PH",
                "src_geoip_src": 2,
                "src_latitude": 456.789,
                "src_location": "Test",
                "src_longitude": 123.456,
                "src_region": "Province of Somewhere",
                "src_zipcode": "1234",
                "srcip": "6.6.6.6",
                "timestamp": "2022-07-17T23:48:52.000Z",
                "traffic_type": "CloudApp",
                "type": "nspolicy",
                "ur_normalized": "test@test.com",
                "user": "test@test.com",
                "userkey": "test@test.com",
                "windowId": 1658016000000
            },
            {
                "_category_id": "8",
                "_correlation_id": "57e53633-3eb9-4055-9e84-07de4c367347",
                "_ef_received_at": 1656449549192,
                "_event_id": "7dc94895-fe14-456d-b9c8-0a7f0dac5064",
                "_forwarded_by": "service-event-forwarder",
                "_gef_src_dp": "ABCD",
                "_id": "9f806593aa4385e4fc14865c",
                "_insertion_epoch_timestamp": 1656449557,
                "_raw_event_inserted_at": 1656449549850,
                "_service_identifier": "service-introspection",
                "_session_begin": 1,
                "access_method": "API Connector",
                "activity": "Login Successful",
                "alert": "no",
                "app": "Microsoft Office 365 Sharepoint Online",
                "app_activity": "UserLoggedIn",
                "app_session_id": 6162799428773683,
                "appcategory": "Collaboration",
                "browser": "unknown",
                "category": "Collaboration",
                "cci": 91,
                "ccl": "excellent",
                "count": 1,
                "device": "Other",
                "dst_latitude": "",
                "dst_longitude": "",
                "event_type": "application",
                "from_user": "test@test.com",
                "instance_id": "some-instance",
                "netskope_activity": "False",
                "object": "test@test.com",
                "object_id": "test@test.com",
                "object_type": "User",
                "organization_unit": "test",
                "os": "unknown",
                "other_categories": [],
                "site": "Microsoft Office 365 Sharepoint Sites",
                "src_country": "PH",
                "src_geoip_src": 2,
                "src_latitude": 456,
                "src_location": "test",
                "src_longitude": 123,
                "src_region": "Province of Test",
                "src_zipcode": "1234",
                "srcip": "2.2.2.2",
                "timestamp": "2022-06-28T16:59:15.000Z",
                "traffic_type": "CloudApp",
                "type": "nspolicy",
                "ur_normalized": "test@test.com",
                "user": "test@test.com",
                "userip": "2.2.2.2",
                "userkey": "test@test.com"
            },
            {
                "_id": "efac69202c964c91fd59bcb9",
                "_insertion_epoch_timestamp": 1658331170,
                "audit_log_event": "Client Disable Request Submitted",
                "ccl": "unknown",
                "count": 1,
                "event_type": "audit",
                "organization_unit": "test",
                "severity_level": 1,
                "supporting_data": {
                    "data_type": "hostname",
                    "data_values": "HAMRGBCNX147"
                },
                "timestamp": "2022-07-20T15:27:50.000Z",
                "type": "admin_audit_logs",
                "ur_normalized": "test@test.com",
                "user": "test@test.com"
            },
            {
                "_correlation_id": "5f3e3987-115c-4fed-9c5e-f69e184069af",
                "_ef_received_at": 1657742097188,
                "_event_id": "bd3de3e3-378e-4e01-ba8d-a5d72565bde7",
                "_forwarded_by": "msg-relayer",
                "_gef_src_dp": "IN-AAA1",
                "_id": "e03cf756afc2a707666fcbc0",
                "_insertion_epoch_timestamp": 1657742104,
                "_raw_event_inserted_at": 1657742097698,
                "_service_identifier": "service-npa",
                "_tenant_id": "test-tenant",
                "access_method": "Client",
                "action": "allow",
                "app": "[CS SEG's]",
                "appcategory": "n/a",
                "category": "",
                "cci": 0,
                "ccl": "unknown",
                "client_bytes": 1593,
                "client_packets": 13,
                "count": 1,
                "device": "Windows",
                "dsthost": "8.8.8.8",
                "dstip": "",
                "dstport": 443,
                "end_time": "2022-07-13T19:53:02+00:00",
                "event_type": "network",
                "hostname": "L-101861180",
                "ip_protocol": "TCP",
                "netskope_pop": "IN-AAA1",
                "network_session_id": "12345678",
                "num_sessions": 1,
                "numbytes": 2387,
                "organization_unit": "test",
                "os": "Windows",
                "os_version": "10.0 (2009)",
                "policy": "Netskope Private Apps Allowed",
                "protocol": "Http",
                "protocol_port": "TCP:443",
                "publisher_cn": "abcd1234",
                "publisher_name": "test",
                "server_bytes": 794,
                "server_packets": 11,
                "session_duration": 23461,
                "site": "1.1.1.1",
                "srcip": "",
                "srcport": 447,
                "start_time": "2022-07-13T19:52:51+00:00",
                "timestamp": "2022-07-13T19:54:57.000Z",
                "total_packets": 24,
                "traffic_type": "PrivateApp",
                "tunnel_id": "1150",
                "tunnel_type": "NPA",
                "tunnel_up_time": 23461,
                "type": "network",
                "ur_normalized": "test@test.com",
                "user": "test@test.com",
                "userip": "",
                "userkey": "test@test.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Events List:

>|Id|Timestamp|Type|Access Method|App|Traffic Type|
>|---|---|---|---|---|---|
>| 23a372c433381a6a11798123 | 2022-07-17T23:48:52.000Z | nspolicy | API Connector | Microsoft Office 365 Sharepoint Online | CloudApp |
>| 9f806593aa4385e4fc14865c | 2022-06-28T16:59:15.000Z | nspolicy | API Connector | Microsoft Office 365 Sharepoint Online | CloudApp |
>| efac69202c964c91fd59bcb9 | 2022-07-20T15:27:50.000Z | admin_audit_logs |  |  |  |
>| e03cf756afc2a707666fcbc0 | 2022-07-13T19:54:57.000Z | network | Client | [CS SEG's] | PrivateApp |
