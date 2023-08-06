Exabeam Data Lake provides a highly scalable, cost-effective, and searchable log management system. Data Lake is used for log collection, storage, processing, and presentation.

This integration was integrated and tested with version DL-i40.3 of Exabeam Data Lake

## Configure Exabeam Data Lake on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Exabeam Data Lake.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | User Name | True |
    | Password | True |
    | Trust any certificate (not secure) |  |
    | Use system proxy settings |  |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### exabeam-data-lake-query

***
Get events from Exabeam Data Lake.

#### Base Command

`exabeam-data-lake-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The search query string to filter the events. (examples in the table below.) | Optional | 
| start_time | The time to start getting results. specified as ISO-8601 strings for example: "2021-01-27T12:43:26.243Z". | Optional | 
| end_time | The time to stop getting results. specified as ISO-8601 strings for example: "2021-02-27T12:43:26.243Z". | Optional | 
| limit | The maximal number of results to return, up to 10,000. | Optional | 
| all_result | Retrieve all results from an Exabeam Data Lake query, with a maximum of 10,000 results. Possible values are: true, false. | Optional | 


## Query Argument - Examples

| **Use Case**   |  **SEARCH** |  
|----------|:-------------:|
| Search for all logs ingested in DL: | * |
| Search for all logs from user "barbara salazar": |  user:"barbara salazar" |
| Search for all vpn logs:	 | exa_category:VPN |
| Search for Windows Event logs with the code number 4624 ("An account was successfully logged on"): | exa_category:"Windows Authentication" AND event_code:4624 |
| Search for successful traffic to the internet: | exa_category:Network AND data_type:networkfw-allow AND NOT dest_ip:[10.0.0.0 TO 10.255.255.255] |

#### Command example

```!exabeam-data-lake-query query=VPN limit=3```

#### Context Example

```json
{
    "ExabeamDataLake": {
        "Log": [
            {
                "_id": "test_id_1",
                "_index": "exabeam-2023",
                "_routing": "test_routing_1",
                "_score": null,
                "_source": {
                    "@timestamp": "2023-07-12T23:59:57.458Z",
                    "@version": "1",
                    "Product": "test_product_1",
                    "Vendor": "test_vendor_1",
                    "action": "Accept",
                    "app_protocol": "test",
                    "data_type": "network",
                    "dest_ip": "test_dest_ip_1",
                    "dest_port": 00,
                    "dest_translated_ip": "0.0.0.0",
                    "dest_translated_port": "0",
                    "direction": "inbound",
                    "event_name": "Accept",
                    "exa-message-size": 1006,
                    "exa_activity_type": [
                        "network"
                    ],
                    "exa_adjustedEventTime": "2023-07-12T23:55:05.000Z",
                    "exa_category": "Network",
                    "exa_device_type": [
                        "network",
                        "network"
                    ],
                    "exa_outcome": [
                        "success"
                    ],
                    "exa_parser_name": "test_parser_name_1",
                    "exa_rawEventTime": "2023-07-12T23:55:05.000Z",
                    "exa_rsc": {
                        "hostname": "localhost",
                        "time_off": 10800,
                        "timestamp": "2023-07-12T23:59:58.459Z",
                        "timezone": "+00"
                    },
                    "forwarder": "test_forwarder_1",
                    "host": "local",
                    "indexTime": "2023-07-12T23:59:59.298Z",
                    "interface_name": "test",
                    "is_ransomware_dest_ip": false,
                    "is_ransomware_src_ip": false,
                    "is_threat_dest_ip": false,
                    "is_threat_src_ip": false,
                    "is_tor_dest_ip": false,
                    "is_tor_src_ip": false,
                    "message": "<134>1 2023-07-12T23:55:05Z",
                    "origin_ip": "test_origin_ip_1",
                    "outcome": "Accept",
                    "product_name": "VPN",
                    "protocol": "00",
                    "rule": "test rule",
                    "rule_id": "test_rule_id_1",
                    "src_ip": "test_src_ip_1",
                    "src_port": 000,
                    "src_translated_ip": "test_src_translated_ip_1",
                    "src_translated_port": "0",
                    "time": "2023-07-12T23:55:05.000Z"
                },
                "_type": "logs",
                "sort": [
                    1689206397458
                ]
            },
            {
                "_id": "test_id_2",
                "_index": "exabeam-2023",
                "_routing": "test_routing_2",
                "_score": null,
                "_source": {
                    "@timestamp": "2023-07-12T23:59:57.458Z",
                    "@version": "2",
                    "Product": "test_product_2",
                    "Vendor": "test_vendor_2",
                    "action": "Accept",
                    "app_protocol": "test",
                    "data_type": "network-connection",
                    "dest_ip": "test_dest_ip_2",
                    "dest_port": 00,
                    "dest_translated_ip": "0.0.0.0",
                    "dest_translated_port": "0",
                    "direction": "inbound",
                    "event_name": "Accept",
                    "exa-message-size": 1006,
                    "exa_activity_type": [
                        "network"
                    ],
                    "exa_adjustedEventTime": "2023-07-12T23:55:05.000Z",
                    "exa_category": "Network",
                    "exa_device_type": [
                        "network",
                        "network"
                    ],
                    "exa_outcome": [
                        "success"
                    ],
                    "exa_parser_name": "test_parser_name_2",
                    "exa_rawEventTime": "2023-07-12T23:55:05.000Z",
                    "exa_rsc": {
                        "hostname": "localhost",
                        "time_off": 10800,
                        "timestamp": "2023-07-12T23:59:58.459Z",
                        "timezone": "+00"
                    },
                    "forwarder": "test_forwarder_2",
                    "host": "local",
                    "indexTime": "2023-07-12T23:59:59.298Z",
                    "interface_name": "test",
                    "is_ransomware_dest_ip": false,
                    "is_ransomware_src_ip": false,
                    "is_threat_dest_ip": false,
                    "is_threat_src_ip": false,
                    "is_tor_dest_ip": false,
                    "is_tor_src_ip": false,
                    "message": "<134>1 2023-07-12T23:55:05Z",
                    "origin_ip": "test_origin_ip_2",
                    "outcome": "Accept",
                    "product_name": "VPN",
                    "protocol": "00",
                    "rule": "test rule",
                    "rule_id": "test_rule_id_2",
                    "src_ip": "test_src_ip_2",
                    "src_port": 000,
                    "src_translated_ip": "test_src_translated_ip_2",
                    "src_translated_port": "0",
                    "time": "2023-07-12T23:55:05.000Z"
                },
                "_type": "logs",
                "sort": [
                    1689206397458
                ]
            },
            {
                "_id": "test_id_3",
                "_index": "exabeam-2023.07.12",
                "_routing": "test_routing_3",
                "_score": null,
                "_source": {
                    "@timestamp": "2023-07-12T23:59:57.458Z",
                    "@version": "1",
                    "Product": "test_product_3",
                    "Vendor": "test_vendor_3",
                    "action": "Accept",
                    "app_protocol": "test",
                    "data_type": "network",
                    "dest_ip": "test_dest_ip_3",
                    "dest_port": 00,
                    "dest_translated_ip": "0.0.0.0",
                    "dest_translated_port": "0",
                    "direction": "inbound",
                    "event_name": "Accept",
                    "exa-message-size": 1006,
                    "exa_activity_type": [
                        "network"
                    ],
                    "exa_adjustedEventTime": "2023-07-12T23:55:05.000Z",
                    "exa_category": "Network",
                    "exa_device_type": [
                        "network",
                        "network"
                    ],
                    "exa_outcome": [
                        "success"
                    ],
                    "exa_parser_name": "test_parser_name_3",
                    "exa_rawEventTime": "2023-07-12T23:55:05.000Z",
                    "exa_rsc": {
                        "hostname": "localhost",
                        "time_off": 10800,
                        "timestamp": "2023-07-12T23:59:58.459Z",
                        "timezone": "+00"
                    },
                    "forwarder": "test_forwarder_1",
                    "host": "local",
                    "indexTime": "2023-07-12T23:59:59.298Z",
                    "interface_name": "test",
                    "is_ransomware_dest_ip": false,
                    "is_ransomware_src_ip": false,
                    "is_threat_dest_ip": false,
                    "is_threat_src_ip": false,
                    "is_tor_dest_ip": false,
                    "is_tor_src_ip": false,
                    "message": "<134>1 2023-07-12T23:55:05Z",
                    "origin_ip": "test_origin_ip_3",
                    "outcome": "Accept",
                    "product_name": "VPN",
                    "protocol": "00",
                    "rule": "test rule",
                    "rule_id": "test_rule_id_3",
                    "src_ip": "test_src_ip_3",
                    "src_port": 000,
                    "src_translated_ip": "test_src_translated_ip_3",
                    "src_translated_port": "0",
                    "time": "2023-07-12T23:55:05.000Z"
                },
                "_type": "logs",
                "sort": [
                    1689206397458
                ]
            },
            
        ]
    }
}
```

#### Human Readable Output

>### Logs

>|Action|Event Name|ID|Product|Time|Vendor|
>|---|---|---|---|---|---|
>| Accept | Accept | test_id_1 | test_product_1 | 2023-07-12T23:55:05.000Z | test_vendor_3 |
>| Accept | Accept | test_id_2 | test_product_2 | 2023-07-12T23:55:05.000Z | test_vendor_3 |
>| Accept | Accept | test_id_3 | test_product_3 | 2023-07-12T23:55:02.000Z | test_vendor_3 |

