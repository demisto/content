Darktrace is a Cyber AI platform for threat detection and response across cloud, email, industrial, and the network.
This integration was integrated and tested with version 6.0.0 of Darktrace

## Configure Darktrace in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| isFetch | Fetch incidents | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| public_api_token | Public API Token | True |
| private_api_token | Private API Token | True |
| min_score | Minimum Score | True |
| max_alerts | Maximum Model Breaches per Fetch | False |
| first_fetch | First fetch time | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

#### Base Command

`darktrace-get-similar-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| did | Darktrace Device ID | Required | 
| max_results | Maximum number of results to return | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.SimilarDevices.deviceId | Number | Darktrace Device ID of the device with the similar devices. | 
| Darktrace.SimilarDevices.devices | Unknown | List of similar devices and their available information | 


#### Command Example

```!darktrace-get-similar-devices did=1 max_results=2```

#### Context Example

```
{
    "Darktrace": {
        "SimilarDevices": {
            "devices": [
                {
                    "did": 823,
                    "firstSeen": "2020-08-07T00:06:40.000Z",
                    "hostname": "ip-172-31-32-146",
                    "ip": "172.31.32.146",
                    "ips": [
                        {
                            "ip": "172.31.32.146",
                            "sid": 114,
                            "time": "2020-09-14 06:00:00",
                            "timems": 1600063200000
                        }
                    ],
                    "lastSeen": "2020-09-14T06:23:38.000Z",
                    "macaddress": "0a:df:4b:52:64:7a",
                    "score": 99,
                    "sid": 114,
                    "typelabel": "Server",
                    "typename": "server",
                    "vendor": ""
                },
                {
                    "did": 3,
                    "firstSeen": "2020-06-09T19:19:32.000Z",
                    "ip": "172.31.16.1",
                    "ips": [
                        {
                            "ip": "172.31.16.1",
                            "sid": 1,
                            "time": "2020-09-11 18:00:00",
                            "timems": 1599847200000
                        }
                    ],
                    "lastSeen": "2020-09-11T18:58:00.000Z",
                    "score": 100,
                    "sid": 1,
                    "typelabel": "Server",
                    "typename": "server"
                }
            ],
            "did": 1
        }
    }
}
```

#### Human Readable Output

>### List of similar devices to device:1:

>|did|firstSeen|hostname|ip|ips|lastSeen|macaddress|score|sid|typelabel|typename|vendor|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 823 | 2020-08-07T00:06:40.000Z | ip-172-31-32-146 | 172.31.32.146 | {'ip': '172.31.32.146', 'timems': 1600063200000, 'time': '2020-09-14 06:00:00', 'sid': 114} | 2020-09-14T06:23:38.000Z | 0a:df:4b:52:64:7a | 99 | 114 | Server | server |  |
>| 3 | 2020-06-09T19:19:32.000Z |  | 172.31.16.1 | {'ip': '172.31.16.1', 'timems': 1599847200000, 'time': '2020-09-11 18:00:00', 'sid': 1} | 2020-09-11T18:58:00.000Z |  | 100 | 1 | Server | server |  |


### darktrace-get-external-endpoint-details

***
Returns details collected by Darktrace about external IP addresses or hostnames.


#### Base Command

`darktrace-get-external-endpoint-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_type | Type of endpoint: IP or hostname | Required | 
| endpoint_value | IP or hostname to look up | Required | 
| devices | Boolean: Include devices that have recently connected to the endpoint | Optional | 
| additional_info | Boolean: Return additional info about the devices | Optional | 
| score | Boolean: Return rarity data for this endpoint | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.ExternalEndpointDetails | Unknown | Returned information about the external endpoint | 


#### Command Example

```!darktrace-get-external-endpoint-details endpoint_type=hostname endpoint_value=cats.com additional_info=true devices=true score=true```

#### Context Example

```
{
    "Darktrace": {
        "ExternalEndpointDetails": {
            "devices": [],
            "dgascore": 0,
            "firsttime": "2020-08-07T04:47:23.000Z",
            "hostname": "cats.com",
            "ips": [],
            "locations": [],
            "popularity": 0
        }
    }
}
```

#### Human Readable Output

>### Hostname: cats.com details

>|devices|dgascore|firsttime|hostname|ips|locations|popularity|
>|---|---|---|---|---|---|---|
>|  | 0 | 2020-08-07T04:47:23.000Z | cats.com |  |  | 0 |


### darktrace-get-device-connection-info

***
Returns the graphable data used in the "Connections Data" view for a specific device that can be accessed from the Threat Visualizer omnisearch in Darktrace. Data returned covers a 4 week period. Parameters are further documented at <https://customerportal.darktrace.com/product-guides/main/api-deviceinfo-request>. It is recommended to run the command to check the relevant fields in context.


#### Base Command

`darktrace-get-device-connection-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| did | Darktrace Device ID | Required | 
| data_type | Specify whether to return data for either connections (co), data size out (sizeout) or data size in (sizein). | Required | 
| external_domain | Restrict external data to a particular domain name. | Optional | 
| destination_did | Darktrace Device DID of destination device to restrict data to. | Optional | 
| show_all_graph_data | Return an entry for all time intervals in the graph data, including zero counts. (Not recommended) | Optional | 
| num_similar_devices | Return data for the primary device and this number of similar devices. | Optional | 
| full_device_details | Return the full device detail objects for all devices referenced by data in an API response. Use of this parameter will alter the JSON structure of the API response for certain calls. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.DeviceConnectionInfo | Unknown | Graphable data used in the "Connections Data" view for a specific device that can be accessed from the Threat Visualizer omnisearch in Darktrace. Data returned covers a 4 week period. Parameters are further documented at <https://customerportal.darktrace.com/product-guides/main/api-deviceinfo-request>. It is recommended to run the command to check the relevant fields in context. | 


#### Command Example

```!darktrace-get-device-connection-info did=1 data_type=co```

#### Context Example

```
{
    "Darktrace": {
        "DeviceConnectionInfo": {
            "deviceInfo": [
                {
                    "did": 1,
                    "graphData": [
                        {
                            "count": 390,
                            "time": 1598302800000
                        },
                        {
                            "count": 7,
                            "time": 1598306400000
                        },
                        {
                            "count": 94,
                            "time": 1598652000000
                        },
                        {
                            "count": 88,
                            "time": 1598990400000
                        },
                        {
                            "count": 25,
                            "time": 1598994000000
                        },
                        {
                            "count": 16,
                            "time": 1598997600000
                        },
                        {
                            "count": 15,
                            "time": 1599001200000
                        },
                        {
                            "count": 25,
                            "time": 1599004800000
                        },
                        {
                            "count": 13,
                            "time": 1599008400000
                        },
                        {
                            "count": 14,
                            "time": 1599012000000
                        },
                        {
                            "count": 13,
                            "time": 1599015600000
                        },
                        {
                            "count": 14,
                            "time": 1599019200000
                        },
                        {
                            "count": 18,
                            "time": 1599022800000
                        },
                        {
                            "count": 14,
                            "time": 1599026400000
                        },
                        {
                            "count": 13,
                            "time": 1599030000000
                        },
                        {
                            "count": 14,
                            "time": 1599033600000
                        },
                        {
                            "count": 13,
                            "time": 1599037200000
                        },
                        {
                            "count": 19,
                            "time": 1599040800000
                        },
                        {
                            "count": 13,
                            "time": 1599044400000
                        },
                        {
                            "count": 14,
                            "time": 1599048000000
                        },
                        {
                            "count": 624,
                            "time": 1599051600000
                        },
                        {
                            "count": 187,
                            "time": 1599055200000
                        },
                        {
                            "count": 169,
                            "time": 1599663600000
                        },
                        {
                            "count": 363,
                            "time": 1599667200000
                        },
                        {
                            "count": 329,
                            "time": 1599670800000
                        },
                        {
                            "count": 324,
                            "time": 1599674400000
                        },
                        {
                            "count": 332,
                            "time": 1599678000000
                        },
                        {
                            "count": 340,
                            "time": 1599681600000
                        },
                        {
                            "count": 334,
                            "time": 1599685200000
                        },
                        {
                            "count": 328,
                            "time": 1599688800000
                        },
                        {
                            "count": 340,
                            "time": 1599692400000
                        },
                        {
                            "count": 330,
                            "time": 1599696000000
                        },
                        {
                            "count": 332,
                            "time": 1599699600000
                        },
                        {
                            "count": 325,
                            "time": 1599703200000
                        },
                        {
                            "count": 344,
                            "time": 1599706800000
                        },
                        {
                            "count": 328,
                            "time": 1599710400000
                        },
                        {
                            "count": 338,
                            "time": 1599714000000
                        },
                        {
                            "count": 76,
                            "time": 1599750000000
                        },
                        {
                            "count": 336,
                            "time": 1599753600000
                        },
                        {
                            "count": 334,
                            "time": 1599757200000
                        },
                        {
                            "count": 334,
                            "time": 1599760800000
                        },
                        {
                            "count": 329,
                            "time": 1599764400000
                        },
                        {
                            "count": 342,
                            "time": 1599768000000
                        },
                        {
                            "count": 329,
                            "time": 1599771600000
                        },
                        {
                            "count": 336,
                            "time": 1599775200000
                        },
                        {
                            "count": 332,
                            "time": 1599778800000
                        },
                        {
                            "count": 332,
                            "time": 1599782400000
                        },
                        {
                            "count": 329,
                            "time": 1599786000000
                        },
                        {
                            "count": 328,
                            "time": 1599789600000
                        },
                        {
                            "count": 332,
                            "time": 1599793200000
                        },
                        {
                            "count": 341,
                            "time": 1599796800000
                        },
                        {
                            "count": 326,
                            "time": 1599800400000
                        },
                        {
                            "count": 330,
                            "time": 1599804000000
                        },
                        {
                            "count": 332,
                            "time": 1599807600000
                        },
                        {
                            "count": 334,
                            "time": 1599811200000
                        },
                        {
                            "count": 335,
                            "time": 1599814800000
                        },
                        {
                            "count": 333,
                            "time": 1599818400000
                        },
                        {
                            "count": 326,
                            "time": 1599822000000
                        },
                        {
                            "count": 328,
                            "time": 1599825600000
                        },
                        {
                            "count": 333,
                            "time": 1599829200000
                        },
                        {
                            "count": 335,
                            "time": 1599832800000
                        },
                        {
                            "count": 339,
                            "time": 1599836400000
                        },
                        {
                            "count": 351,
                            "time": 1599840000000
                        },
                        {
                            "count": 325,
                            "time": 1599843600000
                        },
                        {
                            "count": 329,
                            "time": 1599847200000
                        },
                        {
                            "count": 328,
                            "time": 1599850800000
                        }
                    ],
                    "info": {
                        "devicesAndPorts": [
                            {
                                "deviceAndPort": {
                                    "device": 2,
                                    "direction": "out",
                                    "port": 53
                                },
                                "size": 24
                            },
                            {
                                "deviceAndPort": {
                                    "device": 0,
                                    "direction": "out",
                                    "port": 53
                                },
                                "size": 19
                            },
                            {
                                "deviceAndPort": {
                                    "device": -5,
                                    "direction": "out",
                                    "port": 80
                                },
                                "size": 12
                            },
                            {
                                "deviceAndPort": {
                                    "device": 0,
                                    "direction": "out",
                                    "port": 123
                                },
                                "size": 11
                            },
                            {
                                "deviceAndPort": {
                                    "device": -3,
                                    "direction": "out",
                                    "port": "5001 - 10000"
                                },
                                "size": 10
                            },
                            {
                                "deviceAndPort": {
                                    "device": 3,
                                    "direction": "out",
                                    "port": 67
                                },
                                "size": 9
                            },
                            {
                                "deviceAndPort": {
                                    "device": 0,
                                    "direction": "out",
                                    "port": 443
                                },
                                "size": 4
                            },
                            {
                                "deviceAndPort": {
                                    "device": -6,
                                    "direction": "out",
                                    "port": 1514
                                },
                                "size": 4
                            },
                            {
                                "deviceAndPort": {
                                    "device": 0,
                                    "direction": "out",
                                    "port": 80
                                },
                                "size": 3
                            },
                            {
                                "deviceAndPort": {
                                    "device": -4,
                                    "direction": "out",
                                    "port": "5001 - 10000"
                                },
                                "size": 1
                            },
                            {
                                "deviceAndPort": {
                                    "device": -4,
                                    "direction": "out",
                                    "port": 3289
                                },
                                "size": 1
                            },
                            {
                                "deviceAndPort": {
                                    "device": -4,
                                    "direction": "out",
                                    "port": 1124
                                },
                                "size": 1
                            },
                            {
                                "deviceAndPort": "others",
                                "size": 1
                            }
                        ],
                        "devicesServed": [],
                        "devicesUsed": [
                            {
                                "did": 0,
                                "firstTime": 1591729360000,
                                "size": 37
                            },
                            {
                                "did": 2,
                                "firstTime": 1591729360000,
                                "size": 25
                            },
                            {
                                "did": -5,
                                "firstTime": 1591730027000,
                                "size": 12
                            },
                            {
                                "did": -3,
                                "firstTime": 1591729360000,
                                "size": 10
                            },
                            {
                                "did": 3,
                                "firstTime": 1591730311000,
                                "size": 9
                            },
                            {
                                "did": -6,
                                "firstTime": 1591730311000,
                                "size": 4
                            },
                            {
                                "did": -4,
                                "firstTime": 1591729360000,
                                "size": 2
                            },
                            {
                                "did": "others",
                                "size": 1
                            }
                        ],
                        "portsServed": [],
                        "portsUsed": [
                            {
                                "firstTime": 1591729360000,
                                "port": 53,
                                "size": 44
                            },
                            {
                                "firstTime": 1591729360000,
                                "port": 80,
                                "size": 15
                            },
                            {
                                "firstTime": 1592496475000,
                                "port": "5001 - 10000",
                                "size": 11
                            },
                            {
                                "firstTime": 1591730311000,
                                "port": 123,
                                "size": 11
                            },
                            {
                                "firstTime": 1591730311000,
                                "port": 67,
                                "size": 9
                            },
                            {
                                "firstTime": 1592952598000,
                                "port": 1514,
                                "size": 4
                            },
                            {
                                "firstTime": 1591729361000,
                                "port": 443,
                                "size": 4
                            },
                            {
                                "firstTime": 1592497916000,
                                "port": 3289,
                                "size": 1
                            },
                            {
                                "port": "others",
                                "size": 1
                            }
                        ],
                        "totalDevicesAndPorts": 1589,
                        "totalServed": 0,
                        "totalUsed": 1589
                    },
                    "similarityScore": 100
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results for device id: 1

>|deviceInfo|
>|---|
>| {'did': 1, 'similarityScore': 100, 'graphData': [{'time': 1598302800000, 'count': 390}, {'time': 1598306400000, 'count': 7}, {'time': 1598652000000, 'count': 94}, {'time': 1598990400000, 'count': 88}, {'time': 1598994000000, 'count': 25}, {'time': 1598997600000, 'count': 16}, {'time': 1599001200000, 'count': 15}, {'time': 1599004800000, 'count': 25}, {'time': 1599008400000, 'count': 13}, {'time': 1599012000000, 'count': 14}, {'time': 1599015600000, 'count': 13}, {'time': 1599019200000, 'count': 14}, {'time': 1599022800000, 'count': 18}, {'time': 1599026400000, 'count': 14}, {'time': 1599030000000, 'count': 13}, {'time': 1599033600000, 'count': 14}, {'time': 1599037200000, 'count': 13}, {'time': 1599040800000, 'count': 19}, {'time': 1599044400000, 'count': 13}, {'time': 1599048000000, 'count': 14}, {'time': 1599051600000, 'count': 624}, {'time': 1599055200000, 'count': 187}, {'time': 1599663600000, 'count': 169}, {'time': 1599667200000, 'count': 363}, {'time': 1599670800000, 'count': 329}, {'time': 1599674400000, 'count': 324}, {'time': 1599678000000, 'count': 332}, {'time': 1599681600000, 'count': 340}, {'time': 1599685200000, 'count': 334}, {'time': 1599688800000, 'count': 328}, {'time': 1599692400000, 'count': 340}, {'time': 1599696000000, 'count': 330}, {'time': 1599699600000, 'count': 332}, {'time': 1599703200000, 'count': 325}, {'time': 1599706800000, 'count': 344}, {'time': 1599710400000, 'count': 328}, {'time': 1599714000000, 'count': 338}, {'time': 1599750000000, 'count': 76}, {'time': 1599753600000, 'count': 336}, {'time': 1599757200000, 'count': 334}, {'time': 1599760800000, 'count': 334}, {'time': 1599764400000, 'count': 329}, {'time': 1599768000000, 'count': 342}, {'time': 1599771600000, 'count': 329}, {'time': 1599775200000, 'count': 336}, {'time': 1599778800000, 'count': 332}, {'time': 1599782400000, 'count': 332}, {'time': 1599786000000, 'count': 329}, {'time': 1599789600000, 'count': 328}, {'time': 1599793200000, 'count': 332}, {'time': 1599796800000, 'count': 341}, {'time': 1599800400000, 'count': 326}, {'time': 1599804000000, 'count': 330}, {'time': 1599807600000, 'count': 332}, {'time': 1599811200000, 'count': 334}, {'time': 1599814800000, 'count': 335}, {'time': 1599818400000, 'count': 333}, {'time': 1599822000000, 'count': 326}, {'time': 1599825600000, 'count': 328}, {'time': 1599829200000, 'count': 333}, {'time': 1599832800000, 'count': 335}, {'time': 1599836400000, 'count': 339}, {'time': 1599840000000, 'count': 351}, {'time': 1599843600000, 'count': 325}, {'time': 1599847200000, 'count': 329}, {'time': 1599850800000, 'count': 328}], 'info': {'totalUsed': 1589, 'totalServed': 0, 'totalDevicesAndPorts': 1589, 'devicesAndPorts': [{'deviceAndPort': {'direction': 'out', 'device': 2, 'port': 53}, 'size': 24}, {'deviceAndPort': {'direction': 'out', 'device': 0, 'port': 53}, 'size': 19}, {'deviceAndPort': {'direction': 'out', 'device': -5, 'port': 80}, 'size': 12}, {'deviceAndPort': {'direction': 'out', 'device': 0, 'port': 123}, 'size': 11}, {'deviceAndPort': {'direction': 'out', 'device': -3, 'port': '5001 - 10000'}, 'size': 10}, {'deviceAndPort': {'direction': 'out', 'device': 3, 'port': 67}, 'size': 9}, {'deviceAndPort': {'direction': 'out', 'device': 0, 'port': 443}, 'size': 4}, {'deviceAndPort': {'direction': 'out', 'device': -6, 'port': 1514}, 'size': 4}, {'deviceAndPort': {'direction': 'out', 'device': 0, 'port': 80}, 'size': 3}, {'deviceAndPort': {'direction': 'out', 'device': -4, 'port': '5001 - 10000'}, 'size': 1}, {'deviceAndPort': {'direction': 'out', 'device': -4, 'port': 3289}, 'size': 1}, {'deviceAndPort': {'direction': 'out', 'device': -4, 'port': 1124}, 'size': 1}, {'deviceAndPort': 'others', 'size': 1}], 'portsUsed': [{'port': 53, 'size': 44, 'firstTime': 1591729360000}, {'port': 80, 'size': 15, 'firstTime': 1591729360000}, {'port': '5001 - 10000', 'size': 11, 'firstTime': 1592496475000}, {'port': 123, 'size': 11, 'firstTime': 1591730311000}, {'port': 67, 'size': 9, 'firstTime': 1591730311000}, {'port': 1514, 'size': 4, 'firstTime': 1592952598000}, {'port': 443, 'size': 4, 'firstTime': 1591729361000}, {'port': 3289, 'size': 1, 'firstTime': 1592497916000}, {'port': 'others', 'size': 1}], 'portsServed': [], 'devicesUsed': [{'did': 0, 'size': 37, 'firstTime': 1591729360000}, {'did': 2, 'size': 25, 'firstTime': 1591729360000}, {'did': -5, 'size': 12, 'firstTime': 1591730027000}, {'did': -3, 'size': 10, 'firstTime': 1591729360000}, {'did': 3, 'size': 9, 'firstTime': 1591730311000}, {'did': -6, 'size': 4, 'firstTime': 1591730311000}, {'did': -4, 'size': 2, 'firstTime': 1591729360000}, {'did': 'others', 'size': 1}], 'devicesServed': []}} |

### darktrace-run-advanced-search-analysis

***
Runs advanced search analysis queries.

#### Base Command

`darktrace-run-advanced-search-analysis`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| initialDate | initial date for query (YYYY-MM-DD) | Required |
| initialTime | initial time for query (HH:MM:SS) | Required |
| endDate | end date for query (YYYY-MM-DD) | Required |
| endTime | end time for query (HH:MM:SS) | Required |
| query | enter an advanced search query | Required |
| operation | enter an advanced search operation to perform on query results metric | Required |
| metric | enter an advanced search analysis metric | Required |
| offset | analyses 10k connections at a time, use this parameter to analyse further results | Default |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.AdvancedSearch | Dictionary | Advanced Search Results |

### darktrace-post-to-watched-list

***
Posts hostnames and ips to the Darktrace Watched Domain List.

#### Base Command

`darktrace-post-to-watched-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpointsToWatch | Unique or Comma separated list of ips, hostnames or domains to watch | Required |
| description | Provide an optional description for added entries | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.Endpoint.Watched | String | Whether the device has been successfully tagged |

### darktrace-get-tagged-devices

***
Returns all Darktrace tagged devices

#### Base Command

`darktrace-get-tagged-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tagName | Tag name | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.Device.deviceId | Number | Device unique identifier |
| Darktrace.Device.hostname | String | Device Hostname |
| Darktrace.Device.label | String | device label |
| Darktrace.Device.credentials | Unknown | credentials seen on device |
| Darktrace.Device.otherTags | Unknown | other tags found on device |

### darktrace-get-tags-for-device

***
Returns all tags present on a specified device.

#### Base Command

`darktrace-get-tags-for-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deviceId | Device unique identifier | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.Device.tagId | Number | Tag Id |
| Darktrace.Device.tagName | String | Tag Name |
| Darktrace.Device.tagDescription | String | Tag description if present|
| Darktrace.Device.expiry | Number | Tag expiration if applicable |

### darktrace-post-tag-to-device

***
Posts a tag to a device

#### Base Command

`darktrace-post-tag-to-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deviceId | Device unique identifier | Required |
| tagName | Tag name to be applied | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.Device.tagId | Number | Tag Id |
| Darktrace.Device.tagName | String | Tag Name |
| Darktrace.Device.deviceId | Number | Device unique identifier |
| Darktrace.Device.response | String | POST action message response |