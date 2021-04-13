Darktrace is a Cyber AI platform for threat detection and response across cloud, email, industrial, and the network.
This integration was integrated and tested with version 4.1.0 of Darktrace
## Configure Darktrace on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Darktrace.
3. Click **Add instance** to create and configure a new integration instance.

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

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### darktrace-get-breach
***
Darktrace-get-breach returns a model breach based on its model breach id (pbid)


#### Base Command

`darktrace-get-breach`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pbid | Model breach ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.ModelBreach.pbid | Number | Model breach ID | 
| Darktrace.ModelBreach.time | Date | Model breach generated time. | 
| Darktrace.ModelBreach.commentCount | Number | Number of comments on the model breach | 
| Darktrace.ModelBreach.score | Number | Score of Darktrace model breach \(0 to 1\) | 
| Darktrace.ModelBreach.device.did | Number | Darktrace device ID of Device that breached the model | 
| Darktrace.ModelBreach.device.macaddress | String | MAC address of the device involved in the model breach \(if applicable\) | 
| Darktrace.ModelBreach.device.vendor | String | Vendor of the device involved in the model breach \(if applicable\) | 
| Darktrace.ModelBreach.device.ip | String | IP of the device involved in the model breach \(if applicable\) | 
| Darktrace.ModelBreach.device.hostname | String | Hostname of the device involved in the model breach \(if applicable\) | 
| Darktrace.ModelBreach.device.devicelabel | String | Device label of the device involved in the model breach \(if applicable\) | 
| Darktrace.ModelBreach.model.name | String | Darktrace model that was breached | 
| Darktrace.ModelBreach.model.pid | Number | Model ID of the model that was breached | 
| Darktrace.ModelBreach.model.uuid | String | Model UUID of the model that was breached | 
| Darktrace.ModelBreach.model.tags | Unknown | List of model tags for the model that was breached | 
| Darktrace.ModelBreach.model.priority | Number | Priority of the model that was breached \(0 to 5\) | 
| Darktrace.ModelBreach.model.description | String | Darktrace model description | 


#### Command Example
```!darktrace-get-breach pbid=95```

#### Context Example
```
{
    "Darktrace": {
        "ModelBreach": {
            "commentCount": 0,
            "device": {
                "devicelabel": "Kelly's Laptop",
                "did": 823,
                "hostname": "sf-l-kjohnson",
                "ip": "172.31.32.146",
                "macaddress": "06:42:04:c2:b0:48",
                "vendor": "HP"
            },
            "model": {
                "description": "A device is connecting to watched domains or IP addresses. The watch list can be edited from the main GUI menu, Intel sub-menu, under the icon Watched Domains.\\n\\nAction: Review the domain and IP being connected to.",
                "name": "Compromise::Watched Domain",
                "pid": 762,
                "priority": 5,
                "tags": ["AP: C2 Comms"],
                "uuid": "3338210a-8979-4a1b-8039-63ca8addf166"
            },
            "pbid": 95,
            "score": 1,
            "time": "2020-10-08T21:11:21.000Z"
        }
    }
}
```

#### Human Readable Output

>### Darktrace Model Breach 95
>|commentCount|device|model|pbid|score|time|
>|---|---|---|---|---|---|
>| 0 | did: 823<br/>macaddress: 0a:df:4b:52:64:7a<br/>vendor: HP<br/>ip: 172.31.32.146<br/>hostname: ip-172-31-32-146<br/>devicelabel: Kelly's Laptop | name: Compromise::Watched Domain<br/>pid: 762<br/>uuid: 3338210a-8979-4a1b-8039-63ca8addf166<br/>tags: \[AP: C2 Comms\]<br/>priority: 5<br/>description: A device is connecting to watched domains or IP addresses. The watch list can be edited from the main GUI menu, Intel sub-menu, under the icon Watched Domains. | 95 | 1 | 2020-10-08T21:11:21.000Z |


### darktrace-get-comments
***
Returns the comments on a model breach based on its model breach id (pbid)


#### Base Command

`darktrace-get-comments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pbid | Model Breach ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.ModelBreach.comments | Unknown | Array of the comments on the model breach | 


#### Command Example
```!darktrace-get-comments pbid=46```

#### Context Example
```
{
    "Darktrace": {
        "ModelBreach": {
            "comments": [
                {
                    "message": "Flag for follow-up",
                    "pbid": 46,
                    "pid": 210,
                    "time": "2020-10-08T21:11:21.000Z",
                    "username": "user.one"
                },
                {
                    "message": "Activity has been remediated",
                    "pbid": 46,
                    "pid": 210,
                    "time": "2020-10-08T23:11:21.000Z",
                    "username": "user.two"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Darktrace Model Breach 46 Comments
>|message|pbid|pid|time|username|
>|---|---|---|---|---|
>| Flag for follow-up | 46 | 210 | 2020-10-08T21:11:21.000Z | user.one |
>| Activity has been remediated | 46 | 210 | 2020-10-08T23:11:21.000Z | user.two |


### darktrace-acknowledge
***
Acknowledge a model breach as specified by Model Breach ID


#### Base Command

`darktrace-acknowledge`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pbid | Model Breach ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.ModelBreach.acknowledged | String | Whether the model breach is acknowledged in Darktrace | 
| Darktrace.ModelBreach.pbid | Number | Model breach ID | 


#### Command Example
```!darktrace-acknowledge pbid=111```

#### Context Example
```
{
    "Darktrace": {
        "ModelBreach": {
            "acknowledged": true,
            "pbid": 111
        }
    }
}
```

#### Human Readable Output

>### Model Breach 111 Acknowledged
>|response|
>|---|
>| Successfully acknowledged. |


### darktrace-unacknowledge
***
Unacknowledges a model breach as specified by Model Breach ID


#### Base Command

`darktrace-unacknowledge`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pbid | Darktrace model breach ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.ModelBreach.acknowledged | String | Whether the model breach is acknowledged | 
| Darktrace.ModelBreach.pbid | Number | Model breach ID | 


#### Command Example
```!darktrace-unacknowledge pbid=111```

#### Context Example
```
{
    "Darktrace": {
        "ModelBreach": {
            "acknowledged": false,
            "pbid": 111
        }
    }
}
```

#### Human Readable Output

>### Model Breach 111 Unacknowledged
>|response|
>|---|
>| Successfully unacknowledged. |


### darktrace-list-similar-devices
***
Returns a list of similar devices to a device specified by Darktrace DID


#### Base Command

`darktrace-list-similar-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| did | Darktrace Device ID | Required | 
| max_results | Maximum number of results to return | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.SimilarDevices.did | Number | Darktrace Device ID of the device with the similar devices. | 
| Darktrace.SimilarDevices.devices | Unknown | List of similar devices and their available information | 


#### Command Example
```!darktrace-list-similar-devices did=1 max_results=2```

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
Returns the graphable data used in the "Connections Data" view for a specific device that can be accessed from the Threat Visualizer omnisearch in Darktrace. Data returned covers a 4 week period. Parameters are further documented at https://customerportal.darktrace.com/product-guides/main/api-deviceinfo-request. It is recommended to run the command to check the relevant fields in context.


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
| Darktrace.DeviceConnectionInfo | Unknown | Graphable data used in the "Connections Data" view for a specific device that can be accessed from the Threat Visualizer omnisearch in Darktrace. Data returned covers a 4 week period. Parameters are further documented at https://customerportal.darktrace.com/product-guides/main/api-deviceinfo-request. It is recommended to run the command to check the relevant fields in context. | 


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


### darktrace-get-device-identity-info
***
Gets device identity information based on label, tag, type, hostname, ip, mac, vendor and os. It is recommended to run the command to check the relevant fields in context.


#### Base Command

`darktrace-get-device-identity-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_results | Max number of devices to return. Default is 50. | Optional | 
| order_by | Orders the response by the specified filter. Default value is lastSeen.  | Optional | 
| order | Sets the sort order for returned devices as ascending (asc) or descending (desc). Default is ascending. | Optional | 
| query | A string search. Can query all fields or take a specific field to filter. The query parameter can take a string directly to search all key/value pairs (.e.g query="value") or be limited to a certain data type (.e.g query="label:test"). Fields to filter on are:<br/>- label<br/>- tag<br/>- type<br/>- hostname<br/>- ip<br/>- mac<br/>- vendor<br/>- os | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.DeviceIdentityInfo | Unknown | Information about the device’s identity. It is recommended to run the command to check the relevant fields in context. | 


#### Command Example
```!darktrace-get-device-identity-info query=osSensor```

#### Context Example
```
{
    "Darktrace": {
        "DeviceIdentityInfo": {
            "devices": [
                {
                    "devicelabel": "Kelly's Laptop",
                    "did": 10,
                    "firstSeen": "2020-06-09T19:02:50.000Z",
                    "hostname": "ip-172-31-17-246",
                    "ip": "172.31.17.246",
                    "ips": [
                        {
                            "ip": "172.31.17.246",
                            "sid": 1,
                            "time": "2020-09-11 19:00:00",
                            "timems": 1599850800000
                        }
                    ],
                    "lastSeen": "2020-09-11T18:22:30.000Z",
                    "macaddress": "06:39:01:c2:b0:48",
                    "sid": 1,
                    "tags": [
                        {
                            "data": {
                                "auto": false,
                                "color": 110,
                                "description": "",
                                "visibility": "Public"
                            },
                            "expiry": 0,
                            "isReferenced": true,
                            "name": "Internet Facing System",
                            "restricted": false,
                            "thid": 54,
                            "tid": 54
                        },
                        {
                            "data": {
                                "auto": false,
                                "color": 181,
                                "description": "",
                                "visibility": "Public"
                            },
                            "expiry": 0,
                            "isReferenced": false,
                            "name": "SF Office",
                            "restricted": false,
                            "thid": 90,
                            "tid": 90
                        }
                    ],
                    "typelabel": "Server",
                    "typename": "server",
                    "vendor": ""
                }
            ],
            "displayedCount": 1,
            "totalCount": 1
        }
    }
}
```

#### Human Readable Output

>### Results for query: osSensor (1 results displayed of 1 which match the query)
>|devicelabel|did|firstSeen|hostname|ip|ips|lastSeen|macaddress|sid|tags|typelabel|typename|vendor|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Kelly's Laptop | 10 | 2020-06-09T19:02:50.000Z | ip-172-31-17-246 | 172.31.17.246 | {'ip': '172.31.17.246', 'timems': 1599850800000, 'time': '2020-09-11 19:00:00', 'sid': 1} | 2020-09-11T18:22:30.000Z | 06:39:01:c2:b0:48 | 1 | {'tid': 54, 'expiry': 0, 'thid': 54, 'name': 'Internet Facing System', 'restricted': False, 'data': {'auto': False, 'color': 110, 'description': '', 'visibility': 'Public'}, 'isReferenced': True},<br/>{'tid': 90, 'expiry': 0, 'thid': 90, 'name': 'SF Office', 'restricted': False, 'data': {'auto': False, 'color': 181, 'description': '', 'visibility': 'Public'}, 'isReferenced': False} | Server | server |  |


### darktrace-get-entity-details
***
Returns a time sorted list of connections and events for a device or an entity such as a user credential.


#### Base Command

`darktrace-get-entity-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_results | Maximum number of items to return. Default is 50. | Optional | 
| offset | Starting index to return results from (for example offset=20 with max_results=50 will bring results from index 20 to index 70) | Optional | 
| query | Comma-separated list of values to filter by.<br/><br/>Examples:<br/>query="did=1,count=100,eventtype=unusualconnection"<br/>query="pdid=1,from=2014-12-01T12:00:00,to=2014-12-02T12:00:00"<br/>query="msg=USER123"<br/><br/>Possible values:<br/>- applicationprotocol<br/>- count<br/>- ddid: Identification number of a destination device modelled in the Darktrace system to restrict data to<br/>- deduplicate: Display only one equivalent connection per hour. (true/false)<br/>- destinationport: This filter can be used to filter the returned data by destination port.<br/>- did: Identification number of a device modelled in the Darktrace system.<br/>- endtime: End time of data to return in millisecond format, relative to midnight January 1st 1970 UTC.<br/>- eventtype: Specifies an type of event to return details for. (connection/unusualconnection/newconnection/notice/devicehistory/modelbreach/userdetails)<br/>- externalhostname: Specifies an hostname to return details for.<br/>- sourceport: This filter can be used to filter the returned data by source port.<br/>- starttime: Start time of data to return in millisecond format, relative to midnight January 1st 1970 UTC.<br/>- to: End time of data to return in YYYY-MM-DD HH:MM:SS format<br/>- uid: Specifies a connection UID to return. (Example: CcdXo43n8B75cdYyI5)<br/>- from: Start time of data to return in YYYY-MM-DD HH:MM:SS format.<br/>- fulldevicedetails: Returns the full device detail objects for all devices referenced by data in an API response.<br/>- intext: This filter can be used to filter the returned data to that which interacts with external sources and destinations, or is restricted to internal. (internal/external)<br/>- msg: Specifies the value of the message field in notice events to return details for. Typically used to specify user credential strings.<br/>- odid: Identification number of a device modelled in the Darktrace system to restrict data to. Typically used with ddid and odid to specify device pairs regardless of source/destination.<br/>- pbid: ID for a model breach<br/>- port: This filter can be used to filter the returned data by source or destination port.<br/>- protocol<br/><br/>For more info on this query visit: https://&lt;your-Darktrace-server-url&gt;/apihelp ('details' tab) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.EntityDetails | Unknown | List of entities and their details. Each entity might have different keys. It is recommended to run the command once to check the relevant outputs in context. | 


#### Command Example
```!darktrace-get-entity-details query=did=1,count=10 offset=5```

#### Context Example
```
{
    "Darktrace": {
        "EntityDetails": [
            {
                "action": "connection",
                "applicationprotocol": "SSH",
                "ddid": 10,
                "destination": "Kelly's Laptop",
                "destinationDevice": {
                    "devicelabel": "Kelly's Laptop",
                    "did": 10,
                    "hostname": "ip-172-31-17-246",
                    "id": 1,
                    "ip": "172.31.17.246",
                    "ips": [
                        {
                            "ip": "172.31.17.246",
                            "sid": 1,
                            "time": "2020-09-11 19:00:00",
                            "timems": 1599850800000
                        }
                    ],
                    "macaddress": "06:39:01:c2:b0:48",
                    "sid": 1,
                    "time": "1591729370000",
                    "typelabel": "Server",
                    "typename": "server"
                },
                "destinationPort": 22,
                "direction": "in",
                "eventType": "connection",
                "port": 22,
                "protocol": "TCP",
                "source": "222.186.15.62",
                "sourceDevice": {
                    "asn": "AS23650 AS Number for CHINANET jiangsu province backbone",
                    "connectionippopularity": "0",
                    "country": "China",
                    "countrycode": "CN",
                    "ip": "222.186.15.62",
                    "ippopularity": "0",
                    "latitude": 34.772,
                    "longitude": 113.727,
                    "region": "Asia"
                },
                "sourcePort": 17815,
                "status": "ongoing",
                "time": "2020-09-11 19:42:21",
                "timems": 1599853341264,
                "uid": "CJDfGwAT7fVxNJd01"
            },
            {
                "action": "connection",
                "applicationprotocol": "SSH",
                "ddid": 10,
                "destination": "Kelly's Laptop",
                "destinationDevice": {
                    "devicelabel": "Kelly's Laptop",
                    "did": 10,
                    "hostname": "ip-172-31-17-246",
                    "id": 1,
                    "ip": "172.31.17.246",
                    "ips": [
                        {
                            "ip": "172.31.17.246",
                            "sid": 1,
                            "time": "2020-09-11 19:00:00",
                            "timems": 1599850800000
                        }
                    ],
                    "macaddress": "06:39:01:c2:b0:48",
                    "sid": 1,
                    "time": "1591729370000",
                    "typelabel": "Server",
                    "typename": "server"
                },
                "destinationPort": 22,
                "direction": "in",
                "eventType": "connection",
                "port": 22,
                "protocol": "TCP",
                "source": "222.186.15.62",
                "sourceDevice": {
                    "asn": "AS23650 AS Number for CHINANET jiangsu province backbone",
                    "connectionippopularity": "0",
                    "country": "China",
                    "countrycode": "CN",
                    "ip": "222.186.15.62",
                    "ippopularity": "0",
                    "latitude": 34.772,
                    "longitude": 113.727,
                    "region": "Asia"
                },
                "sourcePort": 17815,
                "time": "2020-09-11 19:42:14",
                "timems": 1599853334254,
                "uid": "CJDfGwAT7fVxNJd01"
            },
            {
                "action": "connection",
                "applicationprotocol": "Unknown",
                "ddid": 10,
                "destination": "Kelly's Laptop",
                "destinationDevice": {
                    "devicelabel": "Kelly's Laptop",
                    "did": 10,
                    "hostname": "ip-172-31-17-246",
                    "id": 1,
                    "ip": "172.31.17.246",
                    "ips": [
                        {
                            "ip": "172.31.17.246",
                            "sid": 1,
                            "time": "2020-09-11 19:00:00",
                            "timems": 1599850800000
                        }
                    ],
                    "macaddress": "06:39:01:c2:b0:48",
                    "sid": 1,
                    "time": "1591729370000",
                    "typelabel": "Server",
                    "typename": "server"
                },
                "destinationPort": 443,
                "direction": "in",
                "eventType": "connection",
                "port": 443,
                "protocol": "TCP",
                "source": "62.113.227.26",
                "sourceDevice": {
                    "asn": "AS47447 23media GmbH",
                    "connectionippopularity": "0",
                    "country": "Germany",
                    "countrycode": "DE",
                    "ip": "62.113.227.26",
                    "ippopularity": "0",
                    "latitude": 51.299,
                    "longitude": 9.491,
                    "region": "Europe"
                },
                "sourcePort": 28228,
                "status": "failed",
                "time": "2020-09-11 19:41:23",
                "timems": 1599853283240,
                "uid": "CQ4hu824CoXul9KV01"
            },
            {
                "action": "connection",
                "applicationprotocol": "Unknown",
                "ddid": 10,
                "destination": "Kelly's Laptop",
                "destinationDevice": {
                    "devicelabel": "Kelly's Laptop",
                    "did": 10,
                    "hostname": "ip-172-31-17-246",
                    "id": 1,
                    "ip": "172.31.17.246",
                    "ips": [
                        {
                            "ip": "172.31.17.246",
                            "sid": 1,
                            "time": "2020-09-11 19:00:00",
                            "timems": 1599850800000
                        }
                    ],
                    "macaddress": "06:39:01:c2:b0:48",
                    "sid": 1,
                    "time": "1591729370000",
                    "typelabel": "Server",
                    "typename": "server"
                },
                "destinationPort": 443,
                "direction": "in",
                "eventType": "connection",
                "port": 443,
                "protocol": "TCP",
                "source": "62.113.227.26",
                "sourceDevice": {
                    "asn": "AS47447 23media GmbH",
                    "connectionippopularity": "0",
                    "country": "Germany",
                    "countrycode": "DE",
                    "ip": "62.113.227.26",
                    "ippopularity": "0",
                    "latitude": 51.299,
                    "longitude": 9.491,
                    "region": "Europe"
                },
                "sourcePort": 54518,
                "status": "failed",
                "time": "2020-09-11 19:41:03",
                "timems": 1599853263230,
                "uid": "CWYWpz2KmHrsjNGO01"
            },
            {
                "action": "notice",
                "destination": "Kelly's Laptop",
                "destinationDevice": {
                    "devicelabel": "Kelly's Laptop",
                    "did": 10,
                    "hostname": "ip-172-31-17-246",
                    "id": 1,
                    "ip": "172.31.17.246",
                    "ips": [
                        {
                            "ip": "172.31.17.246",
                            "sid": 1,
                            "time": "2020-09-11 19:00:00",
                            "timems": 1599850800000
                        }
                    ],
                    "macaddress": "06:39:01:c2:b0:48",
                    "sid": 1,
                    "time": "1591729370000",
                    "typelabel": "Server",
                    "typename": "server"
                },
                "destinationPort": 22,
                "details": "2073 bytes delivered in connection and 0 bytes undelivered.",
                "direction": "in",
                "eventType": "notice",
                "mlid": 328,
                "msg": "Unable to determine login failure or success from encrypted traffic.",
                "nid": 35987,
                "source": "13.85.152.27",
                "sourceDevice": {
                    "asn": "AS8075 MICROSOFT-CORP-MSN-AS-BLOCK",
                    "city": "San Antonio",
                    "country": "United States",
                    "countrycode": "US",
                    "ip": "13.85.152.27",
                    "ippopularity": "0",
                    "latitude": 29.422,
                    "longitude": -98.493,
                    "region": "North America"
                },
                "time": "2020-09-11 19:40:48",
                "timems": 1599853248000,
                "type": "SSH::Undetermined_Encryption_Step",
                "uid": "CMEAtvytG16vv0X01"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results:
>|action|applicationprotocol|ddid|destination|destinationDevice|destinationPort|direction|eventType|port|protocol|source|sourceDevice|sourcePort|status|time|timems|uid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| connection | SSH | 10 | Kelly's Laptop | id: 1<br/>did: 1<br/>macaddress: 06:39:01:c2:b0:48<br/>ip: 172.31.17.246<br/>ips: {'ip': '172.31.17.246', 'timems': 1599850800000, 'time': '2020-09-11 19:00:00', 'sid': 1}<br/>sid: 1<br/>hostname: ip-172-31-17-246<br/>time: 1591729370000<br/>devicelabel: Kelly's Laptop<br/>typename: server<br/>typelabel: Server | 22 | in | connection | 22 | TCP | 222.186.15.62 | longitude: 113.727<br/>latitude: 34.772<br/>country: China<br/>countrycode: CN<br/>asn: AS23650 AS Number for CHINANET jiangsu province backbone<br/>region: Asia<br/>ip: 222.186.15.62<br/>ippopularity: 0<br/>connectionippopularity: 0 | 17815 | ongoing | 2020-09-11 19:42:21 | 1599853341264 | CJDfGwAT7fVxNJd01 |
>| connection | SSH | 10 | Kelly's Laptop | id: 1<br/>did: 1<br/>macaddress: 06:39:01:c2:b0:48<br/>ip: 172.31.17.246<br/>ips: {'ip': '172.31.17.246', 'timems': 1599850800000, 'time': '2020-09-11 19:00:00', 'sid': 1}<br/>sid: 1<br/>hostname: ip-172-31-17-246<br/>time: 1591729370000<br/>devicelabel: Kelly's Laptop<br/>typename: server<br/>typelabel: Server | 22 | in | connection | 22 | TCP | 222.186.15.62 | longitude: 113.727<br/>latitude: 34.772<br/>country: China<br/>countrycode: CN<br/>asn: AS23650 AS Number for CHINANET jiangsu province backbone<br/>region: Asia<br/>ip: 222.186.15.62<br/>ippopularity: 0<br/>connectionippopularity: 0 | 17815 |  | 2020-09-11 19:42:14 | 1599853334254 | CJDfGwAT7fVxNJd01 |
>| connection | Unknown | 10 | Kelly's Laptop | id: 1<br/>did: 1<br/>macaddress: 06:39:01:c2:b0:48<br/>ip: 172.31.17.246<br/>ips: {'ip': '172.31.17.246', 'timems': 1599850800000, 'time': '2020-09-11 19:00:00', 'sid': 1}<br/>sid: 1<br/>hostname: ip-172-31-17-246<br/>time: 1591729370000<br/>devicelabel: Kelly's Laptop<br/>typename: server<br/>typelabel: Server | 443 | in | connection | 443 | TCP | 62.113.227.26 | longitude: 9.491<br/>latitude: 51.299<br/>country: Germany<br/>countrycode: DE<br/>asn: AS47447 23media GmbH<br/>region: Europe<br/>ip: 62.113.227.26<br/>ippopularity: 0<br/>connectionippopularity: 0 | 28228 | failed | 2020-09-11 19:41:23 | 1599853283240 | CQ4hu824CoXul9KV01 |
>| connection | Unknown | 10 | Kelly's Laptop | id: 1<br/>did: 1<br/>macaddress: 06:39:01:c2:b0:48<br/>ip: 172.31.17.246<br/>ips: {'ip': '172.31.17.246', 'timems': 1599850800000, 'time': '2020-09-11 19:00:00', 'sid': 1}<br/>sid: 1<br/>hostname: ip-172-31-17-246<br/>time: 1591729370000<br/>devicelabel: Kelly's Laptop<br/>typename: server<br/>typelabel: Server | 443 | in | connection | 443 | TCP | 62.113.227.26 | longitude: 9.491<br/>latitude: 51.299<br/>country: Germany<br/>countrycode: DE<br/>asn: AS47447 23media GmbH<br/>region: Europe<br/>ip: 62.113.227.26<br/>ippopularity: 0<br/>connectionippopularity: 0 | 54518 | failed | 2020-09-11 19:41:03 | 1599853263230 | CWYWpz2KmHrsjNGO01 |
>| notice |  |  | Kelly's Laptop | id: 1<br/>did: 1<br/>macaddress: 06:39:01:c2:b0:48<br/>ip: 172.31.17.246<br/>ips: {'ip': '172.31.17.246', 'timems': 1599850800000, 'time': '2020-09-11 19:00:00', 'sid': 1}<br/>sid: 1<br/>hostname: ip-172-31-17-246<br/>time: 1591729370000<br/>devicelabel: Kelly's Laptop<br/>typename: server<br/>typelabel: Server | 22 | in | notice |  |  | 13.85.152.27 | longitude: -98.493<br/>latitude: 29.422<br/>city: San Antonio<br/>country: United States<br/>countrycode: US<br/>asn: AS8075 MICROSOFT-CORP-MSN-AS-BLOCK<br/>region: North America<br/>ip: 13.85.152.27<br/>ippopularity: 0 |  |  | 2020-09-11 19:40:48 | 1599853248000 | CMEAtvytG16vv0X01 |

