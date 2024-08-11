# Fortinet FortiNDR Cloud Integration for Cortex XSOAR

## FortiNDR Cloud Overview

Fortinet FortiNDR Cloud is a cloud-native network detection and response solution built for the rapid detection of threat activity, investigation of suspicious behavior, proactive hunting for potential risks, and directing a fast and effective response to active threats.

## Configure Fortinet FortiNDR Cloud on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Instances**.
2. Search for Fortinet FortiNDR Cloud.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Token | True |
    | Connect to UAT Environment | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | True |
    | Detection's status to fetch | False |
    | Include muted detections | False |
    | Include muted devices | False |
    | Include muted rules | False |
    | Fetch incidents | False |
    | Incident type | False |
    | Incident Filter: Account UUID (Optional) | False |
    | Maximum incidents in each fetch each run | False |
    | Delay to allow detection processing before polling | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fortindr-cloud-get-sensors

***
Get a list of all sensors.

#### Base Command

`fortindr-cloud-get-sensors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_uuid | UUID of account to filter by. | Optional | 
| account_code | Account code to filter by. | Optional | 
| sensor_id | ID of the sensor to filter by. | Optional | 
| include | Include additional metadata such as status, interfaces, admin.sensor, admin.zeek, admin.suricata, etc. | Optional | 
| enabled | Filter by true or false. If not provided, all the sensors are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Sensors.created | date | Date when the sensor was created | 
| FortiNDRCloud.Sensors.updated | date | Date when the sensor was last updated | 
| FortiNDRCloud.Sensors.sensor_id | string | ID code of the sensor | 
| FortiNDRCloud.Sensors.account_code | string | ID code of the customer account | 
| FortiNDRCloud.Sensors.location | string | Latitude and longitude where the sensor is located | 
| FortiNDRCloud.Sensors.subdivision | string | State/Province where the sensor is located | 
| FortiNDRCloud.Sensors.city | string | City where the sensor is located | 
| FortiNDRCloud.Sensors.country | string | Country where the sensor is located | 
| FortiNDRCloud.Sensors.tags | string | Labels added for this sensor | 
| FortiNDRCloud.Sensors.pcap_enabled | boolean | If PCAP is enabled on the sensor \(true/false\) | 

#### Command example

```!fortindr-cloud-get-sensors account_uuid=bedf5bf3-94b0-49fa-9085-12ca29876dc3```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Sensors": [
            {
                "account_code": "gig",
                "admin": null,
                "city": null,
                "country": null,
                "created": "2022-12-06T00:26:15.982Z",
                "disabled": null,
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gig2",
                "serial_number": null,
                "status": null,
                "subdivision": null,
                "tags": [],
                "updated": "2022-12-06T00:26:15.982Z"
            },
            {
                "account_code": "gig",
                "admin": null,
                "city": null,
                "country": null,
                "created": "2022-12-06T18:54:29.195Z",
                "disabled": null,
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gig3",
                "serial_number": "VMware-56 4d a9 5a 91 a7 2e ee-74 4d af cb 08 84 34 b4",
                "status": null,
                "subdivision": null,
                "tags": [],
                "updated": "2022-12-06T18:54:29.195Z"
            },
            {
                "account_code": "gig",
                "admin": null,
                "city": "Burnaby",
                "country": "",
                "created": "2022-12-06T22:41:39.561Z",
                "disabled": null,
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gig4",
                "serial_number": null,
                "status": null,
                "subdivision": "",
                "tags": [
                    "AVLab FSA - New Malware"
                ],
                "updated": "2023-05-01T16:27:57.508Z"
            },
            {
                "account_code": "gig",
                "admin": null,
                "city": null,
                "country": null,
                "created": "2022-12-30T16:47:01.725Z",
                "disabled": null,
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gig5",
                "serial_number": null,
                "status": null,
                "subdivision": null,
                "tags": [],
                "updated": "2022-12-30T16:47:01.725Z"
            },
            {
                "account_code": "gig",
                "admin": null,
                "city": null,
                "country": null,
                "created": "2023-02-28T06:16:35.592Z",
                "disabled": null,
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gig6",
                "serial_number": null,
                "status": null,
                "subdivision": null,
                "tags": [],
                "updated": "2023-02-28T06:16:35.592Z"
            },
            {
                "account_code": "gig",
                "admin": null,
                "city": "Burnaby",
                "country": "",
                "created": "2023-04-05T21:39:42.302Z",
                "disabled": null,
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gig7",
                "serial_number": null,
                "status": null,
                "subdivision": "",
                "tags": [
                    "FortiGuard QA"
                ],
                "updated": "2023-05-01T16:28:16.766Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results

>|account_code|admin|city|country|created|disabled|interfaces|location|pcap_enabled|sensor_id|serial_number|status|subdivision|tags|updated|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| gig |  |  |  | 2022-12-06T00:26:15.982Z |  |  |  | false | gig2 |  |  |  |  | 2022-12-06T00:26:15.982Z |
>| gig |  |  |  | 2022-12-06T18:54:29.195Z |  |  |  | false | gig3 | VMware-56 4d a9 5a 91 a7 2e ee-74 4d af cb 08 84 34 b4 |  |  |  | 2022-12-06T18:54:29.195Z |
>| gig |  | Burnaby |  | 2022-12-06T22:41:39.561Z |  |  |  | false | gig4 |  |  |  | AVLab FSA - New Malware | 2023-05-01T16:27:57.508Z |
>| gig |  |  |  | 2022-12-30T16:47:01.725Z |  |  |  | false | gig5 |  |  |  |  | 2022-12-30T16:47:01.725Z |
>| gig |  |  |  | 2023-02-28T06:16:35.592Z |  |  |  | false | gig6 |  |  |  |  | 2023-02-28T06:16:35.592Z |
>| gig |  | Burnaby |  | 2023-04-05T21:39:42.302Z |  |  |  | false | gig7 |  |  |  | FortiGuard QA | 2023-05-01T16:28:16.766Z |


#### Command example

```!fortindr-cloud-get-sensors account_code=gdm```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Sensors": [
            {
                "account_code": "gdm",
                "admin": null,
                "city": "San Jose",
                "country": null,
                "created": "2021-12-17T20:40:54.348Z",
                "disabled": "2022-03-28T18:18:46.826Z",
                "interfaces": null,
                "location": {
                    "latitude": 0,
                    "longitude": 0
                },
                "pcap_enabled": false,
                "sensor_id": "gdm1",
                "serial_number": null,
                "status": null,
                "subdivision": "  USA",
                "tags": [],
                "updated": "2022-11-28T23:24:44.111Z"
            },
            {
                "account_code": "gdm",
                "admin": null,
                "city": "Sunnyvale CA",
                "country": "",
                "created": "2023-01-25T20:11:13.976Z",
                "disabled": null,
                "interfaces": null,
                "location": null,
                "pcap_enabled": true,
                "sensor_id": "gdm3",
                "serial_number": null,
                "status": null,
                "subdivision": "",
                "tags": [
                    "Demo Sensor/Modern"
                ],
                "updated": "2023-04-10T14:55:56.566Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results

>|account_code|admin|city|country|created|disabled|interfaces|location|pcap_enabled|sensor_id|serial_number|status|subdivision|tags|updated|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| gdm |  | San Jose |  | 2021-12-17T20:40:54.348Z | 2022-03-28T18:18:46.826Z |  | latitude: 0.0<br/>longitude: 0.0 | false | gdm1 |  |  |   USA |  | 2022-11-28T23:24:44.111Z |
>| gdm |  | Sunnyvale CA |  | 2023-01-25T20:11:13.976Z |  |  |  | true | gdm3 |  |  |  | Demo Sensor/Modern | 2023-04-10T14:55:56.566Z |


### fortindr-cloud-get-devices

***
Get a list of all devices.

#### Base Command

`fortindr-cloud-get-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Filter devices based on when they were seen. | Optional | 
| end_date | Filter devices based on when they were seen. | Optional | 
| cidr | Filter devices that are under a specific CIDR. | Optional | 
| sensor_id | Filter devices that were observed by a specific sensor. | Optional | 
| traffic_direction | Filter devices that have been noted to only have a certain directionality of traffic ("external" vs "internal"). | Optional | 
| sort_by | Sort output by: "ip_address", "internal", "external". Possible values are: ip_address, internal, external. | Optional | 
| sort_direction | Sort direction ("asc" vs "desc"). Possible values are: asc, desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Devices.date | date | Date when the device was first seen | 
| FortiNDRCloud.Devices.external | boolean | If external traffic has been observed for this device | 
| FortiNDRCloud.Devices.internal | boolean | If internal traffic has been observed for this device | 
| FortiNDRCloud.Devices.ip_address | string | IP address of the device | 
| FortiNDRCloud.Devices.sensor_id | string | ID code of the sensor | 

#### Command example

```!fortindr-cloud-get-devices cidr=2.4.1.1/16```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Devices": [
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "2.4.2.1"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "2.4.2.2"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "2.4.2.3"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results

>|date|external|internal|ip_address|
>|---|---|---|---|
>|  | true | true | 2.4.2.1 |
>|  | true | true | 2.4.2.2 |
>|  | true | true | 2.4.2.3 |

### fortindr-cloud-get-tasks

***
Get a list of all the PCAP tasks.

#### Base Command

`fortindr-cloud-get-tasks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_uuid | Filter to a specific task. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Tasks.task_uuid | string | Unique ID of the task | 
| FortiNDRCloud.Tasks.actual_start_time | date | Date when the task actually ended | 
| FortiNDRCloud.Tasks.requested_start_time | date | Requested date for the task start | 
| FortiNDRCloud.Tasks.updated_email | string | Email address of the user that updated the task | 
| FortiNDRCloud.Tasks.created_uuid | string | Unique ID of the user that created the task | 
| FortiNDRCloud.Tasks.created | date | Date when the task was created | 
| FortiNDRCloud.Tasks.name | string | Name of the task | 
| FortiNDRCloud.Tasks.status | string | Current status of the task | 
| FortiNDRCloud.Tasks.created_email | string | Email address of the user that created the task | 
| FortiNDRCloud.Tasks.updated_uuid | string | Unique ID of the user that updated the task | 
| FortiNDRCloud.Tasks.bpf | string | Berkeley Packet Filter for the task | 
| FortiNDRCloud.Tasks.actual_end_time | date | Date when the task actually ended | 
| FortiNDRCloud.Tasks.account_code | string | ID code of the customer account | 
| FortiNDRCloud.Tasks.requested_end_time | date | Requested date for the task end | 
| FortiNDRCloud.Tasks.updated | date | Date when the task was updated | 
| FortiNDRCloud.Tasks.description | string | Description of the task | 
| FortiNDRCloud.Tasks.has_files | boolean | If this task has files \(true/false\) | 
| FortiNDRCloud.Tasks.sensor_ids | string | Sensors this task is running on | 
| FortiNDRCloud.Tasks.files | string | Files captured for this task | 

#### Command example

```!fortindr-cloud-get-tasks task_uuid=de1ada61-fef3-4cc7-9287-43370cb53ccd```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Tasks": {
            "account_code": "ice",
            "actual_end_time": "2020-01-18T03:16:12.214Z",
            "actual_start_time": "2020-01-17T03:16:12.214Z",
            "bpf": "src host 1.4.1.1 and dst port 10001",
            "created": "2020-01-17T03:18:17.584Z",
            "created_email": "test@test.com",
            "created_uuid": "32329e78-c51f-4da4-bd56-6bfb35d84a9c",
            "description": "src host 1.4.1.1 and dst port 10001",
            "files": [],
            "has_files": false,
            "name": "Meh-Ike phone 10001",
            "requested_end_time": "2020-01-18T03:16:12.214Z",
            "requested_start_time": "2020-01-17T03:16:12.214Z",
            "sensor_ids": [
                "ice1"
            ],
            "status": "inactive",
            "task_uuid": "de1ada61-fef3-4cc7-9287-43370cb53ccd",
            "updated": "2020-01-18T03:17:35.937Z",
            "updated_email": null,
            "updated_uuid": null
        }
    }
}
```

#### Human Readable Output

>### Results

>|account_code|actual_end_time|actual_start_time|bpf|created|created_email|created_uuid|description|files|has_files|name|requested_end_time|requested_start_time|sensor_ids|status|task_uuid|updated|updated_email|updated_uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| ice | 2020-01-18T03:16:12.214Z | 2020-01-17T03:16:12.214Z | src host 1.4.1.1 and dst port 10001 | 2020-01-17T03:18:17.584Z | test@test.com | 32329e78-c51f-4da4-bd56-6bfb35d84a9c | src host 1.4.1.1 and dst port 10001 |  | false | Meh-Ike phone 10001 | 2020-01-18T03:16:12.214Z | 2020-01-17T03:16:12.214Z | ice1 | inactive | de1ada61-fef3-4cc7-9287-43370cb53ccd | 2020-01-18T03:17:35.937Z |  |  |


### fortindr-cloud-create-task

***
Create a new PCAP task.

#### Base Command

`fortindr-cloud-create-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the task. | Required | 
| account_uuid | Account where the task will be created. | Required | 
| description | A description for the task. | Required | 
| bpf | The Berkeley Packet Filter for capture filtering. | Required | 
| requested_start_date | The date the task will become active. (2019-01-30T00:00:00.000Z). | Required | 
| requested_end_date | The date the task will become inactive. (2019-12-31T23:59:59.000Z). | Required | 
| sensor_ids | Sensor IDs on which this task will run (separate multiple accounts by comma). | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!fortindr-cloud-create-task name="Possible Exfiltration via FTP" account_uuid=bedf5bf3-94b0-49fa-9085-12ca29876dc3 description="Capture possible exfiltration via FTP" bpf="host 1.2.3.4 and port 21" requested_start_date=2019-01-01T00:00:00.000Z requested_end_date=2019-01-31T23:59:59.999Z```

#### Human Readable Output

>Task created successfully

### fortindr-cloud-get-telemetry-events

***
Get event telemetry data grouped by time.

#### Base Command

`fortindr-cloud-get-telemetry-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval | Interval to group by: hour (default) or day. Possible values are: hour, day. | Optional | 
| start_date | Start date/time to query for. The default is 1 day ago for interval=hour or 30 days ago for interval=day. | Optional | 
| end_date | End date/time to query for. The default is the current time. | Optional | 
| account_uuid | Account uuid to filter by. | Optional | 
| account_code | Account code to filter by. | Optional | 
| sensor_id | Sensor id to filter by. | Optional | 
| event_type | The type of event. Limited to flow, dns, http, ssl, and x509. Possible values are: flow, dns, http, ssl, x509. | Optional | 
| group_by | Optionally group results by: sensor_id, event_type. Possible values are: sensor_id, event_type. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Telemetry.Events.timestamp | date | Timestamp of the grouped data | 
| FortiNDRCloud.Telemetry.Events.event_count | number | Number of events | 
| FortiNDRCloud.Telemetry.Events.sensor_id | string | Sensor name \(if grouped by sensor_id\) | 
| FortiNDRCloud.Telemetry.Events.event_type | string | Type of event \(if grouped by event_type\) | 

#### Command example

```!fortindr-cloud-get-telemetry-events start_date=2022-08-22T23:00:00.000Z end_date=2022-08-23T01:00:00.000Z```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Telemetry": {
            "Events": [
                {
                    "account_code": null,
                    "event_count": 1791750425,
                    "event_type": null,
                    "sensor_id": null,
                    "timestamp": "2022-08-22T22:00:00.000Z"
                },
                {
                    "account_code": null,
                    "event_count": 1617434640,
                    "event_type": null,
                    "sensor_id": null,
                    "timestamp": "2022-08-22T23:00:00.000Z"
                },
                {
                    "account_code": null,
                    "event_count": 1543942578,
                    "event_type": null,
                    "sensor_id": null,
                    "timestamp": "2022-08-23T00:00:00.000Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results

>|account_code|event_count|event_type|sensor_id|timestamp|
>|---|---|---|---|---|
>|  | 1791750425 |  |  | 2022-08-22T22:00:00.000Z |
>|  | 1617434640 |  |  | 2022-08-22T23:00:00.000Z |
>|  | 1543942578 |  |  | 2022-08-23T00:00:00.000Z |


### fortindr-cloud-get-telemetry-packetstats

***
Get packetstats telemetry data grouped by time.

#### Base Command

`fortindr-cloud-get-telemetry-packetstats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | Scopes the returned metrics to the interfaces of the specified sensor ID. | Optional | 
| start_date | Scopes the returned metrics to dates after the given start_date. If empty returns most current packet stats. | Optional | 
| end_date | Scopes the returned metrics to dates before the given end_date. If empty returns most current packet stats. | Optional | 
| interval | Aggregation interval. 1 hr is not specified by default. | Optional | 
| group_by | Option to group by the following fields: interface_name, sensor_id, account_code. Possible values are: interface_name, sensor_id, account_code. | Optional | 
| account_code | Account code to filter by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Telemetry.Packetstats.account_code | string | Account code the data was filtered by | 
| FortiNDRCloud.Telemetry.Packetstats.timestamp | date | Timestamp of the grouped data | 
| FortiNDRCloud.Telemetry.Packetstats.interface_name | string | Interface the packet data was recorded from | 
| FortiNDRCloud.Telemetry.Packetstats.rx_bits_per_second | number | Receive throughput \(bits per second\) | 
| FortiNDRCloud.Telemetry.Packetstats.rx_bytes | number | Receive data size \(bytes\) | 
| FortiNDRCloud.Telemetry.Packetstats.rx_errors | number | Number of receive errors | 
| FortiNDRCloud.Telemetry.Packetstats.rx_packets | number | Number of receive packets | 
| FortiNDRCloud.Telemetry.Packetstats.sensor_id | string | Sensor ID packet data was recorded from | 
| FortiNDRCloud.Telemetry.Packetstats.tx_bytes | number | Transmit data size \(bytes\) | 
| FortiNDRCloud.Telemetry.Packetstats.tx_errors | number | Number of transmit errors | 
| FortiNDRCloud.Telemetry.Packetstats.tx_packets | number | Number of transmit packets | 

#### Command example

```!fortindr-cloud-get-telemetry-packetstats start_date=2022-08-22T23:00:00.000Z end_date=2022-08-23T01:00:00.000Z```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Telemetry": {
            "Packetstats": [
                {
                    "account_code": null,
                    "interface_name": null,
                    "rx_bits_per_second": 168359035095,
                    "rx_bytes": 1044065401242303200,
                    "rx_errors": 543523121859,
                    "rx_packets": 1511658249026538,
                    "sensor_id": null,
                    "timestamp": "2022-08-22T23:00:00.000Z",
                    "tx_bytes": 1380372603073006,
                    "tx_errors": 0,
                    "tx_packets": 963173536282
                },
                {
                    "account_code": null,
                    "interface_name": null,
                    "rx_bits_per_second": 160856509712,
                    "rx_bytes": 1044106567515174300,
                    "rx_errors": 543525834334,
                    "rx_packets": 1511702749558442,
                    "sensor_id": null,
                    "timestamp": "2022-08-23T00:00:00.000Z",
                    "tx_bytes": 1380469345659022,
                    "tx_errors": 0,
                    "tx_packets": 963257751918
                },
                {
                    "account_code": null,
                    "interface_name": null,
                    "rx_bits_per_second": 157692928879,
                    "rx_bytes": 1044177528134177800,
                    "rx_errors": 543528505834,
                    "rx_packets": 1511789654722335,
                    "sensor_id": null,
                    "timestamp": "2022-08-23T01:00:00.000Z",
                    "tx_bytes": 1380567602819055,
                    "tx_errors": 0,
                    "tx_packets": 963324752205
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results

>|account_code|interface_name|rx_bits_per_second|rx_bytes|rx_errors|rx_packets|sensor_id|timestamp|tx_bytes|tx_errors|tx_packets|
>|---|---|---|---|---|---|---|---|---|---|---|
>|  |  | 168359035095 | 1044065401242303278 | 543523121859 | 1511658249026538 |  | 2022-08-22T23:00:00.000Z | 1380372603073006 | 0 | 963173536282 |
>|  |  | 160856509712 | 1044106567515174237 | 543525834334 | 1511702749558442 |  | 2022-08-23T00:00:00.000Z | 1380469345659022 | 0 | 963257751918 |
>|  |  | 157692928879 | 1044177528134177845 | 543528505834 | 1511789654722335 |  | 2022-08-23T01:00:00.000Z | 1380567602819055 | 0 | 963324752205 |


### fortindr-cloud-get-telemetry-network

***
Get network telemetry data grouped by time

#### Base Command

`fortindr-cloud-get-telemetry-network`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_code | Account code to filter by. | Optional | 
| interval | The interval to filter by (day, month_to_day). Possible values are: day, month_to_day. | Optional | 
| latest_each_month | Filters out all but the latest day and month_to_date for each month. | Optional | 
| sort_order | Sorts by account code first, then timestamp. asc or desc. The default is desc. Possible values are: asc, desc. | Optional | 
| limit | The maximum number of records to return, default: 100, max: 1000. Default is 1000. | Optional | 
| offset | The number of records to skip past. Default: 0. | Optional | 
| start_date | Start date to filter by. | Optional | 
| end_date | End date to filter by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Telemetry.NetworkUsage.account_code | string | The account code for the network usage. | 
| FortiNDRCloud.Telemetry.NetworkUsage.percentile_bps | long | The top percentile BPS value across sensors. | 
| FortiNDRCloud.Telemetry.NetworkUsage.percentile | int | Percentile of BPS records to calculate for percentile_bps. | 
| FortiNDRCloud.Telemetry.NetworkUsage.interval | unknown | Time span the calculation was performed over \(day, month_to_day\). | 
| FortiNDRCloud.Telemetry.Packetstats.timestamp | date | The date the calculation was performed until. | 

#### Command example

```!fortindr-cloud-get-telemetry-network start_date=2022-08-21T00:00:00.000Z end_date=2022-08-21T01:00:00.000Z interval=day```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Telemetry": {
            "NetworkUsage": [
                {
                    "account_code": "zgv",
                    "interval": "day",
                    "percentile": 95,
                    "percentile_bps": 6050493542,
                    "timestamp": "2022-08-21T00:00:00.000000Z"
                },
                {
                    "account_code": "ysz",
                    "interval": "day",
                    "percentile": 95,
                    "percentile_bps": 26125723400,
                    "timestamp": "2022-08-21T00:00:00.000000Z"
                },
                {
                    "account_code": "wum",
                    "interval": "day",
                    "percentile": 95,
                    "percentile_bps": 795340046,
                    "timestamp": "2022-08-21T00:00:00.000000Z"
                },
                {
                    "account_code": "vzg",
                    "interval": "day",
                    "percentile": 95,
                    "percentile_bps": 74340264,
                    "timestamp": "2022-08-21T00:00:00.000000Z"
                },
                {
                    "account_code": "u0y4hMKN",
                    "interval": "day",
                    "percentile": 95,
                    "percentile_bps": 990223331,
                    "timestamp": "2022-08-21T00:00:00.000000Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results

>|account_code|interval|percentile|percentile_bps|timestamp|
>|---|---|---|---|---|
>| zgv | day | 95 | 6050493542 | 2022-08-21T00:00:00.000000Z |
>| ysz | day | 95 | 26125723400 | 2022-08-21T00:00:00.000000Z |
>| wum | day | 95 | 795340046 | 2022-08-21T00:00:00.000000Z |
>| vzg | day | 95 | 74340264 | 2022-08-21T00:00:00.000000Z |
>| u0y4hMKN | day | 95 | 990223331 | 2022-08-21T00:00:00.000000Z |


### fortindr-cloud-get-entity-summary

***
Get summary information about an IP or domain.

#### Base Command

`fortindr-cloud-get-entity-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | IP or Domain to get entity data for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Entity.Summary.entity | string | Entity identifier | 
| FortiNDRCloud.Entity.Summary.first_seen | date | First seen date for this entity | 
| FortiNDRCloud.Entity.Summary.last_seen | date | Last seen date for this entity | 
| FortiNDRCloud.Entity.Summary.prevalence_count_internal | number | Prevalence for this entity within the environment | 

#### Command example

```!fortindr-cloud-get-entity-summary entity=8.8.8.8```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Entity": {
            "Summary": {
                "entity": "8.8.8.8",
                "first_seen": null,
                "last_seen": null,
                "prevalence_count_internal": 0,
                "tags": [
                    {
                        "account_code": "ice",
                        "create_date": "2022-02-08T23:25:54.676Z",
                        "entity": "8.8.8.8",
                        "public": false,
                        "text": "abc",
                        "user_uuid": "3824a467-b192-40ce-ab56-2b97134a49f4"
                    },
                    {
                        "account_code": "srt",
                        "create_date": "2021-11-29T23:47:43.237Z",
                        "entity": "8.8.8.8",
                        "public": false,
                        "text": "external",
                        "user_uuid": "aaf2c09e-23f0-48fb-bead-9f7615b7b198"
                    },
                    {
                        "account_code": "YeqUvMQNgEa",
                        "create_date": "2020-07-22T15:47:12.739Z",
                        "entity": "8.8.8.8",
                        "public": false,
                        "text": "Google DNS",
                        "user_uuid": "fc529b6d-8315-44f8-a288-a103ebf64516"
                    },
                    {
                        "account_code": "yuc",
                        "create_date": "2020-07-22T17:26:50.620Z",
                        "entity": "8.8.8.8",
                        "public": false,
                        "text": "test",
                        "user_uuid": "aaf2c09e-23f0-48fb-bead-9f7615b7b198"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Results

>|entity|first_seen|last_seen|prevalence_count_internal|tags|
>|---|---|---|---|---|
>| 8.8.8.8 |  |  | 0 | {'text': 'abc', 'account_code': 'ice', 'user_uuid': '3824a467-b192-40ce-ab56-2b97134a49f4', 'create_date': '2022-02-08T23:25:54.676Z', 'entity': '8.8.8.8', 'public': False},<br/>{'text': 'external', 'account_code': 'srt', 'user_uuid': 'aaf2c09e-23f0-48fb-bead-9f7615b7b198', 'create_date': '2021-11-29T23:47:43.237Z', 'entity': '8.8.8.8', 'public': False},<br/>{'text': 'Google DNS', 'account_code': 'YeqUvMQNgEa', 'user_uuid': 'fc529b6d-8315-44f8-a288-a103ebf64516', 'create_date': '2020-07-22T15:47:12.739Z', 'entity': '8.8.8.8', 'public': False},<br/>{'text': 'test', 'account_code': 'yuc', 'user_uuid': 'aaf2c09e-23f0-48fb-bead-9f7615b7b198', 'create_date': '2020-07-22T17:26:50.620Z', 'entity': '8.8.8.8', 'public': False} |


### fortindr-cloud-get-entity-pdns

***
Get passive DNS information about an IP or domain.

#### Base Command

`fortindr-cloud-get-entity-pdns`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | IP or Domain to get passive DNS data for. | Required | 
| record_type | Limit results to the specified DNS query type(s). | Optional | 
| source | Limit the results to the specified data source(s). | Optional | 
| resolve_external | When true, the service will query non-ICEBRG data sources. false by default. | Optional | 
| start_date | The earliest date before which to exclude results. Day granularity, inclusive. | Optional | 
| end_date | The latest date after which to exclude results. Day granularity, inclusive. | Optional | 
| account_uuid | Limit results to the specified account UUID(s). Defaults to all accounts for which the user has permission. | Optional | 
| limit | Maximum number of records to be returned. Default 1000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Entity.PDNS.account_uuid | string | Unique ID for the customer account | 
| FortiNDRCloud.Entity.PDNS.first_seen | date | First seen date for matching dns information | 
| FortiNDRCloud.Entity.PDNS.last_seen | date | Last seen date for matching dns information | 
| FortiNDRCloud.Entity.PDNS.record_type | string | DNS record type | 
| FortiNDRCloud.Entity.PDNS.resolved | string | Domain name resolved from the DNS record | 
| FortiNDRCloud.Entity.PDNS.sensor_id | string | ID code of the sensor | 
| FortiNDRCloud.Entity.PDNS.source | string | Source of the DNS record | 

#### Command example

```!fortindr-cloud-get-entity-pdns entity=google.com limit=3```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Entity": {
            "PDNS": [
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2022-04-06T00:00:00.000Z",
                    "last_seen": "2022-08-24T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "5.1.3.1",
                    "sensor_id": "gdm2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2022-04-03T00:00:00.000Z",
                    "last_seen": "2022-08-21T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "5.1.1.1",
                    "sensor_id": "gdm2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2022-03-30T00:00:00.000Z",
                    "last_seen": "2022-08-24T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "5.1.2.1",
                    "sensor_id": "gdm2",
                    "source": "icebrg_dns"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results

>|account_uuid|first_seen|last_seen|record_type|resolved|sensor_id|source|
>|---|---|---|---|---|---|---|
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-06T00:00:00.000Z | 2022-08-24T00:00:00.000Z | a | 5.1.3.1 | gdm2 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-03T00:00:00.000Z | 2022-08-21T00:00:00.000Z | a | 5.1.1.1 | gdm2 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-03-30T00:00:00.000Z | 2022-08-24T00:00:00.000Z | a | 5.1.2.1 | gdm2 | icebrg_dns |

### fortindr-cloud-get-entity-dhcp

***
Get DHCP information about an IP address.

#### Base Command

`fortindr-cloud-get-entity-dhcp`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | IP to get DHCP data for. | Required | 
| start_date | The earliest date before which to exclude results. Day granularity, inclusive. | Optional | 
| end_date | The latest date after which to exclude results. Day granularity, inclusive. | Optional | 
| account_uuid | Limit results to the specified account UUID(s). Defaults to all accounts for which the user has permission. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Entity.DHCP.customer_id | string | ID code of the customer account | 
| FortiNDRCloud.Entity.DHCP.hostnames | string | Hostname of the entity | 
| FortiNDRCloud.Entity.DHCP.ip | string | IP Address of the entity | 
| FortiNDRCloud.Entity.DHCP.lease_end | date | DHCP lease end date | 
| FortiNDRCloud.Entity.DHCP.lease_start | date | DHCP lease start date | 
| FortiNDRCloud.Entity.DHCP.mac | string | MAC address of the entity | 
| FortiNDRCloud.Entity.DHCP.sensor_id | string | Sensor ID that recorded the entity data | 
| FortiNDRCloud.Entity.DHCP.start_lease_as_long | number | Start Date as a long value | 

#### Command example

```!fortindr-cloud-get-entity-dhcp entity=1.3.1.1 start_date=2023-01-01T00:00:00.000Z```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Entity": {
            "DHCP": [
                {
                    "customer_id": "chf",
                    "hostnames": [
                        "DZVZZY2"
                    ],
                    "ip": "1.3.1.1",
                    "lease_end": null,
                    "lease_start": "2023-04-10T16:00:25.623Z",
                    "mac": "98:e7:43:c6:69:e2",
                    "sensor_id": null,
                    "start_lease_as_long": 1681142425623
                },
                {
                    "customer_id": "gst",
                    "hostnames": [
                        "C02YC4RCJHD2"
                    ],
                    "ip": "1.3.1.1",
                    "lease_end": null,
                    "lease_start": "2019-12-03T20:00:57.802Z",
                    "mac": "d8:d0:90:06:8b:3b",
                    "sensor_id": null,
                    "start_lease_as_long": 1575403257802
                },
                {
                    "customer_id": "chf",
                    "hostnames": [
                        "C02CK4ADLVDL"
                    ],
                    "ip": "1.3.1.1",
                    "lease_end": "2023-04-10T16:00:25.623Z",
                    "lease_start": "2023-03-13T14:43:16.004Z",
                    "mac": "00:24:9b:48:03:e7",
                    "sensor_id": null,
                    "start_lease_as_long": 1678718596004
                },
                {
                    "customer_id": "chf",
                    "hostnames": [
                        "C02YG1D9JHD2"
                    ],
                    "ip": "1.3.1.1",
                    "lease_end": "2023-03-13T14:43:16.004Z",
                    "lease_start": "2023-02-21T17:43:46.991Z",
                    "mac": "70:88:6b:88:25:a6",
                    "sensor_id": null,
                    "start_lease_as_long": 1677001426991
                },
                {
                    "customer_id": "chf",
                    "hostnames": [],
                    "ip": "1.3.1.1",
                    "lease_end": "2023-02-21T17:43:46.991Z",
                    "lease_start": "2023-02-21T17:41:33.830Z",
                    "mac": "70:88:6b:88:25:a6",
                    "sensor_id": null,
                    "start_lease_as_long": 1677001293830
                },
                {
                    "customer_id": "chf",
                    "hostnames": [
                        "HQ_MFG_TE_LAB1"
                    ],
                    "ip": "1.3.1.1",
                    "lease_end": "2023-02-21T17:41:33.830Z",
                    "lease_start": "2022-05-15T20:32:25.250Z",
                    "mac": "98:90:96:b5:82:b4",
                    "sensor_id": null,
                    "start_lease_as_long": 1652646745250
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results

>|customer_id|hostnames|ip|lease_end|lease_start|mac|sensor_id|start_lease_as_long|
>|---|---|---|---|---|---|---|---|
>| chf | DZVZZY2 | 1.3.1.1 |  | 2023-04-10T16:00:25.623Z | 98:e7:43:c6:69:e2 |  | 1681142425623 |
>| gst | C02YC4RCJHD2 | 1.3.1.1 |  | 2019-12-03T20:00:57.802Z | d8:d0:90:06:8b:3b |  | 1575403257802 |
>| chf | C02CK4ADLVDL | 1.3.1.1 | 2023-04-10T16:00:25.623Z | 2023-03-13T14:43:16.004Z | 00:24:9b:48:03:e7 |  | 1678718596004 |
>| chf | C02YG1D9JHD2 | 1.3.1.1 | 2023-03-13T14:43:16.004Z | 2023-02-21T17:43:46.991Z | 70:88:6b:88:25:a6 |  | 1677001426991 |
>| chf |  | 1.3.1.1 | 2023-02-21T17:43:46.991Z | 2023-02-21T17:41:33.830Z | 70:88:6b:88:25:a6 |  | 1677001293830 |
>| chf | HQ_MFG_TE_LAB1 | 1.3.1.1 | 2023-02-21T17:41:33.830Z | 2022-05-15T20:32:25.250Z | 98:90:96:b5:82:b4 |  | 1652646745250 |


### fortindr-cloud-get-entity-file

***
Get information about a file.

#### Base Command

`fortindr-cloud-get-entity-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | File hash. Can be an MD5, SHA1, or SHA256 hash of the file. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Entity.File.entity | string | The entity identifier | 
| FortiNDRCloud.Entity.File.sha1 | string | The entity SHA1 hash | 
| FortiNDRCloud.Entity.File.sha256 | string | The entity SHA256 hash | 
| FortiNDRCloud.Entity.File.md5 | string | The entity MD5 hash | 
| FortiNDRCloud.Entity.File.customer_id | string | ID code of the customer account | 
| FortiNDRCloud.Entity.File.names | string | File names for the entity | 
| FortiNDRCloud.Entity.File.prevalence_count_internal | number | Prevalence for this file within the environment | 
| FortiNDRCloud.Entity.File.last_seen | date | Last seen date for this file | 
| FortiNDRCloud.Entity.File.mime_type | string | File MIME type | 
| FortiNDRCloud.Entity.File.first_seen | date | First seen date for this file | 
| FortiNDRCloud.Entity.File.bytes | number | File size | 
| FortiNDRCloud.Entity.File.pe | string | File Portable Executable attributes | 

#### Command example

```!fortindr-cloud-get-entity-file hash=2b7a609371b2a844181c2f79f1b45cf7```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Entity": {
            "File": {
                "bytes": null,
                "customer_id": null,
                "entity": null,
                "first_seen": null,
                "last_seen": null,
                "md5": null,
                "mime_type": [],
                "names": [],
                "pe": null,
                "prevalence_count_internal": null,
                "sha1": null,
                "sha256": null
            }
        }
    }
}
```

#### Human Readable Output

>### Results

>|bytes|customer_id|entity|first_seen|last_seen|md5|mime_type|names|pe|prevalence_count_internal|sha1|sha256|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  |  |  |  |  |  |  |  |  |  |  |


### fortindr-cloud-get-detections

***
Get a list of detections.

#### Base Command

`fortindr-cloud-get-detections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_uuid | Filter to a specific rule. | Optional | 
| account_uuid | For those with access to multiple accounts, specify a single account to return results from. | Optional | 
| status | Filter by detection status: active, resolved. | Optional | 
| device_ip | Device IP to filter by. | Optional | 
| sensor_id | Sensor ID to filter by. | Optional | 
| muted | List detections that a user muted: true / false. | Optional | 
| muted_device | List detections for muted devices: true / false. | Optional | 
| muted_rule | List detections for muted rules. | Optional | 
| include | Include additional information in the response (rules). Possible values are: rules, indicators. | Optional | 
| sort_by | Field to sort by (first_seen, last_seen, status, device_ip, indicator_count). Possible values are: first_seen, last_seen, status, device_ip, indicator_count. | Optional | 
| sort_order | Sort direction ("asc" vs "desc"). Possible values are: asc, desc. | Optional | 
| offset | The number of records to skip past. | Optional | 
| limit | The number of records to return, default: 100, max: 1000. Default is 1000. | Optional | 
| created_start_date | Created start date to filter by (inclusive). | Optional | 
| created_end_date | Created end date to filter by (exclusive). | Optional | 
| created_or_shared_start_date | Created or shared start date to filter by (inclusive). | Optional | 
| created_or_shared_end_date | Created or shared end date to filter by (exclusive). | Optional | 
| active_start_date | Active start date to filter by (inclusive). | Optional | 
| active_end_date | Active end date to filter by (exclusive). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Detections.muted_rule | boolean | Is this rule muted \(true/false\) | 
| FortiNDRCloud.Detections.created | date | Date when the detection was created | 
| FortiNDRCloud.Detections.account_uuid | unknown | Unique ID of the account for this detection | 
| FortiNDRCloud.Detections.resolution_timestamp | date | Date when the detection was resolved | 
| FortiNDRCloud.Detections.first_seen | date | Date when the detection was first seen | 
| FortiNDRCloud.Detections.muted | boolean | If the detection is muted or not \(true/false\) | 
| FortiNDRCloud.Detections.resolution | string | Resolution type | 
| FortiNDRCloud.Detections.muted_user_uuid | string | Unique ID of the user that muted the detection | 
| FortiNDRCloud.Detections.last_seen | date | Date when the detection was last seen | 
| FortiNDRCloud.Detections.status | string | Current status of the detection | 
| FortiNDRCloud.Detections.resolution_user_uuid | string | Unique identifier of the user that resolved the detection | 
| FortiNDRCloud.Detections.resolution_comment | string | Comment entered when detection was resolved | 
| FortiNDRCloud.Detections.muted_comment | string | Comment entered when detection was muted | 
| FortiNDRCloud.Detections.sensor_id | string | ID code of the sensor | 
| FortiNDRCloud.Detections.rule_uuid | string | Unique ID of the rule for this detection | 
| FortiNDRCloud.Detections.updated | date | Date when the detection was last updated | 
| FortiNDRCloud.Detections.uuid | string | Unique ID of the detection | 
| FortiNDRCloud.Detections.muted_device_uuid | string | Unique ID of the muted device | 
| FortiNDRCloud.Detections.device_ip | string | IP address of the detection | 

#### Command example

```!fortindr-cloud-get-detections status=active include=rules created_or_shared_start_date=2022-08-23T22:00:00.000Z created_or_shared_end_date=2022-08-23T22:30:00.000Z```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Detections": [
            {
                "account_uuid": "1e5dbd92-9dca-4f36-bec5-c292172cbeaa",
                "created": "2022-08-23T22:24:44.047670Z",
                "device_ip": "7.3.2.1",
                "event_count": 2,
                "first_seen": "2022-08-23T21:44:33.343000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-23T22:02:18.535000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": true,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Miscellaneous",
                "rule_confidence": "high",
                "rule_description": "test",
                "rule_name": "test icebrg",
                "rule_severity": "high",
                "rule_uuid": "40b4d7e2-66f7-412f-b997-4ec6734313f4",
                "sensor_id": "rzt37",
                "status": "active",
                "updated": "2022-08-23T23:25:06.721425Z",
                "username": null,
                "uuid": "631616f0-27ad-434e-bbfa-f8808785ec40"
            },
            {
                "account_uuid": "1e5dbd92-9dca-4f36-bec5-c292172cbeaa",
                "created": "2022-08-23T22:25:41.295229Z",
                "device_ip": "7.3.2.1",
                "event_count": 2,
                "first_seen": "2022-08-23T21:44:33.343000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-23T22:02:18.535000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": true,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Miscellaneous",
                "rule_confidence": "high",
                "rule_description": "test",
                "rule_name": "test icebrg",
                "rule_severity": "high",
                "rule_uuid": "432ec2a3-11d8-4bd8-81fa-abd39dac5a8d",
                "sensor_id": "rzt37",
                "status": "active",
                "updated": "2022-08-23T23:25:58.939678Z",
                "username": null,
                "uuid": "6e534db2-07db-4cb5-ad36-7bbbcdd9f31f"
            },
            {
                "account_uuid": "1e5dbd92-9dca-4f36-bec5-c292172cbeaa",
                "created": "2022-08-23T22:26:36.675600Z",
                "device_ip": "7.3.2.1",
                "event_count": 2,
                "first_seen": "2022-08-23T21:44:33.343000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-23T22:02:18.535000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": true,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Miscellaneous",
                "rule_confidence": "high",
                "rule_description": "test",
                "rule_name": "test icebrg",
                "rule_severity": "high",
                "rule_uuid": "46e00dd4-2bf2-4d1c-99e7-b5ac8bc71b62",
                "sensor_id": "rzt37",
                "status": "active",
                "updated": "2022-08-23T23:26:59.600742Z",
                "username": null,
                "uuid": "d1264843-cb3d-4f31-a19c-7291a5a4fbbd"
            },
            {
                "account_uuid": "55985199-810b-4a7b-aa88-10190796fb6b",
                "created": "2022-08-23T22:00:02.068235Z",
                "device_ip": "7.4.1.1",
                "event_count": 84,
                "first_seen": "2022-08-23T18:12:32.545000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-10-31T01:45:51.512000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": "9e62c23c-93e0-422c-915f-0fdb8ba49bcd",
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Posture:Potentially Unauthorized Software or Device",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect HTTP connections made by the TeamViewer remote administration tool. A remote administration tool is a type of software that allows remote users to manage a host as if they had physical access. These types of tools can serve legitimate purposes in an enterprise environment but, if installed without authorization, may also indicate a compromised host. An attacker with access to a remote administration tool on a system can use it to surveil the user, install malware, or exfiltrate files from the remote host. Unauthorized installations also provide access to the enterprise network, circumventing any network controls. \r\n\r\nFortiGuard ATR considers TeamViewer to be moderate severity, since it is not inherently malicious, but may be indicative of an attempt to circumvent organizational security controls or a malicious actor using it unbeknownst to the user for privileged remote access. FortiGuard ATR considers this detection high confidence due to the uniqueness of the user agent in HTTP requests made by the client.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by verifying that the affected host has the TeamViewer software installed.\r\n2. Remove any unapproved software.\r\n3. Control software installations on company assets.",
                "rule_name": "TeamViewer Remote Administration Tool",
                "rule_severity": "moderate",
                "rule_uuid": "b1258c0b-3442-43e8-a98e-66440ebdbe6d",
                "sensor_id": "csp1",
                "status": "active",
                "updated": "2022-10-31T02:52:02.084699Z",
                "username": null,
                "uuid": "280fc4c8-8e04-4110-86f5-4022595882bf"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results

>|account_uuid|created|device_ip|event_count|first_seen|hostname|indicators|last_seen|muted|muted_comment|muted_device_uuid|muted_rule|muted_timestamp|muted_user_uuid|resolution|resolution_comment|resolution_timestamp|resolution_user_uuid|rule_category|rule_confidence|rule_description|rule_name|rule_severity|rule_uuid|sensor_id|status|updated|username|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1e5dbd92-9dca-4f36-bec5-c292172cbeaa | 2022-08-23T22:24:44.047670Z | 7.3.2.1 | 2 | 2022-08-23T21:44:33.343000Z |  |  | 2022-08-23T22:02:18.535000Z | false |  |  | true |  |  |  |  |  |  | Miscellaneous | high | test | test icebrg | high | 40b4d7e2-66f7-412f-b997-4ec6734313f4 | rzt37 | active | 2022-08-23T23:25:06.721425Z |  | 631616f0-27ad-434e-bbfa-f8808785ec40 |
>| 1e5dbd92-9dca-4f36-bec5-c292172cbeaa | 2022-08-23T22:25:41.295229Z | 7.3.2.1 | 2 | 2022-08-23T21:44:33.343000Z |  |  | 2022-08-23T22:02:18.535000Z | false |  |  | true |  |  |  |  |  |  | Miscellaneous | high | test | test icebrg | high | 432ec2a3-11d8-4bd8-81fa-abd39dac5a8d | rzt37 | active | 2022-08-23T23:25:58.939678Z |  | 6e534db2-07db-4cb5-ad36-7bbbcdd9f31f |
>| 1e5dbd92-9dca-4f36-bec5-c292172cbeaa | 2022-08-23T22:26:36.675600Z | 7.3.2.1 | 2 | 2022-08-23T21:44:33.343000Z |  |  | 2022-08-23T22:02:18.535000Z | false |  |  | true |  |  |  |  |  |  | Miscellaneous | high | test | test icebrg | high | 46e00dd4-2bf2-4d1c-99e7-b5ac8bc71b62 | rzt37 | active | 2022-08-23T23:26:59.600742Z |  | d1264843-cb3d-4f31-a19c-7291a5a4fbbd |
>| 55985199-810b-4a7b-aa88-10190796fb6b | 2022-08-23T22:00:02.068235Z | 7.4.1.1 | 84 | 2022-08-23T18:12:32.545000Z |  |  | 2022-10-31T01:45:51.512000Z | false |  | 9e62c23c-93e0-422c-915f-0fdb8ba49bcd | false |  |  |  |  |  |  | Posture:Potentially Unauthorized Software or Device | high | This logic is intended to detect HTTP connections made by the TeamViewer remote administration tool. A remote administration tool is a type of software that allows remote users to manage a host as if they had physical access. These types of tools can serve legitimate purposes in an enterprise environment but, if installed without authorization, may also indicate a compromised host. An attacker with access to a remote administration tool on a system can use it to surveil the user, install malware, or exfiltrate files from the remote host. Unauthorized installations also provide access to the enterprise network, circumventing any network controls. <br/><br/>FortiGuard ATR considers TeamViewer to be moderate severity, since it is not inherently malicious, but may be indicative of an attempt to circumvent organizational security controls or a malicious actor using it unbeknownst to the user for privileged remote access. FortiGuard ATR considers this detection high confidence due to the uniqueness of the user agent in HTTP requests made by the client.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by verifying that the affected host has the TeamViewer software installed.<br/>2. Remove any unapproved software.<br/>3. Control software installations on company assets. | TeamViewer Remote Administration Tool | moderate | b1258c0b-3442-43e8-a98e-66440ebdbe6d | csp1 | active | 2022-10-31T02:52:02.084699Z |  | 280fc4c8-8e04-4110-86f5-4022595882bf |


### fortindr-cloud-get-detection-rules

***
Get a list of detection rules.

#### Base Command

`fortindr-cloud-get-detection-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_uuid | For those with access to multiple accounts, specify a single account to return results from. | Optional | 
| search | Filter name or category. | Optional | 
| has_detections | Include rules that have unmuted, unresolved detections. Possible values are: true, false. | Optional | 
| severity | Filter by severity: high, moderate, low. Possible values are: low, moderate, high. | Optional | 
| confidence | Filter by confidence: high, moderate, low. Possible values are: low, moderate, high. | Optional | 
| category | Category to filter by. Possible values are: Attack:Command and Control, Attack:Exploitation, Attack:Exfiltration, Attack:Installation, Attack:Lateral Movement, Attack:Infection Vector, Attack:Miscellaneous, Miscellaneous, Posture:Anomalous Activity, Posture:Insecure Configuration, Posture:Potentially Unauthorized Software or Device, Posture:Miscellaneous, PUA:Adware, PUA:Spyware, PUA:Unauthorized Resource Use, PUA:Miscellaneous. | Optional | 
| rule_account_muted | Include muted rules: true / false. Possible values are: true, false. | Optional | 
| enabled | Enabled rules only. Possible values are: true, false. | Optional | 
| sort_by | The field to sort by: created, updated, detections, severity, confidence, category, last_seen, detections_muted. Defaults to updated. Possible values are: created, updated, detections, severity, confidence, category, last_seen, detections_muted. | Optional | 
| sort_order | Sort direction ("asc" vs "desc"). Possible values are: asc, desc. | Optional | 
| offset | The number of records to skip past. | Optional | 
| limit | The number of records to return, default: 100, max: 1000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Rules.enabled | boolean | Status of the rule: If true it is enabled, if false it is disabled. | 
| FortiNDRCloud.Rules.updated_user_uuid | string | User ID that updated the rule | 
| FortiNDRCloud.Rules.rule_accounts | string | Accounts which have seen detections for this rule | 
| FortiNDRCloud.Rules.auto_resolution_minutes | number | Length of time \(in minutes\) the rule will auto-resolve detections | 
| FortiNDRCloud.Rules.created | date | Date the rule was created | 
| FortiNDRCloud.Rules.account_uuid | string | Account ID the rule was created under | 
| FortiNDRCloud.Rules.confidence | string | Confidence level of the rule | 
| FortiNDRCloud.Rules.name | string | Name of the rule | 
| FortiNDRCloud.Rules.created_user_uuid | string | User ID that created the rule | 
| FortiNDRCloud.Rules.query_signature | string | IQL signature of the rule | 
| FortiNDRCloud.Rules.shared_account_uuids | string | Account IDs the rule is visible to | 
| FortiNDRCloud.Rules.run_account_uuids | string | Account IDs the rule runs on | 
| FortiNDRCloud.Rules.updated | date | Date the rule was updated | 
| FortiNDRCloud.Rules.uuid | string | Unique ID of the rule | 
| FortiNDRCloud.Rules.description | string | Description of the rule | 
| FortiNDRCloud.Rules.severity | string | Severity level of the rule | 
| FortiNDRCloud.Rules.category | string | Category of the rule | 

#### Command example

```!fortindr-cloud-get-detection-rules confidence=high category=Attack:Installation limit=2```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Rules": [
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 30240,
                "category": "Attack:Installation",
                "confidence": "high",
                "created": "2023-05-11T17:02:09.720180Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2023-05-11T17:02:09.720180Z",
                "description": "Test",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:user_agent",
                    "http:uri.uri"
                ],
                "name": "Test: Cobalt Strike JasperLoader Malleable Stager HTTP Request",
                "primary_attack_id": "T1105",
                "query_signature": "(\r\n    http:src.internal = true\r\n    OR http:source = \"Zscaler\"\r\n)\r\nAND uri.path IN (\"/501\", \"/502\")\r\nAND uri.query = \"dwgvhgc=\"",
                "rule_accounts": [
                    {
                        "account_uuid": "21379211-3c42-45f3-b6a7-33f489d09641",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T17:02:09.855742Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    },
                    {
                        "account_uuid": "6bc3d2f1-af77-4236-a9db-17dacd06e4d9",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T17:02:09.975786Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    },
                    {
                        "account_uuid": "29266c1a-645b-458e-b4c7-9bb3405d79be",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T17:02:10.095205Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    },
                    {
                        "account_uuid": "f6f6f836-8bcd-4f5d-bd61-68d303c4f634",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T17:02:10.151422Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    },
                    {
                        "account_uuid": "11a7364e-f020-4ba3-b7c1-ac17006f379b",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T17:02:10.040958Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    },
                    {
                        "account_uuid": "6679810e-5a03-4a82-8458-d1c76b3e1942",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T17:02:09.782635Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    },
                    {
                        "account_uuid": "55f39b72-2622-4137-9051-bc2ff364f059",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T17:02:09.915832Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "9a555e95-e868-4146-a23b-2b88da6a3304"
                ],
                "secondary_attack_id": "T1027.005",
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "tool_implementation",
                "updated": "2023-05-11T17:02:09.720180Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "26874859-0148-4d7f-9a83-145d74830cd9"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 30240,
                "category": "Attack:Installation",
                "confidence": "high",
                "created": "2023-05-11T16:51:20.566178Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2023-05-11T16:51:20.566178Z",
                "description": "Test",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:user_agent",
                    "http:uri.uri"
                ],
                "name": "Test: Cobalt Strike GlobeImposter Malleable Stager HTTP Request",
                "primary_attack_id": "T1105",
                "query_signature": "(\r\n    http:src.internal = true\r\n    OR http:source = \"Zscaler\"\r\n)\r\nAND uri.path IN (\"/JHGCd476334\", \"/JHGcD476334\")",
                "rule_accounts": [
                    {
                        "account_uuid": "55f39b72-2622-4137-9051-bc2ff364f059",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T16:51:20.727818Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    },
                    {
                        "account_uuid": "f6f6f836-8bcd-4f5d-bd61-68d303c4f634",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T16:51:20.969115Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    },
                    {
                        "account_uuid": "11a7364e-f020-4ba3-b7c1-ac17006f379b",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T16:51:20.846743Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    },
                    {
                        "account_uuid": "21379211-3c42-45f3-b6a7-33f489d09641",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T16:51:20.683717Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    },
                    {
                        "account_uuid": "6679810e-5a03-4a82-8458-d1c76b3e1942",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T16:51:20.622813Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    },
                    {
                        "account_uuid": "6bc3d2f1-af77-4236-a9db-17dacd06e4d9",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T16:51:20.789274Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    },
                    {
                        "account_uuid": "29266c1a-645b-458e-b4c7-9bb3405d79be",
                        "detection_count": null,
                        "detection_muted_count": null,
                        "detection_resolved_count": null,
                        "first_seen": null,
                        "last_seen": null,
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2023-05-11T16:51:20.907381Z",
                        "muted_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "9a555e95-e868-4146-a23b-2b88da6a3304"
                ],
                "secondary_attack_id": "T1027.005",
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "tool_implementation",
                "updated": "2023-05-11T16:51:20.566178Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "90403613-164d-4aa5-8370-c4a3924a4533"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results

>|account_uuid|auto_resolution_minutes|category|confidence|created|created_user_uuid|critical_updated|description|device_ip_fields|enabled|indicator_fields|name|primary_attack_id|query_signature|rule_accounts|run_account_uuids|secondary_attack_id|severity|shared_account_uuids|source_excludes|specificity|updated|updated_user_uuid|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 30240 | Attack:Installation | high | 2023-05-11T17:02:09.720180Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2023-05-11T17:02:09.720180Z | Test | src.ip | true | dst.ip,<br/>http:host,<br/>http:user_agent,<br/>http:uri.uri | Test: Cobalt Strike JasperLoader Malleable Stager HTTP Request | T1105 | (<br/>    http:src.internal = true<br/>    OR http:source = "Zscaler"<br/>)<br/>AND uri.path IN ("/501", "/502")<br/>AND uri.query = "dwgvhgc=" | {'account_uuid': '21379211-3c42-45f3-b6a7-33f489d09641', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T17:02:09.855742Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None},<br/>{'account_uuid': '6bc3d2f1-af77-4236-a9db-17dacd06e4d9', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T17:02:09.975786Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None},<br/>{'account_uuid': '29266c1a-645b-458e-b4c7-9bb3405d79be', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T17:02:10.095205Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None},<br/>{'account_uuid': 'f6f6f836-8bcd-4f5d-bd61-68d303c4f634', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T17:02:10.151422Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None},<br/>{'account_uuid': '11a7364e-f020-4ba3-b7c1-ac17006f379b', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T17:02:10.040958Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None},<br/>{'account_uuid': '6679810e-5a03-4a82-8458-d1c76b3e1942', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T17:02:09.782635Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None},<br/>{'account_uuid': '55f39b72-2622-4137-9051-bc2ff364f059', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T17:02:09.915832Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None} | 9a555e95-e868-4146-a23b-2b88da6a3304 | T1027.005 | high |  | Zscaler | tool_implementation | 2023-05-11T17:02:09.720180Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 26874859-0148-4d7f-9a83-145d74830cd9 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 30240 | Attack:Installation | high | 2023-05-11T16:51:20.566178Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2023-05-11T16:51:20.566178Z | Test | src.ip | true | dst.ip,<br/>http:host,<br/>http:user_agent,<br/>http:uri.uri | Test: Cobalt Strike GlobeImposter Malleable Stager HTTP Request | T1105 | (<br/>    http:src.internal = true<br/>    OR http:source = "Zscaler"<br/>)<br/>AND uri.path IN ("/JHGCd476334", "/JHGcD476334") | {'account_uuid': '55f39b72-2622-4137-9051-bc2ff364f059', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T16:51:20.727818Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None},<br/>{'account_uuid': 'f6f6f836-8bcd-4f5d-bd61-68d303c4f634', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T16:51:20.969115Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None},<br/>{'account_uuid': '11a7364e-f020-4ba3-b7c1-ac17006f379b', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T16:51:20.846743Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None},<br/>{'account_uuid': '21379211-3c42-45f3-b6a7-33f489d09641', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T16:51:20.683717Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None},<br/>{'account_uuid': '6679810e-5a03-4a82-8458-d1c76b3e1942', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T16:51:20.622813Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None},<br/>{'account_uuid': '6bc3d2f1-af77-4236-a9db-17dacd06e4d9', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T16:51:20.789274Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None},<br/>{'account_uuid': '29266c1a-645b-458e-b4c7-9bb3405d79be', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': 'cd3ea8eb-e014-4f62-905d-78a021c768b2', 'muted_timestamp': '2023-05-11T16:51:20.907381Z', 'detection_count': None, 'detection_muted_count': None, 'detection_resolved_count': None, 'first_seen': None, 'last_seen': None} | 9a555e95-e868-4146-a23b-2b88da6a3304 | T1027.005 | high |  | Zscaler | tool_implementation | 2023-05-11T16:51:20.566178Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 90403613-164d-4aa5-8370-c4a3924a4533 |


### fortindr-cloud-resolve-detection

***
Resolve a specific detection.

#### Base Command

`fortindr-cloud-resolve-detection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_uuid | Detection UUID to resolve. | Required | 
| resolution | Resolution state. Options: true_positive_mitigated, true_posititve_no_action, false_positive, unknown. Possible values are: true_positive_mitigated, true_positive_no_action, false_positive, unknown. | Required | 
| resolution_comment | Optional comment for the resolution. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!fortindr-cloud-resolve-detection detection_uuid=ff801244-3c31-4f2e-a4be-9559a07ead65 resolution=false_positive resolution_comment="detection is false positive"```

#### Human Readable Output

>Detection resolved successfully

### fortindr-cloud-get-detection-rule-events

***
Get a list of the events that matched on a specific rule.

#### Base Command

`fortindr-cloud-get-detection-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_uuid | Detection UUID to get events for. | Required | 
| offset | The number of records to skip past. | Optional | 
| limit | The number of records to return, default: 0, max: 1000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Events.event_type | string | Event type | 
| FortiNDRCloud.Events.uuid | string | Unique ID for the event | 
| FortiNDRCloud.Events.customer_id | string | ID code of the customer account | 
| FortiNDRCloud.Events.sensor_id | string | ID code of the sensor | 
| FortiNDRCloud.Events.timestamp | date | Date the event occurred | 
| FortiNDRCloud.Events.flow_id | string | Unique ID of the flow record | 
| FortiNDRCloud.Events.src | string | Source's information | 
| FortiNDRCloud.Events.dst | string | Destination's information | 
| FortiNDRCloud.Events.host_domain | string | Domain name | 

#### Base Command

`fortindr-cloud-get-detection-rule-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_uuid | Rule UUID to get events for. | Required | 
| account_uuid | Account uuid to filter by. | Optional | 
| offset | The number of records to skip past. | Optional | 
| limit | The number of records to return, default: 100, max: 1000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiNDRCloud.Events.src_ip | string | Source IP address | 
| FortiNDRCloud.Events.dst_ip | string | Destination IP address | 
| FortiNDRCloud.Events.src_port | number | Source port number | 
| FortiNDRCloud.Events.dst_port | number | Destination port number | 
| FortiNDRCloud.Events.host_domain | string | Domain name | 
| FortiNDRCloud.Events.flow_id | string | Unique ID of the flow record | 
| FortiNDRCloud.Events.event_type | string | Event type | 
| FortiNDRCloud.Events.sensor_id | string | ID code of the sensor | 
| FortiNDRCloud.Events.timestamp | date | Date the event occurred | 
| FortiNDRCloud.Events.customer_id | string | ID code of the customer account | 
| FortiNDRCloud.Events.uuid | string | Unique ID for the event | 

#### Command example

```!fortindr-cloud-get-detection-rule-events rule_uuid=0215f6db-82f1-4f71-8754-79104eecaab6 limit=3```

#### Context Example

```json
{
    "FortiNDRCloud": {
        "Detections": [
            {
                "customer_id": "gig",
                "dst": {
                    "asn": null,
                    "geo": null,
                    "internal": true,
                    "ip": "1.1.1.3",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": 55585
                },
                "event_type": "suricata",
                "flow_id": null,
                "geo_distance": null,
                "http": {
                    "host": {
                        "asn": null,
                        "geo": null,
                        "internal": true,
                        "ip": "1.2.1.3",
                        "ip_bytes": null,
                        "pkts": null,
                        "port": null
                    },
                    "hostname": "1.2.1.3",
                    "method": "GET",
                    "protocol": "HTTP/1.1",
                    "redirect": null,
                    "referrer": null,
                    "response_len": 11644,
                    "response_mime": "application/octet-stream",
                    "status": 200,
                    "uri": "/9Azi",
                    "user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
                    "xff": null
                },
                "intel": null,
                "payload": null,
                "proto": "tcp",
                "sensor_id": "gig7",
                "sig_category": "Misc activity",
                "sig_id": 2900330,
                "sig_name": "ATR INSTALLATION Cobalt Strike Encrypted Beacon x64",
                "sig_rev": 4,
                "sig_severity": 3,
                "source": "Suricata",
                "src": {
                    "asn": null,
                    "geo": null,
                    "internal": true,
                    "ip": "1.2.1.3",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": 80
                },
                "timestamp": "2023-05-11T04:28:02.348Z",
                "uuid": "c0fb758b-efb4-11ed-9f54-0a0561bac71d"
            },
            {
                "customer_id": "gig",
                "dst": {
                    "asn": null,
                    "geo": null,
                    "internal": true,
                    "ip": "1.1.1.2",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": 45955
                },
                "event_type": "suricata",
                "flow_id": null,
                "geo_distance": null,
                "http": {
                    "host": {
                        "domain": "acpananma.com",
                        "domain_entropy": 2.6235198974609375
                    },
                    "hostname": "acpananma.com",
                    "method": "GET",
                    "protocol": "HTTP/1.1",
                    "redirect": null,
                    "referrer": null,
                    "response_len": 14540,
                    "response_mime": "text/html",
                    "status": 200,
                    "uri": "/clients3.google.com/generate_204",
                    "user_agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38",
                    "xff": null
                },
                "intel": [],
                "payload": null,
                "proto": "tcp",
                "sensor_id": "gig7",
                "sig_category": "Misc activity",
                "sig_id": 2900330,
                "sig_name": "ATR INSTALLATION Cobalt Strike Encrypted Beacon x64",
                "sig_rev": 4,
                "sig_severity": 3,
                "source": "Suricata",
                "src": {
                    "asn": null,
                    "geo": null,
                    "internal": true,
                    "ip": "1.2.1.2",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": 80
                },
                "timestamp": "2023-05-11T04:27:59.190Z",
                "uuid": "c0fb7581-efb4-11ed-9f54-0a0561bac71d"
            },
            {
                "customer_id": "gig",
                "dst": {
                    "asn": null,
                    "geo": null,
                    "internal": true,
                    "ip": "1.1.1.1",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": 45009
                },
                "event_type": "suricata",
                "flow_id": null,
                "geo_distance": null,
                "http": {
                    "host": {
                        "asn": null,
                        "geo": null,
                        "internal": true,
                        "ip": "1.2.1.1",
                        "ip_bytes": null,
                        "pkts": null,
                        "port": null
                    },
                    "hostname": "1.2.1.1",
                    "method": "GET",
                    "protocol": "HTTP/1.1",
                    "redirect": null,
                    "referrer": null,
                    "response_len": 7300,
                    "response_mime": "application/octet-stream",
                    "status": 200,
                    "uri": "/9Azi",
                    "user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
                    "xff": null
                },
                "intel": null,
                "payload": null,
                "proto": "tcp",
                "sensor_id": "gig7",
                "sig_category": "Misc activity",
                "sig_id": 2900330,
                "sig_name": "ATR INSTALLATION Cobalt Strike Encrypted Beacon x64",
                "sig_rev": 4,
                "sig_severity": 3,
                "source": "Suricata",
                "src": {
                    "asn": null,
                    "geo": null,
                    "internal": true,
                    "ip": "1.2.1.1",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": 80
                },
                "timestamp": "2023-05-11T04:10:13.389Z",
                "uuid": "f5d5c2cb-efb1-11ed-9b38-020b36c82a21"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results

>|customer_id|dst|event_type|flow_id|geo_distance|http|intel|payload|proto|sensor_id|sig_category|sig_id|sig_name|sig_rev|sig_severity|source|src|timestamp|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| gig | ip: 1.1.1.3<br/>port: 55585<br/>ip_bytes: null<br/>pkts: null<br/>geo: null<br/>asn: null<br/>internal: true | suricata |  |  | status: 200<br/>protocol: HTTP/1.1<br/>uri: /9Azi<br/>host: {"ip": "1.2.1.3", "port": null, "ip_bytes": null, "pkts": null, "geo": null, "asn": null, "internal": true}<br/>hostname: 1.2.1.3<br/>response_len: 11644<br/>method: GET<br/>response_mime: application/octet-stream<br/>referrer: null<br/>user_agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko<br/>redirect: null<br/>xff: null |  |  | tcp | gig7 | Misc activity | 2900330 | ATR INSTALLATION Cobalt Strike Encrypted Beacon x64 | 4.0 | 3 | Suricata | ip: 1.2.1.3<br/>port: 80<br/>ip_bytes: null<br/>pkts: null<br/>geo: null<br/>asn: null<br/>internal: true | 2023-05-11T04:28:02.348Z | c0fb758b-efb4-11ed-9f54-0a0561bac71d |
>| gig | ip: 1.1.1.2<br/>port: 45955<br/>ip_bytes: null<br/>pkts: null<br/>geo: null<br/>asn: null<br/>internal: true | suricata |  |  | status: 200<br/>protocol: HTTP/1.1<br/>uri: /clients3.google.com/generate_204<br/>host: {"domain": "acpananma.com", "domain_entropy": 2.6235198974609375}<br/>hostname: acpananma.com<br/>response_len: 14540<br/>method: GET<br/>response_mime: text/html<br/>referrer: null<br/>user_agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38<br/>redirect: null<br/>xff: null |  |  | tcp | gig7 | Misc activity | 2900330 | ATR INSTALLATION Cobalt Strike Encrypted Beacon x64 | 4.0 | 3 | Suricata | ip: 1.2.1.2<br/>port: 80<br/>ip_bytes: null<br/>pkts: null<br/>geo: null<br/>asn: null<br/>internal: true | 2023-05-11T04:27:59.190Z | c0fb7581-efb4-11ed-9f54-0a0561bac71d |
>| gig | ip: 1.1.1.1<br/>port: 45009<br/>ip_bytes: null<br/>pkts: null<br/>geo: null<br/>asn: null<br/>internal: true | suricata |  |  | status: 200<br/>protocol: HTTP/1.1<br/>uri: /9Azi<br/>host: {"ip": "1.2.1.1", "port": null, "ip_bytes": null, "pkts": null, "geo": null, "asn": null, "internal": true}<br/>hostname: 1.2.1.1<br/>response_len: 7300<br/>method: GET<br/>response_mime: application/octet-stream<br/>referrer: null<br/>user_agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko<br/>redirect: null<br/>xff: null |  |  | tcp | gig7 | Misc activity | 2900330 | ATR INSTALLATION Cobalt Strike Encrypted Beacon x64 | 4.0 | 3 | Suricata | ip: 1.2.1.1<br/>port: 80<br/>ip_bytes: null<br/>pkts: null<br/>geo: null<br/>asn: null<br/>internal: true | 2023-05-11T04:10:13.389Z | f5d5c2cb-efb1-11ed-9b38-020b36c82a21 |


### fortindr-cloud-create-detection-rule

***
Create a new detection rule.

#### Base Command

`fortindr-cloud-create-detection-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_uuid | Account where the rule will be created. | Required | 
| name | The name of the rule. | Required | 
| category | The category of the rule. Possible values are: Attack:Command and Control, Attack:Exploitation, Attack:Exfiltration, Attack:Installation, Attack:Lateral Movement, Attack:Infection Vector, Attack:Miscellaneous, Miscellaneous, Posture:Anomalous Activity, Posture:Insecure Configuration, Posture:Potentially Unauthorized Software or Device, Posture:Miscellaneous, PUA:Adware, PUA:Spyware, PUA:Unauthorized Resource Use, PUA:Miscellaneous. | Required | 
| query_signature | The IQL query for the rule. | Required | 
| description | A description for the rule. | Required | 
| severity | The severity of the rule. Possible values are: low, moderate, high. | Required | 
| confidence | The confidence of the rule. Possible values are: low, moderate, high. | Required | 
| run_account_uuids | Account UUIDs on which this rule will run. This will usually be just your own account UUID. (separate multiple accounts by comma). | Required | 
| auto_resolution_minutes | The number of minutes after which detections will be auto-resolved. If 0 then detections have to be manually resolved. | Optional | 
| device_ip_fields | List of event fields to check for impacted devices. Possible values are: DEFAULT, src.ip, dst.ip, dhcp:assignment.ip, dns:answers.ip, http:host.ip, http:uri.host.ip, http:referrer.host.ip, http:headers.location.host.ip, http:headers.origin.host.ip, http:headers.proxied_client_ips.ip, http:headers.refresh.uri.host.ip, smtp:helo.ip, smtp:x_originating_ip.ip, smtp:path.ip, software:host.ip, ssl:server_name_indication.ip, suricata:http.host.ip, x509:san_dns.ip, x509:san_ip.ip. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!fortindr-cloud-create-detection-rule account_uuid=bedf5bf3-94b0-49fa-9085-12ca29876dc3 name="New Test Rule" category="Posture:Anomalous Activity" query_signature="ip=1.2.3.4" description="Test rule" severity=high confidence=moderate run_account_uuids=bedf5bf3-94b0-49fa-9085-12ca29876dc3 device_ip_fields=DEFAULT```

#### Human Readable Output

>Rule created successfully
