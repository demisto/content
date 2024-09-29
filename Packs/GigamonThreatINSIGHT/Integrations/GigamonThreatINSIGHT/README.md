# Gigamon ThreatINSIGHT Integration for Cortex XSOAR

## Insight Overview

The Gigamon ThreatINSIGHT Cortex XSOAR integration enables security teams to utilize the features and functionality of the ThreatINSIGHT solution with their existing Cortex deployment. The integration leverages ThreatINSIGHT RESTful APIs to interact with the back end to introduce specific data sets into Cortex XSOAR. This document contains all the necessary information to configure, install, and use the integration.

## Integration Overview

The Gigamon ThreatINSIGHT Cortex XSOAR integration enables security teams to utilize the features and functionality of the Insight solution with their existing Cortex XSOAR deployment. The integration leverages Insight’s fully RESTful APIs to interact with the Insight backend to introduce specific data sets into Cortex XSOAR. This document contains all the necessary information to configure, install, and use the integration.
For more information about the Cortex XSOAR integration visit the Insight help documentation here: https://insight.gigamon.com/help/api/apidocs-demisto

## Configure Gigamon ThreatINSIGHT in Cortex


| **Parameter** | **Required** |
| --- | --- |
| API Token | True |
| First Fetch Time (Amount of day before current date) | False |
| Fetch incidents | False |
| Incident type | False |
| Incident Filter: Account UUID (Optional) | False |
| Maximum incidents in each fetch each run | False |
| Incidents Fetch Interval | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### insight-get-sensors
***
Get a list of all sensors.


#### Base Command

`insight-get-sensors`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_uuid | UUID of account to filter by. | Optional | 
| account_code | Account code to fiilter by. | Optional | 
| sensor_id | ID of the sensor to filter by. | Optional | 
| include | Include additional metadata such as status, interfaces, admin.sensor, admin.zeek, admin.suricata, etc. | Optional | 
| enabled | Filter by true or false. If not provided, all the sensors are returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Sensors.created | date | Date when the sensor was created | 
| Insight.Sensors.updated | date | Date when the sensor was last updated | 
| Insight.Sensors.sensor_id | string | ID code of the sensor | 
| Insight.Sensors.account_code | string | ID code of the customer account | 
| Insight.Sensors.location | string | Latitude and longitude where the sensor is located | 
| Insight.Sensors.subdivison | string | State/Province where the sensor is located | 
| Insight.Sensors.city | string | City where the sensor is located | 
| Insight.Sensors.country | string | Country where the sensor is located | 
| Insight.Sensors.tags | string | Labels added for this sensor | 
| Insight.Sensors.pcap_enabled | boolean | If PCAP is enabled on the sensor \(true/false\) | 

#### Command example
```!insight-get-sensors```
#### Context Example
```json
{
    "Insight": {
        "Sensors": [
            {
                "account_code": "gdm",
                "admin": null,
                "city": null,
                "country": null,
                "created": "2021-12-17T20:40:54.348Z",
                "disabled": "2022-03-28T18:18:46.826Z",
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gdm1",
                "serial_number": null,
                "status": null,
                "subdivision": null,
                "tags": [],
                "updated": "2021-12-17T20:40:54.348Z"
            },
            {
                "account_code": "gdm",
                "admin": null,
                "city": null,
                "country": null,
                "created": "2022-03-28T18:17:37.696Z",
                "disabled": null,
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gdm2",
                "serial_number": null,
                "status": null,
                "subdivision": null,
                "tags": [],
                "updated": "2022-03-28T18:17:37.696Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|account_code|admin|city|country|created|disabled|interfaces|location|pcap_enabled|sensor_id|serial_number|status|subdivision|tags|updated|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| gdm |  |  |  | 2021-12-17T20:40:54.348Z | 2022-03-28T18:18:46.826Z |  |  | false | gdm1 |  |  |  |  | 2021-12-17T20:40:54.348Z |
>| gdm |  |  |  | 2022-03-28T18:17:37.696Z |  |  |  | false | gdm2 |  |  |  |  | 2022-03-28T18:17:37.696Z |


#### Command example
```!insight-get-sensors account_code=gdm```
#### Context Example
```json
{
    "Insight": {
        "Sensors": [
            {
                "account_code": "gdm",
                "admin": null,
                "city": null,
                "country": null,
                "created": "2021-12-17T20:40:54.348Z",
                "disabled": "2022-03-28T18:18:46.826Z",
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gdm1",
                "serial_number": null,
                "status": null,
                "subdivision": null,
                "tags": [],
                "updated": "2021-12-17T20:40:54.348Z"
            },
            {
                "account_code": "gdm",
                "admin": null,
                "city": null,
                "country": null,
                "created": "2022-03-28T18:17:37.696Z",
                "disabled": null,
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gdm2",
                "serial_number": null,
                "status": null,
                "subdivision": null,
                "tags": [],
                "updated": "2022-03-28T18:17:37.696Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|account_code|admin|city|country|created|disabled|interfaces|location|pcap_enabled|sensor_id|serial_number|status|subdivision|tags|updated|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| gdm |  |  |  | 2021-12-17T20:40:54.348Z | 2022-03-28T18:18:46.826Z |  |  | false | gdm1 |  |  |  |  | 2021-12-17T20:40:54.348Z |
>| gdm |  |  |  | 2022-03-28T18:17:37.696Z |  |  |  | false | gdm2 |  |  |  |  | 2022-03-28T18:17:37.696Z |


### insight-get-devices
***
Get a list of all devices.


#### Base Command

`insight-get-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Filter devices based on when they were seen. | Optional | 
| end_date | Filter devices based on when they were seen. | Optional | 
| cidr | Filter devices that are under a specific CIDR. | Optional | 
| sensor_id | Filter devices that were observed by a specific sensor. | Optional | 
| traffic_direction | Filter devices that have been noted to only have a certain directionality of traffic ("external" vs "internal"). | Optional | 
| sort_by | Sort output by: "ip", "internal", "external". | Optional | 
| sort_direction | Sort direction ("asc" vs "desc"). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Devices.date | date | Date when the device was first seen | 
| Insight.Devices.external | boolean | If external traffic has been observed for this device | 
| Insight.Devices.internal | boolean | If internal traffic has been observed for this device | 
| Insight.Devices.ip_address | string | IP address of the device | 
| Insight.Devices.sensor_id | string | ID code of the sensor | 

#### Command example
```!insight-get-devices cidr=21.5.0.0/16```
#### Context Example
```json
{
    "Insight": {
        "Devices": [
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "21.5.31.1"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "21.5.31.5"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "21.5.31.101"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|date|external|internal|ip_address|
>|---|---|---|---|
>|  | true | true | 21.5.31.1 |
>|  | true | true | 21.5.31.5 |
>|  | true | true | 21.5.31.101 |


### insight-get-tasks
***
Get a list of all the PCAP tasks.


#### Base Command

`insight-get-tasks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_uuid | Filter to a specific task. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Tasks.task_uuid | string | Unique ID of the task | 
| Insight.Tasks.actual_start_time | date | Date when the task actually ended | 
| Insight.Tasks.requested_start_time | date | Requested date for the task start | 
| Insight.Tasks.updated_email | string | Email address of the user that updated the task | 
| Insight.Tasks.created_uuid | string | Unique ID of the user that created the task | 
| Insight.Tasks.created | date | Date when the task was created | 
| Insight.Tasks.name | string | Name of the task | 
| Insight.Tasks.status | string | Current status of the task | 
| Insight.Tasks.created_email | string | Email address of the user that created the task | 
| Insight.Tasks.updated_uuid | string | Unique ID of the user that updated the task | 
| Insight.Tasks.bpf | string | Berkeley Packet Filter for the task | 
| Insight.Tasks.actual_end_time | date | Date when the task actually ended | 
| Insight.Tasks.account_code | string | ID code of the customer account | 
| Insight.Tasks.requested_end_time | date | Requested date for the task end | 
| Insight.Tasks.updated | date | Date when the task was updated | 
| Insight.Tasks.description | string | Description of the task | 
| Insight.Tasks.has_files | boolean | If this task has files \(true/false\) | 
| Insight.Tasks.sensor_ids | string | Sensors this task is running on | 
| Insight.Tasks.files | string | Files captured for this task | 

#### Command example
```!insight-get-tasks task_uuid=373c9861-16cd-44cb-b768-e53ce3a9fcd4```
#### Context Example
```json
{
    "Insight": {
        "Tasks": {
            "account_code": "gdm",
            "actual_end_time": "2022-08-26T07:59:00.000Z",
            "actual_start_time": "2022-08-25T02:32:00.000Z",
            "bpf": "dst www.discovery.com",
            "created": "2022-08-24T17:46:28.457Z",
            "created_email": "myemail@mycompany.com",
            "created_uuid": "88f034f1-b922-4a41-8e54-9bac90a42517",
            "description": "Test Description",
            "files": [],
            "has_files": false,
            "name": "test Task1",
            "requested_end_time": "2022-08-26T07:59:00.000Z",
            "requested_start_time": "2022-08-25T02:32:00.000Z",
            "sensor_ids": [],
            "status": "active",
            "task_uuid": "373c9861-16cd-44cb-b768-e53ce3a9fcd4",
            "updated": "2022-08-24T17:46:28.457Z",
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
>| gdm | 2022-08-26T07:59:00.000Z | 2022-08-25T02:32:00.000Z | dst www.discovery.com | 2022-08-24T17:46:28.457Z | myemail@mycompany.com | 88f034f1-b922-4a41-8e54-9bac90a42517 | Test Description |  | false | test Task1 | 2022-08-26T07:59:00.000Z | 2022-08-25T02:32:00.000Z |  | active | 373c9861-16cd-44cb-b768-e53ce3a9fcd4 | 2022-08-24T17:46:28.457Z |  |  |


### insight-create-task
***
Create a new PCAP task.


#### Base Command

`insight-create-task`
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
### insight-get-telemetry-events
***
Get event telemetry data grouped by time.


#### Base Command

`insight-get-telemetry-events`
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
| Insight.Telemetry.Events.timestamp | date | Timestamp of the grouped data | 
| Insight.Telemetry.Events.event_count | number | Number of events | 
| Insight.Telemetry.Events.sensor_id | string | Sensor name \(if grouped by sensor_id\) | 
| Insight.Telemetry.Events.event_type | string | Type of event \(if grouped by event_type\) | 

#### Command example
```!insight-get-telemetry-events start_date=2022-08-22T23:00:00.000Z end_date=2022-08-23T01:00:00.000Z```
#### Context Example
```json
{
    "Insight": {
        "Telemetry": {
            "Events": [
                {
                    "event_count": 70185,
                    "event_type": null,
                    "sensor_id": null,
                    "timestamp": "2022-08-22T22:00:00.000Z"
                },
                {
                    "event_count": 70363,
                    "event_type": null,
                    "sensor_id": null,
                    "timestamp": "2022-08-22T23:00:00.000Z"
                },
                {
                    "event_count": 70187,
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
>|event_count|event_type|sensor_id|timestamp|
>|---|---|---|---|
>| 70185 |  |  | 2022-08-22T22:00:00.000Z |
>| 70363 |  |  | 2022-08-22T23:00:00.000Z |
>| 70187 |  |  | 2022-08-23T00:00:00.000Z |


### insight-get-telemetry-packetstats
***
Get packetstats telemetry data grouped by time.


#### Base Command

`insight-get-telemetry-packetstats`
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
| Insight.Telemetry.Packetstats.account_code | string | Account code the data was filtered by | 
| Insight.Telemetry.Packetstats.timestamp | date | Timestamp of the grouped data | 
| Insight.Telemetry.Packetstats.interface_name | string | Interface the packet data was recorded from | 
| Insight.Telemetry.Packetstats.rx_bits_per_second | number | Receive throughput \(bits per second\) | 
| Insight.Telemetry.Packetstats.rx_bytes | number | Receive data size \(bytes\) | 
| Insight.Telemetry.Packetstats.rx_errors | number | Number of receive errors | 
| Insight.Telemetry.Packetstats.rx_packets | number | Number of receive packets | 
| Insight.Telemetry.Packetstats.sensor_id | string | Sensor ID packet data was recorded from | 
| Insight.Telemetry.Packetstats.tx_bytes | number | Transmit data size \(bytes\) | 
| Insight.Telemetry.Packetstats.tx_errors | number | Number of transmit errors | 
| Insight.Telemetry.Packetstats.tx_packets | number | Number of transmit packets | 

#### Command example
```!insight-get-telemetry-packetstats start_date=2022-08-22T23:00:00.000Z end_date=2022-08-23T01:00:00.000Z```
#### Context Example
```json
{
    "Insight": {
        "Telemetry": {
            "Packetstats": [
                {
                    "account_code": null,
                    "interface_name": null,
                    "rx_bits_per_second": 0,
                    "rx_bytes": 942662863653,
                    "rx_errors": 0,
                    "rx_packets": 1821630132,
                    "sensor_id": null,
                    "timestamp": "2022-08-22T22:00:00.000Z",
                    "tx_bytes": 59142067827,
                    "tx_errors": 0,
                    "tx_packets": 56381923
                },
                {
                    "account_code": null,
                    "interface_name": null,
                    "rx_bits_per_second": 1611395,
                    "rx_bytes": 943387991476,
                    "rx_errors": 0,
                    "rx_packets": 1823075830,
                    "sensor_id": null,
                    "timestamp": "2022-08-22T23:00:00.000Z",
                    "tx_bytes": 59178887675,
                    "tx_errors": 0,
                    "tx_packets": 56416169
                },
                {
                    "account_code": null,
                    "interface_name": null,
                    "rx_bits_per_second": 1620858,
                    "rx_bytes": 944117377617,
                    "rx_errors": 0,
                    "rx_packets": 1824526055,
                    "sensor_id": null,
                    "timestamp": "2022-08-23T00:00:00.000Z",
                    "tx_bytes": 59216556939,
                    "tx_errors": 0,
                    "tx_packets": 56452793
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
>|  |  | 0 | 942662863653 | 0 | 1821630132 |  | 2022-08-22T22:00:00.000Z | 59142067827 | 0 | 56381923 |
>|  |  | 1611395 | 943387991476 | 0 | 1823075830 |  | 2022-08-22T23:00:00.000Z | 59178887675 | 0 | 56416169 |
>|  |  | 1620858 | 944117377617 | 0 | 1824526055 |  | 2022-08-23T00:00:00.000Z | 59216556939 | 0 | 56452793 |


### insight-get-telemetry-network
***
Get network telemetry data grouped by time


#### Base Command

`insight-get-telemetry-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_code | Account code to filter by. | Optional | 
| interval | The interval to filter by (day, month_to_day). Possible values are: hour, day. | Optional | 
| latest_each_month | latest_each_month	No	No	Filters out all but the latest day and month_to_date for each month. | Optional | 
| sort_order | Sorts by account code first, then timestamp. asc or desc. The default is desc. | Optional | 
| limit | The maximum number of records to return, default: 100, max: 1000. Default is 1000. | Optional | 
| offset | The number of records to skip past. Default: 0. | Optional | 
| start_date | Start date to filter by. | Optional | 
| end_date | End date to filter by. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Telemetry.NetworkUsage.account_code | string | The account code for the network usage. | 
| Insight.Telemetry.NetworkUsage.percentile_bps | long | The top percentile BPS value across sensors. | 
| Insight.Telemetry.NetworkUsage.percentile | int | Percentile of BPS records to calculate for percentile_bps. | 
| Insight.Telemetry.NetworkUsage.interval | unknown | Time span the calculation was performed over \(day, month_to_day\). | 
| Insight.Telemetry.Packetstats.timestamp | date | The date the calculation was performed until. | 

#### Command example
```!insight-get-telemetry-network start_date=2022-08-21T00:00:00.000Z end_date=2022-08-23T01:00:00.000Z interval=day```
#### Context Example
```json
{
    "Insight": {
        "Telemetry": {
            "NetworkUsage": [
                {
                    "account_code": "gdm",
                    "interval": "day",
                    "percentile": 95,
                    "percentile_bps": 5768519,
                    "timestamp": "2022-08-23T00:00:00.000000Z"
                },
                {
                    "account_code": "gdm",
                    "interval": "day",
                    "percentile": 95,
                    "percentile_bps": 5402040,
                    "timestamp": "2022-08-22T00:00:00.000000Z"
                },
                {
                    "account_code": "gdm",
                    "interval": "day",
                    "percentile": 95,
                    "percentile_bps": 685898,
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
>| gdm | day | 95 | 5768519 | 2022-08-23T00:00:00.000000Z |
>| gdm | day | 95 | 5402040 | 2022-08-22T00:00:00.000000Z |
>| gdm | day | 95 | 685898 | 2022-08-21T00:00:00.000000Z |


### insight-get-entity-summary
***
Get summary information about an IP or domain.


#### Base Command

`insight-get-entity-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | IP or Domain to get entity data for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Entity.Summary.entity | string | Entity identifier | 
| Insight.Entity.Summary.first_seen | date | First seen date for this entity | 
| Insight.Entity.Summary.last_seen | date | Last seen date for this entity | 
| Insight.Entity.Summary.prevalence_count_internal | number | Prevalence for this entity within the environment | 

#### Command example
```!insight-get-entity-summary entity=8.8.8.8```
#### Context Example
```json
{
    "Insight": {
        "Entity": {
            "Summary": {
                "entity": "8.8.8.8",
                "first_seen": "2021-12-17T21:30:02.000Z",
                "last_seen": "2022-08-24T19:19:52.711Z",
                "prevalence_count_internal": 1,
                "tags": []
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|entity|first_seen|last_seen|prevalence_count_internal|tags|
>|---|---|---|---|---|
>| 8.8.8.8 | 2021-12-17T21:30:02.000Z | 2022-08-24T19:19:52.711Z | 1 |  |


### insight-get-entity-pdns
***
Get passive DNS information about an IP or domain.


#### Base Command

`insight-get-entity-pdns`
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
| Insight.Entity.PDNS.account_uuid | string | Unique ID for the customer account | 
| Insight.Entity.PDNS.first_seen | date | First seen date for matching dns information | 
| Insight.Entity.PDNS.last_seen | date | Last seen date for matching dns information | 
| Insight.Entity.PDNS.record_type | string | DNS record type | 
| Insight.Entity.PDNS.resolved | string | Domain name resolved from the DNS record | 
| Insight.Entity.PDNS.sensor_id | string | ID code of the sensor | 
| Insight.Entity.PDNS.source | string | Source of the DNS record | 

#### Command example
```!insight-get-entity-pdns entity=google.com limit=3```
#### Context Example
```json
{
    "Insight": {
        "Entity": {
            "PDNS": [
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2022-04-06T00:00:00.000Z",
                    "last_seen": "2022-08-24T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "132.215.12.206",
                    "sensor_id": "gdm2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2022-04-03T00:00:00.000Z",
                    "last_seen": "2022-08-21T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "132.215.5.238",
                    "sensor_id": "gdm2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2022-03-30T00:00:00.000Z",
                    "last_seen": "2022-08-24T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "132.215.7.238",
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
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-06T00:00:00.000Z | 2022-08-24T00:00:00.000Z | a | 132.215.12.206 | gdm2 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-03T00:00:00.000Z | 2022-08-21T00:00:00.000Z | a | 132.215.5.238 | gdm2 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-03-30T00:00:00.000Z | 2022-08-24T00:00:00.000Z | a | 132.215.7.238 | gdm2 | icebrg_dns |


### insight-get-entity-dhcp
***
Get DHCP information about an IP address.


#### Base Command

`insight-get-entity-dhcp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | IP or Domain to get passive DNS data for. | Required | 
| start_date | The earliest date before which to exclude results. Day granularity, inclusive. | Optional | 
| end_date | The latest date after which to exclude results. Day granularity, inclusive. | Optional | 
| account_uuid | Limit results to the specified account UUID(s). Defaults to all accounts for which the user has permission. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Entity.DHCP.customer_id | string | ID code of the customer account | 
| Insight.Entity.DHCP.hostnames | string | Hostname of the entity | 
| Insight.Entity.DHCP.ip | string | IP Address of the entity | 
| Insight.Entity.DHCP.lease_end | date | DHCP lease end date | 
| Insight.Entity.DHCP.lease_start | date | DHCP lease start date | 
| Insight.Entity.DHCP.mac | string | MAC address of the entity | 
| Insight.Entity.DHCP.sensor_id | string | Sensor ID that recorded the entity data | 
| Insight.Entity.DHCP.start_lease_as_long | number | Start Date as a long value | 

#### Command example
```!insight-get-entity-dhcp entity=21.1.70.100 start_date=2021-01-01T00:00:00.000Z```
#### Context Example
```json
{
    "Insight": {
        "Entity": {
            "DHCP": {
                "customer_id": "gdm",
                "hostnames": [
                    "FinanceWks008"
                ],
                "ip": "21.1.70.100",
                "lease_end": null,
                "lease_start": "2021-12-18T09:02:24.104Z",
                "mac": "00:15:5d:00:04:0e",
                "sensor_id": null,
                "start_lease_as_long": 1639818144104
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|customer_id|hostnames|ip|lease_end|lease_start|mac|sensor_id|start_lease_as_long|
>|---|---|---|---|---|---|---|---|
>| gdm | FinanceWks008 | 21.1.70.100 |  | 2021-12-18T09:02:24.104Z | 00:15:5d:00:04:0e |  | 1639818144104 |


### insight-get-entity-file
***
Get information about a file.


#### Base Command

`insight-get-entity-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | File hash. Can be an MD5, SHA1, or SHA256 hash of the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Entity.File.entity | string | The entity identifier | 
| Insight.Entity.File.sha1 | string | The entity SHA1 hash | 
| Insight.Entity.File.sha256 | string | The entity SHA256 hash | 
| Insight.Entity.File.md5 | string | The entity MD5 hash | 
| Insight.Entity.File.customer_id | string | ID code of the customer account | 
| Insight.Entity.File.names | string | File names for the entity | 
| Insight.Entity.File.prevalence_count_internal | number | Prevalence for this file within the environment | 
| Insight.Entity.File.last_seen | date | Last seen date for this file | 
| Insight.Entity.File.mime_type | string | File MIME type | 
| Insight.Entity.File.first_seen | date | First seen date for this file | 
| Insight.Entity.File.bytes | number | File size | 
| Insight.Entity.File.pe | string | File Portable Executable attributes | 

#### Command example
```!insight-get-entity-file hash=2b7a609371b2a844181c2f79f1b45cf7```
#### Human Readable Output

>We could not find any result for Get Entity File.

### insight-get-detections
***
Get a list of detections.


#### Base Command

`insight-get-detections`
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
| include | Include additional information in the response (rules). Possible values are: rules. | Optional | 
| sort_by | Sort output by: "ip", "internal", "external". | Optional | 
| sort_order | Sort direction ("asc" vs "desc"). | Optional | 
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
| Insight.Detections.muted_rule | boolean | Is this rule muted \(true/false\) | 
| Insight.Detections.created | date | Date when the detection was created | 
| Insight.Detections.account_uuid | unknown | Unique ID of the account for this detection | 
| Insight.Detections.resolution_timestamp | date | Date when the detection was resolved | 
| Insight.Detections.first_seen | date | Date when the detection was first seen | 
| Insight.Detections.muted | boolean | If the detection is muted or not \(true/false\) | 
| Insight.Detections.resolution | string | Resolution type | 
| Insight.Detections.muted_user_uuid | string | Unique ID of the user that muted the detection | 
| Insight.Detections.last_seen | date | Date when the detection was last seen | 
| Insight.Detections.status | string | Current status of the detection | 
| Insight.Detections.resolution_user_uuid | string | Unique identifier of the user that resolved the detection | 
| Insight.Detections.resolution_comment | string | Comment entered when detection was resolved | 
| Insight.Detections.muted_comment | string | Comment entered when detection was muted | 
| Insight.Detections.sensor_id | string | ID code of the sensor | 
| Insight.Detections.rule_uuid | string | Unique ID of the rule for this detection | 
| Insight.Detections.updated | date | Date when the detection was last updated | 
| Insight.Detections.uuid | string | Unique ID of the detection | 
| Insight.Detections.muted_device_uuid | string | Unique ID of the muted device | 
| Insight.Detections.device_ip | string | IP address of the detection | 

#### Command example
```!insight-get-detections status=active include=rules created_or_shared_start_date=2022-08-23T22:00:00.000Z created_or_shared_end_date=2022-08-24T22:00:00.000Z```
#### Context Example
```json
{
    "Insight": {
        "Detections": [
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-24T21:20:19.801089Z",
                "device_ip": "156.112.0.100",
                "event_count": 1,
                "first_seen": "2022-08-24T08:04:36.535000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-24T08:04:36.535000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Discovery",
                "rule_confidence": "moderate",
                "rule_description": "This rule is designed to use the TCP Device Enumeration Observation event generated from a DMZ host that is not a scanner.  This would indicate a potentially compromised DMZ host scanning for other assets within the environment.  \n",
                "rule_name": "TCP Device Enumeration from DMZ host",
                "rule_severity": "moderate",
                "rule_uuid": "2d719a2b-4efb-4ba6-8555-0cd0f9636729",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-24T21:20:19.801089Z",
                "username": null,
                "uuid": "bb65c150-46be-4ba8-870d-b5feee01f06e"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-24T09:03:14.430538Z",
                "device_ip": "156.112.0.100",
                "event_count": 9,
                "first_seen": "2022-08-24T08:03:31.755000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-24T08:06:14.965000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This detection is intended to detect the CKnife Java client interacting with a CKnife Webshell backdoor. CKnife Webshell is commonly used by attackers to establish backdoors on external-facing web servers with unpatched vulnerabilities. CKnife is typically inserted as a PHP or ASPX page on the impacted asset, and accessed via a Java client.\n\nGigamon ATR considers this detection high severity, as it is indicative of successful malicious code execution on an external-facing server. This detection is considered moderate confidence, as it may coincidentally match similar traffic from uncommon devices or scanners.\n\n### Next Steps\n1. Determine if this detection is a true positive by:\n   1. Validating that the webpage in the detection exists, is unauthorized, and contains webshell functionality.\n   2. Validating that the external entity interacting with the device is unknown or unauthorized.\n   3. Inspecting traffic or logs to see if interaction with this webpage is uncommon and recent.\n3. Quarantine the impacted device.\n4. Begin incident response procedures on the impacted device.\n5. Block traffic from attacker infrastructure.\n6. Search traffic or logs from the infected web server to identify potential lateral movement by the attackers.",
                "rule_name": "CKnife Webshell Activity",
                "rule_severity": "high",
                "rule_uuid": "e9008859-c038-4bd5-a805-21efffd58355",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-24T09:03:14.430538Z",
                "username": null,
                "uuid": "6d0d7c2d-33a1-458d-a5e5-461fe7b03409"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|account_uuid|created|device_ip|event_count|first_seen|hostname|indicators|last_seen|muted|muted_comment|muted_device_uuid|muted_rule|muted_timestamp|muted_user_uuid|resolution|resolution_comment|resolution_timestamp|resolution_user_uuid|rule_category|rule_confidence|rule_description|rule_name|rule_severity|rule_uuid|sensor_id|status|updated|username|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-24T21:20:19.801089Z | 156.112.0.100 | 1 | 2022-08-24T08:04:36.535000Z |  |  | 2022-08-24T08:04:36.535000Z | false |  |  | false |  |  |  |  |  |  | Attack:Discovery | moderate | This rule is designed to use the TCP Device Enumeration Observation event generated from a DMZ host that is not a scanner.  This would indicate a potentially compromised DMZ host scanning for other assets within the environment.  <br/> | TCP Device Enumeration from DMZ host | moderate | 2d719a2b-4efb-4ba6-8555-0cd0f9636729 | gdm2 | active | 2022-08-24T21:20:19.801089Z |  | bb65c150-46be-4ba8-870d-b5feee01f06e |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-24T09:03:14.430538Z | 156.112.0.100 | 9 | 2022-08-24T08:03:31.755000Z |  |  | 2022-08-24T08:06:14.965000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This detection is intended to detect the CKnife Java client interacting with a CKnife Webshell backdoor. CKnife Webshell is commonly used by attackers to establish backdoors on external-facing web servers with unpatched vulnerabilities. CKnife is typically inserted as a PHP or ASPX page on the impacted asset, and accessed via a Java client.<br/><br/>Gigamon ATR considers this detection high severity, as it is indicative of successful malicious code execution on an external-facing server. This detection is considered moderate confidence, as it may coincidentally match similar traffic from uncommon devices or scanners.<br/><br/>### Next Steps<br/>1. Determine if this detection is a true positive by:<br/>   1. Validating that the webpage in the detection exists, is unauthorized, and contains webshell functionality.<br/>   2. Validating that the external entity interacting with the device is unknown or unauthorized.<br/>   3. Inspecting traffic or logs to see if interaction with this webpage is uncommon and recent.<br/>3. Quarantine the impacted device.<br/>4. Begin incident response procedures on the impacted device.<br/>5. Block traffic from attacker infrastructure.<br/>6. Search traffic or logs from the infected web server to identify potential lateral movement by the attackers. | CKnife Webshell Activity | high | e9008859-c038-4bd5-a805-21efffd58355 | gdm2 | active | 2022-08-24T09:03:14.430538Z |  | 6d0d7c2d-33a1-458d-a5e5-461fe7b03409 |


### insight-get-detection-rules
***
Get a list of detection rules.


#### Base Command

`insight-get-detection-rules`
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
| sort_by | Sort output by: "ip", "internal", "external". Possible values are: ip, internal, external. | Optional | 
| sort_order | Sort direction ("asc" vs "desc"). Possible values are: asc, desc. | Optional | 
| offset | The number of records to skip past. | Optional | 
| limit | The number of records to return, default: 100, max: 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Rules.enabled | boolean | Status of the rule: If true it is enabled, if false it is disabled. | 
| Insight.Rules.updated_user_uuid | string | User ID that updated the rule | 
| Insight.Rules.rule_accounts | string | Accounts which have seen detections for this rule | 
| Insight.Rules.auto_resolution_minutes | number | Length of time \(in minutes\) the rule will auto-resolve detections | 
| Insight.Rules.created | date | Date the rule was created | 
| Insight.Rules.account_uuid | string | Account ID the rule was created under | 
| Insight.Rules.confidence | string | Confidence level of the rule | 
| Insight.Rules.name | string | Name of the rule | 
| Insight.Rules.created_user_uuid | string | User ID that created the rule | 
| Insight.Rules.query_signature | string | IQL signature of the rule | 
| Insight.Rules.shared_account_uuids | string | Account IDs the rule is visible to | 
| Insight.Rules.run_account_uuids | string | Account IDs the rule runs on | 
| Insight.Rules.updated | date | Date the rule was updated | 
| Insight.Rules.uuid | string | Unique ID of the rule | 
| Insight.Rules.description | string | Description of the rule | 
| Insight.Rules.severity | string | Severity level of the rule | 
| Insight.Rules.category | string | Category of the rule | 

#### Command example
```!insight-get-detection-rules confidence=high category=Attack:Installation```
#### Context Example
```json
{
    "Insight": {
        "Rules": [
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 20160,
                "category": "Attack:Installation",
                "confidence": "high",
                "created": "2019-05-06T13:00:29.165000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2021-01-16T00:27:43.540000Z",
                "description": "This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.\r\n\r\nGigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by:\r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\r\n    2. Verifying that the file is malicious in nature.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:uri.uri",
                    "http:user_agent",
                    "http:files.sha256"
                ],
                "name": "Executable or Script Download From External Python SimpleHTTPServer",
                "primary_attack_id": "T1105",
                "query_signature": "http:headers.server LIKE \"SimpleHTTP/% Python/%\"\r\n// Filter for plain executable binary MIME types\r\nAND (\r\n    response_mime LIKE \"%executable%\"\r\n    OR response_mime LIKE \"%application/x-dosexec%\"\r\n    OR response_mime LIKE \"%application/x-macbinary%\"\r\n\r\n    // Commonly malicious\r\n    OR response_mime LIKE \"%application/x-ms-shortcut%\"\r\n    OR response_mime LIKE \"%application/vnd.ms-htmlhelp%\"\r\n\r\n    // System-level scripts\r\n    OR response_mime LIKE \"%text/x-msdos-batch%\"\r\n    OR response_mime LIKE \"%x-shellscript%\"\r\n)\r\n\r\n// Outbound traffic\r\nAND src.internal = true\r\nAND (\r\n    dst.internal = false\r\n    OR (\r\n        // Not internal IP address\r\n        host.internal != true\r\n        // Proxied traffic\r\n        AND uri.scheme != null\r\n    )\r\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 4,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 12,
                        "first_seen": "2022-02-01T09:35:58.269000Z",
                        "last_seen": "2022-08-23T08:36:02.794000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2022-04-27T16:26:03.115153Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "fe4d55b4-7293-425a-b549-43a22472923d"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 30240,
                "category": "Attack:Installation",
                "confidence": "high",
                "created": "2018-04-24T23:39:13.382000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2020-12-10T00:04:21.861000Z",
                "description": "This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. \n\n## Next Steps \n1. Determine if this is a true positive by: \n    1. Investigating for connections outbound to ports 447 and 449 from the affected host.\n    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).\n    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. \n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:uri.uri",
                    "http:user_agent",
                    "http:files.sha256"
                ],
                "name": "Trickbot Staging Download",
                "primary_attack_id": "T1105",
                "query_signature": "http:user_agent = \"WinHTTP loader/1.0\"\r\nAND response_mime = \"application/x-dosexec\"",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 2,
                        "first_seen": "2021-12-20T09:06:10.558000Z",
                        "last_seen": "2022-08-22T08:09:10.243000Z",
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2022-01-05T18:39:07.352000Z",
                        "muted_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "tool_implementation",
                "updated": "2021-03-19T19:32:19.685000Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "aadb155e-712f-481f-9680-482bab5a238d"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "high",
                "created": "2018-05-15T18:08:55.511000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2020-07-08T21:59:20.870000Z",
                "description": "This logic is intended to detect Pony or Hancitor second stage downloads. Hancitor and Pony are banking trojans that attempt to harvest credentials for web sites, primarily for financial institutions. As well as harvesting credentials for any user accounts used on affected hosts, they can also be used as a remote access tool that enables access to the network. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution, and allows for unauthorized access to the network. Gigamon ATR considers this detection high confidence, as these requests are unlikely to be the result of legitimate activity. \n\n## Next Steps\n1. Determine if this detection is a true positive by checking the host for signs of compromise. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:uri.uri",
                    "http:user_agent"
                ],
                "name": "Pony or Hancitor Second Stage Download",
                "primary_attack_id": "T1105",
                "query_signature": "http:method = \"POST\"\r\nAND uri.path LIKE \"%/gate.php\"\r\nAND (\r\n    response_len > 1MB\r\n    OR user_agent LIKE \"%Windows 98%\"\r\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 17,
                        "first_seen": "2022-02-06T16:22:18.923000Z",
                        "last_seen": "2022-08-21T15:22:21.518000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": "T1104",
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [],
                "specificity": "tool_implementation",
                "updated": "2021-03-17T23:36:35.422000Z",
                "updated_user_uuid": "9128e5ed-4ee4-4b29-a7f4-ea9f9f092dc3",
                "uuid": "2d06c01f-5ae4-4346-8d6a-99926dcac4f1"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|account_uuid|auto_resolution_minutes|category|confidence|created|created_user_uuid|critical_updated|description|device_ip_fields|enabled|indicator_fields|name|primary_attack_id|query_signature|rule_accounts|run_account_uuids|secondary_attack_id|severity|shared_account_uuids|source_excludes|specificity|updated|updated_user_uuid|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 20160 | Attack:Installation | high | 2019-05-06T13:00:29.165000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2021-01-16T00:27:43.540000Z | This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.<br/><br/>Gigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | src.ip | true | dst.ip,<br/>http:host,<br/>http:uri.uri,<br/>http:user_agent,<br/>http:files.sha256 | Executable or Script Download From External Python SimpleHTTPServer | T1105 | http:headers.server LIKE "SimpleHTTP/% Python/%"<br/>// Filter for plain executable binary MIME types<br/>AND (<br/>    response_mime LIKE "%executable%"<br/>    OR response_mime LIKE "%application/x-dosexec%"<br/>    OR response_mime LIKE "%application/x-macbinary%"<br/><br/>    // Commonly malicious<br/>    OR response_mime LIKE "%application/x-ms-shortcut%"<br/>    OR response_mime LIKE "%application/vnd.ms-htmlhelp%"<br/><br/>    // System-level scripts<br/>    OR response_mime LIKE "%text/x-msdos-batch%"<br/>    OR response_mime LIKE "%x-shellscript%"<br/>)<br/><br/>// Outbound traffic<br/>AND src.internal = true<br/>AND (<br/>    dst.internal = false<br/>    OR (<br/>        // Not internal IP address<br/>        host.internal != true<br/>        // Proxied traffic<br/>        AND uri.scheme != null<br/>    )<br/>) | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 4, 'detection_muted_count': 0, 'detection_resolved_count': 12, 'first_seen': '2022-02-01T09:35:58.269000Z', 'last_seen': '2022-08-23T08:36:02.794000Z'} |  |  | moderate |  | Zscaler | procedure | 2022-04-27T16:26:03.115153Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | fe4d55b4-7293-425a-b549-43a22472923d |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 30240 | Attack:Installation | high | 2018-04-24T23:39:13.382000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2020-12-10T00:04:21.861000Z | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. <br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | src.ip | true | dst.ip,<br/>http:host,<br/>http:uri.uri,<br/>http:user_agent,<br/>http:files.sha256 | Trickbot Staging Download | T1105 | http:user_agent = "WinHTTP loader/1.0"<br/>AND response_mime = "application/x-dosexec" | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': '2964a059-e470-4622-929e-2cadcccf98f4', 'muted_timestamp': '2022-01-05T18:39:07.352000Z', 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 2, 'first_seen': '2021-12-20T09:06:10.558000Z', 'last_seen': '2022-08-22T08:09:10.243000Z'} |  |  | high |  | Zscaler | tool_implementation | 2021-03-19T19:32:19.685000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | aadb155e-712f-481f-9680-482bab5a238d |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Attack:Installation | high | 2018-05-15T18:08:55.511000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2020-07-08T21:59:20.870000Z | This logic is intended to detect Pony or Hancitor second stage downloads. Hancitor and Pony are banking trojans that attempt to harvest credentials for web sites, primarily for financial institutions. As well as harvesting credentials for any user accounts used on affected hosts, they can also be used as a remote access tool that enables access to the network. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution, and allows for unauthorized access to the network. Gigamon ATR considers this detection high confidence, as these requests are unlikely to be the result of legitimate activity. <br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by checking the host for signs of compromise. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | src.ip | true | dst.ip,<br/>http:host,<br/>http:uri.uri,<br/>http:user_agent | Pony or Hancitor Second Stage Download | T1105 | http:method = "POST"<br/>AND uri.path LIKE "%/gate.php"<br/>AND (<br/>    response_len > 1MB<br/>    OR user_agent LIKE "%Windows 98%"<br/>) | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 17, 'first_seen': '2022-02-06T16:22:18.923000Z', 'last_seen': '2022-08-21T15:22:21.518000Z'} |  | T1104 | high |  |  | tool_implementation | 2021-03-17T23:36:35.422000Z | 9128e5ed-4ee4-4b29-a7f4-ea9f9f092dc3 | 2d06c01f-5ae4-4346-8d6a-99926dcac4f1 |


### insight-resolve-detection
***
Resolve a specific detection.


#### Base Command

`insight-resolve-detection`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_uuid | Detection UUID to resolve. | Required | 
| resolution | Resolution state. Options: true_positive_mitigated, true_posititve_no_action, false_positive, unknown. Possible values are: true_positive_mitigated, true_positive_no_action, false_positive, unknown. | Required | 
| resolution_comment | Optional comment for the resolution. | Optional | 


#### Context Output

There is no context output for this command.
### insight-get-detection-rule-events
***
Get a list of the events that matched on a specific rule.


#### Base Command

`insight-get-detection-rule-events`
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
| Insight.Events.src_ip | string | Source IP address | 
| Insight.Events.dst_ip | string | Destination IP address | 
| Insight.Events.src_port | number | Source port number | 
| Insight.Events.dst_port | number | Destination port number | 
| Insight.Events.host_domain | string | Domain name | 
| Insight.Events.flow_id | string | Unique ID of the flow record | 
| Insight.Events.event_type | string | Event type | 
| Insight.Events.sensor_id | string | ID code of the sensor | 
| Insight.Events.timestamp | date | Date the event occurred | 
| Insight.Events.customer_id | string | ID code of the customer account | 
| Insight.Events.uuid | string | Unique ID for the event | 

#### Command example
```!insight-get-detection-rule-events rule_uuid=aadb155e-712f-481f-9680-482bab5a238d limit=3```
#### Context Example
```json
{
    "Insight": {
        "Detections": [
            {
                "customer_id": "gdm",
                "dst": {
                    "asn": {
                        "asn": 46562,
                        "asn_org": "PERFORMIVE",
                        "isp": "Performive",
                        "org": "Performive"
                    },
                    "geo": {
                        "city": "Richardson",
                        "country": "US",
                        "location": {
                            "lat": 32.9636,
                            "lon": -96.7468
                        },
                        "subdivision": "TX"
                    },
                    "internal": false,
                    "ip": "101.25.175.118",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": 80
                },
                "event_type": "http",
                "files": [
                    {
                        "bytes": 503808,
                        "md5": "725d4b987107aa0f797f2aad4daaf8cd",
                        "mime_type": null,
                        "name": null,
                        "sha1": "44b8b2a5a79ed223dadb612728661824430fe793",
                        "sha256": "c9075805b3d43e3d0231216662068850cbde533bc7f0f4c7486f5a89224c524c"
                    }
                ],
                "flow_id": "C8fsbW3SBCuWYNaUse",
                "geo_distance": null,
                "headers": {
                    "accept": null,
                    "content_md5": null,
                    "content_type": "image/png",
                    "cookie_length": null,
                    "location": null,
                    "origin": null,
                    "proxied_client_ips": null,
                    "refresh": null,
                    "server": "nginx/1.10.3",
                    "x_powered_by": null
                },
                "host": {
                    "asn": {
                        "asn": 46562,
                        "asn_org": "PERFORMIVE",
                        "isp": "Performive",
                        "org": "Performive"
                    },
                    "geo": {
                        "city": "Richardson",
                        "country": "US",
                        "location": {
                            "lat": 32.9636,
                            "lon": -96.7468
                        },
                        "subdivision": "TX"
                    },
                    "internal": false,
                    "ip": "101.25.175.118",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": null
                },
                "info_msg": null,
                "intel": null,
                "method": "GET",
                "proxied": null,
                "referrer": null,
                "request_len": 0,
                "request_mime": null,
                "request_mimes": null,
                "response_len": 503808,
                "response_mime": "application/x-dosexec",
                "response_mimes": [
                    "application/x-dosexec"
                ],
                "sensor_id": "gdm2",
                "source": "Zeek",
                "src": {
                    "asn": null,
                    "geo": null,
                    "internal": true,
                    "ip": "21.5.31.5",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": 51520
                },
                "status_code": 200,
                "status_msg": "OK",
                "timestamp": "2022-08-22T08:09:10.243Z",
                "trans_depth": 2,
                "uri": {
                    "fragment": null,
                    "host": null,
                    "path": "/scrimet.png",
                    "port": -1,
                    "query": null,
                    "scheme": null,
                    "uri": "/scrimet.png"
                },
                "user_agent": "WinHTTP loader/1.0",
                "username": null,
                "uuid": "343c26aa-21f3-11ed-9d7b-0a1766ad1b93"
            },
            {
                "customer_id": "gdm",
                "dst": {
                    "asn": {
                        "asn": 46562,
                        "asn_org": "PERFORMIVE",
                        "isp": "Performive",
                        "org": "Performive"
                    },
                    "geo": {
                        "city": "Richardson",
                        "country": "US",
                        "location": {
                            "lat": 32.9636,
                            "lon": -96.7468
                        },
                        "subdivision": "TX"
                    },
                    "internal": false,
                    "ip": "101.25.175.118",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": 80
                },
                "event_type": "http",
                "files": [
                    {
                        "bytes": 472706,
                        "md5": null,
                        "mime_type": null,
                        "name": null,
                        "sha1": null,
                        "sha256": null
                    }
                ],
                "flow_id": "C8fsbW3SBCuWYNaUse",
                "geo_distance": null,
                "headers": {
                    "accept": null,
                    "content_md5": null,
                    "content_type": "image/png",
                    "cookie_length": null,
                    "location": null,
                    "origin": null,
                    "proxied_client_ips": null,
                    "refresh": null,
                    "server": "nginx/1.10.3",
                    "x_powered_by": null
                },
                "host": {
                    "asn": {
                        "asn": 46562,
                        "asn_org": "PERFORMIVE",
                        "isp": "Performive",
                        "org": "Performive"
                    },
                    "geo": {
                        "city": "Richardson",
                        "country": "US",
                        "location": {
                            "lat": 32.9636,
                            "lon": -96.7468
                        },
                        "subdivision": "TX"
                    },
                    "internal": false,
                    "ip": "101.25.175.118",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": null
                },
                "info_msg": null,
                "intel": null,
                "method": "GET",
                "proxied": null,
                "referrer": null,
                "request_len": 0,
                "request_mime": null,
                "request_mimes": null,
                "response_len": 472706,
                "response_mime": "application/x-dosexec",
                "response_mimes": [
                    "application/x-dosexec"
                ],
                "sensor_id": "gdm2",
                "source": "Zeek",
                "src": {
                    "asn": null,
                    "geo": null,
                    "internal": true,
                    "ip": "21.5.31.5",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": 51520
                },
                "status_code": 200,
                "status_msg": "OK",
                "timestamp": "2022-08-22T08:09:04.693Z",
                "trans_depth": 1,
                "uri": {
                    "fragment": null,
                    "host": null,
                    "path": "/tablone.png",
                    "port": -1,
                    "query": null,
                    "scheme": null,
                    "uri": "/tablone.png"
                },
                "user_agent": "WinHTTP loader/1.0",
                "username": null,
                "uuid": "3439dbfc-21f3-11ed-9d7b-0a1766ad1b93"
            },
            {
                "customer_id": "gdm",
                "dst": {
                    "asn": {
                        "asn": 46562,
                        "asn_org": "PERFORMIVE",
                        "isp": "Performive",
                        "org": "Performive"
                    },
                    "geo": {
                        "city": "Richardson",
                        "country": "US",
                        "location": {
                            "lat": 32.9636,
                            "lon": -96.7468
                        },
                        "subdivision": "TX"
                    },
                    "internal": false,
                    "ip": "101.25.175.118",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": 80
                },
                "event_type": "http",
                "files": [
                    {
                        "bytes": 503808,
                        "md5": "725d4b987107aa0f797f2aad4daaf8cd",
                        "mime_type": null,
                        "name": null,
                        "sha1": "44b8b2a5a79ed223dadb612728661824430fe793",
                        "sha256": "c9075805b3d43e3d0231216662068850cbde533bc7f0f4c7486f5a89224c524c"
                    }
                ],
                "flow_id": "CRcO6G4eqlWvo7gjia",
                "geo_distance": null,
                "headers": {
                    "accept": null,
                    "content_md5": null,
                    "content_type": "image/png",
                    "cookie_length": null,
                    "location": null,
                    "origin": null,
                    "proxied_client_ips": null,
                    "refresh": null,
                    "server": "nginx/1.10.3",
                    "x_powered_by": null
                },
                "host": {
                    "asn": {
                        "asn": 46562,
                        "asn_org": "PERFORMIVE",
                        "isp": "Performive",
                        "org": "Performive"
                    },
                    "geo": {
                        "city": "Richardson",
                        "country": "US",
                        "location": {
                            "lat": 32.9636,
                            "lon": -96.7468
                        },
                        "subdivision": "TX"
                    },
                    "internal": false,
                    "ip": "101.25.175.118",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": null
                },
                "info_msg": null,
                "intel": null,
                "method": "GET",
                "proxied": null,
                "referrer": null,
                "request_len": 0,
                "request_mime": null,
                "request_mimes": null,
                "response_len": 503808,
                "response_mime": "application/x-dosexec",
                "response_mimes": [
                    "application/x-dosexec"
                ],
                "sensor_id": "gdm2",
                "source": "Zeek",
                "src": {
                    "asn": null,
                    "geo": null,
                    "internal": true,
                    "ip": "21.5.31.101",
                    "ip_bytes": null,
                    "pkts": null,
                    "port": 58761
                },
                "status_code": 200,
                "status_msg": "OK",
                "timestamp": "2022-08-22T08:06:40.603Z",
                "trans_depth": 2,
                "uri": {
                    "fragment": null,
                    "host": null,
                    "path": "/scrimet.png",
                    "port": -1,
                    "query": null,
                    "scheme": null,
                    "uri": "/scrimet.png"
                },
                "user_agent": "WinHTTP loader/1.0",
                "username": null,
                "uuid": "343177d6-21f3-11ed-9d7b-0a1766ad1b93"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|customer_id|dst|event_type|files|flow_id|geo_distance|headers|host|info_msg|intel|method|proxied|referrer|request_len|request_mime|request_mimes|response_len|response_mime|response_mimes|sensor_id|source|src|status_code|status_msg|timestamp|trans_depth|uri|user_agent|username|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| gdm | ip: 101.25.175.118<br/>port: 80<br/>ip_bytes: null<br/>pkts: null<br/>geo: {"location": {"lat": 32.9636, "lon": -96.7468}, "country": "US", "subdivision": "TX", "city": "Richardson"}<br/>asn: {"asn": 46562, "org": "Performive", "isp": "Performive", "asn_org": "PERFORMIVE"}<br/>internal: false | http | {'name': None, 'md5': '725d4b987107aa0f797f2aad4daaf8cd', 'sha1': '44b8b2a5a79ed223dadb612728661824430fe793', 'sha256': 'c9075805b3d43e3d0231216662068850cbde533bc7f0f4c7486f5a89224c524c', 'bytes': 503808, 'mime_type': None} | C8fsbW3SBCuWYNaUse |  | accept: null<br/>content_md5: null<br/>content_type: image/png<br/>cookie_length: null<br/>location: null<br/>origin: null<br/>proxied_client_ips: null<br/>refresh: null<br/>server: nginx/1.10.3<br/>x_powered_by: null | ip: 101.25.175.118<br/>port: null<br/>ip_bytes: null<br/>pkts: null<br/>geo: {"location": {"lat": 32.9636, "lon": -96.7468}, "country": "US", "subdivision": "TX", "city": "Richardson"}<br/>asn: {"asn": 46562, "org": "Performive", "isp": "Performive", "asn_org": "PERFORMIVE"}<br/>internal: false |  |  | GET |  |  | 0 |  |  | 503808 | application/x-dosexec | application/x-dosexec | gdm2 | Zeek | ip: 21.5.31.5<br/>port: 51520<br/>ip_bytes: null<br/>pkts: null<br/>geo: null<br/>asn: null<br/>internal: true | 200 | OK | 2022-08-22T08:09:10.243Z | 2 | uri: /scrimet.png<br/>scheme: null<br/>host: null<br/>port: -1<br/>path: /scrimet.png<br/>query: null<br/>fragment: null | WinHTTP loader/1.0 |  | 343c26aa-21f3-11ed-9d7b-0a1766ad1b93 |
>| gdm | ip: 101.25.175.118<br/>port: 80<br/>ip_bytes: null<br/>pkts: null<br/>geo: {"location": {"lat": 32.9636, "lon": -96.7468}, "country": "US", "subdivision": "TX", "city": "Richardson"}<br/>asn: {"asn": 46562, "org": "Performive", "isp": "Performive", "asn_org": "PERFORMIVE"}<br/>internal: false | http | {'name': None, 'md5': None, 'sha1': None, 'sha256': None, 'bytes': 472706, 'mime_type': None} | C8fsbW3SBCuWYNaUse |  | accept: null<br/>content_md5: null<br/>content_type: image/png<br/>cookie_length: null<br/>location: null<br/>origin: null<br/>proxied_client_ips: null<br/>refresh: null<br/>server: nginx/1.10.3<br/>x_powered_by: null | ip: 101.25.175.118<br/>port: null<br/>ip_bytes: null<br/>pkts: null<br/>geo: {"location": {"lat": 32.9636, "lon": -96.7468}, "country": "US", "subdivision": "TX", "city": "Richardson"}<br/>asn: {"asn": 46562, "org": "Performive", "isp": "Performive", "asn_org": "PERFORMIVE"}<br/>internal: false |  |  | GET |  |  | 0 |  |  | 472706 | application/x-dosexec | application/x-dosexec | gdm2 | Zeek | ip: 21.5.31.5<br/>port: 51520<br/>ip_bytes: null<br/>pkts: null<br/>geo: null<br/>asn: null<br/>internal: true | 200 | OK | 2022-08-22T08:09:04.693Z | 1 | uri: /tablone.png<br/>scheme: null<br/>host: null<br/>port: -1<br/>path: /tablone.png<br/>query: null<br/>fragment: null | WinHTTP loader/1.0 |  | 3439dbfc-21f3-11ed-9d7b-0a1766ad1b93 |
>| gdm | ip: 101.25.175.118<br/>port: 80<br/>ip_bytes: null<br/>pkts: null<br/>geo: {"location": {"lat": 32.9636, "lon": -96.7468}, "country": "US", "subdivision": "TX", "city": "Richardson"}<br/>asn: {"asn": 46562, "org": "Performive", "isp": "Performive", "asn_org": "PERFORMIVE"}<br/>internal: false | http | {'name': None, 'md5': '725d4b987107aa0f797f2aad4daaf8cd', 'sha1': '44b8b2a5a79ed223dadb612728661824430fe793', 'sha256': 'c9075805b3d43e3d0231216662068850cbde533bc7f0f4c7486f5a89224c524c', 'bytes': 503808, 'mime_type': None} | CRcO6G4eqlWvo7gjia |  | accept: null<br/>content_md5: null<br/>content_type: image/png<br/>cookie_length: null<br/>location: null<br/>origin: null<br/>proxied_client_ips: null<br/>refresh: null<br/>server: nginx/1.10.3<br/>x_powered_by: null | ip: 101.25.175.118<br/>port: null<br/>ip_bytes: null<br/>pkts: null<br/>geo: {"location": {"lat": 32.9636, "lon": -96.7468}, "country": "US", "subdivision": "TX", "city": "Richardson"}<br/>asn: {"asn": 46562, "org": "Performive", "isp": "Performive", "asn_org": "PERFORMIVE"}<br/>internal: false |  |  | GET |  |  | 0 |  |  | 503808 | application/x-dosexec | application/x-dosexec | gdm2 | Zeek | ip: 21.5.31.101<br/>port: 58761<br/>ip_bytes: null<br/>pkts: null<br/>geo: null<br/>asn: null<br/>internal: true | 200 | OK | 2022-08-22T08:06:40.603Z | 2 | uri: /scrimet.png<br/>scheme: null<br/>host: null<br/>port: -1<br/>path: /scrimet.png<br/>query: null<br/>fragment: null | WinHTTP loader/1.0 |  | 343177d6-21f3-11ed-9d7b-0a1766ad1b93 |


### insight-create-detection-rule
***
Create a new detection rule.


#### Base Command

`insight-create-detection-rule`
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