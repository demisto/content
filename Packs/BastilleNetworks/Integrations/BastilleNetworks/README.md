RF monitoring for wireless intrusion detection and policy enforcement. Visit https://www.bastille.net for details.

This integration was integrated and tested with Bastille Networks product version 1.5.0.

## Configure BastilleNetworks in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| api_url | Server URL | False |
| api_key | API Key | True |
| site | Site | True |
| concentrator | Concentrator | True |
| map | Map | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| tags | Tags | False |
| event_types | Event types | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bastille-get-device-events
***
Command to fetch device detection events


#### Base Command

`bastille-get-device-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| protocol | Filter by transmitter protocol name | Optional | 
| since | Earliest time to return incidents from | Optional | 
| until | Latest time to return incidents from | Optional | 
| limit | Limit the number of fetched events | Optional | 
| tags | List of tags to filter events by | Optional | 
| event_id | Unique identifier of the zone detection event | Optional | 
| transmitter_id | Device identifier to query the detections for | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bastille.DeviceEvent.event_id | String | Unique identifier of the event | 
| Bastille.DeviceEvent.event_type | String | Type of the event | 
| Bastille.DeviceEvent.time_s | Date | Event detection timestamp | 
| Bastille.DeviceEvent.tags | String | Tags attached to the zone event | 
| Bastille.DeviceEvent.zone_name | String | Zone name where the incident took place | 
| Bastille.DeviceEvent.area.site_id | String | Deployment site identifier | 
| Bastille.DeviceEvent.area.concentrator_id | String | Deployment concentrator identifier | 
| Bastille.DeviceEvent.area.map_id | String | Deployment map identifier | 
| Bastille.DeviceEvent.emitter.protocol | String | Wireless protcol used by the detected transmitter | 
| Bastille.DeviceEvent.emitter.transmitter_id | String | Wireless transmitter identifier | 
| Bastille.DeviceEvent.emitter.vendor | String | Wireless transmitter vendor | 
| Bastille.DeviceEvent.emitter.network.name | String | Name of the network the transmitter is connected to | 
| Bastille.DeviceEvent.device_info.manufacturer | String | Manufacturer associated with device in the deployment | 
| Bastille.DeviceEvent.device_info.user | String | User associated with device in the deployment | 
| Bastille.DeviceEvent.device_info.model | String | Model associated with device in the deployment | 
| Bastille.DeviceEvent.device_info.name | String | Name associated with device in the deployment | 
| Bastille.DeviceEvent.first_seen.time | Number | Event first seen timestamp | 
| Bastille.DeviceEvent.first_seen.position | Unknown | Event first seen coordinates | 
| Bastille.DeviceEvent.last_seen.time | Number | Event last seen timestamp | 
| Bastille.DeviceEvent.last_seen.position | Unknown | Event last seen coordinates | 


#### Command Example
```!bastille-get-device-events since=2020-05-01T13:00:00T until=2020-05-01T17:00:00T```

#### Context Example
```
{
    "Bastille": {
        "DeviceEvent": [
            {
                "area": {
                    "concentrator_id": "c1",
                    "map_id": "m1",
                    "site_id": "s1"
                },
                "device_info": {
                    "manufacturer": "Apple",
                    "model": "iPhone 7",
                    "name": "Jane's iPhone 7",
                    "user": "Jane Doe"
                },
                "emitter": {
                    "network": {
                        "name": "Verizon"
                    },
                    "protocol": "LTE",
                    "transmitter_id": "vzw:1100:249:6f4d",
                    "vendor": "Unknown"
                },
                "event_id": "LTE_vzw:1100:249:6f4d_s1_c1_m1_1588338000",
                "event_type": "device_event",
                "first_seen": {
                    "position": [
                        34.61,
                        13.31
                    ],
                    "time_s": "2020-05-01T13:00:00+00:00"
                },
                "last_seen": {
                    "position": [
                        32.31,
                        11.24
                    ],
                    "time_s": "2020-05-01T13:00:00+00:00"
                },
                "tags": [],
                "time_s": "2020-05-01T13:00:00+00:00"
            },
            {
                "area": {
                    "concentrator_id": "c1",
                    "map_id": "m1",
                    "site_id": "s1"
                },
                "device_info": {
                    "manufacturer": "Apple",
                    "model": "iPhone 7",
                    "name": "Jane's iPhone 7",
                    "user": "Jane Doe"
                },
                "emitter": {
                    "network": {
                        "name": "Verizon"
                    },
                    "protocol": "LTE",
                    "transmitter_id": "vzw:1100:249:6f4d",
                    "vendor": "Unknown"
                },
                "event_id": "LTE_vzw:1100:249:6f4d_s1_c1_m1_1588338060",
                "event_type": "device_event",
                "first_seen": {
                    "position": [
                        34.61,
                        13.31
                    ],
                    "time_s": "2020-05-01T13:01:00+00:00"
                },
                "last_seen": {
                    "position": [
                        32.31,
                        11.24
                    ],
                    "time_s": "2020-05-01T13:01:00+00:00"
                },
                "tags": [],
                "time_s": "2020-05-01T13:01:00+00:00"
            },
            {
                "area": {
                    "concentrator_id": "c1",
                    "map_id": "m1",
                    "site_id": "s1"
                },
                "device_info": {
                    "manufacturer": "Apple",
                    "model": "iPhone 7",
                    "name": "Jane's iPhone 7",
                    "user": "Jane Doe"
                },
                "emitter": {
                    "network": {
                        "name": "Verizon"
                    },
                    "protocol": "LTE",
                    "transmitter_id": "vzw:1100:249:6f4d",
                    "vendor": "Unknown"
                },
                "event_id": "LTE_vzw:1100:249:6f4d_s1_c1_m1_1588338120",
                "event_type": "device_event",
                "first_seen": {
                    "position": [
                        34.61,
                        13.31
                    ],
                    "time_s": "2020-05-01T13:02:00+00:00"
                },
                "last_seen": {
                    "position": [
                        32.31,
                        11.24
                    ],
                    "time_s": "2020-05-01T13:02:00+00:00"
                },
                "tags": [],
                "time_s": "2020-05-01T13:02:00+00:00"
            },
            {
                "area": {
                    "concentrator_id": "c1",
                    "map_id": "m1",
                    "site_id": "s1"
                },
                "device_info": {
                    "manufacturer": "Apple",
                    "model": "iPhone 7",
                    "name": "Jane's iPhone 7",
                    "user": "Jane Doe"
                },
                "emitter": {
                    "network": {
                        "name": "Verizon"
                    },
                    "protocol": "LTE",
                    "transmitter_id": "vzw:1100:249:6f4d",
                    "vendor": "Unknown"
                },
                "event_id": "LTE_vzw:1100:249:6f4d_s1_c1_m1_1588338180",
                "event_type": "device_event",
                "first_seen": {
                    "position": [
                        34.61,
                        13.31
                    ],
                    "time_s": "2020-05-01T13:03:00+00:00"
                },
                "last_seen": {
                    "position": [
                        32.31,
                        11.24
                    ],
                    "time_s": "2020-05-01T13:03:00+00:00"
                },
                "tags": [],
                "time_s": "2020-05-01T13:03:00+00:00"
            },
            {
                "area": {
                    "concentrator_id": "c1",
                    "map_id": "m1",
                    "site_id": "s1"
                },
                "device_info": {
                    "manufacturer": "Apple",
                    "model": "iPhone 7",
                    "name": "Jane's iPhone 7",
                    "user": "Jane Doe"
                },
                "emitter": {
                    "network": {
                        "name": "Verizon"
                    },
                    "protocol": "LTE",
                    "transmitter_id": "vzw:1100:249:6f4d",
                    "vendor": "Unknown"
                },
                "event_id": "LTE_vzw:1100:249:6f4d_s1_c1_m1_1588338240",
                "event_type": "device_event",
                "first_seen": {
                    "position": [
                        34.61,
                        13.31
                    ],
                    "time_s": "2020-05-01T13:04:00+00:00"
                },
                "last_seen": {
                    "position": [
                        32.31,
                        11.24
                    ],
                    "time_s": "2020-05-01T13:04:00+00:00"
                },
                "tags": [],
                "time_s": "2020-05-01T13:04:00+00:00"
            }
        ]
    }
}
```

#### Human Readable Output

>### Device Events
>|area|device_info|emitter|event_id|first_seen|last_seen|tags|time_s|
>|---|---|---|---|---|---|---|---|
>| site_id: s1<br/>concentrator_id: c1<br/>map_id: m1 | manufacturer: Apple<br/>user: Jane Doe<br/>model: iPhone 7<br/>name: Jane's iPhone 7 | protocol: LTE<br/>transmitter_id: vzw:1100:249:6f4d<br/>vendor: Unknown<br/>network: {"name": "Verizon"} | LTE_vzw:1100:249:6f4d_s1_c1_m1_1588338000 | time_s: 2020-05-01T13:00:00+00:00<br/>position: 34.61,<br/>13.31 | position: 32.31,<br/>11.24<br/>time_s: 2020-05-01T13:00:00+00:00 |  | 2020-05-01T13:00:00+00:00 |
>| site_id: s1<br/>concentrator_id: c1<br/>map_id: m1 | manufacturer: Apple<br/>user: Jane Doe<br/>model: iPhone 7<br/>name: Jane's iPhone 7 | protocol: LTE<br/>transmitter_id: vzw:1100:249:6f4d<br/>vendor: Unknown<br/>network: {"name": "Verizon"} | LTE_vzw:1100:249:6f4d_s1_c1_m1_1588338060 | time_s: 2020-05-01T13:01:00+00:00<br/>position: 34.61,<br/>13.31 | position: 32.31,<br/>11.24<br/>time_s: 2020-05-01T13:01:00+00:00 |  | 2020-05-01T13:01:00+00:00 |
>| site_id: s1<br/>concentrator_id: c1<br/>map_id: m1 | manufacturer: Apple<br/>user: Jane Doe<br/>model: iPhone 7<br/>name: Jane's iPhone 7 | protocol: LTE<br/>transmitter_id: vzw:1100:249:6f4d<br/>vendor: Unknown<br/>network: {"name": "Verizon"} | LTE_vzw:1100:249:6f4d_s1_c1_m1_1588338120 | time_s: 2020-05-01T13:02:00+00:00<br/>position: 34.61,<br/>13.31 | position: 32.31,<br/>11.24<br/>time_s: 2020-05-01T13:02:00+00:00 |  | 2020-05-01T13:02:00+00:00 |
>| site_id: s1<br/>concentrator_id: c1<br/>map_id: m1 | manufacturer: Apple<br/>user: Jane Doe<br/>model: iPhone 7<br/>name: Jane's iPhone 7 | protocol: LTE<br/>transmitter_id: vzw:1100:249:6f4d<br/>vendor: Unknown<br/>network: {"name": "Verizon"} | LTE_vzw:1100:249:6f4d_s1_c1_m1_1588338180 | time_s: 2020-05-01T13:03:00+00:00<br/>position: 34.61,<br/>13.31 | position: 32.31,<br/>11.24<br/>time_s: 2020-05-01T13:03:00+00:00 |  | 2020-05-01T13:03:00+00:00 |
>| site_id: s1<br/>concentrator_id: c1<br/>map_id: m1 | manufacturer: Apple<br/>user: Jane Doe<br/>model: iPhone 7<br/>name: Jane's iPhone 7 | protocol: LTE<br/>transmitter_id: vzw:1100:249:6f4d<br/>vendor: Unknown<br/>network: {"name": "Verizon"} | LTE_vzw:1100:249:6f4d_s1_c1_m1_1588338240 | time_s: 2020-05-01T13:04:00+00:00<br/>position: 34.61,<br/>13.31 | position: 32.31,<br/>11.24<br/>time_s: 2020-05-01T13:04:00+00:00 |  | 2020-05-01T13:04:00+00:00 |


### bastille-get-zone-events
***
Command to fetch zone detection events


#### Base Command

`bastille-get-zone-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| zone | Filter by zone name | Optional | 
| protocol | Filter by transmitter protocol name | Optional | 
| since | Earliest time to return incidents from | Optional | 
| until | Latest time to return incidents from | Optional | 
| limit | Limit the number of fetched events | Optional | 
| tags | List of tags to filter events by | Optional | 
| event_id | Unique identifier of the zone detection event | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bastille.ZoneEvent.event_id | String | Unique identifier of the event | 
| Bastille.ZoneEvent.event_type | String | Type of the event | 
| Bastille.ZoneEvent.time_s | Date | Event detection timestamp | 
| Bastille.ZoneEvent.tags | String | Tags attached to the zone event | 
| Bastille.ZoneEvent.zone_name | String | Zone name where the incident took place | 
| Bastille.ZoneEvent.area.site_id | String | Deployment site identifier | 
| Bastille.ZoneEvent.area.concentrator_id | String | Deployment concentrator identifier | 
| Bastille.ZoneEvent.area.map_id | String | Deployment map identifier | 
| Bastille.ZoneEvent.emitter.protocol | String | Wireless protcol used by the detected transmitter | 
| Bastille.ZoneEvent.emitter.transmitter_id | String | Wireless transmitter identifier | 
| Bastille.ZoneEvent.emitter.vendor | String | Wireless transmitter vendor | 
| Bastille.ZoneEvent.emitter.network.name | String | Name of the network the transmitter is connected to | 
| Bastille.ZoneEvent.device_info.manufacturer | String | Manufacturer associated with device in the deployment | 
| Bastille.ZoneEvent.device_info.user | String | User associated with device in the deployment | 
| Bastille.ZoneEvent.device_info.model | String | Model associated with device in the deployment | 
| Bastille.ZoneEvent.device_info.name | String | Name associated with device in the deployment | 
| Bastille.ZoneEvent.first_seen.time | Number | Event first seen timestamp | 
| Bastille.ZoneEvent.first_seen.position | Unknown | Event first seen coordinates | 
| Bastille.ZoneEvent.last_seen.time | Number | Event last seen timestamp | 
| Bastille.ZoneEvent.last_seen.position | Unknown | Event last seen coordinates | 


#### Command Example
```!bastille-get-zone-events zone=conference-1```

#### Context Example
```
{
    "Bastille": {
        "ZoneEvent": [
            {
                "area": {
                    "concentrator_id": "c1",
                    "map_id": "m1",
                    "site_id": "s1"
                },
                "device_info": {
                    "manufacturer": "Apple",
                    "model": "iPhone 7",
                    "name": "Jane's iPhone 7",
                    "user": "Jane Doe"
                },
                "emitter": {
                    "network": {
                        "name": "Verizon"
                    },
                    "protocol": "LTE",
                    "transmitter_id": "vzw:1100:249:6f4d",
                    "vendor": "Unknown"
                },
                "event_id": "conference-1_LTE_vzw:1100:249:6f4d_s1_c1_m1_1585699200",
                "event_type": "zone_event",
                "first_seen": {
                    "position": [
                        34.61,
                        13.31
                    ],
                    "time_s": "2020-04-01T00:00:00+00:00"
                },
                "last_seen": {
                    "position": [
                        32.31,
                        11.24
                    ],
                    "time_s": "2020-04-01T00:00:00+00:00"
                },
                "tags": [],
                "time_s": "2020-04-01T00:00:00+00:00",
                "zone_name": "conference-1"
            },
            {
                "area": {
                    "concentrator_id": "c1",
                    "map_id": "m1",
                    "site_id": "s1"
                },
                "device_info": {
                    "manufacturer": "Apple",
                    "model": "iPhone 7",
                    "name": "Jane's iPhone 7",
                    "user": "Jane Doe"
                },
                "emitter": {
                    "network": {
                        "name": "Verizon"
                    },
                    "protocol": "LTE",
                    "transmitter_id": "vzw:1100:249:6f4d",
                    "vendor": "Unknown"
                },
                "event_id": "conference-1_LTE_vzw:1100:249:6f4d_s1_c1_m1_1585699260",
                "event_type": "zone_event",
                "first_seen": {
                    "position": [
                        34.61,
                        13.31
                    ],
                    "time_s": "2020-04-01T00:01:00+00:00"
                },
                "last_seen": {
                    "position": [
                        32.31,
                        11.24
                    ],
                    "time_s": "2020-04-01T00:01:00+00:00"
                },
                "tags": [],
                "time_s": "2020-04-01T00:01:00+00:00",
                "zone_name": "conference-1"
            },
            {
                "area": {
                    "concentrator_id": "c1",
                    "map_id": "m1",
                    "site_id": "s1"
                },
                "device_info": {
                    "manufacturer": "Apple",
                    "model": "iPhone 7",
                    "name": "Jane's iPhone 7",
                    "user": "Jane Doe"
                },
                "emitter": {
                    "network": {
                        "name": "Verizon"
                    },
                    "protocol": "LTE",
                    "transmitter_id": "vzw:1100:249:6f4d",
                    "vendor": "Unknown"
                },
                "event_id": "conference-1_LTE_vzw:1100:249:6f4d_s1_c1_m1_1585699320",
                "event_type": "zone_event",
                "first_seen": {
                    "position": [
                        34.61,
                        13.31
                    ],
                    "time_s": "2020-04-01T00:02:00+00:00"
                },
                "last_seen": {
                    "position": [
                        32.31,
                        11.24
                    ],
                    "time_s": "2020-04-01T00:02:00+00:00"
                },
                "tags": [],
                "time_s": "2020-04-01T00:02:00+00:00",
                "zone_name": "conference-1"
            },
            {
                "area": {
                    "concentrator_id": "c1",
                    "map_id": "m1",
                    "site_id": "s1"
                },
                "device_info": {
                    "manufacturer": "Apple",
                    "model": "iPhone 7",
                    "name": "Jane's iPhone 7",
                    "user": "Jane Doe"
                },
                "emitter": {
                    "network": {
                        "name": "Verizon"
                    },
                    "protocol": "LTE",
                    "transmitter_id": "vzw:1100:249:6f4d",
                    "vendor": "Unknown"
                },
                "event_id": "conference-1_LTE_vzw:1100:249:6f4d_s1_c1_m1_1585699380",
                "event_type": "zone_event",
                "first_seen": {
                    "position": [
                        34.61,
                        13.31
                    ],
                    "time_s": "2020-04-01T00:03:00+00:00"
                },
                "last_seen": {
                    "position": [
                        32.31,
                        11.24
                    ],
                    "time_s": "2020-04-01T00:03:00+00:00"
                },
                "tags": [],
                "time_s": "2020-04-01T00:03:00+00:00",
                "zone_name": "conference-1"
            },
            {
                "area": {
                    "concentrator_id": "c1",
                    "map_id": "m1",
                    "site_id": "s1"
                },
                "device_info": {
                    "manufacturer": "Apple",
                    "model": "iPhone 7",
                    "name": "Jane's iPhone 7",
                    "user": "Jane Doe"
                },
                "emitter": {
                    "network": {
                        "name": "Verizon"
                    },
                    "protocol": "LTE",
                    "transmitter_id": "vzw:1100:249:6f4d",
                    "vendor": "Unknown"
                },
                "event_id": "conference-1_LTE_vzw:1100:249:6f4d_s1_c1_m1_1585699440",
                "event_type": "zone_event",
                "first_seen": {
                    "position": [
                        34.61,
                        13.31
                    ],
                    "time_s": "2020-04-01T00:04:00+00:00"
                },
                "last_seen": {
                    "position": [
                        32.31,
                        11.24
                    ],
                    "time_s": "2020-04-01T00:04:00+00:00"
                },
                "tags": [],
                "time_s": "2020-04-01T00:04:00+00:00",
                "zone_name": "conference-1"
            }
        ]
    }
}
```

#### Human Readable Output

>### Zone Events
>|area|device_info|emitter|event_id|first_seen|last_seen|tags|time_s|zone_name|
>|---|---|---|---|---|---|---|---|---|
>| site_id: s1<br/>concentrator_id: c1<br/>map_id: m1 | manufacturer: Apple<br/>user: Jane Doe<br/>model: iPhone 7<br/>name: Jane's iPhone 7 | protocol: LTE<br/>transmitter_id: vzw:1100:249:6f4d<br/>vendor: Unknown<br/>network: {"name": "Verizon"} | conference-1_LTE_vzw:1100:249:6f4d_s1_c1_m1_1585699200 | time_s: 2020-04-01T00:00:00+00:00<br/>position: 34.61,<br/>13.31 | position: 32.31,<br/>11.24<br/>time_s: 2020-04-01T00:00:00+00:00 |  | 2020-04-01T00:00:00+00:00 | conference-1 |
>| site_id: s1<br/>concentrator_id: c1<br/>map_id: m1 | manufacturer: Apple<br/>user: Jane Doe<br/>model: iPhone 7<br/>name: Jane's iPhone 7 | protocol: LTE<br/>transmitter_id: vzw:1100:249:6f4d<br/>vendor: Unknown<br/>network: {"name": "Verizon"} | conference-1_LTE_vzw:1100:249:6f4d_s1_c1_m1_1585699260 | time_s: 2020-04-01T00:01:00+00:00<br/>position: 34.61,<br/>13.31 | position: 32.31,<br/>11.24<br/>time_s: 2020-04-01T00:01:00+00:00 |  | 2020-04-01T00:01:00+00:00 | conference-1 |
>| site_id: s1<br/>concentrator_id: c1<br/>map_id: m1 | manufacturer: Apple<br/>user: Jane Doe<br/>model: iPhone 7<br/>name: Jane's iPhone 7 | protocol: LTE<br/>transmitter_id: vzw:1100:249:6f4d<br/>vendor: Unknown<br/>network: {"name": "Verizon"} | conference-1_LTE_vzw:1100:249:6f4d_s1_c1_m1_1585699320 | time_s: 2020-04-01T00:02:00+00:00<br/>position: 34.61,<br/>13.31 | position: 32.31,<br/>11.24<br/>time_s: 2020-04-01T00:02:00+00:00 |  | 2020-04-01T00:02:00+00:00 | conference-1 |
>| site_id: s1<br/>concentrator_id: c1<br/>map_id: m1 | manufacturer: Apple<br/>user: Jane Doe<br/>model: iPhone 7<br/>name: Jane's iPhone 7 | protocol: LTE<br/>transmitter_id: vzw:1100:249:6f4d<br/>vendor: Unknown<br/>network: {"name": "Verizon"} | conference-1_LTE_vzw:1100:249:6f4d_s1_c1_m1_1585699380 | time_s: 2020-04-01T00:03:00+00:00<br/>position: 34.61,<br/>13.31 | position: 32.31,<br/>11.24<br/>time_s: 2020-04-01T00:03:00+00:00 |  | 2020-04-01T00:03:00+00:00 | conference-1 |
>| site_id: s1<br/>concentrator_id: c1<br/>map_id: m1 | manufacturer: Apple<br/>user: Jane Doe<br/>model: iPhone 7<br/>name: Jane's iPhone 7 | protocol: LTE<br/>transmitter_id: vzw:1100:249:6f4d<br/>vendor: Unknown<br/>network: {"name": "Verizon"} | conference-1_LTE_vzw:1100:249:6f4d_s1_c1_m1_1585699440 | time_s: 2020-04-01T00:04:00+00:00<br/>position: 34.61,<br/>13.31 | position: 32.31,<br/>11.24<br/>time_s: 2020-04-01T00:04:00+00:00 |  | 2020-04-01T00:04:00+00:00 | conference-1 |


### bastille-add-device-tag
***
Command to add tag to an existing device


#### Base Command

`bastille-add-device-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| transmitter_id | Unique identifier of an existing admin devices entry | Required | 
| tag | Tag to append to the admin devices entry | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!bastille-add-device-tag transmitter_id=78:9f:70:7b:62:82 tag=test-tag```

#### Context Example
```
{}
```

#### Human Readable Output

>created

### bastille-remove-device-tag
***
Command to remove tag from an existing device


#### Base Command

`bastille-remove-device-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| transmitter_id | Unique identifier of an existing admin devices entry | Required | 
| tag | Tag to be removed from the admin devices entry | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!bastille-remove-device-tag transmitter_id=78:9f:70:7b:62:82 tag=test-tag```

#### Context Example
```
{}
```

#### Human Readable Output

>updated