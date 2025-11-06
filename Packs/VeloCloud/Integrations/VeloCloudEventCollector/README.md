Collects events from the VeloCloud API.
This integration was integrated and tested with VeloCloud as of 2025-10-06.

## Configure VeloCloud Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Enterprise ID |  | True |
| API Key | API key for authenticating with Arista VeloCloud | False |
| First fetch timestamp |  | False |
| Limit of events per fetch |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### velocloud-get-events

***
Get events fro`m Arista VeloCloud

#### Base Command

`velocloud-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | Start time for event query in ISO format or human-readable format (e.g., '3 days ago'). Default is 1 day ago. | Optional |
| end_time | End time for event query in ISO format or human-readable format (e.g., 'now'). Default is now. | Optional |
| limit | Maximum number of events to retrieve. Default is 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VeloCloud.Event.logicalId | String | Event logical ID |
| VeloCloud.Event.category | String | Event category |
| VeloCloud.Event.event | String | Event type |
| VeloCloud.Event.severity | String | Event severity |
| VeloCloud.Event.message | String | Event message |
| VeloCloud.Event.detail | String | Event details, usually in JSON string format |
| VeloCloud.Event.eventTime | Date | Event timestamp |
| VeloCloud.Event.created | Date | Event creation time |
| VeloCloud.Event.edgeName | String | Name of the edge |
| VeloCloud.Event.enterpriseName | String | Name of the enterprise |
| VeloCloud.Event.enterpriseUsername | String | Username associated with the enterprise |
| VeloCloud.Event.segmentName | String | Name of the network segment |

#### Command Example

```!velocloud-get-events limit=1```

```json
{
    "VeloCloud": {
        "Event": {
            "category": "EDGE",
            "created": "2025-11-03T21:02:36.000Z",
            "detail": "{\"last_request_time\":0,\"client_mac\":\"03:11:22:33:44:55\",\"client_ipv4addr\":\"192.168.1.1\",\"hostname\":\"nexusquantum7\",\"os_type\":800,\"os_class\":1,\"os_class_name\":\"OTHER\",\"os_version\":\"\",\"device_type\":\"\",\"os_description\":\"Xerox Printer\",\"dhcp_param_list\":\"6,3,1,15,66,67,13,44,12\",\"segment_id\":0,\"edgeSerialNumber\":\"K7M9N2P5Q8R1\"}",
            "edgeName": "radiancecdnc43",
            "enterpriseName": "ACME Co.",
            "enterpriseUsername": "",
            "event": "EDGE_NEW_DEVICE",
            "eventTime": "2025-11-03T21:02:16.000Z",
            "logicalId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "message": "New or updated client device 03:11:22:33:44:55, ip 192.168.1.1, segId 0, hostname nexusquantum7, os Xerox Printer",
            "segmentName": "",
            "severity": "NOTICE"
        }
    }
}
```
