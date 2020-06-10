An Integration to Query ICS Data from Nozomi Guardian
This integration was integrated and tested with version 19 of Nozomi_Guardian
## Configure Nozomi_Guardian on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Nozomi_Guardian.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| credentials | Username | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### guardian-search
***
Nozomi Guardian Query


#### Base Command

`guardian-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query to search with, example "assets \| where vendor match Dell Inc." | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NozomiGuardian.Queries | String | Query Results | 


#### Command Example
```!guardian-search query=`links | where from match 192.168.10.2 | where protocol match ssh````

#### Context Example
```
{
    "NozomiGuardian": {
        "Queries": [
            {
                "QueryResults": [
                    [
                        {
                            "_can": {
                                "captured_urls": false,
                                "link_events": true,
                                "trace_requests": true
                            },
                            "_checks": {},
                            "_ports": [
                                {
                                    "tcp": "22"
                                }
                            ],
                            "active_checks": [],
                            "alerts": "0",
                            "bpf_filter": "ip host 192.168.10.2 and ip host 192.168.20.20 and (tcp port 22)",
                            "first_activity_time": "1580077950812",
                            "from": "192.168.10.2",
                            "function_codes": [],
                            "has_confirmed_data": true,
                            "is_broadcast": false,
                            "is_fully_learned": true,
                            "is_learned": true,
                            "last_activity_time": "1582666859649",
                            "last_handshake_time": "1582666139562",
                            "last_trace_request_time": "0",
                            "protocol": "ssh",
                            "tcp_connection_attempts.last_15m": "0",
                            "tcp_connection_attempts.last_30m": "0",
                            "tcp_connection_attempts.last_5m": "0",
                            "tcp_connection_attempts.total": "6",
                            "tcp_handshaked_connections.last_15m": "0",
                            "tcp_handshaked_connections.last_30m": "0",
                            "tcp_handshaked_connections.last_5m": "0",
                            "tcp_handshaked_connections.total": "6",
                            "tcp_retransmission.bytes": "6420",
                            "tcp_retransmission.last_15m_bytes": "0",
                            "tcp_retransmission.last_30m_bytes": "0",
                            "tcp_retransmission.last_5m_bytes": "0",
                            "tcp_retransmission.packets": "42",
                            "tcp_retransmission.percent": 0.17246539006459663,
                            "throughput_speed": 0,
                            "to": "192.168.20.20",
                            "transferred.avg_packet_bytes": 107.68277936879863,
                            "transferred.biggest_packet_bytes": "1514",
                            "transferred.bytes": "3722486",
                            "transferred.last_15m_bytes": "0",
                            "transferred.last_30m_bytes": "0",
                            "transferred.last_5m_bytes": "0",
                            "transferred.packets": "34569",
                            "transferred.smallest_packet_bytes": "66",
                            "transport_protocols": [
                                "tcp"
                            ]
                        }
                    ]
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Nozomi Guardian - Results for the Search Query
>|QueryResults|
>|---|
>| [{'from': '192.168.10.2', 'to': '192.168.20.20', 'protocol': 'ssh', 'first_activity_time': '1580077950812', 'last_activity_time': '1582666859649', 'last_handshake_time': '1582666139562', 'transport_protocols': ['tcp'], 'tcp_handshaked_connections.total': '6', 'tcp_handshaked_connections.last_5m': '0', 'tcp_handshaked_connections.last_15m': '0', 'tcp_handshaked_connections.last_30m': '0', 'tcp_connection_attempts.total': '6', 'tcp_connection_attempts.last_5m': '0', 'tcp_connection_attempts.last_15m': '0', 'tcp_connection_attempts.last_30m': '0', 'transferred.packets': '34569', 'transferred.bytes': '3722486', 'transferred.last_5m_bytes': '0', 'transferred.last_15m_bytes': '0', 'transferred.last_30m_bytes': '0', 'transferred.smallest_packet_bytes': '66', 'transferred.biggest_packet_bytes': '1514', 'transferred.avg_packet_bytes': 107.68277936879863, 'tcp_retransmission.percent': 0.17246539006459663, 'tcp_retransmission.packets': '42', 'tcp_retransmission.bytes': '6420', 'tcp_retransmission.last_5m_bytes': '0', 'tcp_retransmission.last_15m_bytes': '0', 'tcp_retransmission.last_30m_bytes': '0', 'throughput_speed': 0, 'is_learned': True, 'is_fully_learned': True, 'is_broadcast': False, 'has_confirmed_data': True, '_can': {'link_events': True, 'captured_urls': False, 'trace_requests': True}, 'alerts': '0', 'last_trace_request_time': '0', '_ports': [{'tcp': '22'}], 'active_checks': [], '_checks': {}, 'function_codes': [], 'bpf_filter': 'ip host 192.168.10.2 and ip host 192.168.20.20 and (tcp port 22)'}] |


### guardian-list-all-assets
***
List all the assets discovered by Nozomi Guardian


#### Base Command

`guardian-list-all-assets`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NozomiGuardian.Assets | Unknown | Nozomi Guardian Assets | 


#### Command Example
```!guardian-list-all-assets```

#### Context Example
```
{
    "NozomiGuardian": {
        "Assets": [
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.20.110"
                ],
                "MAC": [
                    "00:0c:29:b3:6a:30"
                ],
                "Name": "192.168.20.110",
                "OS": "",
                "Vendor": "VMware, Inc."
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.20.3"
                ],
                "MAC": [
                    "00:0c:29:22:50:26"
                ],
                "Name": "192.168.20.3",
                "OS": "",
                "Vendor": "VMware, Inc."
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.20.102"
                ],
                "MAC": [
                    "00:0c:29:58:09:f9"
                ],
                "Name": "192.168.20.102",
                "OS": "Windows 7",
                "Vendor": "VMware, Inc."
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.20.20"
                ],
                "MAC": [
                    "00:0c:29:92:ec:2a"
                ],
                "Name": "demisto.ayman.local",
                "OS": "GNU/Linux",
                "Vendor": "VMware, Inc."
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.20.240"
                ],
                "MAC": [
                    "b8:2a:72:d4:2d:f1"
                ],
                "Name": "192.168.20.240",
                "OS": "",
                "Vendor": "Dell Inc."
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.20.1"
                ],
                "MAC": [
                    "b0:b2:dc:39:7b:95"
                ],
                "Name": "192.168.20.1",
                "OS": "",
                "Vendor": "Zyxel Communications Corporation"
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.20.2"
                ],
                "MAC": [
                    "00:0c:29:22:50:44"
                ],
                "Name": "192.168.20.2",
                "OS": "",
                "Vendor": "VMware, Inc."
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.1.10"
                ],
                "MAC": [
                    "00:0c:29:58:09:f9"
                ],
                "Name": "192.168.1.10",
                "OS": "",
                "Vendor": ""
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "172.17.0.14"
                ],
                "MAC": [
                    "00:0c:29:92:ec:2a"
                ],
                "Name": "172.17.0.14",
                "OS": "",
                "Vendor": ""
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.10.2"
                ],
                "MAC": [
                    "b0:b2:dc:39:7b:95"
                ],
                "Name": "192.168.10.2",
                "OS": "",
                "Vendor": ""
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.220.103"
                ],
                "MAC": [
                    "00:0c:29:22:50:44"
                ],
                "Name": "192.168.220.103",
                "OS": "Windows 10",
                "Vendor": ""
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.40.106"
                ],
                "MAC": [
                    "b0:b2:dc:39:7b:95"
                ],
                "Name": "192.168.40.106",
                "OS": "",
                "Vendor": ""
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.220.102"
                ],
                "MAC": [
                    "00:0c:29:22:50:44"
                ],
                "Name": "192.168.220.102",
                "OS": "Windows 7",
                "Vendor": ""
            },
            {
                "CaptureDevice": "em1",
                "IP": [
                    "192.168.20.100"
                ],
                "MAC": [
                    "00:0c:29:ca:b2:02"
                ],
                "Name": "dc.lab.home",
                "OS": "",
                "Vendor": "VMware, Inc."
            }
        ]
    }
}
```

#### Human Readable Output

>### Nozomi Guardian - Results for the Search Query
>|CaptureDevice|IP|MAC|Name|OS|Vendor|
>|---|---|---|---|---|---|
>| em1 | 192.168.20.110 | 00:0c:29:b3:6a:30 | 192.168.20.110 |  | VMware, Inc. |
>| em1 | 192.168.20.3 | 00:0c:29:22:50:26 | 192.168.20.3 |  | VMware, Inc. |
>| em1 | 192.168.20.102 | 00:0c:29:58:09:f9 | 192.168.20.102 | Windows 7 | VMware, Inc. |
>| em1 | 192.168.20.20 | 00:0c:29:92:ec:2a | demisto.ayman.local | GNU/Linux | VMware, Inc. |
>| em1 | 192.168.20.240 | b8:2a:72:d4:2d:f1 | 192.168.20.240 |  | Dell Inc. |
>| em1 | 192.168.20.1 | b0:b2:dc:39:7b:95 | 192.168.20.1 |  | Zyxel Communications Corporation |
>| em1 | 192.168.20.2 | 00:0c:29:22:50:44 | 192.168.20.2 |  | VMware, Inc. |
>| em1 | 192.168.1.10 | 00:0c:29:58:09:f9 | 192.168.1.10 |  |  |
>| em1 | 172.17.0.14 | 00:0c:29:92:ec:2a | 172.17.0.14 |  |  |
>| em1 | 192.168.10.2 | b0:b2:dc:39:7b:95 | 192.168.10.2 |  |  |
>| em1 | 192.168.220.103 | 00:0c:29:22:50:44 | 192.168.220.103 | Windows 10 |  |
>| em1 | 192.168.40.106 | b0:b2:dc:39:7b:95 | 192.168.40.106 |  |  |
>| em1 | 192.168.220.102 | 00:0c:29:22:50:44 | 192.168.220.102 | Windows 7 |  |
>| em1 | 192.168.20.100 | 00:0c:29:ca:b2:02 | dc.lab.home |  | VMware, Inc. |


### guardian-find-ip-by-mac
***
Find the IP of a MAC address


#### Base Command

`guardian-find-ip-by-mac`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mac | The MAC address value | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NozomiGuardian.Mappings | Unknown | IP to MAC Address Mappings | 


#### Command Example
```!guardian-find-ip-by-mac mac=00:0c:29:22:50:26```

#### Context Example
```
{
    "NozomiGuardian": {
        "Mappings": [
            {
                "IP": [
                    "192.168.20.3"
                ],
                "MAC": "00:0c:29:22:50:26"
            }
        ]
    }
}
```

#### Human Readable Output

>### Nozomi Guardian - Results for the Search Query
>|IP|MAC|
>|---|---|
>| 192.168.20.3 | 00:0c:29:22:50:26 |

