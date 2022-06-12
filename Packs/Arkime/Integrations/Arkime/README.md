Arkime (formerly Moloch) is a large scale, open source, indexed packet capture and search tool.
This integration was integrated and tested with version 1.0.0 of Arkime

## Configure Arkime on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Arkime.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Username | True |
    | Password | True |
    | Use system proxy | False |
    | Trust any certificate | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### arkime-connection-list
***
Gets a list of nodes and links and returns them to the client.


#### Base Command

`arkime-connection-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_field | The source database field name. | Optional | 
| destination_field | The destination database field name. | Optional | 
| date | The number of hours of data to return (-1 means all data). Defaults to 1. | Optional | 
| expression | The search expression string. | Optional | 
| start_time | If the date parameter is not set, this is the start time of data to return. Format is seconds since Unix EPOC. | Optional | 
| stop_time | If the date parameter is not set, this is the stop time of data to return. Format is seconds since Unix EPOC. | Optional | 
| view | The view name to apply before the expression. | Optional | 
| order | Comma separated list of db field names to sort on. Data is sorted in order of the list supplied. Optionally can be followed by :asc or :desc for ascending or descending sorting. | Optional | 
| fields | Comma separated list of db field names to return. Default is ipProtocol, rootId, totDataBytes, srcDataBytes, dstDataBytes, firstPacket, lastPacket, srcIp, srcPort, dstIp, dstPort, totPackets, srcPackets, dstPackets, totBytes, srcBytes, dstBytes, node, http.uri, srcGEO, dstGEO, email.subject, email.src, email.dst, email.filename, dns.host, cert, irc.channel, http.xffGEO. | Optional | 
| bounding | "last"	Query sessions based on different aspects of a session’s time. Options include: ‘first’ - First Packet: the timestamp of the first packet received for the session. ‘last’ - Last Packet: The timestamp of the last packet received for the session. ‘both’ - Bounded: Both the first and last packet timestamps for the session must be inside the time window. ‘either’ - Session Overlaps: The timestamp of the first packet must be before the end of the time window AND the timestamp of the last packet must be after the start of the time window. ‘database’ - Database: The timestamp the session was written to the database. This can be up to several minutes AFTER the last packet was received. | Optional | 
| strictly | When set the entire session must be inside the date range to be observed, otherwise if it overlaps it is displayed. Overwrites the bounding parameter, sets bonding to ‘both’. | Optional | 
| baseline_date | The baseline date range to compare connections against. Default is 0, disabled. Options include: 1x - 1 times query range. 2x - 2 times query range. 4x - 4 times query range. 6x - 6 times query range. 8x - 8 times query range. 10x - 10 times query range. 1 - 1 hour. 6 - 6 hours. 24 - 1 day. 48 - 2 days. 72 - 3 days. 168 - 1 week. 336 - 2 weeks. 720 - 1 month. 1440 - 2 months. 4380 - 6 months. 8760 - 1 year. | Optional | 
| baseline_view | Which connections to display when a baseline date range is applied. Default is all. Options include: ‘all’ - All Nodes: all nodes are visible. ‘actual’ - Actual Nodes: nodes present in the “current” timeframe query results are visible. ‘actualold’ - Baseline Nodes: nodes present in the “baseline” timeframe query results are visible. ‘new’ - New Nodes Only: nodes present in the “current” but NOT the “baseline” timeframe are visible. ‘old’ - Baseline Nodes Only: nodes present in the “baseline” but NOT the “current” timeframe are visible. | Optional | 
| limit | The number of items to return. Defaults to 100, Max is 2,000,000. | Optional | 
| page_number | The page at which to start. The default is 0. | Optional | 
| page_size | Page size. Minimum page size is 1, maximum is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.Connection.nodes.id | String | The source ip. | 
| Arkime.Connection.nodes.cnt | Number | Number of appearances. | 
| Arkime.Connection.nodes.sessions | Number | Number of sessions | 
| Arkime.Connection.nodes.inresult | Number | The inresult. | 
| Arkime.Connection.nodes.type | Number | Connection type. | 
| Arkime.Connection.nodes.network.bytes | Number | The bytes. | 
| Arkime.Connection.nodes.totDataBytes | Number | The totDataBytes. | 
| Arkime.Connection.nodes.network.packets | Number | The packets. | 
| Arkime.Connection.nodes.node | String | The node. | 
| Arkime.Connection.nodes.pos | Number | The pos. | 
| Arkime.Connection.links.value | Number | The value. | 
| Arkime.Connection.links.source | Number | The source. | 
| Arkime.Connection.links.target | Number | The target. | 
| Arkime.Connection.links.network.bytes | Number | The bytes. | 
| Arkime.Connection.links.totDataBytes | Number | The totDataBytes. | 
| Arkime.Connection.links.network.packets | Number | The packets. | 
| Arkime.Connection.links.node | String | The node. | 
| Arkime.Connection.recordsFiltered | Number | The number of history items returned in this result. | 

#### Command example
```!arkime-connection-list baseline_date=720 start_time=1648817940 stop_time=1649595540```
#### Context Example
```json
{
    "Arkime": {
        "Connection": {
            "links": [
                {
                    "network.bytes": 96415,
                    "network.packets": 806,
                    "node": [
                        "localhost"
                    ],
                    "source": 0,
                    "target": 1,
                    "totDataBytes": 0,
                    "value": 2
                },
                {
                    "network.bytes": 1258,
                    "network.packets": 17,
                    "node": [
                        "localhost"
                    ],
                    "source": 2,
                    "target": 3,
                    "totDataBytes": 0,
                    "value": 5
                },
                {
                    "network.bytes": 8819968,
                    "network.packets": 40000,
                    "node": [
                        "localhost"
                    ],
                    "source": 4,
                    "target": 5,
                    "totDataBytes": 0,
                    "value": 4
                },
                {
                    "network.bytes": 45605888,
                    "network.packets": 290000,
                    "node": [
                        "localhost"
                    ],
                    "source": 6,
                    "target": 7,
                    "totDataBytes": 0,
                    "value": 29
                },
                {
                    "network.bytes": 5445,
                    "network.packets": 39,
                    "node": [
                        "localhost"
                    ],
                    "source": 4,
                    "target": 8,
                    "totDataBytes": 0,
                    "value": 1
                },
                {
                    "network.bytes": 5421,
                    "network.packets": 39,
                    "node": [
                        "localhost"
                    ],
                    "source": 4,
                    "target": 9,
                    "totDataBytes": 0,
                    "value": 1
                },
                {
                    "network.bytes": 5447,
                    "network.packets": 39,
                    "node": [
                        "localhost"
                    ],
                    "source": 4,
                    "target": 10,
                    "totDataBytes": 0,
                    "value": 1
                },
                {
                    "network.bytes": 5445,
                    "network.packets": 39,
                    "node": [
                        "localhost"
                    ],
                    "source": 4,
                    "target": 11,
                    "totDataBytes": 0,
                    "value": 1
                },
                {
                    "network.bytes": 812,
                    "network.packets": 8,
                    "node": [
                        "localhost"
                    ],
                    "source": 12,
                    "target": 13,
                    "totDataBytes": 476,
                    "value": 4
                },
                {
                    "network.bytes": 240,
                    "network.packets": 4,
                    "node": [
                        "localhost"
                    ],
                    "source": 14,
                    "target": 15,
                    "totDataBytes": 0,
                    "value": 1
                },
                {
                    "network.bytes": 331422,
                    "network.packets": 1460,
                    "node": [
                        "localhost"
                    ],
                    "source": 16,
                    "target": 17,
                    "totDataBytes": 0,
                    "value": 2
                },
                {
                    "network.bytes": 74250,
                    "network.packets": 900,
                    "node": [
                        "localhost"
                    ],
                    "source": 14,
                    "target": 4,
                    "totDataBytes": 0,
                    "value": 1
                },
                {
                    "network.bytes": 73705,
                    "network.packets": 164,
                    "node": [
                        "localhost"
                    ],
                    "source": 18,
                    "target": 19,
                    "totDataBytes": 0,
                    "value": 2
                },
                {
                    "network.bytes": 860,
                    "network.packets": 8,
                    "node": [
                        "localhost"
                    ],
                    "source": 16,
                    "target": 13,
                    "totDataBytes": 524,
                    "value": 4
                },
                {
                    "network.bytes": 358221,
                    "network.packets": 4037,
                    "node": [
                        "localhost"
                    ],
                    "source": 19,
                    "target": 18,
                    "totDataBytes": 0,
                    "value": 2
                },
                {
                    "network.bytes": 92,
                    "network.packets": 1,
                    "node": [
                        "localhost"
                    ],
                    "source": 20,
                    "target": 21,
                    "totDataBytes": 50,
                    "value": 1
                },
                {
                    "network.bytes": 75940,
                    "network.packets": 373,
                    "node": [
                        "localhost"
                    ],
                    "source": 4,
                    "target": 22,
                    "totDataBytes": 0,
                    "value": 1
                },
                {
                    "network.bytes": 71428,
                    "network.packets": 424,
                    "node": [
                        "localhost"
                    ],
                    "source": 22,
                    "target": 23,
                    "totDataBytes": 0,
                    "value": 1
                },
                {
                    "network.bytes": 7962,
                    "network.packets": 27,
                    "node": [
                        "localhost"
                    ],
                    "source": 4,
                    "target": 23,
                    "totDataBytes": 6408,
                    "value": 2
                },
                {
                    "network.bytes": 7275,
                    "network.packets": 50,
                    "node": [
                        "localhost"
                    ],
                    "source": 24,
                    "target": 25,
                    "totDataBytes": 0,
                    "value": 1
                },
                {
                    "network.bytes": 34010,
                    "network.packets": 57,
                    "node": [
                        "localhost"
                    ],
                    "source": 26,
                    "target": 27,
                    "totDataBytes": 30228,
                    "value": 2
                },
                {
                    "network.bytes": 2300,
                    "network.packets": 20,
                    "node": [
                        "localhost"
                    ],
                    "source": 26,
                    "target": 13,
                    "totDataBytes": 1460,
                    "value": 9
                },
                {
                    "network.bytes": 258,
                    "network.packets": 2,
                    "node": [
                        "localhost"
                    ],
                    "source": 28,
                    "target": 13,
                    "totDataBytes": 174,
                    "value": 1
                },
                {
                    "network.bytes": 11062,
                    "network.packets": 23,
                    "node": [
                        "localhost"
                    ],
                    "source": 28,
                    "target": 29,
                    "totDataBytes": 9742,
                    "value": 1
                },
                {
                    "network.bytes": 860,
                    "network.packets": 8,
                    "node": [
                        "localhost"
                    ],
                    "source": 21,
                    "target": 13,
                    "totDataBytes": 524,
                    "value": 4
                },
                {
                    "network.bytes": 21392,
                    "network.packets": 91,
                    "node": [
                        "localhost"
                    ],
                    "source": 30,
                    "target": 17,
                    "totDataBytes": 0,
                    "value": 1
                },
                {
                    "network.bytes": 11211,
                    "network.packets": 32,
                    "node": [
                        "localhost"
                    ],
                    "source": 26,
                    "target": 31,
                    "totDataBytes": 9064,
                    "value": 2
                },
                {
                    "network.bytes": 1702,
                    "network.packets": 13,
                    "node": [
                        "localhost"
                    ],
                    "source": 32,
                    "target": 33,
                    "totDataBytes": 0,
                    "value": 1
                },
                {
                    "network.bytes": 143171,
                    "network.packets": 987,
                    "node": [
                        "localhost"
                    ],
                    "source": 34,
                    "target": 1,
                    "totDataBytes": 0,
                    "value": 2
                },
                {
                    "network.bytes": 48216,
                    "network.packets": 492,
                    "node": [
                        "localhost"
                    ],
                    "source": 35,
                    "target": 36,
                    "totDataBytes": 31488,
                    "value": 1
                },
                {
                    "network.bytes": 1664,
                    "network.packets": 16,
                    "node": [
                        "localhost"
                    ],
                    "source": 17,
                    "target": 13,
                    "totDataBytes": 992,
                    "value": 8
                },
                {
                    "network.bytes": 90,
                    "network.packets": 1,
                    "node": [
                        "localhost"
                    ],
                    "source": 37,
                    "target": 38,
                    "totDataBytes": 48,
                    "value": 1
                },
                {
                    "network.bytes": 125504,
                    "network.packets": 312,
                    "node": [
                        "localhost"
                    ],
                    "source": 21,
                    "target": 39,
                    "totDataBytes": 0,
                    "value": 1
                }
            ],
            "nodes": [
                {
                    "cnt": 1,
                    "id": "192.168.1.166",
                    "inresult": 1,
                    "network.bytes": 96415,
                    "network.packets": 806,
                    "node": [
                        "localhost"
                    ],
                    "pos": 0,
                    "sessions": 2,
                    "totDataBytes": 0,
                    "type": 1
                },
                {
                    "cnt": 2,
                    "id": "192.168.1.164",
                    "inresult": 1,
                    "network.bytes": 239586,
                    "network.packets": 1793,
                    "node": [
                        "localhost"
                    ],
                    "pos": 1,
                    "sessions": 4,
                    "totDataBytes": 0,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.28",
                    "inresult": 1,
                    "network.bytes": 1258,
                    "network.packets": 17,
                    "node": [
                        "localhost"
                    ],
                    "pos": 2,
                    "sessions": 5,
                    "totDataBytes": 0,
                    "type": 1
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.37",
                    "inresult": 1,
                    "network.bytes": 1258,
                    "network.packets": 17,
                    "node": [
                        "localhost"
                    ],
                    "pos": 3,
                    "sessions": 5,
                    "totDataBytes": 0,
                    "type": 2
                },
                {
                    "cnt": 8,
                    "id": "192.168.1.8",
                    "inresult": 1,
                    "network.bytes": 8999878,
                    "network.packets": 41456,
                    "node": [
                        "localhost"
                    ],
                    "pos": 4,
                    "sessions": 12,
                    "totDataBytes": 6408,
                    "type": 3
                },
                {
                    "cnt": 1,
                    "id": "10.196.102.220",
                    "inresult": 1,
                    "network.bytes": 8819968,
                    "network.packets": 40000,
                    "node": [
                        "localhost"
                    ],
                    "pos": 5,
                    "sessions": 4,
                    "totDataBytes": 0,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.130",
                    "inresult": 1,
                    "network.bytes": 45605888,
                    "network.packets": 290000,
                    "node": [
                        "localhost"
                    ],
                    "pos": 6,
                    "sessions": 29,
                    "totDataBytes": 0,
                    "type": 1
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.88",
                    "inresult": 1,
                    "network.bytes": 45605888,
                    "network.packets": 290000,
                    "node": [
                        "localhost"
                    ],
                    "pos": 7,
                    "sessions": 29,
                    "totDataBytes": 0,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "20.54.37.64",
                    "inresult": 1,
                    "network.bytes": 5445,
                    "network.packets": 39,
                    "node": [
                        "localhost"
                    ],
                    "pos": 8,
                    "sessions": 1,
                    "totDataBytes": 0,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "20.199.120.85",
                    "inresult": 1,
                    "network.bytes": 5421,
                    "network.packets": 39,
                    "node": [
                        "localhost"
                    ],
                    "pos": 9,
                    "sessions": 1,
                    "totDataBytes": 0,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "20.199.120.151",
                    "inresult": 1,
                    "network.bytes": 5447,
                    "network.packets": 39,
                    "node": [
                        "localhost"
                    ],
                    "pos": 10,
                    "sessions": 1,
                    "totDataBytes": 0,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "20.199.120.182",
                    "inresult": 1,
                    "network.bytes": 5445,
                    "network.packets": 39,
                    "node": [
                        "localhost"
                    ],
                    "pos": 11,
                    "sessions": 1,
                    "totDataBytes": 0,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.100",
                    "inresult": 1,
                    "network.bytes": 812,
                    "network.packets": 8,
                    "node": [
                        "localhost"
                    ],
                    "pos": 12,
                    "sessions": 4,
                    "totDataBytes": 476,
                    "type": 1
                },
                {
                    "cnt": 6,
                    "id": "8.8.8.8",
                    "inresult": 1,
                    "network.bytes": 6754,
                    "network.packets": 62,
                    "node": [
                        "localhost"
                    ],
                    "pos": 13,
                    "sessions": 30,
                    "totDataBytes": 4150,
                    "type": 2
                },
                {
                    "cnt": 2,
                    "id": "192.168.1.11",
                    "inresult": 1,
                    "network.bytes": 74490,
                    "network.packets": 904,
                    "node": [
                        "localhost"
                    ],
                    "pos": 14,
                    "sessions": 2,
                    "totDataBytes": 0,
                    "type": 1
                },
                {
                    "cnt": 1,
                    "id": "20.93.58.141",
                    "inresult": 1,
                    "network.bytes": 240,
                    "network.packets": 4,
                    "node": [
                        "localhost"
                    ],
                    "pos": 15,
                    "sessions": 1,
                    "totDataBytes": 0,
                    "type": 2
                },
                {
                    "cnt": 2,
                    "id": "192.168.1.16",
                    "inresult": 1,
                    "network.bytes": 332282,
                    "network.packets": 1468,
                    "node": [
                        "localhost"
                    ],
                    "pos": 16,
                    "sessions": 6,
                    "totDataBytes": 524,
                    "type": 1
                },
                {
                    "cnt": 3,
                    "id": "192.168.1.71",
                    "inresult": 1,
                    "network.bytes": 354478,
                    "network.packets": 1567,
                    "node": [
                        "localhost"
                    ],
                    "pos": 17,
                    "sessions": 11,
                    "totDataBytes": 992,
                    "type": 3
                },
                {
                    "cnt": 2,
                    "id": "104.155.131.72",
                    "inresult": 1,
                    "network.bytes": 431926,
                    "network.packets": 4201,
                    "node": [
                        "localhost"
                    ],
                    "pos": 18,
                    "sessions": 4,
                    "totDataBytes": 0,
                    "type": 3
                },
                {
                    "cnt": 2,
                    "id": "192.168.1.111",
                    "inresult": 1,
                    "network.bytes": 431926,
                    "network.packets": 4201,
                    "node": [
                        "localhost"
                    ],
                    "pos": 19,
                    "sessions": 4,
                    "totDataBytes": 0,
                    "type": 3
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.212",
                    "inresult": 1,
                    "network.bytes": 92,
                    "network.packets": 1,
                    "node": [
                        "localhost"
                    ],
                    "pos": 20,
                    "sessions": 1,
                    "totDataBytes": 50,
                    "type": 1
                },
                {
                    "cnt": 3,
                    "id": "192.168.1.68",
                    "inresult": 1,
                    "network.bytes": 126456,
                    "network.packets": 321,
                    "node": [
                        "localhost"
                    ],
                    "pos": 21,
                    "sessions": 6,
                    "totDataBytes": 574,
                    "type": 3
                },
                {
                    "cnt": 2,
                    "id": "192.168.1.144",
                    "inresult": 1,
                    "network.bytes": 147368,
                    "network.packets": 797,
                    "node": [
                        "localhost"
                    ],
                    "pos": 22,
                    "sessions": 2,
                    "totDataBytes": 0,
                    "type": 3
                },
                {
                    "cnt": 2,
                    "id": "192.168.1.113",
                    "inresult": 1,
                    "network.bytes": 79390,
                    "network.packets": 451,
                    "node": [
                        "localhost"
                    ],
                    "pos": 23,
                    "sessions": 3,
                    "totDataBytes": 6408,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.102",
                    "inresult": 1,
                    "network.bytes": 7275,
                    "network.packets": 50,
                    "node": [
                        "localhost"
                    ],
                    "pos": 24,
                    "sessions": 1,
                    "totDataBytes": 0,
                    "type": 1
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.156",
                    "inresult": 1,
                    "network.bytes": 7275,
                    "network.packets": 50,
                    "node": [
                        "localhost"
                    ],
                    "pos": 25,
                    "sessions": 1,
                    "totDataBytes": 0,
                    "type": 2
                },
                {
                    "cnt": 3,
                    "id": "192.168.1.26",
                    "inresult": 1,
                    "network.bytes": 47521,
                    "network.packets": 109,
                    "node": [
                        "localhost"
                    ],
                    "pos": 26,
                    "sessions": 13,
                    "totDataBytes": 40752,
                    "type": 1
                },
                {
                    "cnt": 1,
                    "id": "34.69.208.173",
                    "inresult": 1,
                    "network.bytes": 34010,
                    "network.packets": 57,
                    "node": [
                        "localhost"
                    ],
                    "pos": 27,
                    "sessions": 2,
                    "totDataBytes": 30228,
                    "type": 2
                },
                {
                    "cnt": 2,
                    "id": "192.168.1.97",
                    "inresult": 1,
                    "network.bytes": 11320,
                    "network.packets": 25,
                    "node": [
                        "localhost"
                    ],
                    "pos": 28,
                    "sessions": 2,
                    "totDataBytes": 9916,
                    "type": 1
                },
                {
                    "cnt": 1,
                    "id": "34.98.77.231",
                    "inresult": 1,
                    "network.bytes": 11062,
                    "network.packets": 23,
                    "node": [
                        "localhost"
                    ],
                    "pos": 29,
                    "sessions": 1,
                    "totDataBytes": 9742,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.63",
                    "inresult": 1,
                    "network.bytes": 21392,
                    "network.packets": 91,
                    "node": [
                        "localhost"
                    ],
                    "pos": 30,
                    "sessions": 1,
                    "totDataBytes": 0,
                    "type": 1
                },
                {
                    "cnt": 1,
                    "id": "35.247.145.234",
                    "inresult": 1,
                    "network.bytes": 11211,
                    "network.packets": 32,
                    "node": [
                        "localhost"
                    ],
                    "pos": 31,
                    "sessions": 2,
                    "totDataBytes": 9064,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.73",
                    "inresult": 1,
                    "network.bytes": 1702,
                    "network.packets": 13,
                    "node": [
                        "localhost"
                    ],
                    "pos": 32,
                    "sessions": 1,
                    "totDataBytes": 0,
                    "type": 1
                },
                {
                    "cnt": 1,
                    "id": "130.211.8.196",
                    "inresult": 1,
                    "network.bytes": 1702,
                    "network.packets": 13,
                    "node": [
                        "localhost"
                    ],
                    "pos": 33,
                    "sessions": 1,
                    "totDataBytes": 0,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.165",
                    "inresult": 1,
                    "network.bytes": 143171,
                    "network.packets": 987,
                    "node": [
                        "localhost"
                    ],
                    "pos": 34,
                    "sessions": 2,
                    "totDataBytes": 0,
                    "type": 1
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.1",
                    "inresult": 1,
                    "network.bytes": 48216,
                    "network.packets": 492,
                    "node": [
                        "localhost"
                    ],
                    "pos": 35,
                    "sessions": 1,
                    "totDataBytes": 31488,
                    "type": 1
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.121",
                    "inresult": 1,
                    "network.bytes": 48216,
                    "network.packets": 492,
                    "node": [
                        "localhost"
                    ],
                    "pos": 36,
                    "sessions": 1,
                    "totDataBytes": 31488,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.49",
                    "inresult": 1,
                    "network.bytes": 90,
                    "network.packets": 1,
                    "node": [
                        "localhost"
                    ],
                    "pos": 37,
                    "sessions": 1,
                    "totDataBytes": 48,
                    "type": 1
                },
                {
                    "cnt": 1,
                    "id": "169.254.169.123",
                    "inresult": 1,
                    "network.bytes": 90,
                    "network.packets": 1,
                    "node": [
                        "localhost"
                    ],
                    "pos": 38,
                    "sessions": 1,
                    "totDataBytes": 48,
                    "type": 2
                },
                {
                    "cnt": 1,
                    "id": "192.168.1.62",
                    "inresult": 1,
                    "network.bytes": 125504,
                    "network.packets": 312,
                    "node": [
                        "localhost"
                    ],
                    "pos": 39,
                    "sessions": 1,
                    "totDataBytes": 0,
                    "type": 2
                }
            ],
            "recordsFiltered": 3527811
        }
    }
}
```

#### Human Readable Output

>Showing 40 results, limit=100
>### Connection Results:
>|Source IP|Count|Sessions|Node|
>|---|---|---|---|
>| 192.168.1.166 | 1 | 2 | localhost |
>| 192.168.1.164 | 2 | 4 | localhost |
>| 192.168.1.28 | 1 | 5 | localhost |
>| 192.168.1.37 | 1 | 5 | localhost |
>| 192.168.1.8 | 8 | 12 | localhost |
>| 10.196.102.220 | 1 | 4 | localhost |
>| 192.168.1.130 | 1 | 29 | localhost |
>| 192.168.1.88 | 1 | 29 | localhost |
>| 20.54.37.64 | 1 | 1 | localhost |
>| 20.199.120.85 | 1 | 1 | localhost |
>| 20.199.120.151 | 1 | 1 | localhost |
>| 20.199.120.182 | 1 | 1 | localhost |
>| 192.168.1.100 | 1 | 4 | localhost |
>| 8.8.8.8 | 6 | 30 | localhost |
>| 192.168.1.11 | 2 | 2 | localhost |
>| 20.93.58.141 | 1 | 1 | localhost |
>| 192.168.1.16 | 2 | 6 | localhost |
>| 192.168.1.71 | 3 | 11 | localhost |
>| 104.155.131.72 | 2 | 4 | localhost |
>| 192.168.1.111 | 2 | 4 | localhost |
>| 192.168.1.212 | 1 | 1 | localhost |
>| 192.168.1.68 | 3 | 6 | localhost |
>| 192.168.1.144 | 2 | 2 | localhost |
>| 192.168.1.113 | 2 | 3 | localhost |
>| 192.168.1.102 | 1 | 1 | localhost |
>| 192.168.1.156 | 1 | 1 | localhost |
>| 192.168.1.26 | 3 | 13 | localhost |
>| 34.69.208.173 | 1 | 2 | localhost |
>| 192.168.1.97 | 2 | 2 | localhost |
>| 34.98.77.231 | 1 | 1 | localhost |
>| 192.168.1.63 | 1 | 1 | localhost |
>| 35.247.145.234 | 1 | 2 | localhost |
>| 192.168.1.73 | 1 | 1 | localhost |
>| 130.211.8.196 | 1 | 1 | localhost |
>| 192.168.1.165 | 1 | 2 | localhost |
>| 192.168.1.1 | 1 | 1 | localhost |
>| 192.168.1.121 | 1 | 1 | localhost |
>| 192.168.1.49 | 1 | 1 | localhost |
>| 169.254.169.123 | 1 | 1 | localhost |
>| 192.168.1.62 | 1 | 1 | localhost |


### arkime-connection-csv-get
***
Gets a list of nodes and links in csv format and returns them to the client.


#### Base Command

`arkime-connection-csv-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_field | The source database field name. | Optional | 
| destination_field | The destination database field name. | Optional | 
| date | The number of hours of data to return (-1 means all data). Defaults to 1. | Optional | 
| expression | The search expression string. | Optional | 
| start_time | If the date parameter is not set, this is the start time of data to return. Format is seconds since Unix EPOC. | Optional | 
| stop_time | If the date parameter is not set, this is the stop time of data to return. Format is seconds since Unix EPOC. | Optional | 
| view | The view name to apply before the expression. | Optional | 
| order | Comma separated list of db field names to sort on. Data is sorted in order of the list supplied. Optionally can be followed by :asc or :desc for ascending or descending sorting. | Optional | 
| fields | Comma separated list of db field names to return. Default is ipProtocol, rootId, totDataBytes, srcDataBytes, dstDataBytes, firstPacket, lastPacket, srcIp, srcPort, dstIp, dstPort, totPackets, srcPackets, dstPackets, totBytes, srcBytes, dstBytes, node, http.uri, srcGEO, dstGEO, email.subject, email.src, email.dst, email.filename, dns.host, cert, irc.channel, http.xffGEO. | Optional | 
| bounding | Query sessions based on different aspects of a session’s time. Options include: ‘first’ - First Packet: the timestamp of the first packet received for the session. ‘last’ - Last Packet: The timestamp of the last packet received for the session. ‘both’ - Bounded: Both the first and last packet timestamps for the session must be inside the time window. ‘either’ - Session Overlaps: The timestamp of the first packet must be before the end of the time window AND the timestamp of the last packet must be after the start of the time window. ‘database’ - Database: The timestamp the session was written to the database. This can be up to several minutes AFTER the last packet was received. | Optional | 
| strictly | When set the entire session must be inside the date range to be observed, otherwise if it overlaps it is displayed. Overwrites the bounding parameter, sets bonding to ‘both’. | Optional | 
| limit | The number of items to return. Defaults to 100, Max is 2,000,000. | Optional | 
| offset | The entry to start at. Defaults to 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.Connection.InfoFile.Name | String | The file name. | 
| Arkime.Connection.InfoFile.EntryID | String | The ID for locating the file in the War Room. | 
| Arkime.Connection.InfoFile.Size | Number | The size of the file \(in bytes\). | 
| Arkime.Connection.InfoFile.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 
| Arkime.Connection.InfoFile.Extension | String | The file extension. | 
| Arkime.Connection.InfoFile.Info | String | Basic information about the file. | 

#### Command example
```!arkime-connection-csv-get start_time=1648817940 stop_time=1649595540```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "1931@4060e8c8-61bb-4131-8a47-32a7d97a9726",
        "Extension": "csv",
        "Info": "text/csv; charset=utf-8",
        "Name": "connections_list.csv",
        "Size": 1892,
        "Type": "ASCII text, with CRLF line terminators"
    }
}
```

#### Human Readable Output



### arkime-session-pcap-get
***
Retrieve the raw session data in pcap format.


#### Base Command

`arkime-session-pcap-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The list of ids to return. | Required | 
| expression | The search expression string. | Optional | 
| start_time | If the date parameter is not set, this is the start time of data to return. Format is seconds since Unix EPOC. | Optional | 
| stop_time | If the date parameter is not set, this is the stop time of data to return. Format is seconds since Unix EPOC. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.PcapFile.data.node | String | The node. | 
| Arkime.PcapFile.data.num | Number | The number. | 
| Arkime.PcapFile.data.name | String | The name. | 
| Arkime.PcapFile.data.first | Number | The first. | 
| Arkime.PcapFile.data.fileSize | Number | The file size. | 
| Arkime.PcapFile.data.packetSize | Number | The packet size. | 

#### Command example
```!arkime-session-pcap-get ids=220516-QHSdz21pJ_xCtJGoL8mbmyNv```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "1947@4060e8c8-61bb-4131-8a47-32a7d97a9726",
        "Extension": "pcap",
        "Info": "application/vnd.tcpdump.pcap",
        "Name": "raw_session_data.pcap",
        "Size": 0,
        "Type": "empty"
    }
}
```

#### Human Readable Output



### arkime-session-csv-get
***
Gets a list of sessions and returns them as CSV to the client.


#### Base Command

`arkime-session-csv-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date | The number of hours of data to return (-1 means all data). Defaults to 1. | Optional | 
| expression | The search expression string. | Optional | 
| start_time | If the date parameter is not set, this is the start time of data to return. Format is seconds since Unix EPOC. | Optional | 
| stop_time | If the date parameter is not set, this is the stop time of data to return. Format is seconds since Unix EPOC. | Optional | 
| view | The view name to apply before the expression. | Optional | 
| order | Comma separated list of db field names to sort on. Data is sorted in order of the list supplied. Optionally can be followed by :asc or :desc for ascending or descending sorting. | Optional | 
| fields | Comma separated list of db field names to return. Default is ipProtocol, rootId, totDataBytes, srcDataBytes, dstDataBytes, firstPacket, lastPacket, srcIp, srcPort, dstIp, dstPort, totPackets, srcPackets, dstPackets, totBytes, srcBytes, dstBytes, node, http.uri, srcGEO, dstGEO, email.subject, email.src, email.dst, email.filename, dns.host, cert, irc.channel, http.xffGEO. | Optional | 
| bounding | "last"	Query sessions based on different aspects of a session’s time. Options include: ‘first’ - First Packet: the timestamp of the first packet received for the session. ‘last’ - Last Packet: The timestamp of the last packet received for the session. ‘both’ - Bounded: Both the first and last packet timestamps for the session must be inside the time window. ‘either’ - Session Overlaps: The timestamp of the first packet must be before the end of the time window AND the timestamp of the last packet must be after the start of the time window. ‘database’ - Database: The timestamp the session was written to the database. This can be up to several minutes AFTER the last packet was received. | Optional | 
| strictly | When set the entire session must be inside the date range to be observed, otherwise if it overlaps it is displayed. Overwrites the bounding parameter, sets bonding to ‘both’. | Optional | 
| limit | The number of items to return. Defaults to 100, Max is 2,000,000. | Optional | 
| offset | The entry to start at. Defaults to 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.Session.InfoFile.Name | String | The file name. | 
| Arkime.Session.InfoFile.EntryID | String | The ID for locating the file in the War Room. | 
| Arkime.Session.InfoFile.Size | Number | The size of the file \(in bytes\). | 
| Arkime.Session.InfoFile.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 
| Arkime.Session.InfoFile.Extension | String | The file extension. | 
| Arkime.Session.InfoFile.Info | String | Basic information about the file. | 

#### Command example
```!arkime-session-csv-get start_time=1650190238 stop_time=1650363038```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "1943@4060e8c8-61bb-4131-8a47-32a7d97a9726",
        "Extension": "csv",
        "Info": "text/csv; charset=utf-8",
        "Name": "sessions_list.csv",
        "Size": 9840,
        "Type": "CSV text"
    }
}
```

#### Human Readable Output



### arkime-session-list
***
Gets a list of sessions and returns them to the client.


#### Base Command

`arkime-session-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date | The number of hours of data to return (-1 means all data). Defaults to 1. | Optional | 
| expression | The search expression string. | Optional | 
| start_time | If the date parameter is not set, this is the start time of data to return. Format is seconds since Unix EPOC. | Optional | 
| stop_time | If the date parameter is not set, this is the stop time of data to return. Format is seconds since Unix EPOC. | Optional | 
| view | The view name to apply before the expression. | Optional | 
| order | Comma separated list of db field names to sort on. Data is sorted in order of the list supplied. Optionally can be followed by :asc or :desc for ascending or descending sorting. | Optional | 
| fields | Comma separated list of db field names to return. Default is ipProtocol, rootId, totDataBytes, srcDataBytes, dstDataBytes, firstPacket, lastPacket, srcIp, srcPort, dstIp, dstPort, totPackets, srcPackets, dstPackets, totBytes, srcBytes, dstBytes, node, http.uri, srcGEO, dstGEO, email.subject, email.src, email.dst, email.filename, dns.host, cert, irc.channel, http.xffGEO. | Optional | 
| bounding | "last"	Query sessions based on different aspects of a session’s time. Options include: ‘first’ - First Packet: the timestamp of the first packet received for the session. ‘last’ - Last Packet: The timestamp of the last packet received for the session. ‘both’ - Bounded: Both the first and last packet timestamps for the session must be inside the time window. ‘either’ - Session Overlaps: The timestamp of the first packet must be before the end of the time window AND the timestamp of the last packet must be after the start of the time window. ‘database’ - Database: The timestamp the session was written to the database. This can be up to several minutes AFTER the last packet was received. | Optional | 
| strictly | When set the entire session must be inside the date range to be observed, otherwise if it overlaps it is displayed. Overwrites the bounding parameter, sets bonding to ‘both’. | Optional | 
| limit | The number of items to return. Defaults to 100, Max is 2,000,000. | Optional | 
| page_number | The page at which to start. The default is 0. | Optional | 
| page_size | Page size. Minimum page size is 1, maximum is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.Session.data.firstPacket | Date | The first packet. | 
| Arkime.Session.data.rootId | String | The root Id. | 
| Arkime.Session.data.totDataBytes | Number | The totDataBytes. | 
| Arkime.Session.data.ipProtocol | Number | The IP Protocol. | 
| Arkime.Session.data.node | String | The node. | 
| Arkime.Session.data.lastPacket | Date | The last packet. | 
| Arkime.Session.data.source.packets | Number | The source packets. | 
| Arkime.Session.data.source.port | Number | The source port. | 
| Arkime.Session.data.source.ip | String | The source ip. | 
| Arkime.Session.data.source.bytes | Number | The source bytes. | 
| Arkime.Session.data.destination.port | Number | The destination port. | 
| Arkime.Session.data.destination.ip | String | The destination ip. | 
| Arkime.Session.data.destination.packets | Number | The destination packets | 
| Arkime.Session.data.destination.bytes | Number | The destination bytes. | 
| Arkime.Session.data.client.bytes | Number | The client bytes. | 
| Arkime.Session.data.server.bytes | Number | The server bytes. | 
| Arkime.Session.data.network.packets | Number | The network packets. | 
| Arkime.Session.data.network.bytes | Number | The network bytes. | 
| Arkime.Session.data.id | String | The data id. | 
| Arkime.Session.graph.xmin | Date | The graph xmin. | 
| Arkime.Session.graph.xmax | Date | The graph xmax. | 
| Arkime.Session.graph.interval | Number | The graph interval. | 
| Arkime.Session.graph.sessionsTotal | Number | The graph sessions total. | 
| Arkime.Session.graph.network.packetsTotal | Number | The network packets total. | 
| Arkime.Session.graph.network.bytesTotal | Number | The network bytes total. | 
| Arkime.Session.graph.totDataBytesTotal | Number | The totDataBytesTotal. | 
| Arkime.Session.recordsTotal | Number | The total number of history results stored. | 
| Arkime.Session.recordsFiltered | Number | The number of history items returned in this result. | 

#### Command example
```!arkime-session-list start_time=1650190238 stop_time=1650363038```
#### Context Example
```json
{
    "Arkime": {
        "Session": {
            "data": [
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 985952,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5110,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7OpiE4Pi1PFaRqu8lztuA6",
                    "ipProtocol": 6,
                    "lastPacket": 1650190531644,
                    "network": {
                        "bytes": 1701336,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 715384,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4890,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 702918,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5057,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5Kx3oHIahAPJJVD8QwphkQ",
                    "ipProtocol": 6,
                    "lastPacket": 1650190579920,
                    "network": {
                        "bytes": 1424580,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 721662,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4943,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 711734,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5055,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6l6qOUggpPvrAj-lbNmjtM",
                    "ipProtocol": 6,
                    "lastPacket": 1650190299352,
                    "network": {
                        "bytes": 1436152,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 724418,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4945,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 872282,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5075,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4c2n50c2ZCOK4EiLnVhN5p",
                    "ipProtocol": 6,
                    "lastPacket": 1650190344424,
                    "network": {
                        "bytes": 1594840,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 722558,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4925,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 813638,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5077,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4k-mSg3xtO349fiRm4suHR",
                    "ipProtocol": 6,
                    "lastPacket": 1650190251081,
                    "network": {
                        "bytes": 1534972,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 721334,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4923,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 808682,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5079,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg58S89EQFFMCoqx9f_zNGIz",
                    "ipProtocol": 6,
                    "lastPacket": 1650190627890,
                    "network": {
                        "bytes": 1521788,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 713106,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4921,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 705278,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5057,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7x9iWf3JhHVp7Z6Uok_93o",
                    "ipProtocol": 6,
                    "lastPacket": 1650190392664,
                    "network": {
                        "bytes": 1431192,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 725914,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4943,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 705736,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5058,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4gqw72t1hEK5Dz93cJzwkp",
                    "ipProtocol": 6,
                    "lastPacket": 1650190674410,
                    "network": {
                        "bytes": 1430080,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 724344,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4942,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 712768,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5058,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7GdPzn9vpJx7RbGSDR88Ko",
                    "ipProtocol": 6,
                    "lastPacket": 1650190486441,
                    "network": {
                        "bytes": 1438232,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 725464,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4942,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 810362,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5079,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6Sm6ZeiStMzoZQnA1zw5Vv",
                    "ipProtocol": 6,
                    "lastPacket": 1650190438416,
                    "network": {
                        "bytes": 1528720,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 718358,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4921,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 801304,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5080,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg59S_lmzghHTq8iCh3TVc1R",
                    "ipProtocol": 6,
                    "lastPacket": 1650190815205,
                    "network": {
                        "bytes": 1518748,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 717444,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4920,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 856210,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5071,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5ozUyy3dZPBqMLRoCpJVhn",
                    "ipProtocol": 6,
                    "lastPacket": 1650190719715,
                    "network": {
                        "bytes": 1576896,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 720686,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4929,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 713460,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5056,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4hDAyHPOBNKaWUVjEpZeVJ",
                    "ipProtocol": 6,
                    "lastPacket": 1650190767489,
                    "network": {
                        "bytes": 1439796,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 726336,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4944,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 712048,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5054,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6Wue2h48lFGrrlL122QoCp",
                    "ipProtocol": 6,
                    "lastPacket": 1650190863428,
                    "network": {
                        "bytes": 1439336,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 727288,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4946,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 714940,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5056,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg67vzWbRQlJM7NeCpOmpE_T",
                    "ipProtocol": 6,
                    "lastPacket": 1650190957070,
                    "network": {
                        "bytes": 1441280,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 726340,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4944,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 808438,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5079,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5psVHhpZRNFYinxEYDTHOI",
                    "ipProtocol": 6,
                    "lastPacket": 1650191004923,
                    "network": {
                        "bytes": 1522028,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 713590,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4921,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 713004,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5054,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6hzpIWfaNOk5jdUsrNkpEv",
                    "ipProtocol": 6,
                    "lastPacket": 1650191192422,
                    "network": {
                        "bytes": 1439084,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 726080,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4946,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 867518,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5069,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4TKBMH8vZOxJG6KfQKCUKN",
                    "ipProtocol": 6,
                    "lastPacket": 1650191237545,
                    "network": {
                        "bytes": 1588600,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 721082,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4931,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 819960,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5078,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4CeqbgfUNIdYK26jtuCppq",
                    "ipProtocol": 6,
                    "lastPacket": 1650191144586,
                    "network": {
                        "bytes": 1540808,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 720848,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4922,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 706988,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5058,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4yXLfvQrhEbYzfY5nHQ2ZZ",
                    "ipProtocol": 6,
                    "lastPacket": 1650191098670,
                    "network": {
                        "bytes": 1428632,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 721644,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4942,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 846990,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5077,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6FHJhwdH9DSISJ8IY7rhhI",
                    "ipProtocol": 6,
                    "lastPacket": 1650190908725,
                    "network": {
                        "bytes": 1563980,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 716990,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4923,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 745532,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5060,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7EgFhkU-lI0r0soCnmtw2x",
                    "ipProtocol": 6,
                    "lastPacket": 1650191050420,
                    "network": {
                        "bytes": 1470856,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 725324,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4940,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 708290,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5047,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4XAj485HJK_byQNB3SfOOg",
                    "ipProtocol": 6,
                    "lastPacket": 1650191572301,
                    "network": {
                        "bytes": 1434168,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 725878,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4953,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 814154,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5069,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5I_P7gwHxMRodlMWTomVNQ",
                    "ipProtocol": 6,
                    "lastPacket": 1650191523992,
                    "network": {
                        "bytes": 1550524,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 736370,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4931,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 852846,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5081,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4nsfrvaMFBzbF4N4iZI0Az",
                    "ipProtocol": 6,
                    "lastPacket": 1650191617560,
                    "network": {
                        "bytes": 1569644,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 716798,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4919,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 704720,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5056,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg48TLrgFKpHGJRsSMsfODJq",
                    "ipProtocol": 6,
                    "lastPacket": 1650191665740,
                    "network": {
                        "bytes": 1428596,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 723876,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4944,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 808742,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5067,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg76kCgTc1RGv65mE3mfUp2n",
                    "ipProtocol": 6,
                    "lastPacket": 1650193457784,
                    "network": {
                        "bytes": 1544284,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 735542,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4933,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 807560,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5078,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4icQO17GJK1r8nm6GRxbVk",
                    "ipProtocol": 6,
                    "lastPacket": 1650193268064,
                    "network": {
                        "bytes": 1524820,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 717260,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4922,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 754908,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5054,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6tIlyXMJ5FEbFqBkdVgLit",
                    "ipProtocol": 6,
                    "lastPacket": 1650193786655,
                    "network": {
                        "bytes": 1480640,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 725732,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4946,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 714712,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5050,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6gcLkWIzBCbIraGKVHXL0q",
                    "ipProtocol": 6,
                    "lastPacket": 1650193834815,
                    "network": {
                        "bytes": 1444108,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 729396,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4950,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 708472,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5054,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5aKQlVky5OwbaWE1WuBit1",
                    "ipProtocol": 6,
                    "lastPacket": 1650193693155,
                    "network": {
                        "bytes": 1433832,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 725360,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4946,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 718012,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5056,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7xcnYhEEJCK5rte1Fw1-tg",
                    "ipProtocol": 6,
                    "lastPacket": 1650192042949,
                    "network": {
                        "bytes": 1447220,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 729208,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4944,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 816518,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5085,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7OBEJ8Z2ZKVKIFD2pd8oRu",
                    "ipProtocol": 6,
                    "lastPacket": 1650192091053,
                    "network": {
                        "bytes": 1530404,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 713886,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4915,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 810886,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5073,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4r8eiWC1ZEiZiXNVisvrMv",
                    "ipProtocol": 6,
                    "lastPacket": 1650193551541,
                    "network": {
                        "bytes": 1531748,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 720862,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4927,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 810390,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5081,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg41_t89L2pNDqIloJzMdHuT",
                    "ipProtocol": 6,
                    "lastPacket": 1650193882869,
                    "network": {
                        "bytes": 1524020,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 713630,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4919,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 751250,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5063,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6R9pIUj5xOE44M5xdQ3sJW",
                    "ipProtocol": 6,
                    "lastPacket": 1650193599306,
                    "network": {
                        "bytes": 1473252,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 722002,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4937,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 807606,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5073,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5FEBX92eRPTJxtQ8kYCE8h",
                    "ipProtocol": 6,
                    "lastPacket": 1650193644878,
                    "network": {
                        "bytes": 1526000,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 718394,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4927,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 804114,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5077,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4h7jO3C1FGc7S0TyDRxQiF",
                    "ipProtocol": 6,
                    "lastPacket": 1650193741428,
                    "network": {
                        "bytes": 1520500,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 716386,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4923,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 720750,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5061,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7DjlmLUqdMjZBmZdSRINxC",
                    "ipProtocol": 6,
                    "lastPacket": 1650193505820,
                    "network": {
                        "bytes": 1452412,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 731662,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4939,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 705856,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5062,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6kbInlb8ZDToPN_Qohnb_G",
                    "ipProtocol": 6,
                    "lastPacket": 1650193316382,
                    "network": {
                        "bytes": 1428976,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 723120,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4938,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 699534,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5063,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7xtv1R8V9CManxWrGp3LSk",
                    "ipProtocol": 6,
                    "lastPacket": 1650194776247,
                    "network": {
                        "bytes": 1420380,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 720846,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4937,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 817298,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5067,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6Mns7QLq1GxYvMjV5cASTJ",
                    "ipProtocol": 6,
                    "lastPacket": 1650194447334,
                    "network": {
                        "bytes": 1540264,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 722966,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4933,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 752150,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5051,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5lSC2rF7tJfI6snEr_m9C_",
                    "ipProtocol": 6,
                    "lastPacket": 1650194492675,
                    "network": {
                        "bytes": 1476708,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 724558,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4949,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 766644,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5056,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6NFixJwXRBWpEOce3hP5b5",
                    "ipProtocol": 6,
                    "lastPacket": 1650194869433,
                    "network": {
                        "bytes": 1495640,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 728996,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4944,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 812212,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5074,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5WEMF4qjhBqqIob88UMeaR",
                    "ipProtocol": 6,
                    "lastPacket": 1650194917674,
                    "network": {
                        "bytes": 1530612,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 718400,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4926,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 708952,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5060,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4uj6Z3I6hOaIeqdTGWZfxN",
                    "ipProtocol": 6,
                    "lastPacket": 1650194965813,
                    "network": {
                        "bytes": 1432008,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 723056,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4940,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 752892,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5056,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5FNzk9fVhJzrGslWHuZT6b",
                    "ipProtocol": 6,
                    "lastPacket": 1650194682373,
                    "network": {
                        "bytes": 1478912,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 726020,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4944,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 820122,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5075,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6ACUZuY_9H8If-f3ZrNv8U",
                    "ipProtocol": 6,
                    "lastPacket": 1650194728014,
                    "network": {
                        "bytes": 1541548,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 721426,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4925,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 818066,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5079,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5zaKaVI7JDc5o_dDABqy11",
                    "ipProtocol": 6,
                    "lastPacket": 1650194824293,
                    "network": {
                        "bytes": 1540256,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 722190,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4921,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 808328,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5074,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6EfqcnKY1FN5Cq4ugNKEpt",
                    "ipProtocol": 6,
                    "lastPacket": 1650194635012,
                    "network": {
                        "bytes": 1524064,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 715736,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4926,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 807562,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5081,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6v1h7GpetCzK9Mo-f7apYD",
                    "ipProtocol": 6,
                    "lastPacket": 1650194540658,
                    "network": {
                        "bytes": 1524860,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 717298,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4919,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 708124,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5054,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4pgg-KRUlDl5oaC1lzxNf4",
                    "ipProtocol": 6,
                    "lastPacket": 1650194588860,
                    "network": {
                        "bytes": 1431944,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 723820,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4946,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 816112,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5068,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7Z5kYqTQNMpoeCBk8C7UOc",
                    "ipProtocol": 6,
                    "lastPacket": 1650193364242,
                    "network": {
                        "bytes": 1536344,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 720232,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4932,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 751190,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5057,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5FJZ6QA8JJm73LN_0dsi2T",
                    "ipProtocol": 6,
                    "lastPacket": 1650193410102,
                    "network": {
                        "bytes": 1475744,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 724554,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4943,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 705226,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5059,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4v0oKyoedAJpl4FFp53ADV",
                    "ipProtocol": 6,
                    "lastPacket": 1650194399098,
                    "network": {
                        "bytes": 1428584,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 723358,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4941,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 712846,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5057,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4hMsksIKRCbb9NFJ9p2cpN",
                    "ipProtocol": 6,
                    "lastPacket": 1650194022100,
                    "network": {
                        "bytes": 1438524,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 725678,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4943,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 814106,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5065,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4w5AbYoo5KnZXjhHFllWWX",
                    "ipProtocol": 6,
                    "lastPacket": 1650194070141,
                    "network": {
                        "bytes": 1536384,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 722278,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4935,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 816708,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5074,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4XFhJwgmxGAYQwGw1hUTB4",
                    "ipProtocol": 6,
                    "lastPacket": 1650194257497,
                    "network": {
                        "bytes": 1536504,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 719796,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4926,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 745498,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5059,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7qZPHuBKRG0I8KBBd_yYuY",
                    "ipProtocol": 6,
                    "lastPacket": 1650194305169,
                    "network": {
                        "bytes": 1469208,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 723710,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4941,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 827946,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5067,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6jz2EIjzBKF7d_CsvcyX6P",
                    "ipProtocol": 6,
                    "lastPacket": 1650193974114,
                    "network": {
                        "bytes": 1546108,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 718162,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4933,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 753194,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5047,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5gtTWu3NFPqaLfy-mJYxTS",
                    "ipProtocol": 6,
                    "lastPacket": 1650193928301,
                    "network": {
                        "bytes": 1485868,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 732674,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4953,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 809324,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5074,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7s-ri9ph5A_obw6c6LQ6wn",
                    "ipProtocol": 6,
                    "lastPacket": 1650194351039,
                    "network": {
                        "bytes": 1528168,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 718844,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4926,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 707208,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5056,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4IiwP5h-BKyJoGlmyCZZLG",
                    "ipProtocol": 6,
                    "lastPacket": 1650194211727,
                    "network": {
                        "bytes": 1429824,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 722616,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4944,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 808298,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5079,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6iJXJvQwtOpoKJR0d4K55L",
                    "ipProtocol": 6,
                    "lastPacket": 1650194163641,
                    "network": {
                        "bytes": 1523948,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 715650,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4921,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 875832,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5098,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7D4t1Fm9JM3oG9J7Cnvb9g",
                    "ipProtocol": 6,
                    "lastPacket": 1650194115456,
                    "network": {
                        "bytes": 1592196,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 716364,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4902,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 718516,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5054,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6gShckKM5LkLZXiXYWVqiR",
                    "ipProtocol": 6,
                    "lastPacket": 1650192936429,
                    "network": {
                        "bytes": 1449524,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 731008,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4946,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 808574,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5075,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7qnnPBfH1HqpBjKp4U6B7Y",
                    "ipProtocol": 6,
                    "lastPacket": 1650192984296,
                    "network": {
                        "bytes": 1527124,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 718550,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4925,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 712778,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5049,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4Pikq1L8ZAD6jCW8rN6dWO",
                    "ipProtocol": 6,
                    "lastPacket": 1650192465708,
                    "network": {
                        "bytes": 1439412,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 726634,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4951,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 855782,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5077,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4pNfV1JuNK7KRpE442w3pu",
                    "ipProtocol": 6,
                    "lastPacket": 1650192511374,
                    "network": {
                        "bytes": 1572964,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 717182,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4923,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 570598,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 4127,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6EvBessN5AfIz3PwATYeQp",
                    "ipProtocol": 6,
                    "lastPacket": 1650192124532,
                    "network": {
                        "bytes": 4436124,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 3865526,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 5873,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 203696,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 2188,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4-U4IB63FB6qcsWBOOOaq0",
                    "ipProtocol": 6,
                    "lastPacket": 1650192133673,
                    "network": {
                        "bytes": 10196256,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 9992560,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 7812,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 830822,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5083,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4cUiH48vtC1oh8s2eptm_0",
                    "ipProtocol": 6,
                    "lastPacket": 1650193222367,
                    "network": {
                        "bytes": 1552668,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 721846,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4917,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 713666,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5061,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5BzfZzd6xLSJa8kreCxjKa",
                    "ipProtocol": 6,
                    "lastPacket": 1650192275523,
                    "network": {
                        "bytes": 1437896,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 724230,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4939,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 937096,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5100,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5tX_HF8-hCgqVC9pKYfuWc",
                    "ipProtocol": 6,
                    "lastPacket": 1650192320560,
                    "network": {
                        "bytes": 1649820,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 712724,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4900,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 713478,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5057,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6pkgeHYhxBh77kTKDcEiw2",
                    "ipProtocol": 6,
                    "lastPacket": 1650193125903,
                    "network": {
                        "bytes": 1437572,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 724094,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4943,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 817168,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5066,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5WnzP4uStFT5zmL3lruW7d",
                    "ipProtocol": 6,
                    "lastPacket": 1650193171927,
                    "network": {
                        "bytes": 1537744,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 720576,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4934,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 715368,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5046,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4GIJh3FvpJ5I7onZASK0pg",
                    "ipProtocol": 6,
                    "lastPacket": 1650193032478,
                    "network": {
                        "bytes": 1444600,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 729232,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4954,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 864882,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5069,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4G3tYKGERFXKrk7ghiHBqS",
                    "ipProtocol": 6,
                    "lastPacket": 1650193077676,
                    "network": {
                        "bytes": 1585228,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 720346,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4931,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 848192,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5080,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4nUTATJuVJW6o3V99Yy1fd",
                    "ipProtocol": 6,
                    "lastPacket": 1650192890456,
                    "network": {
                        "bytes": 1564568,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 716376,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4920,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 707652,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5056,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg683TzTtphKhrxxZ_Ftifzn",
                    "ipProtocol": 6,
                    "lastPacket": 1650192843361,
                    "network": {
                        "bytes": 1431520,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 723868,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4944,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 710478,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5053,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7Woucdw6ZN6IzxhctJ3TyI",
                    "ipProtocol": 6,
                    "lastPacket": 1650191382053,
                    "network": {
                        "bytes": 1434780,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 724302,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4947,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 944882,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5107,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5eQjpzdexJr6JajIMDiXzb",
                    "ipProtocol": 6,
                    "lastPacket": 1650191428356,
                    "network": {
                        "bytes": 1662276,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 717394,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4893,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 810946,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5079,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7ZYLFgtMxNqaMsrcIYkVyf",
                    "ipProtocol": 6,
                    "lastPacket": 1650191901194,
                    "network": {
                        "bytes": 1530100,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 719154,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4921,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 815140,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5074,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6xBhXlUm9MFIDU3dRaQtQb",
                    "ipProtocol": 6,
                    "lastPacket": 1650192227022,
                    "network": {
                        "bytes": 1535792,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 720652,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4926,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 850304,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5082,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5HISM8wX5Kk6Q-28DPQBhb",
                    "ipProtocol": 6,
                    "lastPacket": 1650191807268,
                    "network": {
                        "bytes": 1565724,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 715420,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4918,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 712216,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5058,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6y2WNOeL1Pcr45g64kg8Xb",
                    "ipProtocol": 6,
                    "lastPacket": 1650191853763,
                    "network": {
                        "bytes": 1437936,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 725720,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4942,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 702730,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5057,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6htBLLXEJDDLR0HwIYtEWU",
                    "ipProtocol": 6,
                    "lastPacket": 1650191476710,
                    "network": {
                        "bytes": 1425172,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 722442,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4943,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 780238,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5061,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5iGQA_w41Ke7T-SnRae4Ht",
                    "ipProtocol": 6,
                    "lastPacket": 1650192179428,
                    "network": {
                        "bytes": 1511644,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 731406,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4939,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 809298,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5073,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5OAiGvZMlAXa7dPqDsb5bO",
                    "ipProtocol": 6,
                    "lastPacket": 1650191333975,
                    "network": {
                        "bytes": 1527036,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 717738,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4927,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 712864,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5046,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg5DGQHTCCRNdrtmgGdJCOzC",
                    "ipProtocol": 6,
                    "lastPacket": 1650191761995,
                    "network": {
                        "bytes": 1440360,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 727496,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4954,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 806720,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5086,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg54lJ2cYBJP1IkCs9xNWixD",
                    "ipProtocol": 6,
                    "lastPacket": 1650191713798,
                    "network": {
                        "bytes": 1517652,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 710932,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4914,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 704424,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5058,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4quK-NSoxDGpPIjYOqzila",
                    "ipProtocol": 6,
                    "lastPacket": 1650191949406,
                    "network": {
                        "bytes": 1428172,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 723748,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4942,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 848130,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5077,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg4ZMLaOdYhCT4J0fPftwJd6",
                    "ipProtocol": 6,
                    "lastPacket": 1650191994957,
                    "network": {
                        "bytes": 1563408,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 715278,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4923,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 855236,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5080,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6bqUD-RXBL_q88alztyWE_",
                    "ipProtocol": 6,
                    "lastPacket": 1650192700654,
                    "network": {
                        "bytes": 1572876,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 717640,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4920,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 702438,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5049,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg7SaCgPoi9AzLC7OFFCBA1A",
                    "ipProtocol": 6,
                    "lastPacket": 1650192748892,
                    "network": {
                        "bytes": 1426440,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 724002,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4951,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 712478,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5057,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg6Q8GqyU_pAbo4okmRXlwlG",
                    "ipProtocol": 6,
                    "lastPacket": 1650191285735,
                    "network": {
                        "bytes": 1437972,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 725494,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4943,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 812290,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5075,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg78mEkliChGBoLFAEOOczIf",
                    "ipProtocol": 6,
                    "lastPacket": 1650192417972,
                    "network": {
                        "bytes": 1527968,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 715678,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4925,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 704300,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5058,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg68AjyjAcJDhpfHsE2wvNO5",
                    "ipProtocol": 6,
                    "lastPacket": 1650192559177,
                    "network": {
                        "bytes": 1426996,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 722696,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4942,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 808718,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5077,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg42yo9AQg9FK4zCNPTVdrHO",
                    "ipProtocol": 6,
                    "lastPacket": 1650192607225,
                    "network": {
                        "bytes": 1527220,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 718502,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4923,
                        "port": 22
                    },
                    "totDataBytes": 0
                },
                {
                    "client": {
                        "bytes": 0
                    },
                    "destination": {
                        "as": {},
                        "bytes": 704114,
                        "geo": {},
                        "ip": "192.168.1.88",
                        "packets": 5055,
                        "port": 41096
                    },
                    "firstPacket": 1649921199252,
                    "id": "3@220417-Yg40OdT2YJhEdqNcYu8K07Up",
                    "ipProtocol": 6,
                    "lastPacket": 1650192655384,
                    "network": {
                        "bytes": 1429284,
                        "packets": 10000
                    },
                    "node": "localhost",
                    "rootId": "220414-Yg445Ur1tpRKTKBpr8lhv37w",
                    "server": {
                        "bytes": 0
                    },
                    "source": {
                        "as": {},
                        "bytes": 725170,
                        "geo": {},
                        "ip": "192.168.1.130",
                        "packets": 4945,
                        "port": 22
                    },
                    "totDataBytes": 0
                }
            ],
            "graph": {
                "client.bytesHisto": [],
                "destination.bytesHisto": [],
                "destination.packetsHisto": [],
                "interval": 60,
                "network.bytesTotal": 0,
                "network.packetsTotal": 0,
                "server.bytesHisto": [],
                "sessionsHisto": [],
                "sessionsTotal": 0,
                "source.bytesHisto": [],
                "source.packetsHisto": [],
                "totDataBytesTotal": 0,
                "xmax": 1650363038000,
                "xmin": 1650190238000
            },
            "map": {},
            "recordsFiltered": 516305,
            "recordsTotal": 23491280
        }
    }
}
```

#### Human Readable Output

>Showing 100 results, limit=100
>### Session List Result:
>|ID|IP Protocol|Start Time|Stop Time|Source IP|Source Port|Destination IP|Destination Port|Node|
>|---|---|---|---|---|---|---|---|---|
>| 3@220417-Yg7OpiE4Pi1PFaRqu8lztuA6 | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:15:31 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5Kx3oHIahAPJJVD8QwphkQ | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:16:19 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6l6qOUggpPvrAj-lbNmjtM | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:11:39 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4c2n50c2ZCOK4EiLnVhN5p | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:12:24 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4k-mSg3xtO349fiRm4suHR | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:10:51 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg58S89EQFFMCoqx9f_zNGIz | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:17:07 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7x9iWf3JhHVp7Z6Uok_93o | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:13:12 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4gqw72t1hEK5Dz93cJzwkp | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:17:54 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7GdPzn9vpJx7RbGSDR88Ko | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:14:46 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6Sm6ZeiStMzoZQnA1zw5Vv | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:13:58 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg59S_lmzghHTq8iCh3TVc1R | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:20:15 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5ozUyy3dZPBqMLRoCpJVhn | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:18:39 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4hDAyHPOBNKaWUVjEpZeVJ | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:19:27 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6Wue2h48lFGrrlL122QoCp | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:21:03 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg67vzWbRQlJM7NeCpOmpE_T | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:22:37 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5psVHhpZRNFYinxEYDTHOI | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:23:24 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6hzpIWfaNOk5jdUsrNkpEv | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:26:32 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4TKBMH8vZOxJG6KfQKCUKN | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:27:17 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4CeqbgfUNIdYK26jtuCppq | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:25:44 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4yXLfvQrhEbYzfY5nHQ2ZZ | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:24:58 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6FHJhwdH9DSISJ8IY7rhhI | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:21:48 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7EgFhkU-lI0r0soCnmtw2x | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:24:10 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4XAj485HJK_byQNB3SfOOg | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:32:52 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5I_P7gwHxMRodlMWTomVNQ | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:32:03 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4nsfrvaMFBzbF4N4iZI0Az | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:33:37 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg48TLrgFKpHGJRsSMsfODJq | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:34:25 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg76kCgTc1RGv65mE3mfUp2n | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:04:17 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4icQO17GJK1r8nm6GRxbVk | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:01:08 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6tIlyXMJ5FEbFqBkdVgLit | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:09:46 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6gcLkWIzBCbIraGKVHXL0q | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:10:34 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5aKQlVky5OwbaWE1WuBit1 | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:08:13 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7xcnYhEEJCK5rte1Fw1-tg | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:40:42 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7OBEJ8Z2ZKVKIFD2pd8oRu | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:41:31 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4r8eiWC1ZEiZiXNVisvrMv | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:05:51 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg41_t89L2pNDqIloJzMdHuT | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:11:22 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6R9pIUj5xOE44M5xdQ3sJW | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:06:39 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5FEBX92eRPTJxtQ8kYCE8h | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:07:24 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4h7jO3C1FGc7S0TyDRxQiF | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:09:01 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7DjlmLUqdMjZBmZdSRINxC | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:05:05 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6kbInlb8ZDToPN_Qohnb_G | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:01:56 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7xtv1R8V9CManxWrGp3LSk | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:26:16 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6Mns7QLq1GxYvMjV5cASTJ | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:20:47 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5lSC2rF7tJfI6snEr_m9C_ | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:21:32 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6NFixJwXRBWpEOce3hP5b5 | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:27:49 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5WEMF4qjhBqqIob88UMeaR | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:28:37 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4uj6Z3I6hOaIeqdTGWZfxN | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:29:25 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5FNzk9fVhJzrGslWHuZT6b | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:24:42 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6ACUZuY_9H8If-f3ZrNv8U | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:25:28 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5zaKaVI7JDc5o_dDABqy11 | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:27:04 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6EfqcnKY1FN5Cq4ugNKEpt | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:23:55 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6v1h7GpetCzK9Mo-f7apYD | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:22:20 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4pgg-KRUlDl5oaC1lzxNf4 | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:23:08 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7Z5kYqTQNMpoeCBk8C7UOc | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:02:44 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5FJZ6QA8JJm73LN_0dsi2T | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:03:30 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4v0oKyoedAJpl4FFp53ADV | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:19:59 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4hMsksIKRCbb9NFJ9p2cpN | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:13:42 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4w5AbYoo5KnZXjhHFllWWX | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:14:30 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4XFhJwgmxGAYQwGw1hUTB4 | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:17:37 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7qZPHuBKRG0I8KBBd_yYuY | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:18:25 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6jz2EIjzBKF7d_CsvcyX6P | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:12:54 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5gtTWu3NFPqaLfy-mJYxTS | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:12:08 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7s-ri9ph5A_obw6c6LQ6wn | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:19:11 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4IiwP5h-BKyJoGlmyCZZLG | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:16:51 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6iJXJvQwtOpoKJR0d4K55L | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:16:03 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7D4t1Fm9JM3oG9J7Cnvb9g | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:15:15 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6gShckKM5LkLZXiXYWVqiR | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:55:36 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7qnnPBfH1HqpBjKp4U6B7Y | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:56:24 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4Pikq1L8ZAD6jCW8rN6dWO | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:47:45 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4pNfV1JuNK7KRpE442w3pu | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:48:31 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6EvBessN5AfIz3PwATYeQp | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:42:04 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4-U4IB63FB6qcsWBOOOaq0 | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:42:13 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4cUiH48vtC1oh8s2eptm_0 | 6 | 2022-04-14 07:26:39 | 2022-04-17 11:00:22 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5BzfZzd6xLSJa8kreCxjKa | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:44:35 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5tX_HF8-hCgqVC9pKYfuWc | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:45:20 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6pkgeHYhxBh77kTKDcEiw2 | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:58:45 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5WnzP4uStFT5zmL3lruW7d | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:59:31 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4GIJh3FvpJ5I7onZASK0pg | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:57:12 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4G3tYKGERFXKrk7ghiHBqS | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:57:57 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4nUTATJuVJW6o3V99Yy1fd | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:54:50 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg683TzTtphKhrxxZ_Ftifzn | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:54:03 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7Woucdw6ZN6IzxhctJ3TyI | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:29:42 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5eQjpzdexJr6JajIMDiXzb | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:30:28 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7ZYLFgtMxNqaMsrcIYkVyf | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:38:21 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6xBhXlUm9MFIDU3dRaQtQb | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:43:47 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5HISM8wX5Kk6Q-28DPQBhb | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:36:47 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6y2WNOeL1Pcr45g64kg8Xb | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:37:33 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6htBLLXEJDDLR0HwIYtEWU | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:31:16 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5iGQA_w41Ke7T-SnRae4Ht | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:42:59 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5OAiGvZMlAXa7dPqDsb5bO | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:28:53 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg5DGQHTCCRNdrtmgGdJCOzC | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:36:01 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg54lJ2cYBJP1IkCs9xNWixD | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:35:13 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4quK-NSoxDGpPIjYOqzila | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:39:09 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg4ZMLaOdYhCT4J0fPftwJd6 | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:39:54 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6bqUD-RXBL_q88alztyWE_ | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:51:40 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg7SaCgPoi9AzLC7OFFCBA1A | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:52:28 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg6Q8GqyU_pAbo4okmRXlwlG | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:28:05 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg78mEkliChGBoLFAEOOczIf | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:46:57 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg68AjyjAcJDhpfHsE2wvNO5 | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:49:19 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg42yo9AQg9FK4zCNPTVdrHO | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:50:07 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |
>| 3@220417-Yg40OdT2YJhEdqNcYu8K07Up | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:50:55 | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |


### arkime-unique-field-list
***
Gets a list of unique field values (with or without counts) and sends them to the client.


#### Base Command

`arkime-unique-field-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| counts | Whether to return counts with he list of unique field values. Defaults to 0. 0 = no counts, 1 - counts. | Optional | 
| expression_field_names | Comma separated list of expression field names to return. | Required | 
| date | The number of hours of data to return (-1 means all data). Defaults to 1. | Optional | 
| expression | The search expression string. | Optional | 
| start_time | If the date parameter is not set, this is the start time of data to return. Format is seconds since Unix EPOC. | Optional | 
| stop_time | If the date parameter is not set, this is the stop time of data to return. Format is seconds since Unix EPOC. | Optional | 
| view | The view name to apply before the expression. | Optional | 
| order | Comma separated list of db field names to sort on. Data is sorted in order of the list supplied. Optionally can be followed by :asc or :desc for ascending or descending sorting. | Optional | 
| fields | Comma separated list of db field names to return. Default is ipProtocol, rootId, totDataBytes, srcDataBytes, dstDataBytes, firstPacket, lastPacket, srcIp, srcPort, dstIp, dstPort, totPackets, srcPackets, dstPackets, totBytes, srcBytes, dstBytes, node, http.uri, srcGEO, dstGEO, email.subject, email.src, email.dst, email.filename, dns.host, cert, irc.channel, http.xffGEO. | Optional | 
| bounding | Query sessions based on different aspects of a session’s time. Options include: ‘first’ - First Packet: the timestamp of the first packet received for the session. ‘last’ - Last Packet: The timestamp of the last packet received for the session. ‘both’ - Bounded: Both the first and last packet timestamps for the session must be inside the time window. ‘either’ - Session Overlaps: The timestamp of the first packet must be before the end of the time window AND the timestamp of the last packet must be after the start of the time window. ‘database’ - Database: The timestamp the session was written to the database. This can be up to several minutes AFTER the last packet was received. | Optional | 
| strictly | When set the entire session must be inside the date range to be observed, otherwise if it overlaps it is displayed. Overwrites the bounding parameter, sets bonding to ‘both’. | Optional | 
| limit | The number of items to return. Defaults to 100, Max is 2,000,000. | Optional | 
| page_number | The page at which to start. The default is 0. | Optional | 
| page_size | Page size. Minimum page size is 1, maximum is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.UniqueField.Field | String | The field. | 
| Arkime.UniqueField.Count | Boolean | The count. | 

#### Command example
```!arkime-unique-field-list expression_field_names=dns.ASN counts=0```
#### Context Example
```json
{
    "Arkime": {
        "UniqueField": [
            {
                "Field": "AS8075 MICROSOFT-CORP-MSN-AS-BLOCK"
            },
            {
                "Field": "AS15169 GOOGLE"
            },
            {
                "Field": "AS396982 GOOGLE-CLOUD-PLATFORM"
            },
            {
                "Field": "AS16509 AMAZON-02"
            },
            {
                "Field": "AS13335 CLOUDFLARENET"
            },
            {
                "Field": "AS14618 AMAZON-AES"
            },
            {
                "Field": "AS15133 EDGECAST"
            },
            {
                "Field": "AS16625 AKAMAI-AS"
            },
            {
                "Field": "AS20446 STACKPATH-CDN"
            },
            {
                "Field": "AS393225 ARIN-PFS-IAD"
            },
            {
                "Field": "AS1680 Cellcom Fixed Line Communication L.P."
            },
            {
                "Field": "AS54538 PAN0001"
            },
            {
                "Field": "AS14870 FLEXERA-SC4"
            },
            {
                "Field": "AS20940 Akamai International B.V."
            },
            {
                "Field": "AS22822 LLNW"
            },
            {
                "Field": "AS53736 NUTANIX-IT"
            },
            {
                "Field": "AS8068 MICROSOFT-CORP-MSN-AS-BLOCK"
            },
            {
                "Field": "AS3356 LEVEL3"
            },
            {
                "Field": "---"
            },
            {
                "Field": "AS41231 Canonical Group Limited"
            },
            {
                "Field": "AS7754 MCAFEE"
            },
            {
                "Field": "AS3598 MICROSOFT-CORP-AS"
            },
            {
                "Field": "AS12400 Partner Communications Ltd."
            },
            {
                "Field": "AS202818 Lumen Technologies Uk Limited"
            },
            {
                "Field": "AS12876 Online S.a.s."
            },
            {
                "Field": "AS36351 SOFTLAYER"
            },
            {
                "Field": "AS40816 VMW-PA-SERVER"
            },
            {
                "Field": "AS6939 HURRICANE"
            },
            {
                "Field": "AS1213 HEAnet"
            },
            {
                "Field": "AS12322 Free SAS"
            },
            {
                "Field": "AS16276 OVH SAS"
            },
            {
                "Field": "AS174 COGENT-174"
            },
            {
                "Field": "AS19429 Colombia"
            },
            {
                "Field": "AS1955 KIFU (Governmental Info Tech Development Agency)"
            },
            {
                "Field": "AS19637 AVG19637"
            },
            {
                "Field": "AS208725 Devrandom.be BV"
            },
            {
                "Field": "AS209850 Burdenis-com Eood"
            },
            {
                "Field": "AS22317 F5-NETWORKS"
            },
            {
                "Field": "AS23028 TEAM-CYMRU"
            },
            {
                "Field": "AS3214 xTom GmbH"
            },
            {
                "Field": "AS38719 Dreamscape Networks Limited"
            },
            {
                "Field": "AS393424 AS-TORIX-SVC"
            },
            {
                "Field": "AS50392 LLC Campus Networks"
            },
            {
                "Field": "AS57351 Hypr Helix Ltd"
            },
            {
                "Field": "AS852 TELUS Communications"
            },
            {
                "Field": ""
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 46 results, limit=50
>### Unique Field Results:
>|Field|Count|
>|---|---|
>| AS8075 MICROSOFT-CORP-MSN-AS-BLOCK |  |
>| AS15169 GOOGLE |  |
>| AS396982 GOOGLE-CLOUD-PLATFORM |  |
>| AS16509 AMAZON-02 |  |
>| AS13335 CLOUDFLARENET |  |
>| AS14618 AMAZON-AES |  |
>| AS15133 EDGECAST |  |
>| AS16625 AKAMAI-AS |  |
>| AS20446 STACKPATH-CDN |  |
>| AS393225 ARIN-PFS-IAD |  |
>| AS1680 Cellcom Fixed Line Communication L.P. |  |
>| AS54538 PAN0001 |  |
>| AS14870 FLEXERA-SC4 |  |
>| AS20940 Akamai International B.V. |  |
>| AS22822 LLNW |  |
>| AS53736 NUTANIX-IT |  |
>| AS8068 MICROSOFT-CORP-MSN-AS-BLOCK |  |
>| AS3356 LEVEL3 |  |
>| --- |  |
>| AS41231 Canonical Group Limited |  |
>| AS7754 MCAFEE |  |
>| AS3598 MICROSOFT-CORP-AS |  |
>| AS12400 Partner Communications Ltd. |  |
>| AS202818 Lumen Technologies Uk Limited |  |
>| AS12876 Online S.a.s. |  |
>| AS36351 SOFTLAYER |  |
>| AS40816 VMW-PA-SERVER |  |
>| AS6939 HURRICANE |  |
>| AS1213 HEAnet |  |
>| AS12322 Free SAS |  |
>| AS16276 OVH SAS |  |
>| AS174 COGENT-174 |  |
>| AS19429 Colombia |  |
>| AS1955 KIFU (Governmental Info Tech Development Agency) |  |
>| AS19637 AVG19637 |  |
>| AS208725 Devrandom.be BV |  |
>| AS209850 Burdenis-com Eood |  |
>| AS22317 F5-NETWORKS |  |
>| AS23028 TEAM-CYMRU |  |
>| AS3214 xTom GmbH |  |
>| AS38719 Dreamscape Networks Limited |  |
>| AS393424 AS-TORIX-SVC |  |
>| AS50392 LLC Campus Networks |  |
>| AS57351 Hypr Helix Ltd |  |
>| AS852 TELUS Communications |  |
>|  |  |


#### Command example
```!arkime-unique-field-list expression_field_names=dns.ASN counts=1```
#### Context Example
```json
{
    "Arkime": {
        "UniqueField": [
            {
                "Count": " 803",
                "Field": "AS8075 MICROSOFT-CORP-MSN-AS-BLOCK"
            },
            {
                "Count": " 566",
                "Field": "AS15169 GOOGLE"
            },
            {
                "Count": " 499",
                "Field": "AS396982 GOOGLE-CLOUD-PLATFORM"
            },
            {
                "Count": " 208",
                "Field": "AS16509 AMAZON-02"
            },
            {
                "Count": " 111",
                "Field": "AS13335 CLOUDFLARENET"
            },
            {
                "Count": " 84",
                "Field": "AS14618 AMAZON-AES"
            },
            {
                "Count": " 29",
                "Field": "AS15133 EDGECAST"
            },
            {
                "Count": " 29",
                "Field": "AS16625 AKAMAI-AS"
            },
            {
                "Count": " 17",
                "Field": "AS20446 STACKPATH-CDN"
            },
            {
                "Count": " 16",
                "Field": "AS393225 ARIN-PFS-IAD"
            },
            {
                "Count": " 15",
                "Field": "AS1680 Cellcom Fixed Line Communication L.P."
            },
            {
                "Count": " 14",
                "Field": "AS54538 PAN0001"
            },
            {
                "Count": " 13",
                "Field": "AS14870 FLEXERA-SC4"
            },
            {
                "Count": " 13",
                "Field": "AS20940 Akamai International B.V."
            },
            {
                "Count": " 12",
                "Field": "AS22822 LLNW"
            },
            {
                "Count": " 11",
                "Field": "AS53736 NUTANIX-IT"
            },
            {
                "Count": " 10",
                "Field": "AS8068 MICROSOFT-CORP-MSN-AS-BLOCK"
            },
            {
                "Count": " 7",
                "Field": "AS3356 LEVEL3"
            },
            {
                "Count": " 5",
                "Field": "---"
            },
            {
                "Count": " 5",
                "Field": "AS41231 Canonical Group Limited"
            },
            {
                "Count": " 5",
                "Field": "AS7754 MCAFEE"
            },
            {
                "Count": " 4",
                "Field": "AS3598 MICROSOFT-CORP-AS"
            },
            {
                "Count": " 3",
                "Field": "AS12400 Partner Communications Ltd."
            },
            {
                "Count": " 3",
                "Field": "AS202818 Lumen Technologies Uk Limited"
            },
            {
                "Count": " 2",
                "Field": "AS12876 Online S.a.s."
            },
            {
                "Count": " 2",
                "Field": "AS36351 SOFTLAYER"
            },
            {
                "Count": " 2",
                "Field": "AS40816 VMW-PA-SERVER"
            },
            {
                "Count": " 2",
                "Field": "AS6939 HURRICANE"
            },
            {
                "Count": " 1",
                "Field": "AS1213 HEAnet"
            },
            {
                "Count": " 1",
                "Field": "AS12322 Free SAS"
            },
            {
                "Count": " 1",
                "Field": "AS16276 OVH SAS"
            },
            {
                "Count": " 1",
                "Field": "AS174 COGENT-174"
            },
            {
                "Count": " 1",
                "Field": "AS19429 Colombia"
            },
            {
                "Count": " 1",
                "Field": "AS1955 KIFU (Governmental Info Tech Development Agency)"
            },
            {
                "Count": " 1",
                "Field": "AS19637 AVG19637"
            },
            {
                "Count": " 1",
                "Field": "AS208725 Devrandom.be BV"
            },
            {
                "Count": " 1",
                "Field": "AS209850 Burdenis-com Eood"
            },
            {
                "Count": " 1",
                "Field": "AS22317 F5-NETWORKS"
            },
            {
                "Count": " 1",
                "Field": "AS23028 TEAM-CYMRU"
            },
            {
                "Count": " 1",
                "Field": "AS3214 xTom GmbH"
            },
            {
                "Count": " 1",
                "Field": "AS38719 Dreamscape Networks Limited"
            },
            {
                "Count": " 1",
                "Field": "AS393424 AS-TORIX-SVC"
            },
            {
                "Count": " 1",
                "Field": "AS50392 LLC Campus Networks"
            },
            {
                "Count": " 1",
                "Field": "AS57351 Hypr Helix Ltd"
            },
            {
                "Count": " 1",
                "Field": "AS852 TELUS Communications"
            },
            {
                "Field": ""
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 46 results, limit=50
>### Unique Field Results:
>|Field|Count|
>|---|---|
>| AS8075 MICROSOFT-CORP-MSN-AS-BLOCK |  803 |
>| AS15169 GOOGLE |  566 |
>| AS396982 GOOGLE-CLOUD-PLATFORM |  499 |
>| AS16509 AMAZON-02 |  208 |
>| AS13335 CLOUDFLARENET |  111 |
>| AS14618 AMAZON-AES |  84 |
>| AS15133 EDGECAST |  29 |
>| AS16625 AKAMAI-AS |  29 |
>| AS20446 STACKPATH-CDN |  17 |
>| AS393225 ARIN-PFS-IAD |  16 |
>| AS1680 Cellcom Fixed Line Communication L.P. |  15 |
>| AS54538 PAN0001 |  14 |
>| AS14870 FLEXERA-SC4 |  13 |
>| AS20940 Akamai International B.V. |  13 |
>| AS22822 LLNW |  12 |
>| AS53736 NUTANIX-IT |  11 |
>| AS8068 MICROSOFT-CORP-MSN-AS-BLOCK |  10 |
>| AS3356 LEVEL3 |  7 |
>| --- |  5 |
>| AS41231 Canonical Group Limited |  5 |
>| AS7754 MCAFEE |  5 |
>| AS3598 MICROSOFT-CORP-AS |  4 |
>| AS12400 Partner Communications Ltd. |  3 |
>| AS202818 Lumen Technologies Uk Limited |  3 |
>| AS12876 Online S.a.s. |  2 |
>| AS36351 SOFTLAYER |  2 |
>| AS40816 VMW-PA-SERVER |  2 |
>| AS6939 HURRICANE |  2 |
>| AS1213 HEAnet |  1 |
>| AS12322 Free SAS |  1 |
>| AS16276 OVH SAS |  1 |
>| AS174 COGENT-174 |  1 |
>| AS19429 Colombia |  1 |
>| AS1955 KIFU (Governmental Info Tech Development Agency) |  1 |
>| AS19637 AVG19637 |  1 |
>| AS208725 Devrandom.be BV |  1 |
>| AS209850 Burdenis-com Eood |  1 |
>| AS22317 F5-NETWORKS |  1 |
>| AS23028 TEAM-CYMRU |  1 |
>| AS3214 xTom GmbH |  1 |
>| AS38719 Dreamscape Networks Limited |  1 |
>| AS393424 AS-TORIX-SVC |  1 |
>| AS50392 LLC Campus Networks |  1 |
>| AS57351 Hypr Helix Ltd |  1 |
>| AS852 TELUS Communications |  1 |
>|  |  |


### arkime-multi-unique-field-list
***
Gets an intersection of unique field values (with or without counts) and sends them to the client.


#### Base Command

`arkime-multi-unique-field-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| counts | Whether to return counts with he list of unique field values. Defaults to 0. 0 = no counts, 1 - counts. | Optional | 
| expression_field_names | Comma separated list of expression field names to return. | Required | 
| database_field | The database field to return unique data for. Either exp or field is required, field is given priority if both are present. | Optional | 
| date | The number of hours of data to return (-1 means all data). Defaults to 1. | Optional | 
| expression | The search expression string. | Optional | 
| start_time | If the date parameter is not set, this is the start time of data to return. Format is seconds since Unix EPOC. | Optional | 
| stop_time | If the date parameter is not set, this is the stop time of data to return. Format is seconds since Unix EPOC. | Optional | 
| view | The view name to apply before the expression. | Optional | 
| order | Comma separated list of db field names to sort on. Data is sorted in order of the list supplied. Optionally can be followed by :asc or :desc for ascending or descending sorting. | Optional | 
| fields | Comma separated list of db field names to return. Default is ipProtocol, rootId, totDataBytes, srcDataBytes, dstDataBytes, firstPacket, lastPacket, srcIp, srcPort, dstIp, dstPort, totPackets, srcPackets, dstPackets, totBytes, srcBytes, dstBytes, node, http.uri, srcGEO, dstGEO, email.subject, email.src, email.dst, email.filename, dns.host, cert, irc.channel, http.xffGEO. | Optional | 
| bounding | Query sessions based on different aspects of a session’s time. Options include: ‘first’ - First Packet: the timestamp of the first packet received for the session. ‘last’ - Last Packet: The timestamp of the last packet received for the session. ‘both’ - Bounded: Both the first and last packet timestamps for the session must be inside the time window. ‘either’ - Session Overlaps: The timestamp of the first packet must be before the end of the time window AND the timestamp of the last packet must be after the start of the time window. ‘database’ - Database: The timestamp the session was written to the database. This can be up to several minutes AFTER the last packet was received. | Optional | 
| strictly | When set the entire session must be inside the date range to be observed, otherwise if it overlaps it is displayed. Overwrites the bounding parameter, sets bonding to ‘both’. | Optional | 
| limit | The number of items to return. Defaults to 100, Max is 2,000,000. | Optional | 
| page_number | The page at which to start. The default is 0. | Optional | 
| page_size | Page size. Minimum page size is 1, maximum is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.UniqueField.Field | String | The field. | 
| Arkime.UniqueField.Count | Boolean | The count. | 

#### Command example
```!arkime-multi-unique-field-list expression_field_names=destination.ip counts=1 database_field=dns.ASN```
#### Context Example
```json
{
    "Arkime": {
        "UniqueField": [
            {
                "Count": " 13573",
                "Field": "8.8.8.8"
            },
            {
                "Count": " 3321",
                "Field": "192.168.1.53"
            },
            {
                "Count": " 2846",
                "Field": "192.168.1.65"
            },
            {
                "Count": " 2837",
                "Field": "192.168.1.51"
            },
            {
                "Count": " 2441",
                "Field": "8.8.4.4"
            },
            {
                "Count": " 1404",
                "Field": "13.48.226.5"
            },
            {
                "Count": " 467",
                "Field": "192.168.1.141"
            },
            {
                "Count": " 390",
                "Field": "35.247.145.234"
            },
            {
                "Count": " 356",
                "Field": "192.168.1.64"
            },
            {
                "Count": " 312",
                "Field": "192.168.1.126"
            },
            {
                "Count": " 219",
                "Field": "169.254.169.123"
            },
            {
                "Count": " 183",
                "Field": "192.168.1.95"
            },
            {
                "Count": " 161",
                "Field": "51.124.32.246"
            },
            {
                "Count": " 161",
                "Field": "192.168.1.41"
            },
            {
                "Count": " 149",
                "Field": "224.0.0.252"
            },
            {
                "Count": " 143",
                "Field": "ff02::1:2"
            },
            {
                "Count": " 142",
                "Field": "192.168.1.113"
            },
            {
                "Count": " 126",
                "Field": "192.168.1.136"
            },
            {
                "Count": " 125",
                "Field": "192.168.1.77"
            },
            {
                "Count": " 123",
                "Field": "192.168.1.130"
            },
            {
                "Count": " 123",
                "Field": "239.255.255.250"
            },
            {
                "Count": " 118",
                "Field": "15.236.187.14"
            },
            {
                "Count": " 118",
                "Field": "15.237.17.54"
            },
            {
                "Count": " 118",
                "Field": "192.168.1.255"
            },
            {
                "Count": " 110",
                "Field": "162.159.200.123"
            },
            {
                "Count": " 104",
                "Field": "192.168.1.1"
            },
            {
                "Count": " 99",
                "Field": "40.119.148.38"
            },
            {
                "Count": " 97",
                "Field": "104.46.127.225"
            },
            {
                "Count": " 95",
                "Field": "162.159.246.125"
            },
            {
                "Count": " 90",
                "Field": "162.159.200.1"
            },
            {
                "Count": " 89",
                "Field": "192.168.1.8"
            },
            {
                "Count": " 82",
                "Field": "192.168.1.85"
            },
            {
                "Count": " 76",
                "Field": "224.0.0.253"
            },
            {
                "Count": " 72",
                "Field": "34.96.84.34"
            },
            {
                "Count": " 72",
                "Field": "184.105.176.47"
            },
            {
                "Count": " 69",
                "Field": "192.168.1.97"
            },
            {
                "Count": " 68",
                "Field": "34.69.208.173"
            },
            {
                "Count": " 60",
                "Field": "34.254.235.146"
            },
            {
                "Count": " 60",
                "Field": "154.59.123.123"
            },
            {
                "Count": " 58",
                "Field": "20.83.94.75"
            },
            {
                "Count": " 54",
                "Field": "142.250.186.110"
            },
            {
                "Count": " 52",
                "Field": "3.235.189.123"
            },
            {
                "Count": " 52",
                "Field": "ff02::16"
            },
            {
                "Count": " 50",
                "Field": "34.122.191.141"
            },
            {
                "Count": " 49",
                "Field": "255.255.255.255"
            },
            {
                "Count": " 49",
                "Field": "ff02::2"
            },
            {
                "Count": " 48",
                "Field": "168.149.132.102"
            },
            {
                "Count": " 37",
                "Field": "3.235.189.124"
            },
            {
                "Count": " 37",
                "Field": "35.202.105.28"
            },
            {
                "Count": " 36",
                "Field": "34.98.77.231"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 50 results, limit=50
>### Unique Field Results:
>|Field|Count|
>|---|---|
>| 8.8.8.8 |  13573 |
>| 192.168.1.53 |  3321 |
>| 192.168.1.65 |  2846 |
>| 192.168.1.51 |  2837 |
>| 8.8.4.4 |  2441 |
>| 13.48.226.5 |  1404 |
>| 192.168.1.141 |  467 |
>| 35.247.145.234 |  390 |
>| 192.168.1.64 |  356 |
>| 192.168.1.126 |  312 |
>| 169.254.169.123 |  219 |
>| 192.168.1.95 |  183 |
>| 51.124.32.246 |  161 |
>| 192.168.1.41 |  161 |
>| 224.0.0.252 |  149 |
>| ff02::1:2 |  143 |
>| 192.168.1.113 |  142 |
>| 192.168.1.136 |  126 |
>| 192.168.1.77 |  125 |
>| 192.168.1.130 |  123 |
>| 239.255.255.250 |  123 |
>| 15.236.187.14 |  118 |
>| 15.237.17.54 |  118 |
>| 192.168.1.255 |  118 |
>| 162.159.200.123 |  110 |
>| 192.168.1.1 |  104 |
>| 40.119.148.38 |  99 |
>| 104.46.127.225 |  97 |
>| 162.159.246.125 |  95 |
>| 162.159.200.1 |  90 |
>| 192.168.1.8 |  89 |
>| 192.168.1.85 |  82 |
>| 224.0.0.253 |  76 |
>| 34.96.84.34 |  72 |
>| 184.105.176.47 |  72 |
>| 192.168.1.97 |  69 |
>| 34.69.208.173 |  68 |
>| 34.254.235.146 |  60 |
>| 154.59.123.123 |  60 |
>| 20.83.94.75 |  58 |
>| 142.250.186.110 |  54 |
>| 3.235.189.123 |  52 |
>| ff02::16 |  52 |
>| 34.122.191.141 |  50 |
>| 255.255.255.255 |  49 |
>| ff02::2 |  49 |
>| 168.149.132.102 |  48 |
>| 3.235.189.124 |  37 |
>| 35.202.105.28 |  37 |
>| 34.98.77.231 |  36 |


#### Command example
```!arkime-multi-unique-field-list expression_field_names=destination.ip counts=0 database_field=dns.ASN```
#### Context Example
```json
{
    "Arkime": {
        "UniqueField": [
            {
                "Field": "8.8.8.8"
            },
            {
                "Field": "192.168.1.53"
            },
            {
                "Field": "192.168.1.65"
            },
            {
                "Field": "192.168.1.51"
            },
            {
                "Field": "8.8.4.4"
            },
            {
                "Field": "13.48.226.5"
            },
            {
                "Field": "192.168.1.141"
            },
            {
                "Field": "35.247.145.234"
            },
            {
                "Field": "192.168.1.64"
            },
            {
                "Field": "192.168.1.126"
            },
            {
                "Field": "169.254.169.123"
            },
            {
                "Field": "192.168.1.95"
            },
            {
                "Field": "51.124.32.246"
            },
            {
                "Field": "192.168.1.41"
            },
            {
                "Field": "224.0.0.252"
            },
            {
                "Field": "ff02::1:2"
            },
            {
                "Field": "192.168.1.113"
            },
            {
                "Field": "192.168.1.77"
            },
            {
                "Field": "192.168.1.136"
            },
            {
                "Field": "192.168.1.130"
            },
            {
                "Field": "239.255.255.250"
            },
            {
                "Field": "15.236.187.14"
            },
            {
                "Field": "15.237.17.54"
            },
            {
                "Field": "192.168.1.255"
            },
            {
                "Field": "162.159.200.123"
            },
            {
                "Field": "192.168.1.1"
            },
            {
                "Field": "40.119.148.38"
            },
            {
                "Field": "104.46.127.225"
            },
            {
                "Field": "162.159.246.125"
            },
            {
                "Field": "162.159.200.1"
            },
            {
                "Field": "192.168.1.8"
            },
            {
                "Field": "192.168.1.85"
            },
            {
                "Field": "224.0.0.253"
            },
            {
                "Field": "34.96.84.34"
            },
            {
                "Field": "184.105.176.47"
            },
            {
                "Field": "192.168.1.97"
            },
            {
                "Field": "34.69.208.173"
            },
            {
                "Field": "34.254.235.146"
            },
            {
                "Field": "154.59.123.123"
            },
            {
                "Field": "20.83.94.75"
            },
            {
                "Field": "142.250.186.110"
            },
            {
                "Field": "3.235.189.123"
            },
            {
                "Field": "ff02::16"
            },
            {
                "Field": "34.122.191.141"
            },
            {
                "Field": "255.255.255.255"
            },
            {
                "Field": "ff02::2"
            },
            {
                "Field": "168.149.132.102"
            },
            {
                "Field": "3.235.189.124"
            },
            {
                "Field": "35.202.105.28"
            },
            {
                "Field": "34.98.77.231"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 50 results, limit=50
>### Unique Field Results:
>|Field|Count|
>|---|---|
>| 8.8.8.8 |  |
>| 192.168.1.53 |  |
>| 192.168.1.65 |  |
>| 192.168.1.51 |  |
>| 8.8.4.4 |  |
>| 13.48.226.5 |  |
>| 192.168.1.141 |  |
>| 35.247.145.234 |  |
>| 192.168.1.64 |  |
>| 192.168.1.126 |  |
>| 169.254.169.123 |  |
>| 192.168.1.95 |  |
>| 51.124.32.246 |  |
>| 192.168.1.41 |  |
>| 224.0.0.252 |  |
>| ff02::1:2 |  |
>| 192.168.1.113 |  |
>| 192.168.1.77 |  |
>| 192.168.1.136 |  |
>| 192.168.1.130 |  |
>| 239.255.255.250 |  |
>| 15.236.187.14 |  |
>| 15.237.17.54 |  |
>| 192.168.1.255 |  |
>| 162.159.200.123 |  |
>| 192.168.1.1 |  |
>| 40.119.148.38 |  |
>| 104.46.127.225 |  |
>| 162.159.246.125 |  |
>| 162.159.200.1 |  |
>| 192.168.1.8 |  |
>| 192.168.1.85 |  |
>| 224.0.0.253 |  |
>| 34.96.84.34 |  |
>| 184.105.176.47 |  |
>| 192.168.1.97 |  |
>| 34.69.208.173 |  |
>| 34.254.235.146 |  |
>| 154.59.123.123 |  |
>| 20.83.94.75 |  |
>| 142.250.186.110 |  |
>| 3.235.189.123 |  |
>| ff02::16 |  |
>| 34.122.191.141 |  |
>| 255.255.255.255 |  |
>| ff02::2 |  |
>| 168.149.132.102 |  |
>| 3.235.189.124 |  |
>| 35.202.105.28 |  |
>| 34.98.77.231 |  |


### arkime-field-list
***
Gets available database field objects pertaining to sessions.


#### Base Command

`arkime-field-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| array_response | Whether to return an array of fields, otherwise returns a map. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.Field.friendlyName | String | The friendly name. | 
| Arkime.Field.type | String | The type. | 
| Arkime.Field.group | String | The group. | 
| Arkime.Field.help | String | The help. | 
| Arkime.Field.dbField | String | The dbField. | 

#### Command example
```!arkime-field-list```
#### Context Example
```json
{
    "Arkime": {
        "Field": [
            {
                "dbField": "asnall",
                "dbField2": "asnall",
                "exp": "asn",
                "friendlyName": "All ASN fields",
                "group": "general",
                "help": "Search all ASN fields",
                "regex": "(^asn\\.(?:(?!\\.cnt$).)*$|\\.asn$)",
                "type": "termfield"
            },
            {
                "dbField": "dns.ASN",
                "dbField2": "dns.ASN",
                "exp": "asn.dns",
                "friendlyName": " ASN",
                "group": "dns",
                "help": "GeoIP ASN string calculated from the IP from DNS result",
                "type": "termfield"
            },
            {
                "dbField": "dns.mailserverASN",
                "dbField2": "dns.mailserverASN",
                "exp": "asn.dns.mailserver",
                "friendlyName": " ASN",
                "group": "dns",
                "help": "GeoIP ASN string calculated from the IPs for mailservers",
                "type": "termfield"
            },
            {
                "dbField": "dns.nameserverASN",
                "dbField2": "dns.nameserverASN",
                "exp": "asn.dns.nameserver",
                "friendlyName": " ASN",
                "group": "dns",
                "help": "GeoIP ASN string calculated from the IPs for nameservers",
                "type": "termfield"
            },
            {
                "category": "asn",
                "dbField": "destination.as.full",
                "dbField2": "dstASN",
                "exp": "asn.dst",
                "fieldECS": "destination.as.full",
                "friendlyName": "Dst ASN",
                "group": "general",
                "help": "GeoIP ASN string calculated from the destination IP",
                "type": "termfield"
            },
            {
                "dbField": "email.ASN",
                "dbField2": "email.ASN",
                "exp": "asn.email",
                "friendlyName": " ASN",
                "group": "email",
                "help": "GeoIP ASN string calculated from the Email IP address",
                "type": "termfield"
            },
            {
                "dbField": "socks.ASN",
                "dbField2": "socks.ASN",
                "exp": "asn.socks",
                "friendlyName": " ASN",
                "group": "socks",
                "help": "GeoIP ASN string calculated from the SOCKS destination IP",
                "type": "termfield"
            },
            {
                "category": "asn",
                "dbField": "source.as.full",
                "dbField2": "srcASN",
                "exp": "asn.src",
                "fieldECS": "source.as.full",
                "friendlyName": "Src ASN",
                "group": "general",
                "help": "GeoIP ASN string calculated from the source IP",
                "type": "termfield"
            },
            {
                "dbField": "http.xffASN",
                "dbField2": "http.xffASN",
                "exp": "asn.xff",
                "friendlyName": "XFF  ASN",
                "group": "http",
                "help": "GeoIP ASN string calculated from the X-Forwarded-For Header",
                "type": "termfield"
            },
            {
                "dbField": "asset",
                "dbField2": "asset",
                "exp": "asset",
                "friendlyName": "Asset",
                "group": "general",
                "help": "Asset name",
                "type": "lotermfield"
            },
            {
                "dbField": "assetCnt",
                "dbField2": "assetCnt",
                "exp": "asset.cnt",
                "friendlyName": "Asset Cnt",
                "group": "general",
                "help": "Unique number of Asset name",
                "type": "integer"
            },
            {
                "dbField": "bgp.type",
                "dbField2": "bgp.type",
                "exp": "bgp.type",
                "friendlyName": "Type",
                "group": "bgp",
                "help": "BGP Type field",
                "type": "uptermfield"
            },
            {
                "dbField": "network.bytes",
                "dbField2": "totBytes",
                "exp": "bytes",
                "fieldECS": "network.bytes",
                "friendlyName": "Bytes",
                "group": "general",
                "help": "Total number of raw bytes sent AND received in a session",
                "type": "integer"
            },
            {
                "dbField": "destination.bytes",
                "dbField2": "dstBytes",
                "exp": "bytes.dst",
                "fieldECS": "destination.bytes",
                "friendlyName": "Dst Bytes",
                "group": "general",
                "help": "Total number of raw bytes sent by destination in a session",
                "type": "integer"
            },
            {
                "dbField": "source.bytes",
                "dbField2": "srcBytes",
                "exp": "bytes.src",
                "fieldECS": "source.bytes",
                "friendlyName": "Src Bytes",
                "group": "general",
                "help": "Total number of raw bytes sent by source in a session",
                "type": "integer"
            },
            {
                "dbField": "cert.alt",
                "dbField2": "cert.alt",
                "exp": "cert.alt",
                "friendlyName": "Alt Name",
                "group": "cert",
                "help": "Certificate alternative names",
                "type": "lotermfield"
            },
            {
                "dbField": "cert.altCnt",
                "dbField2": "cert.altCnt",
                "exp": "cert.alt.cnt",
                "friendlyName": "Alt Name Cnt",
                "group": "cert",
                "help": "Unique number of Certificate alternative names",
                "type": "integer"
            },
            {
                "dbField": "certCnt",
                "dbField2": "certCnt",
                "exp": "cert.cnt",
                "friendlyName": "Cert Cnt",
                "group": "cert",
                "help": "Count of certificates",
                "type": "integer"
            },
            {
                "dbField": "cert.curve",
                "dbField2": "cert.curve",
                "exp": "cert.curve",
                "friendlyName": "Curve",
                "group": "cert",
                "help": "Curve Algorithm",
                "type": "termfield"
            },
            {
                "dbField": "cert.hash",
                "dbField2": "cert.hash",
                "exp": "cert.hash",
                "friendlyName": "Hash",
                "group": "cert",
                "help": "SHA1 hash of entire certificate",
                "type": "lotermfield"
            },
            {
                "dbField": "cert.issuerCN",
                "dbField2": "cert.issuerCN",
                "exp": "cert.issuer.cn",
                "friendlyName": "Issuer CN",
                "group": "cert",
                "help": "Issuer's common name",
                "type": "lotermfield"
            },
            {
                "dbField": "cert.issuerON",
                "dbField2": "cert.issuerON",
                "exp": "cert.issuer.on",
                "friendlyName": "Issuer ON",
                "group": "cert",
                "help": "Issuer's organization name",
                "type": "termfield"
            },
            {
                "dbField": "cert.notAfter",
                "dbField2": "cert.notAfter",
                "exp": "cert.notafter",
                "friendlyName": "Not After",
                "group": "cert",
                "help": "Certificate is not valid after this date",
                "type": "date"
            },
            {
                "dbField": "cert.notBefore",
                "dbField2": "cert.notBefore",
                "exp": "cert.notbefore",
                "friendlyName": "Not Before",
                "group": "cert",
                "help": "Certificate is not valid before this date",
                "type": "date"
            },
            {
                "dbField": "cert.publicAlgorithm",
                "dbField2": "cert.publicAlgorithm",
                "exp": "cert.publicAlgorithm",
                "friendlyName": "Public Algorithm",
                "group": "cert",
                "help": "Public Key Algorithm",
                "type": "termfield"
            },
            {
                "dbField": "cert.remainingDays",
                "dbField2": "cert.remainingDays",
                "exp": "cert.remainingDays",
                "friendlyName": "Days remaining",
                "group": "cert",
                "help": "Certificate is still valid for this many days",
                "type": "integer"
            },
            {
                "dbField": "cert.serial",
                "dbField2": "cert.serial",
                "exp": "cert.serial",
                "friendlyName": "Serial Number",
                "group": "cert",
                "help": "Serial Number",
                "type": "lotermfield"
            },
            {
                "dbField": "cert.subjectCN",
                "dbField2": "cert.subjectCN",
                "exp": "cert.subject.cn",
                "friendlyName": "Subject CN",
                "group": "cert",
                "help": "Subject's common name",
                "type": "lotermfield"
            },
            {
                "dbField": "cert.subjectON",
                "dbField2": "cert.subjectON",
                "exp": "cert.subject.on",
                "friendlyName": "Subject ON",
                "group": "cert",
                "help": "Subject's organization name",
                "type": "termfield"
            },
            {
                "dbField": "cert.validDays",
                "dbField2": "cert.validDays",
                "exp": "cert.validfor",
                "friendlyName": "Days Valid For",
                "group": "cert",
                "help": "Certificate is valid for this many days total",
                "type": "integer"
            },
            {
                "dbField": "network.community_id",
                "dbField2": "communityId",
                "exp": "communityId",
                "fieldECS": "network.community_id",
                "friendlyName": "Community Id",
                "group": "general",
                "help": "Community id flow hash",
                "type": "termfield"
            },
            {
                "dbField": "geoall",
                "dbField2": "geoall",
                "exp": "country",
                "friendlyName": "All country fields",
                "group": "general",
                "help": "Search all country fields",
                "regex": "(^country\\.(?:(?!\\.cnt$).)*$|\\.country$)",
                "type": "uptermfield"
            },
            {
                "dbField": "dns.GEO",
                "dbField2": "dns.GEO",
                "exp": "country.dns",
                "friendlyName": " GEO",
                "group": "dns",
                "help": "GeoIP country string calculated from the IP from DNS result",
                "type": "uptermfield"
            },
            {
                "dbField": "dns.mailserverGEO",
                "dbField2": "dns.mailserverGEO",
                "exp": "country.dns.mailserver",
                "friendlyName": " GEO",
                "group": "dns",
                "help": "GeoIP country string calculated from the IPs for mailservers",
                "type": "uptermfield"
            },
            {
                "dbField": "dns.nameserverGEO",
                "dbField2": "dns.nameserverGEO",
                "exp": "country.dns.nameserver",
                "friendlyName": " GEO",
                "group": "dns",
                "help": "GeoIP country string calculated from the IPs for nameservers",
                "type": "uptermfield"
            },
            {
                "category": "country",
                "dbField": "destination.geo.country_iso_code",
                "dbField2": "dstGEO",
                "exp": "country.dst",
                "fieldECS": "destination.geo.country_iso_code",
                "friendlyName": "Dst Country",
                "group": "general",
                "help": "Destination Country",
                "type": "uptermfield"
            },
            {
                "dbField": "email.GEO",
                "dbField2": "email.GEO",
                "exp": "country.email",
                "friendlyName": " GEO",
                "group": "email",
                "help": "GeoIP country string calculated from the Email IP address",
                "type": "uptermfield"
            },
            {
                "dbField": "socks.GEO",
                "dbField2": "socks.GEO",
                "exp": "country.socks",
                "friendlyName": " GEO",
                "group": "socks",
                "help": "GeoIP country string calculated from the SOCKS destination IP",
                "type": "uptermfield"
            },
            {
                "category": "country",
                "dbField": "source.geo.country_iso_code",
                "dbField2": "srcGEO",
                "exp": "country.src",
                "fieldECS": "source.geo.country_iso_code",
                "friendlyName": "Src Country",
                "group": "general",
                "help": "Source Country",
                "type": "uptermfield"
            },
            {
                "dbField": "http.xffGEO",
                "dbField2": "http.xffGEO",
                "exp": "country.xff",
                "friendlyName": "XFF  GEO",
                "group": "http",
                "help": "GeoIP country string calculated from the X-Forwarded-For Header",
                "type": "uptermfield"
            },
            {
                "dbField": "totDataBytes",
                "dbField2": "totDataBytes",
                "exp": "databytes",
                "friendlyName": "Data bytes",
                "group": "general",
                "help": "Total number of data bytes sent AND received in a session",
                "type": "integer"
            },
            {
                "dbField": "server.bytes",
                "dbField2": "dstDataBytes",
                "exp": "databytes.dst",
                "fieldECS": "server.bytes",
                "friendlyName": "Dst data bytes",
                "group": "general",
                "help": "Total number of data bytes sent by destination in a session",
                "type": "integer"
            },
            {
                "dbField": "client.bytes",
                "dbField2": "srcDataBytes",
                "exp": "databytes.src",
                "fieldECS": "client.bytes",
                "friendlyName": "Src data bytes",
                "group": "general",
                "help": "Total number of data bytes sent by source in a session",
                "type": "integer"
            },
            {
                "dbField": "destination.as.number",
                "exp": "destination.as.number",
                "fieldECS": "destination.as.number",
                "friendlyName": "Dst ASN Number",
                "group": "general",
                "help": "GeoIP ASN Number calculated from the destination IP",
                "type": "integer"
            },
            {
                "dbField": "destination.as.organization.name",
                "exp": "destination.as.organization.name",
                "fieldECS": "destination.as.organization.name",
                "friendlyName": "Dst ASN Name",
                "group": "general",
                "help": "GeoIP ASN Name calculated from the destination IP",
                "type": "termfield"
            },
            {
                "aliases": [
                    "host.dhcp"
                ],
                "category": "host",
                "dbField": "dhcp.host",
                "dbField2": "dhcp.host",
                "exp": "dhcp.host",
                "friendlyName": "Host",
                "group": "dhcp",
                "help": "DHCP Host",
                "type": "lotermfield"
            },
            {
                "dbField": "dhcp.hostCnt",
                "dbField2": "dhcp.hostCnt",
                "exp": "dhcp.host.cnt",
                "friendlyName": "Host Cnt",
                "group": "dhcp",
                "help": "Unique number of DHCP Host",
                "type": "integer"
            },
            {
                "aliases": [
                    "host.dhcp.tokens"
                ],
                "dbField": "dhcp.hostTokens",
                "dbField2": "dhcp.hostTokens",
                "exp": "dhcp.host.tokens",
                "friendlyName": "Hostname Tokens",
                "group": "dhcp",
                "help": "DHCP Hostname Tokens",
                "type": "lotextfield"
            },
            {
                "dbField": "dhcp.id",
                "dbField2": "dhcp.id",
                "exp": "dhcp.id",
                "friendlyName": "Transaction id",
                "group": "dhcp",
                "help": "DHCP Transaction Id",
                "type": "lotermfield"
            },
            {
                "dbField": "dhcp.idCnt",
                "dbField2": "dhcp.idCnt",
                "exp": "dhcp.id.cnt",
                "friendlyName": "Transaction id Cnt",
                "group": "dhcp",
                "help": "Unique number of DHCP Transaction Id",
                "type": "integer"
            },
            {
                "dbField": "dhcp.mac",
                "dbField2": "dhcp.mac",
                "exp": "dhcp.mac",
                "friendlyName": "Client MAC",
                "group": "dhcp",
                "help": "Client ethernet MAC ",
                "type": "lotermfield"
            },
            {
                "dbField": "dhcp.macCnt",
                "dbField2": "dhcp.macCnt",
                "exp": "dhcp.mac.cnt",
                "friendlyName": "Client MAC Cnt",
                "group": "dhcp",
                "help": "Unique number of Client ethernet MAC ",
                "type": "integer"
            },
            {
                "dbField": "dhcp.oui",
                "dbField2": "dhcp.oui",
                "exp": "dhcp.oui",
                "friendlyName": "Client OUI",
                "group": "dhcp",
                "help": "Client ethernet OUI ",
                "type": "termfield"
            },
            {
                "dbField": "dhcp.ouiCnt",
                "dbField2": "dhcp.ouiCnt",
                "exp": "dhcp.oui.cnt",
                "friendlyName": "Client OUI Cnt",
                "group": "dhcp",
                "help": "Unique number of Client ethernet OUI ",
                "type": "integer"
            },
            {
                "dbField": "dhcp.type",
                "dbField2": "dhcp.type",
                "exp": "dhcp.type",
                "friendlyName": "Type",
                "group": "dhcp",
                "help": "DHCP Type",
                "type": "uptermfield"
            },
            {
                "dbField": "dhcp.typeCnt",
                "dbField2": "dhcp.typeCnt",
                "exp": "dhcp.type.cnt",
                "friendlyName": "Type Cnt",
                "group": "dhcp",
                "help": "Unique number of DHCP Type",
                "type": "integer"
            },
            {
                "dbField": "dns.opcode",
                "dbField2": "dns.opcode",
                "exp": "dns.opcode",
                "friendlyName": "Op Code",
                "group": "dns",
                "help": "DNS lookup op code",
                "type": "uptermfield"
            },
            {
                "dbField": "dns.opcodeCnt",
                "dbField2": "dns.opcodeCnt",
                "exp": "dns.opcode.cnt",
                "friendlyName": "Op Code Cnt",
                "group": "dns",
                "help": "Unique number of DNS lookup op code",
                "type": "integer"
            },
            {
                "dbField": "dns.puny",
                "dbField2": "dns.puny",
                "exp": "dns.puny",
                "friendlyName": "Puny",
                "group": "dns",
                "help": "DNS lookup punycode",
                "type": "lotermfield"
            },
            {
                "dbField": "dns.punyCnt",
                "dbField2": "dns.punyCnt",
                "exp": "dns.puny.cnt",
                "friendlyName": "Puny Cnt",
                "group": "dns",
                "help": "Unique number of DNS lookup punycode",
                "type": "integer"
            },
            {
                "dbField": "dns.qc",
                "dbField2": "dns.qc",
                "exp": "dns.query.class",
                "friendlyName": "Query Class",
                "group": "dns",
                "help": "DNS lookup query class",
                "type": "uptermfield"
            },
            {
                "dbField": "dns.qcCnt",
                "dbField2": "dns.qcCnt",
                "exp": "dns.query.class.cnt",
                "friendlyName": "Query Class Cnt",
                "group": "dns",
                "help": "Unique number of DNS lookup query class",
                "type": "integer"
            },
            {
                "dbField": "dns.qt",
                "dbField2": "dns.qt",
                "exp": "dns.query.type",
                "friendlyName": "Query Type",
                "group": "dns",
                "help": "DNS lookup query type",
                "type": "uptermfield"
            },
            {
                "dbField": "dns.qtCnt",
                "dbField2": "dns.qtCnt",
                "exp": "dns.query.type.cnt",
                "friendlyName": "Query Type Cnt",
                "group": "dns",
                "help": "Unique number of DNS lookup query type",
                "type": "integer"
            },
            {
                "dbField": "dns.status",
                "dbField2": "dns.status",
                "exp": "dns.status",
                "friendlyName": "Status Code",
                "group": "dns",
                "help": "DNS lookup return code",
                "type": "uptermfield"
            },
            {
                "dbField": "dns.statusCnt",
                "dbField2": "dns.statusCnt",
                "exp": "dns.status.cnt",
                "friendlyName": "Status Code Cnt",
                "group": "dns",
                "help": "Unique number of DNS lookup return code",
                "type": "integer"
            },
            {
                "dbField": "dstDscp",
                "dbField2": "dstDscp",
                "exp": "dscp.dst",
                "friendlyName": "Dst DSCP",
                "group": "general",
                "help": "Destination non zero differentiated services class selector set for session",
                "type": "integer"
            },
            {
                "dbField": "dstDscpCnt",
                "dbField2": "dstDscpCnt",
                "exp": "dscp.dst.cnt",
                "friendlyName": "Dst DSCP Cnt",
                "group": "general",
                "help": "Unique number of Destination non zero differentiated services class selector set for session",
                "type": "integer"
            },
            {
                "dbField": "srcDscp",
                "dbField2": "srcDscp",
                "exp": "dscp.src",
                "friendlyName": "Src DSCP",
                "group": "general",
                "help": "Source non zero differentiated services class selector set for session",
                "type": "integer"
            },
            {
                "dbField": "srcDscpCnt",
                "dbField2": "srcDscpCnt",
                "exp": "dscp.src.cnt",
                "friendlyName": "Src DSCP Cnt",
                "group": "general",
                "help": "Unique number of Source non zero differentiated services class selector set for session",
                "type": "integer"
            },
            {
                "dbField": "email.header-authorization",
                "dbField2": "email.header-authorization",
                "exp": "email.authorization",
                "friendlyName": "email.authorization",
                "group": "email",
                "help": "Email header authorization",
                "type": "termfield"
            },
            {
                "dbField": "email.bodyMagic",
                "dbField2": "email.bodyMagic",
                "exp": "email.bodymagic",
                "friendlyName": "Body Magic",
                "group": "email",
                "help": "The content type of body determined by libfile/magic",
                "type": "termfield"
            },
            {
                "dbField": "email.bodyMagicCnt",
                "dbField2": "email.bodyMagicCnt",
                "exp": "email.bodymagic.cnt",
                "friendlyName": "Body Magic Cnt",
                "group": "email",
                "help": "Unique number of The content type of body determined by libfile/magic",
                "type": "integer"
            },
            {
                "dbField": "email.contentType",
                "dbField2": "email.contentType",
                "exp": "email.content-type",
                "friendlyName": "Content-Type",
                "group": "email",
                "help": "Email content-type header",
                "type": "termfield"
            },
            {
                "dbField": "email.contentTypeCnt",
                "dbField2": "email.contentTypeCnt",
                "exp": "email.content-type.cnt",
                "friendlyName": "Content-Type Cnt",
                "group": "email",
                "help": "Unique number of Email content-type header",
                "type": "integer"
            },
            {
                "category": "user",
                "dbField": "email.dst",
                "dbField2": "email.dst",
                "exp": "email.dst",
                "friendlyName": "Receiver",
                "group": "email",
                "help": "Email to address",
                "requiredRight": "emailSearch",
                "type": "lotermfield"
            },
            {
                "dbField": "email.dstCnt",
                "dbField2": "email.dstCnt",
                "exp": "email.dst.cnt",
                "friendlyName": "Receiver Cnt",
                "group": "email",
                "help": "Unique number of Email to address",
                "type": "integer"
            },
            {
                "dbField": "email.fileContentType",
                "dbField2": "email.fileContentType",
                "exp": "email.file-content-type",
                "friendlyName": "Attach Content-Type",
                "group": "email",
                "help": "Email attachment content types",
                "requiredRight": "emailSearch",
                "type": "termfield"
            },
            {
                "dbField": "email.fileContentTypeCnt",
                "dbField2": "email.fileContentTypeCnt",
                "exp": "email.file-content-type.cnt",
                "friendlyName": "Attach Content-Type Cnt",
                "group": "email",
                "help": "Unique number of Email attachment content types",
                "type": "integer"
            },
            {
                "dbField": "email.filename",
                "dbField2": "email.filename",
                "exp": "email.fn",
                "friendlyName": "Filenames",
                "group": "email",
                "help": "Email attachment filenames",
                "requiredRight": "emailSearch",
                "type": "termfield"
            },
            {
                "dbField": "email.filenameCnt",
                "dbField2": "email.filenameCnt",
                "exp": "email.fn.cnt",
                "friendlyName": "Filenames Cnt",
                "group": "email",
                "help": "Unique number of Email attachment filenames",
                "type": "integer"
            },
            {
                "dbField": "email.header",
                "dbField2": "email.header",
                "exp": "email.has-header",
                "friendlyName": "Header",
                "group": "email",
                "help": "Email has the header set",
                "requiredRight": "emailSearch",
                "type": "lotermfield"
            },
            {
                "dbField": "email.headerCnt",
                "dbField2": "email.headerCnt",
                "exp": "email.has-header.cnt",
                "friendlyName": "Header Cnt",
                "group": "email",
                "help": "Unique number of Email has the header set",
                "type": "integer"
            },
            {
                "dbField": "email.headerValue",
                "dbField2": "email.headerValue",
                "exp": "email.has-header.value",
                "friendlyName": "Header Value",
                "group": "email",
                "help": "Email has the header value",
                "requiredRight": "emailSearch",
                "type": "termfield"
            },
            {
                "dbField": "email.headerValueCnt",
                "dbField2": "email.headerValueCnt",
                "exp": "email.has-header.value.cnt",
                "friendlyName": "Header Value Cnt",
                "group": "email",
                "help": "Unique number of Email has the header value",
                "type": "integer"
            },
            {
                "category": "md5",
                "dbField": "email.md5",
                "dbField2": "email.md5",
                "exp": "email.md5",
                "friendlyName": "Attach MD5s",
                "group": "email",
                "help": "Email attachment MD5s",
                "requiredRight": "emailSearch",
                "type": "termfield"
            },
            {
                "dbField": "email.md5Cnt",
                "dbField2": "email.md5Cnt",
                "exp": "email.md5.cnt",
                "friendlyName": "Attach MD5s Cnt",
                "group": "email",
                "help": "Unique number of Email attachment MD5s",
                "type": "integer"
            },
            {
                "dbField": "email.id",
                "dbField2": "email.id",
                "exp": "email.message-id",
                "friendlyName": "Id",
                "group": "email",
                "help": "Email Message-Id header",
                "requiredRight": "emailSearch",
                "type": "termfield"
            },
            {
                "dbField": "email.idCnt",
                "dbField2": "email.idCnt",
                "exp": "email.message-id.cnt",
                "friendlyName": "Id Cnt",
                "group": "email",
                "help": "Unique number of Email Message-Id header",
                "type": "integer"
            },
            {
                "dbField": "email.mimeVersion",
                "dbField2": "email.mimeVersion",
                "exp": "email.mime-version",
                "friendlyName": "Mime-Version",
                "group": "email",
                "help": "Email Mime-Header header",
                "type": "termfield"
            },
            {
                "dbField": "email.mimeVersionCnt",
                "dbField2": "email.mimeVersionCnt",
                "exp": "email.mime-version.cnt",
                "friendlyName": "Mime-Version Cnt",
                "group": "email",
                "help": "Unique number of Email Mime-Header header",
                "type": "integer"
            },
            {
                "dbField": "email.smtpHello",
                "dbField2": "email.smtpHello",
                "exp": "email.smtp-hello",
                "friendlyName": "SMTP Hello",
                "group": "email",
                "help": "SMTP HELO/EHLO",
                "type": "lotermfield"
            },
            {
                "dbField": "email.smtpHelloCnt",
                "dbField2": "email.smtpHelloCnt",
                "exp": "email.smtp-hello.cnt",
                "friendlyName": "SMTP Hello Cnt",
                "group": "email",
                "help": "Unique number of SMTP HELO/EHLO",
                "type": "integer"
            },
            {
                "category": "user",
                "dbField": "email.src",
                "dbField2": "email.src",
                "exp": "email.src",
                "friendlyName": "Sender",
                "group": "email",
                "help": "Email from address",
                "requiredRight": "emailSearch",
                "type": "lotermfield"
            },
            {
                "dbField": "email.srcCnt",
                "dbField2": "email.srcCnt",
                "exp": "email.src.cnt",
                "friendlyName": "Sender Cnt",
                "group": "email",
                "help": "Unique number of Email from address",
                "type": "integer"
            },
            {
                "dbField": "email.subject",
                "dbField2": "email.subject",
                "exp": "email.subject",
                "friendlyName": "Subject",
                "group": "email",
                "help": "Email subject header",
                "requiredRight": "emailSearch",
                "type": "termfield"
            },
            {
                "dbField": "email.subjectCnt",
                "dbField2": "email.subjectCnt",
                "exp": "email.subject.cnt",
                "friendlyName": "Subject Cnt",
                "group": "email",
                "help": "Unique number of Email subject header",
                "type": "integer"
            },
            {
                "dbField": "email.useragent",
                "dbField2": "email.useragent",
                "exp": "email.x-mailer",
                "friendlyName": "X-Mailer Header",
                "group": "email",
                "help": "Email X-Mailer header",
                "requiredRight": "emailSearch",
                "type": "termfield"
            },
            {
                "dbField": "email.useragentCnt",
                "dbField2": "email.useragentCnt",
                "exp": "email.x-mailer.cnt",
                "friendlyName": "X-Mailer Header Cnt",
                "group": "email",
                "help": "Unique number of Email X-Mailer header",
                "type": "integer"
            },
            {
                "dbField": "email.header-x-priority",
                "dbField2": "email.header-x-priority",
                "exp": "email.x-priority",
                "friendlyName": "email.x-priority",
                "group": "email",
                "help": "Email header x-priority",
                "type": "integer"
            },
            {
                "dbField": "fileand",
                "dbField2": "fileand",
                "exp": "file",
                "friendlyName": "Filename",
                "group": "general",
                "help": "Arkime offline pcap filename",
                "type": "fileand"
            },
            {
                "dbField": "greIp",
                "dbField2": "greIp",
                "exp": "gre.ip",
                "friendlyName": "GRE IP",
                "group": "general",
                "help": "GRE ip addresses for session",
                "type": "ip"
            },
            {
                "dbField": "greASN",
                "dbField2": "greASN",
                "exp": "gre.ip.asn",
                "friendlyName": "GRE IP ASN",
                "group": "general",
                "help": "GeoIP ASN string calculated from the GRE ip addresses for session",
                "type": "termfield"
            },
            {
                "dbField": "greIpCnt",
                "dbField2": "greIpCnt",
                "exp": "gre.ip.cnt",
                "friendlyName": "GRE IP Cnt",
                "group": "general",
                "help": "Unique number of GRE ip addresses for session",
                "type": "integer"
            },
            {
                "dbField": "greGEO",
                "dbField2": "greGEO",
                "exp": "gre.ip.country",
                "friendlyName": "GRE IP GEO",
                "group": "general",
                "help": "GeoIP country string calculated from the GRE ip addresses for session",
                "type": "uptermfield"
            },
            {
                "dbField": "greRIR",
                "dbField2": "greRIR",
                "exp": "gre.ip.rir",
                "friendlyName": "GRE IP RIR",
                "group": "general",
                "help": "Regional Internet Registry string calculated from GRE ip addresses for session",
                "type": "uptermfield"
            },
            {
                "dbField": "hostall",
                "dbField2": "hostall",
                "exp": "host",
                "friendlyName": "All Host fields",
                "group": "general",
                "help": "Search all Host fields",
                "regex": "(^host\\.(?:(?!\\.(cnt|tokens)$).)*$|\\.host$)",
                "transform": "removeProtocolAndURI",
                "type": "lotermfield"
            },
            {
                "aliases": [
                    "dns.host"
                ],
                "category": "host",
                "dbField": "dns.host",
                "dbField2": "dns.host",
                "exp": "host.dns",
                "friendlyName": "Host",
                "group": "dns",
                "help": "DNS lookup hostname",
                "transform": "removeProtocolAndURI",
                "type": "lotermfield"
            },
            {
                "dbField": "dnshostall",
                "dbField2": "dnshostall",
                "exp": "host.dns.all",
                "friendlyName": "All Host",
                "group": "dns",
                "help": "Shorthand for host.dns or host.dns.nameserver",
                "regex": "^host\\.dns(?:(?!\\.(cnt|all)$).)*$",
                "transform": "removeProtocolAndURI",
                "type": "lotermfield"
            },
            {
                "dbField": "dns.hostCnt",
                "dbField2": "dns.hostCnt",
                "exp": "host.dns.cnt",
                "friendlyName": "Host Cnt",
                "group": "dns",
                "help": "Unique number of DNS lookup hostname",
                "transform": "removeProtocolAndURI",
                "type": "integer"
            },
            {
                "category": "host",
                "dbField": "dns.mailserverHost",
                "dbField2": "dns.mailserverHost",
                "exp": "host.dns.mailserver",
                "friendlyName": "MX Host",
                "group": "dns",
                "help": "Hostnames for Mail Exchange Server",
                "transform": "removeProtocolAndURI",
                "type": "lotermfield"
            },
            {
                "dbField": "dns.mailserverHostCnt",
                "dbField2": "dns.mailserverHostCnt",
                "exp": "host.dns.mailserver.cnt",
                "friendlyName": "MX Host Cnt",
                "group": "dns",
                "help": "Unique number of Hostnames for Mail Exchange Server",
                "transform": "removeProtocolAndURI",
                "type": "integer"
            },
            {
                "category": "host",
                "dbField": "dns.nameserverHost",
                "dbField2": "dns.nameserverHost",
                "exp": "host.dns.nameserver",
                "friendlyName": "NS Host",
                "group": "dns",
                "help": "Hostnames for Name Server",
                "transform": "removeProtocolAndURI",
                "type": "lotermfield"
            },
            {
                "dbField": "dns.nameserverHostCnt",
                "dbField2": "dns.nameserverHostCnt",
                "exp": "host.dns.nameserver.cnt",
                "friendlyName": "NS Host Cnt",
                "group": "dns",
                "help": "Unique number of Hostnames for Name Server",
                "transform": "removeProtocolAndURI",
                "type": "integer"
            },
            {
                "aliases": [
                    "dns.host.tokens"
                ],
                "dbField": "dns.hostTokens",
                "dbField2": "dns.hostTokens",
                "exp": "host.dns.tokens",
                "friendlyName": "Hostname Tokens",
                "group": "dns",
                "help": "DNS lookup hostname tokens",
                "transform": "removeProtocolAndURI",
                "type": "lotextfield"
            },
            {
                "aliases": [
                    "email.host"
                ],
                "category": "host",
                "dbField": "email.host",
                "dbField2": "email.host",
                "exp": "host.email",
                "friendlyName": "Hostname",
                "group": "email",
                "help": "Email hostnames",
                "requiredRight": "emailSearch",
                "transform": "removeProtocolAndURI",
                "type": "lotermfield"
            },
            {
                "dbField": "email.hostCnt",
                "dbField2": "email.hostCnt",
                "exp": "host.email.cnt",
                "friendlyName": "Hostname Cnt",
                "group": "email",
                "help": "Unique number of Email hostnames",
                "transform": "removeProtocolAndURI",
                "type": "integer"
            },
            {
                "aliases": [
                    "email.host.tokens"
                ],
                "dbField": "email.hostTokens",
                "dbField2": "email.hostTokens",
                "exp": "host.email.tokens",
                "friendlyName": "Hostname Tokens",
                "group": "email",
                "help": "Email Hostname Tokens",
                "requiredRight": "emailSearch",
                "transform": "removeProtocolAndURI",
                "type": "lotextfield"
            },
            {
                "aliases": [
                    "http.host"
                ],
                "category": "host",
                "dbField": "http.host",
                "dbField2": "http.host",
                "exp": "host.http",
                "friendlyName": "Hostname",
                "group": "http",
                "help": "HTTP host header field",
                "transform": "removeProtocolAndURI",
                "type": "lotermfield"
            },
            {
                "dbField": "http.hostCnt",
                "dbField2": "http.hostCnt",
                "exp": "host.http.cnt",
                "friendlyName": "Hostname Cnt",
                "group": "http",
                "help": "Unique number of HTTP host header field",
                "transform": "removeProtocolAndURI",
                "type": "integer"
            },
            {
                "aliases": [
                    "http.host.tokens"
                ],
                "dbField": "http.hostTokens",
                "dbField2": "http.hostTokens",
                "exp": "host.http.tokens",
                "friendlyName": "Hostname Tokens",
                "group": "http",
                "help": "HTTP host Tokens header field",
                "transform": "removeProtocolAndURI",
                "type": "lotextfield"
            },
            {
                "aliases": [
                    "quic.host"
                ],
                "category": "host",
                "dbField": "quic.host",
                "dbField2": "quic.host",
                "exp": "host.quic",
                "friendlyName": "Hostname",
                "group": "quic",
                "help": "QUIC host header field",
                "transform": "removeProtocolAndURI",
                "type": "lotermfield"
            },
            {
                "dbField": "quic.hostCnt",
                "dbField2": "quic.hostCnt",
                "exp": "host.quic.cnt",
                "friendlyName": "Hostname Cnt",
                "group": "quic",
                "help": "Unique number of QUIC host header field",
                "transform": "removeProtocolAndURI",
                "type": "integer"
            },
            {
                "aliases": [
                    "quic.host.tokens"
                ],
                "dbField": "quic.hostTokens",
                "dbField2": "quic.hostTokens",
                "exp": "host.quic.tokens",
                "friendlyName": "Hostname Tokens",
                "group": "quic",
                "help": "QUIC host tokens header field",
                "transform": "removeProtocolAndURI",
                "type": "lotextfield"
            },
            {
                "aliases": [
                    "smb.host"
                ],
                "category": "host",
                "dbField": "smb.host",
                "dbField2": "smb.host",
                "exp": "host.smb",
                "friendlyName": "Hostname",
                "group": "smb",
                "help": "SMB Host name",
                "transform": "removeProtocolAndURI",
                "type": "termfield"
            },
            {
                "dbField": "smb.hostCnt",
                "dbField2": "smb.hostCnt",
                "exp": "host.smb.cnt",
                "friendlyName": "Hostname Cnt",
                "group": "smb",
                "help": "Unique number of SMB Host name",
                "transform": "removeProtocolAndURI",
                "type": "integer"
            },
            {
                "aliases": [
                    "socks.host"
                ],
                "category": "host",
                "dbField": "socks.host",
                "dbField2": "socks.host",
                "exp": "host.socks",
                "friendlyName": "Host",
                "group": "socks",
                "help": "SOCKS destination host",
                "transform": "removeProtocolAndURI",
                "type": "lotermfield"
            },
            {
                "aliases": [
                    "socks.host.tokens"
                ],
                "dbField": "socks.hostTokens",
                "dbField2": "socks.hostTokens",
                "exp": "host.socks.tokens",
                "friendlyName": "Hostname Tokens",
                "group": "socks",
                "help": "SOCKS Hostname Tokens",
                "transform": "removeProtocolAndURI",
                "type": "lotextfield"
            },
            {
                "dbField": "http.request-authorization",
                "dbField2": "http.request-authorization",
                "exp": "http.authorization",
                "friendlyName": "http.authorization",
                "group": "http",
                "help": "Request header authorization",
                "type": "termfield"
            },
            {
                "dbField": "http.request-authorizationCnt",
                "dbField2": "http.request-authorizationCnt",
                "exp": "http.authorization.cnt",
                "friendlyName": "http.authorization Cnt",
                "group": "http",
                "help": "Unique number of Request header authorization",
                "type": "integer"
            },
            {
                "dbField": "http.authType",
                "dbField2": "http.authType",
                "exp": "http.authtype",
                "friendlyName": "Auth Type",
                "group": "http",
                "help": "HTTP Auth Type",
                "type": "lotermfield"
            },
            {
                "dbField": "http.authTypeCnt",
                "dbField2": "http.authTypeCnt",
                "exp": "http.authtype.cnt",
                "friendlyName": "Auth Type Cnt",
                "group": "http",
                "help": "Unique number of HTTP Auth Type",
                "type": "integer"
            },
            {
                "dbField": "http.bodyMagic",
                "dbField2": "http.bodyMagic",
                "exp": "http.bodymagic",
                "friendlyName": "Body Magic",
                "group": "http",
                "help": "The content type of body determined by libfile/magic",
                "type": "termfield"
            },
            {
                "dbField": "http.bodyMagicCnt",
                "dbField2": "http.bodyMagicCnt",
                "exp": "http.bodymagic.cnt",
                "friendlyName": "Body Magic Cnt",
                "group": "http",
                "help": "Unique number of The content type of body determined by libfile/magic",
                "type": "integer"
            },
            {
                "dbField": "http.request-content-type",
                "dbField2": "http.request-content-type",
                "exp": "http.content-type",
                "friendlyName": "http.content-type",
                "group": "http",
                "help": "Request header content-type",
                "type": "termfield"
            },
            {
                "dbField": "http.response-content-typeCnt",
                "dbField2": "http.response-content-typeCnt",
                "exp": "http.content-type.cnt",
                "friendlyName": "http.content-type Cnt",
                "group": "http",
                "help": "Unique number of Response header content-type",
                "type": "integer"
            },
            {
                "dbField": "http.cookieKey",
                "dbField2": "http.cookieKey",
                "exp": "http.cookie.key",
                "friendlyName": "Cookie Keys",
                "group": "http",
                "help": "The keys to cookies sent up in requests",
                "type": "termfield"
            },
            {
                "dbField": "http.cookieKeyCnt",
                "dbField2": "http.cookieKeyCnt",
                "exp": "http.cookie.key.cnt",
                "friendlyName": "Cookie Keys Cnt",
                "group": "http",
                "help": "Unique number of The keys to cookies sent up in requests",
                "type": "integer"
            },
            {
                "dbField": "http.cookieValue",
                "dbField2": "http.cookieValue",
                "exp": "http.cookie.value",
                "friendlyName": "Cookie Values",
                "group": "http",
                "help": "The values to cookies sent up in requests",
                "type": "termfield"
            },
            {
                "dbField": "http.cookieValueCnt",
                "dbField2": "http.cookieValueCnt",
                "exp": "http.cookie.value.cnt",
                "friendlyName": "Cookie Values Cnt",
                "group": "http",
                "help": "Unique number of The values to cookies sent up in requests",
                "type": "integer"
            },
            {
                "dbField": "hhall",
                "dbField2": "hhall",
                "exp": "http.hasheader",
                "friendlyName": "Has Src or Dst Header",
                "group": "http",
                "help": "Shorthand for http.hasheader.src or http.hasheader.dst",
                "regex": "^http\\.hasheader\\.(?:(?!(cnt|value)$).)*$",
                "type": "lotermfield"
            },
            {
                "dbField": "http.responseHeader",
                "dbField2": "http.responseHeader",
                "exp": "http.hasheader.dst",
                "friendlyName": "Has Dst Header",
                "group": "http",
                "help": "Response has header present",
                "type": "lotermfield"
            },
            {
                "dbField": "http.responseHeaderCnt",
                "dbField2": "http.responseHeaderCnt",
                "exp": "http.hasheader.dst.cnt",
                "friendlyName": "Has Dst Header Cnt",
                "group": "http",
                "help": "Unique number of Response has header present",
                "type": "integer"
            },
            {
                "dbField": "http.responseHeaderValue",
                "dbField2": "http.responseHeaderValue",
                "exp": "http.hasheader.dst.value",
                "friendlyName": "Response Header Values",
                "group": "http",
                "help": "Contains response header values",
                "type": "lotermfield"
            },
            {
                "dbField": "http.responseHeaderValueCnt",
                "dbField2": "http.responseHeaderValueCnt",
                "exp": "http.hasheader.dst.value.cnt",
                "friendlyName": "Response Header Values Cnt",
                "group": "http",
                "help": "Unique number of Contains response header values",
                "type": "integer"
            },
            {
                "dbField": "http.requestHeader",
                "dbField2": "http.requestHeader",
                "exp": "http.hasheader.src",
                "friendlyName": "Has Src Header",
                "group": "http",
                "help": "Request has header present",
                "type": "lotermfield"
            },
            {
                "dbField": "http.requestHeaderCnt",
                "dbField2": "http.requestHeaderCnt",
                "exp": "http.hasheader.src.cnt",
                "friendlyName": "Has Src Header Cnt",
                "group": "http",
                "help": "Unique number of Request has header present",
                "type": "integer"
            },
            {
                "dbField": "http.requestHeaderValue",
                "dbField2": "http.requestHeaderValue",
                "exp": "http.hasheader.src.value",
                "friendlyName": "Request Header Values",
                "group": "http",
                "help": "Contains request header values",
                "type": "lotermfield"
            },
            {
                "dbField": "http.requestHeaderValueCnt",
                "dbField2": "http.requestHeaderValueCnt",
                "exp": "http.hasheader.src.value.cnt",
                "friendlyName": "Request Header Values Cnt",
                "group": "http",
                "help": "Unique number of Contains request header values",
                "type": "integer"
            },
            {
                "dbField": "hhvalueall",
                "dbField2": "hhvalueall",
                "exp": "http.hasheader.value",
                "friendlyName": "Has Value in Src or Dst Header",
                "group": "http",
                "help": "Shorthand for http.hasheader.src.value or http.hasheader.dst.value",
                "regex": "^http\\.hasheader\\.(src|dst)\\.value$",
                "type": "lotermfield"
            },
            {
                "dbField": "http.response-location",
                "dbField2": "http.response-location",
                "exp": "http.location",
                "friendlyName": "http.location",
                "group": "http",
                "help": "Response header location",
                "type": "termfield"
            },
            {
                "category": "md5",
                "dbField": "http.md5",
                "dbField2": "http.md5",
                "exp": "http.md5",
                "friendlyName": "Body MD5",
                "group": "http",
                "help": "MD5 of http body response",
                "type": "lotermfield"
            },
            {
                "dbField": "http.md5Cnt",
                "dbField2": "http.md5Cnt",
                "exp": "http.md5.cnt",
                "friendlyName": "Body MD5 Cnt",
                "group": "http",
                "help": "Unique number of MD5 of http body response",
                "type": "integer"
            },
            {
                "dbField": "http.method",
                "dbField2": "http.method",
                "exp": "http.method",
                "friendlyName": "Request Method",
                "group": "http",
                "help": "HTTP Request Method",
                "type": "termfield"
            },
            {
                "dbField": "http.methodCnt",
                "dbField2": "http.methodCnt",
                "exp": "http.method.cnt",
                "friendlyName": "Request Method Cnt",
                "group": "http",
                "help": "Unique number of HTTP Request Method",
                "type": "integer"
            },
            {
                "dbField": "http.request-origin",
                "dbField2": "http.request-origin",
                "exp": "http.origin",
                "friendlyName": "http.origin",
                "group": "http",
                "help": "Request header origin",
                "type": "termfield"
            },
            {
                "dbField": "http.request-referer",
                "dbField2": "http.request-referer",
                "exp": "http.referer",
                "friendlyName": "http.referer",
                "group": "http",
                "help": "Request header referer",
                "type": "termfield"
            },
            {
                "dbField": "http.request-refererCnt",
                "dbField2": "http.request-refererCnt",
                "exp": "http.referer.cnt",
                "friendlyName": "http.referer Cnt",
                "group": "http",
                "help": "Unique number of Request header referer",
                "type": "integer"
            },
            {
                "dbField": "http.requestBody",
                "dbField2": "http.requestBody",
                "exp": "http.reqbody",
                "friendlyName": "Request Body",
                "group": "http",
                "help": "HTTP Request Body",
                "type": "termfield"
            },
            {
                "dbField": "http.response-server",
                "dbField2": "http.response-server",
                "exp": "http.server",
                "friendlyName": "http.server",
                "group": "http",
                "help": "Response header server",
                "type": "termfield"
            },
            {
                "dbField": "http.statuscode",
                "dbField2": "http.statuscode",
                "exp": "http.statuscode",
                "friendlyName": "Status Code",
                "group": "http",
                "help": "Response HTTP numeric status code",
                "type": "integer"
            },
            {
                "dbField": "http.statuscodeCnt",
                "dbField2": "http.statuscodeCnt",
                "exp": "http.statuscode.cnt",
                "friendlyName": "Status Code Cnt",
                "group": "http",
                "help": "Unique number of Response HTTP numeric status code",
                "type": "integer"
            },
            {
                "category": [
                    "url",
                    "host"
                ],
                "dbField": "http.uri",
                "dbField2": "http.uri",
                "exp": "http.uri",
                "friendlyName": "URI",
                "group": "http",
                "help": "URIs for request",
                "transform": "removeProtocol",
                "type": "termfield"
            },
            {
                "dbField": "http.uriCnt",
                "dbField2": "http.uriCnt",
                "exp": "http.uri.cnt",
                "friendlyName": "URI Cnt",
                "group": "http",
                "help": "Unique number of URIs for request",
                "type": "integer"
            },
            {
                "dbField": "http.key",
                "dbField2": "http.key",
                "exp": "http.uri.key",
                "friendlyName": "QS Keys",
                "group": "http",
                "help": "Keys from query string of URI",
                "type": "termfield"
            },
            {
                "dbField": "http.keyCnt",
                "dbField2": "http.keyCnt",
                "exp": "http.uri.key.cnt",
                "friendlyName": "QS Keys Cnt",
                "group": "http",
                "help": "Unique number of Keys from query string of URI",
                "type": "integer"
            },
            {
                "dbField": "http.path",
                "dbField2": "http.path",
                "exp": "http.uri.path",
                "friendlyName": "URI Path",
                "group": "http",
                "help": "Path portion of URI",
                "type": "termfield"
            },
            {
                "dbField": "http.pathCnt",
                "dbField2": "http.pathCnt",
                "exp": "http.uri.path.cnt",
                "friendlyName": "URI Path Cnt",
                "group": "http",
                "help": "Unique number of Path portion of URI",
                "type": "integer"
            },
            {
                "dbField": "http.uriTokens",
                "dbField2": "http.uriTokens",
                "exp": "http.uri.tokens",
                "friendlyName": "URI Tokens",
                "group": "http",
                "help": "URIs Tokens for request",
                "transform": "removeProtocol",
                "type": "lotextfield"
            },
            {
                "dbField": "http.value",
                "dbField2": "http.value",
                "exp": "http.uri.value",
                "friendlyName": "QS Values",
                "group": "http",
                "help": "Values from query string of URI",
                "type": "termfield"
            },
            {
                "dbField": "http.valueCnt",
                "dbField2": "http.valueCnt",
                "exp": "http.uri.value.cnt",
                "friendlyName": "QS Values Cnt",
                "group": "http",
                "help": "Unique number of Values from query string of URI",
                "type": "integer"
            },
            {
                "category": "user",
                "dbField": "http.user",
                "dbField2": "http.user",
                "exp": "http.user",
                "friendlyName": "User",
                "group": "http",
                "help": "HTTP Auth User",
                "type": "termfield"
            },
            {
                "dbField": "http.useragent",
                "dbField2": "http.useragent",
                "exp": "http.user-agent",
                "friendlyName": "Useragent",
                "group": "http",
                "help": "User-Agent Header",
                "type": "termfield"
            },
            {
                "dbField": "http.useragentCnt",
                "dbField2": "http.useragentCnt",
                "exp": "http.user-agent.cnt",
                "friendlyName": "Useragent Cnt",
                "group": "http",
                "help": "Unique number of User-Agent Header",
                "type": "integer"
            },
            {
                "dbField": "http.useragentTokens",
                "dbField2": "http.useragentTokens",
                "exp": "http.user-agent.tokens",
                "friendlyName": "Useragent Tokens",
                "group": "http",
                "help": "User-Agent Header Tokens",
                "type": "lotextfield"
            },
            {
                "dbField": "http.userCnt",
                "dbField2": "http.userCnt",
                "exp": "http.user.cnt",
                "friendlyName": "User Cnt",
                "group": "http",
                "help": "Unique number of HTTP Auth User",
                "type": "integer"
            },
            {
                "dbField": "httpversion",
                "dbField2": "httpversion",
                "exp": "http.version",
                "friendlyName": "Version",
                "group": "http",
                "help": "HTTP version number",
                "regex": "^http.version.[a-z]+$",
                "type": "termfield"
            },
            {
                "dbField": "http.serverVersion",
                "dbField2": "http.serverVersion",
                "exp": "http.version.dst",
                "friendlyName": "Dst Version",
                "group": "http",
                "help": "Response HTTP version number",
                "type": "termfield"
            },
            {
                "dbField": "http.serverVersionCnt",
                "dbField2": "http.serverVersionCnt",
                "exp": "http.version.dst.cnt",
                "friendlyName": "Dst Version Cnt",
                "group": "http",
                "help": "Unique number of Response HTTP version number",
                "type": "integer"
            },
            {
                "dbField": "http.clientVersion",
                "dbField2": "http.clientVersion",
                "exp": "http.version.src",
                "friendlyName": "Src Version",
                "group": "http",
                "help": "Request HTTP version number",
                "type": "termfield"
            },
            {
                "dbField": "http.clientVersionCnt",
                "dbField2": "http.clientVersionCnt",
                "exp": "http.version.src.cnt",
                "friendlyName": "Src Version Cnt",
                "group": "http",
                "help": "Unique number of Request HTTP version number",
                "type": "integer"
            },
            {
                "dbField": "huntId",
                "dbField2": "huntId",
                "exp": "huntId",
                "friendlyName": "Hunt ID",
                "group": "general",
                "help": "The ID of the packet search job that matched this session",
                "type": "termfield"
            },
            {
                "dbField": "huntName",
                "dbField2": "huntName",
                "exp": "huntName",
                "friendlyName": "Hunt Name",
                "group": "general",
                "help": "The name of the packet search job that matched this session",
                "type": "termfield"
            },
            {
                "dbField": "icmp.code",
                "dbField2": "icmp.code",
                "exp": "icmp.code",
                "friendlyName": "ICMP Code",
                "group": "general",
                "help": "ICMP code field values",
                "type": "integer"
            },
            {
                "dbField": "icmp.type",
                "dbField2": "icmp.type",
                "exp": "icmp.type",
                "friendlyName": "ICMP Type",
                "group": "general",
                "help": "ICMP type field values",
                "type": "integer"
            },
            {
                "dbField": "_id",
                "dbField2": "_id",
                "exp": "id",
                "friendlyName": "Arkime ID",
                "group": "general",
                "help": "Arkime ID for the session",
                "noFacet": "true",
                "type": "termfield"
            },
            {
                "dbField": "initRTT",
                "dbField2": "initRTT",
                "exp": "initRTT",
                "friendlyName": "Initial RTT",
                "group": "general",
                "help": "Initial round trip time, difference between SYN and ACK timestamp divided by 2 in ms",
                "type": "integer"
            },
            {
                "dbField": "ipall",
                "dbField2": "ipall",
                "exp": "ip",
                "friendlyName": "All IP fields",
                "group": "general",
                "help": "Search all ip fields",
                "noFacet": "true",
                "type": "ip"
            },
            {
                "aliases": [
                    "dns.ip"
                ],
                "category": "ip",
                "dbField": "dns.ip",
                "dbField2": "dns.ip",
                "exp": "ip.dns",
                "friendlyName": "IP",
                "group": "dns",
                "help": "IP from DNS result",
                "type": "ip"
            },
            {
                "dbField": "dnsipall",
                "dbField2": "dnsipall",
                "exp": "ip.dns.all",
                "friendlyName": "IP",
                "group": "dns",
                "help": "Shorthand for ip.dns or ip.dns.nameserver",
                "regex": "^ip\\.dns(?:(?!\\.(cnt|all)$).)*$",
                "type": "ip"
            },
            {
                "dbField": "dns.ipCnt",
                "dbField2": "dns.ipCnt",
                "exp": "ip.dns.cnt",
                "friendlyName": "IP Cnt",
                "group": "dns",
                "help": "Unique number of IP from DNS result",
                "type": "integer"
            },
            {
                "category": "ip",
                "dbField": "dns.mailserverIp",
                "dbField2": "dns.mailserverIp",
                "exp": "ip.dns.mailserver",
                "friendlyName": "IP",
                "group": "dns",
                "help": "IPs for mailservers",
                "type": "ip"
            },
            {
                "dbField": "dns.mailserverIpCnt",
                "dbField2": "dns.mailserverIpCnt",
                "exp": "ip.dns.mailserver.cnt",
                "friendlyName": "IP Cnt",
                "group": "dns",
                "help": "Unique number of IPs for mailservers",
                "type": "integer"
            },
            {
                "category": "ip",
                "dbField": "dns.nameserverIp",
                "dbField2": "dns.nameserverIp",
                "exp": "ip.dns.nameserver",
                "friendlyName": "IP",
                "group": "dns",
                "help": "IPs for nameservers",
                "type": "ip"
            },
            {
                "dbField": "dns.nameserverIpCnt",
                "dbField2": "dns.nameserverIpCnt",
                "exp": "ip.dns.nameserver.cnt",
                "friendlyName": "IP Cnt",
                "group": "dns",
                "help": "Unique number of IPs for nameservers",
                "type": "integer"
            },
            {
                "aliases": [
                    "ip.dst:port"
                ],
                "category": "ip",
                "dbField": "destination.ip",
                "dbField2": "dstIp",
                "exp": "ip.dst",
                "fieldECS": "destination.ip",
                "friendlyName": "Dst IP",
                "group": "general",
                "help": "Destination IP",
                "portField": "destination.port",
                "portField2": "dstPort",
                "portFieldECS": "destination.port",
                "type": "ip"
            },
            {
                "category": "ip",
                "dbField": "email.ip",
                "dbField2": "email.ip",
                "exp": "ip.email",
                "friendlyName": "IP",
                "group": "email",
                "help": "Email IP address",
                "requiredRight": "emailSearch",
                "type": "ip"
            },
            {
                "dbField": "email.ipCnt",
                "dbField2": "email.ipCnt",
                "exp": "ip.email.cnt",
                "friendlyName": "IP Cnt",
                "group": "email",
                "help": "Unique number of Email IP address",
                "type": "integer"
            },
            {
                "dbField": "ipProtocol",
                "dbField2": "ipProtocol",
                "exp": "ip.protocol",
                "friendlyName": "IP Protocol",
                "group": "general",
                "help": "IP protocol number or friendly name",
                "transform": "ipProtocolLookup",
                "type": "lotermfield"
            },
            {
                "aliases": [
                    "socks.ip"
                ],
                "dbField": "socks.ip",
                "dbField2": "socks.ip",
                "exp": "ip.socks",
                "friendlyName": "IP",
                "group": "socks",
                "help": "SOCKS destination IP",
                "portField": "socks.port",
                "portField2": "socks.port",
                "type": "ip"
            },
            {
                "category": "ip",
                "dbField": "source.ip",
                "dbField2": "srcIp",
                "exp": "ip.src",
                "fieldECS": "source.ip",
                "friendlyName": "Src IP",
                "group": "general",
                "help": "Source IP",
                "portField": "source.port",
                "portField2": "srcPort",
                "portFieldECS": "source.port",
                "type": "ip"
            },
            {
                "category": "ip",
                "dbField": "http.xffIp",
                "dbField2": "http.xffIp",
                "exp": "ip.xff",
                "friendlyName": "XFF IP",
                "group": "http",
                "help": "X-Forwarded-For Header",
                "type": "ip"
            },
            {
                "dbField": "http.xffIpCnt",
                "dbField2": "http.xffIpCnt",
                "exp": "ip.xff.cnt",
                "friendlyName": "XFF IP Cnt",
                "group": "http",
                "help": "Unique number of X-Forwarded-For Header",
                "type": "integer"
            },
            {
                "dbField": "irc.channel",
                "dbField2": "irc.channel",
                "exp": "irc.channel",
                "friendlyName": "Channel",
                "group": "irc",
                "help": "Channels joined",
                "type": "termfield"
            },
            {
                "dbField": "irc.channelCnt",
                "dbField2": "irc.channelCnt",
                "exp": "irc.channel.cnt",
                "friendlyName": "Channel Cnt",
                "group": "irc",
                "help": "Unique number of Channels joined",
                "type": "integer"
            },
            {
                "category": "user",
                "dbField": "irc.nick",
                "dbField2": "irc.nick",
                "exp": "irc.nick",
                "friendlyName": "Nickname",
                "group": "irc",
                "help": "Nicknames set",
                "type": "termfield"
            },
            {
                "dbField": "irc.nickCnt",
                "dbField2": "irc.nickCnt",
                "exp": "irc.nick.cnt",
                "friendlyName": "Nickname Cnt",
                "group": "irc",
                "help": "Unique number of Nicknames set",
                "type": "integer"
            },
            {
                "dbField": "isis.msgType",
                "dbField2": "isis.msgType",
                "exp": "isis.msgType",
                "friendlyName": "isis.msgType",
                "group": "isis",
                "help": "ISIS Msg Type field",
                "type": "lotermfield"
            },
            {
                "dbField": "krb5.cname",
                "dbField2": "krb5.cname",
                "exp": "krb5.cname",
                "friendlyName": "cname",
                "group": "krb5",
                "help": "Kerberos 5 cname",
                "type": "termfield"
            },
            {
                "dbField": "krb5.cnameCnt",
                "dbField2": "krb5.cnameCnt",
                "exp": "krb5.cname.cnt",
                "friendlyName": "cname Cnt",
                "group": "krb5",
                "help": "Unique number of Kerberos 5 cname",
                "type": "integer"
            },
            {
                "dbField": "krb5.realm",
                "dbField2": "krb5.realm",
                "exp": "krb5.realm",
                "friendlyName": "Realm",
                "group": "krb5",
                "help": "Kerberos 5 Realm",
                "type": "termfield"
            },
            {
                "dbField": "krb5.realmCnt",
                "dbField2": "krb5.realmCnt",
                "exp": "krb5.realm.cnt",
                "friendlyName": "Realm Cnt",
                "group": "krb5",
                "help": "Unique number of Kerberos 5 Realm",
                "type": "integer"
            },
            {
                "dbField": "krb5.sname",
                "dbField2": "krb5.sname",
                "exp": "krb5.sname",
                "friendlyName": "sname",
                "group": "krb5",
                "help": "Kerberos 5 sname",
                "type": "termfield"
            },
            {
                "dbField": "krb5.snameCnt",
                "dbField2": "krb5.snameCnt",
                "exp": "krb5.sname.cnt",
                "friendlyName": "sname Cnt",
                "group": "krb5",
                "help": "Unique number of Kerberos 5 sname",
                "type": "integer"
            },
            {
                "dbField": "ldap.authtype",
                "dbField2": "ldap.authtype",
                "exp": "ldap.authtype",
                "friendlyName": "Auth Type",
                "group": "ldap",
                "help": "The auth type of ldap bind",
                "type": "termfield"
            },
            {
                "dbField": "ldap.authtypeCnt",
                "dbField2": "ldap.authtypeCnt",
                "exp": "ldap.authtype.cnt",
                "friendlyName": "Auth Type Cnt",
                "group": "ldap",
                "help": "Unique number of The auth type of ldap bind",
                "type": "integer"
            },
            {
                "dbField": "ldap.bindname",
                "dbField2": "ldap.bindname",
                "exp": "ldap.bindname",
                "friendlyName": "Bind Name",
                "group": "ldap",
                "help": "The bind name of ldap bind",
                "type": "termfield"
            },
            {
                "dbField": "ldap.bindnameCnt",
                "dbField2": "ldap.bindnameCnt",
                "exp": "ldap.bindname.cnt",
                "friendlyName": "Bind Name Cnt",
                "group": "ldap",
                "help": "Unique number of The bind name of ldap bind",
                "type": "integer"
            },
            {
                "dbField": "macall",
                "dbField2": "macall",
                "exp": "mac",
                "friendlyName": "Src or Dst MAC",
                "group": "general",
                "help": "Shorthand for mac.src or mac.dst",
                "regex": "^mac\\.(?:(?!\\.cnt$).)*$",
                "transform": "dash2Colon",
                "type": "lotermfield"
            },
            {
                "dbField": "destination.mac",
                "dbField2": "destination.mac",
                "exp": "mac.dst",
                "fieldECS": "destination.mac",
                "friendlyName": "Dst MAC",
                "group": "general",
                "help": "Destination ethernet mac addresses set for session",
                "transform": "dash2Colon",
                "type": "lotermfield"
            },
            {
                "dbField": "destination.mac-cnt",
                "dbField2": "destination.mac-cnt",
                "exp": "mac.dst.cnt",
                "friendlyName": "Dst MAC Cnt",
                "group": "general",
                "help": "Unique number of Destination ethernet mac addresses set for session",
                "type": "integer"
            },
            {
                "dbField": "source.mac",
                "dbField2": "source.mac",
                "exp": "mac.src",
                "fieldECS": "source.mac",
                "friendlyName": "Src MAC",
                "group": "general",
                "help": "Source ethernet mac addresses set for session",
                "transform": "dash2Colon",
                "type": "lotermfield"
            },
            {
                "dbField": "source.mac-cnt",
                "dbField2": "source.mac-cnt",
                "exp": "mac.src.cnt",
                "friendlyName": "Src MAC Cnt",
                "group": "general",
                "help": "Unique number of Source ethernet mac addresses set for session",
                "type": "integer"
            },
            {
                "dbField": "modbus.exccode",
                "dbField2": "modbus.exccode",
                "exp": "modbus.exccode",
                "friendlyName": "Modbus Exception Code",
                "group": "modbus",
                "help": "Modbus Exception Codes",
                "type": "integer"
            },
            {
                "dbField": "modbus.exccodeCnt",
                "dbField2": "modbus.exccodeCnt",
                "exp": "modbus.exccode.cnt",
                "friendlyName": "Modbus Exception Code Cnt",
                "group": "modbus",
                "help": "Unique number of Modbus Exception Codes",
                "type": "integer"
            },
            {
                "dbField": "modbus.funccode",
                "dbField2": "modbus.funccode",
                "exp": "modbus.funccode",
                "friendlyName": "Modbus Function Code",
                "group": "modbus",
                "help": "Modbus Function Codes",
                "type": "integer"
            },
            {
                "dbField": "modbus.funccodeCnt",
                "dbField2": "modbus.funccodeCnt",
                "exp": "modbus.funccode.cnt",
                "friendlyName": "Modbus Function Code Cnt",
                "group": "modbus",
                "help": "Unique number of Modbus Function Codes",
                "type": "integer"
            },
            {
                "dbField": "modbus.protocolid",
                "dbField2": "modbus.protocolid",
                "exp": "modbus.protocolid",
                "friendlyName": "Modbus Protocol ID",
                "group": "modbus",
                "help": "Modbus Protocol ID (should always be 0)",
                "type": "integer"
            },
            {
                "dbField": "modbus.transactionid",
                "dbField2": "modbus.transactionid",
                "exp": "modbus.transactionid",
                "friendlyName": "Modbus Transaction IDs",
                "group": "modbus",
                "help": "Modbus Transaction IDs",
                "type": "integer"
            },
            {
                "dbField": "modbus.transactionidCnt",
                "dbField2": "modbus.transactionidCnt",
                "exp": "modbus.transactionid.cnt",
                "friendlyName": "Modbus Transaction IDs Cnt",
                "group": "modbus",
                "help": "Unique number of Modbus Transaction IDs",
                "type": "integer"
            },
            {
                "dbField": "modbus.unitid",
                "dbField2": "modbus.unitid",
                "exp": "modbus.unitid",
                "friendlyName": "Modbus Unit ID",
                "group": "modbus",
                "help": "Modbus Unit ID",
                "type": "integer"
            },
            {
                "category": "user",
                "dbField": "mysql.user",
                "dbField2": "mysql.user",
                "exp": "mysql.user",
                "friendlyName": "User",
                "group": "mysql",
                "help": "Mysql user name",
                "type": "lotermfield"
            },
            {
                "dbField": "mysql.version",
                "dbField2": "mysql.version",
                "exp": "mysql.ver",
                "friendlyName": "Version",
                "group": "mysql",
                "help": "Mysql server version string",
                "type": "termfield"
            },
            {
                "dbField": "node",
                "dbField2": "node",
                "exp": "node",
                "friendlyName": "Arkime Node",
                "group": "general",
                "help": "Arkime node name the session was recorded on",
                "type": "termfield"
            },
            {
                "aliases": [
                    "host.oracle"
                ],
                "category": "host",
                "dbField": "oracle.host",
                "dbField2": "oracle.host",
                "exp": "oracle.host",
                "friendlyName": "Host",
                "group": "oracle",
                "help": "Oracle Host",
                "type": "lotermfield"
            },
            {
                "aliases": [
                    "host.oracle.tokens"
                ],
                "dbField": "oracle.hostTokens",
                "dbField2": "oracle.hostTokens",
                "exp": "oracle.host.tokens",
                "friendlyName": "Hostname Tokens",
                "group": "oracle",
                "help": "Oracle Hostname Tokens",
                "type": "lotextfield"
            },
            {
                "dbField": "oracle.service",
                "dbField2": "oracle.service",
                "exp": "oracle.service",
                "friendlyName": "Service",
                "group": "oracle",
                "help": "Oracle Service",
                "type": "lotermfield"
            },
            {
                "category": "user",
                "dbField": "oracle.user",
                "dbField2": "oracle.user",
                "exp": "oracle.user",
                "friendlyName": "User",
                "group": "oracle",
                "help": "Oracle User",
                "type": "lotermfield"
            },
            {
                "dbField": "dstOui",
                "dbField2": "dstOui",
                "exp": "oui.dst",
                "friendlyName": "Dst OUI",
                "group": "general",
                "help": "Destination ethernet oui set for session",
                "type": "termfield"
            },
            {
                "dbField": "dstOuiCnt",
                "dbField2": "dstOuiCnt",
                "exp": "oui.dst.cnt",
                "friendlyName": "Dst OUI Cnt",
                "group": "general",
                "help": "Unique number of Destination ethernet oui set for session",
                "type": "integer"
            },
            {
                "dbField": "srcOui",
                "dbField2": "srcOui",
                "exp": "oui.src",
                "friendlyName": "Src OUI",
                "group": "general",
                "help": "Source ethernet oui set for session",
                "type": "termfield"
            },
            {
                "dbField": "srcOuiCnt",
                "dbField2": "srcOuiCnt",
                "exp": "oui.src.cnt",
                "friendlyName": "Src OUI Cnt",
                "group": "general",
                "help": "Unique number of Source ethernet oui set for session",
                "type": "integer"
            },
            {
                "dbField": "network.packets",
                "dbField2": "totPackets",
                "exp": "packets",
                "fieldECS": "network.packets",
                "friendlyName": "Packets",
                "group": "general",
                "help": "Total number of packets sent AND received in a session",
                "type": "integer"
            },
            {
                "dbField": "destination.packets",
                "dbField2": "dstPackets",
                "exp": "packets.dst",
                "fieldECS": "destination.packets",
                "friendlyName": "Dst Packets",
                "group": "general",
                "help": "Total number of packets sent by destination in a session",
                "type": "integer"
            },
            {
                "dbField": "source.packets",
                "dbField2": "srcPackets",
                "exp": "packets.src",
                "fieldECS": "source.packets",
                "friendlyName": "Src Packets",
                "group": "general",
                "help": "Total number of packets sent by source in a session",
                "type": "integer"
            },
            {
                "aliases": [
                    "payload.dst"
                ],
                "dbField": "dstPayload8",
                "dbField2": "dstPayload8",
                "exp": "payload8.dst.hex",
                "friendlyName": "Payload Dst Hex",
                "group": "general",
                "help": "First 8 bytes of destination payload in hex",
                "type": "lotermfield"
            },
            {
                "dbField": "dstPayload8",
                "dbField2": "dstPayload8",
                "exp": "payload8.dst.utf8",
                "friendlyName": "Payload Dst UTF8",
                "group": "general",
                "help": "First 8 bytes of destination payload in utf8",
                "noFacet": "true",
                "transform": "utf8ToHex",
                "type": "termfield"
            },
            {
                "dbField": "fballhex",
                "dbField2": "fballhex",
                "exp": "payload8.hex",
                "friendlyName": "Payload Hex",
                "group": "general",
                "help": "First 8 bytes of payload in hex",
                "regex": "^payload8.(src|dst).hex$",
                "type": "lotermfield"
            },
            {
                "aliases": [
                    "payload.src"
                ],
                "dbField": "srcPayload8",
                "dbField2": "srcPayload8",
                "exp": "payload8.src.hex",
                "friendlyName": "Payload Src Hex",
                "group": "general",
                "help": "First 8 bytes of source payload in hex",
                "type": "lotermfield"
            },
            {
                "dbField": "srcPayload8",
                "dbField2": "srcPayload8",
                "exp": "payload8.src.utf8",
                "friendlyName": "Payload Src UTF8",
                "group": "general",
                "help": "First 8 bytes of source payload in utf8",
                "noFacet": "true",
                "transform": "utf8ToHex",
                "type": "termfield"
            },
            {
                "dbField": "fballutf8",
                "dbField2": "fballutf8",
                "exp": "payload8.utf8",
                "friendlyName": "Payload UTF8",
                "group": "general",
                "help": "First 8 bytes of payload in hex",
                "regex": "^payload8.(src|dst).utf8$",
                "type": "lotermfield"
            },
            {
                "dbField": "portall",
                "dbField2": "portall",
                "exp": "port",
                "friendlyName": "All port fields",
                "group": "general",
                "help": "Search all port fields",
                "regex": "(^port\\.(?:(?!\\.cnt$).)*$|\\.port$)",
                "type": "integer"
            },
            {
                "category": "port",
                "dbField": "destination.port",
                "dbField2": "dstPort",
                "exp": "port.dst",
                "fieldECS": "destination.port",
                "friendlyName": "Dst Port",
                "group": "general",
                "help": "Source Port",
                "type": "integer"
            },
            {
                "aliases": [
                    "socks.port"
                ],
                "category": "port",
                "dbField": "socks.port",
                "dbField2": "socks.port",
                "exp": "port.socks",
                "friendlyName": "Port",
                "group": "socks",
                "help": "SOCKS destination port",
                "type": "integer"
            },
            {
                "category": "port",
                "dbField": "source.port",
                "dbField2": "srcPort",
                "exp": "port.src",
                "fieldECS": "source.port",
                "friendlyName": "Src Port",
                "group": "general",
                "help": "Source Port",
                "type": "integer"
            },
            {
                "dbField": "postgresql.app",
                "dbField2": "postgresql.app",
                "exp": "postgresql.app",
                "friendlyName": "Application",
                "group": "postgresql",
                "help": "Postgresql application",
                "type": "termfield"
            },
            {
                "dbField": "postgresql.db",
                "dbField2": "postgresql.db",
                "exp": "postgresql.db",
                "friendlyName": "Database",
                "group": "postgresql",
                "help": "Postgresql database",
                "type": "termfield"
            },
            {
                "category": "user",
                "dbField": "postgresql.user",
                "dbField2": "postgresql.user",
                "exp": "postgresql.user",
                "friendlyName": "User",
                "group": "postgresql",
                "help": "Postgresql user name",
                "type": "termfield"
            },
            {
                "dbField": "protocol",
                "dbField2": "protocol",
                "exp": "protocols",
                "friendlyName": "Protocols",
                "group": "general",
                "help": "Protocols set for session",
                "type": "termfield"
            },
            {
                "dbField": "protocolCnt",
                "dbField2": "protocolCnt",
                "exp": "protocols.cnt",
                "friendlyName": "Protocols Cnt",
                "group": "general",
                "help": "Unique number of Protocols set for session",
                "type": "integer"
            },
            {
                "dbField": "quic.useragent",
                "dbField2": "quic.useragent",
                "exp": "quic.user-agent",
                "friendlyName": "User-Agent",
                "group": "quic",
                "help": "User-Agent",
                "type": "termfield"
            },
            {
                "dbField": "quic.useragentCnt",
                "dbField2": "quic.useragentCnt",
                "exp": "quic.user-agent.cnt",
                "friendlyName": "User-Agent Cnt",
                "group": "quic",
                "help": "Unique number of User-Agent",
                "type": "integer"
            },
            {
                "dbField": "quic.version",
                "dbField2": "quic.version",
                "exp": "quic.version",
                "friendlyName": "Version",
                "group": "quic",
                "help": "QUIC Version",
                "type": "termfield"
            },
            {
                "dbField": "quic.versionCnt",
                "dbField2": "quic.versionCnt",
                "exp": "quic.version.cnt",
                "friendlyName": "Version Cnt",
                "group": "quic",
                "help": "Unique number of QUIC Version",
                "type": "integer"
            },
            {
                "dbField": "radius.endpointIp",
                "dbField2": "radius.endpointIp",
                "exp": "radius.endpoint-ip",
                "friendlyName": "Endpoint IP",
                "group": "radius",
                "help": "Radius endpoint ip addresses for session",
                "type": "ip"
            },
            {
                "dbField": "radius.endpointASN",
                "dbField2": "radius.endpointASN",
                "exp": "radius.endpoint-ip.asn",
                "friendlyName": "Endpoint IP ASN",
                "group": "radius",
                "help": "GeoIP ASN string calculated from the Radius endpoint ip addresses for session",
                "type": "termfield"
            },
            {
                "dbField": "radius.endpointIpCnt",
                "dbField2": "radius.endpointIpCnt",
                "exp": "radius.endpoint-ip.cnt",
                "friendlyName": "Endpoint IP Cnt",
                "group": "radius",
                "help": "Unique number of Radius endpoint ip addresses for session",
                "type": "integer"
            },
            {
                "dbField": "radius.endpointGEO",
                "dbField2": "radius.endpointGEO",
                "exp": "radius.endpoint-ip.country",
                "friendlyName": "Endpoint IP GEO",
                "group": "radius",
                "help": "GeoIP country string calculated from the Radius endpoint ip addresses for session",
                "type": "uptermfield"
            },
            {
                "dbField": "radius.endpointRIR",
                "dbField2": "radius.endpointRIR",
                "exp": "radius.endpoint-ip.rir",
                "friendlyName": "Endpoint IP RIR",
                "group": "radius",
                "help": "Regional Internet Registry string calculated from Radius endpoint ip addresses for session",
                "type": "uptermfield"
            },
            {
                "dbField": "radius.framedIp",
                "dbField2": "radius.framedIp",
                "exp": "radius.framed-ip",
                "friendlyName": "Framed IP",
                "group": "radius",
                "help": "Radius framed ip addresses for session",
                "type": "ip"
            },
            {
                "dbField": "radius.framedASN",
                "dbField2": "radius.framedASN",
                "exp": "radius.framed-ip.asn",
                "friendlyName": "Framed IP ASN",
                "group": "radius",
                "help": "GeoIP ASN string calculated from the Radius framed ip addresses for session",
                "type": "termfield"
            },
            {
                "dbField": "radius.framedIpCnt",
                "dbField2": "radius.framedIpCnt",
                "exp": "radius.framed-ip.cnt",
                "friendlyName": "Framed IP Cnt",
                "group": "radius",
                "help": "Unique number of Radius framed ip addresses for session",
                "type": "integer"
            },
            {
                "dbField": "radius.framedGEO",
                "dbField2": "radius.framedGEO",
                "exp": "radius.framed-ip.country",
                "friendlyName": "Framed IP GEO",
                "group": "radius",
                "help": "GeoIP country string calculated from the Radius framed ip addresses for session",
                "type": "uptermfield"
            },
            {
                "dbField": "radius.framedRIR",
                "dbField2": "radius.framedRIR",
                "exp": "radius.framed-ip.rir",
                "friendlyName": "Framed IP RIR",
                "group": "radius",
                "help": "Regional Internet Registry string calculated from Radius framed ip addresses for session",
                "type": "uptermfield"
            },
            {
                "dbField": "radius.mac",
                "dbField2": "radius.mac",
                "exp": "radius.mac",
                "friendlyName": "MAC",
                "group": "radius",
                "help": "Radius Mac",
                "type": "lotermfield"
            },
            {
                "dbField": "radius.macCnt",
                "dbField2": "radius.macCnt",
                "exp": "radius.mac.cnt",
                "friendlyName": "MAC Cnt",
                "group": "radius",
                "help": "Unique number of Radius Mac",
                "type": "integer"
            },
            {
                "category": "user",
                "dbField": "radius.user",
                "dbField2": "radius.user",
                "exp": "radius.user",
                "friendlyName": "User",
                "group": "radius",
                "help": "RADIUS user",
                "type": "termfield"
            },
            {
                "dbField": "rirall",
                "dbField2": "rirall",
                "exp": "rir",
                "friendlyName": "All rir fields",
                "group": "general",
                "help": "Search all rir fields",
                "regex": "(^rir\\.(?:(?!\\.cnt$).)*$|\\.rir$)",
                "type": "uptermfield"
            },
            {
                "dbField": "dns.RIR",
                "dbField2": "dns.RIR",
                "exp": "rir.dns",
                "friendlyName": " RIR",
                "group": "dns",
                "help": "Regional Internet Registry string calculated from IP from DNS result",
                "type": "uptermfield"
            },
            {
                "dbField": "dns.mailserverRIR",
                "dbField2": "dns.mailserverRIR",
                "exp": "rir.dns.mailserver",
                "friendlyName": " RIR",
                "group": "dns",
                "help": "Regional Internet Registry string calculated from IPs for mailservers",
                "type": "uptermfield"
            },
            {
                "dbField": "dns.nameserverRIR",
                "dbField2": "dns.nameserverRIR",
                "exp": "rir.dns.nameserver",
                "friendlyName": " RIR",
                "group": "dns",
                "help": "Regional Internet Registry string calculated from IPs for nameservers",
                "type": "uptermfield"
            },
            {
                "category": "rir",
                "dbField": "dstRIR",
                "dbField2": "dstRIR",
                "exp": "rir.dst",
                "friendlyName": "Dst RIR",
                "group": "general",
                "help": "Destination RIR",
                "type": "uptermfield"
            },
            {
                "dbField": "email.RIR",
                "dbField2": "email.RIR",
                "exp": "rir.email",
                "friendlyName": " RIR",
                "group": "email",
                "help": "Regional Internet Registry string calculated from Email IP address",
                "type": "uptermfield"
            },
            {
                "dbField": "socks.RIR",
                "dbField2": "socks.RIR",
                "exp": "rir.socks",
                "friendlyName": " RIR",
                "group": "socks",
                "help": "Regional Internet Registry string calculated from SOCKS destination IP",
                "type": "uptermfield"
            },
            {
                "category": "rir",
                "dbField": "srcRIR",
                "dbField2": "srcRIR",
                "exp": "rir.src",
                "friendlyName": "Src RIR",
                "group": "general",
                "help": "Source RIR",
                "type": "uptermfield"
            },
            {
                "dbField": "http.xffRIR",
                "dbField2": "http.xffRIR",
                "exp": "rir.xff",
                "friendlyName": "XFF  RIR",
                "group": "http",
                "help": "Regional Internet Registry string calculated from X-Forwarded-For Header",
                "type": "uptermfield"
            },
            {
                "dbField": "rootId",
                "dbField2": "rootId",
                "exp": "rootId",
                "friendlyName": "Arkime Root ID",
                "group": "general",
                "help": "Arkime ID of the first session in a multi session stream",
                "type": "termfield"
            },
            {
                "dbField": "scrubby",
                "dbField2": "scrubby",
                "exp": "scrubbed.by",
                "friendlyName": "Scrubbed By",
                "group": "general",
                "help": "SPI data was scrubbed by",
                "type": "lotermfield"
            },
            {
                "dbField": "length",
                "dbField2": "length",
                "exp": "session.length",
                "friendlyName": "Session Length",
                "group": "general",
                "help": "Session Length in milliseconds so far",
                "type": "integer"
            },
            {
                "dbField": "segmentCnt",
                "dbField2": "segmentCnt",
                "exp": "session.segments",
                "friendlyName": "Session Segments",
                "group": "general",
                "help": "Number of segments in session so far",
                "type": "integer"
            },
            {
                "dbField": "smb.domain",
                "dbField2": "smb.domain",
                "exp": "smb.domain",
                "friendlyName": "Domain",
                "group": "smb",
                "help": "SMB domain",
                "type": "termfield"
            },
            {
                "dbField": "smb.domainCnt",
                "dbField2": "smb.domainCnt",
                "exp": "smb.domain.cnt",
                "friendlyName": "Domain Cnt",
                "group": "smb",
                "help": "Unique number of SMB domain",
                "type": "integer"
            },
            {
                "dbField": "smb.filename",
                "dbField2": "smb.filename",
                "exp": "smb.fn",
                "friendlyName": "Filename",
                "group": "smb",
                "help": "SMB files opened, created, deleted",
                "type": "termfield"
            },
            {
                "dbField": "smb.filenameCnt",
                "dbField2": "smb.filenameCnt",
                "exp": "smb.fn.cnt",
                "friendlyName": "Filename Cnt",
                "group": "smb",
                "help": "Unique number of SMB files opened, created, deleted",
                "type": "integer"
            },
            {
                "dbField": "smb.os",
                "dbField2": "smb.os",
                "exp": "smb.os",
                "friendlyName": "OS",
                "group": "smb",
                "help": "SMB OS information",
                "type": "termfield"
            },
            {
                "dbField": "smb.osCnt",
                "dbField2": "smb.osCnt",
                "exp": "smb.os.cnt",
                "friendlyName": "OS Cnt",
                "group": "smb",
                "help": "Unique number of SMB OS information",
                "type": "integer"
            },
            {
                "dbField": "smb.share",
                "dbField2": "smb.share",
                "exp": "smb.share",
                "friendlyName": "Share",
                "group": "smb",
                "help": "SMB shares connected to",
                "type": "termfield"
            },
            {
                "dbField": "smb.shareCnt",
                "dbField2": "smb.shareCnt",
                "exp": "smb.share.cnt",
                "friendlyName": "Share Cnt",
                "group": "smb",
                "help": "Unique number of SMB shares connected to",
                "type": "integer"
            },
            {
                "category": "user",
                "dbField": "smb.user",
                "dbField2": "smb.user",
                "exp": "smb.user",
                "friendlyName": "User",
                "group": "smb",
                "help": "SMB User",
                "type": "termfield"
            },
            {
                "dbField": "smb.userCnt",
                "dbField2": "smb.userCnt",
                "exp": "smb.user.cnt",
                "friendlyName": "User Cnt",
                "group": "smb",
                "help": "Unique number of SMB User",
                "type": "integer"
            },
            {
                "dbField": "smb.version",
                "dbField2": "smb.version",
                "exp": "smb.ver",
                "friendlyName": "Version",
                "group": "smb",
                "help": "SMB Version information",
                "type": "termfield"
            },
            {
                "dbField": "smb.versionCnt",
                "dbField2": "smb.versionCnt",
                "exp": "smb.ver.cnt",
                "friendlyName": "Version Cnt",
                "group": "smb",
                "help": "Unique number of SMB Version information",
                "type": "integer"
            },
            {
                "dbField": "snmp.community",
                "dbField2": "snmp.community",
                "exp": "snmp.community",
                "friendlyName": "Community",
                "group": "snmp",
                "help": "SNMP Community",
                "type": "termfield"
            },
            {
                "dbField": "snmp.communityCnt",
                "dbField2": "snmp.communityCnt",
                "exp": "snmp.community.cnt",
                "friendlyName": "Community Cnt",
                "group": "snmp",
                "help": "Unique number of SNMP Community",
                "type": "integer"
            },
            {
                "dbField": "snmp.error",
                "dbField2": "snmp.error",
                "exp": "snmp.error",
                "friendlyName": "Error Code",
                "group": "snmp",
                "help": "SNMP Error Code",
                "type": "integer"
            },
            {
                "dbField": "snmp.errorCnt",
                "dbField2": "snmp.errorCnt",
                "exp": "snmp.error.cnt",
                "friendlyName": "Error Code Cnt",
                "group": "snmp",
                "help": "Unique number of SNMP Error Code",
                "type": "integer"
            },
            {
                "dbField": "snmp.type",
                "dbField2": "snmp.type",
                "exp": "snmp.type",
                "friendlyName": "Type",
                "group": "snmp",
                "help": "SNMP Type",
                "type": "termfield"
            },
            {
                "dbField": "snmp.typeCnt",
                "dbField2": "snmp.typeCnt",
                "exp": "snmp.type.cnt",
                "friendlyName": "Type Cnt",
                "group": "snmp",
                "help": "Unique number of SNMP Type",
                "type": "integer"
            },
            {
                "dbField": "snmp.variable",
                "dbField2": "snmp.variable",
                "exp": "snmp.variable",
                "friendlyName": "Variable",
                "group": "snmp",
                "help": "SNMP Variable",
                "type": "termfield"
            },
            {
                "dbField": "snmp.variableCnt",
                "dbField2": "snmp.variableCnt",
                "exp": "snmp.variable.cnt",
                "friendlyName": "Variable Cnt",
                "group": "snmp",
                "help": "Unique number of SNMP Variable",
                "type": "integer"
            },
            {
                "dbField": "snmp.version",
                "dbField2": "snmp.version",
                "exp": "snmp.version",
                "friendlyName": "Version",
                "group": "snmp",
                "help": "SNMP Version",
                "type": "integer"
            },
            {
                "dbField": "snmp.versionCnt",
                "dbField2": "snmp.versionCnt",
                "exp": "snmp.version.cnt",
                "friendlyName": "Version Cnt",
                "group": "snmp",
                "help": "Unique number of SNMP Version",
                "type": "integer"
            },
            {
                "aliases": [
                    "socksuser"
                ],
                "category": "user",
                "dbField": "socks.user",
                "dbField2": "socks.user",
                "exp": "socks.user",
                "friendlyName": "User",
                "group": "socks",
                "help": "SOCKS authenticated user",
                "type": "termfield"
            },
            {
                "dbField": "source.as.number",
                "exp": "source.as.number",
                "fieldECS": "source.as.number",
                "friendlyName": "Src ASN Number",
                "group": "general",
                "help": "GeoIP ASN Number calculated from the source IP",
                "type": "integer"
            },
            {
                "dbField": "source.as.organization.name",
                "exp": "source.as.organization.name",
                "fieldECS": "source.as.organization.name",
                "friendlyName": "Src ASN Name",
                "group": "general",
                "help": "GeoIP ASN Name calculated from the source IP",
                "type": "termfield"
            },
            {
                "dbField": "srcNode",
                "dbField2": "srcNode",
                "exp": "srcNode",
                "friendlyName": "Arkime Source Node",
                "group": "general",
                "help": "Source Arkime node name the session was recorded on when using send to cluster",
                "type": "termfield"
            },
            {
                "dbField": "ssh.hassh",
                "dbField2": "ssh.hassh",
                "exp": "ssh.hassh",
                "friendlyName": "HASSH",
                "group": "ssh",
                "help": "SSH HASSH field",
                "type": "lotermfield"
            },
            {
                "dbField": "ssh.hasshCnt",
                "dbField2": "ssh.hasshCnt",
                "exp": "ssh.hassh.cnt",
                "friendlyName": "HASSH Cnt",
                "group": "ssh",
                "help": "Unique number of SSH HASSH field",
                "type": "integer"
            },
            {
                "dbField": "ssh.hasshServer",
                "dbField2": "ssh.hasshServer",
                "exp": "ssh.hasshServer",
                "friendlyName": "HASSH Server",
                "group": "ssh",
                "help": "SSH HASSH Server field",
                "type": "lotermfield"
            },
            {
                "dbField": "ssh.hasshServerCnt",
                "dbField2": "ssh.hasshServerCnt",
                "exp": "ssh.hasshServer.cnt",
                "friendlyName": "HASSH Server Cnt",
                "group": "ssh",
                "help": "Unique number of SSH HASSH Server field",
                "type": "integer"
            },
            {
                "dbField": "ssh.key",
                "dbField2": "ssh.key",
                "exp": "ssh.key",
                "friendlyName": "Key",
                "group": "ssh",
                "help": "SSH Key",
                "type": "termfield"
            },
            {
                "dbField": "ssh.keyCnt",
                "dbField2": "ssh.keyCnt",
                "exp": "ssh.key.cnt",
                "friendlyName": "Key Cnt",
                "group": "ssh",
                "help": "Unique number of SSH Key",
                "type": "integer"
            },
            {
                "dbField": "ssh.version",
                "dbField2": "ssh.version",
                "exp": "ssh.ver",
                "friendlyName": "Version",
                "group": "ssh",
                "help": "SSH Software Version",
                "type": "lotermfield"
            },
            {
                "dbField": "ssh.versionCnt",
                "dbField2": "ssh.versionCnt",
                "exp": "ssh.ver.cnt",
                "friendlyName": "Version Cnt",
                "group": "ssh",
                "help": "Unique number of SSH Software Version",
                "type": "integer"
            },
            {
                "dbField": "firstPacket",
                "dbField2": "firstPacket",
                "exp": "starttime",
                "friendlyName": "Start Time",
                "group": "general",
                "help": "Session Start Time",
                "type": "seconds",
                "type2": "date"
            },
            {
                "dbField": "lastPacket",
                "dbField2": "lastPacket",
                "exp": "stoptime",
                "friendlyName": "Stop Time",
                "group": "general",
                "help": "Session Stop Time",
                "type": "seconds",
                "type2": "date"
            },
            {
                "dbField": "tags",
                "dbField2": "tags",
                "exp": "tags",
                "friendlyName": "Tags",
                "group": "general",
                "help": "Tags set for session",
                "type": "termfield"
            },
            {
                "dbField": "tagsCnt",
                "dbField2": "tagsCnt",
                "exp": "tags.cnt",
                "friendlyName": "Tags Cnt",
                "group": "general",
                "help": "Unique number of Tags set for session",
                "type": "integer"
            },
            {
                "dbField": "tcpflags.ack",
                "dbField2": "tcpflags.ack",
                "exp": "tcpflags.ack",
                "friendlyName": "TCP Flag ACK",
                "group": "general",
                "help": "Count of packets with only the ACK flag set",
                "type": "integer"
            },
            {
                "dbField": "tcpflags.fin",
                "dbField2": "tcpflags.fin",
                "exp": "tcpflags.fin",
                "friendlyName": "TCP Flag FIN",
                "group": "general",
                "help": "Count of packets with FIN flag set",
                "type": "integer"
            },
            {
                "dbField": "tcpflags.psh",
                "dbField2": "tcpflags.psh",
                "exp": "tcpflags.psh",
                "friendlyName": "TCP Flag PSH",
                "group": "general",
                "help": "Count of packets with PSH flag set",
                "type": "integer"
            },
            {
                "dbField": "tcpflags.rst",
                "dbField2": "tcpflags.rst",
                "exp": "tcpflags.rst",
                "friendlyName": "TCP Flag RST",
                "group": "general",
                "help": "Count of packets with RST flag set",
                "type": "integer"
            },
            {
                "dbField": "tcpflags.syn",
                "dbField2": "tcpflags.syn",
                "exp": "tcpflags.syn",
                "friendlyName": "TCP Flag SYN",
                "group": "general",
                "help": "Count of packets with SYN and no ACK flag set",
                "type": "integer"
            },
            {
                "dbField": "tcpflags.syn-ack",
                "dbField2": "tcpflags.syn-ack",
                "exp": "tcpflags.syn-ack",
                "friendlyName": "TCP Flag SYN-ACK",
                "group": "general",
                "help": "Count of packets with SYN and ACK flag set",
                "type": "integer"
            },
            {
                "dbField": "tcpflags.urg",
                "dbField2": "tcpflags.urg",
                "exp": "tcpflags.urg",
                "friendlyName": "TCP Flag URG",
                "group": "general",
                "help": "Count of packets with URG flag set",
                "type": "integer"
            },
            {
                "dbField": "tls.cipher",
                "dbField2": "tls.cipher",
                "exp": "tls.cipher",
                "friendlyName": "Cipher",
                "group": "tls",
                "help": "SSL/TLS cipher field",
                "type": "uptermfield"
            },
            {
                "dbField": "tls.cipherCnt",
                "dbField2": "tls.cipherCnt",
                "exp": "tls.cipher.cnt",
                "friendlyName": "Cipher Cnt",
                "group": "tls",
                "help": "Unique number of SSL/TLS cipher field",
                "type": "integer"
            },
            {
                "dbField": "tls.ja3",
                "dbField2": "tls.ja3",
                "exp": "tls.ja3",
                "friendlyName": "JA3",
                "group": "tls",
                "help": "SSL/TLS JA3 field",
                "type": "lotermfield"
            },
            {
                "dbField": "tls.ja3Cnt",
                "dbField2": "tls.ja3Cnt",
                "exp": "tls.ja3.cnt",
                "friendlyName": "JA3 Cnt",
                "group": "tls",
                "help": "Unique number of SSL/TLS JA3 field",
                "type": "integer"
            },
            {
                "dbField": "tls.ja3s",
                "dbField2": "tls.ja3s",
                "exp": "tls.ja3s",
                "friendlyName": "JA3S",
                "group": "tls",
                "help": "SSL/TLS JA3S field",
                "type": "lotermfield"
            },
            {
                "dbField": "tls.ja3sCnt",
                "dbField2": "tls.ja3sCnt",
                "exp": "tls.ja3s.cnt",
                "friendlyName": "JA3S Cnt",
                "group": "tls",
                "help": "Unique number of SSL/TLS JA3S field",
                "type": "integer"
            },
            {
                "dbField": "tlsidall",
                "dbField2": "tlsidall",
                "exp": "tls.sessionid",
                "friendlyName": "Src or Dst Session Id",
                "group": "general",
                "help": "Shorthand for tls.sessionid.src or tls.sessionid.dst",
                "regex": "^tls\\.sessionid\\.(?:(?!\\.cnt$).)*$",
                "type": "lotermfield"
            },
            {
                "dbField": "tls.dstSessionId",
                "dbField2": "tls.dstSessionId",
                "exp": "tls.sessionid.dst",
                "friendlyName": "Dst Session Id",
                "group": "tls",
                "help": "SSL/TLS Dst Session Id",
                "type": "lotermfield"
            },
            {
                "dbField": "tls.srcSessionId",
                "dbField2": "tls.srcSessionId",
                "exp": "tls.sessionid.src",
                "friendlyName": "Src Session Id",
                "group": "tls",
                "help": "SSL/TLS Src Session Id",
                "type": "lotermfield"
            },
            {
                "dbField": "tls.version",
                "dbField2": "tls.version",
                "exp": "tls.version",
                "friendlyName": "Version",
                "group": "tls",
                "help": "SSL/TLS version field",
                "type": "termfield"
            },
            {
                "dbField": "tls.versionCnt",
                "dbField2": "tls.versionCnt",
                "exp": "tls.version.cnt",
                "friendlyName": "Version Cnt",
                "group": "tls",
                "help": "Unique number of SSL/TLS version field",
                "type": "integer"
            },
            {
                "category": "user",
                "dbField": "user",
                "dbField2": "user",
                "exp": "user",
                "friendlyName": "User",
                "group": "general",
                "help": "External user set for session",
                "type": "lotermfield"
            },
            {
                "dbField": "userCnt",
                "dbField2": "userCnt",
                "exp": "user.cnt",
                "friendlyName": "User Cnt",
                "group": "general",
                "help": "Unique number of External user set for session",
                "type": "integer"
            },
            {
                "dbField": "viewand",
                "dbField2": "viewand",
                "exp": "view",
                "friendlyName": "View Name",
                "group": "general",
                "help": "Arkime view name",
                "noFacet": "true",
                "type": "viewand"
            },
            {
                "dbField": "network.vlan.id",
                "dbField2": "network.vlan.id",
                "exp": "vlan",
                "friendlyName": "VLan",
                "group": "general",
                "help": "vlan value",
                "type": "integer"
            },
            {
                "dbField": "network.vlan.id-cnt",
                "dbField2": "network.vlan.id-cnt",
                "exp": "vlan.cnt",
                "friendlyName": "VLan Cnt",
                "group": "general",
                "help": "Unique number of vlan value",
                "type": "integer"
            }
        ]
    }
}
```

#### Human Readable Output

>### Fields Results:
>|Friendly Name|Type|Group|Help|DB Field|
>|---|---|---|---|---|
>| All ASN fields | termfield | general | Search all ASN fields | asnall |
>|  ASN | termfield | dns | GeoIP ASN string calculated from the IP from DNS result | dns.ASN |
>|  ASN | termfield | dns | GeoIP ASN string calculated from the IPs for mailservers | dns.mailserverASN |
>|  ASN | termfield | dns | GeoIP ASN string calculated from the IPs for nameservers | dns.nameserverASN |
>| Dst ASN | termfield | general | GeoIP ASN string calculated from the destination IP | destination.as.full |
>|  ASN | termfield | email | GeoIP ASN string calculated from the Email IP address | email.ASN |
>|  ASN | termfield | socks | GeoIP ASN string calculated from the SOCKS destination IP | socks.ASN |
>| Src ASN | termfield | general | GeoIP ASN string calculated from the source IP | source.as.full |
>| XFF  ASN | termfield | http | GeoIP ASN string calculated from the X-Forwarded-For Header | http.xffASN |
>| Asset | lotermfield | general | Asset name | asset |
>| Asset Cnt | integer | general | Unique number of Asset name | assetCnt |
>| Type | uptermfield | bgp | BGP Type field | bgp.type |
>| Bytes | integer | general | Total number of raw bytes sent AND received in a session | network.bytes |
>| Dst Bytes | integer | general | Total number of raw bytes sent by destination in a session | destination.bytes |
>| Src Bytes | integer | general | Total number of raw bytes sent by source in a session | source.bytes |
>| Alt Name | lotermfield | cert | Certificate alternative names | cert.alt |
>| Alt Name Cnt | integer | cert | Unique number of Certificate alternative names | cert.altCnt |
>| Cert Cnt | integer | cert | Count of certificates | certCnt |
>| Curve | termfield | cert | Curve Algorithm | cert.curve |
>| Hash | lotermfield | cert | SHA1 hash of entire certificate | cert.hash |
>| Issuer CN | lotermfield | cert | Issuer's common name | cert.issuerCN |
>| Issuer ON | termfield | cert | Issuer's organization name | cert.issuerON |
>| Not After | date | cert | Certificate is not valid after this date | cert.notAfter |
>| Not Before | date | cert | Certificate is not valid before this date | cert.notBefore |
>| Public Algorithm | termfield | cert | Public Key Algorithm | cert.publicAlgorithm |
>| Days remaining | integer | cert | Certificate is still valid for this many days | cert.remainingDays |
>| Serial Number | lotermfield | cert | Serial Number | cert.serial |
>| Subject CN | lotermfield | cert | Subject's common name | cert.subjectCN |
>| Subject ON | termfield | cert | Subject's organization name | cert.subjectON |
>| Days Valid For | integer | cert | Certificate is valid for this many days total | cert.validDays |
>| Community Id | termfield | general | Community id flow hash | network.community_id |
>| All country fields | uptermfield | general | Search all country fields | geoall |
>|  GEO | uptermfield | dns | GeoIP country string calculated from the IP from DNS result | dns.GEO |
>|  GEO | uptermfield | dns | GeoIP country string calculated from the IPs for mailservers | dns.mailserverGEO |
>|  GEO | uptermfield | dns | GeoIP country string calculated from the IPs for nameservers | dns.nameserverGEO |
>| Dst Country | uptermfield | general | Destination Country | destination.geo.country_iso_code |
>|  GEO | uptermfield | email | GeoIP country string calculated from the Email IP address | email.GEO |
>|  GEO | uptermfield | socks | GeoIP country string calculated from the SOCKS destination IP | socks.GEO |
>| Src Country | uptermfield | general | Source Country | source.geo.country_iso_code |
>| XFF  GEO | uptermfield | http | GeoIP country string calculated from the X-Forwarded-For Header | http.xffGEO |
>| Data bytes | integer | general | Total number of data bytes sent AND received in a session | totDataBytes |
>| Dst data bytes | integer | general | Total number of data bytes sent by destination in a session | server.bytes |
>| Src data bytes | integer | general | Total number of data bytes sent by source in a session | client.bytes |
>| Dst ASN Number | integer | general | GeoIP ASN Number calculated from the destination IP | destination.as.number |
>| Dst ASN Name | termfield | general | GeoIP ASN Name calculated from the destination IP | destination.as.organization.name |
>| Host | lotermfield | dhcp | DHCP Host | dhcp.host |
>| Host Cnt | integer | dhcp | Unique number of DHCP Host | dhcp.hostCnt |
>| Hostname Tokens | lotextfield | dhcp | DHCP Hostname Tokens | dhcp.hostTokens |
>| Transaction id | lotermfield | dhcp | DHCP Transaction Id | dhcp.id |
>| Transaction id Cnt | integer | dhcp | Unique number of DHCP Transaction Id | dhcp.idCnt |
>| Client MAC | lotermfield | dhcp | Client ethernet MAC  | dhcp.mac |
>| Client MAC Cnt | integer | dhcp | Unique number of Client ethernet MAC  | dhcp.macCnt |
>| Client OUI | termfield | dhcp | Client ethernet OUI  | dhcp.oui |
>| Client OUI Cnt | integer | dhcp | Unique number of Client ethernet OUI  | dhcp.ouiCnt |
>| Type | uptermfield | dhcp | DHCP Type | dhcp.type |
>| Type Cnt | integer | dhcp | Unique number of DHCP Type | dhcp.typeCnt |
>| Op Code | uptermfield | dns | DNS lookup op code | dns.opcode |
>| Op Code Cnt | integer | dns | Unique number of DNS lookup op code | dns.opcodeCnt |
>| Puny | lotermfield | dns | DNS lookup punycode | dns.puny |
>| Puny Cnt | integer | dns | Unique number of DNS lookup punycode | dns.punyCnt |
>| Query Class | uptermfield | dns | DNS lookup query class | dns.qc |
>| Query Class Cnt | integer | dns | Unique number of DNS lookup query class | dns.qcCnt |
>| Query Type | uptermfield | dns | DNS lookup query type | dns.qt |
>| Query Type Cnt | integer | dns | Unique number of DNS lookup query type | dns.qtCnt |
>| Status Code | uptermfield | dns | DNS lookup return code | dns.status |
>| Status Code Cnt | integer | dns | Unique number of DNS lookup return code | dns.statusCnt |
>| Dst DSCP | integer | general | Destination non zero differentiated services class selector set for session | dstDscp |
>| Dst DSCP Cnt | integer | general | Unique number of Destination non zero differentiated services class selector set for session | dstDscpCnt |
>| Src DSCP | integer | general | Source non zero differentiated services class selector set for session | srcDscp |
>| Src DSCP Cnt | integer | general | Unique number of Source non zero differentiated services class selector set for session | srcDscpCnt |
>| email.authorization | termfield | email | Email header authorization | email.header-authorization |
>| Body Magic | termfield | email | The content type of body determined by libfile/magic | email.bodyMagic |
>| Body Magic Cnt | integer | email | Unique number of The content type of body determined by libfile/magic | email.bodyMagicCnt |
>| Content-Type | termfield | email | Email content-type header | email.contentType |
>| Content-Type Cnt | integer | email | Unique number of Email content-type header | email.contentTypeCnt |
>| Receiver | lotermfield | email | Email to address | email.dst |
>| Receiver Cnt | integer | email | Unique number of Email to address | email.dstCnt |
>| Attach Content-Type | termfield | email | Email attachment content types | email.fileContentType |
>| Attach Content-Type Cnt | integer | email | Unique number of Email attachment content types | email.fileContentTypeCnt |
>| Filenames | termfield | email | Email attachment filenames | email.filename |
>| Filenames Cnt | integer | email | Unique number of Email attachment filenames | email.filenameCnt |
>| Header | lotermfield | email | Email has the header set | email.header |
>| Header Cnt | integer | email | Unique number of Email has the header set | email.headerCnt |
>| Header Value | termfield | email | Email has the header value | email.headerValue |
>| Header Value Cnt | integer | email | Unique number of Email has the header value | email.headerValueCnt |
>| Attach MD5s | termfield | email | Email attachment MD5s | email.md5 |
>| Attach MD5s Cnt | integer | email | Unique number of Email attachment MD5s | email.md5Cnt |
>| Id | termfield | email | Email Message-Id header | email.id |
>| Id Cnt | integer | email | Unique number of Email Message-Id header | email.idCnt |
>| Mime-Version | termfield | email | Email Mime-Header header | email.mimeVersion |
>| Mime-Version Cnt | integer | email | Unique number of Email Mime-Header header | email.mimeVersionCnt |
>| SMTP Hello | lotermfield | email | SMTP HELO/EHLO | email.smtpHello |
>| SMTP Hello Cnt | integer | email | Unique number of SMTP HELO/EHLO | email.smtpHelloCnt |
>| Sender | lotermfield | email | Email from address | email.src |
>| Sender Cnt | integer | email | Unique number of Email from address | email.srcCnt |
>| Subject | termfield | email | Email subject header | email.subject |
>| Subject Cnt | integer | email | Unique number of Email subject header | email.subjectCnt |
>| X-Mailer Header | termfield | email | Email X-Mailer header | email.useragent |
>| X-Mailer Header Cnt | integer | email | Unique number of Email X-Mailer header | email.useragentCnt |
>| email.x-priority | integer | email | Email header x-priority | email.header-x-priority |
>| Filename | fileand | general | Arkime offline pcap filename | fileand |
>| GRE IP | ip | general | GRE ip addresses for session | greIp |
>| GRE IP ASN | termfield | general | GeoIP ASN string calculated from the GRE ip addresses for session | greASN |
>| GRE IP Cnt | integer | general | Unique number of GRE ip addresses for session | greIpCnt |
>| GRE IP GEO | uptermfield | general | GeoIP country string calculated from the GRE ip addresses for session | greGEO |
>| GRE IP RIR | uptermfield | general | Regional Internet Registry string calculated from GRE ip addresses for session | greRIR |
>| All Host fields | lotermfield | general | Search all Host fields | hostall |
>| Host | lotermfield | dns | DNS lookup hostname | dns.host |
>| All Host | lotermfield | dns | Shorthand for host.dns or host.dns.nameserver | dnshostall |
>| Host Cnt | integer | dns | Unique number of DNS lookup hostname | dns.hostCnt |
>| MX Host | lotermfield | dns | Hostnames for Mail Exchange Server | dns.mailserverHost |
>| MX Host Cnt | integer | dns | Unique number of Hostnames for Mail Exchange Server | dns.mailserverHostCnt |
>| NS Host | lotermfield | dns | Hostnames for Name Server | dns.nameserverHost |
>| NS Host Cnt | integer | dns | Unique number of Hostnames for Name Server | dns.nameserverHostCnt |
>| Hostname Tokens | lotextfield | dns | DNS lookup hostname tokens | dns.hostTokens |
>| Hostname | lotermfield | email | Email hostnames | email.host |
>| Hostname Cnt | integer | email | Unique number of Email hostnames | email.hostCnt |
>| Hostname Tokens | lotextfield | email | Email Hostname Tokens | email.hostTokens |
>| Hostname | lotermfield | http | HTTP host header field | http.host |
>| Hostname Cnt | integer | http | Unique number of HTTP host header field | http.hostCnt |
>| Hostname Tokens | lotextfield | http | HTTP host Tokens header field | http.hostTokens |
>| Hostname | lotermfield | quic | QUIC host header field | quic.host |
>| Hostname Cnt | integer | quic | Unique number of QUIC host header field | quic.hostCnt |
>| Hostname Tokens | lotextfield | quic | QUIC host tokens header field | quic.hostTokens |
>| Hostname | termfield | smb | SMB Host name | smb.host |
>| Hostname Cnt | integer | smb | Unique number of SMB Host name | smb.hostCnt |
>| Host | lotermfield | socks | SOCKS destination host | socks.host |
>| Hostname Tokens | lotextfield | socks | SOCKS Hostname Tokens | socks.hostTokens |
>| http.authorization | termfield | http | Request header authorization | http.request-authorization |
>| http.authorization Cnt | integer | http | Unique number of Request header authorization | http.request-authorizationCnt |
>| Auth Type | lotermfield | http | HTTP Auth Type | http.authType |
>| Auth Type Cnt | integer | http | Unique number of HTTP Auth Type | http.authTypeCnt |
>| Body Magic | termfield | http | The content type of body determined by libfile/magic | http.bodyMagic |
>| Body Magic Cnt | integer | http | Unique number of The content type of body determined by libfile/magic | http.bodyMagicCnt |
>| http.content-type | termfield | http | Request header content-type | http.request-content-type |
>| http.content-type Cnt | integer | http | Unique number of Response header content-type | http.response-content-typeCnt |
>| Cookie Keys | termfield | http | The keys to cookies sent up in requests | http.cookieKey |
>| Cookie Keys Cnt | integer | http | Unique number of The keys to cookies sent up in requests | http.cookieKeyCnt |
>| Cookie Values | termfield | http | The values to cookies sent up in requests | http.cookieValue |
>| Cookie Values Cnt | integer | http | Unique number of The values to cookies sent up in requests | http.cookieValueCnt |
>| Has Src or Dst Header | lotermfield | http | Shorthand for http.hasheader.src or http.hasheader.dst | hhall |
>| Has Dst Header | lotermfield | http | Response has header present | http.responseHeader |
>| Has Dst Header Cnt | integer | http | Unique number of Response has header present | http.responseHeaderCnt |
>| Response Header Values | lotermfield | http | Contains response header values | http.responseHeaderValue |
>| Response Header Values Cnt | integer | http | Unique number of Contains response header values | http.responseHeaderValueCnt |
>| Has Src Header | lotermfield | http | Request has header present | http.requestHeader |
>| Has Src Header Cnt | integer | http | Unique number of Request has header present | http.requestHeaderCnt |
>| Request Header Values | lotermfield | http | Contains request header values | http.requestHeaderValue |
>| Request Header Values Cnt | integer | http | Unique number of Contains request header values | http.requestHeaderValueCnt |
>| Has Value in Src or Dst Header | lotermfield | http | Shorthand for http.hasheader.src.value or http.hasheader.dst.value | hhvalueall |
>| http.location | termfield | http | Response header location | http.response-location |
>| Body MD5 | lotermfield | http | MD5 of http body response | http.md5 |
>| Body MD5 Cnt | integer | http | Unique number of MD5 of http body response | http.md5Cnt |
>| Request Method | termfield | http | HTTP Request Method | http.method |
>| Request Method Cnt | integer | http | Unique number of HTTP Request Method | http.methodCnt |
>| http.origin | termfield | http | Request header origin | http.request-origin |
>| http.referer | termfield | http | Request header referer | http.request-referer |
>| http.referer Cnt | integer | http | Unique number of Request header referer | http.request-refererCnt |
>| Request Body | termfield | http | HTTP Request Body | http.requestBody |
>| http.server | termfield | http | Response header server | http.response-server |
>| Status Code | integer | http | Response HTTP numeric status code | http.statuscode |
>| Status Code Cnt | integer | http | Unique number of Response HTTP numeric status code | http.statuscodeCnt |
>| URI | termfield | http | URIs for request | http.uri |
>| URI Cnt | integer | http | Unique number of URIs for request | http.uriCnt |
>| QS Keys | termfield | http | Keys from query string of URI | http.key |
>| QS Keys Cnt | integer | http | Unique number of Keys from query string of URI | http.keyCnt |
>| URI Path | termfield | http | Path portion of URI | http.path |
>| URI Path Cnt | integer | http | Unique number of Path portion of URI | http.pathCnt |
>| URI Tokens | lotextfield | http | URIs Tokens for request | http.uriTokens |
>| QS Values | termfield | http | Values from query string of URI | http.value |
>| QS Values Cnt | integer | http | Unique number of Values from query string of URI | http.valueCnt |
>| User | termfield | http | HTTP Auth User | http.user |
>| Useragent | termfield | http | User-Agent Header | http.useragent |
>| Useragent Cnt | integer | http | Unique number of User-Agent Header | http.useragentCnt |
>| Useragent Tokens | lotextfield | http | User-Agent Header Tokens | http.useragentTokens |
>| User Cnt | integer | http | Unique number of HTTP Auth User | http.userCnt |
>| Version | termfield | http | HTTP version number | httpversion |
>| Dst Version | termfield | http | Response HTTP version number | http.serverVersion |
>| Dst Version Cnt | integer | http | Unique number of Response HTTP version number | http.serverVersionCnt |
>| Src Version | termfield | http | Request HTTP version number | http.clientVersion |
>| Src Version Cnt | integer | http | Unique number of Request HTTP version number | http.clientVersionCnt |
>| Hunt ID | termfield | general | The ID of the packet search job that matched this session | huntId |
>| Hunt Name | termfield | general | The name of the packet search job that matched this session | huntName |
>| ICMP Code | integer | general | ICMP code field values | icmp.code |
>| ICMP Type | integer | general | ICMP type field values | icmp.type |
>| Arkime ID | termfield | general | Arkime ID for the session | _id |
>| Initial RTT | integer | general | Initial round trip time, difference between SYN and ACK timestamp divided by 2 in ms | initRTT |
>| All IP fields | ip | general | Search all ip fields | ipall |
>| IP | ip | dns | IP from DNS result | dns.ip |
>| IP | ip | dns | Shorthand for ip.dns or ip.dns.nameserver | dnsipall |
>| IP Cnt | integer | dns | Unique number of IP from DNS result | dns.ipCnt |
>| IP | ip | dns | IPs for mailservers | dns.mailserverIp |
>| IP Cnt | integer | dns | Unique number of IPs for mailservers | dns.mailserverIpCnt |
>| IP | ip | dns | IPs for nameservers | dns.nameserverIp |
>| IP Cnt | integer | dns | Unique number of IPs for nameservers | dns.nameserverIpCnt |
>| Dst IP | ip | general | Destination IP | destination.ip |
>| IP | ip | email | Email IP address | email.ip |
>| IP Cnt | integer | email | Unique number of Email IP address | email.ipCnt |
>| IP Protocol | lotermfield | general | IP protocol number or friendly name | ipProtocol |
>| IP | ip | socks | SOCKS destination IP | socks.ip |
>| Src IP | ip | general | Source IP | source.ip |
>| XFF IP | ip | http | X-Forwarded-For Header | http.xffIp |
>| XFF IP Cnt | integer | http | Unique number of X-Forwarded-For Header | http.xffIpCnt |
>| Channel | termfield | irc | Channels joined | irc.channel |
>| Channel Cnt | integer | irc | Unique number of Channels joined | irc.channelCnt |
>| Nickname | termfield | irc | Nicknames set | irc.nick |
>| Nickname Cnt | integer | irc | Unique number of Nicknames set | irc.nickCnt |
>| isis.msgType | lotermfield | isis | ISIS Msg Type field | isis.msgType |
>| cname | termfield | krb5 | Kerberos 5 cname | krb5.cname |
>| cname Cnt | integer | krb5 | Unique number of Kerberos 5 cname | krb5.cnameCnt |
>| Realm | termfield | krb5 | Kerberos 5 Realm | krb5.realm |
>| Realm Cnt | integer | krb5 | Unique number of Kerberos 5 Realm | krb5.realmCnt |
>| sname | termfield | krb5 | Kerberos 5 sname | krb5.sname |
>| sname Cnt | integer | krb5 | Unique number of Kerberos 5 sname | krb5.snameCnt |
>| Auth Type | termfield | ldap | The auth type of ldap bind | ldap.authtype |
>| Auth Type Cnt | integer | ldap | Unique number of The auth type of ldap bind | ldap.authtypeCnt |
>| Bind Name | termfield | ldap | The bind name of ldap bind | ldap.bindname |
>| Bind Name Cnt | integer | ldap | Unique number of The bind name of ldap bind | ldap.bindnameCnt |
>| Src or Dst MAC | lotermfield | general | Shorthand for mac.src or mac.dst | macall |
>| Dst MAC | lotermfield | general | Destination ethernet mac addresses set for session | destination.mac |
>| Dst MAC Cnt | integer | general | Unique number of Destination ethernet mac addresses set for session | destination.mac-cnt |
>| Src MAC | lotermfield | general | Source ethernet mac addresses set for session | source.mac |
>| Src MAC Cnt | integer | general | Unique number of Source ethernet mac addresses set for session | source.mac-cnt |
>| Modbus Exception Code | integer | modbus | Modbus Exception Codes | modbus.exccode |
>| Modbus Exception Code Cnt | integer | modbus | Unique number of Modbus Exception Codes | modbus.exccodeCnt |
>| Modbus Function Code | integer | modbus | Modbus Function Codes | modbus.funccode |
>| Modbus Function Code Cnt | integer | modbus | Unique number of Modbus Function Codes | modbus.funccodeCnt |
>| Modbus Protocol ID | integer | modbus | Modbus Protocol ID (should always be 0) | modbus.protocolid |
>| Modbus Transaction IDs | integer | modbus | Modbus Transaction IDs | modbus.transactionid |
>| Modbus Transaction IDs Cnt | integer | modbus | Unique number of Modbus Transaction IDs | modbus.transactionidCnt |
>| Modbus Unit ID | integer | modbus | Modbus Unit ID | modbus.unitid |
>| User | lotermfield | mysql | Mysql user name | mysql.user |
>| Version | termfield | mysql | Mysql server version string | mysql.version |
>| Arkime Node | termfield | general | Arkime node name the session was recorded on | node |
>| Host | lotermfield | oracle | Oracle Host | oracle.host |
>| Hostname Tokens | lotextfield | oracle | Oracle Hostname Tokens | oracle.hostTokens |
>| Service | lotermfield | oracle | Oracle Service | oracle.service |
>| User | lotermfield | oracle | Oracle User | oracle.user |
>| Dst OUI | termfield | general | Destination ethernet oui set for session | dstOui |
>| Dst OUI Cnt | integer | general | Unique number of Destination ethernet oui set for session | dstOuiCnt |
>| Src OUI | termfield | general | Source ethernet oui set for session | srcOui |
>| Src OUI Cnt | integer | general | Unique number of Source ethernet oui set for session | srcOuiCnt |
>| Packets | integer | general | Total number of packets sent AND received in a session | network.packets |
>| Dst Packets | integer | general | Total number of packets sent by destination in a session | destination.packets |
>| Src Packets | integer | general | Total number of packets sent by source in a session | source.packets |
>| Payload Dst Hex | lotermfield | general | First 8 bytes of destination payload in hex | dstPayload8 |
>| Payload Dst UTF8 | termfield | general | First 8 bytes of destination payload in utf8 | dstPayload8 |
>| Payload Hex | lotermfield | general | First 8 bytes of payload in hex | fballhex |
>| Payload Src Hex | lotermfield | general | First 8 bytes of source payload in hex | srcPayload8 |
>| Payload Src UTF8 | termfield | general | First 8 bytes of source payload in utf8 | srcPayload8 |
>| Payload UTF8 | lotermfield | general | First 8 bytes of payload in hex | fballutf8 |
>| All port fields | integer | general | Search all port fields | portall |
>| Dst Port | integer | general | Source Port | destination.port |
>| Port | integer | socks | SOCKS destination port | socks.port |
>| Src Port | integer | general | Source Port | source.port |
>| Application | termfield | postgresql | Postgresql application | postgresql.app |
>| Database | termfield | postgresql | Postgresql database | postgresql.db |
>| User | termfield | postgresql | Postgresql user name | postgresql.user |
>| Protocols | termfield | general | Protocols set for session | protocol |
>| Protocols Cnt | integer | general | Unique number of Protocols set for session | protocolCnt |
>| User-Agent | termfield | quic | User-Agent | quic.useragent |
>| User-Agent Cnt | integer | quic | Unique number of User-Agent | quic.useragentCnt |
>| Version | termfield | quic | QUIC Version | quic.version |
>| Version Cnt | integer | quic | Unique number of QUIC Version | quic.versionCnt |
>| Endpoint IP | ip | radius | Radius endpoint ip addresses for session | radius.endpointIp |
>| Endpoint IP ASN | termfield | radius | GeoIP ASN string calculated from the Radius endpoint ip addresses for session | radius.endpointASN |
>| Endpoint IP Cnt | integer | radius | Unique number of Radius endpoint ip addresses for session | radius.endpointIpCnt |
>| Endpoint IP GEO | uptermfield | radius | GeoIP country string calculated from the Radius endpoint ip addresses for session | radius.endpointGEO |
>| Endpoint IP RIR | uptermfield | radius | Regional Internet Registry string calculated from Radius endpoint ip addresses for session | radius.endpointRIR |
>| Framed IP | ip | radius | Radius framed ip addresses for session | radius.framedIp |
>| Framed IP ASN | termfield | radius | GeoIP ASN string calculated from the Radius framed ip addresses for session | radius.framedASN |
>| Framed IP Cnt | integer | radius | Unique number of Radius framed ip addresses for session | radius.framedIpCnt |
>| Framed IP GEO | uptermfield | radius | GeoIP country string calculated from the Radius framed ip addresses for session | radius.framedGEO |
>| Framed IP RIR | uptermfield | radius | Regional Internet Registry string calculated from Radius framed ip addresses for session | radius.framedRIR |
>| MAC | lotermfield | radius | Radius Mac | radius.mac |
>| MAC Cnt | integer | radius | Unique number of Radius Mac | radius.macCnt |
>| User | termfield | radius | RADIUS user | radius.user |
>| All rir fields | uptermfield | general | Search all rir fields | rirall |
>|  RIR | uptermfield | dns | Regional Internet Registry string calculated from IP from DNS result | dns.RIR |
>|  RIR | uptermfield | dns | Regional Internet Registry string calculated from IPs for mailservers | dns.mailserverRIR |
>|  RIR | uptermfield | dns | Regional Internet Registry string calculated from IPs for nameservers | dns.nameserverRIR |
>| Dst RIR | uptermfield | general | Destination RIR | dstRIR |
>|  RIR | uptermfield | email | Regional Internet Registry string calculated from Email IP address | email.RIR |
>|  RIR | uptermfield | socks | Regional Internet Registry string calculated from SOCKS destination IP | socks.RIR |
>| Src RIR | uptermfield | general | Source RIR | srcRIR |
>| XFF  RIR | uptermfield | http | Regional Internet Registry string calculated from X-Forwarded-For Header | http.xffRIR |
>| Arkime Root ID | termfield | general | Arkime ID of the first session in a multi session stream | rootId |
>| Scrubbed By | lotermfield | general | SPI data was scrubbed by | scrubby |
>| Session Length | integer | general | Session Length in milliseconds so far | length |
>| Session Segments | integer | general | Number of segments in session so far | segmentCnt |
>| Domain | termfield | smb | SMB domain | smb.domain |
>| Domain Cnt | integer | smb | Unique number of SMB domain | smb.domainCnt |
>| Filename | termfield | smb | SMB files opened, created, deleted | smb.filename |
>| Filename Cnt | integer | smb | Unique number of SMB files opened, created, deleted | smb.filenameCnt |
>| OS | termfield | smb | SMB OS information | smb.os |
>| OS Cnt | integer | smb | Unique number of SMB OS information | smb.osCnt |
>| Share | termfield | smb | SMB shares connected to | smb.share |
>| Share Cnt | integer | smb | Unique number of SMB shares connected to | smb.shareCnt |
>| User | termfield | smb | SMB User | smb.user |
>| User Cnt | integer | smb | Unique number of SMB User | smb.userCnt |
>| Version | termfield | smb | SMB Version information | smb.version |
>| Version Cnt | integer | smb | Unique number of SMB Version information | smb.versionCnt |
>| Community | termfield | snmp | SNMP Community | snmp.community |
>| Community Cnt | integer | snmp | Unique number of SNMP Community | snmp.communityCnt |
>| Error Code | integer | snmp | SNMP Error Code | snmp.error |
>| Error Code Cnt | integer | snmp | Unique number of SNMP Error Code | snmp.errorCnt |
>| Type | termfield | snmp | SNMP Type | snmp.type |
>| Type Cnt | integer | snmp | Unique number of SNMP Type | snmp.typeCnt |
>| Variable | termfield | snmp | SNMP Variable | snmp.variable |
>| Variable Cnt | integer | snmp | Unique number of SNMP Variable | snmp.variableCnt |
>| Version | integer | snmp | SNMP Version | snmp.version |
>| Version Cnt | integer | snmp | Unique number of SNMP Version | snmp.versionCnt |
>| User | termfield | socks | SOCKS authenticated user | socks.user |
>| Src ASN Number | integer | general | GeoIP ASN Number calculated from the source IP | source.as.number |
>| Src ASN Name | termfield | general | GeoIP ASN Name calculated from the source IP | source.as.organization.name |
>| Arkime Source Node | termfield | general | Source Arkime node name the session was recorded on when using send to cluster | srcNode |
>| HASSH | lotermfield | ssh | SSH HASSH field | ssh.hassh |
>| HASSH Cnt | integer | ssh | Unique number of SSH HASSH field | ssh.hasshCnt |
>| HASSH Server | lotermfield | ssh | SSH HASSH Server field | ssh.hasshServer |
>| HASSH Server Cnt | integer | ssh | Unique number of SSH HASSH Server field | ssh.hasshServerCnt |
>| Key | termfield | ssh | SSH Key | ssh.key |
>| Key Cnt | integer | ssh | Unique number of SSH Key | ssh.keyCnt |
>| Version | lotermfield | ssh | SSH Software Version | ssh.version |
>| Version Cnt | integer | ssh | Unique number of SSH Software Version | ssh.versionCnt |
>| Start Time | seconds | general | Session Start Time | firstPacket |
>| Stop Time | seconds | general | Session Stop Time | lastPacket |
>| Tags | termfield | general | Tags set for session | tags |
>| Tags Cnt | integer | general | Unique number of Tags set for session | tagsCnt |
>| TCP Flag ACK | integer | general | Count of packets with only the ACK flag set | tcpflags.ack |
>| TCP Flag FIN | integer | general | Count of packets with FIN flag set | tcpflags.fin |
>| TCP Flag PSH | integer | general | Count of packets with PSH flag set | tcpflags.psh |
>| TCP Flag RST | integer | general | Count of packets with RST flag set | tcpflags.rst |
>| TCP Flag SYN | integer | general | Count of packets with SYN and no ACK flag set | tcpflags.syn |
>| TCP Flag SYN-ACK | integer | general | Count of packets with SYN and ACK flag set | tcpflags.syn-ack |
>| TCP Flag URG | integer | general | Count of packets with URG flag set | tcpflags.urg |
>| Cipher | uptermfield | tls | SSL/TLS cipher field | tls.cipher |
>| Cipher Cnt | integer | tls | Unique number of SSL/TLS cipher field | tls.cipherCnt |
>| JA3 | lotermfield | tls | SSL/TLS JA3 field | tls.ja3 |
>| JA3 Cnt | integer | tls | Unique number of SSL/TLS JA3 field | tls.ja3Cnt |
>| JA3S | lotermfield | tls | SSL/TLS JA3S field | tls.ja3s |
>| JA3S Cnt | integer | tls | Unique number of SSL/TLS JA3S field | tls.ja3sCnt |
>| Src or Dst Session Id | lotermfield | general | Shorthand for tls.sessionid.src or tls.sessionid.dst | tlsidall |
>| Dst Session Id | lotermfield | tls | SSL/TLS Dst Session Id | tls.dstSessionId |
>| Src Session Id | lotermfield | tls | SSL/TLS Src Session Id | tls.srcSessionId |
>| Version | termfield | tls | SSL/TLS version field | tls.version |
>| Version Cnt | integer | tls | Unique number of SSL/TLS version field | tls.versionCnt |
>| User | lotermfield | general | External user set for session | user |
>| User Cnt | integer | general | Unique number of External user set for session | userCnt |
>| View Name | viewand | general | Arkime view name | viewand |
>| VLan | integer | general | vlan value | network.vlan.id |
>| VLan Cnt | integer | general | Unique number of vlan value | network.vlan.id-cnt |


### arkime-spigraph-get
***
Gets a list of values for a field with counts and graph data and returns them to the client.


#### Base Command

`arkime-spigraph-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | The database field to get data for. Defaults to “node”. | Required | 
| date | The number of hours of data to return (-1 means all data). Defaults to 1. | Optional | 
| expression | The search expression string. | Optional | 
| start_time | If the date parameter is not set, this is the start time of data to return. Format is seconds since Unix EPOC. | Optional | 
| stop_time | If the date parameter is not set, this is the stop time of data to return. Format is seconds since Unix EPOC. | Optional | 
| view | The view name to apply before the expression. | Optional | 
| fields | Comma separated list of db field names to return. Default is ipProtocol, rootId, totDataBytes, srcDataBytes, dstDataBytes, firstPacket, lastPacket, srcIp, srcPort, dstIp, dstPort, totPackets, srcPackets, dstPackets, totBytes, srcBytes, dstBytes, node, http.uri, srcGEO, dstGEO, email.subject, email.src, email.dst, email.filename, dns.host, cert, irc.channel, http.xffGEO. | Optional | 
| bounding | "last"	Query sessions based on different aspects of a session’s time. Options include: ‘first’ - First Packet: the timestamp of the first packet received for the session. ‘last’ - Last Packet: The timestamp of the last packet received for the session. ‘both’ - Bounded: Both the first and last packet timestamps for the session must be inside the time window. ‘either’ - Session Overlaps: The timestamp of the first packet must be before the end of the time window AND the timestamp of the last packet must be after the start of the time window. ‘database’ - Database: The timestamp the session was written to the database. This can be up to several minutes AFTER the last packet was received. | Optional | 
| strictly | When set the entire session must be inside the date range to be observed, otherwise if it overlaps it is displayed. Overwrites the bounding parameter, sets bonding to ‘both’. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.SpiGraph.items.name | String | The name. | 
| Arkime.SpiGraph.items.count | Number | The count. | 
| Arkime.SpiGraph.items.graph.xmin | Date | The graph xmin. | 
| Arkime.SpiGraph.items.graph.xmax | Date | The graph xmax. | 
| Arkime.SpiGraph.items.graph.interval | Number | The graph interval. | 
| Arkime.SpiGraph.items.graph.sessionsHisto | Number | The graph sessionsHisto. | 
| Arkime.SpiGraph.items.graph.sessionsTotal | Number | The sessions total. | 
| Arkime.SpiGraph.items.graph.source.packetsHisto | Number | The source packets histo. | 
| Arkime.SpiGraph.items.graph.destination.packetsHisto | Number | The destination packets histo. | 
| Arkime.SpiGraph.items.graph.network.packetsTotal | Number | The network packets total. | 
| Arkime.SpiGraph.items.graph.source.bytesHisto | Number | The source bytesHisto. | 
| Arkime.SpiGraph.items.graph.destination.bytesHisto | Number | The destination bytesHisto. | 
| Arkime.SpiGraph.items.graph.network.bytesTotal | Date | The network bytesTotal. | 
| Arkime.SpiGraph.items.graph.client.bytesHisto | Number | The client bytesHisto. | 
| Arkime.SpiGraph.items.graph.server.bytesHisto | Number | The server bytesHisto. | 
| Arkime.SpiGraph.items.graph.totDataBytesTotal | Date | The graph totDataBytesTotal. | 
| Arkime.SpiGraph.items.sessionsHisto | Number | The items sessionsHisto. | 
| Arkime.SpiGraph.items.source.packetsHisto | Number | The source packetsHisto. | 
| Arkime.SpiGraph.items.destination.packetsHisto | Number | The destination packetsHisto. | 
| Arkime.SpiGraph.items.source.bytesHisto | Number | The source bytesHisto. | 
| Arkime.SpiGraph.items.destination.bytesHisto | Date | The destination bytesHisto. | 
| Arkime.SpiGraph.items.client.bytesHisto | Number | The client bytesHisto. | 
| Arkime.SpiGraph.items.server.bytesHisto | Date | The server bytesHisto. | 
| Arkime.SpiGraph.items.network.packetsHisto | Number | The network packetsHisto. | 
| Arkime.SpiGraph.items.totDataBytesHisto | Date | The items totDataBytesHisto. | 
| Arkime.SpiGraph.items.network.bytesHisto | Date | The network bytesHisto. | 
| Arkime.SpiGraph.graph.xmin | Date | The graph xmin. | 
| Arkime.SpiGraph.graph.xmax | Date | The graph xmax. | 
| Arkime.SpiGraph.graph.interval | Number | The graph interval. | 
| Arkime.SpiGraph.graph.sessionsHisto | Number | The graph sessionsHisto. | 
| Arkime.SpiGraph.graph.sessionsTotal | Number | The graph sessionsTotal. | 
| Arkime.SpiGraph.graph.source.packetsHisto | Number | The source packetsHisto. | 
| Arkime.SpiGraph.graph.destination.packetsHisto | Number | The destination packetsHisto. | 
| Arkime.SpiGraph.graph.network.packetsTotal | Number | The network packetsTotal. | 
| Arkime.SpiGraph.graph.source.bytesHisto | Number | The source bytesHisto. | 
| Arkime.SpiGraph.graph.destination.bytesHisto | Number | The destination bytesHisto. | 
| Arkime.SpiGraph.graph.network.bytesTotal | Date | The network bytesTotal. | 
| Arkime.SpiGraph.graph.client.bytesHisto | Number | The client bytesHisto. | 
| Arkime.SpiGraph.graph.server.bytesHisto | Number | The server bytesHisto. | 
| Arkime.SpiGraph.graph.totDataBytesTotal | Date | The graph totDataBytesTotal. | 
| Arkime.SpiGraph.recordsTotal | Number | The total number of history results stored. | 
| Arkime.SpiGraph.recordsFiltered | Number | The number of hunts returned in this result. | 

#### Command example
```!arkime-spigraph-get field=220516-QHSdz21pJ_xCtJGoL8mbmyNv```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "1951@4060e8c8-61bb-4131-8a47-32a7d97a9726",
        "Extension": "json",
        "Info": "application/json",
        "Name": "spi_graph.json",
        "Size": 514,
        "Type": "ASCII text, with very long lines (514), with no line terminators"
    }
}
```

#### Human Readable Output



### arkime-spiview-get
***
Gets a list of field values with counts and returns them to the client.


#### Base Command

`arkime-spiview-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spi | Comma separated list of db fields to return. Optionally can be followed by :{count} to specify the number of values returned for the field (defaults to 100). | Required | 
| date | The number of hours of data to return (-1 means all data). Defaults to 1. | Optional | 
| expression | The search expression string. | Optional | 
| start_time | If the date parameter is not set, this is the start time of data to return. Format is seconds since Unix EPOC. | Optional | 
| stop_time | If the date parameter is not set, this is the stop time of data to return. Format is seconds since Unix EPOC. | Optional | 
| view | The view name to apply before the expression. | Optional | 
| fields | Comma separated list of db field names to return. Default is ipProtocol, rootId, totDataBytes, srcDataBytes, dstDataBytes, firstPacket, lastPacket, srcIp, srcPort, dstIp, dstPort, totPackets, srcPackets, dstPackets, totBytes, srcBytes, dstBytes, node, http.uri, srcGEO, dstGEO, email.subject, email.src, email.dst, email.filename, dns.host, cert, irc.channel, http.xffGEO. | Optional | 
| bounding | Query sessions based on different aspects of a session’s time. Options include: ‘first’ - First Packet: the timestamp of the first packet received for the session. ‘last’ - Last Packet: The timestamp of the last packet received for the session. ‘both’ - Bounded: Both the first and last packet timestamps for the session must be inside the time window. ‘either’ - Session Overlaps: The timestamp of the first packet must be before the end of the time window AND the timestamp of the last packet must be after the start of the time window. ‘database’ - Database: The timestamp the session was written to the database. This can be up to several minutes AFTER the last packet was received. | Optional | 
| strictly | When set the entire session must be inside the date range to be observed, otherwise if it overlaps it is displayed. Overwrites the bounding parameter, sets bonding to ‘both’. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.SpiView.spi.destination.ip.doc_count_error_upper_bound | Number | Destination ip - doc_count_error_upper_bound. | 
| Arkime.SpiView.spi.destination.ip.sum_other_doc_count | Number | Destination ip - sum_other_doc_count. | 
| Arkime.SpiView.spi.destination.ip.buckets.key | String | Destination ip - buckets key. | 
| Arkime.SpiView.spi.destination.ip.buckets.doc_count | Number | Destination ip - buckets doc_count. | 
| Arkime.SpiView.error | Unknown | The SpiView error. | 
| Arkime.SpiView.recordsTotal | Number | The total number of history results stored. | 
| Arkime.SpiView.recordsFiltered | Number | The number of history items returned in this result. | 

#### Command example
```!arkime-spiview-get spi=220516-QHSdz21pJ_xCtJGoL8mbmyNv```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "1955@4060e8c8-61bb-4131-8a47-32a7d97a9726",
        "Extension": "json",
        "Info": "application/json",
        "Name": "spi_view.json",
        "Size": 188,
        "Type": "ASCII text, with no line terminators"
    }
}
```

#### Human Readable Output



### arkime-session-tag-add
***
Add tag(s) to individual session(s) by id or by query.


#### Base Command

`arkime-session-tag-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tags | Comma separated list of tags to add to session(s). | Required | 
| session_ids | Comma separated list of sessions to add tag(s) to. | Optional | 
| segments | Whether to add tags to linked session segments. Default is no. Options include: no - Don’t add tags to linked segments all - Add tags to all linked segments time - Add tags to segments occurring in the same time period. | Optional | 
| date | The number of hours of data to return (-1 means all data). Defaults to 1. | Optional | 
| expression | The search expression string. | Optional | 
| start_time | If the date parameter is not set, this is the start time of data to return. Format is seconds since Unix EPOC. | Optional | 
| stop_time | If the date parameter is not set, this is the stop time of data to return. Format is seconds since Unix EPOC. | Optional | 
| view | The view name to apply before the expression. | Optional | 
| order | Comma separated list of db field names to sort on. Data is sorted in order of the list supplied. Optionally can be followed by :asc or :desc for ascending or descending sorting. | Optional | 
| fields | Comma separated list of db field names to return. Default is ipProtocol, rootId, totDataBytes, srcDataBytes, dstDataBytes, firstPacket, lastPacket, srcIp, srcPort, dstIp, dstPort, totPackets, srcPackets, dstPackets, totBytes, srcBytes, dstBytes, node, http.uri, srcGEO, dstGEO, email.subject, email.src, email.dst, email.filename, dns.host, cert, irc.channel, http.xffGEO. | Optional | 
| bounding | Query sessions based on different aspects of a session’s time. Options include: ‘first’ - First Packet: the timestamp of the first packet received for the session. ‘last’ - Last Packet: The timestamp of the last packet received for the session. ‘both’ - Bounded: Both the first and last packet timestamps for the session must be inside the time window. ‘either’ - Session Overlaps: The timestamp of the first packet must be before the end of the time window AND the timestamp of the last packet must be after the start of the time window. ‘database’ - Database: The timestamp the session was written to the database. This can be up to several minutes AFTER the last packet was received. | Optional | 
| strictly | 	When set the entire session must be inside the date range to be observed, otherwise if it overlaps it is displayed. Overwrites the bounding parameter, sets bonding to ‘both’. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.AddSessionTags.success | Boolean | Success status. | 
| Arkime.AddSessionTags.text | String | Text from response | 

#### Command example
```!arkime-session-tag-add tags=test ids=220425-L2AXYh6W4UJOSqilt0i3iDIL segments=time```
#### Context Example
```json
{
    "Arkime": {
        "Tag": {
            "success": true,
            "text": "Tags added successfully"
        }
    }
}
```

#### Human Readable Output

>### Session Tag Results:
>|Success|Text|
>|---|---|
>| true | Tags added successfully |


### arkime-session-tag-remove
***
Removes tag(s) from individual session(s) by id or by query.


#### Base Command

`arkime-session-tag-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tags | Comma separated list of tags to add to session(s). | Required | 
| session_ids | Comma separated list of sessions to add tag(s) to. | Optional | 
| segments | Whether to add tags to linked session segments. Default is no. Options include: no - Don’t add tags to linked segments all - Add tags to all linked segments time - Add tags to segments occurring in the same time period. | Optional | 
| date | The number of hours of data to return (-1 means all data). Defaults to 1. | Optional | 
| expression | The search expression string. | Optional | 
| start_time | If the date parameter is not set, this is the start time of data to return. Format is seconds since Unix EPOC. | Optional | 
| stop_time | If the date parameter is not set, this is the stop time of data to return. Format is seconds since Unix EPOC. | Optional | 
| view | The view name to apply before the expression. | Optional | 
| order | Comma separated list of db field names to sort on. Data is sorted in order of the list supplied. Optionally can be followed by :asc or :desc for ascending or descending sorting. | Optional | 
| fields | Comma separated list of db field names to return. Default is ipProtocol, rootId, totDataBytes, srcDataBytes, dstDataBytes, firstPacket, lastPacket, srcIp, srcPort, dstIp, dstPort, totPackets, srcPackets, dstPackets, totBytes, srcBytes, dstBytes, node, http.uri, srcGEO, dstGEO, email.subject, email.src, email.dst, email.filename, dns.host, cert, irc.channel, http.xffGEO. | Optional | 
| bounding | Query sessions based on different aspects of a session’s time. Options include: ‘first’ - First Packet: the timestamp of the first packet received for the session. ‘last’ - Last Packet: The timestamp of the last packet received for the session. ‘both’ - Bounded: Both the first and last packet timestamps for the session must be inside the time window. ‘either’ - Session Overlaps: The timestamp of the first packet must be before the end of the time window AND the timestamp of the last packet must be after the start of the time window. ‘database’ - Database: The timestamp the session was written to the database. This can be up to several minutes AFTER the last packet was received. | Optional | 
| strictly | 	When set the entire session must be inside the date range to be observed, otherwise if it overlaps it is displayed. Overwrites the bounding parameter, sets bonding to ‘both’. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.AddSessionTags.success | Boolean | Success status. | 
| Arkime.AddSessionTags.text | String | Text from response. | 

#### Command example
```!arkime-session-tag-remove tags=test ids=220425-L2AXYh6W4UJOSqilt0i3iDIL segments=time```
#### Context Example
```json
{
    "Arkime": {
        "Tag": {
            "success": true,
            "text": "Tags removed successfully"
        }
    }
}
```

#### Human Readable Output

>### Session Tag Results:
>|Success|Text|
>|---|---|
>| true | Tags removed successfully |


### arkime-pcap-file-list
***
Gets a list of PCAP files that Arkime knows about.


#### Base Command

`arkime-pcap-file-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of items to return. Defaults to 100, Max is 10,000. | Optional | 
| page_number | The page at which to start. The default is 0. | Optional | 
| page_size | Page size. Minimum page size is 1, maximum is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arkime.File.recordsTotal | Number | The total number of hunts Arkime has. | 
| Arkime.File.recordsFiltered | Number | The number of hunts returned in this result. | 
| Arkime.File.data.node | String | The file data node. | 
| Arkime.File.data.packetPosEncoding | String | The file data packetPosEncoding. | 
| Arkime.File.data.num | Number | The data number. | 
| Arkime.File.data.name | String | The data name. | 
| Arkime.File.data.locked | Number | The file data locked. | 
| Arkime.File.data.first | Number | The file data first. | 
| Arkime.File.data.compression | Number | The file data compression. | 
| Arkime.File.data.packetsSize | Number | The file data packets size. | 
| Arkime.File.data.filesize | Number | The file data file size. | 
| Arkime.File.data.packets | Number | The file data packets. | 

#### Command example
```!arkime-pcap-file-list limit=10```
#### Context Example
```json
{
    "Arkime": {
        "PcapFile": {
            "data": [
                {
                    "compression": 0,
                    "filesize": 2147483898,
                    "first": 1653331569,
                    "locked": 0,
                    "name": "/opt/arkime/raw/localhost-220523-00000280.pcap",
                    "node": "localhost",
                    "num": 280,
                    "packetPosEncoding": "gap0",
                    "packets": 9805564,
                    "packetsSize": 2147483898
                },
                {
                    "compression": 0,
                    "filesize": 2147484044,
                    "first": 1653005794,
                    "locked": 0,
                    "name": "/opt/arkime/raw/localhost-220519-00000281.pcap",
                    "node": "localhost",
                    "num": 281,
                    "packetPosEncoding": "gap0",
                    "packets": 5331898,
                    "packetsSize": 2147484044
                },
                {
                    "compression": 0,
                    "filesize": 2147483893,
                    "first": 1653368682,
                    "locked": 0,
                    "name": "/opt/arkime/raw/localhost-220524-00000282.pcap",
                    "node": "localhost",
                    "num": 282,
                    "packetPosEncoding": "gap0",
                    "packets": 7719615,
                    "packetsSize": 2147483893
                },
                {
                    "compression": 0,
                    "filesize": 2147484038,
                    "first": 1653393304,
                    "locked": 0,
                    "name": "/opt/arkime/raw/localhost-220524-00000283.pcap",
                    "node": "localhost",
                    "num": 283,
                    "packetPosEncoding": "gap0",
                    "packets": 4305191,
                    "packetsSize": 2147484038
                },
                {
                    "compression": 0,
                    "filesize": 2147483960,
                    "first": 1653396343,
                    "locked": 0,
                    "name": "/opt/arkime/raw/localhost-220524-00000284.pcap",
                    "node": "localhost",
                    "num": 284,
                    "packetPosEncoding": "gap0",
                    "packets": 8442750,
                    "packetsSize": 2147483960
                },
                {
                    "compression": 0,
                    "filesize": 2147485212,
                    "first": 1653427235,
                    "locked": 0,
                    "name": "/opt/arkime/raw/localhost-220524-00000285.pcap",
                    "node": "localhost",
                    "num": 285,
                    "packetPosEncoding": "gap0",
                    "packets": 9095229,
                    "packetsSize": 2147485212
                },
                {
                    "compression": 0,
                    "filesize": 2147483877,
                    "first": 1653461157,
                    "locked": 0,
                    "name": "/opt/arkime/raw/localhost-220525-00000286.pcap",
                    "node": "localhost",
                    "num": 286,
                    "packetPosEncoding": "gap0",
                    "packets": 6176160,
                    "packetsSize": 2147483877
                },
                {
                    "compression": 0,
                    "filesize": 2147483884,
                    "first": 1653465604,
                    "locked": 0,
                    "name": "/opt/arkime/raw/localhost-220525-00000287.pcap",
                    "node": "localhost",
                    "num": 287,
                    "packetPosEncoding": "gap0",
                    "packets": 3413459,
                    "packetsSize": 2147483884
                },
                {
                    "compression": 0,
                    "filesize": 2147483909,
                    "first": 1653481470,
                    "locked": 0,
                    "name": "/opt/arkime/raw/localhost-220525-00000288.pcap",
                    "node": "localhost",
                    "num": 288,
                    "packetPosEncoding": "gap0",
                    "packets": 9737747,
                    "packetsSize": 2147483909
                },
                {
                    "compression": 0,
                    "filesize": 2147483662,
                    "first": 1653513520,
                    "locked": 0,
                    "name": "/opt/arkime/raw/localhost-220525-00000289.pcap",
                    "node": "localhost",
                    "num": 289,
                    "packetPosEncoding": "gap0",
                    "packets": 4184811,
                    "packetsSize": 2147483662
                }
            ],
            "recordsFiltered": 44,
            "recordsTotal": 44
        }
    }
}
```

#### Human Readable Output

>Showing 10 results, limit=10
>### Files List Result:
>|Node|Name|Number|First|File Size|Packet Size|
>|---|---|---|---|---|---|
>| localhost | /opt/arkime/raw/localhost-220523-00000280.pcap | 280 | 1970-01-20 03:15:31 | 2147483898 | 2147483898 |
>| localhost | /opt/arkime/raw/localhost-220519-00000281.pcap | 281 | 1970-01-20 03:10:05 | 2147484044 | 2147484044 |
>| localhost | /opt/arkime/raw/localhost-220524-00000282.pcap | 282 | 1970-01-20 03:16:08 | 2147483893 | 2147483893 |
>| localhost | /opt/arkime/raw/localhost-220524-00000283.pcap | 283 | 1970-01-20 03:16:33 | 2147484038 | 2147484038 |
>| localhost | /opt/arkime/raw/localhost-220524-00000284.pcap | 284 | 1970-01-20 03:16:36 | 2147483960 | 2147483960 |
>| localhost | /opt/arkime/raw/localhost-220524-00000285.pcap | 285 | 1970-01-20 03:17:07 | 2147485212 | 2147485212 |
>| localhost | /opt/arkime/raw/localhost-220525-00000286.pcap | 286 | 1970-01-20 03:17:41 | 2147483877 | 2147483877 |
>| localhost | /opt/arkime/raw/localhost-220525-00000287.pcap | 287 | 1970-01-20 03:17:45 | 2147483884 | 2147483884 |
>| localhost | /opt/arkime/raw/localhost-220525-00000288.pcap | 288 | 1970-01-20 03:18:01 | 2147483909 | 2147483909 |
>| localhost | /opt/arkime/raw/localhost-220525-00000289.pcap | 289 | 1970-01-20 03:18:33 | 2147483662 | 2147483662 |

