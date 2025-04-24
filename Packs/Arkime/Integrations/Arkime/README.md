Arkime (formerly Moloch) is a large scale, open source, indexed packet capture and search tool.
This integration was integrated and tested with version 3.4.1 (API v3) of Arkime. 
For older versions, see the Moloch pack (deprecated). 

## Configure Arkime in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Username | True |
| Password | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
                }
            ],
            "nodes": [
                {
                    "cnt": 1,
                    "id": "1.1.1.1",
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
            ],
            "recordsFiltered": 3527811
        }
    }
}
```

#### Human Readable Output

>### Connection Results:
>|Source IP|Count|Sessions|Node|
>|---|---|---|---|
>| 1.1.1.1 | 1 | 2 | localhost |



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
        "EntryID": "2681@4060e8c8-61bb-4131-8a47-32a7d97a9726",
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
        "EntryID": "2697@4060e8c8-61bb-4131-8a47-32a7d97a9726",
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
```!arkime-session-csv-get start_time=1650190238 stop_time=1650363038 limit=2```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "2693@4060e8c8-61bb-4131-8a47-32a7d97a9726",
        "Extension": "csv",
        "Info": "text/csv; charset=utf-8",
        "Name": "sessions_list.csv",
        "Size": 333,
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
```!arkime-session-list start_time=1650190238 stop_time=1650363038 limit=2```
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
                        "ip": "1.1.1.1",
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
                        "ip": "1.1.1.1",
                        "packets": 4890,
                        "port": 22
                    },
                    "totDataBytes": 0
                }
            ],
            "graph": {
                "interval": 60,
                "network.bytesTotal": 0,
                "network.packetsTotal": 0,
                "sessionsTotal": 0,
                "totDataBytesTotal": 0,
                "xmax": 1650363038000,
                "xmin": 1650190238000
            },
            "map": {},
            "recordsFiltered": 516305,
            "recordsTotal": 31698069
        }
    }
}
```

#### Human Readable Output

>Showing 2 results, limit=2
>### Session List Result:
>|ID|IP Protocol|Start Time|Stop Time|Source IP|Source Port| Destination IP |Destination Port|Node|
>|---|---|---|---|---|----------------|---|---|---|
>| 3@220417-Yg7OpiE4Pi1PFaRqu8lztuA6 | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:15:31 | 1.1.1.1 | 22 | 1.1.1.1        | 41096 | localhost |
>| 3@220417-Yg5Kx3oHIahAPJJVD8QwphkQ | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:16:19 | 1.1.1.1 | 22 | 1.1.1.1        | 41096 | localhost |


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
```!arkime-unique-field-list expression_field_names=dns.ASN counts=0 limit=2```
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
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 2 results, limit=2
>### Unique Field Results:
>|Field|Count|
>|---|---|
>| AS8075 MICROSOFT-CORP-MSN-AS-BLOCK |  |
>| AS15169 GOOGLE |  |


#### Command example
```!arkime-unique-field-list expression_field_names=dns.ASN counts=1 limit=2```
#### Context Example
```json
{
    "Arkime": {
        "UniqueField": [
            {
                "Count": " 241",
                "Field": "AS8075 MICROSOFT-CORP-MSN-AS-BLOCK"
            },
            {
                "Count": " 183",
                "Field": "AS15169 GOOGLE"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 2 results, limit=2
>### Unique Field Results:
>|Field|Count|
>|---|---|
>| AS8075 MICROSOFT-CORP-MSN-AS-BLOCK |  241 |
>| AS15169 GOOGLE |  183 |


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
```!arkime-multi-unique-field-list expression_field_names=destination.ip counts=1 database_field=dns.ASN limit=2```
#### Context Example
```json
{
    "Arkime": {
        "UniqueField": [
            {
                "Count": " 10153",
                "Field": "1.1.1.1"
            },
            {
                "Count": " 1957",
                "Field": "1.1.1.1"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 2 results, limit=2
>### Unique Field Results:
>| Field        |Count|
--------------|---|---|
>| 1.1.1.1      |  10153 |
>| 1.1.1.1 |  1957 |


#### Command example
```!arkime-multi-unique-field-list expression_field_names=destination.ip counts=0 database_field=dns.ASN limit=2```
#### Context Example
```json
{
    "Arkime": {
        "UniqueField": [
            {
                "Field": "1.1.1.1"
            },
            {
                "Field": "1.1.1.1"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 2 results, limit=2
>### Unique Field Results:
>| Field        |Count|
--------------|---|---|
>| 1.1.1.1      |  |
>| 1.1.1.1 |  |


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
>| http.content-type | termfield | http | Response header content-type | http.response-content-type |
>| http.content-type Cnt | integer | http | Unique number of Request header content-type | http.request-content-typeCnt |
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
| Arkime.SpiGraph.items.graph.sessionsTotal | Number | The sessions total. | 
| Arkime.SpiGraph.items.graph.network.packetsTotal | Number | The network packets total. | 
| Arkime.SpiGraph.items.graph.network.bytesTotal | Date | The network bytesTotal. | 
| Arkime.SpiGraph.items.graph.totDataBytesTotal | Date | The graph totDataBytesTotal. | 
| Arkime.SpiGraph.graph.xmin | Date | The graph xmin. | 
| Arkime.SpiGraph.graph.xmax | Date | The graph xmax. | 
| Arkime.SpiGraph.graph.interval | Number | The graph interval. | 
| Arkime.SpiGraph.graph.sessionsTotal | Number | The graph sessionsTotal. | 
| Arkime.SpiGraph.graph.network.packetsTotal | Number | The network packetsTotal. | 
| Arkime.SpiGraph.graph.network.bytesTotal | Date | The network bytesTotal. | 
| Arkime.SpiGraph.graph.totDataBytesTotal | Date | The graph totDataBytesTotal. | 
| Arkime.SpiGraph.recordsTotal | Number | The total number of history results stored. | 
| Arkime.SpiGraph.recordsFiltered | Number | The number of hunts returned in this result. | 

#### Command example
```!arkime-spigraph-get field=220516-QHSdz21pJ_xCtJGoL8mbmyNv```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "2701@4060e8c8-61bb-4131-8a47-32a7d97a9726",
        "Extension": "json",
        "Info": "application/json",
        "Name": "spi_graph.json",
        "Size": 512,
        "Type": "ASCII text, with very long lines (512), with no line terminators"
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
        "EntryID": "2705@4060e8c8-61bb-4131-8a47-32a7d97a9726",
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
```!arkime-pcap-file-list limit=2```
#### Context Example
```json
{
    "Arkime": {
        "PcapFile": {
            "data": [
                {
                    "compression": 0,
                    "filesize": 1073744628,
                    "first": 1655844995,
                    "locked": 0,
                    "name": "/opt/arkime/raw/localhost-220621-00000384.pcap",
                    "node": "localhost",
                    "num": 384,
                    "packetPosEncoding": "gap0",
                    "packets": 5069126,
                    "packetsSize": 1073744628
                },
                {
                    "compression": 0,
                    "first": 1655854856,
                    "locked": 0,
                    "name": "/opt/arkime/raw/localhost-220621-00000385.pcap",
                    "node": "localhost",
                    "num": 385,
                    "packetPosEncoding": "gap0"
                }
            ],
            "recordsFiltered": 39,
            "recordsTotal": 39
        }
    }
}
```

#### Human Readable Output

>Showing 2 results, limit=2
>### Files List Result:
>|Node|Name|Number|First|File Size|Packet Size|
>|---|---|---|---|---|---|
>| localhost | /opt/arkime/raw/localhost-220621-00000384.pcap | 384 | 1970-01-20 03:57:24 | 1073744628 | 1073744628 |
>| localhost | /opt/arkime/raw/localhost-220621-00000385.pcap | 385 | 1970-01-20 03:57:34 |  |  |
