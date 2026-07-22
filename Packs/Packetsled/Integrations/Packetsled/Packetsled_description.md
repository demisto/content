# Packetsled Cortex XSOAR Integration

Provides ability to enumerate sensors, enumerate entities (hosts) that have incidents, and to retrieve metadata, file, and packet capture artifacts from the Packetsled API.

Examples:

To enumerate all attached sensors:

```
!packetsled-get-sensors
```

To search for all incidents since the last time they were retrieved:

```
!packetsled-get-incidents
```

To search for metadata for a specific host:

```
!packetsled-get-flows entity=192.168.0.110 limit=10000
```

To deliver a pcap for a given entity to the Cortex XSOAR war room:

```
!packetsled-get-pcaps entity=192.168.0.110
```

## Commands

### packetsled-get-incidents
Fetches incidents of the form:
```json
{"name": "Source: Packetsled SENSOR: <sensor label>, ENTITY: <ip address>", "rawJSON": {<packetsled incident>}}
```
|argument  | description   |
|---|---|
| `start_time`      | The beginning of the time range to query, can be either epoch seconds or ISO formatted datetime - options, will default to 1 hour ago or lastRunTime |
|  `stop_time`   | The end of the time range to query, can be either epoch seconds or ISO formatted datetime - optional, will default to "now" |
|  `envid`      | A unique id in packetsled to identify a group of sensors belonging to a single customer - optional, if not provided, all sensors are queried  |
|  `probe`      | A unique id within an envid used to identify a sensingle sensor - optional, if not provided, all sensors are queried  |

### packetsled-get-flows
Retrieves flow metadata based on provided constraints. The flows are delivered as JSON files into the Cortex XSOAR war room.

|argument  | description   |
|---|---|
| `start_time`  | The beginning of the time range to query, can be either epoch seconds or ISO formatted datetime - options, will default to 1 hour ago or lastRunTime |
| `stop_time`     | The end of the time range to query, can be either epoch seconds or ISO formatted datetime - optional, will default to "now" |
| `envid`      | A unique id in packetsled to identify a group of sensors belonging to a single customer - optional, if not provided, all sensors are queried  |
| `probe`      | A unique id within an envid used to identify a sensingle sensor - optional, if not provided, all sensors are queried  |
|  `entity`      | an ip address - optional |
|  `port`     | port - optional |
|  `geo`     | geo code - optional |
|  `family`     | A protocol family (enumeration value) - optional |
|  `proto`      | a protocol (enumeration value) - optional |

### packetsled-get-files
Retrieves file artifacts based on provided constraints. The files are delivered into the Cortex XSOAR war room.

|argument  | description   |
|:---|:---|
| `start_time`      | The beginning of the time range to query, can be either epoch seconds or ISO formatted datetime - options, will default to 1 hour ago or lastRunTime |
|  `stop_time`     | The end of the time range to query, can be either epoch seconds or ISO formatted datetime - optional, will default to "now" |
|  `envid`      | A unique id in packetsled to identify a group of sensors belonging to a single customer - optional, if not provided, all sensors are queried  |
|  `probe`      | A unique id within an envid used to identify a sensingle sensor - optional, if not provided, all sensors are queried  |
| `entity `     | an ip address - optional |
|  `port `     | port - optional |
|  `geo `     | geo code - optional |
|  `family`      | A protocol family (enumeration value) - optional |
|  `proto`      | a protocol (enumeration value) - optional |

### packetsled-get-pcaps
Retrieves full packet capture files based on provided constraints. The PCAP files are delivered into the Cortex XSOAR war room.

|argument  | description   |
|:---|:---|
| ` start_time`      | The beginning of the time range to query, can be either epoch seconds or ISO formatted datetime - options, will default to 1 hour ago or lastRunTime |
| ` stop_time`     | The end of the time range to query, can be either epoch seconds or ISO formatted datetime - optional, will default to "now" |
|  `envid`      | A unique id in packetsled to identify a group of sensors belonging to a single customer - optional, if not provided, all sensors are queried  |
|  `probe`     | A unique id within an envid used to identify a sensingle sensor - optional, if not provided, all sensors are queried  |
|  `entity`      | an ip address | optional |
|  `port`     | port | optional |
|  `proto`      | a protocol (enumeration value) - optional |
