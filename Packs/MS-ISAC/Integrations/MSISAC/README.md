This API queries alerts and alert data from the MS-ISAC API to enrich and query alerts from the platform
This integration was integrated and tested with version 1.1 of MS-ISAC

## Configure MS-ISAC in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | Key provided by MS-ISAC according to the detailed Instructions | True |
| Server URL | This is the URL provided by MS-ISAC for the base of all endpoints | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### msisac-get-event
***
Retrieve alert data by its ID


#### Base Command

`msisac-get-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the MS-ISAC event. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSISAC.Event.EventID | string | The event ID for this specific retrieval | 
| MSISAC.Event.Stream | unknown | A list of data streams that were pulled from this MS-ISAC event. These lists of dictionaries contain more detailed information | 
| MSISAC.Event.Stream.flow_id | number | The ID for this specific data flow | 
| MSISAC.Event.Stream.start | date | The start data for this stream | 
| MSISAC.Event.Stream.src_ip | string | The source IP of the event | 
| MSISAC.Event.Stream.vlan | unknown | A list of all the VLANs configured for this interface | 
| MSISAC.Event.Stream.pkts_toserver | number | The number of packets sent | 
| MSISAC.Event.Stream.dest_ip | string | The destination IP for this flow | 
| MSISAC.Event.Stream.length | number | The length of this flow | 
| MSISAC.Event.Stream.streamdataascii | string | A string representation of the flow data that is granularly displayed  | 
| MSISAC.Event.Stream.host | string | The Albert sensor that detected the traffic | 
| MSISAC.Event.Stream.proto | string | TCP or UDP communication | 
| MSISAC.Event.Stream.app_proto | string | The application protocol that was used in this communication | 
| MSISAC.Event.Stream.logical_sensor_id | string | The ID for the sensor that detected the traffic | 
| MSISAC.Event.Stream.streamdatalen | string | The total data sent in the request | 
| MSISAC.Event.Stream.pkts_toclient | number | The total amount of packets sent | 
| MSISAC.Event.Stream.flow_id | number | The specific ID for this flow | 
| MSISAC.Event.Stream.in_iface | string | The physical interface that this traffic traversed | 
| MSISAC.Event.Stream.time | date | The time that this traffic occured in a more human readable format than 'start' | 
| MSISAC.Event.Stream.url | string | The URL that was attempted with this traffic | 
| MSISAC.Event.Stream.bytes_toserver | number | The size of the data sent to the server | 
| MSISAC.Event.Stream.status | number | The status code for this data stream | 
| MSISAC.Event.Stream.hostname | string | The hostname \(not URL\) of the attempted traffic | 
| MSISAC.Event.Stream.tx_id | number |  | 
| MSISAC.Event.Stream.http_content_type | string | The content encoding used for the response traffic | 
| MSISAC.Event.Stream.http_method | string | The method used to send the traffic \(GET, POST, etc\) | 
| MSISAC.Event.Stream.protocol | string | What web protocol was used \(HTTP/1.1 etc\) | 
| MSISAC.Event.Stream.bytes_toclient | number | The size of the data sent to the client | 
| MSISAC.Event.Stream.src_port | number | The source port for the traffic | 
| MSISAC.Event.Stream.dest_port | string | The destination port for the traffic | 
| MSISAC.Event.Stream.event_type | unknown | The type of event submitted from MS-ISAC | 



### msisac-retrieve-events
***
Retrieves a list of MS-ISAC events for a given number of days (one or greater)


#### Base Command

`msisac-retrieve-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| days | The number of days worth of events to return. Must be one or greater. Default is 1. | Required | 
| event_id | If you want to search the list of events for a specific event, specify this optional command to return just those results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSISAC.RetrievedEvents.event_id | number | ID for the retrieved MS-ISAC event | 
| MSISAC.RetrievedEvents.stime | date | The time that the traffic started | 
| MSISAC.RetrievedEvents.sourceip | string | The IP that originated the traffic | 
| MSISAC.RetrievedEvents.analyzed_ts | date | The time that this traffic was analyzed by MS-ISAC | 
| MSISAC.RetrievedEvents.logical_sensor_id | string | The ID for the sensor that triggered the event | 
| MSISAC.RetrievedEvents.ticket_id | string | String representation of event_id | 
| MSISAC.RetrievedEvents.queue | string | The group that originated the event | 
| MSISAC.RetrievedEvents.status | string | The current state of the event | 
| MSISAC.RetrievedEvents.previous_escalations | string | How many times this alert has been escalated | 
| MSISAC.RetrievedEvents.last_stime | date | The last time that this traffic was observed \(stop time\) | 
| MSISAC.RetrievedEvents.sensor | string | The hostname of the sensor that triggered the event | 
| MSISAC.RetrievedEvents.analysis | string | The analysis provided by MS-ISAC | 
| MSISAC.RetrievedEvents.description | string | The description of the event | 
| MSISAC.RetrievedEvents.severity | string | The severity assigned to the MS-ISAC alert | 
