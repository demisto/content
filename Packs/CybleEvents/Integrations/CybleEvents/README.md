Cyble Events is an integration which will help Existing Cyble Vision users. This integration would allow users to access
the API available as part of Vision Licensing and integrate the data into XSOAR.

## Configure Cyble Events in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://example.net) |  | True |
| Access Token |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incidents Fetch Interval |  | False |
| Incident Fetch Limit | Maximum incidents to be fetched every time. Upper limit is 50 incidents. | True |
| Incident type |  | False |
| Priority | Fetch the events based on priority. All priorities will be considered by default. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook. After you
successfully execute a command, a DBot message appears in the War Room with the command details.

This integration provides the following command(s) which can be used to access Threat Intelligence

### cyble-vision-fetch-iocs

***
Fetch the indicators for the given timeline

#### Base Command

`cyble-vision-fetch-iocs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | Returns records started with given value. Default is 0. | Optional | 
| limit | Number of records to return (max 1000). Using a smaller limit will get faster responses. Default is 1. | Optional | 
| start_date | Timeline start date in the format "YYYY-MM-DD". Need to used with end_date as timeline range. | Optional | 
| end_date | Timeline end date in the format "YYYY-MM-DD". Need to used with start_date as timeline range. | Optional | 
| type | Returns record by type like (CIDR, CVE, domain, email, FileHash-IMPHASH, FileHash-MD5, FileHash-PEHASH, FileHash-SHA1, FileHash-SHA256, FilePath, hostname, IPv4, IPv6, Mutex, NIDS, URI, URL, YARA, osquery, Ja3, Bitcoinaddress, Sslcertfingerprint). | Optional | 
| keyword | Returns records for the specified keyword. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybleEvents.IoCs.data | String | Returns indicator inital creation date | 

### cyble-vision-fetch-alerts

***
Fetch Incident Event alerts based on the given parameters. Alerts would have multiple events grouped into one based on
specific service type. So users would see, in certain cases, more events than the limit provides.

#### Base Command

`cyble-vision-fetch-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- |--------------|
| from | Returns records for the timeline starting from given indice. Default is 0. | Required     | 
| limit | Number of records to return (max 50). Using a smaller limit will get faster responses. Default is 5. | Required     | 
| start_date | Timeline start date in the format "YYYY/MM/DD". | Required     | 
| end_date | Timeline end date in the format "YYYY/MM/DD". | Required     | 
| order_by | Sorting order for alert fetch either Ascending or Descending. Possible values are: Ascending, Descending. Default is Ascending. | Required     |
| priority | Fetch the events based on priority. Possible values are: high,medium,low,informational. | Optional     | 

#### Context Output

| **Path**                            | **Type** | **Description** |
|-------------------------------------| --- | --- |
| CybleEvents.Events.eventid     | String | Returns the event ID | 
| CybleEvents.Events.eventtype   | String | Returns the event type | 
| CybleEvents.Events.severity         | Number | Returns the event severity | 
| CybleEvents.Events.occurred         | Date | Returns the event occurred timeline | 
| CybleEvents.Events.name             | String | Returns the alert title | 
| CybleEvents.Events.cybleeventsname  | String | Returns the event name | 
| CybleEvents.Events.cybleeventsbucket | String | Returns the event bucket name | 
| CybleEvents.Events.cybleeventskeyword | String | Returns the event keyword | 
| CybleEvents.Events.cybleeventsalias | String | Returns the event type alias name | 

### cyble-vision-fetch-event-detail

***
Fetch Incident detail based on event type and event ID

#### Base Command

`cyble-vision-fetch-event-detail`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------| --- |--------------|
| event_type        | Event Type of the Incident. | Required     | 
| event_id          | Event ID of the incident. | Required     | 
| from              | The value in the field represents the position of records that are retrieved | Required     | 
| limit             | The value in the field represents the number of events that can be returned, maximum allowed is 1000 | Required     |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybleEvents.Events.Details | String | Returns details for given event of specific type | 