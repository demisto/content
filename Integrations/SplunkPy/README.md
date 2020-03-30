## Overview
---
Use the SplunkPy integration to fetch events (logs) from within Demisto, push events from Demisto to SplunkPy, and fetch SplunkPy ES notable events as Demisto incidents.

This integration was integrated and tested with Splunk v6.5.

## Use Cases
---
* Query Splunk for events
* Create a new event in Splunk
* Get results of a search that was executed in Splunk
## Configure SplunkPy on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for SplunkPy.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Host - ip (x.x.x.x)__
    * __Username__
    * __Port__
    * __Fetch notable events ES query__
    * __Fetch Limit (Max.- 200, Recommended less than 50)__
    * __Fetch incidents__
    * __First fetch timestamp (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year)__ 
    * __Incident type__
    * __Proxy - in format: 127.0.0.1:8080__
    * __Timezone of the Splunk server, in minutes. For example, GMT is gmt +3, set +180 (set only if different than Demisto server). Relevant only for fetching notable events.__
    * __Parse Raw part of notable events__
    * __Extract Fields - CSV fields that will be parsed out of _raw notable events__
    * __Earliest time to fetch (the name of the Splunk field whose value defines the query's earliest time to fetch)__
    * __Latest time to fetch (the name of the Splunk field whose value defines the query's latest time to fetch)__
    Params: `Earliest time to fetch` and `Latest time to fetch` are search parameters options.
By default when you run a search from the CLI, the search use~~~~s All Time as the time          range. You can specify time ranges using one of the CLI search parameters, such  as earliest_time, index_earliest, or latest_time.
    * __The app context of the namespace__
    * __HEC Token (HTTP Event Collector)__
    * __HEC URL (e.g: https://localhost:8088)__
    * __Use Splunk Clock Time For Fetch__
    * __Use Splunk Clock Time For Fetch__
    * __Trust any certificate (unsecure)__
4. Click __Test__ to validate the URLs, token, and connection.
### Configure Splunk to Produce Alerts for SplunkPy
We recommend that you configure Splunk to produce basic alerts that the SplunkPy integration can ingest, by creating a summary index in which alerts are stored. The SplunkPy integration can then query that index for incident ingestion. We do not recommend using the Demisto App for Splunk for routine event consumption because this method is not monitorable nor scalable.

1. Create a summary index in Splunk. For more information, see the [Splunk documentation](https://docs.splunk.com/Documentation/Splunk/7.3.0/Indexer/Setupmultipleindexes#Create_events_indexes_2).
2. Build a query to return relevant alerts.
![image](https://user-images.githubusercontent.com/50324325/63265602-ae7fba00-c296-11e9-898c-afc98c56a1cb.png)
3. Identify the Fields list from the Splunk query and save it to a local file.
![image](https://user-images.githubusercontent.com/50324325/63265613-b6d7f500-c296-11e9-81d7-854ee4ee9685.png)
4. Define a search macro to capture the Fields list that you saved locally. For more information, see the [Splunk documentation](https://docs.splunk.com/Documentation/Splunk/7.3.0/Knowledge/Definesearchmacros).
Use the following naming convention: (demisto_fields_{type}).
![image](https://user-images.githubusercontent.com/50324325/63265773-08807f80-c297-11e9-86a1-355a261c356b.png)
![image](https://user-images.githubusercontent.com/50324325/63265623-bccdd600-c296-11e9-9303-47b9791b0205.png)
5. Define a scheduled search, the results of which are stored in the summary index. For more information about scheduling searches, see the [Splunk documentation](https://docs.splunk.com/Documentation/Splunk/7.3.0/Knowledge/Definesearchmacros). 
![image](https://user-images.githubusercontent.com/50324325/63265640-c5261100-c296-11e9-9bd6-426fb328c09c.png)
6. In the Summary indexing section, select the summary index, and enter the {key:value} pair for Demisto classification.
![image](https://user-images.githubusercontent.com/50324325/63265665-d0793c80-c296-11e9-9919-cf6c6af33294.png)
7. Configure the incident type in Demisto by navigating to __Settings > Advanced > Incident Types.__
![image](https://user-images.githubusercontent.com/50324325/63265677-d66f1d80-c296-11e9-95df-190ab18ae484.png)
8. Navigate to __Settings > Integrations > Classification & Mapping__, and drag the value to the appropriate incident type.
![image](https://user-images.githubusercontent.com/50324325/63265720-ea1a8400-c296-11e9-8062-dd40606c5a42.png)
9. Click the __Edit mapping__ link to map the Splunk fields to Demisto.
![image](https://user-images.githubusercontent.com/50324325/63265811-1d5d1300-c297-11e9-8026-52ff1cf30cbf.png)
10. (optional) Create custom fields.
11. Build a playbook and assign it as the default for this incident type.


## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. Get the results of a previous search: splunk-results
2. Search SplunkPy: splunk-search
3. Create a new event: splunk-submit-event
4. Get index: splunk-get-indexes
5. Edit a noteable event: splunk-notable-event-edit
6. Create a job: splunk-job-create
7. Parse the raw part of the event: splunk-parse-raw
8. Send events to an HTTP Event Collector using the Splunk platform JSON event protocol: splunk-submit-event-hec
9. Returns the status of a job: splunk-job-status


### 1. splunk-results
---
Returns the results of a previous Splunk search. You can use this command in conjunction with the splunk-job-create command.
##### Base Command

`splunk-results`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sid | ID of the search for which to return results. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` !splunk-results sid="1566221331.1186" ```

### 2. splunk-search
---
Searches Splunk for events.
##### Base Command

`splunk-search`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The Splunk search language string to execute. For example: "index=* \| head 3".  | Required | 
| earliest_time | Specifies the earliest time in the time range to search. The time string can be a UTC time (with fractional seconds), a relative time specifier (to now), or a formatted time string. Default is 1 week ago, in the format "-7d". You can also specify time in the format: 2014-06-19T12:00:00.000-07:00" | Optional | 
| latest_time |  Specifies the latest time in the time range to search. The time string can be a UTC time (with fractional seconds), a relative time specifier (to now), or a formatted time string. For example: "2014-06-19T12:00:00.000-07:00" or "-3d" (for time 3 days before now) | Optional | 
| event_limit | Maximum number of events to return. Default is 100. If "0", all results are returned. | Optional | 
| app | A string that contains the application namespace in which to restrict searches. | Optional|
6	
| batch_limit | The maximum number of returned results to  process at a time. For example, if 100 results are returned, and you specify a batch_limit of 10, the results will be processed 10 at a time over 10 iterations. This does not effect the search or the context and outputs returned. In some cases, specifying a batch_size enhances search performance. If you think that the search execution is suboptimal, we recommend trying several batch_size values to determine which works best for your search. Default is 25,000. | Optional |
97	
| update_context | Determines whether the results will be entered into the context. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.Result | Unknown | The results of the Splunk search. The results are a JSON array, in which each item is a Splunk event. | 


##### Command Example
```!splunk-search query="* | head 3" earliest_time="-1000d" ```

##### Human Readable Output
### Splunk Search results for query: * | head 3
|_bkt|_cd|_indextime|_kv|_raw|_serial|_si|_sourcetype|_time|host|index|linecount|source|sourcetype|splunk_server|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| main~445~66D21DF4-F4FD-4886-A986-82E72ADCBFE9 | 445:897774 | 1585462906 | 1 | InsertedAt=\"2020-03-29 06:21:43\"; EventID=\"837005\"; EventType=\"Application control\"; Action=\"None\"; ComputerName=\"ACME-code-007\"; ComputerDomain=\"DOMAIN\"; ComputerIPAddress=\"127.0.0.1\"; EventTime=\"2020-03-29 06:21:43\"; EventTypeID=\"5\"; Name=\"LogMeIn\"; EventName=\"LogMeIn\"; UserName=\""; ActionID=\"6\"; ScanTypeID=\"200\"; ScanType=\"Unknown\"; SubTypeID=\"23\"; SubType=\"Remote management tool\"; GroupName=\"";\u003cbr\u003e | 2 | ip-172-31-44-193,<br>main | sophos:appcontrol | 2020-03-28T23:21:43.000-07:00 | 127.0.0.1 | main | 2 | eventgen | sophos:appcontrol | ip-172-31-44-193 |
### 3. splunk-submit-event
---
Creates a new event in Splunk.
##### Base Command

`splunk-submit-event`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | Splunk index to which to push data. Run the splunk-get-indexes command to get all indexes. | Required | 
| data | The new event data to push, can be any string. | Required | 
| sourcetype | Event source type. | Required | 
| host | Event host. Can be "Local" or "120.0.0.1". | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` !splunk-submit-event index="main" data="test" sourcetype="demisto-ci" host="localhost" ```

##### Human Readable Output

![image](https://user-images.githubusercontent.com/50324325/63268589-2fda4b00-c29d-11e9-95b5-4b9fcf6c08ee.png)


### 4. splunk-get-indexes
---
Prints all Splunk index names.
##### Base Command

`splunk-get-indexes`
##### Input

There are no input arguments for this command.

##### Context Output

There is no context output for this command.

##### Command Example
``` !splunk-get-indexes extend-context="indexes=" ```

##### Human Readable Output

![image](https://user-images.githubusercontent.com/50324325/63268447-d8d47600-c29c-11e9-88a4-5003971a492e.png)

### 5. splunk-notable-event-edit
---
Update an existing Notable event in Splunk ES
##### Base Command

`splunk-notable-event-edit`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventIDs | A comma-separated list of event IDs of notable events.s | Required | 
| owner | A Splunk user to assign to the notable event. | Optional | 
| comment | Comment to add to the notable event. | Required | 
| urgency | Notable event urgency. | Optional | 
| status | Notable event status. 0 - Unassigned, 1 - Assigned, 2 - In Progress, 3 - Pending, 4 - Resolved, 5 - Closed. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
``` !splunk-notable-event-edit eventIDs=66D21DF4-F4FD-4886-A986-82E72ADCBFE9@@notable@@a045b8acc3ec93c2c74a2b18c2caabf4 comment="Demisto"```

##### Human Readable Output
![image](https://user-images.githubusercontent.com/50324325/63522203-914e2400-c500-11e9-949a-0b55eb2c5871.png)


### 6. splunk-job-create
---
Creates a new search job in Splunk.
##### Base Command

`splunk-job-create`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The Splunk search language string to execute. For example :"index=* \| head 3". | Required | 
| app | A string that contains the application namespace in which to restrict searches. | Optional|


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.Job | Unknown | The SID of the created job. | 


##### Command Example
```!splunk-job-create query="index=* | head 3" ```

1	
##### Context Example	
```	
{
    "Splunk.Job": "1566221733.1628"
}
```
##### Human Readable Output
![image](https://user-images.githubusercontent.com/50324325/63269769-75981300-c29f-11e9-950a-6ca77bcf564c.png)


### 7. splunk-parse-raw
---
Parses the raw part of the event.
##### Base Command

`splunk-parse-raw`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| raw | The raw data of the Splunk event (string). | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.Raw.Parsed | unknown | The raw event data (parsed). | 


##### Command Example
``` !splunk-parse-raw ```


### 8. splunk-submit-event-hec
---
Sends events to an HTTP Event Collector using the Splunk platform JSON event protocol.
##### Base Command

`splunk-submit-event-hec`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event | Event payload key-value.<br>String example: "event": "Access log test message." | Required |
| fields | Fields for indexing that do not occur in the event payload itself. Accepts multiple comma separated fields. | Optional |
| index | The index name. | Optional |
| host | The hostname. | Optional |
| source_type | User-defined event source type. | Optional |
| source | User-defined event source. | Optional | 
| time | Epoch-formatted time | Optional | 

##### Context Output

There is no context output for this command.

##### Command Example
```!splunk-submit-event-hec event="something happened" fields="severity: INFO, category: test, test1" source_type=access source="/var/log/access.log"```

##### Human Readable Output
The event was sent successfully to Splunk.

9. Returns the status of a job: splunk-job-status
### 9. splunk-job-status
---
Returns the status of a job

##### Base Command
`splunk-job-status`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sid | ID of the job for which to get the status | Required |

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.JobStatus.CID | Unknown | ID of the job. |
| Splunk.JobStatus.Status | Unknown | Status of the job. |

##### Command Example
```!splunk-job-status sid=1234.5667```

##### Context Example
Splank.JobStatus = {
    'SID': 1234.5667,
    'Status': DONE
}

##### Human Readable Output
![image](https://user-images.githubusercontent.com/50324325/77630707-2b24f600-6f54-11ea-94fe-4bf6c734aa29.png)

## Aditional Information
To get the HEC Token -
1. Go to Splunk UI
2. Under "Settings" -> "Data" -> "Data inputs"
![Screen Shot 2020-01-20 at 10 22 50](https://user-images.githubusercontent.com/45915502/72710123-0f296080-3b6f-11ea-9eb4-a3cebb1e8700.png)
3. Then click on "HTTP Event Collector"
4. Click on "New Token"
5. Add all the relevant details until done.


_For the HTTP Port number:_
Click on Global settings (in the http event collector page)
![Screen Shot 2020-01-20 at 10 27 25](https://user-images.githubusercontent.com/45915502/72710342-8d860280-3b6f-11ea-8d66-4d60303aba48.png)

The default port is 8088
