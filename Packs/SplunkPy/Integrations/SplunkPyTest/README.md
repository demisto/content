Runs queries on Splunk servers.
## Configure SplunkPy - test on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SplunkPy - test.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Username |  | True |
    | Password |  | True |
    | Port | The port in Splunk server which is open to the REST API calls. | True |
    | Fetch events query | The Splunk search query by which to fetch events. The default query fetches ES notable events. You can edit this query to fetch other types of events. Note, that to fetch ES notable events, make sure to include the \\\`notable\\\` macro in your query. | False |
    | Fetch Limit (Max.- 200, Recommended less than 50) |  | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Use Splunk Clock Time For Fetch | Whether to use the Splunk clock time from the Splunk server for fetch, or not. | False |
    | Parse Raw Part of Notable Events | Whether to parse the raw part of the Notables, or not. | False |
    | Replace with Underscore in Incident Fields | Whether to replace special characters to underscore when parsing the raw data of the Notables, or not. | False |
    | Timezone of the Splunk server, in minutes. For example, if GMT is gmt +3, set timezone to +180. For UTC, set the timezone to 0. This is relevant only for fetching and mirroring notable events. It must be specified when mirroring is enabled. |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | The amount of time to go back when performing the first fetch, or when creating a mapping using the Select Schema option. | False |
    | Extract Fields - CSV fields that will be parsed out of _raw notable events |  | False |
    | Event Type Field | Used only for mapping with the Select Schema option. The name of the field that contains the type of the event or alert. The default value is "source", which is a good option for notable events. However, you may choose any custom field. | False |
    | Use CIM Schemas for Mapping | If selected, when creating a mapper using the \`Select Schema\` feature \(supported from Cortex XSOAR V6.0\), the Splunk CIM field will be pulled. See https://docs.splunk.com/Documentation/CIM/4.18.0/User/Overview for more information. | False |
    | Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from Splunk to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to Splunk\), or Incoming and Outgoing \(from/to Cortex XSOAR and Splunk\). | False |
    | Close Mirrored Cortex XSOAR Incidents (Incoming Mirroring) | When selected, closing the Splunk notable event with a "Closed" status will close the Cortex XSOAR incident. | False |
    | Additional Splunk status labels to close on mirror (Incoming Mirroring) | A comma-separated list of Splunk status labels to mirror as closed Cortex XSOAR incident \(Example: Resolved,False-Positive\). | False |
    | Enable Splunk statuses marked as "End Status" to close on mirror (Incoming Mirroring) | When selected, Splunk Notable Events with a status that is marked as "End Status" will close the Cortex XSOAR incident. | False |
    | Close Mirrored Splunk Notable Events (Outgoing Mirroring) | When selected, closing the Cortex XSOAR incident  will close the Notable Event in Splunk. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | The app context of the namespace |  | False |
    | HEC Token (HTTP Event Collector) |  | False |
    | HEC Token (HTTP Event Collector) |  | False |
    | HEC BASE URL (e.g: https://localhost:8088 or https://example.splunkcloud.com/). |  | False |
    | Enrichment Types | Enrichment types to enrich each fetched notable. If none are selected, the integration will fetch notables as usual \(without enrichment\). Multiple drilldown searches enrichment is supported from Enterprise Security v7.2.0. For more info about enrichment types see the integration additional info. | False |
    | Asset enrichment lookup tables | CSV of the Splunk lookup tables from which to take the Asset enrichment data. | False |
    | Identity enrichment lookup tables | CSV of the Splunk lookup tables from which to take the Identity enrichment data. | False |
    | Enrichment Timeout (Minutes) | When the selected timeout was reached, notable events that were not enriched will be saved without the enrichment. | False |
    | Number of Events Per Enrichment Type | The limit of how many events to retrieve per each one of the enrichment types \(Drilldown, Asset, and Identity\). In a case of multiple drilldown enrichments the limit will apply for each drilldown search query. To retrieve all events, enter "0" \(not recommended\). | False |
    | Advanced: Extensive logging (for debugging purposes). Do not use this option unless advised otherwise. |  | False |
    | Advanced: Fetch backwards window for the events occurrence time (minutes) | The fetch time range will be at least the size specified here. This will support events that have a gap between their occurrence time and their index time in Splunk. To decide how long the backwards window should be, you need to determine the average time between them both in your Splunk environment. | False |
    | Advanced: Unique ID fields | A comma-separated list of fields, which together are a unique identifier for the events to fetch in order to avoid fetching duplicates incidents. | False |
    | Enable user mapping | Whether to enable the user mapping between Cortex XSOAR and Splunk, or not. For more information see https://xsoar.pan.dev/docs/reference/integrations/splunk-py\#configure-user-mapping-between-splunk-and-cortex-xsoar | False |
    | Users Lookup table name | The name of the lookup table in Splunk, containing the username's mapping data. | False |
    | XSOAR user key | The name of the lookup column containing the Cortex XSOAR username. | False |
    | SPLUNK user key | The name of the lookup table containing the Splunk username. | False |
    | Incidents Fetch Interval |  | False |
    | Comment tag from Splunk | Add this tag to an entry to mirror it as a comment from Splunk. | False |
    | Comment tag to Splunk | Add this tag to an entry to mirror it as a comment to Splunk. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### splunk-results

***
Returns the results of a previous Splunk search. You can use this command in conjunction with the splunk-job-create command.

#### Base Command

`splunk-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sid | ID of the search for which to return results. | Required | 
| limit | The maximum number of returned results per search. To retrieve all results, enter "0" (not recommended). Default is 100. | Optional | 

#### Context Output

There is no context output for this command.
### splunk-search

***
Searches Splunk for events. For human readable output, the table command is supported in the query argument. For example, `query=" * | table field1 field2 field3"` will generate a table with field1, field2, and field3 as headers.

#### Base Command

`splunk-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The Splunk search language string to execute. For example: "index=* \| head 3". . | Required | 
| earliest_time | Specifies the earliest time in the time range to search. The time string can be a UTC time (with fractional seconds), a relative time specifier (to now), or a formatted time string. Default is 1 week ago, in the format "-7d". You can also specify time in the format: 2014-06-19T12:00:00.000-07:00. | Optional | 
| latest_time | Specifies the latest time in the time range to search. The time string can be a UTC time (with fractional seconds), a relative time specifier (to now), or a formatted time string. For example: "2014-06-19T12:00:00.000-07:00" or "-3d" (for 3 days ago). | Optional | 
| event_limit | Maximum number of events to return. Default is 100. If "0", all results are returned. | Optional | 
| batch_limit | The maximum number of returned results to process at a time. For example, if 100 results are returned, and you specify a batch_limit of 10, the results will be processed 10 at a time over 10 iterations. This does not effect the search or the context and outputs returned. In some cases, specifying a batch_size enhances search performance. If you think that the search execution is suboptimal, we recommend trying several batch_size values to determine which works best for your search. Default is 25,000. Default is 25000. | Optional | 
| update_context | Determines whether the results will be entered into the context. Possible values: "true" and "false". Possible values are: true, false. Default is true. | Optional | 
| app | A string that contains the application namespace in which to restrict searches. | Optional | 
| polling | Use XSOAR built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 30. | Optional | 
| sid | The job sid. | Optional | 
| fast_mode | The Fast mode prioritizes the performance of the search and does not return nonessential field or event data. This means that the search returns what is essential and required if fast_mode equals 'true'. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.Result | Unknown | The results of the Splunk search. The results are a JSON array, in which each item is a Splunk event. | 
| Splunk.JobStatus.SID | String | ID of the job. | 
| Splunk.JobStatus.Status | String | Status of the job. | 
| Splunk.JobStatus.TotalResults | String | The number of events that were returned by the job. | 

### splunk-submit-event

***
Creates a new event in Splunk.

#### Base Command

`splunk-submit-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | Splunk index in which to push data. Run the splunk-get-indexes command to get all indexes. | Required | 
| data | The new event data to push. Can be any string. | Required | 
| sourcetype | Event source type. | Required | 
| host | Event host. Can be "Local" or "120.0.0.1". | Required | 

#### Context Output

There is no context output for this command.
### splunk-get-indexes

***
Prints all Splunk index names.

#### Base Command

`splunk-get-indexes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### splunk-notable-event-edit

***
Updates existing notable events in Splunk ES.

#### Base Command

`splunk-notable-event-edit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventIDs | A comma-separated list of event IDs of notable events. | Required | 
| owner | A Splunk user to assign to the notable events. | Optional | 
| comment | Comment to add to the notable events. | Optional | 
| urgency | Notable event urgency. Possible values: "critical", "high", "medium", "low", and "informational". Possible values are: critical, high, medium, low, informational. | Optional | 
| status | Notable event status. 0 - Unassigned, 1 - Assigned, 2 - In Progress, 3 - Pending, 4 - Resolved, 5 - Closed. | Optional | 
| disposition | Disposition of the notable. If the more options exist on the server, specifying the disposition as `disposition:#` will work in place of choosing one of the default values from the list. Possible values are: True Positive - Suspicious Activity, Benign Positive - Suspicious But Expected, False Positive - Incorrect Analytic Logic, False Positive - Inaccurate Data, Other, Undetermined. | Optional | 

#### Context Output

There is no context output for this command.
### splunk-job-create

***
Creates a new search job in Splunk.

#### Base Command

`splunk-job-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The Splunk search language string to execute. For example :"index=* \| head 3". | Required | 
| app | A string that contains the application namespace in which to restrict searches. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.Job | Unknown | The SID of the created job. | 

### splunk-parse-raw

***
Parses the raw part of the event.

#### Base Command

`splunk-parse-raw`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| raw | The raw data of the Splunk event (string). Default is ${Splunk.Result._raw}. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.Raw.Parsed | unknown | The raw event data \(parsed\). | 

### splunk-submit-event-hec

***
Sends events to an HTTP Event Collector using the Splunk platform JSON event protocol.

#### Base Command

`splunk-submit-event-hec`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event | Event payload key-value pair.<br/>String example: "event": "Access log test message". | Optional | 
| fields | Fields for indexing that do not occur in the event payload itself. Accepts multiple, comma-separated, fields. | Optional | 
| index | The index name. | Optional | 
| host | The hostname. | Optional | 
| source_type | User-defined event source type. | Optional | 
| source | User-defined event source. | Optional | 
| time | Epoch-formatted time. | Optional | 
| request_channel | A channel identifier (ID) where to send the request, must be a Globally Unique Identifier (GUID). If the indexer acknowledgment is turned on, a channel is required. | Optional | 
| batch_event_data | A  batch of events to send to Splunk. For example, `{"event": "something happened at 14/10/2024 12:29", "fields": {"severity": "INFO", "category": "test2, test2"}, "index": "index0","sourcetype": "sourcetype0","source": "/example/something" } {"event": "something happened at 14/10/2024 13:29", "index": "index1", "sourcetype": "sourcetype1","source": "/example/something", "fields":{ "fields" : "severity: INFO, category: test2, test2"}}`. If provided all arguments except of `request_channel` are ignored. | Optional | 
| entry_id | The entry ID in Cortex XSOAR of the file containing a batch of events. If provided, the arguments related to a single event are ignored. | Optional | 

#### Context Output

There is no context output for this command.
### splunk-job-status

***
Returns the status of a job.

#### Base Command

`splunk-job-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sid | ID of the job for which to get the status. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.JobStatus.SID | String | ID of the job. | 
| Splunk.JobStatus.Status | String | Status of the job. | 

### splunk-kv-store-collection-create

***
Creates a new KV store table.

#### Base Command

`splunk-kv-store-collection-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kv_store_name | The name of the KV store collection. | Required | 
| app_name | The name of the Splunk application in which to create the KV store. The default is "search". Default is search. | Required | 

#### Context Output

There is no context output for this command.
### splunk-kv-store-collection-config

***
Configures the KV store fields.

#### Base Command

`splunk-kv-store-collection-config`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kv_store_collection_name | The name of the KV store collection. | Required | 
| kv_store_fields | The list of names and value types used to define the KV store collection scheme, e.g., id=number, name=string, address=string.<br/>. | Required | 
| app_name | The name of the Splunk application that contains the KV store collection. The default is "search". Default is search. | Required | 

#### Context Output

There is no context output for this command.
### splunk-kv-store-collection-create-transform

***
Creates the KV store collection transform.

#### Base Command

`splunk-kv-store-collection-create-transform`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kv_store_collection_name | The name of the KV store collection. | Required | 
| supported_fields | A comma-delimited list of the fields supported by the collection, e.g., _key,id,name,address. If no value is specified, the KV Store collection configuration will be used.<br/>. | Optional | 
| app_name | The name of the Splunk application that contains the KV store collection. Default is search. | Required | 

#### Context Output

There is no context output for this command.
### splunk-kv-store-collection-add-entries

***
Adds objects to a KV store utilizing the batch-save API.

#### Base Command

`splunk-kv-store-collection-add-entries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kv_store_data | The data to add to the KV store collection, according to the collection JSON format, e.g., [{"name": "Splunk HQ", "id": 456, "address": { "street": "340 Brannan Street", "city": "San Francisco", "state": "CA", "zip": "121212"}}, {"name": "Splunk HQ", "id": 123, "address": { "street": "250 Brannan Street", "city": "San Francisco", "state": "CA", "zip": "94107"}}]. | Required | 
| kv_store_collection_name | The name of the KV store collection. | Required | 
| indicator_path | The path to the indicator value in kv_store_data. | Optional | 
| app_name | The name of the Splunk application that contains the KV store collection. The default is "search". Default is search. | Required | 

#### Context Output

There is no context output for this command.
### splunk-kv-store-collections-list

***
Lists all collections for the specified application.

#### Base Command

`splunk-kv-store-collections-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application in which to create the KV store. The default is "search". Default is search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.CollectionList | String | List of collections. | 

### splunk-kv-store-collection-data-list

***
Lists all data within a specific KV store collection or collections.

#### Base Command

`splunk-kv-store-collection-data-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application that contains the KV store collection. The default is "search". Default is search. | Required | 
| kv_store_collection_name | A comma-separated list of KV store collections. | Required | 
| limit | Maximum number of records to return. The default is 50. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.KVstoreData | Unknown | An array of collection names. Each collection name will have an array of values, e.g., Splunk.KVstoreData.&lt;collection_name&gt; is a list of the data in the collection. | 

### splunk-kv-store-collection-data-delete

***
Deletes all data within the specified KV store collection or collections.

#### Base Command

`splunk-kv-store-collection-data-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application that contains the KV store collection. For example, "search". Default is search. | Required | 
| kv_store_collection_name | A comma-separated list of KV store collections. | Required | 

#### Context Output

There is no context output for this command.
### splunk-kv-store-collection-delete

***
Deletes the specified KV stores.

#### Base Command

`splunk-kv-store-collection-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application that contains the KV store. The default is "store". Default is search. | Required | 
| kv_store_name | A comma-separated list of KV stores. | Required | 

#### Context Output

There is no context output for this command.
### splunk-kv-store-collection-search-entry

***
Searches for specific objects in a store. The search can be a basic key-value pair or a full query.

#### Base Command

`splunk-kv-store-collection-search-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application that contains the KV store collection. The default is "search". Default is search. | Required | 
| kv_store_collection_name | The name of the KV store collection. | Required | 
| key | The key name to search in the store. If the query argument is used, this argument will be ignored. | Optional | 
| value | The value to search in the store. If the query argument is used, this argument will be ignored. | Optional | 
| query | Complex query to search in the store with operators such as "and", "or", "not", etc. For more information, see the Splunk documentation: https://docs.splunk.com/Documentation/Splunk/8.0.3/RESTREF/RESTkvstore. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.KVstoreData | Unknown | An array of collection names. Each collection name will have an array of values, e.g., Splunk.KVstoreData.&lt;collection_name&gt; is a list of the data in the collection. | 

### splunk-kv-store-collection-delete-entry

***
Deletes the specified object in store. The search can be a basic key-value pair or a full query.

#### Base Command

`splunk-kv-store-collection-delete-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application that contains the KV store collection. The default is "search". Default is search. | Required | 
| kv_store_collection_name | The name of the KV store collection. | Required | 
| indicator_path | The path to the indicator value in kv_store_data. | Optional | 
| key | The key name to search in the store. If the query argument is used, this argument will be ignored. | Optional | 
| value | The value to search in the store. If the query argument is used, this argument will be ignored. | Optional | 
| query | Complex query to search in the store with operators such as "and", "or", "not", etc.<br/>For more information, see the Splunk documentation: https://docs.splunk.com/Documentation/Splunk/8.0.3/RESTREF/RESTkvstore. | Optional | 

#### Context Output

There is no context output for this command.
### get-mapping-fields

***
Query Splunk to retrieve a list of sample alerts by alert type. Used for mapping fetched incidents through the Get Schema option.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### get-remote-data

***
Gets data from a notable event. This method does not update the current incident, and should be used for debugging purposes.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote event ID. | Required | 
| lastUpdate | ISO format date with timezone, e.g., 2021-02-09T16:41:30.589575+02:00. The incident is only updated if it was modified after the last update time. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### get-modified-remote-data

***
Gets the list of notable events that were modified since the last update. This command should be used for debugging purposes, and is available from Cortex XSOAR version 6.1.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | ISO format date with timezone, e.g., 2021-02-09T16:41:30.589575+02:00. The incident is only returned if it was modified after the last update time. | Optional | 

#### Context Output

There is no context output for this command.
### splunk-reset-enriching-fetch-mechanism

***
Resets the enrichment mechanism of fetched notables.

#### Base Command

`splunk-reset-enriching-fetch-mechanism`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### splunk-get-username-by-xsoar-user

***
Returns the Splunk's username matching the given Cortex XSOAR's username.

#### Base Command

`splunk-get-username-by-xsoar-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| xsoar_username | Cortex XSOAR username to match in Splunk's usernames records. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.UserMapping.XsoarUser | String | Cortex XSOAR user mapping. | 
| Splunk.UserMapping.SplunkUser | String | Splunk user mapping. | 

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and SplunkPy - test corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in SplunkPy - test events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in SplunkPy - test events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and SplunkPy - test events will be reflected in both directions. |

3. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding event is closed in SplunkPy - test.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and SplunkPy - test.
