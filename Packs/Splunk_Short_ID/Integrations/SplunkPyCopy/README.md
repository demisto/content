Run queries on Splunk servers.
## Configure SplunkPy_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SplunkPy_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Host - ip (x.x.x.x) |  | True |
    | Username |  | True |
    | Password |  | True |
    | Port |  | True |
    | Fetch notable events ES query |  | False |
    | Fetch Limit (Max.- 200, Recommended less than 50) |  | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Use system proxy settings |  | False |
    | Timezone of the Splunk server, in minutes. For example, GMT is gmt +3, set +180 (set only if different than Demisto server). Relevant only for fetching notable events. |  | False |
    | Parse Raw part of notable events |  | False |
    | Replace with Underscore in Incident Fields |  | False |
    | Extract Fields - CSV fields that will be parsed out of _raw notable events |  | False |
    | Use Splunk Clock Time For Fetch |  | False |
    | Trust any certificate (not secure) |  | False |
    | Earliest time to fetch (the name of the Splunk field whose value defines the query's earliest time to fetch) |  | False |
    | Latest time to fetch (the name of the Splunk field whose value defines the query's latest time to fetch) |  | False |
    | The app context of the namespace |  | False |
    | HEC Token (HTTP Event Collector) |  | False |
    | HEC URL (e.g: https://localhost:8088). |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | How far back in time to go when performing the first fetch, or when creating a mapping using the Select Schema option. | False |
    | Use Python requests handler |  | False |
    | Event Type Field | Used only for Mapping with the Select Schema option. The name of the field that contains the type of the event or alert. The default value is "source", which is a good option for Notable Events, however you may choose any custom field that suits the need. | False |
    | Use CIM Schemas for Mapping | If selected, when creating a mapper using the \`Select Schema\` feature \(Supported from XSOAR V6.0\), Splunk CIM field will be pulled. See https://docs.splunk.com/Documentation/CIM/4.18.0/User/Overview for more info. | False |
    | Incidents Fetch Interval |  | False |

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
| limit | The maximum number of returned results per search. To retrieve all results, enter "0" (Not recommended). Default is 100. | Optional | 

#### Context Output

There is no context output for this command.
### splunk-search

***
Searches Splunk for events.

#### Base Command

`splunk-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The Splunk search language string to execute. For example: "index=* \| head 3". . | Required | 
| earliest_time | Specifies the earliest time in the time range to search. The time string can be a UTC time (with fractional seconds), a relative time specifier (to now), or a formatted time string. Default is 1 week ago, in the format "-7d". You can also specify time in the format: 2014-06-19T12:00:00.000-07:00". | Optional | 
| latest_time |  Specifies the latest time in the time range to search. The time string can be a UTC time (with fractional seconds), a relative time specifier (to now), or a formatted time string. For example: "2014-06-19T12:00:00.000-07:00" or "-3d" (for time 3 days before now). | Optional | 
| event_limit | Maximum number of events to return. Default is 100. If "0", all results are returned. | Optional | 
| batch_limit | The maximum number of returned results to  process at a time. For example, if 100 results are returned, and you specify a batch_limit of 10, the results will be processed 10 at a time over 10 iterations. This does not effect the search or the context and outputs returned. In some cases, specifying a batch_size enhances search performance. If you think that the search execution is suboptimal, we recommend trying several batch_size values to determine which works best for your search. Default is 25,000. Default is 25000. | Optional | 
| update_context | Determines whether the results will be entered into the context. Possible values are: true, false. Default is true. | Optional | 
| app | A string that contains the application namespace in which to restrict searches. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.Result | Unknown | The results of the Splunk search. The results are a JSON array, in which each item is a Splunk event. | 

### splunk-submit-event

***
Creates a new event in Splunk.

#### Base Command

`splunk-submit-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | Splunk index to which to push data. Run the splunk-get-indexes command to get all indexes. | Required | 
| data | The new event data to push, can be any string. | Required | 
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
Update an existing Notable event in Splunk ES.

#### Base Command

`splunk-notable-event-edit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventIDs | A comma-separated list of event IDs of notable events. | Required | 
| owner | A Splunk user to assign to the notable event. | Optional | 
| comment | Comment to add to the notable event. | Optional | 
| urgency | Notable event urgency. Possible values are: critical, high, medium, low, informational. | Optional | 
| status | Notable event status. 0 - Unassigned, 1 - Assigned, 2 - In Progress, 3 - Pending, 4 - Resolved, 5 - Closed. | Optional | 

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
| event | Event payload key-value.<br/>String example: "event": "Access log test message.". | Required | 
| fields | Fields for indexing that do not occur in the event payload itself. Accepts multiple, comma separated, fields. | Optional | 
| index | The index name. | Optional | 
| host | The hostname. | Optional | 
| source_type | User-defined event source type. | Optional | 
| source | User-defined event source. | Optional | 
| time | Epoch-formatted time. | Optional | 

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
| kv_store_fields | The list of names and value types to define the KV store collection scheme, e.g., id=number, name=string, address=string.<br/>. | Required | 
| app_name | The name of the Splunk application that contains the KV store collection. The default is "search". Default is search. | Required | 

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
| kv_store_data | The data to add to the KV store collection, according to the collection JSON format, e.g., {"name": "Splunk HQ", "id": 123, "address": { "street": "250 Brannan Street", "city": "San Francisco", "state": "CA", "zip": "94107"}}. | Required | 
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
| Splunk.KVstoreData | Unknown | An array of collection names. Each collection name will have an array of values, e.g., Splunk.KVstoreData.&lt;colletion_name&gt; is a list of the data in the collection\). | 

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
Deletes the specified KV store.

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
Searches for specific objects in a store. Search can be basic key value or a full query.

#### Base Command

`splunk-kv-store-collection-search-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application that contains the KV store collection. The default is "search". Default is search. | Required | 
| kv_store_collection_name | The name of the KV store collection. | Required | 
| key | The key name to search in the store. If the query argument is used, this argument will be ignored. | Optional | 
| value | The value to search in the store. If the query argument is used, this argument will be ignored. | Optional | 
| query | Complex query to search in the store with operators such as "and", "or", "not", etc. For more information see the Splunk documentation: https://docs.splunk.com/Documentation/Splunk/8.0.3/RESTREF/RESTkvstore. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.KVstoreData | Unknown | An array of collection names. Each collection name will have an array of values, e.g., Splunk.KVstoreData.&lt;colletion_name&gt; is a list of the data in the collection\). | 

### splunk-kv-store-collection-delete-entry

***
Deletes the specified object in store. Search can be basic key value or a full query.

#### Base Command

`splunk-kv-store-collection-delete-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application that contains the KV store collection. The deafult is "search". Default is search. | Required | 
| kv_store_collection_name | The name of the KV store collection. | Required | 
| indicator_path | The path to the indicator value in kv_store_data. | Optional | 
| key | The key name to search in the store. If the query argument is used, this argument will be ignored. | Optional | 
| value | The value to search in the store. If the query argument is used, this argument will be ignored. | Optional | 
| query | Complex query to search in the store with operators such as "and", "or", "not", etc.<br/>For more information see the Splunk documentation: https://docs.splunk.com/Documentation/Splunk/8.0.3/RESTREF/RESTkvstore. | Optional | 

#### Context Output

There is no context output for this command.
### get-mapping-fields

***
Query Splunk to retrieve a list of sample alerts by alert type. Used for Mapping fetched incidents through the Get Schema option.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### get-license-status

***

#### Base Command

`get-license-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
