Use the SplunkPy integration to fetch events (logs) from within Cortex XSOAR, push events from Cortex XSOAR to SplunkPy, and fetch SplunkPy ES notable events as Cortex XSOAR incidents.

This integration was integrated and tested with Splunk v7.2.

## Use Cases
---
* Query Splunk for events.
* Create a new event in Splunk.
* Get results of a search that was executed in Splunk.

## Configure SplunkPy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SplunkPy.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| host | The host name to the server, including the scheme (x.x.x.x). | True |
| authentication | The username used for authentication. | True |
| port | The port affiliated with the server. | True |
| fetchQuery | The notable events ES query to be fetched. | False |
| fetch_limit | The limit of incidents to fetch. The maximum is 200 (It is recommended to fetch less than 50). | False |
| isFetch | The incidents fetched. | False |
| incidentType | The incident type. | False |
| proxy | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | False |
| timezone | The timezone of the Splunk server (in minutes). For example, GMT is gmt +3, set +180 (set this only if it is different than the Cortex XSOAR server). This is relevant only for fetching notable events. | False |
| parseNotableEventsRaw | Parses the raw part of notable events. | False |
| replaceKeys | Replace with Underscore in Incident Fields | False |
| extractFields | The CSV fields that will be parsed out of _raw notable events. | False |
| useSplunkTime | Uses the Splunk clock time for the fetch. | False |
| unsecure |  When selected, certificates are not checked. (not secure) | False |
| earliest_fetch_time_fieldname | The earliest time to fetch (the name of the Splunk field whose value defines the query's earliest time to fetch). | False |
| latest_fetch_time_fieldname | The latest time to fetch (the name of the Splunk field whose value defines the query's latest time to fetch). | False |
| app | The context of the application's namespace. | False |
| hec_token | The HEC token (HTTP Event Collector). | False |
| hec_url | The HEC URL. For example, https://localhost:8088. | False |
| fetch_time | The first timestamp to fetch in \<number\>\<time unit\> format. For example, "12 hours", "7 days", "3 months", "1 year". | False |
| use_requests_handler | Use Python requests handler  | False |
| type_field | Used only for Mapping with the Select Schema option. The name of the field that contains the type of the event or alert. The default value is "source", which is a good option for Notable Events, however you may choose any custom field that suits the need. | False |

The (!) `Earliest time to fetch` and `Latest time to fetch` are search parameters options. The search uses `All Time` as the default time range when you run a search from the CLI. Time ranges can be specified using one of the CLI search parameters, such as `earliest_time`, `index_earliest`, or `latest_time`.

4. Click **Test** to validate the URLs, token, and connection.

**Note:** To use a Splunk Cloud instance, contact Splunk support to request API access. Use a non-SAML account to access the API.

### Configure Splunk to Produce Alerts for SplunkPy
It is recommended that Splunk is configured to produce basic alerts that the SplunkPy integration can ingest, by creating a summary index in which alerts are stored. The SplunkPy integration can then query that index for incident ingestion. It is not recommended to use the Cortex XSOAR application with Splunk for routine event consumption because this method is not able to be monitored and is not scalable.

1. Create a summary index in Splunk. For more information, click [here](https://docs.splunk.com/Documentation/Splunk/7.3.0/Indexer/Setupmultipleindexes#Create_events_indexes_2).
2. Build a query to return relevant alerts.
![image](https://user-images.githubusercontent.com/50324325/63265602-ae7fba00-c296-11e9-898c-afc98c56a1cb.png)
3. Identify the fields list from the Splunk query and save it to a local file.
![image](https://user-images.githubusercontent.com/50324325/63265613-b6d7f500-c296-11e9-81d7-854ee4ee9685.png)
4. Define a search macro to capture the fields list that you saved locally. For more information, click [here](https://docs.splunk.com/Documentation/Splunk/7.3.0/Knowledge/Definesearchmacros).
Use the following naming convention: (demisto_fields_{type}).
![image](https://user-images.githubusercontent.com/50324325/63265773-08807f80-c297-11e9-86a1-355a261c356b.png)
![image](https://user-images.githubusercontent.com/50324325/63265623-bccdd600-c296-11e9-9303-47b9791b0205.png)
5. Define a scheduled search, the results of which are stored in the summary index. For more information about scheduling searches, click [here](https://docs.splunk.com/Documentation/Splunk/7.3.0/Knowledge/Definesearchmacros). 
![image](https://user-images.githubusercontent.com/50324325/63265640-c5261100-c296-11e9-9bd6-426fb328c09c.png)
6. In the Summary indexing section, select the summary index, and enter the {key:value} pair for Cortex XSOAR classification.
![image](https://user-images.githubusercontent.com/50324325/63265665-d0793c80-c296-11e9-9919-cf6c6af33294.png)
7. Configure the incident type in Cortex XSOAR by navigating to __Settings > Advanced > Incident Types.__
![image](https://user-images.githubusercontent.com/50324325/63265677-d66f1d80-c296-11e9-95df-190ab18ae484.png)
8. Navigate to __Settings > Integrations > Classification & Mapping__, and drag the value to the appropriate incident type.
![image](https://user-images.githubusercontent.com/50324325/63265720-ea1a8400-c296-11e9-8062-dd40606c5a42.png)
9. Click the __Edit mapping__ link to map the Splunk fields to Cortex XSOAR.
![image](https://user-images.githubusercontent.com/50324325/63265811-1d5d1300-c297-11e9-8026-52ff1cf30cbf.png)
10. (Optional) Create custom fields.
11. Build a playbook and assign it as the default for this incident type.

### Mapping fetched incidents using Select Schema
This integration supports the `Select Schema` feature of XSOAR 6.0 by providing the `get-mapping-fields` command. 
When creating a new field Mapping for fetched incidents, the `Pull Instances` option retrieves current alerts which can be clicked to visually map fields.
The `Select Schema` option retrieves possible objects, even if they are not the next objects to be fetched, or have not been triggered in the past 24 hours. 
This enables you to map fields for an incident without having to generate a new alert or incident just for the sake of mapping.
The `get-mapping-fields` command can be executed in the Playground to test and review the list of sample objects that are returned under the current configuration.

To use this feature, you must set several integration instance parameters:
 - `Fetch notable events ES query` - The query used for fetching new incidents. `Select Schema` will run a modified version of this query to get the object samples, so it is important to have the correct query here. 
 - `Event Type Field` - The name of the field that contains the type of the event or alert. The default value is `source` which for `Notable Events` will contains the rule name. However you may choose any custom field that suits this purpose.
 - `First fetch timestamp` - The time scope of objects to be pulled. You may choose to go back further in time to include samples for alert types that haven't triggered recently - so long as your Splunk server can handle the more intensive Search Job involved.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get results
***
Returns the results of a previous Splunk search. This command can be used in conjunction with the `splunk-job-create` command.

##### Base Command

`splunk-results`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sid | The ID of the search for which to return results. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` !splunk-results sid="1566221331.1186" ```

### Search for events
***
Searches Splunk for events.


##### Base Command

`splunk-search`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The Splunk search language string to execute. For example, "index=* \| head 3". | Required | 
| earliest_time | Specifies the earliest time in the time range to search. The time string can be a UTC time (with fractional seconds), a relative time specifier (to now), or a formatted time string. The default is 1 week ago, in the format "-7d". You can also specify time in the format: 2014-06-19T12:00:00.000-07:00". | Optional | 
| latest_time |  Specifies the latest time in the time range to search. The time string can be a UTC time (with fractional seconds), a relative time specifier (to now), or a formatted time string. For example: "2014-06-19T12:00:00.000-07:00" or "-3d" (for time 3 days before now). | Optional | 
| event_limit | The maximum number of events to return. The default is 100. If "0" is selected, all results are returned. | Optional | 
| app | The string that contains the application namespace in which to restrict searches. | Optional|
| batch_limit | The maximum number of returned results to process at a time. For example, if 100 results are returned, and you specify a `batch_limit` of 10, the results will be processed 10 at a time over 10 iterations. This does not affect the search or the context and outputs returned. In some cases, specifying a `batch_size` enhances search performance. If you think that the search execution is suboptimal, it is  recommended to try several `batch_size` values to determine which works best for your search. The default is 25,000. | Optional |	
| update_context | Determines whether the results will be entered into the context. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.Result | Unknown | The results of the Splunk search. The results are a JSON array, in which each item is a Splunk event. | 


##### Command Example
```!splunk-search query="* | head 3" earliest_time="-1000d"```

##### Human Readable Output
### Splunk Search results for query: * | head 3
|_bkt|_cd|_indextime|_kv|_raw|_serial|_si|_sourcetype|_time|host|index|linecount|source|sourcetype|splunk_server|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| main~445~66D21DF4-F4FD-4886-A986-82E72ADCBFE9 | 445:897774 | 1585462906 | 1 | InsertedAt="2020-03-29 06:21:43"; EventID="837005"; EventType="Application control"; Action="None"; ComputerName="ACME-code-007"; ComputerDomain="DOMAIN"; ComputerIPAddress="127.0.0.1"; EventTime="2020-03-29 06:21:43"; EventTypeID="5"; Name="LogMeIn"; EventName="LogMeIn"; UserName=""; ActionID="6"; ScanTypeID="200"; ScanType="Unknown"; SubTypeID="23"; SubType="Remote management tool"; GroupName="";\u003cbr\u003e | 2 | ip-172-31-44-193, main | sophos:appcontrol | 2020-03-28T23:21:43.000-07:00 | 127.0.0.1 | main | 2 | eventgen | sophos:appcontrol | ip-172-31-44-193 |

### Create event
***
Creates a new event in Splunk.


##### Base Command

`splunk-submit-event`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | The Splunk index to which to push the data. Run the `splunk-get-indexes` command to get all of the indexes. | Required | 
| data | The new event data to push. Can be, any string. | Required | 
| sourcetype | The event source type. | Required | 
| host | The event host. Can be, "Local" or "120.0.0.1". | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` !splunk-submit-event index="main" data="test" sourcetype="demisto-ci" host="localhost" ```

##### Human Readable Output

![image](https://user-images.githubusercontent.com/50324325/63268589-2fda4b00-c29d-11e9-95b5-4b9fcf6c08ee.png)


### Print all index names
***
Prints all Splunk index names.
##### Base Command

`splunk-get-indexes`

##### Input

There are no input arguments for this command.

##### Context Output

There is no context output for this command.

##### Command Example
``` !splunk-get-indexes extend-context="indexes="```

##### Human Readable Output

![image](https://user-images.githubusercontent.com/50324325/63268447-d8d47600-c29c-11e9-88a4-5003971a492e.png)


### Update notable events
***
Update an existing notable event in Splunk ES.

##### Base Command

`splunk-notable-event-edit`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventIDs | The comma-separated list of event IDs of notable events. | Required | 
| owner | The Splunk user to assign to the notable event. | Optional | 
| comment | The comment to add to the notable event. | Required | 
| urgency | The urgency of the notable event. | Optional | 
| status | The notable event status. Can be 0 - 5, where 0 - Unassigned, 1 - Assigned, 2 - In Progress, 3 - Pending, 4 - Resolved, 5 - Closed. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
``` !splunk-notable-event-edit eventIDs=66D21DF4-F4FD-4886-A986-82E72ADCBFE9@@notable@@a045b8acc3ec93c2c74a2b18c2caabf4 comment="Demisto"```

##### Human Readable Output
![image](https://user-images.githubusercontent.com/50324325/63522203-914e2400-c500-11e9-949a-0b55eb2c5871.png)


### Create a new job
***
Creates a new search job in Splunk.


##### Base Command

`splunk-job-create`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The Splunk search language string to execute. For example,  "index=* \| head 3". | Required | 
| app | The string that contains the application namespace in which to restrict searches. | Optional|


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.Job | Unknown | The SID of the created job. | 


##### Command Example
```!splunk-job-create query="index=* | head 3"```

##### Context Example	
```	
{
    "Splunk.Job": "1566221733.1628"
}
```
##### Human Readable Output
![image](https://user-images.githubusercontent.com/50324325/63269769-75981300-c29f-11e9-950a-6ca77bcf564c.png)


### Parse an event
***
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


### Submit an event 
***
Sends events to an HTTP event collector using the Splunk platform JSON event protocol.
##### Base Command

`splunk-submit-event-hec`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event | The event payload key-value. An example string: "event": "Access log test message.". | Required |
| fields | Fields for indexing that do not occur in the event payload itself. Accepts multiple, comma separated, fields. | Optional |
| index | The index name. | Optional |
| host | The hostname. | Optional |
| source_type | The user-defined event source type. | Optional |
| source | The user-defined event source. | Optional | 
| time | The epoch-formatted time. | Optional | 

##### Context Output

There is no context output for this command.

##### Command Example
```!splunk-submit-event-hec event="something happened" fields="severity: INFO, category: test, test1" source_type=access source="/var/log/access.log"```

##### Human Readable Output
The event was sent successfully to Splunk.

### Get job status
***
Returns the status of a job.

##### Base Command
`splunk-job-status`

##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sid | The ID of the job for which to get the status. | Required |

##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.JobStatus.CID | Unknown | The ID of the job. |
| Splunk.JobStatus.Status | Unknown | The status of the job. |

##### Command Example
```!splunk-job-status sid=1234.5667```

##### Context Example
```
Splank.JobStatus = {
    'SID': 1234.5667,
    'Status': DONE
}
```

##### Human Readable Output
![image](https://user-images.githubusercontent.com/50324325/77630707-2b24f600-6f54-11ea-94fe-4bf6c734aa29.png)

### Get Mapping Fields
***
Gets one sample alert per alert type. Used only for creating a mapping with `Select Schema`. 
##### Base Command

`get-mapping-fields`
##### Input

There are no input arguments for this command.

##### Context Output

There is no context output for this command.

##### Command Example
```!get-mapping-fields using="SplunkPy_7.2" raw-response="true"```

##### Human Readable Output
```{
    "Access - Brute Force Access Behavior Detected - Rule": {
        "_bkt": "notable~712~66D21DF4-F4FD-4886-A986-82E72ADCBFE9",
        "_cd": "712:21939",
        "_indextime": "1598464820",
        "_serial": "0",
        "_si": [
            "ip-1-1-1-1",
            "notable"
        ],
        "_sourcetype": "stash",
        "_time": "2020-08-26T11:00:20.000-07:00",
        "host": "ip-1-1-1-1",
        "host_risk_object_type": "system",
        "host_risk_score": "0",
        "index": "notable",
        "linecount": "1",
        "priority": "unknown",
        "risk_score": "460",
        "rule_description": "Access - Brute Force Access Behavior Detected - Rule",
        "rule_name": "Access - Brute Force Access Behavior Detected - Rule",
        "rule_title": "Access - Brute Force Access Behavior Detected - Rule",
        "security_domain": "Access - Brute Force Access Behavior Detected - Rule",
        "severity": "unknown",
        "source": "Access - Brute Force Access Behavior Detected - Rule",
        "sourcetype": "stash",
        "splunk_server": "ip-1-1-1-1",
        "src": "1.1.1.1",
        "src_risk_object_type": "system",
        "src_risk_score": "460",
        "urgency": "low"
    },
    "Access - Excessive Failed Logins - Rule": {
        "_bkt": "notable~712~66D21DF4-F4FD-4886-A986-82E72ADCBFE9",
        "_cd": "712:21515",
        "_indextime": "1598460945",
        "_serial": "22",
        "_si": [
            "ip-1-1-1-1",
            "notable"
        ],
        "_sourcetype": "stash",
        "_time": "2020-08-26T09:55:45.000-07:00",
        "host": "ip-1-1-1-1",
        "host_risk_object_type": "system",
        "host_risk_score": "0",
        "index": "notable",
        "linecount": "1",
        "priority": "unknown",
        "risk_score": "380",
        "rule_description": "Access - Excessive Failed Logins - Rule",
        "rule_name": "Access - Excessive Failed Logins - Rule",
        "rule_title": "Access - Excessive Failed Logins - Rule",
        "security_domain": "Access - Excessive Failed Logins - Rule",
        "severity": "unknown",
        "source": "Access - Excessive Failed Logins - Rule",
        "sourcetype": "stash",
        "splunk_server": "ip-1-1-1-1",
        "src": "1.1.1.1",
        "src_risk_object_type": "system",
        "src_risk_score": "380",
        "urgency": "low"
=======
### splunk-kv-store-collection-create
***
Creates a new KV store table.


#### Base Command

`splunk-kv-store-collection-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kv_store_name | The name of the KV store collection. | Required | 
| app_name | The name of the Splunk application in which to create the KV store. The default is "search". | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!splunk-kv-store-collection-create app_name=search kv_store_name=demisto_store```

#### Human Readable Output

>KV store collection search created successfully

### splunk-kv-store-collection-config
***
Configures the KV store fields.


#### Base Command

`splunk-kv-store-collection-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kv_store_collection_name | The name of the KV store collection. | Required | 
| kv_store_fields | The list of names and value types to define the KV store collection scheme, e.g., id=number, name=string, address=string.<br/> | Required | 
| app_name | The name of the Splunk application that contains the KV store collection. The default is "search". | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!splunk-kv-store-collection-config app_name=search kv_store_collection_name=demisto_store kv_store_fields=addr=string```


#### Human Readable Output

>KV store collection search configured successfully

### splunk-kv-store-collection-add-entries
***
Adds objects to a KV store utilizing the batch-save API.


#### Base Command

`splunk-kv-store-collection-add-entries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kv_store_data | The data to add to the KV store collection, according to the collection JSON format, e.g., {"name": "Splunk HQ", "id": 123, "address": { "street": "250 Brannan Street", "city": "San Francisco", "state": "CA", "zip": "94107"}} | Required | 
| kv_store_collection_name | The name of the KV store collection. | Required | 
| indicator_path | The path to the indicator value in kv_store_data. | Optional | 
| app_name | The name of the Splunk application that contains the KV store collection. The default is "search". | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!splunk-kv-store-collection-add-entries app_name=search kv_store_collection_name=demisto_store kv_store_data="{\"addr\": \"0.0.0.0\"}" indicator_path=addr```


#### Human Readable Output

>Data added to demisto_store

### splunk-kv-store-collections-list
***
Lists all collections for the specified application.


#### Base Command

`splunk-kv-store-collections-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application in which to create the KV store. The default is "search". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.CollectionList | String | List of collections. | 


#### Command Example
```!splunk-kv-store-collections-list app_name=search```

#### Context Example
```
{
    "Splunk": {
        "CollectionList": [
            "autofocus_tags",
            "files"
        ]
    }
}
```

#### Human Readable Output

>list of collection names search
>| name |
>| --- |
>|autofocus_tags|
>|files|

### splunk-kv-store-collection-data-list
***
Lists all data within a specific KV store collection or collections.


#### Base Command

`splunk-kv-store-collection-data-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application that contains the KV store collection. The default is "search". | Required | 
| kv_store_collection_name | A comma-separated list of KV store collections. | Required | 
| limit | Maximum number of records to return. The default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.KVstoreData | Unknown | An array of collection names. Each collection name will have an array of values, e.g., Splunk.KVstoreData.&lt;colletion_name&gt; is a list of the data in the collection\). | 


#### Command Example
```!splunk-kv-store-collection-data-list app_name=search limit=3 kv_store_collection_name=demisto_store```

#### Context Example
```
{
    "Splunk": {
        "KVstoreData": {
            "demisto_store": [
                {
                    "_key": "5f4e2e9c097d9e6749453536",
                    "_user": "nobody",
                    "addr": "0.0.0.0"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### list of collection values demisto_store
>|_key|_user|addr|
>|---|---|---|
>| 5f4e2e9c097d9e6749453536 | nobody | 0.0.0.0 |


### splunk-kv-store-collection-data-delete
***
Deletes all data within the specified KV store collection or collections.


#### Base Command

`splunk-kv-store-collection-data-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application that contains the KV store collection. For example, "search"." | Required | 
| kv_store_collection_name | A comma-separated list of KV store collections. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!splunk-kv-store-collection-data-delete app_name=search kv_store_collection_name=demisto_store```

#### Human Readable Output

>The values of the demisto_store were deleted successfully

### splunk-kv-store-collection-delete
***
Deletes the specified KV store.


#### Base Command

`splunk-kv-store-collection-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application that contains the KV store. The default is "search". | Required | 
| kv_store_name | A comma-separated list of KV stores. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!splunk-kv-store-collection-delete app_name=search kv_store_name=demisto_store```


#### Human Readable Output

>The following KV store demisto_store were deleted successfully

### splunk-kv-store-collection-search-entry
***
Searches for specific objects in a store. Search can be basic key value or a full query.


#### Base Command

`splunk-kv-store-collection-search-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application that contains the KV store collection. The default is "search". | Required | 
| kv_store_collection_name | The name of the KV store collection | Required | 
| key | The key name to search in the store. If the query argument is used, this argument will be ignored. | Optional | 
| value | The value to search in the store. If the query argument is used, this argument will be ignored. | Optional | 
| query | Complex query to search in the store with operators such as "and", "or", "not", etc. For more information see the Splunk documentation: https://docs.splunk.com/Documentation/Splunk/8.0.3/RESTREF/RESTkvstore | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splunk.KVstoreData | Unknown | An array of collection names. Each collection name will have an array of values, e.g., Splunk.KVstoreData.&lt;colletion_name&gt; is a list of the data in the collection\). | 


#### Command Example
```!splunk-kv-store-collection-search-entry app_name=search kv_store_collection_name=demisto_store key=addr value=0.0.0.0```

#### Context Example
```
{
    "Splunk": {
        "KVstoreData": {
            "demisto_store": [
                {
                    "_key": "5f4e2e9c097d9e6749453536",
                    "_user": "nobody",
                    "addr": "0.0.0.0"
                }
            ]
        }
    }
}
```

## Additional Information
=======
#### Human Readable Output

>### list of collection values demisto_store
>|_key|_user|addr|
>|---|---|---|
>| 5f4e2e9c097d9e6749453536 | nobody | 0.0.0.0 |


### splunk-kv-store-collection-delete-entry
***
Deletes the specified object in store. Search can be basic key value or a full query.


#### Base Command

`splunk-kv-store-collection-delete-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the Splunk application that contains the KV store collection. The deafult is "search". | Required | 
| kv_store_collection_name | The name of the KV store collection. | Required | 
| indicator_path | The path to the indicator value in kv_store_data. | Optional | 
| key | The key name to search in the store. If the query argument is used, this argument will be ignored. | Optional | 
| value | The value to search in the store. If the query argument is used, this argument will be ignored. | Optional | 
| query | Complex query to search in the store with operators such as "and", "or", "not", etc.<br/>For more information see the Splunk documentation: https://docs.splunk.com/Documentation/Splunk/8.0.3/RESTREF/RESTkvstore | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!splunk-kv-store-collection-delete-entry app_name=search kv_store_collection_name=demisto_store key=addr value=0.0.0.0 indicator_path=addr```

#### Human Readable Output

>The values of the demisto_store were deleted successfully

## Aditional Information
To get the HEC Token
1. Go to the Splunk UI.
2. Under "Settings" -> "Data" -> "Data inputs".
![Screen Shot 2020-01-20 at 10 22 50](https://user-images.githubusercontent.com/45915502/72710123-0f296080-3b6f-11ea-9eb4-a3cebb1e8700.png)
3. Then click on "HTTP Event Collector".
4. Click on "New Token".
5. Add all the relevant details until done.


_For the HTTP Port number:_
Click on Global settings (in the http event collector page)
![Screen Shot 2020-01-20 at 10 27 25](https://user-images.githubusercontent.com/45915502/72710342-8d860280-3b6f-11ea-8d66-4d60303aba48.png)

The default port is 8088.

## Troubleshooting

In case you encounter HTTP errors (e.g. IncompleteRead), we suggest using Python requests handler.
