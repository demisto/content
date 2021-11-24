Use Azure Data Explorer integration to collect and analyze data inside clusters of Azure Data Explorer and manage search queries.
This integration was integrated and tested with version V1 of AzureDataExplorer.

## Configure Azure Data Explorer on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Data Explorer.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Cluster URL (e.g. https://help.kusto.windows.net) |  | True |
    | Application ID |  | True |
    | Client Activity Prefix | A customized prefix of the client activity identifier for the query execution. For example, for a prefix value of 'XSOAR-DataExplorer', the client activity ID will be in the format of:  'XSOAR-DataExplorer;&amp;lt;UUID&amp;gt;'. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-data-explorer-search-query-execute
***
Execute a KQL query against the given database inside a cluster. The Kusto query is a read-only request to process data and return results. To learn more about KQL go to https://docs.microsoft.com/en-us/azure/kusto/query/.


#### Base Command

`azure-data-explorer-search-query-execute`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | KQL search query to execute on given database. | Required | 
| database_name | The name of the database to execute the query on. | Required | 
| timeout | The timeout for the execution of search query on server side. The timeout is a float number in minutes that ranges from 0 to 60.| Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDataExplorer.SearchQueryResults.Query | String | The executed query on the given database. | 
| AzureDataExplorer.SearchQueryResults.ClientActivityID | String | The Client Activity ID. A unique identifier of the executed query. | 
| AzureDataExplorer.SearchQueryResults.PrimaryResults | Unknown | The results of the query execution. | 
| AzureDataExplorer.SearchQueryResults.Database | String | Database against query will be executed. | 


#### Command Example
```!azure-data-explorer-search-query-execute database_name=Samples query="StormEvents| limit 1"```

#### Context Example
```json
{
    "AzureDataExplorer": {
        "SearchQueryResults": {
            "ClientActivityID": "XSOAR-DataExplorer;759d43a9-cdc1-4882-8f8b-3e8d8a703f1e",
            "Database": "Samples",
            "PrimaryResults": [
                {
                    "BeginLat": 28.0393,
                    "BeginLocation": "MELBOURNE BEACH",
                    "BeginLon": -80.6048,
                    "DamageCrops": 0,
                    "DamageProperty": 0,
                    "DeathsDirect": 0,
                    "DeathsIndirect": 0,
                    "EndLat": 28.0393,
                    "EndLocation": "MELBOURNE BEACH",
                    "EndLon": -80.6048,
                    "EndTime": "2007-09-29T08:11:00",
                    "EpisodeId": 11091,
                    "EpisodeNarrative": "Showers and thunderstorms lingering along the coast produced waterspouts in Brevard County.",
                    "EventId": 61032,
                    "EventNarrative": "A waterspout formed in the Atlantic southeast of Melbourne Beach and briefly moved toward shore.",
                    "EventType": "Waterspout",
                    "InjuriesDirect": 0,
                    "InjuriesIndirect": 0,
                    "Source": "Trained Spotter",
                    "StartTime": "2007-09-29T08:11:00",
                    "State": "ATLANTIC SOUTH",
                    "StormSummary": {
                        "Details": {
                            "Description": "A waterspout formed in the Atlantic southeast of Melbourne Beach and briefly moved toward shore.",
                            "Location": "ATLANTIC SOUTH"
                        },
                        "EndTime": "2007-09-29T08:11:00.0000000Z",
                        "StartTime": "2007-09-29T08:11:00.0000000Z",
                        "TotalDamages": 0
                    }
                }
            ],
            "Query": "StormEvents| limit 1"
        }
    }
}
```

#### Human Readable Output

>### Results of executing search query with client activity ID: XSOAR-DataExplorer;759d43a9-cdc1-4882-8f8b-3e8d8a703f1e
>|Begin Lat|Begin Location|Begin Lon|Damage Crops|Damage Property|Deaths Direct|Deaths Indirect|End Lat|End Location|End Lon|End Time|Episode Id|Episode Narrative|Event Id|Event Narrative|Event Type|Injuries Direct|Injuries Indirect|Source|Start Time|State|Storm Summary|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 28.0393 | MELBOURNE BEACH | -80.6048 | 0 | 0 | 0 | 0 | 28.0393 | MELBOURNE BEACH | -80.6048 | 2007-09-29T08:11:00 | 11091 | Showers and thunderstorms lingering along the coast produced waterspouts in Brevard County. | 61032 | A waterspout formed in the Atlantic southeast of Melbourne Beach and briefly moved toward shore. | Waterspout | 0 | 0 | Trained Spotter | 2007-09-29T08:11:00 | ATLANTIC SOUTH | TotalDamages: 0<br/>StartTime: 2007-09-29T08:11:00.0000000Z<br/>EndTime: 2007-09-29T08:11:00.0000000Z<br/>Details: {"Description": "A waterspout formed in the Atlantic southeast of Melbourne Beach and briefly moved toward shore.", "Location": "ATLANTIC SOUTH"} |


### azure-data-explorer-search-query-list
***
List search queries that have reached a final state in the given database.  A database admin or database monitor can see any command that was invoked on their database. Other users can only see queries that were invoked by them.


#### Base Command

`azure-data-explorer-search-query-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| database_name | The name of the database to list the completed search queries. . | Required | 
| client_activity_id | The client activity ID property of search query. Use this to get a specific search query. | Optional | 
| limit | The maximum number of completed queries to return. Default is 50. | Optional | 
| page | The page number from which to start a search. Default is 1. | Optional | 
| page_size | The maximum number of completed queries to return per page. If this argument is not provided, an automatic pagination will be made accroding to the limit argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDataExplorer.SearchQuery.ClientActivityId | String | The client activity ID. A unique identifier of the query execution.   | 
| AzureDataExplorer.SearchQuery.Text | String | The search query text.  | 
| AzureDataExplorer.SearchQuery.Database | String | The name of the database that the search query run on.  | 
| AzureDataExplorer.SearchQuery.StartedOn | String | query execution start time in UTC.  | 
| AzureDataExplorer.SearchQuery.LastUpdatedOn | String | The last update time of the query. | 
| AzureDataExplorer.SearchQuery.Duration | Date | The search query runtime. | 
| AzureDataExplorer.SearchQuery.State | String | The search query state.  | 
| AzureDataExplorer.SearchQuery.RootActivityId | String | Root Activity ID. | 
| AzureDataExplorer.SearchQuery.User | String | The user who performed the query. | 
| AzureDataExplorer.SearchQuery.FailureReason | String | The reason for query failure. | 
| AzureDataExplorer.SearchQuery.TotalCpu | String | The total CPU clock time \(User mode \+ Kernel mode\) consumed by this query. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Memory.Hits | Number | The number of cache hits. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Memory.Misses | Number | The number of cache misses. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Disk.Hits | Number | The number of disk hits. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Disk.Misses | Number | The number of disk misses. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.Hot.HitBytes | Number | Shads hot hit bytes. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.Hot.MissBytes | Number | Shards hot cache misses. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.Hot.RetrieveBytes | Number | Shards hot cache retrieved bytes | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.Cold.HitBytes | Number | Shards cold cache hits. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.Cold.MissBytes | Number | Shards cold cache misses. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.Cold.RetrieveBytes | Number | Shards cold cache retrieved bytes. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.BypassBytes | Number | Shards cache bypass bytes. | 
| AzureDataExplorer.SearchQuery.Application | String | Application name that invoked the command. | 
| AzureDataExplorer.SearchQuery.MemoryPeak | Number | Memory peak. | 
| AzureDataExplorer.SearchQuery.ScannedExtentsStatistics.MinDataScannedTime | Date | Minimum data scan time. | 
| AzureDataExplorer.SearchQuery.ScannedExtentsStatistics.MaxDataScannedTime | Date | Maximum data scan time. | 
| AzureDataExplorer.SearchQuery.ScannedExtentsStatistics.TotalExtentsCount | Number | Total extent count. | 
| AzureDataExplorer.SearchQuery.ScannedExtentsStatistics.ScannedExtentsCount | Number | Scanned extent count. | 
| AzureDataExplorer.SearchQuery.ScannedExtentsStatistics.TotalRowsCount | Number | Total rows count. | 
| AzureDataExplorer.SearchQuery.ScannedExtentsStatistics.ScannedRowsCount | Number | Scanned rows count. | 
| AzureDataExplorer.SearchQuery.Principal | String | The principal that invoked the query. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.SecurityTokenPresent | Boolean | If true, the security token is present in the request. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.AuthorizationScheme | String | Authorization scheme. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.RequestHostName | String | Request hostname. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.LocalClusterName | String | The cluster name. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.OriginClusterName | String | Origin cluster name. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.api_version | String | API version. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.request_readonly | Boolean | If true, the request is read-only. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.servertimeout | Number | Server timeout value. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.servertimeoutorigin | String | Server timeout origin. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.query_datascope | Number | Query datascope. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.query_fanout_nodes_percent | Number | Query fanout nodes percent. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.query_fanout_threads_percent | Number | Query fanout threads percent. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.maxmemoryconsumptionperiterator | Number | Max memory consumption per iterator. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.max_memory_consumption_per_query_per_node | Number | Max memory consumption per query per node. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.truncationmaxsize | Number | Truncation max size. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.truncationmaxrecords | Number | Truncation max records. | 
| AzureDataExplorer.SearchQuery.ResultSetStatistics.TableCount | Number | Tables count. | 
| AzureDataExplorer.SearchQuery.ResultSetStatistics.TablesStatistics.RowCount | Number | Search query results' rows count. | 
| AzureDataExplorer.SearchQuery.ResultSetStatistics.TablesStatistics.TableSize | Number | Table size. | 
| AzureDataExplorer.SearchQuery.WorkloadGroup | String | Workload group. | 


#### Command Example
```!azure-data-explorer-search-query-list database_name=Samples limit=1```

#### Context Example
```json
{
    "AzureDataExplorer": {
        "SearchQuery": {
            "Application": "KusWeb",
            "CacheStatistics": {
                "Disk": {
                    "Hits": 0,
                    "Misses": 0
                },
                "Memory": {
                    "Hits": 0,
                    "Misses": 0
                },
                "Shards": {
                    "BypassBytes": 0,
                    "Cold": {
                        "HitBytes": 0,
                        "MissBytes": 0,
                        "RetrieveBytes": 0
                    },
                    "Hot": {
                        "HitBytes": 0,
                        "MissBytes": 0,
                        "RetrieveBytes": 0
                    }
                }
            },
            "ClientActivityId": "KustoWebV2;f1be2c7e-f810-437b-a1f8-f8bbbedf238d",
            "ClientRequestProperties": {
                "AuthorizationScheme": "Bearer",
                "LocalClusterName": "https://help.kusto.windows.net/",
                "Options": {
                    "api_version": "v2",
                    "max_memory_consumption_per_query_per_node": 2000000000,
                    "maxmemoryconsumptionperiterator": 5368709120,
                    "query_datascope": 1,
                    "query_fanout_nodes_percent": 100,
                    "query_fanout_threads_percent": 100,
                    "query_language": "csl",
                    "queryconsistency": "strongconsistency",
                    "request_app_name": "KusWeb",
                    "request_readonly": true,
                    "request_readonly_hardline": false,
                    "servertimeout": 600000000,
                    "truncationmaxrecords": 500000,
                    "truncationmaxsize": 67108864
                },
                "OriginClusterName": "https://help.kusto.windows.net/",
                "RequestHostName": "https://help.kusto.windows.net:443/",
                "SecurityTokenPresent": true
            },
            "Database": "Samples",
            "Duration": "0:00:00",
            "FailureReason": "[none]",
            "LastUpdatedOn": "2021-11-24T15:15:27",
            "MemoryPeak": 0,
            "Principal": "aaduser=xxx-xxxx-xxxx",
            "ResultSetStatistics": {
                "TableCount": 2,
                "TablesStatistics": [
                    {
                        "RowCount": 0,
                        "TableSize": 0
                    },
                    {
                        "RowCount": 2,
                        "TableSize": 1244
                    }
                ]
            },
            "RootActivityId": "2b9e0ec8-f6b0-407e-90b6-68eba3777564",
            "ScannedExtentsStatistics": {
                "MaxDataScannedTime": null,
                "MinDataScannedTime": null,
                "ScannedExtentsCount": 0,
                "ScannedRowsCount": 0,
                "TotalExtentsCount": 0,
                "TotalRowsCount": 0
            },
            "StartedOn": "2021-11-24T15:15:27",
            "State": "Completed",
            "Text": "set notruncation;\nCovid19",
            "TotalCpu": "0:00:00",
            "User": "dataExplorer@qmasterslabgmail.onmicrosoft.com",
            "WorkloadGroup": "default"
        }
    }
}
```

#### Human Readable Output

>### List of Completed Search Queries 
>Showing 0 to 1 records out of 134.
> 
>|Client Activity Id|User|Text|Database|Started On|Last Updated On|State|
>|---|---|---|---|---|---|---|
>| KustoWebV2;f1be2c7e-f810-437b-a1f8-f8bbbedf238d | dataExplorer@qmasterslabgmail.onmicrosoft.com | set notruncation;<br/>Covid19 | Samples | 2021-11-24T15:15:27 | 2021-11-24T15:15:27 | Completed |


### azure-data-explorer-running-search-query-list
***
List currently executing search queries in the given database. A database admin or database monitor can see any search query that was invoked on their database.
Other users can only see search queries that were invoked by them.


#### Base Command

`azure-data-explorer-running-search-query-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| database_name | Database name. | Required | 
| client_activity_id | The client activity ID property of search query. Use this to get a specific running search query. | Optional | 
| limit | The maximum number of running queries to return. Default is 50. | Optional | 
| page | The page number from which to start a search. Default is 1. | Optional | 
| page_size | The maximum number of running queries to return per page. If this argument is not provided, an automatic pagination will be made accroding to the limit argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDataExplorer.RunningSearchQuery.ClientActivityId | String | The client activity ID. A unique identifier of the query execution.   | 
| AzureDataExplorer.RunningSearchQuery.Text | String | The search query text.  | 
| AzureDataExplorer.RunningSearchQuery.Database | String | The name of the database that the search query run on.  | 
| AzureDataExplorer.RunningSearchQuery.StartedOn | Date | query execution start time in UTC.  | 
| AzureDataExplorer.RunningSearchQuery.LastUpdatedOn | String | The last update time of the query. | 
| AzureDataExplorer.RunningSearchQuery.Duration | String | The search query runtime. | 
| AzureDataExplorer.RunningSearchQuery.State | String | The search query state.  | 
| AzureDataExplorer.RunningSearchQuery.RootActivityId | String | Root Activity ID. | 
| AzureDataExplorer.RunningSearchQuery.User | String | The user who performed the query. | 
| AzureDataExplorer.RunningSearchQuery.FailureReason | String | The reason for query failure. | 
| AzureDataExplorer.RunningSearchQuery.TotalCpu | String | The total CPU clock time \(User mode \+ Kernel mode\) consumed by this query. | 
| AzureDataExplorer.RunningSearchQuery.CacheStatistics | Unknown | The cache statistics. | 
| AzureDataExplorer.RunningSearchQuery.Application | Unknown | Application name that invoked the command. | 
| AzureDataExplorer.RunningSearchQuery.MemoryPeak | Number | Memory peak. | 
| AzureDataExplorer.RunningSearchQuery.ScannedExtentsStatistics | Unknown | Scanned extent count. | 
| AzureDataExplorer.RunningSearchQuery.Principal | String | The principal that invoked the query. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.SecurityTokenPresent | Boolean | If true, the security token is present in the request. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.AuthorizationScheme | String | Authorization scheme. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.RequestHostName | String | Request hostname. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.LocalClusterName | String | The cluster name. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.OriginClusterName | String | Origin cluster name. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.api_version | String | API version. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.request_readonly | Boolean | If true, the request is read-only. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.servertimeout | Number | Server timeout value. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.servertimeoutorigin | String | Server timeout origin. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.query_datascope | Number | Query datascope. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.query_fanout_nodes_percent | Number | Query fanout nodes percent. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.query_fanout_threads_percent | Number | Query fanout threads percent. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.maxmemoryconsumptionperiterator | Number | Max memory consumption per iterator. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.max_memory_consumption_per_query_per_node | Number | Max memory consumption per query per node. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.truncationmaxsize | Number | Truncation max size. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.truncationmaxrecords | Number | Truncation max records. | 
| AzureDataExplorer.RunningSearchQuery.ResultSetStatistics | Unknown | Result set statistics. | 
| AzureDataExplorer.RunningSearchQuery.WorkloadGroup | String | Workload group. | 


#### Command Example
```!azure-data-explorer-running-search-query-list database_name=Samples limit=1```

#### Context Example
```json
{
    "AzureDataExplorer": {
        "RunningSearchQuery": {
            "Application": "KusWeb",
            "CacheStatistics": "null",
            "ClientActivityId": "KustoWebV2;c6ff3e99-d2cb-4a3e-ab05-955ae383a7c6",
            "ClientRequestProperties": "{\"SecurityTokenPresent\":true,\"AuthorizationScheme\":\"Bearer\",\"RequestHostName\":\"https://help.kusto.windows.net:443/\",\"LocalClusterName\":\"https://help.kusto.windows.net/\",\"OriginClusterName\":\"https://help.kusto.windows.net/\",\"Options\":{\"servertimeout\":600000000,\"queryconsistency\":\"strongconsistency\",\"query_language\":\"csl\",\"request_readonly\":true,\"request_readonly_hardline\":false,\"api_version\":\"v2\",\"request_app_name\":\"KusWeb\",\"query_datascope\":1,\"query_fanout_nodes_percent\":100,\"query_fanout_threads_percent\":100,\"maxmemoryconsumptionperiterator\":5368709120,\"max_memory_consumption_per_query_per_node\":2000000000,\"truncationmaxsize\":67108864,\"truncationmaxrecords\":500000}}",
            "Database": "Samples",
            "Duration": "0:00:00",
            "FailureReason": "",
            "LastUpdatedOn": "2021-11-24T15:16:34",
            "MemoryPeak": 0,
            "Principal": "aaduser=xxx-xxxx-xxxx",
            "ResultSetStatistics": "null",
            "RootActivityId": "c8233607-30a9-4cc0-9c54-ec716e5fc246",
            "ScannedExtentsStatistics": "null",
            "StartedOn": "2021-11-24T15:16:34",
            "State": "InProgress",
            "Text": "set notruncation;\nCovid19_Bing",
            "TotalCpu": "0:00:00",
            "User": "dataExplorer@qmasterslabgmail.onmicrosoft.com",
            "WorkloadGroup": "default"
        }
    }
}
```

#### Human Readable Output

>### List of Currently running Search Queries 
>Showing 0 to 1 records out of 2.
> 
>|Client Activity Id|User|Text|Database|Started On|Last Updated On|State|
>|---|---|---|---|---|---|---|
>| KustoWebV2;c6ff3e99-d2cb-4a3e-ab05-955ae383a7c6 | dataExplorer@qmasterslabgmail.onmicrosoft.com | set notruncation;<br/>Covid19_Bing | Samples | 2021-11-24T15:16:34 | 2021-11-24T15:16:34 | InProgress |


### azure-data-explorer-running-search-query-cancel
***
Starts a best-effort attempt to cancel a specific running search query in the specified database.


#### Base Command

`azure-data-explorer-running-search-query-cancel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| client_activity_id | The client activity ID of the query to delete. | Required | 
| database_name | Database name. | Required | 
| reason | Describe the reason for canceling the running query. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDataExplorer.CanceledSearchQuery.RunningQueryCanceled | Boolean | If true, the query was successfully canceled. | 
| AzureDataExplorer.CanceledSearchQuery.ClientRequestId | String | Client Activity ID of the cancelled query. | 
| AzureDataExplorer.CanceledSearchQuery.ReasonPhrase | String | Cancelation reason. | 


#### Command Example
```!azure-data-explorer-running-search-query-cancel database_name=Samples client_activity_id=xxxx-xxxxx-xxxxx```

#### Context Example
```json
{
    "AzureDataExplorer": {
        "CanceledSearchQuery": {
            "ClientRequestId": "xxxx-xxxxx-xxxxx",
            "ReasonPhrase": "None",
            "RunningQueryCanceled": false
        }
    }
}
```

#### Human Readable Output

>### Canceled Search Query xxxx-xxxxx-xxxxx
>|Client Request Id|Reason Phrase|Running Query Canceled|
>|---|---|---|
>| xxxx-xxxxx-xxxxx | None | false |
