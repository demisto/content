# Azure Data Explorer

Use Azure Data Explorer integration to collect and analyze data inside clusters of Azure Data Explorer and manage search queries.
This integration was integrated and tested with version V1 of AzureDataExplorer.

## Configure Azure Data Explorer on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Data Explorer.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Cluster URL (e.g. https://help.kusto.windows.net) |  | True |
    | Application ID |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Client Activity Prefix | A customized prefix of the client activity identifier for the query execution. For example, for a prefix value of 'XSOAR-DataExplorer', the client activity ID will be in the format of:  'XSOAR-DataExplorer;&amp;lt;UUID&amp;gt;'. | True |

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
| timeout | The timeout on the search query execution on server side. The timeout is in range of 1 minute to 60 minutes. Default value is 5. . Default is 5. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDataExplorer.SearchQueryResults.Query | String | The executed query on the given database. | 
| AzureDataExplorer.SearchQueryResults.ClientActivityID | String | The Client Activity ID. A unique identifier of the executed query. | 
| AzureDataExplorer.SearchQueryResults.PrimaryResults | Unknown | The results of the query execution. | 


#### Command Example
```!azure-data-explorer-search-query-execute database_name=Samples query="StormEvents| limit 2"```

#### Context Example
```json
{
    "AzureDataExplorer": {
        "SearchQueryResults": {
            "ClientActivityID": "XSOAR-DataExplorer1;a9ba2416-6362-4f91-aa59-e8c8918d9b97",
            "Query": "StormEvents| limit 2",
            "Results": [
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
                },
                {
                    "BeginLat": 29.28,
                    "BeginLocation": "ORMOND BEACH",
                    "BeginLon": -81.05,
                    "DamageCrops": 0,
                    "DamageProperty": 0,
                    "DeathsDirect": 0,
                    "DeathsIndirect": 0,
                    "EndLat": 29.02,
                    "EndLocation": "NEW SMYRNA BEACH",
                    "EndLon": -80.93,
                    "EndTime": "2007-09-19T18:00:00",
                    "EpisodeId": 11074,
                    "EpisodeNarrative": "Thunderstorms lingered over Volusia County.",
                    "EventId": 60904,
                    "EventNarrative": "As much as 9 inches of rain fell in a 24-hour period across parts of coastal Volusia County.",
                    "EventType": "Heavy Rain",
                    "InjuriesDirect": 0,
                    "InjuriesIndirect": 0,
                    "Source": "Trained Spotter",
                    "StartTime": "2007-09-18T20:00:00",
                    "State": "FLORIDA",
                    "StormSummary": {
                        "Details": {
                            "Description": "As much as 9 inches of rain fell in a 24-hour period across parts of coastal Volusia County.",
                            "Location": "FLORIDA"
                        },
                        "EndTime": "2007-09-19T18:00:00.0000000Z",
                        "StartTime": "2007-09-18T20:00:00.0000000Z",
                        "TotalDamages": 0
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results of executing search query with client activity ID: XSOAR-DataExplorer1;a9ba2416-6362-4f91-aa59-e8c8918d9b97
>|BeginLat|BeginLocation|BeginLon|DamageCrops|DamageProperty|DeathsDirect|DeathsIndirect|EndLat|EndLocation|EndLon|EndTime|EpisodeId|EpisodeNarrative|EventId|EventNarrative|EventType|InjuriesDirect|InjuriesIndirect|Source|StartTime|State|StormSummary|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 28.0393 | MELBOURNE BEACH | -80.6048 | 0 | 0 | 0 | 0 | 28.0393 | MELBOURNE BEACH | -80.6048 | 2007-09-29T08:11:00 | 11091 | Showers and thunderstorms lingering along the coast produced waterspouts in Brevard County. | 61032 | A waterspout formed in the Atlantic southeast of Melbourne Beach and briefly moved toward shore. | Waterspout | 0 | 0 | Trained Spotter | 2007-09-29T08:11:00 | ATLANTIC SOUTH | TotalDamages: 0<br/>StartTime: 2007-09-29T08:11:00.0000000Z<br/>EndTime: 2007-09-29T08:11:00.0000000Z<br/>Details: {"Description": "A waterspout formed in the Atlantic southeast of Melbourne Beach and briefly moved toward shore.", "Location": "ATLANTIC SOUTH"} |
>| 29.28 | ORMOND BEACH | -81.05 | 0 | 0 | 0 | 0 | 29.02 | NEW SMYRNA BEACH | -80.93 | 2007-09-19T18:00:00 | 11074 | Thunderstorms lingered over Volusia County. | 60904 | As much as 9 inches of rain fell in a 24-hour period across parts of coastal Volusia County. | Heavy Rain | 0 | 0 | Trained Spotter | 2007-09-18T20:00:00 | FLORIDA | TotalDamages: 0<br/>StartTime: 2007-09-18T20:00:00.0000000Z<br/>EndTime: 2007-09-19T18:00:00.0000000Z<br/>Details: {"Description": "As much as 9 inches of rain fell in a 24-hour period across parts of coastal Volusia County.", "Location": "FLORIDA"} |


### azure-data-explorer-search-query-list
***
List search queries that have reached a final state in the given database. 
A database admin or database monitor can see any command that was invoked
on their database. Other users can only see queries that were invoked by them.


#### Base Command

`azure-data-explorer-search-query-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| database_name | The name of the database to list the completed search queries. . | Required | 
| page | The page number from which to start a search. Default value is 1. Default is 1. | Optional | 
| limit | The maximum number of completed queries to return. Default is 50.. Default value is 50. Default is 50. | Optional | 
| client_activity_id | The client activity ID property of search query. Use this to get a specific search query. | Optional | 


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
| AzureDataExplorer.SearchQuery.ClientRequestProperties.SecurityTokenPresent | Boolean | Security token present. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.AuthorizationScheme | String | Authorization scheme. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.RequestHostName | String | Request hostname. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.LocalClusterName | String | The cluster name. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.OriginClusterName | String | Origin cluster name. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.api_version | String | API version. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.request_readonly | Boolean | Request readonly. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.servertimeout | Number | Server timeout option. | 
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
```!azure-data-explorer-search-query-list database_name=Samples page=1 limit=2```

#### Context Example
```json
{
    "AzureDataExplorer": {
        "SearchQuery": [
            {
                "Application": "",
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
                            "HitBytes": 517324,
                            "MissBytes": 0,
                            "RetrieveBytes": 0
                        }
                    }
                },
                "ClientActivityId": "XSOAR-DataExplorer1;30ab0069-c546-442d-ade6-d007ea53525b",
                "ClientRequestProperties": {
                    "AuthorizationScheme": "Bearer",
                    "LocalClusterName": "https://help.kusto.windows.net/",
                    "Options": {
                        "api_version": "v1",
                        "max_memory_consumption_per_query_per_node": 2000000000,
                        "maxmemoryconsumptionperiterator": 5368709120,
                        "query_datascope": 1,
                        "query_fanout_nodes_percent": 100,
                        "query_fanout_threads_percent": 100,
                        "request_readonly": true,
                        "servertimeout": 3000000000,
                        "truncationmaxrecords": 500000,
                        "truncationmaxsize": 67108864
                    },
                    "OriginClusterName": "https://help.kusto.windows.net/",
                    "RequestHostName": "https://help.kusto.windows.net:443/",
                    "SecurityTokenPresent": true
                },
                "Database": "Samples",
                "Duration": "0:00:00.015631",
                "FailureReason": "[none]",
                "LastUpdatedOn": "2021-11-03T15:33:18",
                "MemoryPeak": 1266368,
                "Principal": "aaduser=0cd1dcb9-3fa1-4470-b5f9-c9f2574a0c4d;0dd6c060-d39a-4e06-873c-48a43c2e24dd",
                "ResultSetStatistics": {
                    "TableCount": 1,
                    "TablesStatistics": [
                        {
                            "RowCount": 2,
                            "TableSize": 1118
                        }
                    ]
                },
                "RootActivityId": "d60b3baf-c6db-43ed-9e32-bfdc8efff8d9",
                "ScannedExtentsStatistics": {
                    "MaxDataScannedTime": "2016-03-17T08:24:02.6259906Z",
                    "MinDataScannedTime": "2016-03-17T08:24:02.6259906Z",
                    "ScannedExtentsCount": 1,
                    "ScannedRowsCount": 2,
                    "TotalExtentsCount": 1,
                    "TotalRowsCount": 59066
                },
                "StartedOn": "2021-11-03T15:33:18",
                "State": "Completed",
                "Text": "StormEvents| limit 2",
                "TotalCpu": "0:00:00",
                "User": "dataExplorer@qmasterslabgmail.onmicrosoft.com",
                "WorkloadGroup": "default"
            },
            {
                "Application": "",
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
                            "HitBytes": 517324,
                            "MissBytes": 0,
                            "RetrieveBytes": 0
                        }
                    }
                },
                "ClientActivityId": "XSOAR-DataExplorer1;5e813139-e819-48be-946a-0c325de42d68",
                "ClientRequestProperties": {
                    "AuthorizationScheme": "Bearer",
                    "LocalClusterName": "https://help.kusto.windows.net/",
                    "Options": {
                        "api_version": "v1",
                        "max_memory_consumption_per_query_per_node": 2000000000,
                        "maxmemoryconsumptionperiterator": 5368709120,
                        "query_datascope": 1,
                        "query_fanout_nodes_percent": 100,
                        "query_fanout_threads_percent": 100,
                        "request_readonly": true,
                        "servertimeout": 3000000000,
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
                "LastUpdatedOn": "2021-11-03T14:04:41",
                "MemoryPeak": 524384,
                "Principal": "aaduser=0cd1dcb9-3fa1-4470-b5f9-c9f2574a0c4d;0dd6c060-d39a-4e06-873c-48a43c2e24dd",
                "ResultSetStatistics": {
                    "TableCount": 1,
                    "TablesStatistics": [
                        {
                            "RowCount": 2,
                            "TableSize": 1118
                        }
                    ]
                },
                "RootActivityId": "2c3ab6a1-bdd8-4e8c-87f4-494418b156d8",
                "ScannedExtentsStatistics": {
                    "MaxDataScannedTime": "2016-03-17T08:24:02.6259906Z",
                    "MinDataScannedTime": "2016-03-17T08:24:02.6259906Z",
                    "ScannedExtentsCount": 1,
                    "ScannedRowsCount": 2,
                    "TotalExtentsCount": 1,
                    "TotalRowsCount": 59066
                },
                "StartedOn": "2021-11-03T14:04:41",
                "State": "Completed",
                "Text": "StormEvents| limit 2",
                "TotalCpu": "0:00:00",
                "User": "dataExplorer@qmasterslabgmail.onmicrosoft.com",
                "WorkloadGroup": "default"
            }
        ]
    }
}
```

#### Human Readable Output

>### List of Completed Search Queries 
>Showing page 1 out of 106 total pages. Current page size: 2.
> 
>|Client Activity Id|User|Text|Database|Started On|Last Updated On|State|
>|---|---|---|---|---|---|---|
>| XSOAR-DataExplorer1;30ab0069-c546-442d-ade6-d007ea53525b | dataExplorer@qmasterslabgmail.onmicrosoft.com | StormEvents\| limit 2 | Samples | 2021-11-03T15:33:18 | 2021-11-03T15:33:18 | Completed |
>| XSOAR-DataExplorer1;5e813139-e819-48be-946a-0c325de42d68 | dataExplorer@qmasterslabgmail.onmicrosoft.com | StormEvents\| limit 2 | Samples | 2021-11-03T14:04:41 | 2021-11-03T14:04:41 | Completed |


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
| page | The page number from which to start a search. Default is 1. | Optional | 
| limit | The maximum number of running queries to return. Default is 50. | Optional | 
| client_activity_id | The client activity ID property of search query. Use this to get a specific running search query. | Optional | 


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
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.SecurityTokenPresent | Boolean | Security token present. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.AuthorizationScheme | String | Authorization scheme. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.RequestHostName | String | Request hostname. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.LocalClusterName | String | The cluster name. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.OriginClusterName | String | Origin cluster name. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.api_version | String | API version. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.request_readonly | Boolean | Request readonly. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.servertimeout | Number | Server timeout option. | 
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
```!azure-data-explorer-running-search-query-list database_name=Samples page=1 limit=2```


#### Context Example
```json
{
    "AzureDataExplorer": {
        "RunningSearchQuery": {
            "Application": "KusWeb",
            "CacheStatistics": "null",
            "ClientActivityId": "KustoWebV2;cd28e48a-4b12-4269-afb6-9b338f59d6a3",
            "ClientRequestProperties": "{\"SecurityTokenPresent\":true,\"AuthorizationScheme\":\"Bearer\",\"RequestHostName\":\"https://help.kusto.windows.net:443/\",\"LocalClusterName\":\"https://help.kusto.windows.net/\",\"OriginClusterName\":\"https://help.kusto.windows.net/\",\"Options\":{\"servertimeout\":600000000,\"queryconsistency\":\"strongconsistency\",\"query_language\":\"csl\",\"request_readonly\":true,\"request_readonly_hardline\":false,\"api_version\":\"v2\",\"request_app_name\":\"KusWeb\",\"query_datascope\":1,\"query_fanout_nodes_percent\":100,\"query_fanout_threads_percent\":100,\"maxmemoryconsumptionperiterator\":5368709120,\"max_memory_consumption_per_query_per_node\":2000000000,\"truncationmaxsize\":67108864,\"truncationmaxrecords\":500000}}",
            "Database": "Samples",
            "Duration": "0:00:00",
            "FailureReason": "",
            "LastUpdatedOn": "2021-11-04T15:22:44",
            "MemoryPeak": 0,
            "Principal": "aaduser=0cd1dcb9-3fa1-4470-b5f9-c9f2574a0c4d;0dd6c060-d39a-4e06-873c-48a43c2e24dd",
            "ResultSetStatistics": "null",
            "RootActivityId": "c41c41df-5988-46f2-a7e0-b80568b31707",
            "ScannedExtentsStatistics": "null",
            "StartedOn": "2021-11-04T15:22:44",
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
>Showing page 1 out of 1 total pages. Current page size: 2.
> 
>|Client Activity Id|User|Text|Database|Started On|Last Updated On|State|
>|---|---|---|---|---|---|---|
>| KustoWebV2;cd28e48a-4b12-4269-afb6-9b338f59d6a3 | dataExplorer@qmasterslabgmail.onmicrosoft.com | set notruncation;<br/>Covid19_Bing | Samples | 2021-11-04T15:22:44 | 2021-11-04T15:22:44 | InProgress |


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
| AzureDataExplorer.CanceledSearchQuery.RunningQueryCanceled | Boolean | True if the query was successfuly canceled. Otherwise false. | 
| AzureDataExplorer.CanceledSearchQuery.ClientRequestId | String | Client Activity ID of the cancelled query. | 
| AzureDataExplorer.CanceledSearchQuery.ReasonPhrase | String | Cancelation reason. | 


#### Command Example
```!azure-data-explorer-running-search-query-cancel database_name=Samples client_activity_id=KustoWebV2;45c5b88b-5fc5-4fb7-8665-12f67c8b136a```

#### Context Example
```json
{
    "AzureDataExplorer": {
        "CancelledSearchQuery": {
            "ClientRequestId": "KustoWebV2;45c5b88b-5fc5-4fb7-8665-12f67c8b136a",
            "ReasonPhrase": "None",
            "RunningQueryCanceled": false
        }
    }
}
```

#### Human Readable Output

>### Canceled Search Query KustoWebV2;45c5b88b-5fc5-4fb7-8665-12f67c8b136a
>|Client Request Id|Reason Phrase|Running Query Canceled|
>|---|---|---|
>| KustoWebV2;45c5b88b-5fc5-4fb7-8665-12f67c8b136a | None | false |
