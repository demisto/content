Use the Azure Data Explorer integration to collect and analyze data inside Azure Data Explorer clusters, and to manage search queries.
This integration was integrated and tested with version V1 of AzureDataExplorer.

# Authorization

In order to connect to the Azure Data Explorer using either Cortex XSOAR Azure App or the Self-Deployed Azure App, use one of the following methods:

1. *Authorization Code Flow* (Recommended).
2. *Device Code Flow*.
3. *Client Credentials Flow*.

## Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.
To add the registration, refer to the following [Microsoft article](https://learn.microsoft.com/en-us/defender-xdr/api-create-app-web?view=o365-worldwide) steps 1-8.

### Required permissions

- Azure Data Explorer - permission `user_impersonation` of type Delegated.
- Microsoft Graph - permission `offline_access` of type Delegated.

To add a permission:

1. Navigate to **Azure Poral** > **Home** > **App registrations**.
2. Search for your app under 'all applications'.
3. Click **API permissions** > **Add permission**.
4.  Search for the specific Microsoft API and select the specific permission of type Delegated.

### Authentication Using the Authorization Code Flow (recommended)

1. In the *Authentication Type* field, select the **Authorization Code** option.
2. In the *Application ID* field, enter your Client/Application ID. 
3. In the *Client Secret* field, enter your Client Secret.
4. In the *Tenant ID* field, enter your Tenant ID .
5. In the *Application redirect URI* field, enter your Application redirect URI.
6. Save the instance.
7. Run the `!azure-data-explorer-generate-login-url` command in the War Room and follow the instruction.
8. Save the instance.
   
### Authentication Using the Device Code Flow

Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Azure Data Explorer with Cortex XSOAR.

1. Fill in the required parameters.
2. In the *Authentication Type* field, select the **Device Code** option.
3. Run the ***!azure-data-explorer-auth-start*** command.
4. Follow the instructions that appear.
5. Run the ***!azure-data-explorer-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (a9ce8db2-847a-46af-9bfb-725d8a8d3c53).

### Authentication Using the Client Credentials Flow

1. Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)

   *Note:* In the *Select members* section, assign the application you created earlier.

2. To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:
   a. In the *Authentication Type* field, select the **Client Credentials** option.
   b. In the *Application ID* field, enter your Client/Application ID.
   e. In the *Tenant ID* field, enter your Tenant ID .
   f. In the *Client Secret* field, enter your Client Secret.
   g. Click **Test** to validate the URLs, token, and connection
   h. Save the instance.


## Configure Azure Data Explorer in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Cluster URL (e.g. https://help.kusto.windows.net) |  | True |
| Application ID |  | True |
| Client Activity Prefix | A customized prefix of the client activity identifier for the query execution. For example, for a prefix value of 'XSOAR-DataExplorer', the client activity ID will be in the format of:  'XSOAR-DataExplorer;&amp;lt;UUID&amp;gt;'. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Authentication Type | Type of authentication - could be Authorization Code Flow \(recommended\), Device Code Flow or Client Credentials Flow. | False |
| Tenant ID | For Authorization Code or Client Credentials Flows. | False |
| Client Secret | For Authorization Code or Client Credentials Flows. | False |
| Application redirect URI (for Authorization Code mode) |  | False |
| Authorization code | for Authorization Code mode - received from the authorization step. see Detailed Instructions \(?\) section | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-data-explorer-search-query-execute
***
Execute a Kusto Query Language (KQL) query against the given database inside a cluster. The Kusto query is a read-only request to process data and return results. To learn more about KQL go to https://docs.microsoft.com/en-us/azure/kusto/query/.


#### Base Command

`azure-data-explorer-search-query-execute`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Kusto Query Language (KQL) search query to execute on given database. | Required | 
| database_name | The name of the database to execute the query on. | Required | 
| timeout | The timeout for the execution of the search query on the server side. The timeout is a float number in minutes that ranges from 0 to 60. Default is 5. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDataExplorer.SearchQueryResults.Query | String | The executed query on the given database. | 
| AzureDataExplorer.SearchQueryResults.ClientActivityID | String | The Client Activity ID. A unique identifier of the executed query. | 
| AzureDataExplorer.SearchQueryResults.PrimaryResults | Unknown | The results of the query execution. | 
| AzureDataExplorer.SearchQueryResults.Database | String | The database against which the query will be executed. | 


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
List search queries that have reached a final state in the given database.  A database admin or database monitor can see any command that was invoked on their database. Other users can only see queries that they themselves invoked.


#### Base Command

`azure-data-explorer-search-query-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| database_name | The name of the database from which to list the completed search queries. . | Required | 
| client_activity_id | The client activity ID property of the search query. Use this value to get a specific search query. | Optional | 
| limit | The maximum number of completed queries to return. Default is 50. | Optional | 
| page | The page number from which to start a search. Default is 1. | Optional | 
| page_size | The maximum number of completed queries to return per page. If this argument is not provided, an automatic pagination will be made according to the limit argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDataExplorer.SearchQuery.ClientActivityId | String | The client activity ID. A unique identifier of the query execution. | 
| AzureDataExplorer.SearchQuery.Text | String | The search query text. | 
| AzureDataExplorer.SearchQuery.Database | String | The name of the database that the search query is run on. | 
| AzureDataExplorer.SearchQuery.StartedOn | Date | The query execution start time in UTC.  | 
| AzureDataExplorer.SearchQuery.LastUpdatedOn | Date | The last update time of the query. | 
| AzureDataExplorer.SearchQuery.Duration | Date | The search query runtime. | 
| AzureDataExplorer.SearchQuery.State | String | The search query state. | 
| AzureDataExplorer.SearchQuery.RootActivityId | String | The root activity ID. | 
| AzureDataExplorer.SearchQuery.User | String | The user who performed the query. | 
| AzureDataExplorer.SearchQuery.FailureReason | String | The reason for query failure. | 
| AzureDataExplorer.SearchQuery.TotalCpu | String | The total CPU clock time \(User mode \+ Kernel mode\) consumed by this query. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Memory.Hits | Number | The number of cache hits. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Memory.Misses | Number | The number of cache misses. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Disk.Hits | Number | The number of disk hits. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Disk.Misses | Number | The number of disk misses. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.Hot.HitBytes | Number | The amount of data \(in bytes\) which was found in the hot data cache of the table's extents, during the search query execution. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.Hot.MissBytes | Number | The amount of data \(in bytes\) which was not found in the hot data cache of the table's extents, during the search query execution. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.Hot.RetrieveBytes | Number | The amount of data \(in bytes\) that was retrieved from hot data cache of the table's extents, during the search query execution. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.Cold.HitBytes | Number | The amount of data \(in bytes\) which was found in the cold data cache of the table's extents, during the search query execution. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.Cold.MissBytes | Number | The amount of data \(in bytes\) which was not found in the cold data cache of the table's extents, during the search query execution. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.Cold.RetrieveBytes | Number | The amount of data \(in bytes\) that was retrieved from cold data cache during the search query execution. | 
| AzureDataExplorer.SearchQuery.CacheStatistics.Shards.BypassBytes | Number | The amount of data \(in bytes\) that was bypassed \(reloaded\) in the cache of the table's extents during the search query execution. | 
| AzureDataExplorer.SearchQuery.Application | String | The application name that invoked the command. | 
| AzureDataExplorer.SearchQuery.MemoryPeak | Number | The peak memory usage of the query execution. | 
| AzureDataExplorer.SearchQuery.ScannedExtentsStatistics.MinDataScannedTime | Date | The minimum data scan time. | 
| AzureDataExplorer.SearchQuery.ScannedExtentsStatistics.MaxDataScannedTime | Date | The maximum data scan time. | 
| AzureDataExplorer.SearchQuery.ScannedExtentsStatistics.TotalExtentsCount | Number | The total number of extents which were used during the query execution. | 
| AzureDataExplorer.SearchQuery.ScannedExtentsStatistics.ScannedExtentsCount | Number | The number of extents which were scanned during the query execution. | 
| AzureDataExplorer.SearchQuery.ScannedExtentsStatistics.TotalRowsCount | Number | The total row count of extents which were used during the query execution. | 
| AzureDataExplorer.SearchQuery.ScannedExtentsStatistics.ScannedRowsCount | Number | The number of scanned rows of an extent during query execution. | 
| AzureDataExplorer.SearchQuery.Principal | String | The principal that invoked the query. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.SecurityTokenPresent | Boolean | Whether the security token is present in the request or not. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.AuthorizationScheme | String | The authorization scheme. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.RequestHostName | String | The hostname of the request. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.LocalClusterName | String | The cluster name. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.OriginClusterName | String | The origin cluster name. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.api_version | String | The API version. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.request_readonly | Boolean | Whether the request is read-only or not. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.servertimeout | Number | The server timeout value. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.servertimeoutorigin | String | The server timeout origin. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.query_datascope | Number | The query datascope. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.query_fanout_nodes_percent | Number | The percentage of the query nodes in the cluster to use per subquery distribution operation. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.query_fanout_threads_percent | Number | The percentage of CPUs the cluster will assign on each node. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.maxmemoryconsumptionperiterator | Number | The maximum amount of memory that a single query plan result set iterator can hold. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.max_memory_consumption_per_query_per_node | Number | The maximum amount of memory that can be used on a single node for a specific query. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.truncationmaxsize | Number | The maximum overall data size returned by the query, in bytes. | 
| AzureDataExplorer.SearchQuery.ClientRequestProperties.Options.truncationmaxrecords | Number | The maximum number of records returned by the query. | 
| AzureDataExplorer.SearchQuery.ResultSetStatistics.TableCount | Number | The number of tables that were retrieved following search query execution. | 
| AzureDataExplorer.SearchQuery.ResultSetStatistics.TablesStatistics.RowCount | Number | The row count of the table retrieved following search query execution. | 
| AzureDataExplorer.SearchQuery.ResultSetStatistics.TablesStatistics.TableSize | Number | The total size in bytes of the table retrieved following search query execution. | 
| AzureDataExplorer.SearchQuery.WorkloadGroup | String | The workload group which the query was assigned to. The query is executed using the policies assigned to the workload group. There are two pre-defined workload groups \(internal and default\) and up to 10 custom workload groups which may be defined at the cluster level. | 


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
Other users can only see search queries that they themselves invoked.


#### Base Command

`azure-data-explorer-running-search-query-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| database_name | The database name. | Required | 
| client_activity_id | The client activity ID property of the search query. Use this to get a specific running search query. | Optional | 
| limit | The maximum number of running queries to return. Default is 50. | Optional | 
| page | The page number from which to start a search. Default is 1. | Optional | 
| page_size | The maximum number of running queries to return per page. If this argument is not provided, an automatic pagination will be made according to the limit argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDataExplorer.RunningSearchQuery.ClientActivityId | String | The client activity ID. A unique identifier of the query execution.   | 
| AzureDataExplorer.RunningSearchQuery.Text | String | The search query text.  | 
| AzureDataExplorer.RunningSearchQuery.Database | String | The name of the database that the search query is run on.  | 
| AzureDataExplorer.RunningSearchQuery.StartedOn | Date | The query execution start time in UTC.  | 
| AzureDataExplorer.RunningSearchQuery.LastUpdatedOn | String | The last update time of the query. | 
| AzureDataExplorer.RunningSearchQuery.Duration | Date | The search query runtime duration. | 
| AzureDataExplorer.RunningSearchQuery.State | String | The search query state.  | 
| AzureDataExplorer.RunningSearchQuery.RootActivityId | String | The root activity ID. | 
| AzureDataExplorer.RunningSearchQuery.User | String | The user who performed the query. | 
| AzureDataExplorer.RunningSearchQuery.FailureReason | String | The reason for query failure. | 
| AzureDataExplorer.RunningSearchQuery.TotalCpu | String | The total CPU clock time \(User mode \+ Kernel mode\) consumed by this query. | 
| AzureDataExplorer.RunningSearchQuery.CacheStatistics | Unknown | The cache statistics. | 
| AzureDataExplorer.RunningSearchQuery.Application | String | The application name that invoked the command. | 
| AzureDataExplorer.RunningSearchQuery.MemoryPeak | Number | The peak memory usage of the running query execution. | 
| AzureDataExplorer.RunningSearchQuery.ScannedExtentsStatistics | Unknown | The scanned extent count. | 
| AzureDataExplorer.RunningSearchQuery.Principal | String | The principal that invoked the query. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.SecurityTokenPresent | Boolean | Whether the security token is present in the request or not. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.AuthorizationScheme | String | The authorization scheme. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.RequestHostName | String | The hostname of the request. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.LocalClusterName | String | The cluster name. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.OriginClusterName | String | The origin cluster name. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.api_version | String | The API version. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.request_readonly | Boolean | Whether the request is read-only or not. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.servertimeout | Number | The server timeout value. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.servertimeoutorigin | String | The server timeout origin. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.query_datascope | Number | The query datascope. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.query_fanout_nodes_percent | Number | The percentage of the query nodes in the cluster to use per subquery distribution operation. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.query_fanout_threads_percent | Number | The percentage of CPUs the cluster will assign on each node. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.maxmemoryconsumptionperiterator | Number | The maximum amount of memory that a single query plan result set iterator can hold. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.max_memory_consumption_per_query_per_node | Number | The maximum amount of memory that can be used on a single node for a specific query. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.truncationmaxsize | Number | The maximum overall data size returned by the query, in bytes. | 
| AzureDataExplorer.RunningSearchQuery.ClientRequestProperties.Options.truncationmaxrecords | Number | The maximum number of records returned by the query. | 
| AzureDataExplorer.RunningSearchQuery.ResultSetStatistics | Unknown | The result set statistics. | 
| AzureDataExplorer.RunningSearchQuery.WorkloadGroup | String | The workload group. | 


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
| database_name | The database name. | Required | 
| reason | The reason for canceling the running query. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDataExplorer.CanceledSearchQuery.RunningQueryCanceled | Boolean | Whether the query was successfully canceled or not. | 
| AzureDataExplorer.CanceledSearchQuery.ClientRequestId | String | The client activity ID of the cancelled query. | 
| AzureDataExplorer.CanceledSearchQuery.ReasonPhrase | String | The reason for canceling the running query. | 

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

### azure-data-explorer-auth-start
***
Run this command to start the authorization process and follow the instructions in the command results.


#### Base Command

`azure-data-explorer-auth-start`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### azure-data-explorer-auth-complete
***
Run this command to complete the authorization process. This should be used after running the azure-data-explorer-auth-start command.


#### Base Command

`azure-data-explorer-auth-complete`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### azure-data-explorer-auth-reset
***
Run this command if for some reason you need to rerun the authentication process.


#### Base Command

`azure-data-explorer-auth-reset`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### azure-data-explorer-auth-test
***
Run this command to test the connectivity to Azure Data Explorer.


#### Base Command

`azure-data-explorer-auth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### azure-data-explorer-generate-login-url
***
Generate the login url used for Authorization code flow.

#### Base Command

`azure-data-explorer-generate-login-url`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```azure-data-explorer-generate-login-url```

#### Human Readable Output

>### Authorization instructions
>1. Click on the [login URL]() to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
>```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.



