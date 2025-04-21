Search for and analyze data in real time. 
Supports version 6 and later.
This integration was integrated and tested with versions 6.6.2, 7.3, 8.4.1 of Elasticsearch.

## Permissions

The permissions required to use this integration depends on which operations you need to perform. The API user should have the same permissions a regular user would have in order to access the data via the UI. Following are the permissions needed for certain commands:
- **!es-eql-search/search/es-search/fetch-incidents** - If the Elasticsearch security features are enabled, you must have the *read* [index privilege](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-privileges.html#privileges-list-indices) for the target data stream, index, or alias.
- **!get-mapping-fields** - If the Elasticsearch security features are enabled, you must have the *view_index_metadata* or *manage* [index privilege](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-privileges.html#privileges-list-indices) for the target data stream, index, or alias.
- **!es-index** - If the Elasticsearch security features are enabled, you must have the *write* [index privilege](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-privileges.html#privileges-list-indices) for the target data stream, index, or alias.

## Configure Elasticsearch v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Elasticsearch server to which the integration connects. Ensure that the URL includes the correct Elasticsearch port. By default this is 9200. | True |
| Username for server login | Provide Username \+ Passoword instead of API key \+ API ID | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Client type | For Elasticsearch version 7 and below, select 'Elasticsearch'. For Elasticsearch server version 8, select 'Elasticsearch_v8'. In some hosted Elasticsearch environments, the standard Elasticsearch client is not supported. If you encounter any related client issues, consider using the 'OpenSearch' client type. | False |
| Index from which to fetch incidents (CSV) |  | False |
| Query String | The query will be used when fetching incidents. Index time field will be used as a filter in the query | False |
| Index time field (for sorting sort and limiting data) | The time field on which sorting and limiting are performed. If using a nested field, separate field names using dot notation. | False |
| Raw Query | Will override the 'Query String' Lucene syntax string. Results will not be filtered. | False |
| Time field type |  | False |
| Map JSON fields into labels |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| The maximum number of results to return per fetch. |  | False |
| Request timeout (in seconds). |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |



## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### es-search
***
Queries an index.


#### Base Command

`es-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | The index in which to perform a search. | Required | 
| query | The string to query (in Lucene syntax). Possible values are: . | Optional | 
| fields | A comma-separated list of document fields to fetch. If empty, the entire document is fetched. | Optional | 
| explain | Calculates an explanation of a score for a query. For example, "value:1.6943597". Possible values are: true, false. Default is false. | Optional | 
| page | The page number from which to start a search. Default is 0. | Optional | 
| size | The number of documents displayed per page. Can be an integer between "1" and "10,000". Default is 100. | Optional | 
| sort-field | The field by which to sort the results table. The supported result types are boolean, numeric, date, and keyword fields. Keyword fields require the doc_values parameter to be set to "true" from the Elasticsearch server. Possible values are: . | Optional | 
| sort-order | The order by which to sort the results table. The results tables can only be sorted if a sort-field is defined. Possible values are: asc, desc. Default is asc. | Optional | 
| query_dsl | Will overwrite the ‘query' arguments. | Optional | 
| timestamp_range_start | The starting time of the time range. | Optional | 
| timestamp_range_end | The ending time of the time range. | Optional | 
| timestamp_field | Timestamp field name. Default is @timestamp. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Search.Results._index | String | The index to which the document belongs. | 
| Elasticsearch.Search.Results._id | String | The ID of the document. | 
| Elasticsearch.Search.Results._type | String | The mapping type of the document. | 
| Elasticsearch.Search.max_score | Number | The maximum relevance score of a query. | 
| Elasticsearch.Search.Query | String | The query performed in the search. | 
| Elasticsearch.Search.total.value | Number | The number of search results. | 
| Elasticsearch.Search.Results._score | Number | The relevance score of the search result. | 
| Elasticsearch.Search.Index | String | The index in which the search was performed. | 
| Elasticsearch.Search.Server | String | The server on which the search was performed. | 
| Elasticsearch.Search.timed_out | Boolean | Whether the search stopped due to a timeout. | 
| Elasticsearch.Search.took | Number | The time in milliseconds taken for the search to complete. | 
| Elasticsearch.Search.Page | Number | The page number from which the search started. | 
| Elasticsearch.Search.Size | Number | The maximum number of scores that a search can return. | 

### search
***
Searches an index.


#### Base Command

`search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | The index in which to perform a search. | Required | 
| query | The string to query (in Lucene syntax). Possible values are: . | Optional | 
| fields | A comma-separated list of document fields to fetch. If empty, fetches the entire document. | Optional | 
| explain | Calculates an explanation of a score for a query. For example, "value:1.6943597". Possible values are: true, false. Default is false. | Optional | 
| page | The page number from which to start a search. Default is 0. | Optional | 
| size | The number of documents displayed per page. Can be an integer between "1" and "10,000". Default is 100. | Optional | 
| sort-field | The field by which to sort the results table. The supported result types are boolean, numeric, date, and keyword fields. Keyword fields require the doc_values parameter to be set to "true" from the Elasticsearch server. Possible values are: . | Optional | 
| sort-order | The order by which to sort the results table. The results tables can only be sorted if a sort-field is defined. Possible values are: asc, desc. Default is asc. | Optional | 
| timestamp_field | Timestamp field name. Default is @timestamp. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Search.Results._index | String | The index to which the document belongs. | 
| Elasticsearch.Search.Results._id | String | The ID of the document. | 
| Elasticsearch.Search.Results._type | String | The mapping type of the document. | 
| Elasticsearch.Search.max_score | Number | The maximum relevance score of a query. | 
| Elasticsearch.Search.Query | String | The query performed in the search. | 
| Elasticsearch.Search.total.value | Number | The number of search results. | 
| Elasticsearch.Search.Results._score | Number | The relevance score of the search result. | 
| Elasticsearch.Search.Index | String | The index in which the search was performed. | 
| Elasticsearch.Search.Server | String | The server on which the search was performed. | 
| Elasticsearch.Search.timed_out | Boolean | Whether the search stopped due to a time out. | 
| Elasticsearch.Search.took | Number | The time in milliseconds taken for the search to complete. | 
| Elasticsearch.Search.Page | Number | The page number from which the search started. | 
| Elasticsearch.Search.Size | Number | The maximum number of scores that a search can return. | 

### get-mapping-fields
***
Returns the schema of the index to fetch from. This commmand should be used for debugging purposes.


#### Base Command

`get-mapping-fields`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### es-eql-search
***
Search using EQL query


#### Base Command

`es-eql-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | The index in which to perform a search. | Required | 
| query | The string to query (in Lucene syntax). | Required | 
| fields | A comma-separated list of document fields to fetch. If empty, fetches the entire document. | Optional | 
| sort-tiebreaker | If two or more events share the same timestamp, Elasticsearch uses a tiebreaker field value to sort the events in ascending order. | Optional | 
| filter | Filter using query DSL. | Optional | 
| event_category_field | The event category field. Default is event.category. | Optional | 
| size | The number of documents displayed per page. Can be an integer between "1" and "10,000". Default is 100. | Optional | 
| timestamp_range_start | The starting time of the time range. | Optional | 
| timestamp_range_end | The ending time of the time range. | Optional | 
| timestamp_field | Timestamp field name. Default is @timestamp. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Search.Results._index | String | The index to which the document belongs. | 
| Elasticsearch.Search.Results._id | String | The ID of the document. | 
| Elasticsearch.Search.Results._type | String | The mapping type of the document. | 
| Elasticsearch.Search.max_score | Number | The maximum relevance score of a query. | 
| Elasticsearch.Search.Query | String | The query performed in the search. | 
| Elasticsearch.Search.total.value | Number | The number of search results. | 
| Elasticsearch.Search.Results._score | Number | The relevance score of the search result. | 
| Elasticsearch.Search.Index | String | The index in which the search was performed. | 
| Elasticsearch.Search.Server | String | The server on which the search was performed. | 
| Elasticsearch.Search.timed_out | Boolean | Whether the search stopped due to a timeout. | 
| Elasticsearch.Search.took | Number | The time in milliseconds taken for the search to complete. | 
| Elasticsearch.Search.Page | Number | The page number from which the search started. | 
| Elasticsearch.Search.Size | Number | The maximum number of scores that a search can return. |

### es-index
***
Indexes a document into an Elasticsearch index.


#### Base Command

`es-index`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index_name | The name of the index to ingest into. | Required | 
| document | The document object (JSON format) to be indexed. See [Elasticsearch documentation](https://www.elastic.co/guide/en/elasticsearch/client/python-api/current/examples.html#ex-index) for further information about indexing documents via the Elasticsearch client. | Required | 
| id | The ID of the indexed document (will be generated if empty). The document will be updated if one with a corresponding ID exists. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Index.id | String | The ID of the indexed document. |
| Elasticsearch.Index.index | String | The name of the index which the document was ingested to. |  
| Elasticsearch.Index.version | Number | The version number of the indexed document. | 
| Elasticsearch.Index.result | String | The result of the index operation. | 

#### Command Example
```!es-index index_name=test-xsoar document="{\"name\":\"test\"}" id=1234```

#### Context Example
```
{
    "Elasticsearch": {
        "Index": {
            "id": "1234",
            "index": "test-xsoar",
            "version": 1,
            "result": "created"
        }
    }
}
```

#### Human Readable Output

> ### Indexed document
>|ID|Index name|Version|Result|
>|---|---|---|---|
>| 1234 | test-xsoar | 1 | created | 

### es-integration-health-check
***
Returns the health status of the integration. This commmand should be used for debugging purposes.

#### Base Command

`es-integration-health-check`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### es-get-indices-statistics

***
Returns Elasticsearch indices statistics and information. This command is not supported for client type OpenSearch.

#### Base Command

`es-get-indices-statistics`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indices to return. Default is 50. | Optional |
| all_results | Whether to retrieve all the Elasticsearch indices. If true, the "limit" argument will be ignored. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.IndexStatistics.Name | String | The name of the index. |
| Elasticsearch.IndexStatistics.Status | String | The status of the index. |
| Elasticsearch.IndexStatistics.Health | String | The health status of the index. |
| Elasticsearch.IndexStatistics.UUID | String | The UUID of the index. |
| Elasticsearch.IndexStatistics.DocumentsCount | Number | The number of documents that are indexed in the index. |
| Elasticsearch.IndexStatistics.DocumentsDeleted | Number | The number of documents that were deleted from the index. |
