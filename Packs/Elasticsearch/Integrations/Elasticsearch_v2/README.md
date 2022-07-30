Search for and analyze data in real time. 
 Supports version 6 and later.
This integration was integrated and tested with version 8.3 of Elasticsearch v2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-elasticsearch-v2).

## Configure Elasticsearch v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Elasticsearch v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | The Elasticsearch server to which the integration connects. Ensure that the URL includes the correct Elasticsearch port. By default this is 9200. | True |
    | Username for server login | Provide Username \+ Passoword instead of API key \+ API ID | False |
    | Password |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Client type | In some hosted ElasticSearch environments, the standard ElasticSearch client is not supported. If you encounter any related client issues, please consider using the OpenSearch client type. | False |
    | Index from which to fetch incidents (CSV) |  | False |
    | Query by which to fetch incidents (Lucene syntax) |  | False |
    | Raw Query | Will replace the ‘fetch_query’ lucene syntax string. | False |
    | Query Time Range - Start | Query time range expressions, start time. Will replace the First Fetch field. | False |
    | Query Time Range - End | Query time range expressions, end time. | False |
    | Index time field (for sorting sort and limiting data) |  | False |
    | Time field type |  | False |
    | Map JSON fields into labels |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | The maximum number of results to return per fetch. The default is 50. |  | False |
    | Request timeout (in seconds). |  | False |
    | Incident type |  | False |
    | Fetch incidents |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| query | The string to query (in Lucene syntax). Possible values are: . | Required | 
| fields | A comma-separated list of document fields to fetch. If empty, the entire document is fetched. | Optional | 
| explain | Calculates an explanation of a score for a query. Default is "false". For example, "value:1.6943597". Possible values are: true, false. Default is false. | Optional | 
| page | The page number from which to start a search. The default is "0". Default is 0. | Optional | 
| size | The number of documents displayed per page. Can be an integer between "1" and "10,000". The default is "100". Default is 100. | Optional | 
| sort-field | The field by which to sort the results table. The supported result types are boolean, numeric, date, and keyword fields. Keyword fields require the doc_values parameter to be set to "true" from the Elasticsearch server. Possible values are: . | Optional | 
| sort-order | The order by which to sort the results table. The results tables can only be sorted if a sort-field is defined. Possible values are: asc, desc. Default is asc. | Optional | 
| query_dsl | Used instead of ‘query'. | Optional | 
| timestamp_range_start | The starting time of the time range. | Optional | 
| timestamp_range_end | The ending time of the time range. | Optional | 


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

### search
***
Searches an index.


#### Base Command

`search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | The index in which to perform a search. | Required | 
| query | The string to query (in Lucene syntax). Possible values are: . | Required | 
| fields | A comma-separated list of document fields to fetch. If empty, fetches the entire document. | Optional | 
| explain | Calculates an explanation of a score for a query. Default is "false". For example, "value:1.6943597". Possible values are: true, false. Default is false. | Optional | 
| page | The page number from which to start a search. The default is "0". Default is 0. | Optional | 
| size | The number of documents displayed per page. Can be an integer between "1" and "10,000". The default is "100". Default is 100. | Optional | 
| sort-field | The field by which to sort the results table. The supported result types are boolean, numeric, date, and keyword fields. Keyword fields require the doc_values parameter to be set to "true" from the Elasticsearch server. Possible values are: . | Optional | 
| sort-order | The order by which to sort the results table. The results tables can only be sorted if a sort-field is defined. Possible values are: asc, desc. Default is asc. | Optional | 


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
| index | The index in which to perform a search. | Optional | 
| query | The string to query (in Lucene syntax). | Required | 
| fields | A comma-separated list of document fields to fetch. If empty, fetches the entire document. | Required | 
| sort-tiebreaker | If two or more events share the same timestamp, Elasticsearch uses a tiebreaker field value to sort the events in ascending order. | Optional | 
| filter | Filter using query DSL. | Optional | 
| event_category_field | The event catagory field. Default is event.category. | Optional | 
| size | The number of documents displayed per page. Can be an integer between "1" and "10,000". The default is "100". Default is 100. | Optional | 
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
| Elasticsearch.Search.timed_out | Boolean | Whether the search stopped due to a time out. | 
| Elasticsearch.Search.took | Number | The time in milliseconds taken for the search to complete. | 
| Elasticsearch.Search.Page | Number | The page number from which the search started. | 
| Elasticsearch.Search.Size | Number | The maximum number of scores that a search can return. |