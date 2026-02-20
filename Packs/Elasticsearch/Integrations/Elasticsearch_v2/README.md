Elasticsearch_v2 integration is used to search for and analyze data in real time.
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
| Server URL | The Elasticsearch server to which the integration connects. Ensure that the URL includes the correct Elasticsearch port. The default port for Elasticsearch v7 and below is 9200. Use the Server URL for on-premises deployments. | False |
| Kibana API URL | The Elasticsearch server to which the integration connects. Ensure that the URL includes the correct Kibana port. The default port for the Kibana API is 443. Example: https://hostname.com:443 | False |
| Authorization type | Select the authentication type and enter the appropriate credentials:- Basic Auth: Enter Username and Password.- Bearer Auth: Enter Username and Password.- API Key Auth: Enter the API Key ID and API Key. | False |
| API key ID |  | False |
| API Key |  | False |
| Username | Provide Username \+ Password instead of API key \+ API ID | False |
| Password |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Client type | In some hosted ElasticSearch environments, the standard ElasticSearch client is not supported. If you encounter any related client issues, please consider using the OpenSearch client type. | False |
| Index from which to fetch incidents | CSV | False |
| Query String | Query string uses the Lucene syntax.For more information about the Lucene syntax, see the link in the help section.The query will be used when fetching incidents. Index time field will be used as a filter in the query.The integration test button doesn't fully test the fetch incidents validity. To verify that the instance is set up correctly for fetching incidents, run the '\!es-integration-health-check' command. | False |
| Index time field | The time field used for sorting and limiting results. If using a nested field, separate field names with dot notation. | False |
| Raw Query | Raw Query allows raw DSL queries and will override the 'Query String' Lucene syntax string.Results will not be filtered or sorted. Use additional parameters in the raw query for these purposes.For more information see the link in the help section.The integration test button doesn't fully test the fetch incidents validity. To verify that the instance is set up correctly for fetching incidents, run the '\!es-integration-health-check' command. | False |
| Time field type | For more information see the explanation in the help section. | False |
| Map JSON fields into labels |  | False |
| First fetch timestamp | &lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days | False |
| The maximum number of results to return per fetch. |  | False |
| Request timeout (in seconds). |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| Incidents Fetch Interval |  | False |


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

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

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
>
>|ID|Index name|Version|Result|
>|---|---|---|---|
>| 1234 | test-xsoar | 1 | created |

### es-integration-health-check

***
Returns the health status of the integration. This commmand should be used for debugging purposes.

#### Base Command

`es-integration-health-check`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

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
| all_results | Whether to retrieve all the Elasticsearch indices. If true, the "limit" argument will be ignored. Possible values are: false, true. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.IndexStatistics.Name | String | The name of the index. | 
| Elasticsearch.IndexStatistics.Status | String | The status of the index. | 
| Elasticsearch.IndexStatistics.Health | String | The health status of the index. | 
| Elasticsearch.IndexStatistics.UUID | String | The UUID of the index. | 
| Elasticsearch.IndexStatistics.DocumentsCount | Number | The number of documents that are indexed in the index. | 
| Elasticsearch.IndexStatistics.DocumentsDeleted | Number | The number of documents that were deleted from the index. | 

### es-esql-search

***
Search using ES|QL query (Elasticsearch 8.11 and above).

#### Base Command

`es-esql-search`

#### Input

| **Argument Name** | **Description**                                                                | **Required** |
| --- |--------------------------------------------------------------------------------| --- |
| query | The ES\|QL query string to execute using piped syntax (for example, FROM index | WHERE field == "value"). | Required |
| limit | Maximum number of results to return.                                           | Optional |

#### Context Output

| **Path**                 | **Description**      | **Type** |
|--------------------------|----------------------|----------------------|
| Elasticsearch.ESQLSearch | ES\|QL search result | unknown |
### kibana-enable-alert-rule

***
Used to enable a rule used for detection alerting. 

#### Base Command

`kibana-enable-alert-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID to enable. Find rule ID with "kibana-search-rule-details". | Required | 

#### Context Output

There is no context output for this command.
### kibana-get-task-manager-health

***
Get the health status of the Kibana task manager.

#### Base Command

`kibana-get-task-manager-health`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### kibana-get-user-by-email

***
Search for a single user's UID in Kibana by email address filter.

#### Base Command

`kibana-get-user-by-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_wildcard | Full or partial email address to search for user with. (i.e. william.smith@*). | Required | 

#### Context Output

There is no context output for this command.
### kibana-add-file-to-case

***
Attach a file to a case. 

#### Base Command

`kibana-add-file-to-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to attach the file to. Locate with "kibana-find-cases". | Required | 
| file_id | File entry ID from XSOAR context data to add to the case. | Required | 

#### Context Output

There is no context output for this command.
### kibana-add-alert-note

***
Add note to an alert in Kibana.

#### Base Command

`kibana-add-alert-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID to update the note on. Find with "kibana-list-detection-alerts". | Required | 
| note | The note text to add to the alert. | Required | 

#### Context Output

There is no context output for this command.
### kibana-delete-value-list-item

***
Used to delete a value list item given the item ID as input.

#### Base Command

`kibana-delete-value-list-item`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | Value list entry ID to delete. Find with "kibana-get-value-list-items". | Required | 

#### Context Output

There is no context output for this command.
### kibana-delete-value-list

***
Used to delete a value list given the list ID as input.

#### Base Command

`kibana-delete-value-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Value list ID to delete. Find with "kibana-get-value-lists". | Required | 

#### Context Output

There is no context output for this command.
### kibana-find-case-comments

***
Finds comments for an input case ID

#### Base Command

`kibana-find-case-comments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to find comments for. Locate with "kibana-find-cases". | Required | 

#### Context Output

There is no context output for this command.
### kibana-list-detection-alerts

***
Used to search for detection alerts in Kibana

#### Base Command

`kibana-list-detection-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_status | Status of the detection alert to search for. Possible values are: open, closed. | Required | 

#### Context Output

There is no context output for this command.
### kibana-get-status

***
Check Kibana's operational status

#### Base Command

`kibana-get-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### kibana-delete-case-comment

***
Delete a case comment

#### Base Command

`kibana-delete-case-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to delete comment on. Retrieve case IDs with "kibana-find-cases". | Required | 
| comment_id | Identifier for the comment. To retrieve comment IDs use kibana-find-case-comments. | Required | 

#### Context Output

There is no context output for this command.
### kibana-get-alerting-health

***
Get the health status of Kibana alerting framework

#### Base Command

`kibana-get-alerting-health`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### kibana-update-case-status

***
Updates the status of an input case

#### Base Command

`kibana-update-case-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the case to update. Possible values are: open, in-progress, closed. | Required | 
| case_id | ID of case in Kibana. Locate with "kibana-find-cases". | Required | 
| version_id | Version ID of the case. Found with kibana-find-cases. This ID changes after each case update. | Required | 

#### Context Output

There is no context output for this command.
### kibana-create-value-list

***
Used to create a value list in Kibana

#### Base Command

`kibana-create-value-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | Describes the value list. | Required | 
| name | Value list's name. | Required | 
| data_type | Elasticsearch data type the list container holds. Possible values are: keyword, ip, ip_range, text. | Required | 
| list_id | Value list's identifier. | Required | 

#### Context Output

There is no context output for this command.
### kibana-find-alerts-for-case

***
Returns information on the alerts of a case in Kibana.

#### Base Command

`kibana-find-alerts-for-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of case in Kibana. Locate with "kibana-find-cases". | Required | 

#### Context Output

There is no context output for this command.
### kibana-update-alert-status

***
Updates the status of an input alert.

#### Base Command

`kibana-update-alert-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID to update. Find with "kibana-list-detection-alerts". | Required | 
| status | Status to set the alert to. Possible values are: open, closed. | Required | 

#### Context Output

There is no context output for this command.
### kibana-add-case-comment

***
Adds a comment to a case in Kibana. Get case ID/owner from kibana-find-cases.

#### Base Command

`kibana-add-case-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to add comment to. Locate with "kibana-find-cases". | Required | 
| case_owner | Owner of the case listed in kibana-find-cases output. Possible values are: cases, observability, securitySolution. | Required | 
| comment | The comment to add to the case in Kibana. | Required | 

#### Context Output

There is no context output for this command.
### kibana-get-upgrade-readiness-status

***
Check the status of your cluster.

#### Base Command

`kibana-get-upgrade-readiness-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### kibana-delete-case

***
Deletes a case in Kibana based on case ID

#### Base Command

`kibana-delete-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to delete. Locate with "kibana-find-cases". | Required | 

#### Context Output

There is no context output for this command.
### kibana-get-user-list

***
Search for list of users in Kibana and return user's UID.

#### Base Command

`kibana-get-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### kibana-get-value-list-items

***
Used to display entries in an input value list.

#### Base Command

`kibana-get-value-list-items`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Value list ID to retrieve values for. Find with "kibana-get-value-lists". | Required | 
| result_size | Size of results to return. Default is 100. | Optional | 

#### Context Output

There is no context output for this command.
### kibana-disable-alert-rule

***
Disable a detection alerting rule. Clears associated alerts from active alerts page.

#### Base Command

`kibana-disable-alert-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID to disable. Find rule ID with "kibana-search-rule-details". | Required | 

#### Context Output

There is no context output for this command.
### kibana-assign-alert

***
Used to assign an alert in Kibana to a user via user ID input

#### Base Command

`kibana-assign-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | UID of user to be assigned. Locate with 'kibana-get-user-list'. | Required | 
| alert_id | Alert ID to assign user to. Find with "kibana-list-detection-alerts". | Required | 

#### Context Output

There is no context output for this command.
### kibana-import-value-list-items

***
Import value list items from a TXT or CSV file.

#### Base Command

`kibana-import-value-list-items`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Value list ID to import values to. Find with "kibana-get-value-lists". | Required | 
| file_content | Entries of the IOC file to import to Kibana. | Required | 

#### Context Output

There is no context output for this command.
### kibana-find-cases

***
Used to list cases in Kibana

#### Base Command

`kibana-find-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the cases to retrieve. Possible values are: open, in-progress, closed. | Optional | 
| severity | The status of the cases to retrieve. Possible values are: critical, high, medium, low. | Optional | 
| from_time | Earliest time to search from (i.e. 2025-10-02T00:27:58.162Z). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.Cases | unknown | Kibana Cases Search Result | 

### kibana-get-value-lists

***
Find all value lists in Kibana Detection Rules menu.

#### Base Command

`kibana-get-value-lists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### kibana-get-exception-lists

***
Get a list of all exception list containers.

#### Base Command

`kibana-get-exception-lists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### kibana-get-case-information

***
Retrieve information for a specific case in Kibana.

#### Base Command

`kibana-get-case-information`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to retrieve information for. View available case IDs with kibana_find_cases. | Required | 

#### Context Output

There is no context output for this command.
### kibana-create-value-list-item

***
Create a value list item and associate it with the specified value list.

#### Base Command

`kibana-create-value-list-item`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Value list ID to update. Find with "kibana-get-value-lists". | Required | 
| new_value_list_item | Item to add to the specified value list. | Required | 

#### Context Output

There is no context output for this command.
### kibana-find-user-spaces

***
Get list of user spaces in Kibana

#### Base Command

`kibana-find-user-spaces`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### kibana-delete-rule

***
Delete rule in Kibana based on input rule ID.

#### Base Command

`kibana-delete-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID to delete. Find with "kibana-search-rule-details". | Required | 

#### Context Output

There is no context output for this command.
### kibana-search-rule-details

***
Retrieve details about detection rule in Kibana based on input KQL filter.

#### Base Command

`kibana-search-rule-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kql_query | Example query: "alert.attributes.name: *Smith*". | Optional | 

#### Context Output

There is no context output for this command.
