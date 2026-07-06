Elasticsearch_v2 integration is used to search for and analyze data in real time.
Supports version 6 and later.
This integration was integrated and tested with versions 6.6.2, 7.3, 8.4.1 of Elasticsearch.

## Permissions

The permissions required to use this integration depends on which operations you need to perform. The API user should have the same permissions a regular user would have in order to access the data via the UI. Following are the permissions needed for certain commands:

- **!es-eql-search/search/es-search/fetch-incidents** - If the Elasticsearch security features are enabled, you must have the *read* [index privilege](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-privileges.html#privileges-list-indices) for the target data stream, index, or alias.
- **!get-mapping-fields** - If the Elasticsearch security features are enabled, you must have the *view_index_metadata* or *manage* [index privilege](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-privileges.html#privileges-list-indices) for the target data stream, index, or alias.
- **!es-index** - If the Elasticsearch security features are enabled, you must have the *write* [index privilege](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-privileges.html#privileges-list-indices) for the target data stream, index, or alias.
- **!es-kibana-* commands** - To execute Kibana commands, you must have the necessary privileges for the applicable resource within the Management, Observability, or Security feature privileges, depending on the command you are using. Kibana API endpoints are gated by feature privileges granted at one of two levels: *Read* (GET / list / view operations) and *All* (POST / PUT / PATCH / DELETE operations). For rules and cases, the privilege is owner/consumer-scoped - a security-owned object needs the Security privilege, an observability-owned one needs Observability, and a stack-owned one needs Management/Stack Rules.

## Configure Elasticsearch v2 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Elasticsearch server to which the integration connects. Ensure that the URL includes the correct Elasticsearch port. The default port for Elasticsearch v7 and below is 9200. Use the Server URL for on-premises deployments. | False |
| Authorization type | Select the authentication type and enter the appropriate credentials:<br/>- Basic Auth: Enter Username and Password.<br/>- Bearer Auth: Enter Username and Password.<br/>- API Key Auth: Enter the API Key ID and API Key. | True |
| API key ID | Use for API key auth | False |
| API Key | Use for API key auth | False |
| Username | Use for API Key auth. Optionally you can use Username as an API key ID and Password as an API key for Basic auth. | False |
| Password | Use for API Key auth. Optionally you can use Username as an API key ID and Password as an API key for Basic auth. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Client type | In some hosted ElasticSearch environments, the standard ElasticSearch client is not supported. If you encounter any related client issues, please consider using the OpenSearch client type. | False |
| Index to fetch incidents from | CSV | False |
| Query String | Query string uses the Lucene syntax.<br/>For more information about the Lucene syntax see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.3/query-dsl-query-string-query.html#query-string-syntax).<br/>The query will be used when fetching incidents. Index time field will be used as a filter in the query.<br/><br/>The integration test button doesn't fully test the fetch incidents validity. To verify that the instance is set up correctly for fetching incidents, run the '\!es-integration-health-check' command. | False |
| Fields to fetch (_source already included) | A comma-separated list of Elasticsearch fields to retrieve in addition to the default _source fields. For example: host.hostname, host.id. | False |
| Index time field | The time field used for sorting and limiting results. If using a nested field, separate field names with dot notation. | False |
| Raw Query | Raw Query allows raw DSL queries and will override the 'Query String' Lucene syntax string.<br/>Results will not be filtered or sorted. Use additional parameters in the raw query for these purposes.<br/>For more information about Query DSL see [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html).<br/><br/>The integration test button doesn't fully test the fetch incidents validity. To verify that the instance is set up correctly for fetching incidents, run the '\!es-integration-health-check' command. | False |
| Time field type | 3 formats supported:<br/> *Simple-Date - A plain date string. You must specify the format in which the date is stored.<br/>For more information about time formatting, see [here](http://strftime.org/).<br/>* Timestamp-Second - A numeric value representing the number of seconds since the Unix epoch (00:00:00 UTC on 1 January 1970). Example: '1572164838'<br/> * Timestamp-Milliseconds - A numeric value representing the number of milliseconds since the Unix epoch. Example: '1572164838123' | False |
| Map JSON fields into labels |  | False |
| First fetch timestamp | &lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days | False |
| The maximum number of results per fetch |  | False |
| Request timeout (in seconds). |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| Space ID | The default Kibana space ID to use for es-kibana-* commands. Used to derive the Kibana base URL from the Server URL. If a space_id argument is provided to a command, it overrides this value. See [Spaces](https://www.elastic.co/docs/deploy-manage/manage-spaces) for more information. | False |

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

### es-kibana-alerting-health-get

***
Retrieves the health of the Kibana alerting framework.

#### Base Command

`es-kibana-alerting-health-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.AlertingHealth.is_sufficiently_secure | Boolean | Whether the alerting framework is sufficiently secure. |
| Elasticsearch.Kibana.AlertingHealth.has_permanent_encryption_key | Boolean | Whether a permanent encryption key is configured. |
| Elasticsearch.Kibana.AlertingHealth.alerting_framework_health.decryption_health.status | String | The decryption health status. |
| Elasticsearch.Kibana.AlertingHealth.alerting_framework_health.execution_health.status | String | The execution health status. |
| Elasticsearch.Kibana.AlertingHealth.alerting_framework_health.read_health.status | String | The read health status. |

### es-kibana-rule-types-list

***
Retrieves all rule types available in Kibana.

#### Base Command

`es-kibana-rule-types-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.RuleType.id | String | The rule type ID. |
| Elasticsearch.Kibana.RuleType.name | String | The rule type name. |
| Elasticsearch.Kibana.RuleType.category | String | The rule type category. |
| Elasticsearch.Kibana.RuleType.producer | String | The rule type producer. |
| Elasticsearch.Kibana.RuleType.action_groups.id | String | The action group ID. |

### es-kibana-rule-list

***
Retrieves information about rules.

#### Base Command

`es-kibana-rule-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| rule_id | The identifier for the rule. | Optional |
| search | An Elasticsearch simple_query_string query that filters the objects in the response. | Optional |
| default_search_operator | The default operator to use for the simple_query_string. | Optional |
| search_fields | The fields to perform the simple_query_string parsed query against. | Optional |
| sort_field | Determines which field is used to sort the results. | Optional |
| sort_order | Determines the sort order. | Optional |
| has_reference_id | Filters the rules that have a relation with the reference objects with a specific identifier. | Optional |
| has_reference_type | Filters the rules that have a relation with the reference objects with a specific type. | Optional |
| fields | The fields to return in the attributes key of the response. | Optional |
| filter | A KQL string that you filter with an attribute from your saved object. | Optional |
| filter_consumers | List of consumers to filter. | Optional |
| page | The page number from which to start a search. | Optional |
| size | The number of rules to return per page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Rule.id | String | The rule ID. |
| Elasticsearch.Kibana.Rule.enabled | Boolean | Whether the rule is enabled. |
| Elasticsearch.Kibana.Rule.name | String | The rule name. |
| Elasticsearch.Kibana.Rule.rule_type_id | String | The rule type ID. |
| Elasticsearch.Kibana.Rule.created_at | Date | The creation date of the rule. |

### es-kibana-rule-enable

***
Enable a rule.

#### Base Command

`es-kibana-rule-enable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| rule_id | The identifier for the rule. | Required |

#### Context Output

There is no context output for this command.

### es-kibana-rule-disable

***
Disable a rule.

#### Base Command

`es-kibana-rule-disable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| rule_id | The identifier for the rule. | Required |

#### Context Output

There is no context output for this command.

### es-kibana-rule-update

***
Update a rule.

#### Base Command

`es-kibana-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| rule_id | The identifier for the rule. | Required |
| alert_delay_active | The number of consecutive runs that must meet the rule conditions. | Optional |
| artifacts_dashboards_id | Not more than 10 elements. | Optional |
| artifacts_investigation_guide_blob | Maximum length is 10000. | Optional |
| consumer | The name of the application or feature that owns the rule. | Optional |
| enabled | Indicates whether you want the rule to run on an interval basis after it is created. | Optional |
| flapping_enabled | Determines whether the rule can enter the flapping state. | Optional |
| flapping_look_back_window | The minimum number of runs in which the threshold must be met. Minimum value is 2, maximum value is 20. | Optional |
| flapping_status_change_threshold | The minimum number of times an alert must switch states within the defined look back window time. | Optional |
| name | The name of the rule. | Optional |
| notify_when | Indicates how frequently rule actions are triggered. | Optional |
| schedule_interval | The interval is specified in seconds, minutes, hours, or days. | Optional |
| tags | The tags for the rule. | Optional |
| entry_id | Entry ID for the file containing the request JSON. If provided, other parameters won't be considered. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Rule.id | String | The rule ID. |

### es-kibana-rule-alert-mute

***
Mute an alert, or mute all alerts for a rule.

#### Base Command

`es-kibana-rule-alert-mute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| rule_id | The identifier for the rule. | Required |
| alert_id | The identifier for the alert. | Optional |
| validate_alerts_existence | Whether to validate the existence of the alert. | Optional |
| mute_all | Whether to mute all alerts. | Optional |

#### Context Output

There is no context output for this command.

### es-kibana-rule-alert-unmute

***
Unmute an alert, or unmute all alerts for a rule.

#### Base Command

`es-kibana-rule-alert-unmute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| rule_id | The identifier for the rule. | Required |
| alert_id | The identifier for the alert. | Optional |
| unmute_all | Whether to unmute all alerts. | Optional |

#### Context Output

There is no context output for this command.

### es-kibana-detection-alert-status-set

***
Set the status of one or more detection alerts.

#### Base Command

`es-kibana-detection-alert-status-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| status | The new status of the detection alert(s). | Required |
| signal_ids | List of alert ids. Use field _id on alert document or kibana.alert.uuid. | Optional |
| query | An Elasticsearch query used to select which alerts to update, as an alternative to signal_ids. | Optional |
| reason | The reason for the status change. | Optional |
| conflicts | Determines how version conflicts should be handled. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.SecurityAlertSetStatus.total | Number | The total number of alerts matched by the request. |
| Elasticsearch.Kibana.SecurityAlertSetStatus.updated | Number | The number of alerts that were updated. |

### es-kibana-case-create

***
Creates a new case in Kibana.

#### Base Command

`es-kibana-case-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| assignee_uid | An array containing users that are assigned to the case. Not more than 10 elements. | Optional |
| category | A word or phrase that categorizes the case. Maximum length is 50. | Optional |
| connector_fields | A JSON object containing the connector fields. To create a case without a connector, specify null. | Optional |
| connector_id | The identifier for the connector. To create a case without a connector, use none. | Optional |
| connector_name | The name of the connector. To create a case without a connector, use none. | Optional |
| connector_type | The type of connector. To create a case without a connector, use .none. | Optional |
| connector_fields_issue_type_jira | The type of issue. | Optional |
| connector_fields_parent_jira | The key of the parent issue, when the issue type is sub-task. | Optional |
| connector_fields_priority_jira | The priority of the issue. | Optional |
| connector_fields_issue_types_resilient | The type of incident. | Optional |
| connector_fields_severity_code_resilient | The severity code of the incident. | Optional |
| connector_fields_category_servicenow | The category of the incident. | Optional |
| connector_fields_impact_servicenow | The effect an incident had on business. | Optional |
| connector_fields_severity_servicenow | The severity of the incident. | Optional |
| connector_fields_subcategory_servicenow | The subcategory of the incident. | Optional |
| connector_fields_urgency_servicenow | The extent to which the incident resolution can be delayed. | Optional |
| connector_fields_dest_ip_servicenow | Indicates whether cases will send a comma-separated list of destination IPs. | Optional |
| connector_fields_malware_hash_servicenow | Indicates whether cases will send a comma-separated list of malware hashes. | Optional |
| connector_fields_malware_url_servicenow | Indicates whether cases will send a comma-separated list of malware URLs. | Optional |
| connector_fields_priority_servicenow | The priority of the issue. | Optional |
| connector_fields_source_ip_servicenow | Indicates whether cases will send a comma-separated list of source IPs. | Optional |
| connector_fields_case_id_swimlane | The case identifier for Swimlane connectors. | Optional |
| custom_key | The unique identifier for the custom field. The key value must exist in the case configuration settings. | Optional |
| custom_type | The custom field type. It must match the type specified in the case configuration settings. | Optional |
| custom_value | The custom field value (string or boolean). | Optional |
| description | The description for the case. Maximum length is 30000. | Optional |
| owner | The application that owns the cases: Stack Management, Observability, or Elastic Security. | Required |
| extract_observables | When true, observables (e.g. IPs, hashes, URLs) are automatically extracted from case comments. | Optional |
| sync_alerts | Turns alert syncing on or off. | Optional |
| severity | The severity of the case. | Optional |
| tags | The words and phrases that help categorize cases. Not more than 200 elements. | Optional |
| title | A title for the case. Maximum length is 160. | Optional |
| entry_id | Entry ID for the file containing the full request JSON. If provided, other parameters won't be considered. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Case.title | String | The title of the case. |
| Elasticsearch.Kibana.Case.id | String | The case ID. |
| Elasticsearch.Kibana.Case.description | String | The description of the case. |
| Elasticsearch.Kibana.Case.owner | String | The owner of the case. |
| Elasticsearch.Kibana.Case.severity | String | The severity of the case. |
| Elasticsearch.Kibana.Case.status | String | The status of the case. |
| Elasticsearch.Kibana.Case.created_at | Date | The creation date of the case. |
| Elasticsearch.Kibana.Case.connector.type | String | The connector type of the case. |

### es-kibana-case-update

***
Update cases in Kibana.

#### Base Command

`es-kibana-case-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. | Required |
| version | The current version of the case. To determine this value, use es-kibana-case-list. | Required |
| assignee_uid | An array containing users that are assigned to the case. Not more than 10 elements. | Optional |
| category | A word or phrase that categorizes the case. Maximum length is 50. | Optional |
| close_reason | The close reason to sync to attached alerts when closing the case. | Optional |
| connector_fields | A JSON object containing the connector fields. To remove a connector, specify null. | Optional |
| connector_id | The identifier for the connector. To remove a connector, specify none. | Optional |
| connector_name | The name of the connector. To remove a connector, specify none. | Optional |
| connector_type | The type of connector. To remove a connector, specify .none. | Optional |
| connector_fields_issue_type_jira | The type of issue. | Optional |
| connector_fields_parent_jira | The key of the parent issue, when the issue type is sub-task. | Optional |
| connector_fields_priority_jira | The priority of the issue. | Optional |
| connector_fields_issue_types_resilient | The type of incident. | Optional |
| connector_fields_severity_code_resilient | The severity code of the incident. | Optional |
| connector_fields_category_servicenow | The category of the incident. | Optional |
| connector_fields_impact_servicenow | The effect an incident had on business. | Optional |
| connector_fields_severity_servicenow | The severity of the incident. | Optional |
| connector_fields_subcategory_servicenow | The subcategory of the incident. | Optional |
| connector_fields_urgency_servicenow | The extent to which the incident resolution can be delayed. | Optional |
| connector_fields_dest_ip_servicenow | Indicates whether cases will send a comma-separated list of destination IPs. | Optional |
| connector_fields_malware_hash_servicenow | Indicates whether cases will send a comma-separated list of malware hashes. | Optional |
| connector_fields_malware_url_servicenow | Indicates whether cases will send a comma-separated list of malware URLs. | Optional |
| connector_fields_priority_servicenow | The priority of the issue. | Optional |
| connector_fields_source_ip_servicenow | Indicates whether cases will send a comma-separated list of source IPs. | Optional |
| connector_fields_case_id_swimlane | The case identifier for Swimlane connectors. | Optional |
| custom_key | The unique identifier for the custom field. The key value must exist in the case configuration settings. | Optional |
| custom_type | The custom field type. It must match the type specified in the case configuration settings. | Optional |
| custom_value | The custom field value (string or boolean). | Optional |
| description | The description for the case. Maximum length is 30000. | Optional |
| extract_observables | When true, observables (e.g. IPs, hashes, URLs) are automatically extracted from case comments. | Optional |
| sync_alerts | Turns alert syncing on or off. | Optional |
| severity | The severity of the case. | Optional |
| status | The status of the case. | Optional |
| tags | The words and phrases that help categorize cases. Not more than 200 elements. | Optional |
| title | A title for the case. Maximum length is 160. | Optional |
| entry_id | Entry ID for the file containing the request JSON. If provided, other parameters won't be considered. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Case.title | String | The title of the case. |
| Elasticsearch.Kibana.Case.id | String | The case ID. |
| Elasticsearch.Kibana.Case.description | String | The description of the case. |
| Elasticsearch.Kibana.Case.owner | String | The owner of the case. |
| Elasticsearch.Kibana.Case.severity | String | The severity of the case. |
| Elasticsearch.Kibana.Case.status | String | The status of the case. |
| Elasticsearch.Kibana.Case.created_at | Date | The creation date of the case. |
| Elasticsearch.Kibana.Case.connector.type | String | The connector type of the case. |

### es-kibana-case-delete

***
Deletes one or more cases by ID.

#### Base Command

`es-kibana-case-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The cases that you want to remove. To get the case identifiers, use es-kibana-case-list. | Required |

#### Context Output

There is no context output for this command.

### es-kibana-case-list

***
Retrieves the details of Kibana cases.

#### Base Command

`es-kibana-case-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use the search cases API (leave empty). | Optional |
| assignees | Filters the returned cases by assignees. Valid values are none or unique identifiers for the user profiles. | Optional |
| category | Filters the returned cases by category. | Optional |
| default_search_operator | The default operator to use for the simple_query_string. | Optional |
| search | An Elasticsearch simple_query_string query that filters the objects in the response. | Optional |
| from | Returns only cases that were created after a specific date (KQL data range or date match expression). | Optional |
| to | Returns only cases that were created before a specific date (KQL data range or date match expression). | Optional |
| owner | A filter to limit the response to a specific set of applications. | Optional |
| reporters | Filters the returned cases by the user name of the reporter. | Optional |
| search_fields | The fields to perform the simple_query_string parsed query against. | Optional |
| severity | The severity of the case. | Optional |
| sort_field | Determines which field is used to sort the results. | Optional |
| sort_order | Determines the sort order. | Optional |
| status | Filters the returned cases by state. | Optional |
| tags | Filters the returned cases by tags. | Optional |
| page | The page number from which to start a search. | Optional |
| size | The number of items to return. Limited to 100 items. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Case.title | String | The title of the case. |
| Elasticsearch.Kibana.Case.id | String | The case ID. |
| Elasticsearch.Kibana.Case.description | String | The description of the case. |
| Elasticsearch.Kibana.Case.owner | String | The owner of the case. |
| Elasticsearch.Kibana.Case.severity | String | The severity of the case. |
| Elasticsearch.Kibana.Case.status | String | The status of the case. |
| Elasticsearch.Kibana.Case.created_at | Date | The creation date of the case. |
| Elasticsearch.Kibana.Case.connector.type | String | The connector type of the case. |

### es-kibana-case-alerts-list

***
Retrieves all alerts for a case.

#### Base Command

`es-kibana-case-alerts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use es-kibana-case-list. | Required |
| limit | Limit on the number of keys to return. | Optional |
| offset | Starting record index to begin retrieving records from. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Case.Alert.id | String | The alert ID. |
| Elasticsearch.Kibana.Case.Alert.index | String | The alert index. |
| Elasticsearch.Kibana.Case.Alert.attached_at | Date | The date the alert was attached to the case. |

### es-kibana-case-comment-add

***
Add a case comment or alert.

#### Base Command

`es-kibana-case-comment-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use es-kibana-case-list. | Required |
| alert_id | The alert identifiers. Required only when type is alert. | Optional |
| index | The alert indices. Required only when type is alert. | Optional |
| owner | The application that owns the cases: Stack Management, Observability, or Elastic Security. | Required |
| rule_id | The rule identifier. | Optional |
| rule_name | The rule name. | Optional |
| type | The type of comment. | Required |
| comment | The new comment. Required only when type is user. Maximum length is 30000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Case.id | String | The case ID. |
| Elasticsearch.Kibana.Case.comments.comment | String | The comment text. |
| Elasticsearch.Kibana.Case.comments.created_by.username | String | The user who created the comment. |

### es-kibana-case-comment-update

***
Update a case comment or alert.

#### Base Command

`es-kibana-case-comment-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use es-kibana-case-list. | Required |
| comment_id | The identifier for the comment. | Optional |
| comment | The new comment. Required only when type is user. Maximum length is 30000. | Optional |
| alert_id | The alert identifiers. Required only when type is alert. | Optional |
| index | The alert indices. Required only when type is alert. | Optional |
| owner | The application that owns the cases: Stack Management, Observability, or Elastic Security. | Required |
| rule_id | The rule identifier. | Optional |
| rule_name | The rule name. | Optional |
| type | The type of comment. | Required |
| version | The current comment version. To retrieve version values, use the get comments API. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Case.id | String | The case ID. |
| Elasticsearch.Kibana.Case.comments.comment | String | The comment text. |
| Elasticsearch.Kibana.Case.comments.updated_by.username | String | The user who updated the comment. |
| Elasticsearch.Kibana.Case.comments.updated_at | Date | The date the comment was updated. |

### es-kibana-case-comment-delete

***
Deletes all comments and alerts from a case.

#### Base Command

`es-kibana-case-comment-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use es-kibana-case-list. | Required |

#### Context Output

There is no context output for this command.

### es-kibana-case-file-attach

***
Attach a file to a case.

#### Base Command

`es-kibana-case-file-attach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use es-kibana-case-list. | Required |
| entry_id | Entry ID for the file that needs to be attached. | Required |
| file_name | The desired name of the file being attached to the case (without file extension). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Case.id | String | The case ID. |
| Elasticsearch.Kibana.Case.comments.updated_by.username | String | The user who attached the file. |

### es-kibana-endpoint-exception-list-item-create

***
Create an Elastic Endpoint exception list item, and associate it with the Elastic Endpoint exception list.

#### Base Command

`es-kibana-endpoint-exception-list-item-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| description | Describes the exception list. | Optional |
| entries_field | A string that does not contain only whitespace characters. | Optional |
| entries_list_id | Value list's identifier. | Optional |
| entries_list_type | Specifies the Elasticsearch data type of excludes the list container holds. | Optional |
| entries_operator | The exception item entry operator. | Optional |
| entries_type | The exception item entry type. | Optional |
| item_id | Human readable string identifier, e.g. trusted-linux-processes. | Optional |
| meta | Additional properties are allowed (JSON object). | Optional |
| name | Exception list name. Minimum length is 1. | Optional |
| os_types | Use this field to specify the operating system. | Optional |
| tags | String array containing words and phrases to help categorize exception items. | Optional |
| entry_id | Entry ID for the file containing the full request JSON. If provided, other parameters won't be considered. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.EndpointExceptionListItem.id | String | The exception list item ID. |
| Elasticsearch.Kibana.EndpointExceptionListItem.item_id | String | The exception list item human-readable ID. |
| Elasticsearch.Kibana.EndpointExceptionListItem.list_id | String | The exception list ID. |
| Elasticsearch.Kibana.EndpointExceptionListItem.name | String | The exception list item name. |
| Elasticsearch.Kibana.EndpointExceptionListItem.description | String | The exception list item description. |
| Elasticsearch.Kibana.EndpointExceptionListItem.created_at | Date | The creation date of the exception list item. |

### es-kibana-endpoint-exception-list-item-update

***
Update an Elastic Endpoint exception list item.

#### Base Command

`es-kibana-endpoint-exception-list-item-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| exception_list_item_id | Exception's identifier. | Optional |
| item_id | Human readable string identifier, e.g. trusted-linux-processes. | Optional |
| _version | The version id, normally returned by the API when the item is retrieved. | Optional |
| description | Describes the exception list. | Optional |
| entries_field | A string that does not contain only whitespace characters. | Optional |
| entries_list_id | Value list's identifier. | Optional |
| entries_list_type | Specifies the Elasticsearch data type of excludes the list container holds. | Optional |
| entries_operator | The exception item entry operator. | Optional |
| entries_type | The exception item entry type. | Optional |
| entries_value | A string that does not contain only whitespace characters. | Optional |
| meta | Additional properties are allowed (JSON object). | Optional |
| name | Exception list name. Minimum length is 1. | Optional |
| os_types | Use this field to specify the operating system. | Optional |
| tags | String array containing words and phrases to help categorize exception items. | Optional |
| entry_id | Entry ID for the file containing the full request JSON. If provided, other parameters won't be considered. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.EndpointExceptionListItem.id | String | The exception list item ID. |
| Elasticsearch.Kibana.EndpointExceptionListItem.item_id | String | The exception list item human-readable ID. |
| Elasticsearch.Kibana.EndpointExceptionListItem.list_id | String | The exception list ID. |
| Elasticsearch.Kibana.EndpointExceptionListItem.name | String | The exception list item name. |
| Elasticsearch.Kibana.EndpointExceptionListItem.description | String | The exception list item description. |
| Elasticsearch.Kibana.EndpointExceptionListItem.created_at | Date | The creation date of the exception list item. |

### es-kibana-endpoint-exception-list-item-delete

***
Delete an Elastic Endpoint exception list item.

#### Base Command

`es-kibana-endpoint-exception-list-item-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| item_id | Either id or item_id must be specified. | Required |

#### Context Output

There is no context output for this command.

### es-kibana-endpoint-exception-list-item-list

***
Retrieves Elastic Endpoint exception list items.

#### Base Command

`es-kibana-endpoint-exception-list-item-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| filter | Filters the returned results according to the value of the specified field, using the <field name>:<field value> syntax. | Optional |
| item_id | Either id or item_id must be specified. | Optional |
| sort_field | Determines which field is used to sort the results. | Optional |
| sort_order | Determines the sort order. | Optional |
| page | The page number to return. Minimum value is 0. | Optional |
| size | The number of exception list items to return per page. Minimum value is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.EndpointExceptionListItem.id | String | The exception list item ID. |
| Elasticsearch.Kibana.EndpointExceptionListItem.item_id | String | The exception list item human-readable ID. |
| Elasticsearch.Kibana.EndpointExceptionListItem.list_id | String | The exception list ID. |
| Elasticsearch.Kibana.EndpointExceptionListItem.name | String | The exception list item name. |
| Elasticsearch.Kibana.EndpointExceptionListItem.description | String | The exception list item description. |
| Elasticsearch.Kibana.EndpointExceptionListItem.created_at | Date | The creation date of the exception list item. |

### es-kibana-exception-list-list

***
Get a list of all exception list containers.

#### Base Command

`es-kibana-exception-list-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| exception_list_id | Exception list's identifier. Either id or list_id must be specified. | Optional |
| list_id | Human readable exception list string identifier. Either id or list_id must be specified. | Optional |
| filter | Filters the returned results according to the value of the specified field. | Optional |
| namespace_type | Determines whether the returned containers are Kibana associated with a Kibana space or available in all spaces. | Optional |
| sort_field | Determines which field is used to sort the results. | Optional |
| sort_order | Determines the sort order. | Optional |
| page | The page number to return. Minimum value is 1. | Optional |
| size | The number of exception lists to return per page. Minimum value is 1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.ExceptionList.id | String | The exception list ID. |
| Elasticsearch.Kibana.ExceptionList.list_id | String | The human-readable exception list ID. |
| Elasticsearch.Kibana.ExceptionList.name | String | The exception list name. |
| Elasticsearch.Kibana.ExceptionList.description | String | The exception list description. |
| Elasticsearch.Kibana.ExceptionList.created_at | Date | The creation date of the exception list. |

### es-kibana-exception-list-create

***
Create an exception list.

#### Base Command

`es-kibana-exception-list-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| description | Describes the exception list. | Optional |
| list_id | The exception list's human-readable string identifier. | Optional |
| meta | Placeholder for metadata about the list container (JSON object). | Optional |
| name | The name of the exception list. | Optional |
| namespace_type | Determines whether the returned containers are Kibana associated with a Kibana space or available in all spaces. | Optional |
| os_types | Use this field to specify the operating system. Only enter one value. | Optional |
| tags | String array containing words and phrases to help categorize exception containers. | Optional |
| type | The type of exception list to be created. | Required |
| version | The document version automatically increased on updates. | Optional |
| entry_id | Entry ID for the file containing the request JSON. If provided, other parameters won't be considered. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.ExceptionList.id | String | The exception list ID. |
| Elasticsearch.Kibana.ExceptionList.list_id | String | The human-readable exception list ID. |
| Elasticsearch.Kibana.ExceptionList.name | String | The exception list name. |
| Elasticsearch.Kibana.ExceptionList.description | String | The exception list description. |
| Elasticsearch.Kibana.ExceptionList.created_at | Date | The creation date of the exception list. |

### es-kibana-exception-list-update

***
Updates an existing exception list.

#### Base Command

`es-kibana-exception-list-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| _version | The version id, normally returned by the API when the item was retrieved. | Optional |
| description | Describes the exception list. | Required |
| exception_list_id | Exception list's identifier. | Optional |
| list_id | The exception list's human-readable string identifier. | Optional |
| meta | Placeholder for metadata about the list container (JSON object). | Optional |
| name | The name of the exception list. | Required |
| namespace_type | Determines whether the returned containers are Kibana associated with a Kibana space or available in all spaces. | Optional |
| os_types | Use this field to specify the operating system. Only enter one value. | Optional |
| tags | String array containing words and phrases to help categorize exception containers. | Optional |
| type | The type of exception list to be created. | Required |
| version | The document version automatically increased on updates. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.ExceptionList.id | String | The exception list ID. |
| Elasticsearch.Kibana.ExceptionList.list_id | String | The human-readable exception list ID. |
| Elasticsearch.Kibana.ExceptionList.name | String | The exception list name. |
| Elasticsearch.Kibana.ExceptionList.description | String | The exception list description. |
| Elasticsearch.Kibana.ExceptionList.created_at | Date | The creation date of the exception list. |

### es-kibana-exception-list-delete

***
Delete an exception list using the id or list_id field.

#### Base Command

`es-kibana-exception-list-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| exception_list_id | Exception list's identifier. Either id or list_id must be specified. | Optional |
| list_id | Human readable exception list string identifier. Either id or list_id must be specified. | Optional |
| namespace_type | Determines whether the returned containers are Kibana associated with a Kibana space or available in all spaces. | Optional |

#### Context Output

There is no context output for this command.

### es-kibana-exception-list-item-list

***
Get a list of all exception list items in the specified list.

#### Base Command

`es-kibana-exception-list-item-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| exception_list_item_id | Exception list item's identifier. Either id or item_id must be specified. | Optional |
| item_id | Human readable exception item string identifier. Either id or item_id must be specified. | Optional |
| exception_list_id | The list_ids of the items to fetch. | Optional |
| filter | Filters the returned results according to the value of the specified field, using the <field name>:<field value> syntax. | Optional |
| namespace_type | Determines whether the returned containers are Kibana associated with a Kibana space or available in all spaces. | Optional |
| search | Free-text search term applied to exception list item fields. | Optional |
| sort_field | Determines which field is used to sort the results. | Optional |
| sort_order | Determines the sort order. | Optional |
| page | The page number to return. Minimum value is 0. | Optional |
| size | The number of exception list items to return per page. Minimum value is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.ExceptionListItem.id | String | The exception list item ID. |
| Elasticsearch.Kibana.ExceptionListItem.item_id | String | The exception list item human-readable ID. |
| Elasticsearch.Kibana.ExceptionListItem.list_id | String | The exception list ID. |
| Elasticsearch.Kibana.ExceptionListItem.name | String | The exception list item name. |
| Elasticsearch.Kibana.ExceptionListItem.description | String | The exception list item description. |
| Elasticsearch.Kibana.ExceptionListItem.created_at | Date | The creation date of the exception list item. |

### es-kibana-exception-list-item-create

***
Create an exception item and associate it with the specified exception list.

#### Base Command

`es-kibana-exception-list-item-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| comment | A string that does not contain only whitespace characters. | Optional |
| description | Describes the exception list. | Optional |
| expire_time | The exception item's expiration date, in ISO format. | Optional |
| item_id | Human readable string identifier, e.g. trusted-linux-processes. | Optional |
| meta | Additional properties are allowed (JSON object). | Optional |
| name | Exception list name. | Optional |
| namespace_type | Determines whether the returned containers are Kibana associated with a Kibana space or available in all spaces. | Optional |
| type | The type of exception list to be created. | Optional |
| entries_field | A string that does not contain only whitespace characters. | Optional |
| entries_operator | The exception item entry operator. | Optional |
| entries_type | The exception item entry type. | Optional |
| entries_value | The exception item entry value. | Optional |
| entries_list_id | Value list's identifier. | Optional |
| entries_list_type | Specifies the Elasticsearch data type of excludes the list container holds. | Optional |
| list_id | The exception list's human-readable string identifier. | Optional |
| os_types | Use this field to specify the operating system. Only enter one value. | Optional |
| tags | String array containing words and phrases to help categorize exception containers. | Optional |
| entry_id | Entry ID for the file containing the request JSON. If provided, other parameters won't be considered. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.ExceptionListItem.id | String | The exception list item ID. |
| Elasticsearch.Kibana.ExceptionListItem.item_id | String | The exception list item human-readable ID. |
| Elasticsearch.Kibana.ExceptionListItem.list_id | String | The exception list ID. |
| Elasticsearch.Kibana.ExceptionListItem.name | String | The exception list item name. |
| Elasticsearch.Kibana.ExceptionListItem.description | String | The exception list item description. |
| Elasticsearch.Kibana.ExceptionListItem.created_at | Date | The creation date of the exception list item. |

### es-kibana-exception-item-list-update

***
Updates an existing exception list item.

#### Base Command

`es-kibana-exception-item-list-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| _version | The version ID, normally returned by the API when the item is retrieved. | Optional |
| comment | A string that does not contain only whitespace characters. | Optional |
| comment_id | A string that does not contain only whitespace characters. | Optional |
| description | Describes the exception list. | Optional |
| expire_time | The exception item's expiration date, in ISO format. | Optional |
| exception_list_item_id | Exception's identifier. | Optional |
| item_id | Human readable string identifier, e.g. trusted-linux-processes. | Optional |
| meta | Additional properties are allowed (JSON object). | Optional |
| name | Exception list name. | Optional |
| namespace_type | Determines whether the returned containers are Kibana associated with a Kibana space or available in all spaces. | Optional |
| type | The type of exception list to be created. | Optional |
| entries_field | A string that does not contain only whitespace characters. | Optional |
| entries_operator | The exception item entry operator. | Optional |
| entries_type | The exception item entry type. | Optional |
| entries_value | The exception item entry value. | Optional |
| entries_list_id | Value list's identifier. | Optional |
| entries_list_type | Specifies the Elasticsearch data type of excludes the list container holds. | Optional |
| list_id | The exception list's human-readable string identifier. | Optional |
| os_types | Use this field to specify the operating system. Only enter one value. | Optional |
| tags | String array containing words and phrases to help categorize exception containers. | Optional |
| entry_id | Entry ID for the file containing the request JSON. If provided, other parameters won't be considered. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.ExceptionListItem.id | String | The exception list item ID. |
| Elasticsearch.Kibana.ExceptionListItem.item_id | String | The exception list item human-readable ID. |
| Elasticsearch.Kibana.ExceptionListItem.list_id | String | The exception list ID. |
| Elasticsearch.Kibana.ExceptionListItem.name | String | The exception list item name. |
| Elasticsearch.Kibana.ExceptionListItem.description | String | The exception list item description. |
| Elasticsearch.Kibana.ExceptionListItem.updated_at | Date | The update date of the exception list item. |

### es-kibana-exception-list-item-delete

***
Deletes an exception list item.

#### Base Command

`es-kibana-exception-list-item-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| exception_list_item_id | Exception list item's identifier. Either id or item_id must be specified. | Optional |
| item_id | Human readable exception item string identifier. Either id or item_id must be specified. | Optional |
| namespace_type | Determines whether the returned containers are Kibana associated with a Kibana space or available in all spaces. | Optional |

#### Context Output

There is no context output for this command.

### es-kibana-value-lists-list

***
Retrieves details of a value list (the list container).

#### Base Command

`es-kibana-value-lists-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| value_list_id | Value list identifier (id) returned when the list was created. | Optional |
| filter | Filters the returned results according to the value of the specified field, using the <field name>:<field value> syntax. | Optional |
| cursor | Returns the lists that come after the last lists returned in the previous call. | Optional |
| sort_field | Determines which field is used to sort the results. | Optional |
| sort_order | Determines the sort order. | Optional |
| page | The page number to return. | Optional |
| size | The number of value lists to return per page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.ValueList.id | String | The value list ID. |
| Elasticsearch.Kibana.ValueList.name | String | The value list name. |
| Elasticsearch.Kibana.ValueList.description | String | The value list description. |
| Elasticsearch.Kibana.ValueList.created_at | Date | The creation date of the value list. |

### es-kibana-value-list-item-get

***
Retrieves value list items.

#### Base Command

`es-kibana-value-list-item-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| value_list_item_id | Value list item identifier. Required if list_id and value are not specified. | Optional |
| value_list_id | Parent value list's id to page through items for. | Optional |
| value | The value used to evaluate exceptions. Required if id is not specified. | Optional |
| filter | Filters the returned results according to the value of the specified field, using the <field name>:<field value> syntax. | Optional |
| cursor | Opaque cursor returned in a previous response; pass it to continue listing from the next page. | Optional |
| sort_field | Determines which field is used to sort the results. | Optional |
| sort_order | Determines the sort order. | Optional |
| page | The page number to return. | Optional |
| size | The number of list items to return per page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.ValueListItem.id | String | The value list item ID. |
| Elasticsearch.Kibana.ValueListItem.list_id | String | The value list ID. |
| Elasticsearch.Kibana.ValueListItem.name | String | The value list item name. |
| Elasticsearch.Kibana.ValueListItem.description | String | The value list item description. |
| Elasticsearch.Kibana.ValueListItem.created_at | Date | The creation date of the value list item. |

### es-kibana-value-list-item-create

***
Adds a new item to a value list.

#### Base Command

`es-kibana-value-list-item-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| value_list_id | Value list's identifier. | Required |
| meta | Placeholder for metadata about the value list item (JSON object). Example {"source":"threatfeed","priority":3,"active":true}. | Optional |
| refresh | Determines when changes made by the request are made visible to search. | Optional |
| value | The value used to evaluate exceptions. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.ValueListItem.id | String | The value list item ID. |
| Elasticsearch.Kibana.ValueListItem.list_id | String | The value list ID. |
| Elasticsearch.Kibana.ValueListItem.name | String | The value list item name. |
| Elasticsearch.Kibana.ValueListItem.description | String | The value list item description. |
| Elasticsearch.Kibana.ValueListItem.created_at | Date | The creation date of the value list item. |

### es-kibana-value-list-item-update

***
Updates an existing value list item.

#### Base Command

`es-kibana-value-list-item-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| _version | The version id, normally returned by the API when the document is retrieved. | Optional |
| value_list_item_id | Value list item identifier. | Required |
| meta | Placeholder for metadata about the value list item (JSON object). Example {"source":"threatfeed","priority":3,"active":true}. | Optional |
| value | The value used to evaluate exceptions. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.ValueListItem.id | String | The value list item ID. |
| Elasticsearch.Kibana.ValueListItem.list_id | String | The value list ID. |
| Elasticsearch.Kibana.ValueListItem.name | String | The value list item name. |
| Elasticsearch.Kibana.ValueListItem.description | String | The value list item description. |
| Elasticsearch.Kibana.ValueListItem.created_at | Date | The creation date of the value list item. |

### es-kibana-value-list-item-delete

***
Deletes a value list item.

#### Base Command

`es-kibana-value-list-item-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| value_list_item_id | Value list item's identifier. Required if list_id and value are not specified. | Optional |
| value_list_id | Value list's identifier. | Optional |
| value | The value used to evaluate exceptions. Required if id is not specified. | Optional |
| refresh | Determines when changes made by the request are made visible to search. | Optional |

#### Context Output

There is no context output for this command.

### es-kibana-value-list-item-export

***
Exports all items of a value list as a file (returned to the War Room).

#### Base Command

`es-kibana-value-list-item-export`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| value_list_id | Value list's id to export. | Optional |

#### Context Output

There is no context output for this command.

### es-kibana-value-list-item-import

***
Import value list items from a TXT or CSV file.

#### Base Command

`es-kibana-value-list-item-import`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| value_list_id | List's id to import. | Optional |
| type | Type of the importing list. | Optional |
| refresh | Determines when changes made by the request are made visible to search. | Optional |
| entry_id | Entry ID for the file containing the items to import. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.ValueListItem.id | String | The value list item ID. |
| Elasticsearch.Kibana.ValueListItem.list_id | String | The value list ID. |
| Elasticsearch.Kibana.ValueListItem.name | String | The value list item name. |
| Elasticsearch.Kibana.ValueListItem.description | String | The value list item description. |
| Elasticsearch.Kibana.ValueListItem.created_at | Date | The creation date of the value list item. |
