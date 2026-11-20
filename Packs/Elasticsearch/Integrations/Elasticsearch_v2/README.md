Elasticsearch_v2 integration is used to search for and analyze data in real time.
Supports version 6 and later.
This integration was integrated and tested with versions 6.6.2, 7.3, 8.4.1 of Elasticsearch.

## Permissions

The permissions required to use this integration depends on which operations you need to perform. The API user should have the same permissions a regular user would have in order to access the data via the UI. Following are the permissions needed for certain commands:

- **!es-eql-search/search/es-search/fetch-incidents** - If the Elasticsearch security features are enabled, you must have the *read* [index privilege](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-privileges.html#privileges-list-indices) for the target data stream, index, or alias.
- **!get-mapping-fields** - If the Elasticsearch security features are enabled, you must have the *view_index_metadata* or *manage* [index privilege](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-privileges.html#privileges-list-indices) for the target data stream, index, or alias.
- **!es-index** - If the Elasticsearch security features are enabled, you must have the *write* [index privilege](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-privileges.html#privileges-list-indices) for the target data stream, index, or alias.
- **!es-kibana-* commands** - To execute Kibana commands, you must have the necessary privileges for the applicable resource. The privilege required depends on the command you are using. Kibana API endpoints are gated by feature privileges granted at one of two levels: *Read* (GET / list / view operations) and *All* (POST / PUT / PATCH / DELETE operations). For rules and cases, the privilege is scoped to the feature that owns the object — a Security-owned object requires the **Security** feature privilege, an Observability-owned object requires the **Observability** feature privilege, and a stack-owned object requires the **Management** / **Stack Rules** feature privilege.
- **!es-kibana-endpoint-isolate / !es-kibana-endpoint-unisolate / !es-kibana-endpoint-execute-command** - These are active endpoint response actions: isolation and unisolation change endpoint connectivity, and execute-command runs a shell command on the endpoint. They require the applicable endpoint response-action privileges. Existing integration instances may not have these privileges and can receive a 403 response.
- **!es-kibana-endpoint-agent-get** - Requires the `fleet-agents-read` privilege to retrieve a Fleet agent.

## Configure Elasticsearch v2 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Elasticsearch server to which the integration connects. Ensure that the URL includes the correct Elasticsearch port. The default port for Elasticsearch v7 and below is 9200. Use the Server URL for on-premises deployments. | False |
| Kibana Server URL | The Kibana server used by the es-kibana-\* commands and by fetching and mirroring security alerts and cases. Required for on-premises \(self-managed\) deployments, where Kibana is usually hosted separately from Elasticsearch \(for example, https://kibana.example.com:5601\). If left empty, the Kibana URL is derived from the Server URL, which is supported only for Elastic Cloud deployments whose hostname contains ".es." \(the segment is replaced with ".kb."\). | False |
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
| Space ID | The default Kibana space ID to use for es-kibana-* commands. Used to derive the Kibana base URL from the Server URL. If a `space_id` argument is provided to a command, it overrides this value. See [Spaces](https://www.elastic.co/docs/deploy-manage/manage-spaces) for more information. | False |
| Fetch incident types | The type of incident to fetch from Elasticsearch (Elasticsearch Entity, Elasticsearch Security Alert, or Elasticsearch Case). | False |
| Incident Mirroring Direction | Mirroring works only for the Elasticsearch Security Alert and Elasticsearch Case incident types. | False |
| Fetch cases by Severity | Case severities to fetch. If none are chosen, all severity levels will be returned. Relevant only for incident type Elasticsearch Case. | False |
| Fetch cases by Status | Case statuses to fetch. If none are chosen, in-progress and open will be returned. Relevant only for incident type Elasticsearch Case. | False |
| Fetch alerts for case | When enabled, fetches alerts associated with each Elasticsearch Case. You must have read privileges for the Cases feature in the Management, Observability, or Security section of the Kibana feature privileges. | False |
| Close Mirrored XSOAR Incident | Whether closing the Elasticsearch alert or case is mirrored in Cortex XSOAR. | False |
| Close Mirrored Elasticsearch Incident | Whether closing the Cortex XSOAR incident is mirrored in Elasticsearch. | False |

## Fetch

Use the **Fetch incident types** parameter to select what to fetch from Elasticsearch: the default **Elasticsearch Entity**, **Elasticsearch Security Alert**, or **Elasticsearch Case**.

Mirroring is only available for Elasticsearch Security Alerts and Cases.

### Fetch

The default fetch behavior. Configure the **Index to fetch incidents from**, **Query String**, and/or **Raw Query** fields to fetch generic Elasticsearch documents as incidents.

### Fetch Security Alerts

To fetch security alerts, set the **Index to fetch incidents from** to one of these patterns: `.internal.alerts-security.alerts-*` or `.siem-signals-*`. Use the **Query String** field (Lucene syntax) to filter the alerts (for example, `*` to fetch all alerts). The **Index time field**, **First fetch timestamp**, and **The maximum number of results per fetch** parameters are applied to the query.

**Note:** When the **Raw Query** field is set, it overrides the **Query String**. The time range, sort, and maximum number of results are not applied to it, and Elasticsearch defaults are used instead (for example, 10 results in relevance order). Because the same alerts are returned in every fetch cycle and are already fetched, no new incidents are created after the first cycle. If you use **Raw Query**, add a time range filter, a sort, and a `size` to the query, for example:

```json
{
  "query": {
    "bool": {
      "must": [{"match_all": {}}],
      "filter": [{"range": {"@timestamp": {"gte": "now-15m"}}}]
    }
  },
  "sort": [{"@timestamp": "asc"}],
  "size": 200
}
```

### Fetch Cases

Use the **Fetch cases by Severity** parameter to filter cases by the required severity and the **Fetch cases by Status** parameter to filter cases by the required status. Enable **Fetch alerts for case** to also retrieve the alerts associated with each case.

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Elasticsearch (Kibana) Security Alerts and Cases.

Mirroring is only available for **Elasticsearch Security Alert** and **Elasticsearch Case** incident types.

To set up mirroring:

1. Enable **Fetch incidents** in your instance configuration.
2. In the **Fetch incident types** parameter, select **Elasticsearch Security Alert** or **Elasticsearch Case**.
3. In the **Incident Mirroring Direction** parameter, select in which direction the incidents should be mirrored:
    - **Incoming** - Changes in Elasticsearch (status, tags, workflow reason, case fields) are reflected in Cortex XSOAR.
    - **Outgoing** - Changes in Cortex XSOAR are reflected in Elasticsearch.
    - **Incoming And Outgoing** - Changes are mirrored in both directions.
4. Optionally, select **Close Mirrored XSOAR Incident** to close the Cortex XSOAR incident when the Elasticsearch alert/case is closed, and **Close Mirrored Elasticsearch Incident** to close the Elasticsearch alert/case when the Cortex XSOAR incident is closed.

**Notes:**

- The mirroring is affected by the following integration parameters: **Incident Mirroring Direction**, **Close Mirrored XSOAR Incident**, and **Close Mirrored Elasticsearch Incident**.
- To ensure mirroring works as expected, mappers are required so that the fields are properly mapped to and from Elasticsearch. Select the appropriate incoming and outgoing mappers per incident type (**Elasticsearch Security Alert - Incoming/Outgoing Mapper** and **Elasticsearch Case - Incoming/Outgoing Mapper**).
- Set the **Fetch incident types** parameter even when mirroring only. It is used to resolve the incident type when the remote lookup is unavailable; without it, changes may not be mirrored out.
- Mirroring **out** always uses the Kibana API, because the security alert indices are Kibana system indices and writing to them directly would skip Kibana's bookkeeping (such as `kibana.alert.workflow_status_updated_at`, which mirroring in relies on). The configured credentials therefore need the **Security → Alerts: All** Kibana privilege, and the **Space ID** must match the space that owns the alerts. If either is wrong, the fetch keeps working while mirroring out reports that 0 alerts were updated.

#### Which Security Alert fields can be mirrored

Elasticsearch only allows a detection alert's **workflow status**, **status reason**, and **workflow tags** to be changed. These are the only fields mirrored out:

| Cortex XSOAR incident field | Elasticsearch field |
| --- | --- |
| Elasticsearch Workflow Alert Status | `kibana.alert.workflow_status` |
| Elasticsearch Workflow Alert Status Reason | `kibana.alert.workflow_reason` |
| Tags | `kibana.alert.workflow_tags` |

Other fields, such as **severity**, **risk score**, or the detection rule, cannot be pushed back to Elasticsearch because no API exists to change them on an existing alert. Editing those fields in Cortex XSOAR updates the local incident only, and an error is written to the log explaining that nothing was mirrored out. These fields are still mirrored **in** (from Elasticsearch to Cortex XSOAR).

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

#### Command Example

```!es-esql-search query="FROM logs-* | WHERE host.name == \"web-01\" | LIMIT 5"```

#### Context Example

```json
{
    "Elasticsearch": {
        "ESQLSearch": [
            {
                "@timestamp": "2024-01-15T10:23:45.000Z",
                "host.name": "web-01",
                "message": "Connection established"
            }
        ]
    }
}
```

#### Human Readable Output

>### Search query
>
>|Query|Total|
>|---|---|
>| FROM logs-* \| WHERE host.name == "web-01" \| LIMIT 5 | 1 |
>
>### Results
>
>|@timestamp|host.name|message|
>|---|---|---|
>| 2024-01-15T10:23:45.000Z | web-01 | Connection established |

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

#### Command Example

```!es-kibana-alerting-health-get```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "AlertingHealth": {
                "is_sufficiently_secure": true,
                "has_permanent_encryption_key": true,
                "alerting_framework_health": {
                    "decryption_health": {"status": "ok"},
                    "execution_health": {"status": "ok"},
                    "read_health": {"status": "ok"}
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Alerting Framework Health
>
>|Is sufficiently secure|Has permanent encryption key|Decryption status|Execution status|Read status|
>|---|---|---|---|---|
>| true | true | ok | ok | ok |

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

#### Command Example

```!es-kibana-rule-types-list```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "RuleType": [
                {
                    "id": ".index-threshold",
                    "name": "Index threshold",
                    "category": "management",
                    "producer": "stackAlerts",
                    "action_groups": [{"id": "threshold met"}, {"id": "recovered"}]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Kibana Rule Types
>
>|Rule type ID|Name|Category|Producer|Action Group Id|
>|---|---|---|---|---|
>| .index-threshold | Index threshold | management | stackAlerts | threshold met, recovered |

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
| search | An Elasticsearch `simple_query_string` query that filters the objects in the response. | Optional |
| default_search_operator | The default operator to use for the `simple_query_string`. | Optional |
| search_fields | The fields to perform the `simple_query_string` parsed query against. | Optional |
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

#### Command Example

```!es-kibana-rule-list rule_id="1234"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "Rule": {
                "id": "1234",
                "enabled": true,
                "name": "CPU threshold alert",
                "rule_type_id": ".index-threshold",
                "created_at": "2024-01-10T08:00:00.000Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Rules
>
>|Rule ID|Enabled|Name|Type ID|Creation date|
>|---|---|---|---|---|
>| 1234 | true | CPU threshold alert | .index-threshold | 2024-01-10T08:00:00.000Z |

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

#### Command Example

```!es-kibana-rule-enable rule_id="1234"```

#### Context Example

```json
{}
```

#### Human Readable Output

>The rule 1234 has been successfully enabled.

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

#### Command Example

```!es-kibana-rule-disable rule_id="1234"```

#### Context Example

```json
{}
```

#### Human Readable Output

>The rule 1234 has been successfully disabled.

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

#### Command Example

```!es-kibana-rule-update rule_id="1234" name="Updated CPU alert" schedule_interval="5m"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "Rule": {
                "id": "1234",
                "name": "Updated CPU alert",
                "enabled": true,
                "rule_type_id": ".index-threshold",
                "created_at": "2024-01-10T08:00:00.000Z"
            }
        }
    }
}
```

#### Human Readable Output

>The rule 1234 has been successfully changed.
>
>|Rule ID|Changed fields|
>|---|---|
>| 1234 | name, schedule |

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

#### Command Example

```!es-kibana-rule-alert-mute rule_id="1234" mute_all="true"```

#### Context Example

```json
{}
```

#### Human Readable Output

>The alerts have been successfully muted.

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

#### Command Example

```!es-kibana-rule-alert-unmute rule_id="1234" unmute_all="true"```

#### Context Example

```json
{}
```

#### Human Readable Output

>The alerts have been successfully unmuted.

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
| signal_ids | List of alert IDs. Use field `_id` on alert document or `kibana.alert.uuid`. | Optional |
| query | An Elasticsearch query used to select which alerts to update, as an alternative to `signal_ids`. | Optional |
| reason | The reason for the status change. | Optional |
| conflicts | Determines how version conflicts should be handled. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.SecurityAlertSetStatus.total | Number | The total number of alerts matched by the request. |
| Elasticsearch.Kibana.SecurityAlertSetStatus.updated | Number | The number of alerts that were updated. |

#### Command Example

```!es-kibana-detection-alert-status-set status="closed" signal_ids="1234,5678"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "SecurityAlertSetStatus": {
                "total": 2,
                "updated": 2
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Detection Alert Status Update
>
>|Total|Updated|
>|---|---|
>| 2 | 2 |

### es-kibana-endpoint-execute-command

***
Run a shell command on one or more Elastic Defend endpoints.

#### Base Command

`es-kibana-endpoint-execute-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Kibana space ID. | Optional |
| endpoint_ids | Endpoint IDs to run the command on. A maximum of 250 IDs can be specified. | Required |
| agent_type | Agent type. Defaults to `endpoint`. | Optional |
| alert_ids | Alert IDs associated with the action. A maximum of 50 IDs can be specified. | Optional |
| case_ids | Case IDs in which to log the action. A maximum of 50 IDs can be specified. | Optional |
| comment | Optional action comment. Maximum length is 30,000 characters. | Optional |
| command | Shell command to run on the endpoint. | Required |
| timeout | Maximum timeout in seconds. Minimum value is 1; defaults to 1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.agents | String | Agent IDs targeted by the action. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.agentState | Unknown | Response action state for each agent. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.agentType | String | Agent type. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.command | String | Response action command. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.completedAt | String | Action completion time. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.createdBy | String | User who created the action. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.hosts | Unknown | Host names associated with the agents. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.id | String | Response action ID. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.isComplete | Boolean | Whether the action is complete. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.isExpired | Boolean | Whether the action is expired. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.outputs | Unknown | Outputs for each agent. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.parameters | Unknown | Action parameters. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.startedAt | Date | Action start time. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.status | String | Action status. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.wasCancelled | Boolean | Whether the action was cancelled. |
| Elasticsearch.Kibana.EndpointExecuteCommandAction.wasSuccessful | Boolean | Whether the action was successful. |

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "EndpointExecuteCommandAction": {
                "id": "action-1",
                "agents": ["agent-1"],
                "agentType": "endpoint",
                "command": "execute",
                "parameters": {"command": "ls -al", "timeout": 600},
                "isComplete": false,
                "status": "pending",
                "wasSuccessful": false
            }
        }
    }
}
```

#### Command Example

```!es-kibana-endpoint-execute-command endpoint_ids="agent-1" command="ls -al" timeout="600"```

#### Human Readable Output

>### Kibana Endpoint Execute Command Action
>
>|Agents|Agent Type|Command|Id|Is Complete|Parameters|Status|Was Successful|
>|---|---|---|---|---|---|---|---|
>| agent-1 | endpoint | execute | action-1 | false | {"command":"ls -al","timeout":600} | pending | false |

### es-kibana-endpoint-action-details

***
Retrieve the details of a response action by its ID.

#### Base Command

`es-kibana-endpoint-action-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Kibana space ID. | Optional |
| action_id | ID of the response action to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.EndpointGetActionDetails.agents | String | The agent IDs to which the response action was sent. |
| Elasticsearch.Kibana.EndpointGetActionDetails.agentState | Unknown | The response action state for each agent ID. |
| Elasticsearch.Kibana.EndpointGetActionDetails.agentType | String | The agent type. |
| Elasticsearch.Kibana.EndpointGetActionDetails.command | String | The response action command. |
| Elasticsearch.Kibana.EndpointGetActionDetails.completedAt | String | The response action completion time. |
| Elasticsearch.Kibana.EndpointGetActionDetails.createdBy | String | The user who created the response action. |
| Elasticsearch.Kibana.EndpointGetActionDetails.hosts | Unknown | The host names associated with the agent IDs. |
| Elasticsearch.Kibana.EndpointGetActionDetails.id | String | The response action ID. |
| Elasticsearch.Kibana.EndpointGetActionDetails.isComplete | Boolean | Whether the response action is complete. |
| Elasticsearch.Kibana.EndpointGetActionDetails.isExpired | Boolean | Whether the response action is expired. |
| Elasticsearch.Kibana.EndpointGetActionDetails.outputs | Unknown | The response action outputs for each agent ID. |
| Elasticsearch.Kibana.EndpointGetActionDetails.parameters | Unknown | The response action parameters. |
| Elasticsearch.Kibana.EndpointGetActionDetails.startedAt | String | The response action start time. |
| Elasticsearch.Kibana.EndpointGetActionDetails.status | String | The response action status. |
| Elasticsearch.Kibana.EndpointGetActionDetails.wasCancelled | Boolean | Whether the response action was cancelled. |
| Elasticsearch.Kibana.EndpointGetActionDetails.wasSuccessful | Boolean | Whether the response action was successful. |

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "EndpointGetActionDetails": {
                "id": "action-1",
                "agents": ["agent-1"],
                "agentType": "endpoint",
                "command": "execute",
                "parameters": {"command": "ls -al", "timeout": 600},
                "isComplete": true,
                "status": "completed",
                "wasSuccessful": true
            }
        }
    }
}
```

#### Command Example

```!es-kibana-endpoint-action-details action_id="action-1"```

#### Human Readable Output

>### Kibana Endpoint Action Details
>
>|Agents|Agent Type|Command|Id|Is Complete|Parameters|Status|Was Successful|
>|---|---|---|---|---|---|---|---|
>| agent-1 | endpoint | execute | action-1 | true | {"command":"ls -al","timeout":600} | completed | true |

### es-kibana-endpoint-metadata-get

***
Retrieve host metadata for a specific endpoint.

#### Base Command

`es-kibana-endpoint-metadata-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Kibana space ID. | Optional |
| id | Agent ID of the endpoint. Maximum length is 256. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.EndpointMetadataGet.host_status | String | Endpoint host status. |
| Elasticsearch.Kibana.EndpointMetadataGet.last_checkin | String | Endpoint's last check-in time. |
| Elasticsearch.Kibana.EndpointMetadataGet.metadata | Unknown | Endpoint metadata. |

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "EndpointMetadataGet": {
                "host_status": "online",
                "last_checkin": "2026-10-02T12:00:00Z",
                "metadata": {"hostname": "host-1"}
            }
        }
    }
}
```

#### Command Example

```!es-kibana-endpoint-metadata-get id="agent-1"```

#### Human Readable Output

>### Kibana Endpoint Metadata
>
>|Host Status|Last Checkin|Metadata|
>|---|---|---|
>| online | 2026-10-02T12:00:00Z | {"hostname":"host-1"} |

### es-kibana-endpoint-agent-get

***
Retrieve an Elastic Fleet agent by ID. Requires the `fleet-agents-read` privilege.

#### Base Command

`es-kibana-endpoint-agent-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Kibana space ID. | Optional |
| agent_id | The ID of the agent to retrieve. | Required |
| with_metrics | Include CPU and memory metrics. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.EndpointAgentGet.item | Unknown | The agent returned by the request. |

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "EndpointAgentGet": {
                "item": {
                    "id": "agent-1",
                    "status": "online",
                    "local_metadata": {"host": {"hostname": "host-1"}}
                }
            }
        }
    }
}
```

#### Command Example

```!es-kibana-endpoint-agent-get agent_id="agent-1" with_metrics="true"```

#### Human Readable Output

>### Kibana Fleet Agent
>
>|id|status|local_metadata|
>|---|---|---|
>| agent-1 | online | {"host":{"hostname":"host-1"}} |

### es-kibana-endpoint-isolate

***
Isolate an endpoint from the network. The endpoint remains isolated until it's released.

#### Base Command

`es-kibana-endpoint-isolate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| endpoint_ids | Endpoint IDs to isolate. A maximum of 250 IDs can be specified. | Required |
| agent_type | The type of agent on which to run the isolation action. | Optional |
| alert_ids | Alert IDs associated with the action. A maximum of 50 IDs can be specified. | Optional |
| case_ids | Case IDs in which to log the action. A maximum of 50 IDs can be specified. | Optional |
| comment | An optional comment for the isolation action. Maximum length is 30,000 characters. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.EndpointIsolationAction.agents | String | The agent IDs to which the response action was sent. |
| Elasticsearch.Kibana.EndpointIsolationAction.agentState | Unknown | The response action state for each agent ID. |
| Elasticsearch.Kibana.EndpointIsolationAction.agentType | String | The agent type. |
| Elasticsearch.Kibana.EndpointIsolationAction.command | String | The response action command. |
| Elasticsearch.Kibana.EndpointIsolationAction.completedAt | String | The response action completion time. |
| Elasticsearch.Kibana.EndpointIsolationAction.createdBy | String | The user who created the response action. |
| Elasticsearch.Kibana.EndpointIsolationAction.hosts | Unknown | The host names associated with the agent IDs. |
| Elasticsearch.Kibana.EndpointIsolationAction.id | String | The response action ID. |
| Elasticsearch.Kibana.EndpointIsolationAction.isComplete | Boolean | Whether the response action is complete. |
| Elasticsearch.Kibana.EndpointIsolationAction.isExpired | Boolean | Whether the response action is expired. |
| Elasticsearch.Kibana.EndpointIsolationAction.outputs | Unknown | The response action outputs for each agent ID. |
| Elasticsearch.Kibana.EndpointIsolationAction.startedAt | Date | The response action start time. |
| Elasticsearch.Kibana.EndpointIsolationAction.status | String | The response action status. |
| Elasticsearch.Kibana.EndpointIsolationAction.wasCancelled | Boolean | Whether the response action was cancelled. |
| Elasticsearch.Kibana.EndpointIsolationAction.wasSuccessful | Boolean | Whether the response action was successful. |

#### Command Example

```!es-kibana-endpoint-isolate endpoint_ids="endpoint-1,endpoint-2" agent_type="endpoint" comment="Isolating as initial response"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "EndpointIsolationAction": {
                "id": "action-1",
                "agents": ["endpoint-1", "endpoint-2"],
                "agentType": "endpoint",
                "command": "isolate",
                "isComplete": false,
                "status": "pending",
                "wasSuccessful": false
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Endpoint Isolation Action
>
>|Action ID|Agent type|Command|Status|Is Complete|Was Successful|
>|---|---|---|---|---|---|
>| action-1 | endpoint | isolate | pending | false | false |

### es-kibana-endpoint-unisolate

***
Release an isolated endpoint so it can rejoin the network.

#### Base Command

`es-kibana-endpoint-unisolate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Kibana space ID. | Optional |
| endpoint_ids | Endpoint IDs to release. A maximum of 250 IDs can be specified. | Required |
| agent_type | The type of agent on which to run the unisolation action. Defaults to `endpoint`. | Optional |
| alert_ids | Alert IDs associated with the action. A maximum of 50 IDs can be specified. | Optional |
| case_ids | Case IDs in which to log the action. A maximum of 50 IDs can be specified. | Optional |
| comment | An optional comment for the unisolation action. Maximum length is 30,000 characters. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.EndpointUnisolationAction.agents | String | The agent IDs targeted by the action. |
| Elasticsearch.Kibana.EndpointUnisolationAction.agentState | Unknown | The response action state for each agent. |
| Elasticsearch.Kibana.EndpointUnisolationAction.agentType | String | The agent type. |
| Elasticsearch.Kibana.EndpointUnisolationAction.command | String | The response action command. |
| Elasticsearch.Kibana.EndpointUnisolationAction.completedAt | String | The response action completion time. |
| Elasticsearch.Kibana.EndpointUnisolationAction.createdBy | String | The user who created the action. |
| Elasticsearch.Kibana.EndpointUnisolationAction.hosts | Unknown | Host names associated with the agents. |
| Elasticsearch.Kibana.EndpointUnisolationAction.id | String | The response action ID. |
| Elasticsearch.Kibana.EndpointUnisolationAction.isComplete | Boolean | Whether the action is complete. |
| Elasticsearch.Kibana.EndpointUnisolationAction.isExpired | Boolean | Whether the action is expired. |
| Elasticsearch.Kibana.EndpointUnisolationAction.outputs | Unknown | Outputs for each agent. |
| Elasticsearch.Kibana.EndpointUnisolationAction.startedAt | Date | Action start time. |
| Elasticsearch.Kibana.EndpointUnisolationAction.status | String | Action status. |
| Elasticsearch.Kibana.EndpointUnisolationAction.wasCancelled | Boolean | Whether the action was cancelled. |
| Elasticsearch.Kibana.EndpointUnisolationAction.wasSuccessful | Boolean | Whether the action was successful. |

#### Command Example

```!es-kibana-endpoint-unisolate endpoint_ids="endpoint-1,endpoint-2" agent_type="endpoint" comment="Releasing endpoint"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "EndpointUnisolationAction": {
                "id": "action-1",
                "agents": ["endpoint-1", "endpoint-2"],
                "agentType": "endpoint",
                "command": "unisolate",
                "isComplete": true,
                "status": "completed",
                "wasSuccessful": true
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Endpoint Unisolation Action
>
>|Id|Agent Type|Command|Status|Is Complete|Was Successful|
>|---|---|---|---|---|---|
>| action-2 | endpoint | unisolate | completed | true | true |

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
| connector_fields | A JSON object containing the connector fields. To create a case without a connector, specify `null`. | Optional |
| connector_id | The identifier for the connector. To create a case without a connector, use `none`. | Optional |
| connector_name | The name of the connector. To create a case without a connector, use `none`. | Optional |
| connector_type | The type of connector. To create a case without a connector, use `none`. | Optional |
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

#### Command Example

```!es-kibana-case-create owner="securitySolution" title="Suspicious login" description="Multiple failed logins detected" severity="medium"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "Case": {
                "id": "1234",
                "title": "Suspicious login",
                "description": "Multiple failed logins detected",
                "owner": "securitySolution",
                "severity": "medium",
                "status": "open",
                "created_at": "2024-01-15T10:00:00.000Z",
                "connector": {"type": ".none"}
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Case
>
>|Title|ID|Description|Owner|Severity|Status|Created at|Connector type|
>|---|---|---|---|---|---|---|---|
>| Suspicious login | 1234 | Multiple failed logins detected | securitySolution | medium | open | 2024-01-15T10:00:00.000Z | .none |

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
| version | The current version of the case. To determine this value, use `es-kibana-case-list`. | Required |
| assignee_uid | An array containing users that are assigned to the case. Not more than 10 elements. | Optional |
| category | A word or phrase that categorizes the case. Maximum length is 50. | Optional |
| close_reason | The close reason to sync to attached alerts when closing the case. | Optional |
| connector_fields | A JSON object containing the connector fields. To remove a connector, specify `null`. | Optional |
| connector_id | The identifier for the connector. To remove a connector, specify `none`. | Optional |
| connector_name | The name of the connector. To remove a connector, specify `none`. | Optional |
| connector_type | The type of connector. To remove a connector, specify `none`. | Optional |
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

#### Command Example

```!es-kibana-case-update case_id="1234" version="WzEsMV0=" title="Suspicious login - updated" severity="high"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "Case": {
                "id": "1234",
                "title": "Suspicious login - updated",
                "description": "Multiple failed logins detected",
                "owner": "securitySolution",
                "severity": "high",
                "status": "open",
                "created_at": "2024-01-15T10:00:00.000Z",
                "connector": {"type": ".none"}
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Case(s) Updated
>
>|Title|ID|Description|Owner|Severity|Status|Created at|Connector type|
>|---|---|---|---|---|---|---|---|
>| Suspicious login - updated | 1234 | Multiple failed logins detected | securitySolution | high | open | 2024-01-15T10:00:00.000Z | .none |

### es-kibana-case-delete

***
Deletes one or more cases by ID.

#### Base Command

`es-kibana-case-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The cases that you want to remove. To get the case identifiers, use `es-kibana-case-list`. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!es-kibana-case-delete case_id="1234"```

#### Context Example

```json
{}
```

#### Human Readable Output

>The cases 1234 have been successfully deleted.

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

#### Command Example

```!es-kibana-case-list```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "Case": [
                {
                    "id": "1234",
                    "title": "Suspicious login",
                    "description": "Multiple failed logins detected",
                    "owner": "securitySolution",
                    "severity": "medium",
                    "status": "open",
                    "created_at": "2024-01-15T10:00:00.000Z",
                    "connector": {"type": ".none"}
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Kibana Cases
>
>|Title|ID|Description|Owner|Severity|Status|Created at|Connector type|
>|---|---|---|---|---|---|---|---|
>| Suspicious login | 1234 | Multiple failed logins detected | securitySolution | medium | open | 2024-01-15T10:00:00.000Z | .none |

### es-kibana-case-alerts-list

***
Retrieves all alerts for a case.

#### Base Command

`es-kibana-case-alerts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use `es-kibana-case-list`. | Required |
| limit | Limit on the number of keys to return. | Optional |
| offset | Starting record index to begin retrieving records from. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Case.Alert.id | String | The alert ID. |
| Elasticsearch.Kibana.Case.Alert.index | String | The alert index. |
| Elasticsearch.Kibana.Case.Alert.attached_at | Date | The date the alert was attached to the case. |

#### Command Example

```!es-kibana-case-alerts-list case_id="1234"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "Case": {
                "1234": {
                    "Alert": [
                        {
                            "id": "5678",
                            "index": ".alerts-security.alerts-default",
                            "attached_at": "2024-01-15T11:00:00.000Z"
                        }
                    ]
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Alerts for Case 1234
>
>|Case id|Attached at|Alert id|Index|
>|---|---|---|---|
>| 1234 | 2024-01-15T11:00:00.000Z | 5678 | .alerts-security.alerts-default |

### es-kibana-case-comment-add

***
Add a case comment or alert.

#### Base Command

`es-kibana-case-comment-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use `es-kibana-case-list`. | Required |
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

#### Command Example

```!es-kibana-case-comment-add case_id="1234" type="user" owner="securitySolution" comment="Investigated and confirmed malicious activity."```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "Case": {
                "id": "1234",
                "comments": [
                    {
                        "comment": "Investigated and confirmed malicious activity.",
                        "created_by": {"username": "analyst"}
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Case Comment Added
>
>|Case id|Comment|Created by|
>|---|---|---|
>| 1234 | Investigated and confirmed malicious activity. | analyst |

### es-kibana-case-comment-update

***
Update a case comment or alert.

#### Base Command

`es-kibana-case-comment-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use `es-kibana-case-list`. | Required |
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

#### Command Example

```!es-kibana-case-comment-update case_id="1234" comment_id="5678" type="user" owner="securitySolution" comment="Updated: confirmed false positive." version="WzEsMV0="```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "Case": {
                "id": "1234",
                "comments": [
                    {
                        "id": "5678",
                        "comment": "Updated: confirmed false positive.",
                        "updated_by": {"username": "analyst"},
                        "updated_at": "2024-01-15T12:00:00.000Z"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Case Comment Updated
>
>|Case id|Comment|Updated by|Updated at|
>|---|---|---|---|
>| 1234 | Updated: confirmed false positive. | analyst | 2024-01-15T12:00:00.000Z |

### es-kibana-case-comment-delete

***
Deletes all comments and alerts from a case, or a single comment or alert when comment_id is provided.

#### Base Command

`es-kibana-case-comment-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use `es-kibana-case-list`. | Required |
| comment_id | The identifier of the comment or alert to delete. When not provided, all comments and alerts for the case are deleted. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!es-kibana-case-comment-delete case_id="1234"```

#### Context Example

```json
{}
```

#### Human Readable Output

>The comments and alerts for the case 1234 have been successfully deleted.

### es-kibana-case-file-attach

***
Attach a file to a case.

#### Base Command

`es-kibana-case-file-attach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use `es-kibana-case-list`. | Required |
| entry_id | Entry ID for the file that needs to be attached. | Required |
| file_name | The desired name of the file being attached to the case (without file extension). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Case.id | String | The case ID. |
| Elasticsearch.Kibana.Case.comments.updated_by.username | String | The user who attached the file. |

#### Command Example

```!es-kibana-case-file-attach case_id="1234" entry_id="1@1"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "Case": {
                "id": "1234",
                "comments": [
                    {
                        "updated_by": {"username": "analyst"}
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>File successfully attached to case 1234.

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
| item_id | Human readable string identifier, e.g. `trusted-linux-processes`. | Optional |
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

#### Command Example

```!es-kibana-endpoint-exception-list-item-create name="Trusted process" description="Allow known safe process" entries_field="process.name" entries_type="match" entries_operator="included" entries_value="safe_process.exe" os_types="windows"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "EndpointExceptionListItem": {
                "id": "1234",
                "item_id": "trusted-process-1",
                "list_id": "endpoint_list",
                "name": "Trusted process",
                "description": "Allow known safe process",
                "created_at": "2024-01-15T10:00:00.000Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Endpoint Exception List Item
>
>|ID|Item ID|List ID|Name|Description|Creation date|
>|---|---|---|---|---|---|
>| 1234 | trusted-process-1 | endpoint_list | Trusted process | Allow known safe process | 2024-01-15T10:00:00.000Z |

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
| item_id | Human readable string identifier, e.g. `trusted-linux-processes`. | Optional |
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

#### Command Example

```!es-kibana-endpoint-exception-list-item-update item_id="trusted-process-1" name="Trusted process updated" description="Updated description" entries_field="process.name" entries_type="match" entries_operator="included" entries_value="safe_process.exe"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "EndpointExceptionListItem": {
                "id": "1234",
                "item_id": "trusted-process-1",
                "list_id": "endpoint_list",
                "name": "Trusted process updated",
                "description": "Updated description",
                "created_at": "2024-01-15T10:00:00.000Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Endpoint Exception List Item
>
>|ID|Item ID|List ID|Name|Description|Creation date|
>|---|---|---|---|---|---|
>| 1234 | trusted-process-1 | endpoint_list | Trusted process updated | Updated description | 2024-01-15T10:00:00.000Z |

### es-kibana-endpoint-exception-list-item-delete

***
Delete an Elastic Endpoint exception list item.

#### Base Command

`es-kibana-endpoint-exception-list-item-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| item_id | Either `id` or `item_id` must be specified. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!es-kibana-endpoint-exception-list-item-delete item_id="trusted-process-1"```

#### Context Example

```json
{}
```

#### Human Readable Output

>The item trusted-process-1 has been successfully deleted.

### es-kibana-endpoint-exception-list-item-list

***
Retrieves Elastic Endpoint exception list items.

#### Base Command

`es-kibana-endpoint-exception-list-item-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| filter | Filters the returned results according to the value of the specified field, using the `<field name>:<field value>` syntax. | Optional |
| item_id | Either `id` or `item_id` must be specified. | Optional |
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

#### Command Example

```!es-kibana-endpoint-exception-list-item-list```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "EndpointExceptionListItem": [
                {
                    "id": "1234",
                    "item_id": "trusted-process-1",
                    "list_id": "endpoint_list",
                    "name": "Trusted process",
                    "description": "Allow known safe process",
                    "created_at": "2024-01-15T10:00:00.000Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Kibana Endpoint Exception List Items
>
>|ID|Item ID|List ID|Name|Description|Creation date|
>|---|---|---|---|---|---|
>| 1234 | trusted-process-1 | endpoint_list | Trusted process | Allow known safe process | 2024-01-15T10:00:00.000Z |

### es-kibana-exception-list-list

***
Get a list of all exception list containers.

#### Base Command

`es-kibana-exception-list-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| exception_list_id | Exception list's identifier. Either `id` or `list_id` must be specified. | Optional |
| list_id | Human readable exception list string identifier. Either `id` or `list_id` must be specified. | Optional |
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

#### Command Example

```!es-kibana-exception-list-list```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "ExceptionList": [
                {
                    "id": "1234",
                    "list_id": "my-exception-list",
                    "name": "My Exception List",
                    "description": "Exceptions for trusted processes",
                    "created_at": "2024-01-15T10:00:00.000Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Kibana Exception Lists
>
>|Exception list ID|List ID|Name|Description|Creation date|
>|---|---|---|---|---|
>| 1234 | my-exception-list | My Exception List | Exceptions for trusted processes | 2024-01-15T10:00:00.000Z |

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

#### Command Example

```!es-kibana-exception-list-create type="detection" name="My Exception List" description="Exceptions for trusted processes" list_id="my-exception-list"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "ExceptionList": {
                "id": "1234",
                "list_id": "my-exception-list",
                "name": "My Exception List",
                "description": "Exceptions for trusted processes",
                "created_at": "2024-01-15T10:00:00.000Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Exception List
>
>|Exception list ID|List ID|Name|Description|Creation date|
>|---|---|---|---|---|
>| 1234 | my-exception-list | My Exception List | Exceptions for trusted processes | 2024-01-15T10:00:00.000Z |

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

#### Command Example

```!es-kibana-exception-list-update exception_list_id="1234" name="My Exception List Updated" description="Updated description" type="detection"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "ExceptionList": {
                "id": "1234",
                "list_id": "my-exception-list",
                "name": "My Exception List Updated",
                "description": "Updated description",
                "created_at": "2024-01-15T10:00:00.000Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Exception List
>
>|Exception list ID|List ID|Name|Description|Creation date|
>|---|---|---|---|---|
>| 1234 | my-exception-list | My Exception List Updated | Updated description | 2024-01-15T10:00:00.000Z |

### es-kibana-exception-list-delete

***
Delete an exception list using the id or list_id field.

#### Base Command

`es-kibana-exception-list-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| exception_list_id | Exception list's identifier. Either `id` or `list_id` must be specified. | Optional |
| list_id | Human readable exception list string identifier. Either `id` or `list_id` must be specified. | Optional |
| namespace_type | Determines whether the returned containers are Kibana associated with a Kibana space or available in all spaces. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!es-kibana-exception-list-delete list_id="my-exception-list"```

#### Context Example

```json
{}
```

#### Human Readable Output

>The exception list my-exception-list has been successfully deleted.

### es-kibana-exception-list-item-list

***
Get a list of all exception list items in the specified list.

#### Base Command

`es-kibana-exception-list-item-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| exception_list_item_id | Exception list item's identifier. Either `id` or `item_id` must be specified. | Optional |
| item_id | Human readable exception item string identifier. Either `id` or `item_id` must be specified. | Optional |
| exception_list_id | The list_ids of the items to fetch. | Optional |
| filter | Filters the returned results according to the value of the specified field, using the `<field name>:<field value>` syntax. | Optional |
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

#### Command Example

```!es-kibana-exception-list-item-list exception_list_id="my-exception-list"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "ExceptionListItem": [
                {
                    "id": "1234",
                    "item_id": "my-item-1",
                    "list_id": "my-exception-list",
                    "name": "Trusted IP",
                    "description": "Known safe IP address",
                    "created_at": "2024-01-15T10:00:00.000Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Kibana Exception List Items
>
>|ID|Item ID|List ID|Name|Description|Creation date|
>|---|---|---|---|---|---|
>| 1234 | my-item-1 | my-exception-list | Trusted IP | Known safe IP address | 2024-01-15T10:00:00.000Z |

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
| item_id | Human readable string identifier, e.g. `trusted-linux-processes`. | Optional |
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

#### Command Example

```!es-kibana-exception-list-item-create list_id="my-exception-list" name="Trusted IP" description="Known safe IP address" entries_field="source.ip" entries_type="match" entries_operator="included" entries_value="192.168.1.1"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "ExceptionListItem": {
                "id": "1234",
                "item_id": "my-item-1",
                "list_id": "my-exception-list",
                "name": "Trusted IP",
                "description": "Known safe IP address",
                "created_at": "2024-01-15T10:00:00.000Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Exception List Item
>
>|ID|Item ID|List ID|Name|Description|Creation date|
>|---|---|---|---|---|---|
>| 1234 | my-item-1 | my-exception-list | Trusted IP | Known safe IP address | 2024-01-15T10:00:00.000Z |

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
| item_id | Human readable string identifier, e.g. `trusted-linux-processes`. | Optional |
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

#### Command Example

```!es-kibana-exception-item-list-update item_id="my-item-1" name="Trusted IP updated" description="Updated safe IP" entries_field="source.ip" entries_type="match" entries_operator="included" entries_value="192.168.1.1"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "ExceptionListItem": {
                "id": "1234",
                "item_id": "my-item-1",
                "list_id": "my-exception-list",
                "name": "Trusted IP updated",
                "description": "Updated safe IP",
                "updated_at": "2024-01-15T12:00:00.000Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Exception List Item Updated
>
>|Exception list item ID|Item Id|List ID|Name|Description|Update date|
>|---|---|---|---|---|---|
>| 1234 | my-item-1 | my-exception-list | Trusted IP updated | Updated safe IP | 2024-01-15T12:00:00.000Z |

### es-kibana-exception-list-item-delete

***
Deletes an exception list item.

#### Base Command

`es-kibana-exception-list-item-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| exception_list_item_id | Exception list item's identifier. Either `id` or `item_id` must be specified. | Optional |
| item_id | Human readable exception item string identifier. Either `id` or `item_id` must be specified. | Optional |
| namespace_type | Determines whether the returned containers are Kibana associated with a Kibana space or available in all spaces. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!es-kibana-exception-list-item-delete item_id="my-item-1"```

#### Context Example

```json
{}
```

#### Human Readable Output

>The exception list item my-item-1 has been successfully deleted.

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
| filter | Filters the returned results according to the value of the specified field, using the `<field name>:<field value>` syntax. | Optional |
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

#### Command Example

```!es-kibana-value-lists-list```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "ValueList": [
                {
                    "id": "1234",
                    "name": "trusted-ips",
                    "description": "List of trusted IP addresses",
                    "created_at": "2024-01-15T10:00:00.000Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Kibana Value Lists
>
>|Value list ID|Name|Description|Creation date|
>|---|---|---|---|
>| 1234 | trusted-ips | List of trusted IP addresses | 2024-01-15T10:00:00.000Z |

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
| filter | Filters the returned results according to the value of the specified field, using the `<field name>:<field value>` syntax. | Optional |
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

#### Command Example

```!es-kibana-value-list-item-get value_list_id="1234"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "ValueListItem": [
                {
                    "id": "5678",
                    "list_id": "1234",
                    "value": "192.168.1.1",
                    "created_at": "2024-01-15T10:00:00.000Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Kibana Value List Items
>
>|Value list item ID|List ID|Value|Creation date|
>|---|---|---|---|
>| 5678 | 1234 | 192.168.1.1 | 2024-01-15T10:00:00.000Z |

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

#### Command Example

```!es-kibana-value-list-item-create value_list_id="1234" value="10.0.0.1"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "ValueListItem": {
                "id": "5678",
                "list_id": "1234",
                "value": "10.0.0.1",
                "created_at": "2024-01-15T10:00:00.000Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Value List Item
>
>|Value list item ID|List ID|Value|Creation date|
>|---|---|---|---|
>| 5678 | 1234 | 10.0.0.1 | 2024-01-15T10:00:00.000Z |

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

#### Command Example

```!es-kibana-value-list-item-update value_list_item_id="5678" value="10.0.0.2"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "ValueListItem": {
                "id": "5678",
                "list_id": "1234",
                "value": "10.0.0.2",
                "created_at": "2024-01-15T10:00:00.000Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Value List Item
>
>|Value list item ID|List ID|Value|Creation date|
>|---|---|---|---|
>| 5678 | 1234 | 10.0.0.2 | 2024-01-15T10:00:00.000Z |

### es-kibana-value-list-item-delete

***
Deletes a value list item.

#### Base Command

`es-kibana-value-list-item-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| value_list_item_id | Value list item's identifier. Required if `list_id` and `value` are not specified. | Optional |
| value_list_id | Value list's identifier. | Optional |
| value | The value used to evaluate exceptions. Required if id is not specified. | Optional |
| refresh | Determines when changes made by the request are made visible to search. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!es-kibana-value-list-item-delete value_list_item_id="5678"```

#### Context Example

```json
{}
```

#### Human Readable Output

>The value list item 5678 has been successfully deleted.

### es-kibana-value-list-item-export

***
Exports all items of a value list as a file (returned to the War Room).

#### Base Command

`es-kibana-value-list-item-export`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| value_list_id | Value list's ID to export. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!es-kibana-value-list-item-export value_list_id="1234"```

#### Context Example

```json
{}
```

#### Human Readable Output

>The value list 1234 has been exported successfully.

### es-kibana-value-list-item-import

***
Import value list items from a TXT or CSV file.

#### Base Command

`es-kibana-value-list-item-import`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| value_list_id | List's ID to import. | Optional |
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

#### Command Example

```!es-kibana-value-list-item-import value_list_id="1234" entry_id="1@1"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "ValueListItem": {
                "id": "5678",
                "list_id": "1234",
                "value": "10.0.0.1",
                "created_at": "2024-01-15T10:00:00.000Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Value List Item
>
>|Value list item ID|List ID|Value|Creation date|
>|---|---|---|---|
>| 5678 | 1234 | 10.0.0.1 | 2024-01-15T10:00:00.000Z |

### es-update

***
Updates a document in an Elasticsearch index.

#### Base Command

`es-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index_name | The name of the index in which to update. | Required |
| id | The ID of the document to be updated. | Required |
| body | The message body acting as the definition for the requested changes. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.UpdatedDocument.id | String | The ID of the updated document. |
| Elasticsearch.UpdatedDocument.index | String | The name of the index from which the document was updated. |
| Elasticsearch.UpdatedDocument.version | Number | The version number of the updated document. |
| Elasticsearch.UpdatedDocument.result | String | The result of the update operation. |

#### Command Example

```!es-update index_name=test-xsoar id=1234 body="{\"doc\":{\"name\":\"new name\"}}"```

#### Context Example

```json
{
    "Elasticsearch": {
        "UpdatedDocument": {
            "id": "1234",
            "index": "test-xsoar",
            "version": 2,
            "result": "updated"
        }
    }
}
```

#### Human Readable Output

>### Updated document
>
>|ID|Index name|Version|Result|
>|---|---|---|---|
>| 1234 | test-xsoar | 2 | updated |

### es-get-multiple

***
Retrieves multiple documents from Elasticsearch.

#### Base Command

`es-get-multiple`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index_name | The name of the index from which to retrieve the documents. | Optional |
| body | The message body acting as a selector for the documents. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Documents | Unknown | The retrieved documents. |

#### Command Example

```!es-get-multiple index_name=test-xsoar body="{\"docs\":[{\"_id\":\"1234\"},{\"_id\":\"5678\"}]}"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Documents": {
            "docs": [
                {"_index": "test-xsoar", "_id": "1234", "_version": 1, "found": true, "_source": {"name": "test"}},
                {"_index": "test-xsoar", "_id": "5678", "_version": 1, "found": true, "_source": {"name": "test2"}}
            ]
        }
    }
}
```

#### Human Readable Output

>Retrieved 2 documents

### es-get

***
Retrieves a document from an Elasticsearch index.

#### Base Command

`es-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index_name | The name of the index from which to retrieve the document. | Required |
| id | The ID of the document to be retrieved. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Document.id | String | The ID of the retrieved document. |
| Elasticsearch.Document.index | String | The name of the index from which the document was retrieved. |
| Elasticsearch.Document.version | Number | The version number of the retrieved document. |
| Elasticsearch.Document.found | String | Whether the requested document has been found. |

#### Command Example

```!es-get index_name=test-xsoar id=1234```

#### Context Example

```json
{
    "Elasticsearch": {
        "Document": {
            "id": "1234",
            "index": "test-xsoar",
            "version": 1,
            "found": true
        }
    }
}
```

#### Human Readable Output

>### Retrieved document
>
>|ID|Index name|Version|Found|
>|---|---|---|---|
>| 1234 | test-xsoar | 1 | true |

### es-delete

***
Deletes a document from an Elasticsearch index.

#### Base Command

`es-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index_name | The name of the index from which to delete. | Required |
| id | The ID of the document to be deleted. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.DeletedDocument.id | String | The ID of the deleted document. |
| Elasticsearch.DeletedDocument.index | String | The name of the index from which the document was deleted. |
| Elasticsearch.DeletedDocument.version | Number | The version number of the deleted document. |
| Elasticsearch.DeletedDocument.result | String | The result of the delete operation. |

#### Command Example

```!es-delete index_name=test-xsoar id=1234```

#### Context Example

```json
{
    "Elasticsearch": {
        "DeletedDocument": {
            "id": "1234",
            "index": "test-xsoar",
            "version": 3,
            "result": "deleted"
        }
    }
}
```

#### Human Readable Output

>### Deleted document
>
>|ID|Index name|Version|Result|
>|---|---|---|---|
>| 1234 | test-xsoar | 3 | deleted |

### es-kibana-case-activity-find

***
Find the activity (user actions) for a case.

#### Base Command

`es-kibana-case-activity-find`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use `es-kibana-case-list`. | Required |
| page | The page from which to start. ES default is 1. | Optional |
| sort_order | The sort order for the result. ES default is desc. | Optional |
| types | The types of user actions to return. | Optional |
| size | Number of results to return per page. ES default is 20, maximum is 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.CaseActivity.id | String | The action ID. |
| Elasticsearch.Kibana.CaseActivity.type | String | The action type. |
| Elasticsearch.Kibana.CaseActivity.user | String | The username of the user who performed the action. |
| Elasticsearch.Kibana.CaseActivity.action | String | A description of the action that was performed. |
| Elasticsearch.Kibana.CaseActivity.created_at | Date | The time the action was performed. |

#### Command Example

```!es-kibana-case-activity-find case_id="1234"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "CaseActivity": [
                {
                    "id": "5678",
                    "type": "create_case",
                    "user": "elastic",
                    "action": "create",
                    "created_at": "2024-01-15T10:00:00.000Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Kibana Case Activity for Case 1234
>
>|ID|Type|User|Action|Created at|
>|---|---|---|---|---|
>| 5678 | create_case | elastic | create | 2024-01-15T10:00:00.000Z |

### es-kibana-case-comment-find

***
Find the comments and alerts for a case.

#### Base Command

`es-kibana-case-comment-find`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use `es-kibana-case-list`. | Required |
| sort_order | The sort order for the result. ES default is desc. | Optional |
| page | Page number to retrieve. ES default is 1. | Optional |
| size | Number of results to return per page. ES default is 20, maximum is 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.CaseComment.id | String | The comment or alert ID. |
| Elasticsearch.Kibana.CaseComment.type | String | The comment or alert type. |
| Elasticsearch.Kibana.CaseComment.comment | String | The comment text. |
| Elasticsearch.Kibana.CaseComment.created_by.username | String | The username of the user who created the comment. |
| Elasticsearch.Kibana.CaseComment.created_at | Date | The time the comment was created. |
| Elasticsearch.Kibana.CaseComment.updated_at | Date | The time the comment was last updated. |

#### Command Example

```!es-kibana-case-comment-find case_id="1234"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "CaseComment": [
                {
                    "id": "5678",
                    "type": "user",
                    "comment": "A new comment",
                    "created_by": {"username": "elastic"},
                    "created_at": "2024-01-15T10:00:00.000Z",
                    "updated_at": "2024-01-15T11:00:00.000Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Kibana Case Comments for Case 1234
>
>|ID|Type|Comment|Created by|Created at|Updated at|
>|---|---|---|---|---|---|
>| 5678 | user | A new comment | elastic | 2024-01-15T10:00:00.000Z | 2024-01-15T11:00:00.000Z |

### es-kibana-case-comment-get

***
Get a single comment or alert for a case.

#### Base Command

`es-kibana-case-comment-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| case_id | The identifier for the case. To retrieve case IDs, use `es-kibana-case-list`. | Required |
| comment_id | The identifier of the comment or alert. To retrieve comment IDs, use `es-kibana-case-comment-find`. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.CaseComment.id | String | The comment or alert ID. |
| Elasticsearch.Kibana.CaseComment.type | String | The comment or alert type. |
| Elasticsearch.Kibana.CaseComment.comment | String | The comment text. |
| Elasticsearch.Kibana.CaseComment.created_by.username | String | The username of the user who created the comment. |
| Elasticsearch.Kibana.CaseComment.created_at | Date | The time the comment was created. |
| Elasticsearch.Kibana.CaseComment.updated_at | Date | The time the comment was last updated. |

#### Command Example

```!es-kibana-case-comment-get case_id="1234" comment_id="5678"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "CaseComment": {
                "id": "5678",
                "type": "user",
                "comment": "A new comment",
                "created_by": {"username": "elastic"},
                "created_at": "2024-01-15T10:00:00.000Z",
                "updated_at": "2024-01-15T11:00:00.000Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Case Comment 5678
>
>|ID|Type|Comment|Created by|Created at|Updated at|
>|---|---|---|---|---|---|
>| 5678 | user | A new comment | elastic | 2024-01-15T10:00:00.000Z | 2024-01-15T11:00:00.000Z |

### es-kibana-case-connectors-find

***
Find the connectors configured for cases.

#### Base Command

`es-kibana-case-connectors-find`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.CaseConnector.id | String | The connector ID. |
| Elasticsearch.Kibana.CaseConnector.name | String | The connector name. |
| Elasticsearch.Kibana.CaseConnector.actionTypeId | String | The connector action type. |
| Elasticsearch.Kibana.CaseConnector.referencedByCount | Date | The amount of references. |

#### Command Example

```!es-kibana-case-connectors-find```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "CaseConnector": [
                {
                    "id": "1234",
                    "name": "my-Jira",
                    "actionTypeId": ".jira",
                    "referencedByCount": 0
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Kibana Case Connectors
>
>|ID|Name|Type|Reference count|
>|---|---|---|---|
>| 1234 | my-Jira | .jira | 0 |

### es-kibana-case-creators-get

***
Retrieves the case creators and the number of cases each creator has.

#### Base Command

`es-kibana-case-creators-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owner | A filter to limit the response to a specific set of applications. Values are cases, observability, or securitySolution. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.CaseCreators | Unknown | A map of case creators. |

#### Command Example

```!es-kibana-case-creators-get owner="securitySolution"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "CaseCreators": [
                {"username": "elastic"},
                {"username": "jdoe"}
            ]
        }
    }
}
```

#### Human Readable Output

>### Kibana Case Creators
>
>|name|
>|---|
>| elastic |
>| jdoe |

### es-kibana-case-by-alert-get

***
Retrieves the cases linked to an alert.

#### Base Command

`es-kibana-case-by-alert-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| alert_id | The identifier of the alert. To retrieve alert IDs, use `es-kibana-detection-alert-search`. | Required |
| owner | A filter to limit the response to a specific set of applications. Values are cases, observability, or securitySolution. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Cases.title | Unknown | The cases retrieved for the given alert. |

#### Command Example

```!es-kibana-case-by-alert-get alert_id="5678"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "Cases": [
                {
                    "id": "1234",
                    "title": "Suspicious login",
                    "description": "Multiple failed logins detected",
                    "owner": "securitySolution",
                    "severity": "medium",
                    "status": "open",
                    "created_at": "2024-01-15T10:00:00.000Z",
                    "connector": {"type": ".none"}
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Cases for Alert 5678
>
>|Title|Case id|Description|Owner|Severity|Status|Creation date|Type|
>|---|---|---|---|---|---|---|---|
>| Suspicious login | 1234 | Multiple failed logins detected | securitySolution | medium | open | 2024-01-15T10:00:00.000Z | .none |

### es-kibana-alerts-index-create

***
Creates a Kibana alerts index.

#### Base Command

`es-kibana-alerts-index-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!es-kibana-alerts-index-create```

#### Context Example

```json
{}
```

#### Human Readable Output

>Creation acknowledged

### es-kibana-alerts-index-get

***
Retrieve all Kibana alerts indices.

#### Base Command

`es-kibana-alerts-index-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.Index | Unknown | The information retrieved for the Kibana alerts indices. |

#### Command Example

```!es-kibana-alerts-index-get```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "Index": {
                "index_mapping_outdated":false,
                "name": ".alerts-security.alerts-default"
            }
        }
    }
}
```

#### Human Readable Output

>| index_mapping_outdated | name |
>| --- | --- |
>| false | .alerts-security.alerts-default |

### es-kibana-alerts-index-delete

***
Deletes a Kibana alerts index.

#### Base Command

`es-kibana-alerts-index-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!es-kibana-alerts-index-delete```

#### Context Example

```json
{}
```

#### Human Readable Output

>Deletion acknowledged

### es-kibana-value-list-delete

***
Delete a value list using the list ID.

#### Base Command

`es-kibana-value-list-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| value_list_id | Value list identifier to delete, including all of its list items. | Required |
| delete_references | Determines whether exception items referencing this value list should be deleted. | Optional |
| ignore_references | Determines whether to delete value list without performing any additional checks of where this list may be utilized. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.ValueList | Unknown | The deleted value list metadata. |

#### Command Example

```!es-kibana-value-list-delete value_list_id="1234"```

#### Context Example

```json
{}
```

#### Human Readable Output

>The value list item 1234 has been successfully deleted.

### es-kibana-case-settings-create

***
Adds (sets) the case settings in Kibana.

#### Base Command

`es-kibana-case-settings-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| body | The full case settings object as a JSON object. If provided, the other arguments won't be considered. | Optional |
| closure_type | Whether a case is automatically closed when it is pushed to external systems (close-by-pushing) or not (close-by-user). | Optional |
| connector_id | The identifier of the default connector. Use none if you do not want a default connector. To retrieve connector IDs, use `es-kibana-case-connectors-find`. | Optional |
| connector_name | The name of the default connector. Use none if you do not want a default connector. | Optional |
| connector_type | The type of the default connector. | Optional |
| connector_fields | The connector fields as a JSON object. The fields are not propagated to individual cases, so it is recommended to leave it unset (defaults to null). | Optional |
| custom_fields | The custom fields case configuration as a JSON array of objects with the key, label, type (text or toggle) and an optional defaultValue property. | Optional |
| extract_observables | Indicates whether observables (for example, IPs, hashes, and URLs) are automatically extracted from case comments and events. | Optional |
| owner | The application that owns the cases - Stack Management, Observability, or Elastic Security.. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.CaseSettings.id | String | The identifier of the case configuration. |
| Elasticsearch.Kibana.CaseSettings.closure_type | String | Whether a case is automatically closed when it is pushed to external systems. |
| Elasticsearch.Kibana.CaseSettings.connector.id | String | The identifier of the default connector. |
| Elasticsearch.Kibana.CaseSettings.connector.name | String | The name of the default connector. |
| Elasticsearch.Kibana.CaseSettings.connector.type | String | The type of the default connector. |
| Elasticsearch.Kibana.CaseSettings.created_at | Date | The creation date of the case settings. |
| Elasticsearch.Kibana.CaseSettings.created_by.username | String | The user who created the case settings. |
| Elasticsearch.Kibana.CaseSettings.customFields | Unknown | The custom fields case configuration. |

#### Command Example

```!es-kibana-case-settings-create owner="cases" closure_type="close-by-user" connector_id="none" connector_name="none" connector_type=".none"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "CaseSettings": {
                "id": "1234",
                "closure_type": "close-by-user",
                "connector": {
                    "id": "5678",
                    "name": "my-jira-connector",
                    "type": ".jira"
                },
                "created_at": "2024-01-15T10:00:00.000Z",
                "created_by": {"username": "elastic"},
                "customFields": [{"key": "field_1", "label": "Field 1", "type": "text"}]
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Case Settings
>
>|ID|Closure type|Connector|Connector type|Custom fields|Created at|
>|---|---|---|---|---|---|
>| 1234 | close-by-user | my-jira-connector | .jira | field_1 | 2024-01-15T10:00:00.000Z |

### es-kibana-case-settings-update

***
Updates the case settings in Kibana.

#### Base Command

`es-kibana-case-settings-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| space_id | Refer to https://www.elastic.co/docs/deploy-manage/manage-spaces for more information. | Optional |
| configuration_id | The identifier of the case configuration to update. To retrieve it, use the id field of the case configuration returned by the case settings APIs (for example, `es-kibana-case-settings-create`). | Required |
| body | The case settings object as a JSON object. If provided, the other arguments won't be considered. Only the provided fields are updated. | Optional |
| version | The version of the connector. To retrieve the version value, use the get configuration API. | Required |
| closure_type | Whether a case is automatically closed when it is pushed to external systems (close-by-pushing) or not (close-by-user). | Optional |
| connector_id | The identifier of the default connector. Use none if you do not want a default connector. To retrieve connector IDs, use `es-kibana-case-connectors-find`. | Optional |
| connector_name | The name of the default connector. Use none if you do not want a default connector. | Optional |
| connector_type | The type of the default connector. | Optional |
| connector_fields | The connector fields as a JSON object. The fields are not propagated to individual cases, so it is recommended to leave it unset (defaults to null). | Optional |
| custom_fields | The custom fields case configuration as a JSON array of objects with the key, label, type (text or toggle) and an optional defaultValue property. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.Kibana.CaseSettings.id | String | The identifier of the case configuration. |
| Elasticsearch.Kibana.CaseSettings.closure_type | String | Whether a case is automatically closed when it is pushed to external systems. |
| Elasticsearch.Kibana.CaseSettings.connector.id | String | The identifier of the default connector. |
| Elasticsearch.Kibana.CaseSettings.connector.name | String | The name of the default connector. |
| Elasticsearch.Kibana.CaseSettings.connector.type | String | The type of the default connector. |
| Elasticsearch.Kibana.CaseSettings.created_at | Date | The creation date of the case settings. |
| Elasticsearch.Kibana.CaseSettings.created_by.username | String | The user who created the case settings. |
| Elasticsearch.Kibana.CaseSettings.customFields | Unknown | The custom fields case configuration. |

#### Command Example

```!es-kibana-case-settings-update configuration_id="1234" version="1" closure_type="close-by-pushing"```

#### Context Example

```json
{
    "Elasticsearch": {
        "Kibana": {
            "CaseSettings": {
                "id": "1234",
                "closure_type": "close-by-pushing",
                "connector": {
                    "id": "5678",
                    "name": "my-jira-connector",
                    "type": ".jira"
                },
                "created_at": "2024-01-15T10:00:00.000Z",
                "created_by": {"username": "elastic"},
                "customFields": [{"key": "field_1", "label": "Field 1", "type": "text"}]
            }
        }
    }
}
```

#### Human Readable Output

>### Kibana Case Settings Updated
>
>|ID|Closure type|Connector|Connector type|Custom fields|Created at|
>|---|---|---|---|---|---|
>| 1234 | close-by-pushing | my-jira-connector | .jira | field_1 | 2024-01-15T10:00:00.000Z |

### es-index-create

***
Creates a new Elasticsearch index.

#### Base Command

`es-index-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | The name of the index to create. | Required |
| settings | JSON object with the index settings, for example {"number_of_shards": 1}. | Optional |
| mappings | JSON object with the index mappings. | Optional |
| aliases | JSON object with the aliases to assign to the index. | Optional |
| wait_for_active_shards | The number of shard copies that must be active before proceeding. Set to all or any positive integer up to the total number of shards per index (including the primary). Default: 1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.IndexManagement.Name | String | The name of the created index. |
| Elasticsearch.IndexManagement.Acknowledged | Boolean | Whether the request was acknowledged by the cluster. |
| Elasticsearch.IndexManagement.ShardsAcknowledged | Boolean | Whether the request was acknowledged by all configured nodes. |

#### Command Example

```!es-index-create index=test-xsoar settings="{\"number_of_shards\":1}"```

#### Context Example

```json
{
    "Elasticsearch": {
        "IndexManagement": {
            "Name": "test-xsoar",
            "Acknowledged": true,
            "ShardsAcknowledged": true
        }
    }
}
```

#### Human Readable Output

>### Created index
>
>|Index name|Acknowledged|Shards Acknowledged|
>|---|---|---|
>| test-xsoar | true | true |

### es-index-get

***
Retrieves information (aliases, mappings and settings) about one or more Elasticsearch indices.

#### Base Command

`es-index-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | The name of the index to retrieve. Can be a comma-separated list of index names or an index pattern. | Required |
| expand_wildcards | Whether to expand wildcard expressions to indices that are open, closed, or both. | Optional |
| flat_settings | Whether to return settings in the flat format. Default is false. | Optional |
| include_defaults | Whether to return all default settings in the output. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.IndexManagement.Name | String | The name of the index. |
| Elasticsearch.IndexManagement.Aliases | Unknown | The aliases assigned to the index. |
| Elasticsearch.IndexManagement.Mappings | Unknown | The mappings of the index. |
| Elasticsearch.IndexManagement.Settings | Unknown | The settings of the index. |

#### Command Example

```!es-index-get index=test-xsoar```

#### Context Example

```json
{
    "Elasticsearch": {
        "IndexManagement": [
            {
                "Name": "test-xsoar",
                "Aliases": {"test-alias": {}},
                "Mappings": {"properties": {"name": {"type": "text"}}},
                "Settings": {"index": {"number_of_shards": "1", "number_of_replicas": "1"}}
            }
        ]
    }
}
```

#### Human Readable Output

>### Indices information
>
>|Index name|Aliases|
>|---|---|
>| test-xsoar | test-alias |

### es-index-delete

***
Deletes one or more Elasticsearch indices.

#### Base Command

`es-index-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | The name of the index to delete. Can be a comma-separated list of index names or an index pattern. | Required |
| ignore_unavailable | Whether to ignore if a wildcard expression resolves into no concrete indices instead of returning an error. | Optional |
| allow_no_indices | Whether to ignore if a wildcard expression resolves into no concrete indices. | Optional |
| expand_wildcards | Whether to expand wildcard expressions to indices that are open, closed, or both. | Optional |
| master_timeout | The maximum time to wait for a connection to the master node. | Optional |
| timeout | The maximum time to wait for the request to complete. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Elasticsearch.IndexManagement.Name | String | The name of the deleted index. |
| Elasticsearch.IndexManagement.Acknowledged | Boolean | Whether the request was acknowledged by the cluster. |

#### Command Example

```!es-index-delete index=test-xsoar```

#### Context Example

```json
{
    "Elasticsearch": {
        "IndexManagement": {
            "Name": "test-xsoar",
            "Acknowledged": true
        }
    }
}
```

#### Human Readable Output

>### Deleted index
>
>|Index name|Acknowledged|
>|---|---|
>| test-xsoar | true |

<~PLATFORM>

## License Requirements

The following configuration parameters require one of these licenses: **Cortex XSIAM** or **Agentix**:

- Fetch incidents

</~PLATFORM>
