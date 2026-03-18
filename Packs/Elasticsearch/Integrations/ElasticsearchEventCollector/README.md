Elasticsearch Event Collector integration is used to search for and analyze data in real time.
Supports version 6 and later.

## Configure Elasticsearch Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Elasticsearch server to which the integration connects. Ensure that the URL includes the correct Elasticsearch port. The default port for Elasticsearch v7 and below is 9200. Use the Server URL for on-premises deployments. | False |
| Authorization type | Select the authentication type and enter the appropriate credentials:<br/>- Basic Auth: Enter Username and Password.<br/>- Bearer Auth: Enter Username and Password.<br/>- API Key Auth: Enter the API Key ID and API Key. | True |
| API key ID | Use for API key auth | False |
| API Key | Use for API key auth | False |
| Username | Use for Basic auth. Optionally you can use Username as an API key ID and Password as an API key for API Key auth. | False |
| Password | Use for Basic auth. Optionally you can use Username as an API key ID and Password as an API key for API Key auth. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Client type | In some hosted ElasticSearch environments, the standard ElasticSearch client is not supported. If you encounter any related client issues, please consider using the OpenSearch client type. | False |
| Index to fetch events from | CSV | False |
| Query String | Query string uses the Lucene syntax.<br/>For more information about the Lucene syntax see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.3/query-dsl-query-string-query.html#query-string-syntax).<br/>The query will be used when fetching events. Index time field will be used as a filter in the query. | False |
| Index time field | The time field used for sorting and limiting results. If using a nested field, separate field names with dot notation. | False |
| Raw Query | Raw Query allows raw DSL queries and will override the 'Query String' Lucene syntax string.<br/>Results will not be filtered or sorted. Use additional parameters in the raw query for these purposes.<br/>For more information about Query DSL see [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html).| False |
| Time field type | 3 formats supported:<br/> *Simple-Date - A plain date string. You must specify the format in which the date is stored.<br/>For more information about time formatting, see [here](http://strftime.org/).<br/>* Timestamp-Second - A numeric value representing the number of seconds since the Unix epoch (00:00:00 UTC on 1 January 1970). Example: '1572164838'<br/> * Timestamp-Milliseconds - A numeric value representing the number of milliseconds since the Unix epoch. Example: '1572164838123'| False |
| Map JSON fields into labels |  | False |
| The maximum number of results per fetch |  | False |
| Request timeout (in seconds). |  | False |
| Fetch events |  | False |

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### es-get-events

***
Gets events from Elasticsearch.
This command is used for developing/ debugging and is to be used with caution, as it can cause the API request limit to be exceeded.

#### Base Command

`es-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | Start time for fetching events. Supports ISO format ("2023-01-01T23:59:59") or natural language ("2 hours ago", "now"). | Required |
| end_time | End time for fetching events. Supports ISO format ("2023-01-01T23:59:59") or natural language ("2 hours ago", "now"). | Optional |
| time_method | For more information see the explanation in the help section. | Required |
| fetch_size | The maximum number of results per fetch, default 10. | Optional |
| fetch_index | CSV. | Optional |
| fetch_time_field | The time field used for sorting and limiting results. If using a nested field, separate field names with dot notation. | Required |
| fetch_query | Query string uses the Lucene syntax. | Optional |
| raw_query | Raw Query allows raw DSL queries and will override the 'Query String' Lucene syntax string. | Optional |

#### Context Output

There is no context output for this command.
