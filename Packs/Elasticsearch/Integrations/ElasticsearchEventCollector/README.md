Search for and analyze data in real time.
 Supports version 6 and later.

## Configure ElasticsearchEventCollector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Elasticsearch server to which the integration connects. Ensure that the URL includes the correct Elasticsearch port. The default port for Elasticsearch v7 and below is 9200. Use the Server URL for on-premises deployments. | False |
| Authorization type | Select the authentication type and enter the appropriate credentials:<br/>- Basic Auth: Enter Username and Password.<br/>- Bearer Auth: Enter Username and Password.<br/>- API Key Auth: Enter the API Key ID and API Key. | True |
| API key ID | Use for API key auth | False |
| API Key |  | False |
| Username | Use for Basic auth. Optionally you can use Username as an API key ID and Password as an API key for API Key auth. | False |
| Password |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Client type | In some hosted ElasticSearch environments, the standard ElasticSearch client is not supported. If you encounter any related client issues, please consider using the OpenSearch client type. | False |
| Index to fetch incidents from | CSV | False |
| Query String | Query string uses the Lucene syntax.<br/>For more information about the Lucene syntax, see the link in the help section.<br/>The query will be used when fetching incidents. Index time field will be used as a filter in the query.<br/><br/>The integration test button doesn't fully test the fetch incidents validity. To verify that the instance is set up correctly for fetching incidents, run the '\!es-integration-health-check' command. | False |
| Index time field | The time field used for sorting and limiting results. If using a nested field, separate field names with dot notation. | False |
| Raw Query | Raw Query allows raw DSL queries and will override the 'Query String' Lucene syntax string.<br/>Results will not be filtered or sorted. Use additional parameters in the raw query for these purposes.<br/>For more information see the link in the help section.<br/><br/>The integration test button doesn't fully test the fetch incidents validity. To verify that the instance is set up correctly for fetching incidents, run the '\!es-integration-health-check' command. | False |
| Time field type | For more information see the explanation in the help section. | False |
| Map JSON fields into labels |  | False |
| The maximum number of results per fetch |  | False |
| Request timeout (in seconds). |  | False |
| Incident type |  | False |
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
| fetch_size | The maximum number of results per fetch, default 10 | Optional |
| fetch_index | CSV | Optional |
| fetch_time_field | The time field used for sorting and limiting results. If using a nested field, separate field names with dot notation. | Required |
| fetch_query | Query string uses the Lucene syntax. | Optional |
| raw_query | Raw Query allows raw DSL queries and will override the 'Query String' Lucene syntax string. | Optional |

#### Context Output

There is no context output for this command.
