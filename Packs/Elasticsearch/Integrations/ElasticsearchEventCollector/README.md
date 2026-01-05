Search for and analyze data in real time.
Supports version 6 and later.
This integration was integrated and tested with versions 6.6.2, 7.3, 8.4.1 of Elasticsearch.

## Configure ElasticsearchEventCollector in Cortex

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
