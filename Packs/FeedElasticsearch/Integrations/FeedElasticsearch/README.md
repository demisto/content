## Overview
---

Fetch indicators stored in an Elasticsearch database. 
1. The Cortex XSOAR Feed contains system indicators saved in an Elasticsearch index. 
2. The Cortex XSOAR MT Shared Feed contains indicators shared by a tenant account in a multi-tenant environment. 
3. The Generic Feed contains a feed in a format specified by the user.

Supports version 6 and later.
This integration was integrated and tested with versions 6.6.2, 7.3, 8.4.1 of Elasticsearch.

## Configure Elasticsearch Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Name (see ?-&gt;Authentication) | Provide Username \+ Passoword instead of API key \+ API ID | False |
| Password |  | False |
| Client type | For Elasticsearch version 7 and below, select 'Elasticsearch'. For Elasticsearch server version 8, select 'Elasticsearch_v8'. In some hosted ElasticSearch environments, the standard ElasticSearch client is not supported. If you encounter any related client issues, please consider using the OpenSearch client type. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Feed Type | The Cortex XSOAR Feed contains system indicators saved in an Elasticsearch index. The Cortex XSOAR MT Shared Feed contains indicators shared by a tenant account in a multi-tenant environment. Generic Feed contains a feed in a format specified by the user | False |
| Fetch indicators |  | False |
| First Fetch Time | Determine how far to look back for fetched indicators \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days\). | False |
| Fetch Limit | The maximal number of indicators that could be fetched in a fetch cycle. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Feed Fetch Interval |  | False |
| Tags | Supports CSV values. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Indicator Value Field | Source field that contains the indicator value in the index. Relevant for generic feed type only. | False |
| Indicator Type Field | Source field that contains the indicator type in the index. Relevant for generic feed type only. | False |
| Indicator Type | Default indicator type used in case no "Indicator Type Field" was provided. Relevant for generic feed type only. | False |
| Index from Which To Fetch Indicators | A comma-separated list of indexes. If empty, searches all indexes. | False |
| Time Field Type |  | False |
| Index Time Field | Used for sorting and limiting data. If empty, results are not sorted. Relevant for generic feed type only. | False |
| Query | Elasticsearch query to execute when fetching indicators from Elasticsearch | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### es-get-indicators

***
Gets indicators available in the configured Elasticsearch database.

#### Base Command

`es-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to fetch. Default is 50. | Required |

#### Context Output

There is no context output for this command.