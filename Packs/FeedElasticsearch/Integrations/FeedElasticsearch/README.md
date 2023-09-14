## Overview
---

Fetch indicators stored in an Elasticsearch database. 
1. The Cortex XSOAR Feed contains system indicators saved in an Elasticsearch index. 
2. The Cortex XSOAR MT Shared Feed contains indicators shared by a tenant account in a multi-tenant environment. 
3. The Generic Feed contains a feed in a format specified by the user.

## Configure Elasticsearch Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Elasticsearch Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Name (see ?-&gt;Authentication) | Provide Username \+ Passoword instead of API key \+ API ID | False |
    | Password |  | False |
    | Client type | In some hosted ElasticSearch environments, the standard ElasticSearch client is not supported. If you encounter any related client issues, please consider using the OpenSearch client type. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Feed Type | The Cortex XSOAR Feed contains system indicators saved in an Elasticsearch index. The Cortex XSOAR MT Shared Feed contains indicators shared by a tenant account in a multi-tenant environment. Generic Feed contains a feed in a format specified by the user | False |
    | Fetch indicators |  | False |
    | First Fetch Time | Determine how far to look back for fetched indicators \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days\). | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Tags | Supports CSV values. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Indicator Value Field | Source field that contains the indicator value in the index | False |
    | Indicator Type Field | Source field that contains the indicator type in the index | False |
    | Indicator Type | Default indicator type used in case no "Indicator Type Field" was provided | False |
    | Index from Which To Fetch Indicators | A comma-separated list of indexes. If empty, searches all indexes. | False |
    | Time Field Type |  | False |
    | Index Time Field | Used for sorting and limiting data. If empty, results are not sorted. | False |
    | Query | Elasticsearch query to execute when fetching indicators from Elasticsearch | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### es-get-indicators

***
Gets indicators available in the configured Elasticsearch database.

#### Base Command

`es-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to fetch. The default is 50. Default is 50. | Required | 

#### Context Output

There is no context output for this command.
