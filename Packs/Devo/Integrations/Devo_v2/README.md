## Overview

---

Use the Devo v2 integration to query Devo for alerts, lookup tables, with support of pagination, and to write to lookup tables.\
This integration was integrated and tested with version 6.0+ Devo.\
Devo is a generic log management
solution which can also act as an advanced SIEM. Users are able to query petabytes of data in a fraction
of the time that other traditional time series databases can't.

## Use Cases

---

* Ingest all user defined alerts from Devo into Cortex XSOAR
* Query any data source available on the Devo.
* Run needle in haystack multi-table queries for threat hunting incidents.
* Write results back to Devo as searchable records or alerts.
* Write new entries into lookup tables to be used in synthesis tables (ALPHA)

## Prerequisites

---

* Active Devo account and domain.
* OAuth token with the `*.**` permissions.
* Writer TLS Certificate, Key, and Chain if writing back to Devo.

### Get your Cortex XSOAR OAuth Token

1. Login to your Devo domain with a user with the ability to create security credentials.
2. Navigate to __Administration__ > __Credentials__ > __Authentication Tokens__.
3. If a token for Cortex XSOAR has not already been  created, Click __CREATE NEW TOKEN__

    * Create the Token with `*.**` table permissions as an `apiv2` token.

4. Note the generated `Token`

### Get your Cortex XSOAR Writer Credentials

1. Login to your Devo domain with a user with the ability to create security credentials.
2. Navigate to __Administration__ > __Credentials__ > __X.509 Certificates__.
3. Click `NEW CERTIFICATE` if you do not already have a set of keys for Cortex XSOAR.
4. Download the following files:
    * `Certificate`
    * `Private Key`
    * `CHAIN CA`


## Configure Devo v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Devo v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Query Server Endpoint (e.g. <https://apiv2-us.devo.com/search/query>) | True |
    | Port (e.g. 443) | False |
    | OAuth Token (Preferred method) | True |
    | Writer relay to connect to (e.g. us.elb.relay.logtrust.net) | False |
    | Writer JSON credentials | False |
    | Devo base domain | False |
    | Fetch incidents | False |
    | Incident type | False |
    | Custom Alert Table name(if not provided, 'siem.logtrust.alert.info' will be used) | False |
    | Custom Alert Table prefix (provide prefix if custom table name provided) | False |
    | Fetch incidents alert filter (Same filters for get-alerts) | False |
    | Deduplication parameters JSON if required | False |
    | Fetch Incident Limit(must be between 10 and 100; advisable 50 for better performance.) | False |
    | Incidents Fetch Interval | False |
    | Global query default timeout in seconds | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch Incidents Lookback Time (in seconds). Must be between 3600 (1 hour; default) to 86400 (24 hours). | False |
    | Fetch Incident Time Frame (in seconds) | False |

4. Click **Test** to validate the URLs, token, and connection.

### Configuration Details :

* __Writer JSON credentials__ *Optional*

    ```json
    {
        "key": "string",
        "crt": "string",
        "chain": "string"
    }
    ```

    The JSON should be given in one line, and new lines should be replaced with `\n`, for example:

    ```json
    {"key": "-----BEGIN RSA PRIVATE KEY-----\n\n...\n-----END RSA PRIVATE KEY-----", "crt": "-----BEGIN CERTIFICATE-----\n\n...\n-----END CERTIFICATE-----", "chain": "-----BEGIN CERTIFICATE-----\n\n...\n-----END CERTIFICATE-----"}
    ```

* __Fetch incidents alert filter (Same filters for get-alerts)__ *Optional*

    ```json
    {
        "type": <"AND" | "OR">,
        "filters" : [
            {"key": "<String Devo Column Name>", "operator": "<Devo Linq Operator>", "value": "<string>"},
            {"key": "<String Devo Column Name>", "operator": "<Devo Linq Operator>", "value": "<string>"},
            ...
            {"key": "<String Devo Column Name>", "operator": "<Devo Linq Operator>", "value": "<string>"}
        ]
    }
    ```



**Note:** single table query and multi table query can take long hours to complete runing and xsoar only allows commands to run for 5 minutes.
To override that follow the below steps:

* Login to xsoar.
* Go to settings.
* Go to about > troubleshooting.
* In server configurations add the following:
  * key = <name_of_integration>.devo-run-query.timeout, value = 1440
  * key = <name_of_integration>.devo-multi-table-query.timeout, value = 1440
* Click save.

## Fetched Incidents Data

Fetched incidents data will resemble closely to that of the data you get back from the `devo-get-alerts` command.\
The format is as follows. The keyN in the main body will be the columns that you used to define your alert in Devo.

```json
{
  "devo.metadata.alert": {
    "eventdate": "string",
    "alertHost": "string",
    "domain": "string",
    "priority": "string",
    "context": "string",
    "category": "string",
    "status": "string",
    "alertId": "string",
    "srcIp": "string",
    "srcPort": "string",
    "srcHost": "string",
    "dstIp": "string",
    "dstPort": "string",
    "dstHost": "string",
    "application": "string",
    "engine":  "string"
  },
  <key0>: <value0>,
  <key1>: <value1>,
  ...
  <keyN>: <valueN>
}
```

Currently the only data that is fetchable in Devo are the alerts that users have defined in the platform.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. devo-run-query
2. devo-get-alerts
3. devo-multi-table-query
4. devo-write-to-table
5. devo-write-to-lookup-table

### 1. devo-run-query

---
Queries Devo based on the specified LINQ query.

Please refer to to the Devo documentation for building a query with LINQ
[HERE](https://docs.devo.com/confluence/ndt/searching-data/building-a-query/build-a-query-using-linq).

#### Required Permissions

 A Cortex XSOAR instance configured with the correct OAuth token that has permission to query the target tables

#### Base Command

`devo-run-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A LINQ query to run in Devo, with pagination support. | Required | 
| from | Start datetime for the specified query. This argument supports natural language (e.g., 2 day, 3 week), Unix timestamps, Python datetime objects, and string datetimes. | Required | 
| to | End datetime for specified query. If provided must be in same format as "from" argument. This argument is ignored in a date range. | Optional | 
| items_per_page | Enter the per page value you want to set. Default is 50. | Optional | 
| queryTimeout | Timeout in seconds for this query to run against Devo to override the minute default in the platform. Default is 60. | Optional | 
| writeToContext | Whether to write results to context. Can be "true" or "false". Default is true. | Optional | 
| linqLinkBase | Overrides the global Devo base domain for linq linking. | Optional | 
| filtered_columns | The subset of fields (separated by a comma) that you want to display from the query result. Use this if you want to filter out unwanted columns in your result. Context data is eventually modified by this parameter. | Optional | 
| ip_as_string | Flag to return IP as string. | Optional | 


#### Time Format for __from__ and __to__ Arguments:

This integration supports the following time formats for the __from__ and __to__ arguments:

* Date ranges such as "1 day", "30 minutes", etc. If a date range is provided for __from__, the __to__ parameter is not needed and will be ignored.
* Unix timestamps in milliseconds and seconds.
* Datetime strings in the format '%Y-%m-%dT%H:%M:%S'.
* Python datetime objects.

Please ensure that the __from__ and __to__ times are provided in the same format.\
Using unsupported formats will result in an error.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Devo.QueryResults | unknown | List of dictionary alerts from the specified time range. | 
| Devo.QueryLink | unknown | The link to the Devo table for executed query. | 

#### Command Example

```text
!devo-run-query query="from siem.logtrust.web.activity select *" from=1576845233.193244 to=1576845293.193244 items_per_page=1000
```

#### Human Readable Output

>### Devo run query results
>|eventdate|level|domain|userid|username|sessionid|correlationId|srcHost|srcPort|serverHost|serverPort|type|method|url|headers|params|referer|userAgent|locale|contentLength|responseLength|responseTime|result|resourceInfo|errorInfo|country|region|city|isp|org|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|2019-10-23T17:18:29.784000|INFO|helloworld|988409ce-3955-44a8-bcbb-b613bc8d9f8e|<john.doe@devo.com>|22671FE384D9FDF20E9BFFD7F4469971||1.2.3.4|45590|us.devo.com|8080||GET|<https://us.devo.com/alerts/alertsGlobe.json>||{origin:app.custom.tsAnomalyDetectionDev,serialNumber:ad475065-b0ef-4bbe-a620-a6dcd0874629,}|<https://us.devo.com/welcome>|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36|en_US|0|124|7|OK|||US|NJ|Secaucus|Ppman Services Srl|M247 Ltd New Jersey|
>|2019-10-23T17:18:29.800000|INFO|helloworld|988409ce-3955-44a8-bcbb-b613bc8d9f8e|<john.doe@devo.com>|22671FE384D9FDF20E9BFFD7F4469971||1.2.3.4|45588|us.devo.com|8080||GET|`https://us.devo.com/domain/notification.json`||{origin:app.custom.tsAnomalyDetectionDev,serialNumber:ad475065-b0ef-4bbe-a620-a6dcd0874629,}|https://us.devo.com/welcome|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36|en_US|0|119|24|OK|||US|NJ|Secaucus|Ppman Services Srl|M247 Ltd New Jersey|
>|2019-10-23T17:18:59.780000|INFO|helloworld|988409ce-3955-44a8-bcbb-b613bc8d9f8e|john.doe@devo.com|22671FE384D9FDF20E9BFFD7F4469971||1.2.3.4|45816|us.devo.com|8080||GET|https://us.devo.com/alerts/alertsGlobe.json||{origin:app.custom.tsAnomalyDetectionDev,serialNumber:ad475065-b0ef-4bbe-a620-a6dcd0874629,}|https://us.devo.com/welcome|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36|en_US|0|124|7|OK|||US|NJ|Secaucus|Ppman Services Srl|M247 Ltd New Jersey|

>|DevoTableLink|
>|---|
>|[Devo Direct Link](https://us.devo.com/welcome#/verticalApp?path=apps/custom/dsQueryForwarder&targetQuery=blah==)|

### 2. devo-get-alerts

---
Queries alerts in the specified timeframe.

Alerts are based off the table `siem.logtrust.alert.info` found in your Devo account.\
Please refer to this table
for a list of columns you can filter off of. Also please refer back to the LINQ documentation for operations
that are allowed.

#### Required Permissions

Requires a Devo OAuth token that has read permission on siem.logtrust.alert.info table.

#### Base Command

`devo-get-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | name of alert table to fetch alerts from a table. If not provided 'siem.logtrust.alert.info' will be used. | Optional | 
| prefix | Prefix to use for the column names. | Optional | 
| from | Start datetime for alerts to fetch. | Required | 
| to | End datetime for alerts to fetch. | Optional | 
| items_per_page | Enter the per page value you want to set. Default is 50. | Optional | 
| filters | Key value filter to apply to retrieve the specified alerts. For more information, see the Devo documentation. | Optional | 
| queryTimeout | Timeout in seconds for this query to run against Devo to override the minute default in the platform. Default is 60. | Optional | 
| writeToContext | Whether to write results to context. Can be "true" or "false". Default is true. | Optional | 
| linqLinkBase | Overrides the global Devo base domain for linq linking. | Optional | 
| filtered_columns | The subset of fields (separated by a comma) that you want to display from the query result. Use this if you want to filter out unwanted columns in your result. Context data is eventually modified by this parameter. | Optional | 

#### Time Format for __from__ and __to__ Arguments:

This integration supports the following time formats for the __from__ and __to__ arguments:

* Date ranges such as "1 day", "30 minutes", etc. If a date range is provided for __from__, the __to__ parameter is not needed and will be ignored.
* Unix timestamps in milliseconds and seconds.
* Datetime strings in the format '%Y-%m-%dT%H:%M:%S'.
* Python datetime objects.

Please ensure that the __from__ and __to__ times are provided in the same format.\
Using unsupported formats will result in an error.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Devo.AlertsResults | unknown | List of dictionary alerts from the specified time range. |
| Devo.QueryLink | unknown | The link to the Devo table for the executed query. |

#### Command Example

```text
!devo-get-alerts from=1576845233.193244 to=1576845293.193244
```

#### Human Readable Output

>### Devo get alerts results
>|eventdate|alertHost|domain|priority|context|category|status|alertId|srcIp|srcPort|srcHost|dstIp|dstPort|dstHost|protocol|username|application|engine|extraData|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|2019-10-23T18:18:07.320000|backoffice|helloworld|5.0|my.alert.helloworld.simultaneous_login|my.context|4|6715552||||||||||pilot.my.alert.helloworld.simultaneous_login|duration_seconds: 30.142<br/>cluster: -<br/>prev_timestamp: 2019-10-23+18:17:29.652<br/>instance: -<br/>distance: 294.76<br/>level: info<br/>city: Secaucus<br/>srcHost: 1.2.3.4<br/>prev_city: Waltham<br/>format: output_qs9n126lnvh<br/>prev_geolocation: 42°23'49.925537109375"N+71°14'36.2420654296875"W<br/>message:0.0.0.4Waltham0°0'0.00"N+0°0'0.0"N+0°0'0.00"W0.0.0<<br/>eventdate: 2019-10-23+18:18:02.087<br/>prev_srcHost: 50.204.142.130<br/>duration: 0.008372777777777778<br/>indices: 0,9,31,49,69,77,123,136,149,156,204,217,231<br/>payload: 0.0.0.4Waltham0°0'0.00"N+0°0'0.0"N+0°0'0.00"W0.0.0<<br/>state: ANOMALOUS<br/>category: modelserverdev<br/>facility: user<br/>username: john.doe@devo.com<br/>geolocation: 0°0'0.00"N+0°0'0.0"W<br/>timestamp: 2019-10-23+18:17:59.794|

>|DevoTableLink|
>|---|
>|[Devo Direct Link](https://us.devo.com/welcome#/verticalApp?path=apps/custom/dsQueryForwarder&targetQuery=blah==)|

### 3. devo-multi-table-query

---
Queries multiple tables for a given token and returns relevant results.

This method is used for when you do not know which columns a specified search token will show up in (Needle in a haystack search)
Thus querying all columns for the search token and returning a union of the given tables.

#### Required Permissions

A Cortex XSOAR instance configured with the correct OAuth token that has permission to query the target tables

#### Base Command

`devo-multi-table-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tables | A list of table names to check for the searchToken. | Required | 
| searchToken | A string to search for in the specified tables (in any column). | Required | 
| from | Start datetime for the specified query. This argument supports natural language (e.g., 2 day, 3 week), Unix timestamps, Python datetime objects, and string datetimes. | Required | 
| to | End datetime for specified query. If provided must be in same format as "from" argument. This argument is ignored in a date range. | Optional | 
| limit | Limit of results to return to context. 0 for no limit. Default is 50. | Optional | 
| queryTimeout | Timeout in seconds for this query to run against Devo to override the minute default in the platform. Default is 60. | Optional | 
| writeToContext | Whether to write results to context. Can be "true" or "false". Default is true. | Optional | 
| items_per_page | Enter the per page value you want to set. Default is 50. | Optional | 
| filtered_columns | The subset of fields (separated by a comma) that you want to display from the query result. Use this if you want to filter out unwanted columns in your result. Context data is eventually modified by this parameter. | Optional | 

#### Time Format for __from__ and __to__ Arguments:

This integration supports the following time formats for the __from__ and __to__ arguments:

* Date ranges such as "1 day", "30 minutes", etc. If a date range is provided for __from__, the __to__ parameter is not needed and will be ignored.
* Unix timestamps in milliseconds and seconds.
* Datetime strings in the format '%Y-%m-%dT%H:%M:%S'.
* Python datetime objects.

Please ensure that the __from__ and __to__ times are provided in the same format.\
Using unsupported formats will result in an error.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Devo.MultiResults | unknown | A list of dictionary results. |


##### Command Example
```
!devo-multi-table-query tables="[siem.logtrust.alert.info, siem.logtrust.web.navigation]" searchToken="parag@metronlabs.com" from=1707416980 to=1707805927
```

#### Human Readable Output

>### Devo multi-query results
>|isp|serverPort|srcPort|responseTime|headers|eventdate|correlationId|userEmail|responseLength|message|result|method|type|url|userid|level|referer|username|region|userAgent|sessionid|resourceInfo|contentLength|org|domain|srcHost|city|params|serverHost|errorInfo|section|action|origin|country|locale|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|Amazon.com|8080|33522|||2019-09-18T07:58:39.691000||john@doe.com|||||0|`https://us.devo.com/alerts/view.json`|400d338d-c9a6-4930-90a5-357937f3e735||https://us.devo.com/welcome||VA|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36|8723DEE4B38F1056BC738760B5E79FD3|||Amazon.com|helloworld|1.2.3.4|Ashburn||us.devo.com||alert|index|undefined|US||
>|Amazon.com|8080|33574|||2019-09-18T07:58:41.685000||john@doe.com||UserDomain: UserDomain[id: 2942, domain: 6ab72601-e982-4694-8ce6-3d526047f8a5/helloworld, roles: null, logged: 2019-09-18 04:32:58.0, status: 0, creation date: 2018-11-05 14:23:44.0, update date: 2019-09-18 04:32:58.0]\||||0|https://us.devo.com/lxcWidgets/lxcWidget.json|400d338d-c9a6-4930-90a5-357937f3e735||https://us.devo.com/welcome||VA|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36|8723DEE4B38F1056BC738760B5E79FD3|||Amazon.com|helloworld|1.2.3.4|Ashburn||us.devo.com||lxc_widgets|index|undefined|US||
>|Comcast Cable|8080|37094|45||2019-09-18T08:08:21.593000|||124||OK|GET||https://us.devo.com/alerts/alertsGlobe.json|400d338d-c9a6-4930-90a5-357937f3e735|INFO|https://us.devo.com/welcome|john@doe.com|CA|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36|8723DEE4B38F1056BC738760B5E79FD3||0|Comcast Cable|helloworld|1.2.3.4|San Francisco|{origin:menu.alerts,serialNumber:b181cf08-14e0-49c2-826b-e4ff36afaa84,}|us.devo.com|||||US|en_US|
>|Comcast Cable|8080|37092|78||2019-09-18T08:08:21.625000|||119||OK|GET||`https://us.devo.com/domain/notification.json`|400d338d-c9a6-4930-90a5-357937f3e735|INFO|https://us.devo.com/welcome|john@doe.com|CA|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36|8723DEE4B38F1056BC738760B5E79FD3||0|Comcast Cable|helloworld|1.2.3.4|San Francisco|{origin:menu.alerts,serialNumber:b181cf08-14e0-49c2-826b-e4ff36afaa84,}|us.devo.com|||||US|en_US|



### 4. devo-write-to-table

---
Writes records to a specified Devo table.

The records written to the table should all be of the same JSON format and to the same table. We currently do not support
writing to multiple tables in a single operation.

For more information on the way we write to a table please refer to this documentation found [HERE](https://github.com/DevoInc/python-ds-connector#loading-data-into-devo)

#### Required Permissions

A Cortex XSOAR instance configured with the correct write JSON credentials

#### Base Command

`devo-write-to-table`

#### Input

| **Argument Name** | **Description**                                                 | **Required** |
|-------------------|-----------------------------------------------------------------|--------------|
| tableName         | Table name to write to                                          | Required     |
| records           | Records written to specified Devo table.                        | Required     |
| linqLinkBase      | Overrides the global link base so is able to be set at run time | Optional     |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Devo.RecordsWritten | unknown | Records written to specified Devo table. | 
| Devo.LinqQuery | unknown | The LINQ query to use to see your data in Devo. | 
| Devo.QueryLink | unknown | The link to the Devo table for the executed query. | 


##### Command Example
```
!devo-write-to-table tableName="my.app.test.test" records=`[ "This is my first event", "This is my second log", {"hello": "world"}, {"hello": "friend"}, ["a", "b", "c"], ["1", "2", "3"], 1234, true ]`
```

##### Human Readable Output
Total Records Sent: 8.
Total Bytes Sent: 196.

##### Entries to load into Devo

|eventdate|format|cluster|instance|message|
|---|---|---|---|---|
|2024-02-12 17:51:51.277|test|-|-|This is my first event|
|2024-02-12 17:51:51.277|test|-|-|This is my second log|
|2024-02-12 17:51:51.277|test|-|-|{"hello": "world"}|
|2024-02-12 17:51:51.277|test|-|-|{"hello": "friend"}|
|2024-02-12 17:51:51.277|test|-|-|["a", "b", "c"]|
|2024-02-12 17:51:51.277|test|-|-|["1", "2", "3"]|
|2024-02-12 17:51:51.277|test|-|-|1234|
|2024-02-12 17:51:51.277|test|-|-|True|


##### Link to Devo Query

|DevoTableLink|
|---|
|[Devo Direct Link](https://us.devo.com/welcome#/verticalApp?path=apps/custom/dsQueryForwarder&targetQuery=blah==)|


### 5. devo-write-to-lookup-table

---
Writes lookup table entry records to a specified Devo table.

For more information on lookup tables please refer to documentation found [HERE](https://docs.devo.com/confluence/ndt/searching-data/working-in-the-search-window/data-enrichment).
We can add extra records with incremental lookup additions.\
Please refer to our Python SDK for more information on how we are
adding in extra lookup information found [HERE](https://github.com/DevoInc/python-sdk/)

#### Required Permissions

A Cortex XSOAR instance configured with the correct write JSON credentials.

#### Base Command

`devo-write-to-lookup-table`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lookupTableName | The lookup table name to write to. | Required | 
| headers | Headers for lookup table control. | Required | 
| records | Records to write to the specified table. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Devo.RecordsWritten | unknown | Lookup records written to the lookup table. | 


##### Command Example
```
!devo-write-to-lookup-table lookupTableName="lookup123" headers=`{"headers": ["foo", "bar", "baz"], "key_index": 0, "action": "FULL"}` records=`[{"fields": ["foo1", "bar1", "baz1"], "delete": false}, {"fields": ["foo2", "bar2", "baz2"]}, {"fields": ["foo3", "bar3", "baz3"]}]`
```

##### Human Readable Output
Lookup Table Name: lookup123.
Total Records Sent: 3.
Total Bytes Sent: 125.

##### Entries to load into Devo
The headers of headers array is written into the my.lookup.control table.

|eventdate|lookup|lookupId|lookupOp|type|lookupFields|
|---|---|---|---|---|---|
|2024-02-13 10:57:14.238|lookup123|1707802034.0032315_lookup123|FULL|START|[{"foo":{"type":"str","key":true}},{"bar":{"type":"str"}},{"baz":{"type":"str"}}]|
|2024-02-13 10:57:24.246|lookup123|1707802034.0032315_lookup123|FULL|END|[{"foo":{"type":"str","key":true}},{"bar":{"type":"str"}},{"baz":{"type":"str"}}]|

The fields of records array is written into the my.lookup.data table.

|eventdate|lookup|lookupId|lookupOp|rawData|
|---|---|---|---|---|
|2024-02-13 10:57:19.239|lookup123|1707802034.0032315_lookup123|null|"foo1", "bar1", "baz1"|
|2024-02-13 10:57:19.240|lookup123|1707802034.0032315_lookup123|null|"foo2", "bar2", "baz2"|
|2024-02-13 10:57:19.240|lookup123|1707802034.0032315_lookup123|null|"foo3", "bar3", "baz3"|

#### Youtube Video Demo (Click Image, Will redirect to youtube)

[(https://raw.githubusercontent.com/demisto/content/98ead849e9e32921f64f7ac07fda2bff1b5f7c0b/Packs/Devo/doc_files/devo_video.jpg)](https://www.youtube.com/watch?v=jyUqEcWOXfU)

## Known Limitations

* Currently the lookup table functionality is in Alpha. Please use at your own risk as behavior is still not fully stable.
* It is up to the user to make sure your Cortex XSOAR instance can handle the amount of data returned by a query.