## Overview
---

The Devo_v2 Integration with enhanced functionality and data structures.
This integration was integrated and tested with version 6.0+ Devo. Devo is a generic log management
solution which can also act as an advanced SIEM. Users are able to query petabytes of data in a fraction
of the time that other traditional time series databases can't.

## Use Cases
---

* Ingest all user defined alerts from Devo into Demisto
* Query any data source available on the Devo.
* Run needle in haystack multi-table queries for threat hunting incidents.
* Write results back to Devo as searchable records or alerts.
* Write new entries into lookup tables to be used in synthesis tables (ALPHA)

## Prerequisites
---

* Active Devo account and domain.
* OAuth token with the `*.**` permissions.
* Writer TLS Certificate, Key, and Chain if writing back to Devo.

### Get your Demisto OAuth Token
1. Login to your Devo domain with a user with the ability to create security credentials.
2. Navigate to __Administration__ > __Credentials__ > __Authentication Tokens__.
3. If a token for Demisto has not already been  created, Click __CREATE NEW TOKEN__
  * Create the Token with `*.**` table permissions as an `apiv2` token.
4. Note the generated `Token`

### Get your Demisto Writer Credentials
1. Login to your Devo domain with a user with the ability to create security credentials.
2. Navigate to __Administration__ > __Credentials__ > __X.509 Certificates__.
3. Click `NEW CERTIFICATE` if you do not already have a set of keys for Demisto.
4. Download the following files:
  * `Certificate`
  * `Private Key`
  * `CHAIN CA`


## Configure Devo_v2 on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Devo_v2
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Query Server Endpoint (e.g. `https://apiv2-us.devo.com/search/query`)__
    * __Oauth Token (Preferred method)__
    * __Writer relay to connect to (e.g. us.elb.relay.logtrust.net)__ *Optional*
    * __Writer JSON credentials__ *Optional*
    ```
    {
        "key": string,
        "crt": string,
        "chain": string
    }
    ```
    * __Devo base domain__ *Optional*
    * __Use system proxy settings__ *Optional*
    * __Fetch incidents__ *Optional*
    * __Incident type__ *Optional*
    * __Fetch incidents alert filter (Same filters for get-alerts)__ *Optional*
    ```
    {
        "type": <"AND" | "OR">,
        "filters" : [
          {"key": <String Devo Column Name>, "operator": <Devo Linq Operator>, "value": <string>},
          {"key": <String Devo Column Name>, "operator": <Devo Linq Operator>, "value": <string>},
          ...
          {"key": <String Devo Column Name>, "operator": <Devo Linq Operator>, "value": <string>}
        ]
    }
    ```
    * __Deduplication parameters JSON if required. SEE README__ *Optional*
    ```
    {
        "cooldown": <int seconds cooldown for each type of alert>
    }
    ```
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---
Fetched incidents data will resemble closely to that of the data you get back from the `devo-get-alerts` command.
The format is as follows. The keyN in the main body will be the columns that you used to define your alert in Devo.
```
{
  "devo.metadata.alert": {
    "eventdate" :  string,
    "alertHost" :  string,
    "domain" :  string,
    "priority" :  string,
    "context" :  string,
    "category" :  string,
    "status" :  string,
    "alertId" :  string,
    "srcIp" :  string,
    "srcPort" :  string,
    "srcHost" :  string,
    "dstIp" :  string,
    "dstPort" :  string,
    "dstHost" :  string,
    "application" :  string,
    "engine" :  string
  },
  <key0>: <value0>,
  <key1>: <value1>,
  ...
  <keyN>: <valueN>
}
```
Currently the only data that is fetchable in Devo are the alerts that users have defined in the platform.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. devo-run-query
2. devo-get-alerts
3. devo-multi-table-query
4. devo-write-to-table
5. devo-write-to-lookup-table
### 1. devo-run-query
---
Queries Devo based on linq query.

Please refer to to the Devo documentation for building a query with LINQ
[HERE](https://docs.devo.com/confluence/ndt/searching-data/building-a-query/build-a-query-using-linq)
##### Required Permissions
**A Demisto instance configured with the correct OAuth token that has permission to query the target tables**
##### Base Command

`devo-run-query`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A LINQ Query to run | Required |
| from | Start datetime for specified query. Unix timestamp in seconds expected (Decimal milliseconds okay) | Required |
| to | End datetime for specified query. Unix timestamp in seconds expected (Decimal milliseconds okay) | Optional |
| writeToContext | Whether to write results to context or not | Optional |

#####__from__ and __to__ time note:
This integration allows for the following formats. Note that when __from__ and __to__ times
are both given that they must be the same given format.
- When __from__ is a date range such as "1 day", "30 minute", etc... __to__ is not needed and will be ignored even if given.
- Unix timestamps in millis and seconds are accepted.
- Datetime strings in the format '%Y-%m-%dT%H:%M:%S' are accepted.
- Python datetime objects are accepted as well.
- Unsupported formats will error out.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Devo.QueryResults | unknown | List of dictionary of results |
| Devo.QueryLink | unknown | Link back to Devo table for executed query |


##### Command Example
```
!devo-run-query query="from siem.logtrust.web.activity select *" from=1576845233.193244 to=1576845293.193244
```

##### Human Readable Output
Devo run query results

|eventdate|level|domain|userid|username|sessionid|correlationId|srcHost|srcPort|serverHost|serverPort|type|method|url|headers|params|referer|userAgent|locale|contentLength|responseLength|responseTime|result|resourceInfo|errorInfo|country|region|city|isp|org|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|2019-10-23T17:18:29.784000|INFO|helloworld|988409ce-3955-44a8-bcbb-b613bc8d9f8e|john.doe@devo.com|22671FE384D9FDF20E9BFFD7F4469971||1.2.3.4|45590|us.devo.com|8080||GET|https://us.devo.com/alerts/alertsGlobe.json||{origin:app.custom.tsAnomalyDetectionDev,serialNumber:ad475065-b0ef-4bbe-a620-a6dcd0874629,}|https://us.devo.com/welcome|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36|en_US|0|124|7|OK|||US|NJ|Secaucus|Ppman Services Srl|M247 Ltd New Jersey|
|2019-10-23T17:18:29.800000|INFO|helloworld|988409ce-3955-44a8-bcbb-b613bc8d9f8e|john.doe@devo.com|22671FE384D9FDF20E9BFFD7F4469971||1.2.3.4|45588|us.devo.com|8080||GET|`https://us.devo.com/domain/notification.json`||{origin:app.custom.tsAnomalyDetectionDev,serialNumber:ad475065-b0ef-4bbe-a620-a6dcd0874629,}|https://us.devo.com/welcome|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36|en_US|0|119|24|OK|||US|NJ|Secaucus|Ppman Services Srl|M247 Ltd New Jersey|
|2019-10-23T17:18:59.780000|INFO|helloworld|988409ce-3955-44a8-bcbb-b613bc8d9f8e|john.doe@devo.com|22671FE384D9FDF20E9BFFD7F4469971||1.2.3.4|45816|us.devo.com|8080||GET|https://us.devo.com/alerts/alertsGlobe.json||{origin:app.custom.tsAnomalyDetectionDev,serialNumber:ad475065-b0ef-4bbe-a620-a6dcd0874629,}|https://us.devo.com/welcome|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36|en_US|0|124|7|OK|||US|NJ|Secaucus|Ppman Services Srl|M247 Ltd New Jersey|
|2019-10-23T17:18:59.799000|INFO|helloworld|988409ce-3955-44a8-bcbb-b613bc8d9f8e|john.doe@devo.com|22671FE384D9FDF20E9BFFD7F4469971||1.2.3.4|45814|us.devo.com|8080||GET|`https://us.devo.com/domain/notification.json`||{origin:app.custom.tsAnomalyDetectionDev,serialNumber:ad475065-b0ef-4bbe-a620-a6dcd0874629,}|https://us.devo.com/welcome|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36|en_US|0|119|25|OK|||US|NJ|Secaucus|Ppman Services Srl|M247 Ltd New Jersey|
|2019-10-23T17:19:29.777000|INFO|helloworld|988409ce-3955-44a8-bcbb-b613bc8d9f8e|john.doe@devo.com|22671FE384D9FDF20E9BFFD7F4469971||1.2.3.4|46096|us.devo.com|8080||GET|https://us.devo.com/alerts/alertsGlobe.json||{origin:app.custom.tsAnomalyDetectionDev,serialNumber:ad475065-b0ef-4bbe-a620-a6dcd0874629,}|https://us.devo.com/welcome|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36|en_US|0|124|7|OK|||US|NJ|Secaucus|Ppman Services Srl|M247 Ltd New Jersey|

|DevoTableLink|
|---|
|[Devo Direct Link](https://us.devo.com/welcome#/verticalApp?path=apps/custom/dsQueryForwarder&targetQuery=blah==)|

### 2. devo-get-alerts
---
Queries alerts in the specified timeframe.

Alerts are based off the table `siem.logtrust.alert.info` found in your Devo account. Please refer to this table
for a list of columns you can filter off of. Also please refer back to the LINQ documentation for operations
that are allowed.
##### Required Permissions
**Requires a Devo OAuth token that has read permission on siem.logtrust.alert.info table**
##### Base Command

`devo-get-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | Start datetime for alerts to fetch | Required |
| to | End datetime for alerts to fetch | Optional |
| filters | key value filter to apply to retrieve specified alerts. refer to docs | Optional |
| writeToContext | write results to context or not | Optional |

#####__from__ and __to__ time note:
This integration allows for the following formats. Note that when __from__ and __to__ times
are both given that they must be the same given format.
- When __from__ is a date range such as "1 day", "30 minute", etc... __to__ is not needed and will be ignored even if given.
- Unix timestamps in millis and seconds are accepted.
- Datetime strings in the format '%Y-%m-%dT%H:%M:%S' are accepted.
- Python datetime objects are accepted as well.
- Unsupported formats will error out.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Devo.AlertsResults | list of dictionaries | List of dictionary alerts in specified time range |
| Devo.QueryLink | string | Link back to Devo table for executed query |


##### Command Example
```
!devo-get-alerts from=1576845233.193244 to=1576845293.193244
```

##### Human Readable Output
Devo get alerts results

|eventdate|alertHost|domain|priority|context|category|status|alertId|srcIp|srcPort|srcHost|dstIp|dstPort|dstHost|protocol|username|application|engine|extraData|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|2019-10-23T18:18:07.320000|backoffice|helloworld|5.0|my.alert.helloworld.simultaneous_login|my.context|4|6715552||||||||||pilot.my.alert.helloworld.simultaneous_login|duration_seconds: 30.142<br/>cluster: -<br/>prev_timestamp: 2019-10-23+18:17:29.652<br/>instance: -<br/>distance: 294.76<br/>level: info<br/>city: Secaucus<br/>srcHost: 1.2.3.4<br/>prev_city: Waltham<br/>format: output_qs9n126lnvh<br/>prev_geolocation: 42°23'49.925537109375"N+71°14'36.2420654296875"W<br/>message: 0,9,31,49,69,77,123,136,149,156,204,217,231&lt;&gt;ANOMALOUSjohn.doe@devo.com294.755774516937950.008372777777777778Secaucus40°47'15.36529541015625"N+74°3'35.9912109375"W15718546797941.2.3.4Waltham42°23'49.925537109375"N+71°14'36.2420654296875"W157185464965250.204.142.130<br/>eventdate: 2019-10-23+18:18:02.087<br/>prev_srcHost: 50.204.142.130<br/>duration: 0.008372777777777778<br/>indices: 0,9,31,49,69,77,123,136,149,156,204,217,231<br/>payload: ANOMALOUSjohn.doe@devo.com294.755774516937950.008372777777777778Secaucus40°47'15.36529541015625"N+74°3'35.9912109375"W15718546797941.2.3.4Waltham42°23'49.925537109375"N+71°14'36.2420654296875"W157185464965250.204.142.130<br/>state: ANOMALOUS<br/>category: modelserverdev<br/>facility: user<br/>username: john.doe@devo.com<br/>geolocation: 40°47'15.36529541015625"N+74°3'35.9912109375"W<br/>timestamp: 2019-10-23+18:17:59.794|

|DevoTableLink|
|---|
|[Devo Direct Link](https://us.devo.com/welcome#/verticalApp?path=apps/custom/dsQueryForwarder&targetQuery=blah==)|

### 3. devo-multi-table-query
---
Queries multiple tables for a given token and returns relevant results.

This method is used for when you do not know which columns a specified search token will show up in (Needle in a haystack search)
Thus querying all columns for the search token and returning a union of the given tables.
##### Required Permissions
**A Demisto instance configured with the correct OAuth token that has permission to query the target tables**
##### Base Command

`devo-multi-table-query`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tables | List of table names to check for searchToken | Required |
| searchToken | String that you wish to search for in given tables in any column | Required |
| from | Start time in seconds unix timestamp | Required |
| to | End time in seconds unix timestamp | Optional |
| writeToContext | write results to context or not | Optional |

#####__from__ and __to__ time note:
This integration allows for the following formats. Note that when __from__ and __to__ times
are both given that they must be the same given format.
- When __from__ is a date range such as "1 day", "30 minute", etc... __to__ is not needed and will be ignored even if given.
- Unix timestamps in millis and seconds are accepted.
- Datetime strings in the format '%Y-%m-%dT%H:%M:%S' are accepted.
- Python datetime objects are accepted as well.
- Unsupported formats will error out.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Devo.MultiResults | list of dictionaries | List of dictionary results |


##### Command Example
```
!devo-multi-table-query tables='["siem.logtrust.web.activity", "siem.logtrust.web.navigation"]' searchToken="john@doe.com" from=1576845233.193244 to=1576845293.193244
```

##### Human Readable Output
Devo multi-query results

|isp|serverPort|srcPort|responseTime|headers|eventdate|correlationId|userEmail|responseLength|message|result|method|type|url|userid|level|referer|username|region|userAgent|sessionid|resourceInfo|contentLength|org|domain|srcHost|city|params|serverHost|errorInfo|section|action|origin|country|locale|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|Amazon.com|8080|33522|||2019-09-18T07:58:39.691000||john@doe.com|||||0|`https://us.devo.com/alerts/view.json`|400d338d-c9a6-4930-90a5-357937f3e735||https://us.devo.com/welcome||VA|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36|8723DEE4B38F1056BC738760B5E79FD3|||Amazon.com|helloworld|1.2.3.4|Ashburn||us.devo.com||alert|index|undefined|US||
|Amazon.com|8080|33532|||2019-09-18T07:58:40.789000||john@doe.com|||||0|https://us.devo.com/generic/storedSearchAction.streamjson|400d338d-c9a6-4930-90a5-357937f3e735||https://us.devo.com/welcome||VA|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36|8723DEE4B38F1056BC738760B5E79FD3|||Amazon.com|helloworld|1.2.3.4|Ashburn||us.devo.com||stored_continuum_search|create|undefined|US||
|Amazon.com|8080|33538|||2019-09-18T07:58:40.801000||john@doe.com|||||0|https://us.devo.com/generic/storedSearchAction.streamjson|400d338d-c9a6-4930-90a5-357937f3e735||https://us.devo.com/welcome||VA|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36|8723DEE4B38F1056BC738760B5E79FD3|||Amazon.com|helloworld|1.2.3.4|Ashburn||us.devo.com||stored_continuum_search|create|undefined|US||
|Amazon.com|8080|33574|||2019-09-18T07:58:41.685000||john@doe.com||UserDomain: UserDomain[id: 2942, domain: 6ab72601-e982-4694-8ce6-3d526047f8a5/helloworld, roles: null, logged: 2019-09-18 04:32:58.0, status: 0, creation date: 2018-11-05 14:23:44.0, update date: 2019-09-18 04:32:58.0]\||||0|https://us.devo.com/lxcWidgets/lxcWidget.json|400d338d-c9a6-4930-90a5-357937f3e735||https://us.devo.com/welcome||VA|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36|8723DEE4B38F1056BC738760B5E79FD3|||Amazon.com|helloworld|1.2.3.4|Ashburn||us.devo.com||lxc_widgets|index|undefined|US||
|Comcast Cable|8080|37094|45||2019-09-18T08:08:21.593000|||124||OK|GET||https://us.devo.com/alerts/alertsGlobe.json|400d338d-c9a6-4930-90a5-357937f3e735|INFO|https://us.devo.com/welcome|john@doe.com|CA|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36|8723DEE4B38F1056BC738760B5E79FD3||0|Comcast Cable|helloworld|1.2.3.4|San Francisco|{origin:menu.alerts,serialNumber:b181cf08-14e0-49c2-826b-e4ff36afaa84,}|us.devo.com|||||US|en_US|
|Comcast Cable|8080|37092|78||2019-09-18T08:08:21.625000|||119||OK|GET||`https://us.devo.com/domain/notification.json`|400d338d-c9a6-4930-90a5-357937f3e735|INFO|https://us.devo.com/welcome|john@doe.com|CA|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36|8723DEE4B38F1056BC738760B5E79FD3||0|Comcast Cable|helloworld|1.2.3.4|San Francisco|{origin:menu.alerts,serialNumber:b181cf08-14e0-49c2-826b-e4ff36afaa84,}|us.devo.com|||||US|en_US|
|Comcast Cable|8080|37196|10||2019-09-18T08:08:51.563000|||124||OK|GET||https://us.devo.com/alerts/alertsGlobe.json|400d338d-c9a6-4930-90a5-357937f3e735|INFO|https://us.devo.com/welcome|john@doe.com|CA|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36|8723DEE4B38F1056BC738760B5E79FD3||0|Comcast Cable|helloworld|1.2.3.4|San Francisco|{origin:menu.alerts,serialNumber:b181cf08-14e0-49c2-826b-e4ff36afaa84,}|us.devo.com|||||US|en_US|
|Comcast Cable|8080|37194|33||2019-09-18T08:08:51.583000|||119||OK|GET||`https://us.devo.com/domain/notification.json`|400d338d-c9a6-4930-90a5-357937f3e735|INFO|https://us.devo.com/welcome|john@doe.com|CA|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36|8723DEE4B38F1056BC738760B5E79FD3||0|Comcast Cable|helloworld|1.2.3.4|San Francisco|{origin:menu.alerts,serialNumber:b181cf08-14e0-49c2-826b-e4ff36afaa84,}|us.devo.com|||||US|en_US|


### 4. devo-write-to-table
---
Write records to a specified Devo table

The records written to the table should all be of the same JSON format and to the same table. We currently do not support
writing to multiple tables in a single operation.

For more information on the way we write to a table please refer to this documentation found [HERE](https://github.com/DevoInc/python-ds-connector#loading-data-into-devo)
##### Required Permissions
**A Demisto instance configured with the correct write JSON credentials**
##### Base Command

`devo-write-to-table`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tableName | Table name to write to | Required |
| records | Records to write to given tableName | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Devo.RecordsWritten | int | Count of records written to Devo |
| Devo.LinqQuery | string | Linq query that is to be used to see your data in Devo |
| Devo.QueryLink | string | Link back to Devo table for executed query |


##### Command Example
```
!devo-write-to-table tableName="my.app.demisto.test" records='[{"hello": "world"}, {"hello": "demisto"}]'
```

##### Human Readable Output
Entries to load into Devo

|hello|
|---|
|world|
|demisto||

Link to Devo Query

|DevoTableLink|
|---|
|[Devo Direct Link](https://us.devo.com/welcome#/verticalApp?path=apps/custom/dsQueryForwarder&targetQuery=blah==)|


### 5. devo-write-to-lookup-table
---
Writes a record to a given lookup table

For more information on lookup tables please refer to documentation found [HERE](https://docs.devo.com/confluence/ndt/searching-data/working-in-the-search-window/data-enrichment).
We can add extra records with incremental lookup additions. Please refer to our Python SDK for more information on how we are
adding in extra lookup information found [HERE](https://github.com/DevoInc/python-sdk/)
##### Required Permissions
**A Demisto instance configured with the correct write JSON credentials**
##### Base Command

`devo-write-to-lookup-table`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lookupTableName | Lookup table name you are trying to write to | Required |
| headers | Headers of records to upload. Order sensitive. | Optional |
| records | Lookup table records to insert | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Devo.RecordsWritten | int | Count of records written to Devo |


##### Command Example
```
!devo-write-to-lookup-table lookupTableName="lookup123" headers='["foo", "bar", "baz"]' records='[{"key": "foo1", "values": ["foo1", "bar1", "baz1"]}]'
```

##### Human Readable Output
N/A


#### Youtube Video Demo (Click Image, Will redirect to youtube)
[![Devo-Demisto Plugin Demo](https://img.youtube.com/vi/jyUqEcWOXfU/0.jpg)](https://www.youtube.com/watch?v=jyUqEcWOXfU "Devo Demisto Demo")

## Known Limitations
---
* Currently the lookup table functionality is in Alpha. Please use at your own risk as behavior is still not fully stable.
* It is up to the user to make sure your demisto instance can handle the amount of data returned by a query.
