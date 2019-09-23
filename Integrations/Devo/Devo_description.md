## Demisto - Devo Integration ##

_Please note this integration is currently in active development and functionality may change_

The main purpose of the Devo Integration is two-fold. The first is to allow for easier querying of data
through Devo with additional logic to benefit the end user. The second is to provide a method for logging data back
into Devo with a queryable format without the need of building a custom parser.

### Devo Parameters ###

| Parameter               | Required | Type            | Default                                | Description                                                                                                                                                                                        |
|-------------------------|----------|-----------------|----------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| reader_endpoint         | TRUE     | Short Text      | https://apiv2-us.devo.com/search/query | The reader endpoint is the query endpoint that you wish to use for querying. Defaults to the US query domain.                                                                                      |
| reader_oauth_token      | TRUE     | Encrypted       | None                                   | This is the oauth token you must pass.  Please note at this time the oauth token will need `*.**` access for the integration `Test` to work. Will allow for custom health check in next iteration. |
| writer_relay            | FALSE    | Short Text      | None                                   | Writer relay that you will use to send data to Devo. The default US cloud hosted relay is `us.elb.relay.logtrust.net`                                                                              |
| writer_credentials      | False    | Encrypted       | None                                   | This value needs to be a valid JSON string object with the following keys: `key`, `crt`, and `chain`                                                                                               |
| Fetch Incidents         | False    | Built-In Option | False                                  | If checked this box will fetch alerts every minute and populate your incidents with them.                                                                                                          |
| fetch_incidents_filters | False    | Short Text      | None                                   | If fetch-incidents enabled this will apply filters the same way as the get-alerts command would apply. Please see how to define filters                                                            |

**Examples**

*reader_endpoint*
```
https://apiv2-us.devo.com/search/query
```

*reader_oauth_token*
```
IAMANOAUTHTOKEN
```

*writer_relay*
```
us.elb.relay.logtrust.net
```

*writer_credentials*
```json
{
  "key":"FAKEKEYHERE",
  "crt":"FAKECERTHERE",
  "chain":"FAKECHAINHERE"
}
```

*fetch_incidents_filters*
```json
[
  {"key":"engine","value":"simultaneous_login", "operator":"->"},
  {"key":"extraData","value":"test@test.com","operator":"->"},
  {"key":"extraData","value":"ANOMALOUS","operator":"->"}
]
```

### Devo (Preview) Commands ###

`devo-run-query`

Runs a linq query and returns results from the specified timeframe.

*inputs*

| Argument       | Required | Type   | Description                                                                                                                                                        |
|----------------|----------|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| query          | TRUE     | string | A linq query that you wish to run against Devo                                                                                                                     |
| from           | TRUE     | float  | Start datetime for specified Query. Expects a unix timestamp in seconds with milliseconds allowed after decimal points.                                            |
| to             | FALSE    | float  | End datetime for specified Query. If no value is provided will default to now. Expects a unix timestamp in seconds with milliseconds allowed after decimal points |
| writeToContext | FALSE    | string | String of `true` or `false` to pass on the results context.                                                                                                        |

*outputs*

| ContextPath       | Type          | Description                                                                                                                                         |
|-------------------|---------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| Devo.QueryResults | list(objects) | Will return a list of python dictionary objects. Each object in the list will be a row from the query. If no rows are returned result will be null. |
| Devo.QueryLink    | object        | Will return an JSON object with a single key called DevoTableLink and a URL link back to Devo for the results just queried.                         |

*current caveats*
- None

`devo-multi-table-query`

Runs a linq query against multiple tables to search for a specified token in any column. This command should only be
run in smaller timeframes to avoid returning massive amounts of data.

*inputs*

| Argument       | Required | Type         | Description                                                                                                                                                       |
|----------------|----------|--------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| tables         | TRUE     | list(string) | An array of string tablenames that should be scanned for the given searchToken.                                                                                   |
| searchToken    | TRUE     | string       | A string search token to search for in all given columns of the specified tables.                                                                                 |
| from           | TRUE     | float        | Start datetime for specified Query. Expects a unix timestamp in seconds with milliseconds allowed after decimal                                                   |
| to             | FALSE    | float        | End datetime for specified Query. If no value is provided will default to now. Expects a unix timestamp in seconds with milliseconds allowed after decimal points |
| writeToContext | FALSE    | string       | String of `true` or `false` to pass on the results                                                                                                                |

*outputs*

| ContextPath       | Type          | Description                                                                                                                                         |
|-------------------|---------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| Devo.MultiResults | list(objects) | Will return a list of python dictionary objects. Each object in the list will be a row from the query. If no rows are returned result will be null. |

*current caveats*
- This command is potentially very dangerous as you can end up scanning **A LOT** of data.
- Next version will offer better guard rails in the form of limiting results and may use a paging system to get results

`devo-get-alerts`

Grabs all alerts based on specified filters for a given time range.

*inputs*

| Argument       | Required | Type          | Description                                                                                                                                              |
|----------------|----------|---------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| from           | TRUE     | float         | Start datetime for alerts. Expects a unix timestamp in seconds with milliseconds allowed after decimal                                                   |
| to             | FALSE    | float         | End datetime for alerts. If no value is provided will default to now. Expects a unix timestamp in seconds with milliseconds allowed after decimal points |
| filters        | FALSE    | list(objects) | List of JSON objects that are `{"key":<string>, "value":<string>, "operator":<string>}` where `key` is the column and `value` is the filter you wish to apply. Please refer to `siem.logtrust.alert.info` for valid columns and also linq reference for valid operators                                   |
| writeToContext | FALSE    | string        | String of `true` or `false` to pass on the results                                                                                                       |

*outputs*

| ContextPath       | Type          | Description                                                                                                                                         |
|-------------------|---------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| Devo.AlertsResults | list(objects) | Will return a list of python dictionary objects. Each object in the list will be an alert that was triggered from Devo. If no alerts are returned result will be null. |
| Devo.QueryLink    | object        | Will return an JSON object with a single key called DevoTableLink and a URL link back to Devo for the results just queried.                         |

*current caveats*
- The only filters you can apply currently are matches in specified columns, next version will offer more customization.

`devo-write-to-table`

Writes a list of given events to a specified table.

*inputs*

| Argument  | Required | Type          | Description                                                                                                                                                                                       |
|-----------|----------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| tableName | TRUE     | string        | The name of the Devo table you are trying to write to                                                                                                                                             |
| records   | TRUE     | list(objects) | A list of objects where each object is a separate event. Currently it is a good idea that all of your events have the exact same keys so that the generated linq query will parse data correctly. |

*outputs*

| ContextPath         | Type          | Description                                                                                                        |
|---------------------|---------------|--------------------------------------------------------------------------------------------------------------------|
| Devo.RecordsWritten | list(objects) | Will return a list of python dictionary objects. Each object in the list will be the row that was written to Devo. |
| Devo.LinqQuery      | string        | A string that you can use to parse the data in the table you just wrote to.                                        |
| Devo.QueryLink      | object        | Will return an JSON object with a single key called DevoTableLink and a URL link back to Devo for records just written                         |

*current caveats*
- All the objects should have same keys or else the format we are writing the tables for on the fly parsing will fail.
- Next version will allow for raw messages to be uploaded instead of expecting dictionary objects in a list only.

`fetch-incidents`

This will fetch incidents if enabled. There is one global setting for the filters to be applied for fetching the alerts.
Please reference the Devo Security Operation's team's guide on how to enrich alerts with lookup tables. As described if
your alert has the `extraData` fields enriched by a lookup table we will accordingly map those fields with the Demisto
incident.

*inputs*

| Argument                | Required | Type          | Description                                                                             |
|-------------------------|----------|---------------|-----------------------------------------------------------------------------------------|
| fetch_incidents_filters | false    | list(objects) | Same as get-alerts filters. This filter will be used when fetching incidents from Devo. |

This integration will attempt to map specific fields to some incident fields as described below if they are present
within the `extraData` field of the alert.

*mapping*

| extraData Field            | Mapped Incident Field | Type   | Default       | Description                                                                                             |
|----------------------------|-----------------------|--------|---------------|---------------------------------------------------------------------------------------------------------|
| extraData.alertPriority    | severity              | string | 1             | The priority from Devo will be mapped accordingly to Demisto. Please see SecOps documentation on levels |
| extraData.alertName        | name                  | string | alert.context | A specified name for the incident that can be different to that of the alert name.                      |
| extraData.alertDescription | details               | string | None          | Any additional details about this alert that has been enriched from a lookup table                      |
