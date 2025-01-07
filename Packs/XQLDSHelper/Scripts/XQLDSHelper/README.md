

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| templates_type | The type of the templates data. |
| template_name | The name of a template to choose it from 'templates'. |
| templates | A list of templates to choose from for building an entry. |
| base_time | The base time for the relative time provided to earliest_time or latest_time \(The default is the first available value from the following: alert.occurred, incident.occurred, alert.created, incident.created, now\). |
| round_time | The value \(in seconds\) used to round down the base time \(Default = 0\). |
| earliest_time | The earliest time at which the time range of the query starts \(Default = 24 hours ago\). |
| latest_time | The latest time at which the time range of the query ends \(Default = now\). |
| variable_substitution | The pair of default opening and closing markers that enclose a variable name \(Default = $\{,\}\). |
| cache_type | The name of the type that defines which data is stored and retrieved from the cache to create the entry \(Default = dataset\). |
| max_retries | The maximum number of retries to query XQL for recoverable errors \(Default = 10\). |
| retry_interval | The wait time \(in seconds\) between retries \(Default = 10\). |
| polling_interval | The polling interval \(in seconds\) to wait for results \(Default = 10\). |
| xql_query_instance | The name of the integration instance to execute xdr-xql-generic-query. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| XQLDSHelper.QueryParams | The query parameters. | unknown |
| XQLDSHelper.QueryHash | The hash value of the query parameters. | string |
| XQLDSHelper.Entry | The entry data for the general dynamic section. | unknown |
