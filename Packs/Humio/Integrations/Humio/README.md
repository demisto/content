Integration with Humio
This integration was integrated and tested with version xx of Humio
## Configure Humio on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Humio.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Humio URL | True |
| API-key | User API token | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| queryParameter | Query to use to fetch incidents | False |
| queryRepository | Fetch incidents from repository | False |
| queryStartTime | Fetch incidents from | False |
| queryTimeZoneOffsetMinutes | TimeZoneOffset in Minutes | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.
## Obtaining an API key
Go to https://your-humio/settings and copy the API token. Example [https://cloud.humio.com/settings](https://cloud.humio.com/settings)

## Fetch incidents
The parameters used for fetch-incidents are only used if you want to use the fetch incidents feature. It is recommended to use alerts and notifiers in Humio to send this data to XSOAR via a webhook notifier instead. You can read more about the supported time-formats for backfilling [here](https://docs.humio.com/api/using-the-search-api-with-humio/#time-specification)

## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### humio-query
***
Query the data from Humio


#### Base Command

`humio-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository | Repository to search | Required | 
| queryString | Query string to use | Required | 
| start | Relative or absolute (epoch) | Optional | 
| end | Relative or absolute (epoch) | Optional | 
| isLive | Answer with true, 1, t, y or yes | Optional | 
| timeZoneOffsetMinutes | TimeZoneOffset in Minutes (default 0) | Optional | 
| arguments | Additional arguments | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Humio.Query | Unknown | Query output | 


#### Command Example
```!humio-query repository=sandbox queryString="foo=bar" start=24h end=now isLive=false```

#### Context Example
```
{
    "Humio": {
        "Query": [
            [
                {
                    "#repo": "sandbox_Szpj6CNb6h7eWK1ZI09D9HFk",
                    "#type": "kv",
                    "@id": "hgXrSjcMWB08aJW40hfNUONL_3_2_1588676868",
                    "@rawstring": "foo=bar bar=foo",
                    "@session": "c12af55f-069d-43eb-840f-ff08fd11f685",
                    "@timestamp": 1588676868908,
                    "@timezone": "Z",
                    "bar": "foo",
                    "foo": "bar"
                },
                {
                    "#repo": "sandbox_Szpj6CNb6h7eWK1ZI09D9HFk",
                    "#type": "kv",
                    "@id": "hgXrSjcMWB08aJW40hfNUONL_3_1_1588676850",
                    "@rawstring": "foo=bar",
                    "@session": "c12af55f-069d-43eb-840f-ff08fd11f685",
                    "@timestamp": 1588676850226,
                    "@timezone": "Z",
                    "foo": "bar"
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>### Humio Query Results
>|#repo|#type|@id|@rawstring|@session|@timestamp|@timezone|bar|foo|
>|---|---|---|---|---|---|---|---|---|
>| sandbox_Szpj6CNb6h7eWK1ZI09D9HFk | kv | hgXrSjcMWB08aJW40hfNUONL_3_2_1588676868 | foo=bar bar=foo | c12af55f-069d-43eb-840f-ff08fd11f685 | 1588676868908 | Z | foo | bar |
>| sandbox_Szpj6CNb6h7eWK1ZI09D9HFk | kv | hgXrSjcMWB08aJW40hfNUONL_3_1_1588676850 | foo=bar | c12af55f-069d-43eb-840f-ff08fd11f685 | 1588676850226 | Z |  | bar |


### humio-query-job
***
Issue a query job to Humio


#### Base Command

`humio-query-job`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queryString | Query string to use | Required | 
| start | Relative or absolute (epoch) | Optional | 
| end | Relative or absolute (epoch) | Optional | 
| repository | Repository to use | Required | 
| isLive | Is it live? | Optional | 
| timeZoneOffsetMinutes | Timezone offset in Minutes | Optional | 
| arguments | Additional Arguments | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Humio.Job | Unknown | Query Job outputs | 


#### Command Example
```!humio-query-job queryString="foo=bar" repository=sandbox```

#### Context Example
```
{
    "Humio": {
        "Job": {
            "id": "1-1feyl7ulm_fmWhWmLhkPkWxZ",
            "queryOnView": "<M:foo=bar>"
        }
    }
}
```

#### Human Readable Output

>### Humio Query Job
>|id|queryOnView|
>|---|---|
>| 1-1feyl7ulm_fmWhWmLhkPkWxZ | <M:foo=bar> |


### humio-poll
***
Issue poll command to Humio


#### Base Command

`humio-poll`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository | Repository to use | Required | 
| id | Id to poll for  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Humio.Result | Unknown | Poll results | 
| Humio.Result.cancelled | Unknown | If it was cancelled | 
| Humio.Result.events | Unknown | Events in the poll | 
| Humio.Result.done | Unknown | If its done | 
| Humio.Result.metaData | Unknown | MetaData from the poll | 
| Humio.Result.job_id | String | Humio Job id the results came from | 


#### Command Example
```!humio-poll repository=sandbox id=1-mJg87kWn247FiYFpsnwZcx9G```

#### Context Example
```
{
    "Humio": {
        "Result": {
            "cancelled": false,
            "done": true,
            "events": [
                {
                    "#repo": "sandbox_Szpj6CNb6h7eWK1ZI09D9HFk",
                    "#type": "kv",
                    "@id": "hgXrSjcMWB08aJW40hfNUONL_3_2_1588676868",
                    "@rawstring": "foo=bar bar=foo",
                    "@session": "c12af55f-069d-43eb-840f-ff08fd11f685",
                    "@timestamp": 1588676868908,
                    "@timezone": "Z",
                    "bar": "foo",
                    "foo": "bar"
                },
                {
                    "#repo": "sandbox_Szpj6CNb6h7eWK1ZI09D9HFk",
                    "#type": "kv",
                    "@id": "hgXrSjcMWB08aJW40hfNUONL_3_1_1588676850",
                    "@rawstring": "foo=bar",
                    "@session": "c12af55f-069d-43eb-840f-ff08fd11f685",
                    "@timestamp": 1588676850226,
                    "@timezone": "Z",
                    "foo": "bar"
                }
            ],
            "job_id": "1-mJg87kWn247FiYFpsnwZcx9G",
            "metaData": {
                "eventCount": 2,
                "extraData": {
                    "hasMoreEvents": "false"
                },
                "filterQuery": {
                    "end": 1588680722272,
                    "includeDeletedEvents": false,
                    "isInteractive": false,
                    "isLive": false,
                    "noResultUntilDone": false,
                    "queryString": "foo=bar",
                    "showQueryEventDistribution": false,
                    "start": 1588594322272
                },
                "isAggregate": false,
                "pollAfter": 1000,
                "processedBytes": 704,
                "processedEvents": 6,
                "queryEnd": 1588680722272,
                "queryStart": 1588594322272,
                "resultBufferSize": 2,
                "timeMillis": 280833,
                "totalWork": 1,
                "warnings": [],
                "workDone": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Humio Poll Result
>|#repo|#type|@id|@rawstring|@session|@timestamp|@timezone|bar|foo|
>|---|---|---|---|---|---|---|---|---|
>| sandbox_Szpj6CNb6h7eWK1ZI09D9HFk | kv | hgXrSjcMWB08aJW40hfNUONL_3_2_1588676868 | foo=bar bar=foo | c12af55f-069d-43eb-840f-ff08fd11f685 | 1588676868908 | Z | foo | bar |
>| sandbox_Szpj6CNb6h7eWK1ZI09D9HFk | kv | hgXrSjcMWB08aJW40hfNUONL_3_1_1588676850 | foo=bar | c12af55f-069d-43eb-840f-ff08fd11f685 | 1588676850226 | Z |  | bar |


### humio-delete-job
***
Issue a job delete command to Humio


#### Base Command

`humio-delete-job`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the job to delete | Required | 
| repository | Repository to use | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!humio-delete-job repository=sandbox id=1-mJg87kWn247FiYFpsnwZcx9G```

#### Context Example
```
{}
```

#### Human Readable Output

>Command executed. Status code <Response [204]>

### humio-list-alerts
***
List alerts from Humio


#### Base Command

`humio-list-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository | Repository to use | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Humio.Alert.description | String | Description of the alert | 
| Humio.Alert.id | String | The alert id | 
| Humio.Alert.name | String | The alert name | 
| Humio.Alert.notifiers | String | The notifiers the alert will use | 
| Humio.Alert.query.end | String | the end time of the query | 
| Humio.Alert.query.isLive | Number | whether or not the query is live | 
| Humio.Alert.query.queryString | String | The query string being used | 
| Humio.Alert.query.start | String | The start time of the query | 
| Humio.Alert.silenced | Number | Whether or not the alert is enabled | 
| Humio.Alert.throttleTimeMillis | Number | The throttle time for alerts | 


#### Command Example
```!humio-list-alerts repository=sandbox```

#### Context Example
```
{
    "Humio": {
        "Alert": [
            {
                "description": "",
                "error": "All notifications failed.",
                "id": "ArHY37FM9Z8kWxYMRknwmdR5yJwNEUgc",
                "labels": [],
                "lastAlarm": 1588680716684,
                "name": "new_alert_namme2",
                "notifiers": [
                    "AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez"
                ],
                "query": {
                    "end": "now",
                    "isLive": true,
                    "queryString": "alert=true",
                    "start": "24h"
                },
                "silenced": false,
                "throttleTimeMillis": 300000
            },
            {
                "description": "",
                "error": "All notifications failed.",
                "id": "zXN-qja2pm5YFKVYDnllAmK4ctQ3wiOs",
                "labels": [],
                "lastAlarm": 1588680716684,
                "name": "new_alert_name3",
                "notifiers": [
                    "AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez"
                ],
                "query": {
                    "end": "now",
                    "isLive": true,
                    "queryString": "alert=true",
                    "start": "24h"
                },
                "silenced": false,
                "throttleTimeMillis": 300000
            },
            {
                "description": "",
                "error": "All notifications failed.",
                "id": "dIn3uuIvY4Gz90Bt2Dn2mVtDuB11ZUl2",
                "labels": [],
                "lastAlarm": 1588680716685,
                "name": "SampleAlert",
                "notifiers": [
                    "BTkuj8QArhIFMh_L39FoN0tnyTUEXplc"
                ],
                "query": {
                    "end": "now",
                    "isLive": true,
                    "queryString": "foo=bar",
                    "start": "24h"
                },
                "silenced": false,
                "throttleTimeMillis": 300000
            },
            {
                "description": "new_alert",
                "error": "All notifications failed.",
                "id": "kgguoWz0KgxEwge8IQt70L33C1J83U0C",
                "labels": [
                    "label"
                ],
                "lastAlarm": 1588680716684,
                "name": "new_alert_name",
                "notifiers": [
                    "AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez"
                ],
                "query": {
                    "end": "now",
                    "isLive": true,
                    "queryString": "alert=true",
                    "start": "24h"
                },
                "silenced": false,
                "throttleTimeMillis": 500000
            },
            {
                "description": "description 2",
                "id": "zNVae7vz-DH7GpeQUPfx1KXMGXGg7bf7",
                "labels": [
                    "label"
                ],
                "lastAlarm": 1588677696684,
                "name": "new name",
                "notifiers": [
                    "BTkuj8QArhIFMh_L39FoN0tnyTUEXplc"
                ],
                "query": {
                    "end": "now",
                    "isLive": true,
                    "queryString": "test=true",
                    "start": "24h"
                },
                "silenced": false,
                "throttleTimeMillis": 500000
            },
            {
                "description": "",
                "error": "All notifications failed.",
                "id": "sFeYsP2mOJ_-CAqKt9frixFIYzXluiTB",
                "labels": [],
                "lastAlarm": 1588680716684,
                "name": "new_alert_name2",
                "notifiers": [
                    "AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez"
                ],
                "query": {
                    "end": "now",
                    "isLive": true,
                    "queryString": "alert=true",
                    "start": "24h"
                },
                "silenced": false,
                "throttleTimeMillis": 300000
            },
            {
                "description": "",
                "error": "All notifications failed.",
                "id": "sn82IuvTc9Vfnl45XqLWoZASIcBezvu1",
                "labels": [],
                "lastAlarm": 1588680716684,
                "name": "new_alert_name4",
                "notifiers": [
                    "AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez"
                ],
                "query": {
                    "end": "now",
                    "isLive": true,
                    "queryString": "alert=true",
                    "start": "24h"
                },
                "silenced": false,
                "throttleTimeMillis": 300000
            },
            {
                "description": "",
                "error": "All notifications failed.",
                "id": "ljeBta_tEvrGRRbae7MzLRiZG4NbckBm",
                "labels": [],
                "lastAlarm": 1588680716684,
                "name": "new_alert_name5",
                "notifiers": [
                    "AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez"
                ],
                "query": {
                    "end": "now",
                    "isLive": true,
                    "queryString": "alert=true",
                    "start": "24h"
                },
                "silenced": false,
                "throttleTimeMillis": 300000
            }
        ]
    }
}
```

#### Human Readable Output

>### Humio Alerts
>|description|error|id|labels|lastAlarm|name|notifiers|query|silenced|throttleTimeMillis|
>|---|---|---|---|---|---|---|---|---|---|
>|  | All notifications failed. | ArHY37FM9Z8kWxYMRknwmdR5yJwNEUgc |  | 1588680716684 | new_alert_namme2 | AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez | end: now<br/>isLive: true<br/>queryString: alert=true<br/>start: 24h | false | 300000 |
>|  | All notifications failed. | zXN-qja2pm5YFKVYDnllAmK4ctQ3wiOs |  | 1588680716684 | new_alert_name3 | AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez | end: now<br/>isLive: true<br/>queryString: alert=true<br/>start: 24h | false | 300000 |
>|  | All notifications failed. | dIn3uuIvY4Gz90Bt2Dn2mVtDuB11ZUl2 |  | 1588680716685 | SampleAlert | BTkuj8QArhIFMh_L39FoN0tnyTUEXplc | end: now<br/>isLive: true<br/>queryString: foo=bar<br/>start: 24h | false | 300000 |
>| new_alert | All notifications failed. | kgguoWz0KgxEwge8IQt70L33C1J83U0C | label | 1588680716684 | new_alert_name | AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez | end: now<br/>isLive: true<br/>queryString: alert=true<br/>start: 24h | false | 500000 |
>| description 2 |  | zNVae7vz-DH7GpeQUPfx1KXMGXGg7bf7 | label | 1588677696684 | new name | BTkuj8QArhIFMh_L39FoN0tnyTUEXplc | end: now<br/>isLive: true<br/>queryString: test=true<br/>start: 24h | false | 500000 |
>|  | All notifications failed. | sFeYsP2mOJ_-CAqKt9frixFIYzXluiTB |  | 1588680716684 | new_alert_name2 | AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez | end: now<br/>isLive: true<br/>queryString: alert=true<br/>start: 24h | false | 300000 |
>|  | All notifications failed. | sn82IuvTc9Vfnl45XqLWoZASIcBezvu1 |  | 1588680716684 | new_alert_name4 | AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez | end: now<br/>isLive: true<br/>queryString: alert=true<br/>start: 24h | false | 300000 |
>|  | All notifications failed. | ljeBta_tEvrGRRbae7MzLRiZG4NbckBm |  | 1588680716684 | new_alert_name5 | AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez | end: now<br/>isLive: true<br/>queryString: alert=true<br/>start: 24h | false | 300000 |


### humio-get-alert-by-id
***
list alerts by id from Humio


#### Base Command

`humio-get-alert-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository | Repository to use | Required | 
| id | Alert ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Humio.Alert.description | String | Description of the alert | 
| Humio.Alert.id | String | The alert id | 
| Humio.Alert.name | String | The alert name | 
| Humio.Alert.notifiers | String | The notifiers the alert will use | 
| Humio.Alert.query.end | String | the end time of the query | 
| Humio.Alert.query.isLive | Number | whether or not the query is live | 
| Humio.Alert.query.queryString | String | The query string being used | 
| Humio.Alert.query.start | String | The start time of the query | 
| Humio.Alert.silenced | Number | Whether or not the alert is enabled | 
| Humio.Alert.throttleTimeMillis | Number | The throttle time for alerts | 


#### Command Example
```!humio-get-alert-by-id repository=sandbox id=ArHY37FM9Z8kWxYMRknwmdR5yJwNEUgc```

#### Context Example
```
{
    "Humio": {
        "Alert": {
            "description": "",
            "error": "All notifications failed.",
            "id": "ArHY37FM9Z8kWxYMRknwmdR5yJwNEUgc",
            "labels": [],
            "lastAlarm": 1588680716684,
            "name": "new_alert_namme2",
            "notifiers": [
                "AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez"
            ],
            "query": {
                "end": "now",
                "isLive": true,
                "queryString": "alert=true",
                "start": "24h"
            },
            "silenced": false,
            "throttleTimeMillis": 300000
        }
    }
}
```

#### Human Readable Output

>### Humio Alerts
>|error|id|lastAlarm|name|notifiers|query|silenced|throttleTimeMillis|
>|---|---|---|---|---|---|---|---|
>| All notifications failed. | ArHY37FM9Z8kWxYMRknwmdR5yJwNEUgc | 1588680716684 | new_alert_namme2 | AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez | end: now<br/>isLive: true<br/>queryString: alert=true<br/>start: 24h | false | 300000 |


### humio-create-alert
***
Create an alert in Humio


#### Base Command

`humio-create-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository | Repository to use | Required | 
| name | Name of the alert | Required | 
| queryString | Query to use | Required | 
| start | Start time, relative or epoch in ms. | Optional | 
| description | Description of the alert | Optional | 
| throttleTimeMillis | Time millis interval | Optional | 
| silenced | Is it silenced | Optional | 
| notifiers | comma-separated values of notifier IDs | Required | 
| labels | comma-separated values of labels | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Humio.Alert.description | String | Description of the alert | 
| Humio.Alert.id | String | The alert id | 
| Humio.Alert.name | String | The alert name | 
| Humio.Alert.notifiers | String | The notifiers the alert will use | 
| Humio.Alert.query.end | String | the end time of the query | 
| Humio.Alert.query.isLive | Number | whether or not the query is live | 
| Humio.Alert.query.queryString | String | The query string being used | 
| Humio.Alert.query.start | String | The start time of the query | 
| Humio.Alert.silenced | Number | Whether or not the alert is enabled | 
| Humio.Alert.throttleTimeMillis | Number | The throttle time for alerts | 


#### Command Example
```!humio-create-alert name=SampleTestAlert notifiers=BTkuj8QArhIFMh_L39FoN0tnyTUEXplc queryString="foo=bar" repository=sandbox```

#### Context Example
```
{
    "Humio": {
        "Alert": {
            "description": "",
            "id": "_LLJeuH_--APkyCVaj3NDdXPlyfAtcsB",
            "labels": [],
            "name": "SampleTestAlert",
            "notifiers": [
                "BTkuj8QArhIFMh_L39FoN0tnyTUEXplc"
            ],
            "query": {
                "end": "now",
                "isLive": true,
                "queryString": "foo=bar",
                "start": "24h"
            },
            "silenced": false,
            "throttleTimeMillis": 300000
        }
    }
}
```

#### Human Readable Output

>### Humio Alerts
>|id|name|notifiers|query|silenced|throttleTimeMillis|
>|---|---|---|---|---|---|
>| _LLJeuH_--APkyCVaj3NDdXPlyfAtcsB | SampleTestAlert | BTkuj8QArhIFMh_L39FoN0tnyTUEXplc | end: now<br/>isLive: true<br/>queryString: foo=bar<br/>start: 24h | false | 300000 |


### humio-list-notifiers
***
List all notifiers in Humio


#### Base Command

`humio-list-notifiers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository | Repository to use | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Humio.Notifier | Unknown | List of notifiers | 


#### Command Example
```!humio-list-notifiers repository=sandbox```

#### Context Example
```
{
    "Humio": {
        "Notifier": [
            {
                "entity": "WebHookNotifier",
                "id": "BTkuj8QArhIFMh_L39FoN0tnyTUEXplc",
                "name": "Null Webhook",
                "properties": {
                    "bodyTemplate": "{\n  \"repository\": \"{repo_name}\",\n  \"timestamp\": \"{alert_triggered_timestamp}\",\n  \"alert\": {\n    \"name\": \"{alert_name}\",\n    \"description\": \"{alert_description}\",\n    \"query\": {\n      \"queryString\": \"{query_string} \",\n      \"end\": \"{query_time_end}\",\n      \"start\": \"{query_time_start}\"\n    },\n    \"notifierID\": \"{alert_notifier_id}\",\n    \"id\": \"{alert_id}\",\n    \"linkURL\": \"{url}\"\n  },\n  \"warnings\": \"{warnings}\",\n  \"events\": {events},\n  \"numberOfEvents\": {event_count}\n}",
                    "headers": {
                        "Content-Type": "application/json"
                    },
                    "ignoreSSL": false,
                    "method": "POST",
                    "url": "http://localhost"
                }
            },
            {
                "entity": "WebHookNotifier",
                "id": "AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez",
                "name": "other",
                "properties": {
                    "bodyTemplate": "BODY",
                    "headers": {
                        "Content-Type": "application/json"
                    },
                    "ignoreSSL": false,
                    "method": "POST",
                    "url": "http://localhost"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Humio Notifiers
>|entity|id|name|properties|
>|---|---|---|---|
>| WebHookNotifier | BTkuj8QArhIFMh_L39FoN0tnyTUEXplc | Null Webhook | bodyTemplate: {<br/>  "repository": "{repo_name}",<br/>  "timestamp": "{alert_triggered_timestamp}",<br/>  "alert": {<br/>    "name": "{alert_name}",<br/>    "description": "{alert_description}",<br/>    "query": {<br/>      "queryString": "{query_string} ",<br/>      "end": "{query_time_end}",<br/>      "start": "{query_time_start}"<br/>    },<br/>    "notifierID": "{alert_notifier_id}",<br/>    "id": "{alert_id}",<br/>    "linkURL": "{url}"<br/>  },<br/>  "warnings": "{warnings}",<br/>  "events": {events},<br/>  "numberOfEvents": {event_count}<br/>}<br/>headers: {"Content-Type": "application/json"}<br/>ignoreSSL: false<br/>method: POST<br/>url: http://localhost |
>| WebHookNotifier | AQs6CuWm-uyXfYaNzwMyDGTX4S4qyAez | other | bodyTemplate: BODY<br/>headers: {"Content-Type": "application/json"}<br/>ignoreSSL: false<br/>method: POST<br/>url: http://localhost |


### humio-delete-alert
***
Delete alert in Humio


#### Base Command

`humio-delete-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository | Repository to use | Required | 
| id | ID of the alert to be deleted | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Humio.Humio-delete-alert | Unknown | Details of the deletion | 


#### Command Example
```!humio-delete-alert repository=sandbox id=dIn3uuIvY4Gz90Bt2Dn2mVtDuB11ZUl2```

#### Context Example
```
{}
```

#### Human Readable Output

>Command executed. Status code <Response [204]>

### humio-get-notifier-by-id
***
Get notifier from Humio by id


#### Base Command

`humio-get-notifier-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository | Repository to use | Required | 
| id | ID to use | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Humio.Notifier | Unknown | Details of the notifier | 


#### Command Example
```!humio-get-notifier-by-id repository=sandbox id=BTkuj8QArhIFMh_L39FoN0tnyTUEXplc```

#### Context Example
```
{
    "Humio": {
        "Notifier": {
            "entity": "WebHookNotifier",
            "id": "BTkuj8QArhIFMh_L39FoN0tnyTUEXplc",
            "name": "Null Webhook",
            "properties": {
                "bodyTemplate": "BODY",
                "headers": {
                    "Content-Type": "application/json"
                },
                "ignoreSSL": false,
                "method": "POST",
                "url": "http://localhost"
            }
        }
    }
}
```

#### Human Readable Output

>### Humio Notifiers
>|entity|id|name|properties|
>|---|---|---|---|
>| WebHookNotifier | BTkuj8QArhIFMh_L39FoN0tnyTUEXplc | Null Webhook | bodyTemplate: {<br/>  "repository": "{repo_name}",<br/>  "timestamp": "{alert_triggered_timestamp}",<br/>  "alert": {<br/>    "name": "{alert_name}",<br/>    "description": "{alert_description}",<br/>    "query": {<br/>      "queryString": "{query_string} ",<br/>      "end": "{query_time_end}",<br/>      "start": "{query_time_start}"<br/>    },<br/>    "notifierID": "{alert_notifier_id}",<br/>    "id": "{alert_id}",<br/>    "linkURL": "{url}"<br/>  },<br/>  "warnings": "{warnings}",<br/>  "events": {events},<br/>  "numberOfEvents": {event_count}<br/>}<br/>headers: {"Content-Type": "application/json"}<br/>ignoreSSL: false<br/>method: POST<br/>url: http://localhost |

