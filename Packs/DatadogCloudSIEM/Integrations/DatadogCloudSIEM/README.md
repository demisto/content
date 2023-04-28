## Datadog Cloud SIEM

Datadog is an observability service for cloud-scale applications, providing monitoring of servers, databases, tools, and services, through a SaaS-based data analytics platform.

The SaaS platform integrates and automates infrastructure monitoring, application performance monitoring and log management to provide unified, real-time observability of our customers' entire technology stack.
This integration was integrated and tested with version 2.12.0 of DatadogCloudSIEM

## Configure Datadog Cloud SIEM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Datadog Cloud SIEM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | Datadog website URL | True |
    | API Key | The API Key to use for authentication | True |
    | Application Key | The application key to use for authentication. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | How many incidents to fetch each time. |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) |  | False |
    | Incident type |  | False |
    | Fetch incidents |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### datadog-event-create

***
This endpoint allows you to post events to the stream.

#### Base Command

`datadog-event-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | The body of the event.<br/>Limited to 4000 characters.<br/>The text supports markdown. To use markdown in the event text, start the text block with %%% \n and end the text block with \n %%% . | Required | 
| title | The title of an event. | Required | 
| date_happened | Limited to events no older than 18 hours.<br/>Format :  <br/>yyyy-MM-dd’T’HH:mm:ssZ or “12 hours ago” or “-12 hours” or “15 min ago” or “-15 min”. | Optional | 
| device_name | A device name. | Optional | 
| host_name | Host name to associate with the event . | Optional | 
| priority | The priority of the event.<br/><br/>Restricted value : low<br/>Permitted value :  normal (Bug will be fixed in near future). Possible values are: normal, low. | Optional | 
| related_event_id | ID of the parent event. | Optional | 
| tags | A list of tags to apply to the event. <br/>Comma seperated strings.<br/>Ex: "environment:production, region:East” . | Optional | 
| aggregation_key | An arbitrary string to use for aggregation. <br/>If you specify a key, all events using that key are grouped together in the Event Stream. <br/>Limited to 100 characters. | Optional | 
| source_type_name | The type of event being posted. A complete list of source attribute values available here. https://docs.datadoghq.com/integrations/faq/list-of-api-source-attribute-value/. | Optional | 
| alert_type | If an alert event is enabled, set its type. Possible values are: error, warning, info, success, user_update, recommendation, snapshot. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Event.date_happened | Number | POSIX timestamp of the event | 
| Datadog.Event.id | Number | Integer ID of the event. | 
| Datadog.Event.priority | String | The priority of the event. For example, normal or low. Allowed enum values: normal, low. | 
| Datadog.Event.text | String | The body of the event. Limited to 4000 characters. The text supports markdown. | 
| Datadog.Event.tags | Unknown | A list of tags to apply to the event. | 
| Datadog.Event.url | String | URL of the event. | 
| Datadog.Event.status | String | The status of the event. | 
| Datadog.Event.title | String | The event title. | 
| Datadog.Event.alert_type | String | Allowed enum values: error, warning, info, success, user update, recommendation, snapshot | 
| Datadog.Event.device_name | String | A device name. | 
| Datadog.Event.source_type_name | String | The type of event being posted. | 
| Datadog.Event.host | String | Host name to associate with the event. Any tags associated with the host are also applied to this event. | 

#### Command example
```!datadog-event-create title="EventTitle" text="EventText"```
#### Context Example
```json
{
    "Datadog": {
        "Event": {
            "event": {
                "date_happened": 1682693546,
                "handle": null,
                "id": 7020101911644005000,
                "id_str": "7020101911644005221",
                "priority": null,
                "related_event_id": null,
                "tags": null,
                "text": "EventText",
                "title": "EventTitle",
                "url": "https://app.datadoghq.com/event/event?id=7020101911644005221"
            },
            "status": "ok"
        }
    }
}
```

#### Human Readable Output

>### Event Details
>|Title|Text|Date Happened|Id|
>|---|---|---|---|
>| EventTitle | EventText | April 28, 2023 02:52 PM | 7020101911644005221 |


### datadog-event-list

***
Get a list of Events / Get the details of a particular Event.

#### Base Command

`datadog-event-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the event. | Optional | 
| start_date | Start Date <br/>Format : yyyy-MM-dd’T’HH:mm:ssZ  or “-1days” or “12 hours ago” or “-12 hours” or “15 min ago” or “-15 min”. . | Optional | 
| end_date | End Date <br/>Default: now <br/>Format : yyyy-MM-dd’T’HH:mm:ssZ or "-1 days" or “12 hours ago” or “-12 hours” or “15 min ago” or “-15 min”. . | Optional | 
| priority | The priority of the event. Possible values are: normal, low. | Optional | 
| sources | A comma separated string of sources.<br/>A complete list of source attribute values available here: https://docs.datadoghq.com/integrations/faq/list-of-api-source-attribute-value/. | Optional | 
| tags | A comma separated list indicating what tags, if any, should be used to filter the list of events. <br/>Comma seperated string <br/>Ex: "environment:production, region:East". | Optional | 
| unaggregated | Set unaggregated to 'true' to return all events within the specified [start,end] timeframe. Possible values are: True, False. | Optional | 
| exclude_aggregate | Set exclude_aggregate to 'true' to only return unaggregated events where is_aggregate=false in the response. Possible values are: True, False. | Optional | 
| page | The page number. Default is 1. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Event.alert_type | String | Allowed enum values: error,warning,info,success,user_update,recommendation,snapshot | 
| Datadog.Event.date_happened | Number | POSIX timestamp of the event | 
| Datadog.Event.device_name | String | A device name.  | 
| Datadog.Event.id | Number | Integer ID of the event. | 
| Datadog.Event.priority | String | The priority of the event. For example, normal or low. Allowed enum values: normal, low. | 
| Datadog.Event.text | String | The body of the event. Limited to 4000 characters. The text supports markdown. | 
| Datadog.Event.tags | Unknown | A list of tags to apply to the event. | 
| Datadog.Event.url | String | URL of the event. | 
| Datadog.Event.status | String | The status of the event. | 
| Datadog.Event.host | String | Host name to associate with the event. Any tags associated with the host are also applied to this event. | 
| Datadog.Event.title | String | The Event title. | 
| Datadog.Event.source_type_name | String | The type of event being posted. | 

#### Command example
```!datadog-event-list limit=2```
#### Context Example
```json
{
    "Datadog": {
        "Event": [
            {
                "alert_type": "info",
                "comments": [],
                "date_happened": 1682693438,
                "device_name": null,
                "host": null,
                "id": 7020100108476104000,
                "id_str": "7020100108476103833",
                "is_aggregate": false,
                "monitor_group_status": null,
                "monitor_groups": [],
                "monitor_id": null,
                "priority": "normal",
                "resource": "/api/v1/events/7020100108476103833",
                "source": "Incidents",
                "tags": [
                    "source:incidents"
                ],
                "text": "Status: Active | Severity: Unknown | Commander: Unassigned\nhttps://app.datadoghq.com/incidents/221",
                "title": "Incident #221: incident-test1",
                "url": "/event/event?id=7020100108476103833"
            },
            {
                "alert_type": "info",
                "comments": [],
                "date_happened": 1682693405,
                "device_name": null,
                "host": null,
                "id": 7020099538683812000,
                "id_str": "7020099538683812328",
                "is_aggregate": false,
                "monitor_group_status": null,
                "monitor_groups": [],
                "monitor_id": null,
                "priority": "normal",
                "resource": "/api/v1/events/7020099538683812328",
                "source": "My Apps",
                "tags": [
                    "source:my_apps"
                ],
                "text": "EventText",
                "title": "EventTitle",
                "url": "/event/event?id=7020099538683812328"
            }
        ]
    }
}
```

#### Human Readable Output

>### Events List
>|Title|Text|Date Happened|Id|Priority|Source|Tags|Is Aggregate|Alert Type|
>|---|---|---|---|---|---|---|---|---|
>| Incident #221: incident-test1 | Status: Active \| Severity: Unknown \| Commander: Unassigned<br/>https:<span>//</span>app.datadoghq.com/incidents/221 | April 28, 2023 02:50 PM | 7020100108476103833 | normal | Incidents | source:incidents | false | info |
>| EventTitle | EventText | April 28, 2023 02:50 PM | 7020099538683812328 | normal | My Apps | source:my_apps | false | info |


### datadog-tag-list

***
Return a mapping of tags to hosts for your whole infrastructure.

#### Base Command

`datadog-tag-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| source | Source to filter.<br/>Ex : user, datadog. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Tag | String | A list of tags to apply to the host. | 
| Datadog.HostTag | Unknown | The host name. | 

#### Command example
```!datadog-tag-list limit=10```
#### Context Example
```json
{
    "Datadog": [
        {
            "Hostname": [
                "TestHost2"
            ],
            "Tag": "team:infra"
        },
        {
            "Hostname": [
                "TestHost2"
            ],
            "Tag": "role:database"
        },
        {
            "Hostname": [
                "TestHost2"
            ],
            "Tag": "region:west"
        },
        {
            "Hostname": [
                "TestHost2"
            ],
            "Tag": "app:frontend"
        }
    ]
}
```

#### Human Readable Output

>### Tags List
>|Tag|Host Name|
>|---|---|
>| team:infra | TestHost2 |
>| role:database | TestHost2 |
>| region:west | TestHost2 |
>| app:frontend | TestHost2 |


### datadog-host-tag-create

***
This endpoint allows you to add new tags to a host, optionally specifying where these tags come from.

#### Base Command

`datadog-host-tag-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_name | The host name. | Required | 
| tags | A list of tags to apply to the host. <br/>Comma seperated values. Ex: "environment:production, region:East” . | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Tag | Unknown | A list of tags to apply to the host. | 
| Datadog.HostTag | String | The host name. | 

#### Command example
```!datadog-host-tag-create host_name="TestHost2" tags="env:prod"```
#### Context Example
```json
{
    "Datadog": {
        "Hostname": "TestHost2",
        "Tag": []
    }
}
```

#### Human Readable Output

>### Host Tags Details
>|Host Name|
>|---|
>| TestHost2 |


### datadog-host-tag-get

***
Return the list of tags that apply to a given host.

#### Base Command

`datadog-host-tag-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_name | The host name. | Required | 
| source | Source to filter.<br/>Ex : user, datadog. | Optional | 
| page | The page number. Default is 1. . | Optional | 
| page_size | The number of requested results per page. <br/>Default is 50. . | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user, then the limit argument will be ignored. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Tag | Unknown | A list of tags to apply to the host. | 
| Datadog.HostTag | String | The host name. | 

#### Command example
```!datadog-host-tag-get host_name="TestHost2"```
#### Context Example
```json
{
    "Datadog": {
        "Hostname": "TestHost2",
        "Tag": [
            "role:database",
            "app:frontend",
            "team:infra",
            "region:west"
        ]
    }
}
```

#### Human Readable Output

>### Host Tags List
>|Tags|
>|---|
>| role:database |
>| app:frontend |
>| team:infra |
>| region:west |


### datadog-host-tag-update

***
This endpoint allows you to replace all tags in an integration source with those supplied in the request.

#### Base Command

`datadog-host-tag-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_name | The host name. | Required | 
| tags | A list of tags to apply to the host  <br/>Previous tags will be replaced by new tags. <br/>Comma seperated values. Ex: "environment:production, region:East”  . | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Tag | Unknown | A list of tags to apply to the host. | 
| Datadog.HostTag | String | The host name. | 

#### Command example
```!datadog-host-tag-update host_name="TestHost2"```
#### Context Example
```json
{
    "Datadog": {
        "Hostname": "TestHost2",
        "Tag": []
    }
}
```

#### Human Readable Output

>### Host Tags Details
>|Host Name|
>|---|
>| TestHost2 |


### datadog-host-tag-delete

***
This endpoint allows you to remove all user-assigned tags for a single host.

#### Base Command

`datadog-host-tag-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_name | Host name to remove associated tags. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!datadog-host-tag-delete host_name="TestHost2"```
#### Human Readable Output

>### Host tags deleted successfully!


### datadog-active-metric-list

***
Get the list of actively reporting metrics.

#### Base Command

`datadog-active-metric-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | List of actively reporting metrics from a given time until now.<br/>Format :  yyyy-MM-dd’T’HH:mm:ssZ Or '-1days' . | Required | 
| host_name | Hostname for filtering the list of metrics.<br/><br/>Please do not fill this field ( Bug will be fixed in near future). | Optional | 
| tag_filter | Filter metrics that have been submitted with the given tags.<br/>Ex: “region:east,env:prod”. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user, then the limit argument will be ignored. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Metric.from | String | Time when the metrics were active, seconds since the Unix epoch. | 
| Datadog.Metric | Unknown | List of metric names. | 

#### Command example
```!datadog-active-metric-list from="-2days"```
#### Context Example
```json
{
    "Datadog": {
        "Metric": [
            "datadog.agent.python.version",
            "datadog.agent.running",
            "datadog.dogstatsd.client.aggregated_context",
            "datadog.dogstatsd.client.aggregated_context_by_type",
            "datadog.dogstatsd.client.bytes_dropped",
            "datadog.dogstatsd.client.bytes_dropped_queue",
            "datadog.dogstatsd.client.bytes_dropped_writer",
            "datadog.dogstatsd.client.bytes_sent",
            "datadog.dogstatsd.client.events",
            "datadog.dogstatsd.client.metric_dropped_on_receive",
            "datadog.dogstatsd.client.metrics",
            "datadog.dogstatsd.client.metrics_by_type",
            "datadog.dogstatsd.client.packets_dropped",
            "datadog.dogstatsd.client.packets_dropped_queue",
            "datadog.dogstatsd.client.packets_dropped_writer",
            "datadog.dogstatsd.client.packets_sent",
            "datadog.dogstatsd.client.service_checks",
            "datadog.estimated_usage.events.custom_events",
            "datadog.estimated_usage.events.ingested_events",
            "datadog.estimated_usage.hosts",
            "datadog.estimated_usage.incident_management.active_users",
            "datadog.event.tracking.indexation.feed.events",
            "datadog.event.tracking.intake.feed.bytes",
            "datadog.event.tracking.intakev2.feed.bytes",
            "datadog.process.agent",
            "datadog.trace_agent.cpu_percent",
            "datadog.trace_agent.events.max_eps.current_rate",
            "datadog.trace_agent.events.max_eps.max_rate",
            "datadog.trace_agent.events.max_eps.reached_max",
            "datadog.trace_agent.events.max_eps.sample_rate",
            "datadog.trace_agent.heap_alloc",
            "datadog.trace_agent.heartbeat",
            "datadog.trace_agent.receiver.out_chan_fill",
            "datadog.trace_agent.receiver.ratelimit",
            "datadog.trace_agent.sampler.kept",
            "datadog.trace_agent.sampler.rare.hits",
            "datadog.trace_agent.sampler.rare.misses",
            "datadog.trace_agent.sampler.rare.shrinks",
            "datadog.trace_agent.sampler.seen",
            "datadog.trace_agent.sampler.size",
            "datadog.trace_agent.stats_writer.bytes",
            "datadog.trace_agent.stats_writer.client_payloads",
            "datadog.trace_agent.stats_writer.encode_ms.avg",
            "datadog.trace_agent.stats_writer.encode_ms.count",
            "datadog.trace_agent.stats_writer.encode_ms.max",
            "datadog.trace_agent.stats_writer.errors",
            "datadog.trace_agent.stats_writer.payloads",
            "datadog.trace_agent.stats_writer.retries",
            "datadog.trace_agent.stats_writer.splits",
            "datadog.trace_agent.stats_writer.stats_buckets"
        ],
        "Metric.from": "1682520764"
    }
}
```

#### Human Readable Output

>### Active Metric List
>|From|Metric Name|
>|---|---|
>| 2023-04-26 14:52:44 | datadog.agent.python.version,<br/>datadog.agent.running,<br/>datadog.dogstatsd.client.aggregated_context,<br/>datadog.dogstatsd.client.aggregated_context_by_type,<br/>datadog.dogstatsd.client.bytes_dropped,<br/>datadog.dogstatsd.client.bytes_dropped_queue,<br/>datadog.dogstatsd.client.bytes_dropped_writer,<br/>datadog.dogstatsd.client.bytes_sent,<br/>datadog.dogstatsd.client.events,<br/>datadog.dogstatsd.client.metric_dropped_on_receive,<br/>datadog.dogstatsd.client.metrics,<br/>datadog.dogstatsd.client.metrics_by_type,<br/>datadog.dogstatsd.client.packets_dropped,<br/>datadog.dogstatsd.client.packets_dropped_queue,<br/>datadog.dogstatsd.client.packets_dropped_writer,<br/>datadog.dogstatsd.client.packets_sent,<br/>datadog.dogstatsd.client.service_checks,<br/>datadog.estimated_usage.events.custom_events,<br/>datadog.estimated_usage.events.ingested_events,<br/>datadog.estimated_usage.hosts,<br/>datadog.estimated_usage.incident_management.active_users,<br/>datadog.event.tracking.indexation.feed.events,<br/>datadog.event.tracking.intake.feed.bytes,<br/>datadog.event.tracking.intakev2.feed.bytes,<br/>datadog.process.agent,<br/>datadog.trace_agent.cpu_percent,<br/>datadog.trace_agent.events.max_eps.current_rate,<br/>datadog.trace_agent.events.max_eps.max_rate,<br/>datadog.trace_agent.events.max_eps.reached_max,<br/>datadog.trace_agent.events.max_eps.sample_rate,<br/>datadog.trace_agent.heap_alloc,<br/>datadog.trace_agent.heartbeat,<br/>datadog.trace_agent.receiver.out_chan_fill,<br/>datadog.trace_agent.receiver.ratelimit,<br/>datadog.trace_agent.sampler.kept,<br/>datadog.trace_agent.sampler.rare.hits,<br/>datadog.trace_agent.sampler.rare.misses,<br/>datadog.trace_agent.sampler.rare.shrinks,<br/>datadog.trace_agent.sampler.seen,<br/>datadog.trace_agent.sampler.size,<br/>datadog.trace_agent.stats_writer.bytes,<br/>datadog.trace_agent.stats_writer.client_payloads,<br/>datadog.trace_agent.stats_writer.encode_ms.avg,<br/>datadog.trace_agent.stats_writer.encode_ms.count,<br/>datadog.trace_agent.stats_writer.encode_ms.max,<br/>datadog.trace_agent.stats_writer.errors,<br/>datadog.trace_agent.stats_writer.payloads,<br/>datadog.trace_agent.stats_writer.retries,<br/>datadog.trace_agent.stats_writer.splits,<br/>datadog.trace_agent.stats_writer.stats_buckets |


### datadog-metric-search

***
Search for metrics from the last 24 hours in Datadog.

#### Base Command

`datadog-metric-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query string to search metrics from last 24 hours in Datadog.<br/>A complete list of query string values available here. https://app.datadoghq.com/metric/summary. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Metric.metric_name | Unknown | List of metrics that match the search query. | 

#### Command example
```!datadog-metric-search query="datadog.agent.python.version"```
#### Context Example
```json
{
    "Datadog": {
        "Metric": {
            "metric_name": [
                "datadog.agent.python.version"
            ]
        }
    }
}
```

#### Human Readable Output

>### Metrics Search List
>|Metric Name|
>|---|
>| datadog.agent.python.version |


### datadog-metric-metadata-get

***
Get metadata about a specific metric.

#### Base Command

`datadog-metric-metadata-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| metric_name | Name of the metric for which to get metadata. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.MetricMetadata.description | String | Metric description. | 
| Datadog.MetricMetadata.integration | String | Name of the integration that sent the metric if applicable. | 
| Datadog.MetricMetadata.per_unit | String | Per unit of the metric such as second in bytes per second. | 
| Datadog.MetricMetadata.short_name | String | A more human-readable and abbreviated version of the metric name. | 
| Datadog.MetricMetadata.statsd_interval | Number | StatsD flush interval of the metric in seconds if applicable. | 
| Datadog.MetricMetadata.type | String | Metric type | 
| Datadog.MetricMetadata.unit | String | Primary unit of the metric | 
| Datadog.MetricMetadata.metric_name | String | The metric name. | 

#### Command example
```!datadog-metric-metadata-get metric_name="system.io.block_in"```
#### Context Example
```json
{
    "Datadog": {
        "MetricMetadata": {
            "description": null,
            "integration": null,
            "metric_name": "system.io.block_in",
            "per_unit": null,
            "short_name": null,
            "statsd_interval": null,
            "type": "gauge",
            "unit": null
        }
    }
}
```

#### Human Readable Output

>### Metric Metadata Details
>|Metric Name|Type|
>|---|---|
>| system.io.block_in | gauge |


### datadog-metric-metadata-update

***
Edit metadata of a specific metric.

#### Base Command

`datadog-metric-metadata-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| metric_name | Name of the metric for which to edit metadata. | Required | 
| description | Metric description. | Optional | 
| per_unit | Per unit of the metric  <br/>A complete list of metric units values available here. https://docs.datadoghq.com/metrics/units/#unit-list. | Optional | 
| short_name | A more human-readable and abbreviated version of the metric name. | Optional | 
| statsd_interval | StatsD flush interval of the metric in seconds if applicable. | Optional | 
| type | Metric type. Possible values are: count, rate, gauge, set, histogram, distribution. | Optional | 
| unit | Primary unit of the metric. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.MetricMetadata.description | String | Metric description. | 
| Datadog.MetricMetadata.per_unit | String | Per unit of the metric such as second in bytes per second. | 
| Datadog.MetricMetadata.short_name | String | A more human-readable and abbreviated version of the metric name. | 
| Datadog.MetricMetadata.statsd_interval | Number | StatsD flush interval of the metric in seconds if applicable. | 
| Datadog.MetricMetadata.type | String | Metric type | 
| Datadog.MetricMetadata.unit | String | Primary unit of the metric | 
| Datadog.MetricMetadata.metric_name | String | The metric name. | 

#### Command example
```!datadog-metric-metadata-update metric_name="system.io.block_in"```
#### Context Example
```json
{
    "Datadog": {
        "MetricMetadata": {
            "description": null,
            "integration": null,
            "metric_name": "system.io.block_in",
            "per_unit": null,
            "short_name": null,
            "statsd_interval": null,
            "type": "gauge",
            "unit": null
        }
    }
}
```

#### Human Readable Output

>### Metric Metadata Details
>|Metric Name|Type|
>|---|---|
>| system.io.block_in | gauge |


### datadog-incident-create

***
Datadog Incidents Create is used to Create an incident.

#### Base Command

`datadog-incident-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_impacted | A flag indicating whether the incident caused customer impact.<br/><br/>Restricted value : True<br/>Permitted value : False ( Bug will be fixed in near future). Possible values are: True, False. | Required | 
| title | The title of the incident, which summarizes what happened. | Required | 
| severity | The severity of the incident.<br/>Default value=unknown. Possible values are: SEV-1, SEV-2, SEV-3, SEV-4, SEV-5, UNKNOWN. | Optional | 
| state | The State of the incident. Possible values are: active, stable, resolved. | Optional | 
| detection_method | Specify how the incident was detected. Possible values are: customer, employee, monitor, other, unknown. | Optional | 
| root_cause | This field allows you to enter the description of the root cause, triggers, and contributing factors of the incident. | Optional | 
| summary | Summary of the incident. | Optional | 
| content | The Markdown content of the cell  which is used to format using the Markdown syntax rules.<br/>Markdown cells usually serve as explanatory or descriptive texts to your code.<br/>If content is provided important is required. | Optional | 
| important | A flag indicating whether the timeline cell is important and should be highlighted. Possible values are: True, False. | Optional | 
| display_name | The name of the notified handle. | Optional | 
| handle | The email address used for the notification. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Incident.id | String | The ID of the incident. | 
| Datadog.Incident.attributes.public_id | Number | The monotonically increasing integer ID for the incident. | 
| Datadog.Incident.attributes.resolved | Unknown | Timestamp when the incident's state was last changed from active or stable to resolved or completed. | 
| Datadog.Incident.attributes.title | String | The title of the incident, which summarizes what happened. | 
| Datadog.Incident.attributes.customer_impact_scope | Unknown | A summary of the impact customers experienced during the incident. | 
| Datadog.Incident.attributes.customer_impact_start | Unknown | Timestamp when customers began being impacted by the incident. | 
| Datadog.Incident.attributes.customer_impact_end | Unknown | Timestamp when customers were no longer impacted by the incident. | 
| Datadog.Incident.attributes.customer_impacted | Boolean | A flag indicating whether the incident caused customer impact. | 
| Datadog.Incident.attributes.notification_handles.display_name | String | The name of the notified handle. | 
| Datadog.Incident.attributes.notification_handles.handle | String | The email address used for the notification. | 
| Datadog.Incident.attributes.created | String | Timestamp when the incident was created. | 
| Datadog.Incident.attributes.modified | String | Timestamp when the incident was last modified. | 
| Datadog.Incident.attributes.detected | String | Timestamp when the incident was detected. | 
| Datadog.Incident.attributes.customer_impact_duration | Number | Length of the incident's customer impact in seconds. Equals the difference between customer_impact_start and customer_impact_end. | 
| Datadog.Incident.attributes.time_to_detect | Number | The amount of time in seconds to detect the incident. Equals the difference between customer_impact_start and detected. | 
| Datadog.Incident.attributes.time_to_repair | Number | The amount of time in seconds to resolve customer impact after detecting the issue. Equals the difference between customer_impact_end and detected. | 
| Datadog.Incident.attributes.time_to_internal_response | Number | The amount of time in seconds to call incident after detection. Equals the difference of detected and created. | 
| Datadog.Incident.attributes.time_to_resolve | Number | The amount of time in seconds to resolve the incident after it was created. Equals the difference between created and resolved. | 
| Datadog.Incident.attributes.fields.severity.value | String | The severity of the incident. | 
| Datadog.Incident.attributes.fields.state.value | String | The status of the incident. | 
| Datadog.Incident.attributes.fields.detection_method.value | String | Specify how the incident was detected with these default options - customer, employee, monitor, other, or unknown. | 
| Datadog.Incident.attributes.fields.root_cause.value | String | This text field allows you to enter the description of the root cause, triggers, and contributing factors of the incident. | 
| Datadog.Incident.attributes.fields.summary.value | String | Summary of incident. | 
| Datadog.Incident.relationships.created_by_user.data.id | String | A unique identifier that represents the user. | 
| Datadog.Incident.relationships.integrations.data.id | String | A unique identifier that represents the integration metadata. | 
| Datadog.Incident.relationships.last_modified_by_user.data.id | String | A unique identifier that represents the user. | 
| Datadog.Incident.relationships.commander_user.data.id | Unknown | A unique identifier that represents the user. | 
| Datadog.Incident.included.attributes.created_at | String | Creation time of the user. | 
| Datadog.Incident.included.attributes.disabled | Boolean | Whether the user is disabled. | 
| Datadog.Incident.included.attributes.email | String | Email of the user. | 
| Datadog.Incident.included.attributes.handle | String | Handle of the user. | 
| Datadog.Incident.included.attributes.icon | String | URL of the user's icon. | 
| Datadog.Incident.included.attributes.modified_at | String | Time that the user was last modified. | 
| Datadog.Incident.included.attributes.name | String | Name of the user. | 
| Datadog.Incident.included.attributes.service_account | Boolean | Whether the user is a service account. | 
| Datadog.Incident.included.attributes.status | String | Status of the user. | 
| Datadog.Incident.included.attributes.title | String | Title of the user. | 
| Datadog.Incident.included.attributes.verified | Boolean | Whether the user is verified. | 
| Datadog.Incident.included.id | String | ID of the user. | 
| Datadog.Incident.included.relationships.org.id | String | ID of the organization. | 
| Datadog.Incident.included.relationships.other_orgs.id | String | ID of the other organization. | 
| Datadog.Incident.included.relationships.other_users.id | String | A unique identifier that represents the user. | 
| Datadog.Incident.included.relationships.roles.id | String | The unique identifier of the role. | 

#### Command example
```!datadog-incident-create customer_impacted=False title="incident-test1"```
#### Context Example
```json
{
    "Datadog": {
        "Incident": {
            "attributes": {
                "archived": null,
                "case_id": null,
                "commander": null,
                "created": "2023-04-28T14:53:01+00:00",
                "created_by": {
                    "data": {
                        "attributes": {
                            "email": "integrations@loginsoft.com",
                            "handle": "integrations@loginsoft.com",
                            "icon": "https://secure.gravatar.com/avatar/3e04e593f20b31b84122703a927d39f4?s=48&d=retro",
                            "name": "Muthu Mahadevan",
                            "uuid": "5db43403-9895-11ed-a432-b611e40f0c37"
                        },
                        "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                        "type": "users"
                    }
                },
                "created_by_uuid": null,
                "creation_idempotency_key": null,
                "customer_impact_duration": 0,
                "customer_impact_end": null,
                "customer_impact_scope": null,
                "customer_impact_start": null,
                "customer_impacted": false,
                "detected": "2023-04-28T14:53:01+00:00",
                "field_analytics": null,
                "fields": {
                    "detection_method": {
                        "type": "dropdown",
                        "value": "unknown"
                    },
                    "root_cause": {
                        "type": "textbox",
                        "value": null
                    },
                    "services": {
                        "type": "autocomplete",
                        "value": null
                    },
                    "severity": {
                        "type": "dropdown",
                        "value": "UNKNOWN"
                    },
                    "state": {
                        "type": "dropdown",
                        "value": "active"
                    },
                    "summary": {
                        "type": "textbox",
                        "value": null
                    },
                    "teams": {
                        "type": "autocomplete",
                        "value": null
                    }
                },
                "last_modified_by": {
                    "data": {
                        "attributes": {
                            "email": "integrations@loginsoft.com",
                            "handle": "integrations@loginsoft.com",
                            "icon": "https://secure.gravatar.com/avatar/3e04e593f20b31b84122703a927d39f4?s=48&d=retro",
                            "name": "Muthu Mahadevan",
                            "uuid": "5db43403-9895-11ed-a432-b611e40f0c37"
                        },
                        "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                        "type": "users"
                    }
                },
                "last_modified_by_uuid": null,
                "modified": "2023-04-28T14:53:01+00:00",
                "non_datadog_creator": null,
                "notification_handles": [
                    {
                        "created_at": "2023-04-28T14:53:01.768657+00:00",
                        "display_name": null,
                        "handle": null
                    }
                ],
                "public_id": 222,
                "resolved": null,
                "severity": "UNKNOWN",
                "state": "active",
                "time_to_detect": 0,
                "time_to_internal_response": 0,
                "time_to_repair": 0,
                "time_to_resolve": 0,
                "title": "incident-test1",
                "visibility": "organization"
            },
            "id": "cf0de97a-469c-559b-bba4-d13804b3b360",
            "relationships": {
                "attachments": {
                    "data": []
                },
                "commander_user": {
                    "data": null
                },
                "created_by_user": {
                    "data": {
                        "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                        "type": "users"
                    }
                },
                "impacts": {
                    "data": []
                },
                "integrations": {
                    "data": []
                },
                "last_modified_by_user": {
                    "data": {
                        "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                        "type": "users"
                    }
                },
                "responders": {
                    "data": []
                },
                "user_defined_fields": {
                    "data": [
                        {
                            "id": "97561247-dfe9-5a79-9dce-7fd8b0fe4219",
                            "type": "user_defined_field"
                        },
                        {
                            "id": "50c35859-9f10-5e0d-9c67-56873ed48078",
                            "type": "user_defined_field"
                        },
                        {
                            "id": "a4fa9eed-69c5-5b2a-9d80-b11f7ce513df",
                            "type": "user_defined_field"
                        },
                        {
                            "id": "2aff984e-e13e-5e6f-956f-bf3ef48beeaa",
                            "type": "user_defined_field"
                        },
                        {
                            "id": "b82c3141-e2a4-542e-9c6e-10934d79c3a7",
                            "type": "user_defined_field"
                        },
                        {
                            "id": "51c3d56a-08d9-5eaa-85b4-a56dee0d789b",
                            "type": "user_defined_field"
                        },
                        {
                            "id": "b5fc7c1c-57e0-515c-b9cf-9c454962c1b0",
                            "type": "user_defined_field"
                        }
                    ]
                }
            },
            "type": "incidents"
        }
    }
}
```

#### Human Readable Output

>### Incident Details
>|ID|Title|Created|Customer Impacted|Customer Impact Duration|Customer Impact Scope|Detected|Resolved|Time to Detect|Time to Internal Response|Time to Repair|Time to Resolve|Severity|State|Detection Method|Root Cause|Summary|Notification Display Name|Notification Handle|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| cf0de97a-469c-559b-bba4-d13804b3b360 | incident-test1 | April 28, 2023 02:53 PM | False | 0 | None | April 28, 2023 02:53 PM | None | 0 | 0 | 0 | 0 | UNKNOWN | active | unknown | None | None | None | None |


### datadog-incident-delete

***
Delete an existing incident.

#### Base Command

`datadog-incident-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The UUID of the incident. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!datadog-incident-delete incident_id=1cc7af96-aad6-5085-aa3b-2d121b923642```
#### Human Readable Output

>### Incident deleted successfully!


### datadog-incident-update

***
Updates an incident. Provide only the attributes that should be updated as this request is a partial update.

#### Base Command

`datadog-incident-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The UUID of the incident. | Required | 
| customer_impact_end | Specifies the end of the search time frame.<br/>Format : yyyy-MM-dd’T’HH:mm:ssZ Or  '-1days'. | Optional | 
| customer_impact_scope | A summary of the impact customers experienced during the incident. | Optional | 
| customer_impact_start | Timestamp  when customers began being impacted by the incident .<br/>Format : yyyy-MM-dd’T’HH:mm:ssZ Or  '-1days'. | Optional | 
| customer_impacted | A flag indicating whether the incident caused customer impact. Possible values are: True, False. | Optional | 
| detected | Timestamp when the incident was detected.<br/>Format : yyyy-MM-dd’T’HH:mm:ssZ Or  '-1days'. | Optional | 
| severity | The Severity of the incident.<br/>Default value=unknown. Possible values are: SEV-1, SEV-2, SEV-3, SEV-4, SEV-5, UNKNOWN. | Optional | 
| state | The State of the incident. Possible values are: active, stable, resolved. | Optional | 
| detection_method | Specify how the incident was detected. Possible values are: customer, employee, monitor, other, unknown. | Optional | 
| root_cause | This field allows you to enter the description of the root cause, triggers, and contributing factors of the incident. | Optional | 
| summary | Summary of the incident. | Optional | 
| display_name | The name of the notified handle. | Optional | 
| handle | The email address used for the notification. | Optional | 
| title | The title of the incident, which summarizes what happened. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Incident.id | String | The incident ID. | 
| Datadog.Incident.attributes.public_id | Number | The monotonically increasing integer ID for the incident. | 
| Datadog.Incident.attributes.title | String | The title of the incident, which summarizes what happened. | 
| Datadog.Incident.attributes.resolved | String | Timestamp when the incident's state was last changed from active or stable to resolved or completed. | 
| Datadog.Incident.attributes.customer_impact_scope | String | A summary of the impact customers experienced during the incident. | 
| Datadog.Incident.attributes.customer_impact_start | Date | Timestamp when customers began being impacted by the incident. | 
| Datadog.Incident.attributes.customer_impact_end | String | Timestamp when customers were no longer impacted by the incident. | 
| Datadog.Incident.attributes.customer_impacted | Boolean | A flag indicating whether the incident caused customer impact. | 
| Datadog.Incident.attributes.notification_handles.handle | String | The email address used for the notification. | 
| Datadog.Incident.attributes.notification_handles.display_name | String | The name of the notified handle. | 
| Datadog.Incident.attributes.created | String | Timestamp when the incident was created. | 
| Datadog.Incident.attributes.modified | String | Timestamp when the incident was last modified. | 
| Datadog.Incident.attributes.detected | String | Timestamp when the incident was detected. | 
| Datadog.Incident.attributes.customer_impact_duration | Number | Length of the incident's customer impact in seconds. Equals the difference between customer_impact_start and customer_impact_end. | 
| Datadog.Incident.attributes.time_to_detect | Number | The amount of time in seconds to detect the incident. Equals the difference between customer_impact_start and detected. | 
| Datadog.Incident.attributes.time_to_repair | Number | The amount of time in seconds to resolve customer impact after detecting the issue. Equals the difference between customer_impact_end and detected. | 
| Datadog.Incident.attributes.time_to_internal_response | Number | The amount of time in seconds to call incident after detection. Equals the difference of detected and created. | 
| Datadog.Incident.attributes.time_to_resolve | Number | The amount of time in seconds to resolve the incident after it was created. Equals the difference between created and resolved. | 
| Datadog.Incident.attributes.fields.severity.value | String | The severity of the incident. | 
| Datadog.Incident.attributes.fields.state.value | String | The status of the incident. | 
| Datadog.Incident.attributes.fields.detection_method.value | String | Specify how the incident was detected with these default options: customer, employee, monitor, other, or unknown. | 
| Datadog.Incident.attributes.fields.root_cause.value | String | This text field allows you to enter the description of the root cause, triggers, and contributing factors of the incident. | 
| Datadog.Incident.attributes.fields.summary.value | String | Summary of incident. | 
| Datadog.Incident.relationships.created_by_user.data.id | String | A unique identifier that represents the user. | 
| Datadog.Incident.relationships.last_modified_by_user.data.id | String | A unique identifier that represents the user. | 
| Datadog.Incident.relationships.commander_user.data.id | String | A unique identifier that represents the user. | 
| Datadog.Incident.included.attributes.created_at | String | Creation time of the user. | 
| Datadog.Incident.included.attributes.disabled | Boolean | Whether the user is disabled. | 
| Datadog.Incident.included.attributes.email | String | Email of the user. | 
| Datadog.Incident.included.attributes.handle | String | Handle of the user. | 
| Datadog.Incident.included.attributes.icon | String | URL of the user's icon. | 
| Datadog.Incident.included.attributes.modified_at | String | Time that the user was last modified. | 
| Datadog.Incident.included.attributes.name | String | Name of the user. | 
| Datadog.Incident.included.attributes.service_account | Boolean | Whether the user is a service account. | 
| Datadog.Incident.included.attributes.status | String | Status of the user. | 
| Datadog.Incident.included.attributes.title | String | Title of the user. | 
| Datadog.Incident.included.attributes.verified | Boolean | Whether the user is verified. | 
| Datadog.Incident.included.id | String | ID of the user. | 
| Datadog.Incident.included.relationships.org.id | String | ID of the organization. | 
| Datadog.Incident.included.relationships.other_orgs.id | String | ID of the other organization. | 
| Datadog.Incident.included.relationships.other_users.id | String | A unique identifier that represents the user. | 
| Datadog.Incident.included.relationships.roles.id | String | The unique identifier of the role. | 

#### Command example
```!datadog-incident-update incident_id=1cc7af96-aad6-5085-aa3b-2d121b923642```
#### Context Example
```json
{
    "Datadog": {
        "Incident": {
            "attributes": {
                "archived": null,
                "case_id": null,
                "commander": {
                    "data": {
                        "attributes": {
                            "email": "integrations@loginsoft.com",
                            "handle": "integrations@loginsoft.com",
                            "icon": "https://secure.gravatar.com/avatar/3e04e593f20b31b84122703a927d39f4?s=48&d=retro",
                            "name": "Muthu Mahadevan",
                            "uuid": "5db43403-9895-11ed-a432-b611e40f0c37"
                        },
                        "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                        "type": "users"
                    }
                },
                "created": "2023-01-25T10:39:15+00:00",
                "created_by": {
                    "data": {
                        "attributes": {
                            "email": "integrations@loginsoft.com",
                            "handle": "integrations@loginsoft.com",
                            "icon": "https://secure.gravatar.com/avatar/3e04e593f20b31b84122703a927d39f4?s=48&d=retro",
                            "name": "Muthu Mahadevan",
                            "uuid": "5db43403-9895-11ed-a432-b611e40f0c37"
                        },
                        "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                        "type": "users"
                    }
                },
                "created_by_uuid": "5db43403-9895-11ed-a432-b611e40f0c37",
                "creation_idempotency_key": null,
                "customer_impact_duration": 0,
                "customer_impact_end": null,
                "customer_impact_scope": null,
                "customer_impact_start": null,
                "customer_impacted": false,
                "detected": "2023-01-25T10:39:15+00:00",
                "field_analytics": null,
                "fields": {
                    "detection_method": {
                        "type": "dropdown",
                        "value": "unknown"
                    },
                    "root_cause": {
                        "type": "textbox",
                        "value": null
                    },
                    "services": {
                        "type": "autocomplete",
                        "value": null
                    },
                    "severity": {
                        "type": "dropdown",
                        "value": "UNKNOWN"
                    },
                    "state": {
                        "type": "dropdown",
                        "value": "resolved"
                    },
                    "summary": {
                        "type": "textbox",
                        "value": null
                    },
                    "teams": {
                        "type": "autocomplete",
                        "value": null
                    }
                },
                "last_modified_by": {
                    "data": {
                        "attributes": {
                            "email": "integrations@loginsoft.com",
                            "handle": "integrations@loginsoft.com",
                            "icon": "https://secure.gravatar.com/avatar/3e04e593f20b31b84122703a927d39f4?s=48&d=retro",
                            "name": "Muthu Mahadevan",
                            "uuid": "5db43403-9895-11ed-a432-b611e40f0c37"
                        },
                        "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                        "type": "users"
                    }
                },
                "last_modified_by_uuid": "5db43403-9895-11ed-a432-b611e40f0c37",
                "modified": "2023-04-28T14:53:06+00:00",
                "non_datadog_creator": null,
                "notification_handles": null,
                "public_id": 2,
                "resolved": null,
                "severity": "UNKNOWN",
                "state": "resolved",
                "time_to_detect": 0,
                "time_to_internal_response": 0,
                "time_to_repair": 0,
                "time_to_resolve": 0,
                "title": "test-incident-i1",
                "visibility": "organization"
            },
            "id": "1cc7af96-aad6-5085-aa3b-2d121b923642",
            "relationships": {
                "attachments": {
                    "data": []
                },
                "commander_user": {
                    "data": {
                        "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                        "type": "users"
                    }
                },
                "created_by_user": {
                    "data": {
                        "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                        "type": "users"
                    }
                },
                "impacts": {
                    "data": []
                },
                "integrations": {
                    "data": []
                },
                "last_modified_by_user": {
                    "data": {
                        "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                        "type": "users"
                    }
                },
                "responders": {
                    "data": [
                        {
                            "id": "388fc28b-073d-532b-a5b8-766f5bdd1b24",
                            "type": "incident_responders"
                        }
                    ]
                },
                "user_defined_fields": {
                    "data": [
                        {
                            "id": "97561247-dfe9-5a79-9dce-7fd8b0fe4219",
                            "type": "user_defined_field"
                        },
                        {
                            "id": "50c35859-9f10-5e0d-9c67-56873ed48078",
                            "type": "user_defined_field"
                        },
                        {
                            "id": "a4fa9eed-69c5-5b2a-9d80-b11f7ce513df",
                            "type": "user_defined_field"
                        },
                        {
                            "id": "2aff984e-e13e-5e6f-956f-bf3ef48beeaa",
                            "type": "user_defined_field"
                        },
                        {
                            "id": "b82c3141-e2a4-542e-9c6e-10934d79c3a7",
                            "type": "user_defined_field"
                        },
                        {
                            "id": "51c3d56a-08d9-5eaa-85b4-a56dee0d789b",
                            "type": "user_defined_field"
                        },
                        {
                            "id": "b5fc7c1c-57e0-515c-b9cf-9c454962c1b0",
                            "type": "user_defined_field"
                        }
                    ]
                }
            },
            "type": "incidents"
        }
    }
}
```

#### Human Readable Output

>### Incident Details
>|ID|Title|Created|Customer Impacted|Customer Impact Duration|Customer Impact Scope|Detected|Resolved|Time to Detect|Time to Internal Response|Time to Repair|Time to Resolve|Severity|State|Detection Method|Root Cause|Summary|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1cc7af96-aad6-5085-aa3b-2d121b923642 | test-incident-i1 | January 25, 2023 10:39 AM | False | 0 | None | January 25, 2023 10:39 AM | None | 0 | 0 | 0 | 0 | UNKNOWN | resolved | unknown | None | None |


### datadog-incident-list

***
Get all incidents for the user’s organization / Get the details of an incident using incident_id.

#### Base Command

`datadog-incident-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The UUID of the incident. | Optional | 
| state | The status of the incident. Possible values are: active, stable, resolved. | Optional | 
| severity | The severity of the incident. Possible values are: SEV-1, SEV-2, SEV-3, SEV-4, SEV-5, UNKNOWN. | Optional | 
| customer_impacted | A flag indicating whether the incident caused customer impact. Possible values are: True, False. | Optional | 
| detection_method | Specify how the incident was detected. Possible values are: customer, employee, monitor, other, unknown. | Optional | 
| sort | Specifies the order of returned incidents. Possible values are: asc, desc. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| page | The page number. Default is 1. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user, then the limit argument will be ignored. | Optional | 
| include | Specifies which types of related objects should be included in the response.<br/>Allowed enum values: users, attachments. Possible values are: users, attachments. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Incident.id | String | The ID of the incident. | 
| Datadog.Incident.attributes.public_id | Number | The monotonically increasing integer ID for the incident. | 
| Datadog.Incident.attributes.resolved | Unknown | Timestamp when the incident's state was last changed from active or stable to resolved or completed. | 
| Datadog.Incident.attributes.title | String | The title of the incident, which summarizes what happened. | 
| Datadog.Incident.attributes.customer_impact_scope | Unknown | A summary of the impact customers experienced during the incident. | 
| Datadog.Incident.attributes.customer_impact_start | Unknown | Timestamp when customers began being impacted by the incident. | 
| Datadog.Incident.attributes.customer_impact_end | Unknown | Timestamp when customers were no longer impacted by the incident. | 
| Datadog.Incident.attributes.customer_impacted | Boolean | A flag indicating whether the incident caused customer impact. | 
| Datadog.Incident.attributes.notification_handles.display_name | String | The name of the notified handle. | 
| Datadog.Incident.attributes.notification_handles.handle | String | The email address used for the notification. | 
| Datadog.Incident.attributes.created | String | Timestamp when the incident was created. | 
| Datadog.Incident.attributes.modified | String | Timestamp when the incident was last modified. | 
| Datadog.Incident.attributes.detected | String | Timestamp when the incident was detected. | 
| Datadog.Incident.attributes.customer_impact_duration | Number | Length of the incident's customer impact in seconds. Equals the difference between customer_impact_start and customer_impact_end. | 
| Datadog.Incident.attributes.time_to_detect | Number | The amount of time in seconds to detect the incident. Equals the difference between customer_impact_start and detected. | 
| Datadog.Incident.attributes.time_to_repair | Number | The amount of time in seconds to resolve customer impact after detecting the issue. Equals the difference between customer_impact_end and detected. | 
| Datadog.Incident.attributes.time_to_internal_response | Number | The amount of time in seconds to call incident after detection. Equals the difference of detected and created. | 
| Datadog.Incident.attributes.time_to_resolve | Number | The amount of time in seconds to resolve the incident after it was created. Equals the difference between created and resolved. | 
| Datadog.Incident.attributes.fields.severity.value | String | The severity of the incident. | 
| Datadog.Incident.attributes.fields.state.value | String | The status of the incident. | 
| Datadog.Incident.attributes.fields.detection_method.value | String | Specify how the incident was detected with these default options - customer, employee, monitor, other, or unknown. | 
| Datadog.Incident.attributes.fields.root_cause.value | String | This text field allows you to enter the description of the root cause, triggers, and contributing factors of the incident. | 
| Datadog.Incident.attributes.fields.summary.value | String | Summary of incident. | 
| Datadog.Incident.relationships.created_by_user.data.id | String | A unique identifier that represents the user. | 
| Datadog.Incident.relationships.integrations.data.id | String | A unique identifier that represents the integration metadata. | 
| Datadog.Incident.relationships.last_modified_by_user.data.id | String | A unique identifier that represents the user. | 
| Datadog.Incident.relationships.commander_user.data.id | Unknown | A unique identifier that represents the user. | 
| Datadog.Incident.included.attributes.created_at | String | Creation time of the user. | 
| Datadog.Incident.included.attributes.disabled | Boolean | Whether the user is disabled. | 
| Datadog.Incident.included.attributes.email | String | Email of the user. | 
| Datadog.Incident.included.attributes.handle | String | Handle of the user. | 
| Datadog.Incident.included.attributes.icon | String | URL of the user's icon. | 
| Datadog.Incident.included.attributes.modified_at | String | Time that the user was last modified. | 
| Datadog.Incident.included.attributes.name | String | Name of the user. | 
| Datadog.Incident.included.attributes.service_account | Boolean | Whether the user is a service account. | 
| Datadog.Incident.included.attributes.status | String | Status of the user. | 
| Datadog.Incident.included.attributes.title | String | Title of the user. | 
| Datadog.Incident.included.attributes.verified | Boolean | Whether the user is verified. | 
| Datadog.Incident.included.id | String | ID of the user. | 
| Datadog.Incident.included.relationships.org.id | String | ID of the organization. | 
| Datadog.Incident.included.relationships.other_orgs.id | String | ID of the other organization. | 
| Datadog.Incident.included.relationships.other_users.id | String | A unique identifier that represents the user. | 
| Datadog.Incident.included.relationships.roles.id | String | The unique identifier of the role. | 

#### Command example
```!datadog-incident-list limit=2```
#### Context Example
```json
{
    "Datadog": {
        "Incident": [
            {
                "attributes": {
                    "archived": null,
                    "case_id": null,
                    "commander": {
                        "data": {
                            "attributes": {
                                "email": "integrations@loginsoft.com",
                                "handle": "integrations@loginsoft.com",
                                "icon": "https://secure.gravatar.com/avatar/3e04e593f20b31b84122703a927d39f4?s=48&d=retro",
                                "name": "Muthu Mahadevan",
                                "uuid": "5db43403-9895-11ed-a432-b611e40f0c37"
                            },
                            "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                            "type": "users"
                        }
                    },
                    "created": "2023-02-02T06:53:06+00:00",
                    "created_by": {
                        "data": {
                            "attributes": {
                                "email": "integrations@loginsoft.com",
                                "handle": "integrations@loginsoft.com",
                                "icon": "https://secure.gravatar.com/avatar/3e04e593f20b31b84122703a927d39f4?s=48&d=retro",
                                "name": "Muthu Mahadevan",
                                "uuid": "5db43403-9895-11ed-a432-b611e40f0c37"
                            },
                            "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                            "type": "users"
                        }
                    },
                    "created_by_uuid": null,
                    "creation_idempotency_key": null,
                    "customer_impact_duration": 0,
                    "customer_impact_end": null,
                    "customer_impact_scope": "",
                    "customer_impact_start": null,
                    "customer_impacted": false,
                    "detected": "2023-02-02T06:53:06+00:00",
                    "field_analytics": {
                        "state": {
                            "resolved": {
                                "duration": 0,
                                "spans": [
                                    {
                                        "end": null,
                                        "start": 1675320786
                                    }
                                ]
                            }
                        }
                    },
                    "fields": {
                        "detection_method": {
                            "type": "dropdown",
                            "value": "unknown"
                        },
                        "root_cause": {
                            "type": "textbox",
                            "value": null
                        },
                        "services": {
                            "type": "autocomplete",
                            "value": null
                        },
                        "severity": {
                            "type": "dropdown",
                            "value": "UNKNOWN"
                        },
                        "state": {
                            "type": "dropdown",
                            "value": "resolved"
                        },
                        "summary": {
                            "type": "textbox",
                            "value": null
                        },
                        "teams": {
                            "type": "autocomplete",
                            "value": null
                        }
                    },
                    "last_modified_by": {
                        "data": {
                            "attributes": {
                                "email": "integrations@loginsoft.com",
                                "handle": "integrations@loginsoft.com",
                                "icon": "https://secure.gravatar.com/avatar/3e04e593f20b31b84122703a927d39f4?s=48&d=retro",
                                "name": "Muthu Mahadevan",
                                "uuid": "5db43403-9895-11ed-a432-b611e40f0c37"
                            },
                            "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                            "type": "users"
                        }
                    },
                    "last_modified_by_uuid": null,
                    "modified": "2023-02-02T06:53:06+00:00",
                    "non_datadog_creator": null,
                    "notification_handles": null,
                    "public_id": 5,
                    "resolved": null,
                    "severity": "UNKNOWN",
                    "state": "resolved",
                    "time_to_detect": 0,
                    "time_to_internal_response": 0,
                    "time_to_repair": 0,
                    "time_to_resolve": 0,
                    "title": "Example-Create_an_incident_returns_CREATED_response",
                    "visibility": "organization"
                },
                "id": "73e9f627-5dd6-526f-b658-6e89b7e2e438",
                "relationships": {
                    "attachments": {
                        "data": []
                    },
                    "commander_user": {
                        "data": {
                            "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                            "type": "users"
                        }
                    },
                    "created_by_user": {
                        "data": {
                            "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                            "type": "users"
                        }
                    },
                    "impacts": {
                        "data": []
                    },
                    "integrations": {
                        "data": []
                    },
                    "last_modified_by_user": {
                        "data": {
                            "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                            "type": "users"
                        }
                    },
                    "responders": {
                        "data": [
                            {
                                "id": "1f3687b4-0ca8-530f-8501-b85423ba4676",
                                "type": "incident_responders"
                            }
                        ]
                    },
                    "user_defined_fields": {
                        "data": []
                    }
                },
                "type": "incidents"
            },
            {
                "attributes": {
                    "archived": null,
                    "case_id": null,
                    "commander": {
                        "data": {
                            "attributes": {
                                "email": "integrations@loginsoft.com",
                                "handle": "integrations@loginsoft.com",
                                "icon": "https://secure.gravatar.com/avatar/3e04e593f20b31b84122703a927d39f4?s=48&d=retro",
                                "name": "Muthu Mahadevan",
                                "uuid": "5db43403-9895-11ed-a432-b611e40f0c37"
                            },
                            "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                            "type": "users"
                        }
                    },
                    "created": "2023-02-02T10:07:52+00:00",
                    "created_by": {
                        "data": {
                            "attributes": {
                                "email": "integrations@loginsoft.com",
                                "handle": "integrations@loginsoft.com",
                                "icon": "https://secure.gravatar.com/avatar/3e04e593f20b31b84122703a927d39f4?s=48&d=retro",
                                "name": "Muthu Mahadevan",
                                "uuid": "5db43403-9895-11ed-a432-b611e40f0c37"
                            },
                            "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                            "type": "users"
                        }
                    },
                    "created_by_uuid": null,
                    "creation_idempotency_key": null,
                    "customer_impact_duration": 0,
                    "customer_impact_end": null,
                    "customer_impact_scope": "",
                    "customer_impact_start": null,
                    "customer_impacted": false,
                    "detected": "2023-02-02T10:07:52+00:00",
                    "field_analytics": {
                        "state": {
                            "resolved": {
                                "duration": 0,
                                "spans": [
                                    {
                                        "end": null,
                                        "start": 1675332472
                                    }
                                ]
                            }
                        }
                    },
                    "fields": {
                        "detection_method": {
                            "type": "dropdown",
                            "value": "unknown"
                        },
                        "root_cause": {
                            "type": "textbox",
                            "value": null
                        },
                        "services": {
                            "type": "autocomplete",
                            "value": null
                        },
                        "severity": {
                            "type": "dropdown",
                            "value": "UNKNOWN"
                        },
                        "state": {
                            "type": "dropdown",
                            "value": "resolved"
                        },
                        "summary": {
                            "type": "textbox",
                            "value": null
                        },
                        "teams": {
                            "type": "autocomplete",
                            "value": null
                        }
                    },
                    "last_modified_by": {
                        "data": {
                            "attributes": {
                                "email": "integrations@loginsoft.com",
                                "handle": "integrations@loginsoft.com",
                                "icon": "https://secure.gravatar.com/avatar/3e04e593f20b31b84122703a927d39f4?s=48&d=retro",
                                "name": "Muthu Mahadevan",
                                "uuid": "5db43403-9895-11ed-a432-b611e40f0c37"
                            },
                            "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                            "type": "users"
                        }
                    },
                    "last_modified_by_uuid": null,
                    "modified": "2023-02-02T10:07:52+00:00",
                    "non_datadog_creator": null,
                    "notification_handles": null,
                    "public_id": 6,
                    "resolved": null,
                    "severity": "UNKNOWN",
                    "state": "resolved",
                    "time_to_detect": 0,
                    "time_to_internal_response": 0,
                    "time_to_repair": 0,
                    "time_to_resolve": 0,
                    "title": "test-incident-i1",
                    "visibility": "organization"
                },
                "id": "dc203d96-2c07-55f4-9312-5427468a8190",
                "relationships": {
                    "attachments": {
                        "data": []
                    },
                    "commander_user": {
                        "data": {
                            "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                            "type": "users"
                        }
                    },
                    "created_by_user": {
                        "data": {
                            "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                            "type": "users"
                        }
                    },
                    "impacts": {
                        "data": []
                    },
                    "integrations": {
                        "data": []
                    },
                    "last_modified_by_user": {
                        "data": {
                            "id": "5db43403-9895-11ed-a432-b611e40f0c37",
                            "type": "users"
                        }
                    },
                    "responders": {
                        "data": [
                            {
                                "id": "2e70690d-a064-5aed-8b26-68343a0c8566",
                                "type": "incident_responders"
                            }
                        ]
                    },
                    "user_defined_fields": {
                        "data": []
                    }
                },
                "type": "incidents"
            }
        ]
    }
}
```

#### Human Readable Output

>### Incidents List
>|ID|Title|Created|Customer Impacted|Customer Impact Duration|Detected|Resolved|Time to Detect|Time to Internal Response|Time to Repair|Time to Resolve|Severity|State|Detection Method|Root Cause|Summary|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 73e9f627-5dd6-526f-b658-6e89b7e2e438 | Example-Create_an_incident_returns_CREATED_response | February 02, 2023 06:53 AM | False | 0 | February 02, 2023 06:53 AM | None | 0 | 0 | 0 | 0 | UNKNOWN | resolved | unknown | None | None |
>| dc203d96-2c07-55f4-9312-5427468a8190 | test-incident-i1 | February 02, 2023 10:07 AM | False | 0 | February 02, 2023 10:07 AM | None | 0 | 0 | 0 | 0 | UNKNOWN | resolved | unknown | None | None |


### datadog-time-series-point-query

***
Query of Sequence of data points which are collected over time intervals, allowing us to track changes over time.

#### Base Command

`datadog-time-series-point-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | Start of the queried time period.<br/>Format : YYYY-MM-dd’T’HH:mm:ssZ Or '-1days'. | Required | 
| to | End of the queried time period.<br/>Format : yyyy-MM-dd’T’HH:mm:ssZ Or '-1days'. | Required | 
| query | Query string.<br/>Ex : query="system.cpu.idle" <br/>A complete list of query string values available here. https://app.datadoghq.com/metric/summary. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.TimeSeriesPoint.from_date | Date | Start of requested time window, milliseconds since Unix epoch. | 
| Datadog.TimeSeriesPoint.error | String | Message indicating the errors if status is not ok. | 
| Datadog.TimeSeriesPoint.group_by | Unknown | List of tag keys on which to group.  | 
| Datadog.TimeSeriesPoint.message | String | Message indicating success if status is ok. | 
| Datadog.TimeSeriesPoint.query | String | Query string. | 
| Datadog.TimeSeriesPoint.res_type | String | Type of response. | 
| Datadog.TimeSeriesPoint.series.aggr | Unknown | Aggregation type. | 
| Datadog.TimeSeriesPoint.series.display_name | String | Display name of the metric. | 
| Datadog.TimeSeriesPoint.series.end | Date | End of the time window, milliseconds since Unix epoch. | 
| Datadog.TimeSeriesPoint.series.expression | String | Metric expression. | 
| Datadog.TimeSeriesPoint.series.interval | Number | Number of seconds between data samples. | 
| Datadog.TimeSeriesPoint.series.length | Number | Number of data samples. | 
| Datadog.TimeSeriesPoint.series.metric | String | Metric name. | 
| Datadog.TimeSeriesPoint.series.pointlist | Number | List of points of the time series. | 
| Datadog.TimeSeriesPoint.series.query_index | Number | The index of the series query within the request. | 
| Datadog.TimeSeriesPoint.series.scope | String | Metric scope, comma separated list of tags. | 
| Datadog.TimeSeriesPoint.series.start | Date | Start of the time window, milliseconds since Unix epoch. | 
| Datadog.TimeSeriesPoint.series.tag_set | Unknown | Unique tags identifying this series. | 
| Datadog.TimeSeriesPoint.series.unit.family | String | Unit family allows for conversion between units of the same family, for scaling. | 
| Datadog.TimeSeriesPoint.series.unit.name | String | Unit name. | 
| Datadog.TimeSeriesPoint.series.unit.plural | String | Plural form of the unit's name. | 
| Datadog.TimeSeriesPoint.series.unit.scale_factor | Number | Factor for scaling between units of the same family. | 
| Datadog.TimeSeriesPoint.series.unit.short_name | String | Abbreviation of the unit. | 
| Datadog.TimeSeriesPoint.status | String | Status of the query. | 
| Datadog.TimeSeriesPoint.to_date | Date | End of requested time window, milliseconds since Unix epoch. | 

#### Command example
```!datadog-time-series-point-query from="-2days" query="system.cpu.idle" to=now```
#### Context Example
```json
{
    "Datadog": {
        "TimeSeriesPoint": {
            "from_date": 1682520795000,
            "group_by": [],
            "message": "",
            "query": "system.cpu.idle{*}",
            "res_type": "time_series",
            "resp_version": 1,
            "series": [
                {
                    "aggr": null,
                    "attributes": {},
                    "display_name": "system.cpu.idle",
                    "end": 1682693999000,
                    "expression": "system.cpu.idle{*}",
                    "interval": 600,
                    "length": 288,
                    "metric": "system.cpu.idle",
                    "pointlist": [
                        [
                            1682521200000,
                            97.48440740832112
                        ],
                        [
                            1682521800000,
                            96.73048786403365
                        ],
                        [
                            1682522400000,
                            97.57092829654492
                        ],
                        [
                            1682523000000,
                            84.13978680907982
                        ],
                        [
                            1682523600000,
                            87.21321567700204
                        ],
                        [
                            1682524200000,
                            88.58691781215045
                        ],
                        [
                            1682524800000,
                            92.46264440025988
                        ],
                        [
                            1682525400000,
                            96.85268790686185
                        ],
                        [
                            1682526000000,
                            86.6021549905176
                        ],
                        [
                            1682526600000,
                            80.30905928170162
                        ],
                        [
                            1682527200000,
                            85.17906383448344
                        ],
                        [
                            1682527800000,
                            85.24201879147702
                        ],
                        [
                            1682528400000,
                            84.81654632977384
                        ],
                        [
                            1682529000000,
                            88.17770465295037
                        ],
                        [
                            1682529600000,
                            91.63146630216026
                        ],
                        [
                            1682530200000,
                            89.03770886985187
                        ],
                        [
                            1682530800000,
                            92.69700340290726
                        ],
                        [
                            1682531400000,
                            97.60644503787948
                        ],
                        [
                            1682532000000,
                            97.30407945684367
                        ],
                        [
                            1682532600000,
                            96.80294569202402
                        ],
                        [
                            1682533200000,
                            97.51973611533819
                        ],
                        [
                            1682533800000,
                            97.21059788820565
                        ],
                        [
                            1682534400000,
                            96.49870817073165
                        ],
                        [
                            1682535000000,
                            97.53200577947266
                        ],
                        [
                            1682535600000,
                            96.45937333905442
                        ],
                        [
                            1682536200000,
                            97.64608443246813
                        ],
                        [
                            1682536800000,
                            97.50301129386935
                        ],
                        [
                            1682537400000,
                            96.43442697811062
                        ],
                        [
                            1682538000000,
                            97.62420135931556
                        ],
                        [
                            1682538600000,
                            96.76013574350165
                        ],
                        [
                            1682539200000,
                            97.16389120600665
                        ],
                        [
                            1682539800000,
                            97.66723571142498
                        ],
                        [
                            1682540400000,
                            96.81197566124256
                        ],
                        [
                            1682541000000,
                            97.27272361406833
                        ],
                        [
                            1682541600000,
                            97.48289644260636
                        ],
                        [
                            1682542200000,
                            97.14237484471806
                        ],
                        [
                            1682542800000,
                            96.98183694783673
                        ],
                        [
                            1682543400000,
                            97.64233224971687
                        ],
                        [
                            1682544000000,
                            96.64993356102377
                        ],
                        [
                            1682544600000,
                            97.20613818034654
                        ],
                        [
                            1682545200000,
                            97.62928683578465
                        ],
                        [
                            1682545800000,
                            97.64023269541887
                        ],
                        [
                            1682546400000,
                            96.33876521797457
                        ],
                        [
                            1682547000000,
                            97.45494947188324
                        ],
                        [
                            1682547600000,
                            97.61867134699123
                        ],
                        [
                            1682548200000,
                            97.25751408609828
                        ],
                        [
                            1682548800000,
                            96.690624671662
                        ],
                        [
                            1682549400000,
                            97.61376798494652
                        ],
                        [
                            1682550000000,
                            96.39396479856566
                        ],
                        [
                            1682550600000,
                            88.61220901113839
                        ],
                        [
                            1682551200000,
                            97.5579462245945
                        ],
                        [
                            1682551800000,
                            96.4377819391647
                        ],
                        [
                            1682552400000,
                            97.62882223378766
                        ],
                        [
                            1682553000000,
                            96.77369119729835
                        ],
                        [
                            1682553600000,
                            97.29888379811395
                        ],
                        [
                            1682554200000,
                            97.462811218682
                        ],
                        [
                            1682554800000,
                            96.63660223969892
                        ],
                        [
                            1682555400000,
                            94.49592612074146
                        ],
                        [
                            1682556000000,
                            95.65668847204412
                        ],
                        [
                            1682556600000,
                            97.60641691441192
                        ],
                        [
                            1682557200000,
                            97.24729217219254
                        ],
                        [
                            1682557800000,
                            96.22932073984336
                        ],
                        [
                            1682558400000,
                            97.58941909245416
                        ],
                        [
                            1682559000000,
                            96.48150005994037
                        ],
                        [
                            1682559600000,
                            97.45543618965787
                        ],
                        [
                            1682560200000,
                            97.62582334813533
                        ],
                        [
                            1682560800000,
                            96.40691872038451
                        ],
                        [
                            1682561400000,
                            97.59168669952524
                        ],
                        [
                            1682562000000,
                            96.67615852915233
                        ],
                        [
                            1682562600000,
                            97.28744277345977
                        ],
                        [
                            1682563200000,
                            97.63406843942434
                        ],
                        [
                            1682563800000,
                            94.52232542474344
                        ],
                        [
                            1682564400000,
                            97.29369799544561
                        ],
                        [
                            1682565000000,
                            96.47790079402618
                        ],
                        [
                            1682565600000,
                            97.5850088596751
                        ],
                        [
                            1682566200000,
                            96.48116212245546
                        ],
                        [
                            1682566800000,
                            97.6413585731874
                        ],
                        [
                            1682567400000,
                            97.62929808380116
                        ],
                        [
                            1682568000000,
                            96.32282164577653
                        ],
                        [
                            1682568600000,
                            81.95119360317373
                        ],
                        [
                            1682569200000,
                            85.68010595020273
                        ],
                        [
                            1682569800000,
                            92.9344616839865
                        ],
                        [
                            1682570400000,
                            88.31700718673805
                        ],
                        [
                            1682571000000,
                            91.88347656012311
                        ],
                        [
                            1682571600000,
                            88.41501191928009
                        ],
                        [
                            1682572200000,
                            91.76008410358929
                        ],
                        [
                            1682572800000,
                            91.59544636637986
                        ],
                        [
                            1682573400000,
                            97.37588506954846
                        ],
                        [
                            1682574000000,
                            91.4502770839871
                        ],
                        [
                            1682574600000,
                            90.04020281888486
                        ],
                        [
                            1682575200000,
                            93.33226122586382
                        ],
                        [
                            1682575800000,
                            91.3793967742724
                        ],
                        [
                            1682576400000,
                            90.40200806930827
                        ],
                        [
                            1682577000000,
                            91.94245502487573
                        ],
                        [
                            1682577600000,
                            92.12364726354531
                        ],
                        [
                            1682578200000,
                            93.40131815743692
                        ],
                        [
                            1682578800000,
                            87.4161392803949
                        ],
                        [
                            1682579400000,
                            93.43745569750497
                        ],
                        [
                            1682580000000,
                            94.55050382997004
                        ],
                        [
                            1682580600000,
                            91.20505444834585
                        ],
                        [
                            1682581200000,
                            92.3459358234305
                        ],
                        [
                            1682581800000,
                            92.39138103842483
                        ],
                        [
                            1682582400000,
                            93.94614048947606
                        ],
                        [
                            1682583000000,
                            97.17987961629184
                        ],
                        [
                            1682583600000,
                            97.63487811569372
                        ],
                        [
                            1682584200000,
                            97.23526782416118
                        ],
                        [
                            1682584800000,
                            97.70234773911845
                        ],
                        [
                            1682585400000,
                            96.56598404320327
                        ],
                        [
                            1682586000000,
                            97.26469161820471
                        ],
                        [
                            1682586600000,
                            89.36715639087211
                        ],
                        [
                            1682587200000,
                            93.93208340782876
                        ],
                        [
                            1682587800000,
                            90.57010477134806
                        ],
                        [
                            1682588400000,
                            93.474497194695
                        ],
                        [
                            1682589000000,
                            93.59161472430912
                        ],
                        [
                            1682589600000,
                            91.3458442558882
                        ],
                        [
                            1682590200000,
                            93.76960445105485
                        ],
                        [
                            1682590800000,
                            93.51359497612862
                        ],
                        [
                            1682591400000,
                            92.8395802043548
                        ],
                        [
                            1682592000000,
                            94.6040082161313
                        ],
                        [
                            1682592600000,
                            96.51278596311813
                        ],
                        [
                            1682593200000,
                            92.34862614329226
                        ],
                        [
                            1682593800000,
                            89.49695376524497
                        ],
                        [
                            1682594400000,
                            94.9067845462651
                        ],
                        [
                            1682595000000,
                            92.5102294932273
                        ],
                        [
                            1682595600000,
                            92.26090854231634
                        ],
                        [
                            1682596200000,
                            93.81489613643488
                        ],
                        [
                            1682596800000,
                            91.5847580909729
                        ],
                        [
                            1682597400000,
                            91.44057397842407
                        ],
                        [
                            1682598000000,
                            94.36251125335693
                        ],
                        [
                            1682598600000,
                            93.59926977157593
                        ],
                        [
                            1682599200000,
                            92.32946577072144
                        ],
                        [
                            1682599800000,
                            91.04372906684875
                        ],
                        [
                            1682600400000,
                            87.51747102737427
                        ],
                        [
                            1682601000000,
                            91.70421019054595
                        ],
                        [
                            1682601600000,
                            84.22085829038878
                        ],
                        [
                            1682602200000,
                            95.74583514901094
                        ],
                        [
                            1682602800000,
                            97.57643337249756
                        ],
                        [
                            1682603400000,
                            96.64552021026611
                        ],
                        [
                            1682604000000,
                            97.2176965713501
                        ],
                        [
                            1682604600000,
                            96.79030933380128
                        ],
                        [
                            1682605200000,
                            97.61971111297608
                        ],
                        [
                            1682605800000,
                            97.30796890258789
                        ],
                        [
                            1682606400000,
                            96.74761981964112
                        ],
                        [
                            1682607000000,
                            97.57153015136718
                        ],
                        [
                            1682607600000,
                            96.65576057434082
                        ],
                        [
                            1682608200000,
                            97.3435525894165
                        ],
                        [
                            1682608800000,
                            97.60918159484864
                        ],
                        [
                            1682609400000,
                            79.39077148558002
                        ],
                        [
                            1682610000000,
                            82.00617418289184
                        ],
                        [
                            1682610600000,
                            85.56051979064941
                        ],
                        [
                            1682611200000,
                            84.10478801727295
                        ],
                        [
                            1682611800000,
                            83.69890675544738
                        ],
                        [
                            1682612400000,
                            92.34198063817517
                        ],
                        [
                            1682613000000,
                            82.1601449215051
                        ],
                        [
                            1682613600000,
                            81.92808866500854
                        ],
                        [
                            1682614200000,
                            83.64684104919434
                        ],
                        [
                            1682614800000,
                            89.03892082214355
                        ],
                        [
                            1682615400000,
                            94.32065490196491
                        ],
                        [
                            1682616000000,
                            97.60104560852051
                        ],
                        [
                            1682616600000,
                            96.2286563873291
                        ],
                        [
                            1682617200000,
                            97.6518180847168
                        ],
                        [
                            1682617800000,
                            97.644801902771
                        ],
                        [
                            1682618400000,
                            96.4357536315918
                        ],
                        [
                            1682619000000,
                            97.65837287902832
                        ],
                        [
                            1682619600000,
                            96.80581798553467
                        ],
                        [
                            1682620200000,
                            97.2159481048584
                        ],
                        [
                            1682620800000,
                            97.17367362976074
                        ],
                        [
                            1682621400000,
                            96.78033866882325
                        ],
                        [
                            1682622000000,
                            97.26325778961181
                        ],
                        [
                            1682622600000,
                            96.79739780426026
                        ],
                        [
                            1682623200000,
                            97.58135108947754
                        ],
                        [
                            1682623800000,
                            96.751997756958
                        ],
                        [
                            1682624400000,
                            97.3066032409668
                        ],
                        [
                            1682625000000,
                            97.6451021194458
                        ],
                        [
                            1682625600000,
                            96.36336250305176
                        ],
                        [
                            1682626200000,
                            97.68665046691895
                        ],
                        [
                            1682626800000,
                            97.53792667388916
                        ],
                        [
                            1682627400000,
                            96.53842906951904
                        ],
                        [
                            1682628000000,
                            97.64238739013672
                        ],
                        [
                            1682628600000,
                            96.81128673553467
                        ],
                        [
                            1682629200000,
                            97.27343292236328
                        ],
                        [
                            1682629800000,
                            97.53718166351318
                        ],
                        [
                            1682630400000,
                            96.75984058380126
                        ],
                        [
                            1682631000000,
                            97.35216808319092
                        ],
                        [
                            1682631600000,
                            96.75571193695069
                        ],
                        [
                            1682632200000,
                            97.67135772705078
                        ],
                        [
                            1682632800000,
                            96.66441631317139
                        ],
                        [
                            1682633400000,
                            97.39322910308837
                        ],
                        [
                            1682634000000,
                            97.48210468292237
                        ],
                        [
                            1682634600000,
                            96.44509811401367
                        ],
                        [
                            1682635200000,
                            97.64750537872314
                        ],
                        [
                            1682635800000,
                            97.62411403656006
                        ],
                        [
                            1682636400000,
                            96.453293800354
                        ],
                        [
                            1682637000000,
                            97.64222850799561
                        ],
                        [
                            1682637600000,
                            96.76531753540038
                        ],
                        [
                            1682638200000,
                            97.17852249145508
                        ],
                        [
                            1682638800000,
                            97.11903667449951
                        ],
                        [
                            1682639400000,
                            97.36345615386963
                        ],
                        [
                            1682640000000,
                            97.28464050292969
                        ],
                        [
                            1682640600000,
                            96.68140773773193
                        ],
                        [
                            1682641200000,
                            97.60981101989746
                        ],
                        [
                            1682641800000,
                            91.65326766967773
                        ],
                        [
                            1682642400000,
                            97.17956733703613
                        ],
                        [
                            1682643000000,
                            97.41119709014893
                        ],
                        [
                            1682643600000,
                            96.49349365234374
                        ],
                        [
                            1682644200000,
                            97.63050994873046
                        ],
                        [
                            1682644800000,
                            93.36230411529542
                        ],
                        [
                            1682645400000,
                            95.30139226913452
                        ],
                        [
                            1682646000000,
                            97.66707038879395
                        ],
                        [
                            1682646600000,
                            96.71833953857421
                        ],
                        [
                            1682647200000,
                            97.15893287658692
                        ],
                        [
                            1682647800000,
                            96.76797637939453
                        ],
                        [
                            1682648400000,
                            97.64756755828857
                        ],
                        [
                            1682649000000,
                            97.35356674194335
                        ],
                        [
                            1682649600000,
                            96.83387107849121
                        ],
                        [
                            1682650200000,
                            97.65504913330078
                        ],
                        [
                            1682650800000,
                            96.44734764099121
                        ],
                        [
                            1682651400000,
                            97.53182430267334
                        ],
                        [
                            1682652000000,
                            97.5084846496582
                        ],
                        [
                            1682652600000,
                            96.52712574005128
                        ],
                        [
                            1682653200000,
                            97.67660675048828
                        ],
                        [
                            1682653800000,
                            96.77627754211426
                        ],
                        [
                            1682654400000,
                            97.3186227798462
                        ],
                        [
                            1682655000000,
                            97.65579872131347
                        ],
                        [
                            1682655600000,
                            96.79428195953369
                        ],
                        [
                            1682656200000,
                            60.201404392240306
                        ],
                        [
                            1682656800000,
                            83.15728759765625
                        ],
                        [
                            1682657400000,
                            93.75498533248901
                        ],
                        [
                            1682658000000,
                            89.82336874008179
                        ],
                        [
                            1682658600000,
                            79.83826985359192
                        ],
                        [
                            1682659200000,
                            80.0052146077156
                        ],
                        [
                            1682659800000,
                            85.08877735137939
                        ],
                        [
                            1682660400000,
                            88.58028345108032
                        ],
                        [
                            1682661000000,
                            85.84431484937667
                        ],
                        [
                            1682661600000,
                            83.3854887008667
                        ],
                        [
                            1682662200000,
                            90.06866779327393
                        ],
                        [
                            1682662800000,
                            91.87395706176758
                        ],
                        [
                            1682663400000,
                            92.65545740127564
                        ],
                        [
                            1682664000000,
                            92.50728197097779
                        ],
                        [
                            1682664600000,
                            92.3748475074768
                        ],
                        [
                            1682665200000,
                            92.33070802688599
                        ],
                        [
                            1682665800000,
                            81.07693064212799
                        ],
                        [
                            1682666400000,
                            91.42785693081943
                        ],
                        [
                            1682667000000,
                            84.1410339004115
                        ],
                        [
                            1682667600000,
                            80.17443594932556
                        ],
                        [
                            1682668200000,
                            82.12359919548035
                        ],
                        [
                            1682668800000,
                            82.57723922729492
                        ],
                        [
                            1682669400000,
                            78.92460832595825
                        ],
                        [
                            1682670000000,
                            76.89122042655944
                        ],
                        [
                            1682670600000,
                            80.20570783615112
                        ],
                        [
                            1682671200000,
                            87.90225458145142
                        ],
                        [
                            1682671800000,
                            81.89591889381408
                        ],
                        [
                            1682672400000,
                            85.10432805158197
                        ],
                        [
                            1682673000000,
                            85.11556205749511
                        ],
                        [
                            1682673600000,
                            85.88338403701782
                        ],
                        [
                            1682674200000,
                            90.2623077392578
                        ],
                        [
                            1682674800000,
                            88.96403980255127
                        ],
                        [
                            1682675400000,
                            88.04144659042359
                        ],
                        [
                            1682676000000,
                            84.05185642242432
                        ],
                        [
                            1682676600000,
                            83.58657345771789
                        ],
                        [
                            1682677200000,
                            82.58894581794739
                        ],
                        [
                            1682677800000,
                            88.83294243812561
                        ],
                        [
                            1682678400000,
                            88.97372632026672
                        ],
                        [
                            1682679000000,
                            88.95859699249267
                        ],
                        [
                            1682679600000,
                            88.1772349357605
                        ],
                        [
                            1682680200000,
                            90.939768409729
                        ],
                        [
                            1682680800000,
                            92.22097072601318
                        ],
                        [
                            1682681400000,
                            94.16260262691614
                        ],
                        [
                            1682682000000,
                            93.11157732009887
                        ],
                        [
                            1682682600000,
                            91.92160806655883
                        ],
                        [
                            1682683200000,
                            90.83914051055908
                        ],
                        [
                            1682683800000,
                            87.98394122123719
                        ],
                        [
                            1682684400000,
                            91.64494190216064
                        ],
                        [
                            1682685000000,
                            90.7819682598114
                        ],
                        [
                            1682685600000,
                            91.96860055923462
                        ],
                        [
                            1682686200000,
                            94.73343752347506
                        ],
                        [
                            1682686800000,
                            96.47880172729492
                        ],
                        [
                            1682687400000,
                            94.63617012717508
                        ],
                        [
                            1682688000000,
                            97.56094493865967
                        ],
                        [
                            1682688600000,
                            96.45301170349121
                        ],
                        [
                            1682689200000,
                            97.66946258544922
                        ],
                        [
                            1682689800000,
                            96.74827632904052
                        ],
                        [
                            1682690400000,
                            97.28894691467285
                        ],
                        [
                            1682691000000,
                            97.54164028167725
                        ],
                        [
                            1682691600000,
                            96.70230045318604
                        ],
                        [
                            1682692200000,
                            97.050044631958
                        ],
                        [
                            1682692800000,
                            96.79117546081542
                        ],
                        [
                            1682693400000,
                            97.54119110107422
                        ]
                    ],
                    "query_index": 0,
                    "scope": "*",
                    "start": 1682521200000,
                    "tag_set": [],
                    "unit": [
                        {
                            "family": "percentage",
                            "id": 17,
                            "name": "percent",
                            "plural": "percent",
                            "scale_factor": 1,
                            "short_name": "%"
                        },
                        null
                    ]
                }
            ],
            "status": "ok",
            "times": [],
            "to_date": 1682693595000,
            "values": []
        }
    },
    "InfoFile": {
        "EntryID": "181@5be6c436-9d99-4c0d-8a75-9a876a0ced7b",
        "Extension": "json",
        "Info": "application/json",
        "Name": "timeseries_query_points.json",
        "Size": 19583,
        "Type": "CSV text"
    }
}
```

#### Human Readable Output

>### Query Timeseries Points 

