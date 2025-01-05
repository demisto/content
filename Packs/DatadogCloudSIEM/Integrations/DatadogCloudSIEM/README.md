## Datadog Cloud SIEM

Datadog is an observability service for cloud-scale applications, providing monitoring of servers, databases, tools, and services, through a SaaS-based data analytics platform.

The SaaS platform integrates and automates infrastructure monitoring, application performance monitoring and log management to provide unified, real-time observability of our customers' entire technology stack.
This integration was integrated and tested with version 2.12.0 of datadog-api-client.

## Configure Datadog Cloud SIEM in Cortex


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


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### datadog-event-create

***
This endpoint allows you to post events to the stream.

#### Base Command

`datadog-event-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | A description of the event.<br/>Limited to 4000 characters.<br/>The description supports markdown. To use markdown in the event text, start the text block with %%% \n and end the text block with \n %%% . | Required | 
| title | The title of an event. | Required | 
| date_happened | The timestamp cannot be older than 18 hours.<br/>Format :  <br/>yyyy-MM-dd’T’HH:mm:ssZ or “12 hours ago” or “-12 hours” or “15 min ago” or “-15 min”. | Optional | 
| device_name | A device name. | Optional | 
| host_name | Host name to associate with the event. | Optional | 
| priority | The priority of the event.<br/><br/>Restricted value : low<br/>Permitted value : normal (Bug will be fixed in the near future.). Possible values are: normal, low. | Optional | 
| related_event_id | ID of the parent event. | Optional | 
| tags | A comma-separated list of tags to apply to the event. <br/>Ex: "environment:production, region:East” . | Optional | 
| aggregation_key | An arbitrary string to use for aggregation. <br/>If you specify a key, all events using that key are grouped together in the Event Stream. <br/>Limited to 100 characters. | Optional | 
| source_type_name | The type of event being posted. A complete list of source attribute values are available here: https://docs.datadoghq.com/integrations/faq/list-of-api-source-attribute-value/. | Optional | 
| alert_type | If an alert event is enabled, set its type. Possible values are: error, warning, info, success, user_update, recommendation, snapshot. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Event.date_happened | Number | The timestamp of when the event happened. | 
| Datadog.Event.id | Number | Integer ID of the event. | 
| Datadog.Event.priority | String | The priority of the event.  Possible values: normal, low. | 
| Datadog.Event.text | String | The description of the event. Limited to 4000 characters. The description supports markdown. | 
| Datadog.Event.tags | Unknown | A list of tags to apply to the event. | 
| Datadog.Event.url | String | URL of the event. | 
| Datadog.Event.status | String | The status of the event. | 
| Datadog.Event.title | String | The event title. | 
| Datadog.Event.alert_type | String | The alert type. Possible values: error, warning, info, success, user_update, recommendation, snapshot. | 
| Datadog.Event.device_name | String | A device name associated with the event. | 
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
                "date_happened": 1683015522,
                "handle": null,
                "id": 7025503766209322000,
                "id_str": "7025503766209321995",
                "priority": null,
                "related_event_id": null,
                "tags": null,
                "text": "EventText",
                "title": "EventTitle",
                "url": "https://app.datadoghq.com/event/event?id=7025503766209321995"
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
>| EventTitle | EventText | May 02, 2023 08:18 AM | 7025503766209321995 |


### datadog-event-list

***
Get a list of events / Get the details of a particular event.

#### Base Command

`datadog-event-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the event. | Optional | 
| start_date | Start Date <br/>Format : yyyy-MM-dd’T’HH:mm:ssZ  or “-1days” or “12 hours ago” or “-12 hours” or “15 min ago” or “-15 min”. . | Optional | 
| end_date | End Date <br/>Default: now <br/>Format : yyyy-MM-dd’T’HH:mm:ssZ or "-1 days" or “12 hours ago” or “-12 hours” or “15 min ago” or “-15 min”. . | Optional | 
| priority | The priority of the event. Possible values are: normal, low. | Optional | 
| sources | A comma-separated string of sources.<br/>A complete list of source attribute values is available here: https://docs.datadoghq.com/integrations/faq/list-of-api-source-attribute-value/. | Optional | 
| tags | A comma-separated list indicating what tags, if any, should be used to filter the list of events. <br/>Ex: "environment:production, region:East". | Optional | 
| unaggregated | Set unaggregated to 'true' to return all events within the specified [start,end] timeframe. Possible values are: True, False. | Optional | 
| exclude_aggregate | Set exclude_aggregate to 'true' to only return unaggregated events where is_aggregate=false in the response. Possible values are: True, False. | Optional | 
| page | The page number. Default is 1. | Optional | 
| limit | The maximum number of records to return from the collection. Default is 50. If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Event.alert_type | String | The alert type. Possible values: error, warning, info, success, user_update, recommendation, snapshot. | 
| Datadog.Event.date_happened | Number | The timestamp of when the event happened. | 
| Datadog.Event.device_name | String | A device name.  | 
| Datadog.Event.id | Number | Integer ID of the event. | 
| Datadog.Event.priority | String | The priority of the event.  Possible values: normal, low. | 
| Datadog.Event.text | String | The description of the event. Limited to 4000 characters. The description supports markdown. | 
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
                "date_happened": 1683015432,
                "device_name": null,
                "host": null,
                "id": 7025502259105342000,
                "id_str": "7025502259105342299",
                "is_aggregate": false,
                "monitor_group_status": null,
                "monitor_groups": [],
                "monitor_id": null,
                "priority": "normal",
                "resource": "/api/v1/events/7025502259105342299",
                "source": "Incidents",
                "tags": [
                    "source:incidents"
                ],
                "text": "Status: Active | Severity: Unknown | Commander: Unassigned\nhttps://app.datadoghq.com/incidents/236",
                "title": "Incident #236: incident-test1",
                "url": "/event/event?id=7025502259105342299"
            },
            {
                "alert_type": "info",
                "comments": [],
                "date_happened": 1683015404,
                "device_name": null,
                "host": null,
                "id": 7025501798182967000,
                "id_str": "7025501798182967576",
                "is_aggregate": false,
                "monitor_group_status": null,
                "monitor_groups": [],
                "monitor_id": null,
                "priority": "normal",
                "resource": "/api/v1/events/7025501798182967576",
                "source": "Incidents",
                "tags": [
                    "source:incidents"
                ],
                "text": "Status: Active | Severity: Unknown | Commander: Unassigned\nhttps://app.datadoghq.com/incidents/235",
                "title": "Incident #235: incident-test1",
                "url": "/event/event?id=7025501798182967576"
            }
        ]
    }
}
```

#### Human Readable Output

>### Events List
>|Title|Text|Date Happened|Id|Priority|Source|Tags|Is Aggregate|Alert Type|
>|---|---|---|---|---|---|---|---|---|
>| Incident #236: incident-test1 | Status: Active \| Severity: Unknown \| Commander: Unassigned<br/>https:<span>//</span>app.datadoghq.com/incidents/236 | May 02, 2023 08:17 AM | 7025502259105342299 | normal | Incidents | source:incidents | false | info |
>| Incident #235: incident-test1 | Status: Active \| Severity: Unknown \| Commander: Unassigned<br/>https:<span>//</span>app.datadoghq.com/incidents/235 | May 02, 2023 08:16 AM | 7025501798182967576 | normal | Incidents | source:incidents | false | info |


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
| limit | The maximum number of records to return from the collection. Default value is 50. If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| source | Source to filter.<br/>Ex: user, datadog. | Optional | 

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
            "Tag": "role:database"
        },
        {
            "Hostname": [
                "TestHost2"
            ],
            "Tag": "app:frontend"
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
            "Tag": "team:infra"
        }
    ]
}
```

#### Human Readable Output

>### Tags List
>|Tag|Host Name|
>|---|---|
>| role:database | TestHost2 |
>| app:frontend | TestHost2 |
>| region:west | TestHost2 |
>| team:infra | TestHost2 |


### datadog-host-tag-create

***
This endpoint allows you to add new tags to a host, optionally specifying where these tags come from.

#### Base Command

`datadog-host-tag-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_name | The host name. | Required | 
| tags | A list of tags to apply to the host. <br/>Comma-seperated values. Ex: "environment:production, region:East” . | Required | 

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
        "Tag": [
            "env:prod"
        ]
    }
}
```

#### Human Readable Output

>### Host Tags Details
>|Host Name|Tag|
>|---|---|
>| TestHost2 | env:prod |


### datadog-host-tag-get

***
Return the list of tags that apply to a given host.

#### Base Command

`datadog-host-tag-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_name | The host name. | Required | 
| source | Source to filter.<br/>Ex: user, datadog. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. <br/>Default is 50. . | Optional | 
| limit | The maximum number of records to return from the collection. Default value is 50. If the page_size argument is set by the user, then the limit argument will be ignored. | Optional | 

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
            "team:infra",
            "region:west",
            "app:frontend"
        ]
    }
}
```

#### Human Readable Output

>### Host Tags List
>|Tags|
>|---|
>| role:database |
>| team:infra |
>| region:west |
>| app:frontend |


### datadog-host-tag-update

***
This endpoint allows you to replace all tags in an integration source with those supplied in the request.

#### Base Command

`datadog-host-tag-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_name | The host name. | Required | 
| tags | A comma-separated list of tags to apply to the host  <br/>Previous tags will be replaced by new tags. Ex: "environment:production, region:East” . | Optional | 

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
| host_name | Host name from which to remove associated tags. | Required | 

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
| host_name | Hostname for filtering the list of metrics.<br/><br/>Please do not complete this field (Bug will be fixed in the near future.). | Optional | 
| tag_filter | Filter metrics that have been submitted with the given tags.<br/>Ex: “region:east,env:prod”. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| limit | The maximum number of records to return from the collection. Default value is 50. If the page_size argument is set by the user, then the limit argument will be ignored. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Metric.from | String | Time when the metrics were active in seconds since the Unix epoch. | 
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
        "Metric.from": "1682842737"
    }
}
```

#### Human Readable Output

>### Active Metric List
>|From|Metric Name|
>|---|---|
>| 2023-04-30 08:18:57 | datadog.agent.python.version,<br/>datadog.agent.running,<br/>datadog.dogstatsd.client.aggregated_context,<br/>datadog.dogstatsd.client.aggregated_context_by_type,<br/>datadog.dogstatsd.client.bytes_dropped,<br/>datadog.dogstatsd.client.bytes_dropped_queue,<br/>datadog.dogstatsd.client.bytes_dropped_writer,<br/>datadog.dogstatsd.client.bytes_sent,<br/>datadog.dogstatsd.client.events,<br/>datadog.dogstatsd.client.metric_dropped_on_receive,<br/>datadog.dogstatsd.client.metrics,<br/>datadog.dogstatsd.client.metrics_by_type,<br/>datadog.dogstatsd.client.packets_dropped,<br/>datadog.dogstatsd.client.packets_dropped_queue,<br/>datadog.dogstatsd.client.packets_dropped_writer,<br/>datadog.dogstatsd.client.packets_sent,<br/>datadog.dogstatsd.client.service_checks,<br/>datadog.estimated_usage.events.custom_events,<br/>datadog.estimated_usage.events.ingested_events,<br/>datadog.estimated_usage.hosts,<br/>datadog.estimated_usage.incident_management.active_users,<br/>datadog.event.tracking.indexation.feed.events,<br/>datadog.event.tracking.intake.feed.bytes,<br/>datadog.event.tracking.intakev2.feed.bytes,<br/>datadog.process.agent,<br/>datadog.trace_agent.cpu_percent,<br/>datadog.trace_agent.events.max_eps.current_rate,<br/>datadog.trace_agent.events.max_eps.max_rate,<br/>datadog.trace_agent.events.max_eps.reached_max,<br/>datadog.trace_agent.events.max_eps.sample_rate,<br/>datadog.trace_agent.heap_alloc,<br/>datadog.trace_agent.heartbeat,<br/>datadog.trace_agent.receiver.out_chan_fill,<br/>datadog.trace_agent.receiver.ratelimit,<br/>datadog.trace_agent.sampler.kept,<br/>datadog.trace_agent.sampler.rare.hits,<br/>datadog.trace_agent.sampler.rare.misses,<br/>datadog.trace_agent.sampler.rare.shrinks,<br/>datadog.trace_agent.sampler.seen,<br/>datadog.trace_agent.sampler.size,<br/>datadog.trace_agent.stats_writer.bytes,<br/>datadog.trace_agent.stats_writer.client_payloads,<br/>datadog.trace_agent.stats_writer.encode_ms.avg,<br/>datadog.trace_agent.stats_writer.encode_ms.count,<br/>datadog.trace_agent.stats_writer.encode_ms.max,<br/>datadog.trace_agent.stats_writer.errors,<br/>datadog.trace_agent.stats_writer.payloads,<br/>datadog.trace_agent.stats_writer.retries,<br/>datadog.trace_agent.stats_writer.splits,<br/>datadog.trace_agent.stats_writer.stats_buckets |


### datadog-metric-search

***
Search for metrics from the last 24 hours in Datadog.

#### Base Command

`datadog-metric-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query string to search metrics from last 24 hours in Datadog.<br/>A complete list of query string values are available here: https://app.datadoghq.com/metric/summary. | Required | 

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
| Datadog.MetricMetadata.short_name | String | A human-readable and abbreviated version of the metric name. | 
| Datadog.MetricMetadata.statsd_interval | Number | StatsD flush interval of the metric in seconds if applicable. | 
| Datadog.MetricMetadata.type | String | Metric type. | 
| Datadog.MetricMetadata.unit | String | Primary unit of the metric. | 
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
| per_unit | Per unit of the metric  <br/>A complete list of metric units values are available here: https://docs.datadoghq.com/metrics/units/#unit-list. | Optional | 
| short_name | A human-readable and abbreviated version of the metric name. | Optional | 
| statsd_interval | StatsD flush interval of the metric in seconds if applicable. | Optional | 
| type | Metric type. Possible values are: count, rate, gauge, set, histogram, distribution. | Optional | 
| unit | Primary unit of the metric. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.MetricMetadata.description | String | Metric description. | 
| Datadog.MetricMetadata.per_unit | String | Per unit of the metric such as second in bytes per second. | 
| Datadog.MetricMetadata.short_name | String | A human-readable and abbreviated version of the metric name. | 
| Datadog.MetricMetadata.statsd_interval | Number | StatsD flush interval of the metric in seconds if applicable. | 
| Datadog.MetricMetadata.type | String | Metric type. | 
| Datadog.MetricMetadata.unit | String | Primary unit of the metric. | 
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
Create an incident.

#### Base Command

`datadog-incident-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_impacted | A flag indicating whether the incident caused customer impact.<br/><br/>Restricted value : True<br/>Permitted value : False (Bug will be fixed in the near future.). Possible values are: True, False. | Required | 
| title | The title of the incident, which summarizes what happened. | Required | 
| severity | The severity of the incident.<br/>Default value=unknown. Possible values are: SEV-1, SEV-2, SEV-3, SEV-4, SEV-5, UNKNOWN. | Optional | 
| state | The state of the incident. Possible values are: active, stable, resolved. | Optional | 
| detection_method | Specify how the incident was detected. Possible values are: customer, employee, monitor, other, unknown. | Optional | 
| root_cause | This field allows you to enter the description of the root cause, triggers, and contributing factors of the incident. | Optional | 
| summary | Summary of the incident. | Optional | 
| content | The Markdown content of the cell  that is used to format using the Markdown syntax rules.<br/>If content is provided, important attribute is required. | Optional | 
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
                "created": "2023-05-02T08:19:12+00:00",
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
                "detected": "2023-05-02T08:19:12+00:00",
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
                "modified": "2023-05-02T08:19:12+00:00",
                "non_datadog_creator": null,
                "notification_handles": [
                    {
                        "created_at": "2023-05-02T08:19:12.355144+00:00",
                        "display_name": null,
                        "handle": null
                    }
                ],
                "public_id": 237,
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
            "id": "33203994-907e-5fb1-8655-9a81f4fd2d99",
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
>| 33203994-907e-5fb1-8655-9a81f4fd2d99 | incident-test1 | May 02, 2023 08:19 AM | False | 0 | None | May 02, 2023 08:19 AM | None | 0 | 0 | 0 | 0 | UNKNOWN | active | unknown | None | None | None | None |


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
```!datadog-incident-delete incident_id=73e9f627-5dd6-526f-b658-6e89b7e2e438```
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
| customer_impact_start | Timestamp when customers began being impacted by the incident.<br/>Format : yyyy-MM-dd’T’HH:mm:ssZ Or  '-1days'. | Optional | 
| customer_impacted | A flag indicating whether the incident caused customer impact. Possible values are: True, False. | Optional | 
| detected | Timestamp when the incident was detected.<br/>Format : yyyy-MM-dd’T’HH:mm:ssZ Or  '-1days'. | Optional | 
| severity | The severity of the incident.<br/>Default value=unknown. Possible values are: SEV-1, SEV-2, SEV-3, SEV-4, SEV-5, UNKNOWN. | Optional | 
| state | The state of the incident. Possible values are: active, stable, resolved. | Optional | 
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
```!datadog-incident-update incident_id=73e9f627-5dd6-526f-b658-6e89b7e2e438```
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
                "created_by_uuid": "5db43403-9895-11ed-a432-b611e40f0c37",
                "creation_idempotency_key": null,
                "customer_impact_duration": 0,
                "customer_impact_end": null,
                "customer_impact_scope": null,
                "customer_impact_start": null,
                "customer_impacted": false,
                "detected": "2023-02-02T06:53:06+00:00",
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
                "modified": "2023-05-02T08:19:15+00:00",
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
>| 73e9f627-5dd6-526f-b658-6e89b7e2e438 | Example-Create_an_incident_returns_CREATED_response | February 02, 2023 06:53 AM | False | 0 | None | February 02, 2023 06:53 AM | None | 0 | 0 | 0 | 0 | UNKNOWN | resolved | unknown | None | None |


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
| limit | The maximum number of records to return from the collection. Default value is 50. If the page_size argument is set by the user, then the limit argument will be ignored. | Optional | 
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
                    "created": "2023-02-03T06:36:49+00:00",
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
                    "detected": "2023-02-03T06:36:49+00:00",
                    "field_analytics": {
                        "state": {
                            "active": {
                                "duration": 0,
                                "spans": [
                                    {
                                        "end": null,
                                        "start": 1675406209
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
                    "modified": "2023-02-03T06:36:49+00:00",
                    "non_datadog_creator": null,
                    "notification_handles": null,
                    "public_id": 7,
                    "resolved": null,
                    "severity": "UNKNOWN",
                    "state": "active",
                    "time_to_detect": 0,
                    "time_to_internal_response": 0,
                    "time_to_repair": 0,
                    "time_to_resolve": 0,
                    "title": "test-incident-i1",
                    "visibility": "organization"
                },
                "id": "e8d7e756-fc4b-5ae3-978b-dc6c081b0c38",
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
                                "id": "9977aa0f-d44b-5590-9ccb-3123d0083df5",
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
>| dc203d96-2c07-55f4-9312-5427468a8190 | test-incident-i1 | February 02, 2023 10:07 AM | False | 0 | February 02, 2023 10:07 AM | None | 0 | 0 | 0 | 0 | UNKNOWN | resolved | unknown | None | None |
>| e8d7e756-fc4b-5ae3-978b-dc6c081b0c38 | test-incident-i1 | February 03, 2023 06:36 AM | False | 0 | February 03, 2023 06:36 AM | None | 0 | 0 | 0 | 0 | UNKNOWN | active | unknown | None | None |


### datadog-time-series-point-query

***
Query of sequence of data points that are collected over time intervals, allowing us to track changes over time.

#### Base Command

`datadog-time-series-point-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | Start of the queried time period.<br/>Format : YYYY-MM-dd’T’HH:mm:ssZ Or '-1days'. | Required | 
| to | End of the queried time period.<br/>Format : yyyy-MM-dd’T’HH:mm:ssZ Or '-1days'. | Required | 
| query | Query string.<br/>Ex : query="system.cpu.idle" <br/>A complete list of query string values are available here: https://app.datadoghq.com/metric/summary. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.TimeSeriesPoint.from_date | Date | Start of requested time window in milliseconds since Unix epoch. | 
| Datadog.TimeSeriesPoint.error | String | Message indicating the errors if status is not OK. | 
| Datadog.TimeSeriesPoint.group_by | Unknown | List of tag keys on which to group. | 
| Datadog.TimeSeriesPoint.message | String | Message indicating success if status is OK. | 
| Datadog.TimeSeriesPoint.query | String | Query string. | 
| Datadog.TimeSeriesPoint.res_type | String | Type of response. | 
| Datadog.TimeSeriesPoint.series.aggr | Unknown | Aggregation type. | 
| Datadog.TimeSeriesPoint.series.display_name | String | Display name of the metric. | 
| Datadog.TimeSeriesPoint.series.end | Date | End of the time window in milliseconds since Unix epoch. | 
| Datadog.TimeSeriesPoint.series.expression | String | Metric expression. | 
| Datadog.TimeSeriesPoint.series.interval | Number | Number of seconds between data samples. | 
| Datadog.TimeSeriesPoint.series.length | Number | Number of data samples. | 
| Datadog.TimeSeriesPoint.series.metric | String | Metric name. | 
| Datadog.TimeSeriesPoint.series.pointlist | Number | List of points of the time series. | 
| Datadog.TimeSeriesPoint.series.query_index | Number | The index of the series query within the request. | 
| Datadog.TimeSeriesPoint.series.scope | String | Metric scope, comma-separated list of tags. | 
| Datadog.TimeSeriesPoint.series.start | Date | Start of the time window in milliseconds since Unix epoch. | 
| Datadog.TimeSeriesPoint.series.tag_set | Unknown | Unique tags identifying this series. | 
| Datadog.TimeSeriesPoint.series.unit.family | String | Unit family allows for conversion between units of the same family, for scaling. | 
| Datadog.TimeSeriesPoint.series.unit.name | String | Unit name. | 
| Datadog.TimeSeriesPoint.series.unit.plural | String | Plural form of the unit's name. | 
| Datadog.TimeSeriesPoint.series.unit.scale_factor | Number | Factor for scaling between units of the same family. | 
| Datadog.TimeSeriesPoint.series.unit.short_name | String | Abbreviation of the unit. | 
| Datadog.TimeSeriesPoint.status | String | Status of the query. | 
| Datadog.TimeSeriesPoint.to_date | Date | End of requested time window in milliseconds since Unix epoch. | 

#### Command example
```!datadog-time-series-point-query from="-2days" query="system.cpu.idle" to=now```
#### Context Example
```json
{
    "Datadog": {
        "TimeSeriesPoint": {
            "from_date": 1682842763000,
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
                    "end": 1683015599000,
                    "expression": "system.cpu.idle{*}",
                    "interval": 600,
                    "length": 288,
                    "metric": "system.cpu.idle",
                    "pointlist": [
                        [
                            1682842800000,
                            97.68919160970269
                        ],
                        [
                            1682843400000,
                            97.55890285173439
                        ],
                        [
                            1682844000000,
                            96.49665198601438
                        ],
                        [
                            1682844600000,
                            97.60656468956665
                        ],
                        [
                            1682845200000,
                            96.46683787164527
                        ],
                        [
                            1682845800000,
                            97.31057102926411
                        ],
                        [
                            1682846400000,
                            97.42793296109512
                        ],
                        [
                            1682847000000,
                            96.68693763315584
                        ],
                        [
                            1682847600000,
                            97.3771188138178
                        ],
                        [
                            1682848200000,
                            96.72998751249345
                        ],
                        [
                            1682848800000,
                            97.62954125786733
                        ],
                        [
                            1682849400000,
                            77.14230663729796
                        ],
                        [
                            1682850000000,
                            88.26801909872933
                        ],
                        [
                            1682850600000,
                            86.02685150500194
                        ],
                        [
                            1682851200000,
                            84.00416064890126
                        ],
                        [
                            1682851800000,
                            89.77305977137284
                        ],
                        [
                            1682852400000,
                            88.86388291794412
                        ],
                        [
                            1682853000000,
                            90.1959230668219
                        ],
                        [
                            1682853600000,
                            90.03270970659261
                        ],
                        [
                            1682854200000,
                            87.91900109680276
                        ],
                        [
                            1682854800000,
                            97.23605304252636
                        ],
                        [
                            1682855400000,
                            96.60989713791317
                        ],
                        [
                            1682856000000,
                            97.50563599324373
                        ],
                        [
                            1682856600000,
                            97.32647399147586
                        ],
                        [
                            1682857200000,
                            96.61270144540423
                        ],
                        [
                            1682857800000,
                            97.52764314718497
                        ],
                        [
                            1682858400000,
                            96.2354357811757
                        ],
                        [
                            1682859000000,
                            97.41964291458275
                        ],
                        [
                            1682859600000,
                            97.61164500383322
                        ],
                        [
                            1682860200000,
                            96.46508399622611
                        ],
                        [
                            1682860800000,
                            97.58440080220365
                        ],
                        [
                            1682861400000,
                            96.84386123641282
                        ],
                        [
                            1682862000000,
                            97.04455454916223
                        ],
                        [
                            1682862600000,
                            97.60976408344193
                        ],
                        [
                            1682863200000,
                            96.56558696406229
                        ],
                        [
                            1682863800000,
                            97.31680955647474
                        ],
                        [
                            1682864400000,
                            97.04899471049758
                        ],
                        [
                            1682865000000,
                            97.2700389650987
                        ],
                        [
                            1682865600000,
                            97.3597508572846
                        ],
                        [
                            1682866200000,
                            74.85728918945622
                        ],
                        [
                            1682866800000,
                            90.84739153963339
                        ],
                        [
                            1682867400000,
                            87.93083580607792
                        ],
                        [
                            1682868000000,
                            88.28429692694718
                        ],
                        [
                            1682868600000,
                            91.19499023071066
                        ],
                        [
                            1682869200000,
                            84.32294896148393
                        ],
                        [
                            1682869800000,
                            80.09028188998793
                        ],
                        [
                            1682870400000,
                            80.50370281917974
                        ],
                        [
                            1682871000000,
                            87.69754886349604
                        ],
                        [
                            1682871600000,
                            86.16375720510432
                        ],
                        [
                            1682872200000,
                            91.97728729289375
                        ],
                        [
                            1682872800000,
                            92.93239023033911
                        ],
                        [
                            1682873400000,
                            88.45125172015098
                        ],
                        [
                            1682874000000,
                            83.56762948547365
                        ],
                        [
                            1682874600000,
                            81.18553522649025
                        ],
                        [
                            1682875200000,
                            87.33947717054426
                        ],
                        [
                            1682875800000,
                            96.70690645370289
                        ],
                        [
                            1682876400000,
                            97.24881095590827
                        ],
                        [
                            1682877000000,
                            86.19395251613199
                        ],
                        [
                            1682877600000,
                            79.33825550564715
                        ],
                        [
                            1682878200000,
                            97.35916762596933
                        ],
                        [
                            1682878800000,
                            83.60114168565777
                        ],
                        [
                            1682879400000,
                            86.40088256128556
                        ],
                        [
                            1682880000000,
                            88.86342829757884
                        ],
                        [
                            1682880600000,
                            83.673347114479
                        ],
                        [
                            1682881200000,
                            90.64582331071828
                        ],
                        [
                            1682881800000,
                            96.40032924637842
                        ],
                        [
                            1682882400000,
                            97.57672850158652
                        ],
                        [
                            1682883000000,
                            97.16299767045095
                        ],
                        [
                            1682883600000,
                            96.41473289838689
                        ],
                        [
                            1682884200000,
                            97.60346442485695
                        ],
                        [
                            1682884800000,
                            96.72430523042364
                        ],
                        [
                            1682885400000,
                            97.24908345950675
                        ],
                        [
                            1682886000000,
                            97.66362570510984
                        ],
                        [
                            1682886600000,
                            96.6379408243517
                        ],
                        [
                            1682887200000,
                            97.34621920283732
                        ],
                        [
                            1682887800000,
                            96.72955622660783
                        ],
                        [
                            1682888400000,
                            97.5670509529114
                        ],
                        [
                            1682889000000,
                            97.4096741664448
                        ],
                        [
                            1682889600000,
                            96.6416677517087
                        ],
                        [
                            1682890200000,
                            97.47505966555818
                        ],
                        [
                            1682890800000,
                            97.36514047143945
                        ],
                        [
                            1682891400000,
                            96.71634323122396
                        ],
                        [
                            1682892000000,
                            97.59423901167419
                        ],
                        [
                            1682892600000,
                            96.495519905703
                        ],
                        [
                            1682893200000,
                            97.61490350788276
                        ],
                        [
                            1682893800000,
                            96.75056445957436
                        ],
                        [
                            1682894400000,
                            97.12463809931985
                        ],
                        [
                            1682895000000,
                            97.397298553389
                        ],
                        [
                            1682895600000,
                            96.67973777732777
                        ],
                        [
                            1682896200000,
                            97.38628721031546
                        ],
                        [
                            1682896800000,
                            97.58569868700977
                        ],
                        [
                            1682897400000,
                            96.67829637369323
                        ],
                        [
                            1682898000000,
                            97.37146245322631
                        ],
                        [
                            1682898600000,
                            96.63573982430894
                        ],
                        [
                            1682899200000,
                            97.32622037572727
                        ],
                        [
                            1682899800000,
                            97.18948150453217
                        ],
                        [
                            1682900400000,
                            96.70889504963978
                        ],
                        [
                            1682901000000,
                            92.83240206071135
                        ],
                        [
                            1682901600000,
                            96.24090572524229
                        ],
                        [
                            1682902200000,
                            94.89762202796074
                        ],
                        [
                            1682902800000,
                            97.48724619410453
                        ],
                        [
                            1682903400000,
                            96.42331397251345
                        ],
                        [
                            1682904000000,
                            96.96379562512394
                        ],
                        [
                            1682904600000,
                            96.72004364333131
                        ],
                        [
                            1682905200000,
                            97.32866471738978
                        ],
                        [
                            1682905800000,
                            96.8663528907526
                        ],
                        [
                            1682906400000,
                            97.26132890324051
                        ],
                        [
                            1682907000000,
                            97.17071466264382
                        ],
                        [
                            1682907600000,
                            96.69149861250813
                        ],
                        [
                            1682908200000,
                            97.53057257808432
                        ],
                        [
                            1682908800000,
                            96.42738606990447
                        ],
                        [
                            1682909400000,
                            97.57847922735282
                        ],
                        [
                            1682910000000,
                            97.49585786937361
                        ],
                        [
                            1682910600000,
                            96.47683124490452
                        ],
                        [
                            1682911200000,
                            97.59319190301542
                        ],
                        [
                            1682911800000,
                            96.61164854483346
                        ],
                        [
                            1682912400000,
                            97.34307140104379
                        ],
                        [
                            1682913000000,
                            97.42360130846467
                        ],
                        [
                            1682913600000,
                            96.70482087315251
                        ],
                        [
                            1682914200000,
                            82.68463290327405
                        ],
                        [
                            1682914800000,
                            87.22091003690943
                        ],
                        [
                            1682915400000,
                            91.30389579813557
                        ],
                        [
                            1682916000000,
                            86.17321286523531
                        ],
                        [
                            1682916600000,
                            89.57817695683572
                        ],
                        [
                            1682917200000,
                            89.51745690092866
                        ],
                        [
                            1682917800000,
                            86.05651056681317
                        ],
                        [
                            1682918400000,
                            94.54685459966245
                        ],
                        [
                            1682919000000,
                            97.53635940551757
                        ],
                        [
                            1682919600000,
                            85.40497551060149
                        ],
                        [
                            1682920200000,
                            87.47233686447143
                        ],
                        [
                            1682920800000,
                            91.81801414489746
                        ],
                        [
                            1682921400000,
                            91.6728684425354
                        ],
                        [
                            1682922000000,
                            93.37926044464112
                        ],
                        [
                            1682922600000,
                            92.06111488342285
                        ],
                        [
                            1682923200000,
                            91.74471473693848
                        ],
                        [
                            1682923800000,
                            92.38498139381409
                        ],
                        [
                            1682924400000,
                            90.96255555152894
                        ],
                        [
                            1682925000000,
                            92.58001050949096
                        ],
                        [
                            1682925600000,
                            89.59682540893554
                        ],
                        [
                            1682926200000,
                            93.66164741516113
                        ],
                        [
                            1682926800000,
                            92.37742338180541
                        ],
                        [
                            1682927400000,
                            92.87542362213135
                        ],
                        [
                            1682928000000,
                            92.59752836227418
                        ],
                        [
                            1682928600000,
                            92.34011125564575
                        ],
                        [
                            1682929200000,
                            93.25030155181885
                        ],
                        [
                            1682929800000,
                            91.01534223556519
                        ],
                        [
                            1682930400000,
                            92.34260077476502
                        ],
                        [
                            1682931000000,
                            92.45317645072937
                        ],
                        [
                            1682931600000,
                            93.11917352676392
                        ],
                        [
                            1682932200000,
                            91.90303659439087
                        ],
                        [
                            1682932800000,
                            92.51879920959473
                        ],
                        [
                            1682933400000,
                            91.80618476867676
                        ],
                        [
                            1682934000000,
                            91.66250858306884
                        ],
                        [
                            1682934600000,
                            94.40911598205567
                        ],
                        [
                            1682935200000,
                            92.56935110092164
                        ],
                        [
                            1682935800000,
                            90.23668350892909
                        ],
                        [
                            1682936400000,
                            91.40067520141602
                        ],
                        [
                            1682937000000,
                            90.99129023551941
                        ],
                        [
                            1682937600000,
                            92.08251762390137
                        ],
                        [
                            1682938200000,
                            91.45994124412536
                        ],
                        [
                            1682938800000,
                            91.8886640548706
                        ],
                        [
                            1682939400000,
                            92.15395317077636
                        ],
                        [
                            1682940000000,
                            94.51186275482178
                        ],
                        [
                            1682940600000,
                            93.49708862304688
                        ],
                        [
                            1682941200000,
                            91.9177869796753
                        ],
                        [
                            1682941800000,
                            93.26048307418823
                        ],
                        [
                            1682942400000,
                            93.83549823760987
                        ],
                        [
                            1682943000000,
                            90.84619603157043
                        ],
                        [
                            1682943600000,
                            90.57391901016236
                        ],
                        [
                            1682944200000,
                            94.10509014129639
                        ],
                        [
                            1682944800000,
                            93.45607872009278
                        ],
                        [
                            1682945400000,
                            94.485795211792
                        ],
                        [
                            1682946000000,
                            95.17550961933439
                        ],
                        [
                            1682946600000,
                            96.30417423248291
                        ],
                        [
                            1682947200000,
                            93.72561276969263
                        ],
                        [
                            1682947800000,
                            93.791539478302
                        ],
                        [
                            1682948400000,
                            96.51701316833496
                        ],
                        [
                            1682949000000,
                            97.59251976013184
                        ],
                        [
                            1682949600000,
                            96.65057926177978
                        ],
                        [
                            1682950200000,
                            96.39872074127197
                        ],
                        [
                            1682950800000,
                            96.95123195648193
                        ],
                        [
                            1682951400000,
                            97.09582843780518
                        ],
                        [
                            1682952000000,
                            97.32118377685546
                        ],
                        [
                            1682952600000,
                            96.7192850112915
                        ],
                        [
                            1682953200000,
                            97.31954612731934
                        ],
                        [
                            1682953800000,
                            96.46082082608851
                        ],
                        [
                            1682954400000,
                            97.6137767791748
                        ],
                        [
                            1682955000000,
                            97.57977352142333
                        ],
                        [
                            1682955600000,
                            96.39733371734619
                        ],
                        [
                            1682956200000,
                            97.57958984375
                        ],
                        [
                            1682956800000,
                            93.40429412234913
                        ],
                        [
                            1682957400000,
                            97.41219553133337
                        ],
                        [
                            1682958000000,
                            97.64250965118408
                        ],
                        [
                            1682958600000,
                            96.56701278686523
                        ],
                        [
                            1682959200000,
                            97.31135902404785
                        ],
                        [
                            1682959800000,
                            96.62135620117188
                        ],
                        [
                            1682960400000,
                            95.69584540433662
                        ],
                        [
                            1682961000000,
                            96.4551498413086
                        ],
                        [
                            1682961600000,
                            82.83752933394958
                        ],
                        [
                            1682962200000,
                            80.77699341773987
                        ],
                        [
                            1682962800000,
                            84.43782148361205
                        ],
                        [
                            1682963400000,
                            86.75046839714051
                        ],
                        [
                            1682964000000,
                            84.8414074420929
                        ],
                        [
                            1682964600000,
                            90.83040225121283
                        ],
                        [
                            1682965200000,
                            97.61848545074463
                        ],
                        [
                            1682965800000,
                            96.59116592407227
                        ],
                        [
                            1682966400000,
                            97.12413749694824
                        ],
                        [
                            1682967000000,
                            97.01634254455567
                        ],
                        [
                            1682967600000,
                            97.1782657623291
                        ],
                        [
                            1682968200000,
                            97.338010597229
                        ],
                        [
                            1682968800000,
                            96.597536277771
                        ],
                        [
                            1682969400000,
                            97.62985134124756
                        ],
                        [
                            1682970000000,
                            96.78451328277588
                        ],
                        [
                            1682970600000,
                            97.32024822235107
                        ],
                        [
                            1682971200000,
                            97.56389789581299
                        ],
                        [
                            1682971800000,
                            91.67191410064697
                        ],
                        [
                            1682972400000,
                            97.67930965423584
                        ],
                        [
                            1682973000000,
                            96.90955696105956
                        ],
                        [
                            1682973600000,
                            97.1065580368042
                        ],
                        [
                            1682974200000,
                            97.56303386688232
                        ],
                        [
                            1682974800000,
                            96.67407855987548
                        ],
                        [
                            1682975400000,
                            97.4095703125
                        ],
                        [
                            1682976000000,
                            97.36583309173584
                        ],
                        [
                            1682976600000,
                            96.91839199066162
                        ],
                        [
                            1682977200000,
                            97.19643096923828
                        ],
                        [
                            1682977800000,
                            96.59364604949951
                        ],
                        [
                            1682978400000,
                            97.53491477966308
                        ],
                        [
                            1682979000000,
                            96.49621620178223
                        ],
                        [
                            1682979600000,
                            97.61087799072266
                        ],
                        [
                            1682980200000,
                            96.48229598999023
                        ],
                        [
                            1682980800000,
                            97.37382354736329
                        ],
                        [
                            1682981400000,
                            97.45425434112549
                        ],
                        [
                            1682982000000,
                            96.52091464996337
                        ],
                        [
                            1682982600000,
                            96.37306346893311
                        ],
                        [
                            1682983200000,
                            97.65558986663818
                        ],
                        [
                            1682983800000,
                            97.01161842346191
                        ],
                        [
                            1682984400000,
                            97.04633121490478
                        ],
                        [
                            1682985000000,
                            97.67448387145996
                        ],
                        [
                            1682985600000,
                            96.4870777130127
                        ],
                        [
                            1682986200000,
                            97.12660694122314
                        ],
                        [
                            1682986800000,
                            96.86757278442383
                        ],
                        [
                            1682987400000,
                            92.47167110443115
                        ],
                        [
                            1682988000000,
                            97.05547466278077
                        ],
                        [
                            1682988600000,
                            96.58370475769043
                        ],
                        [
                            1682989200000,
                            97.50096378326415
                        ],
                        [
                            1682989800000,
                            95.54611043930053
                        ],
                        [
                            1682990400000,
                            97.36933155059815
                        ],
                        [
                            1682991000000,
                            97.55457153320313
                        ],
                        [
                            1682991600000,
                            96.33489990234375
                        ],
                        [
                            1682992200000,
                            97.5664665222168
                        ],
                        [
                            1682992800000,
                            96.6094539642334
                        ],
                        [
                            1682993400000,
                            97.32307376861573
                        ],
                        [
                            1682994000000,
                            96.65733642578125
                        ],
                        [
                            1682994600000,
                            97.44806709289551
                        ],
                        [
                            1682995200000,
                            97.2319408416748
                        ],
                        [
                            1682995800000,
                            96.68061962127686
                        ],
                        [
                            1682996400000,
                            97.46142768859863
                        ],
                        [
                            1682997000000,
                            96.45687561035156
                        ],
                        [
                            1682997600000,
                            97.64165458679199
                        ],
                        [
                            1682998200000,
                            97.52013568878174
                        ],
                        [
                            1682998800000,
                            96.44671306610107
                        ],
                        [
                            1682999400000,
                            97.50459079742431
                        ],
                        [
                            1683000000000,
                            97.5139726638794
                        ],
                        [
                            1683000600000,
                            74.73514027222676
                        ],
                        [
                            1683001200000,
                            71.76150830565021
                        ],
                        [
                            1683001800000,
                            76.02476398944854
                        ],
                        [
                            1683002400000,
                            79.73913691246855
                        ],
                        [
                            1683003000000,
                            86.59184470176697
                        ],
                        [
                            1683003600000,
                            91.48028373718262
                        ],
                        [
                            1683004200000,
                            83.21679837703705
                        ],
                        [
                            1683004800000,
                            91.41991556803386
                        ],
                        [
                            1683005400000,
                            92.95062686920166
                        ],
                        [
                            1683006000000,
                            96.5307487487793
                        ],
                        [
                            1683006600000,
                            97.23182048797608
                        ],
                        [
                            1683007200000,
                            97.30785942077637
                        ],
                        [
                            1683007800000,
                            96.76249485015869
                        ],
                        [
                            1683008400000,
                            97.25039939880371
                        ],
                        [
                            1683009000000,
                            96.61633625030518
                        ],
                        [
                            1683009600000,
                            96.93941535949708
                        ],
                        [
                            1683010200000,
                            82.3803980543333
                        ],
                        [
                            1683010800000,
                            93.65725679397583
                        ],
                        [
                            1683011400000,
                            93.97111072540284
                        ],
                        [
                            1683012000000,
                            95.11310119628907
                        ],
                        [
                            1683012600000,
                            97.4148162841797
                        ],
                        [
                            1683013200000,
                            86.47753492154573
                        ],
                        [
                            1683013800000,
                            93.15384928385417
                        ],
                        [
                            1683014400000,
                            97.54811916351318
                        ],
                        [
                            1683015000000,
                            96.65062589903135
                        ]
                    ],
                    "query_index": 0,
                    "scope": "*",
                    "start": 1682842800000,
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
            "to_date": 1683015563000,
            "values": []
        }
    },
    "InfoFile": {
        "EntryID": "453@5be6c436-9d99-4c0d-8a75-9a876a0ced7b",
        "Extension": "json",
        "Info": "application/json",
        "Name": "timeseries_query_points.json",
        "Size": 19584,
        "Type": "CSV text"
    }
}
```

#### Human Readable Output

>### Query Timeseries Points 
