Datadog is an observability service for cloud-scale applications, providing monitoring of servers, databases, tools, and services, through a SaaS-based data analytics platform.

The SaaS platform integrates and automates infrastructure monitoring, application performance monitoring and log management to provide unified, real-time observability of our customers' entire technology stack.
This integration was integrated and tested with version xx of DatadogCloudSIEM

## Configure Datadog Cloud SIEM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Datadog Cloud SIEM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | Datadog webiste URL | True |
    | API Key | The API Key to use for authentication | True |
    | Application Key | The application key to use for authentication. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

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
| priority | The priority of the event. Possible values are: normal, low. | Optional | 
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
### datadog-active-metric-list

***
Get the list of actively reporting metrics.

#### Base Command

`datadog-active-metric-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | List of actively reporting metrics from a given time until now.<br/>Format :  yyyy-MM-dd’T’HH:mm:ssZ Or '-1days' . | Required | 
| host_name | Hostname for filtering the list of metrics. | Optional | 
| tag_filter | Filter metrics that have been submitted with the given tags. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user, then the limit argument will be ignored. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Datadog.Metric.from | String | Time when the metrics were active, seconds since the Unix epoch. | 
| Datadog.Metric | Unknown | List of metric names. | 

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
| Datadog.Metric | Unknown | List of metrics that match the search query. | 

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
| Datadog.Metric.description | String | Metric description. | 
| Datadog.Metric.integration | String | Name of the integration that sent the metric if applicable. | 
| Datadog.Metric.per_unit | String | Per unit of the metric such as second in bytes per second. | 
| Datadog.Metric.short_name | String | A more human-readable and abbreviated version of the metric name. | 
| Datadog.Metric.statsd_interval | Number | StatsD flush interval of the metric in seconds if applicable. | 
| Datadog.Metric.type | String | Metric type | 
| Datadog.Metric.unit | String | Primary unit of the metric | 

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
| Datadog.Metric.description | String | Metric description. | 
| Datadog.Metric.per_unit | String | Per unit of the metric such as second in bytes per second. | 
| Datadog.Metric.short_name | String | A more human-readable and abbreviated version of the metric name. | 
| Datadog.Metric.statsd_interval | Number | StatsD flush interval of the metric in seconds if applicable. | 
| Datadog.Metric.type | String | Metric type | 
| Datadog.Metric.unit | String | Primary unit of the metric | 
