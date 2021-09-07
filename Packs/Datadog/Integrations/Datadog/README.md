Datadog is a monitoring service for cloud-scale applications, providing monitoring of servers, databases, tools, and services, through a SaaS-based data analytics platform.
This integration was integrated and tested with version xx of Datadog

## Configure Datadog on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Datadog.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://api.datadoghq.eu) |  | True |
    | API Key |  | True |
    | Application Key |  | False |
    | Event Priority | Priority of events to pull | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch incidents |  | False |
    | Incidents Fetch Interval |  | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### dd-get-events
***
The event stream can be queried and filtered by time, priority, sources and tags.


#### Base Command

`dd-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | POSIX timestamp. | Required | 
| end | POSIX timestamp. | Required | 
| priority | Priority of your events, either low or normal. Possible values are: low, normal. | Optional | 
| sources | A comma separated string of sources. | Optional | 
| tags | A comma separated list indicating what tags, if any, should be used to filter the list of monitors by scope. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### dd-get-event-id
***
This endpoint allows you to query for event details.


#### Base Command

`dd-get-event-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the event. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### dd-get-incidents
***
Get all incidents for the user’s organization


#### Base Command

`dd-get-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### dd-get-incident-id
***
Get the details of an incident by incident_id.


#### Base Command

`dd-get-incident-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The UUID the incident. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### dd-list-hosts
***
This endpoint allows searching for hosts by name, alias, or tag. Hosts live within the past 3 hours are included by default.


#### Base Command

`dd-list-hosts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | String to filter search results. | Optional | 
| count | Number of hosts to return. Max 1000. Default is 5. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### dd-mute-host
***
Mute a host.


#### Base Command

`dd-mute-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Name of the host to mute. | Required | 
| message | Message to associate with the muting of this host. | Required | 
| end | POSIX timestamp in seconds when the host is unmuted. If omitted, the host remains muted until explicitly unmuted. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### dd-unmute-host
***
Un-mute a host.


#### Base Command

`dd-unmute-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Name of the host to un-mute. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### dd-get-users
***
Get the list of all users in the organization. This list includes all users even if they are deactivated or unverified.


#### Base Command

`dd-get-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Filter all users by the given string. Defaults to no filtering. | Optional | 
| status | Filter on status attribute. Possible values are: Active, Pending, Disabled. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### dd-get-active-metrics-list
***
Get the list of actively reporting metrics from a given time until now.


#### Base Command

`dd-get-active-metrics-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | Seconds since the Unix epoch. | Required | 
| host | Hostname for filtering the list of metrics returned. If set, metrics retrieved are those with the corresponding hostname tag. | Optional | 
| tag_filter | Filter metrics that have been submitted with the given tags. Supports boolean and wildcard expressions. Cannot be combined with other filters. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### dd-submit-metics
***
The metrics end-point allows you to post time-series data that can be graphed on Datadog’s dashboards.


#### Base Command

`dd-submit-metics`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The name of the host that produced the metric. | Required | 
| interval | If the type of the metric is rate or count, define the corresponding interval. | Optional | 
| metric | The name of the timeseries. If the metric exist, it will be updated. else it will be created. | Required | 
| pointTimeStamp | Timestamps should be in POSIX time in seconds, and cannot be more than ten minutes in the future or more than one hour in the past. | Required | 
| pointValue | A scalar value (cannot be a string). | Optional | 
| type | The type of the metric either count or rate. Possible values are: count, rate. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


