AdminByRequest is a Privileged Access Management (PAM) solution that enables secure, temporary elevation to local admin rights.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Admin By Request in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Key | The API Key allows you to interact with the AdminByRequest API service. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch events |  | False |
| Event types to fetch | Which records the integration should fetch from the AdminByRequest API. Available for Auditlogs, Events, and Requests. | True |
| Maximum number of Auditlog per fetch | Maximum number of audit log entries to retrieve per fetch cycle. Applies only if the "Auditlog" event type is enabled for fetching. | False |
| Maximum number of Events per fetch | Maximum number of event entries to retrieve per fetch cycle. Applies only if the "Events" event type is enabled for fetching. | False |
| Maximum number of Requests per fetch | Maximum number of request entries to retrieve per fetch cycle. Applies only if the "Requests" event type is enabled for fetching. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### adminbyrequest-get-events

***
Retrieves a list of entries logs events from the AdminByRequest instance.

#### Base Command

`adminbyrequest-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to 'true' in order to create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required |
| event_type | The type of event to fetch. Default is Auditlog. | Optional |
| limit | Returns no more than the specified number of events (for entries of type 'Requests' the default value is 5000). | Optional |
| first_fetch | The UTC date or relative timestamp from when to start fetching incidents. Notice that for event type 'Requests' there is the option to set a start date. Supported formats: N days, N weeks, N months, N years, yyyy-mm-dd. | Optional |

#### Context Output

There is no context output for this command.

### API Limitations

- Please DO NOT consistently use a high "limit" number or flood the API. The account will be automatically throttled.
- Daily quota: 100,000 API calls (approximately 60 calls per minute maximum).

### adminbyrequest-list-requests

***
Lists requests from AdminByRequest.

#### Base Command

`adminbyrequest-list-requests`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The ID of a specific request to retrieve. | Optional |
| status | Filters requests by status. Possible values are: Pending, Open, Approved, Denied, Quarantined. | Optional |
| want_scan_details | Set to true to include scan details in the response. Possible values are: true, false. | Optional |
| limit | The maximum number of requests to return. Default is 50. | Optional |
| all_results | Set to true to fetch all available results, overriding the limit. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AdminByRequest.Request.id | Number | The ID of the request. |
| AdminByRequest.Request.type | String | The type of the request. |
| AdminByRequest.Request.settingsName | String | The name of the settings. |
| AdminByRequest.Request.application.name | String | The name of the application. |
| AdminByRequest.Request.application.scanResult | String | The scan result of the application. |
| AdminByRequest.Request.user | Unknown | The user associated with the request. |
| AdminByRequest.Request.computer.name | String | The name of the computer. |
| AdminByRequest.Request.status | String | The status of the request. |
| AdminByRequest.Request.reason | String | The reason for the request. |
| AdminByRequest.Request.approvedBy | String | The user who approved the request. |
| AdminByRequest.Request.approvedByEmail | String | The email of the user who approved the request. |
| AdminByRequest.Request.deniedReason | String | The reason for denying the request. |
| AdminByRequest.Request.deniedBy | String | The user who denied the request. |
| AdminByRequest.Request.deniedByEmail | String | The email of the user who denied the request. |
| AdminByRequest.Request.requestTime | Date | The time the request was made. |
| AdminByRequest.Request.startTime | Date | The start time of the request. |
| AdminByRequest.Request.eventText | String | The text of the request. |
| AdminByRequest.Request.eventTime | Date | The time the request occurred. |

### adminbyrequest-request-deny

***
Denies a request in AdminByRequest.

#### Base Command

`adminbyrequest-request-deny`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The ID of the request to deny. | Required |
| denied_by | The user who denied the request. | Optional |
| reason | The reason for denying the request. | Optional |

#### Context Output

There is no context output for this command.

### adminbyrequest-request-approve

***
Approves a request in AdminByRequest.

#### Base Command

`adminbyrequest-request-approve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The ID of the request to approve. | Required |
| approved_by | The user who approved the request. | Optional |

#### Context Output

There is no context output for this command.
