Collects DDoS detection critical events and general events from Akamai Prolexic Analytics for Cortex XSIAM.
This integration was integrated and tested with version `v2` of the Akamai Prolexic Analytics API.

## Configure Akamai Prolexic in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Akamai API host \(the value of the "host" field in your .edgerc file\). Example: https://akab-h05tnam3wl42son7nktnlnnx-kbob3i3v.luna.akamaiapis.net | True |
| Contract ID | The policy domain name of the data center or proxy that the events belong to. | True |
| Client Token | The EdgeGrid client token, taken from the "client_token" field of your .edgerc file. | True |
| Client Secret | The EdgeGrid client secret, taken from the "client_secret" field of your .edgerc file. | True |
| Access Token | The EdgeGrid access token, taken from the "access_token" field of your .edgerc file. | True |
| Account Switch Key | The account switch key used to run operations against a managed account, for customers managing more than one account. The Identity and Access Management API provides a list of available account switch keys. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch events |  | False |
| Event types to fetch | The Akamai Prolexic event sources to collect. Each selected source is fetched and deduplicated independently. | True |
| First fetch time | The point in time from which to start fetching events on the first run. Examples: "1 day", "12 hours". | False |
| Maximum events per fetch | The maximum number of events to fetch per source, per fetch. Maximum allowed: 10000. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### akamai-prolexic-get-events

***
Gets events from Akamai Prolexic. This command is used for developing and debugging and is to be used with caution, as it can create duplicate events in the dataset.

#### Base Command

`akamai-prolexic-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events to retrieve per source. Default is 50. | Optional | 
| event_type | A comma-separated list of event types to retrieve. If empty, uses the integration configuration. Possible values are: Critical Events, Events. | Optional | 
| start_time | The lower-bound timestamp for events to retrieve. Supports ISO 8601 (e.g., "2026-04-20T10:00:00Z") or relative time expressions (e.g., "3 days ago"). If omitted, the integration's "First fetch time" value is used. | Optional | 
| end_time | The upper-bound timestamp for events to retrieve. Supports ISO 8601 (e.g., "2026-04-20T18:00:00Z") or relative time expressions (e.g., "1 hour ago"). If omitted, no upper bound is applied. | Optional | 
| should_push_events | Whether to push the retrieved events to Cortex XSIAM. If false, the events are only displayed. Possible values are: true, false. Default is false. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!akamai-prolexic-get-events limit=2 event_type="Critical Events" should_push_events=false```

#### Context Example

```json
{}
```

#### Human Readable Output

>### Akamai Prolexic Events
>
>|_time|event_type|source_log_type|_ENTRY_STATUS|id|firstOccur|recentOccur|severity|description|
>|---|---|---|---|---|---|---|---|---|
>| 2026-04-20T10:00:00.000000Z | Critical Events | CRITICAL_EVENTS | new | ce-1 | 2026-04-20T10:00:00Z | 2026-04-20T10:00:00Z | high | DDoS detected on policy A |
>| 2026-04-20T11:30:00.000000Z | Critical Events | CRITICAL_EVENTS | updated | ce-2 | 2026-04-20T11:30:00Z | 2026-04-20T12:00:00Z | critical | Volumetric attack on policy B |
