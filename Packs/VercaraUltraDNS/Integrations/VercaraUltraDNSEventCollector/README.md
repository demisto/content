This integration fetches DNS configuration audit logs from Vercara UltraDNS platform.
This integration was integrated and tested with the 3.18.0 Vercara UltraDNS API.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Vercara UltraDNS Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The base URL for the Vercara UltraDNS API. Default is https://api.ultradns.com | True |
| Username | Username for authentication | True |
| Password | Password for authentication | True |
| Trust any certificate (not secure) | Use SSL secure connection or not. | False |
| Use system proxy settings | Use proxy settings for connection or not. | False |
| Fetch events | Whether to bring events or not. | False |
| The maximum number of audit logs per fetch | Maximum number of events to fetch per cycle. Default is 2,500, maximum is 2,500. | False |

## Vercara UltraDNS Event Collector Authentication

The integration uses OAuth 2.0 password grant flow for authentication:

1. **Initial Token Request**: Uses username/password to obtain access token and refresh token
2. **Token Usage**: Access token is used in Authorization header for API requests
3. **Token Refresh**: Automatically refreshes tokens when they expire, with fallback to username/password if refresh fails

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### vercara-ultradns-get-events

***
Gets DNS configuration audit events from Vercara UltraDNS.

#### Base Command

`vercara-ultradns-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required |
| limit | Maximum number of events to return. Default is 50, maximum is 2,500. | Optional |
| start_time | Start time for event collection (e.g., "2023-01-01T00:00:00"). | Required |
| end_time | End time for event collection (e.g., "2023-01-01T23:59:59"). Default is now if not provided. | Optional |


#### Context Output

There is no context output for this command.