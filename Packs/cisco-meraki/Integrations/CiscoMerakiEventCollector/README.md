Collects configuration changes, network events, API requests and appliance security events from Cisco Meraki into Cortex XSIAM.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Cisco Meraki Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL | The API base URL: https://api.meraki.com (global), https://api.meraki.ca, https://api.meraki.cn, https://api.meraki.in or https://api.gov-meraki.com. OAuth 2.0 is supported only for https://api.meraki.com. | True |
| API Key | Required when OAuth 2.0 is not configured. | False |
| Client ID / Client Secret | OAuth 2.0 credentials. When set, OAuth 2.0 is used instead of the API key. | False |
| Redirect URI | The redirect URI registered on the Meraki OAuth 2.0 integration. Required for OAuth 2.0. | False |
| Authorization code | The `code` received after running `cisco-meraki-generate-login-url`. Required for OAuth 2.0. | False |
| Organization ID | The ID of the Meraki organization to collect events from. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch events |  | False |
| Event types to fetch | Configuration changes, Network events, API requests, Appliance security events. Default is all. | False |
| Network IDs | Networks to collect network events from. Default is all the networks of the organization. | False |
| Maximum number of events per fetch, per event type | Default is 10000. | False |

Events are sent to the `cisco_meraki_raw` dataset. Every event carries a `_source_log_type` field with the event type: `configuration_changes`, `network_events`, `api_requests` or `appliance_security_events`.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cisco-meraki-get-events

***
Get events from Cisco Meraki. This command is intended for development and debugging purposes and should be used with caution, as it may create duplicate events.

#### Base Command

`cisco-meraki-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_types | Comma-separated event types to get. Default is all event types. Possible values are: Configuration changes, Network events, API requests, Appliance security events. | Optional |
| limit | The maximum number of events to return per event type. Default is 10. | Optional |
| start_time | The start time to get events from (organization-level event types). Default is 1 hour ago. | Optional |
| should_push_events | Whether to push the events to Cortex XSIAM. Possible values are: true, false. Default is false. | Required |

#### Context Output

There is no context output for this command.

### cisco-meraki-generate-login-url

***
Generate the login URL used to authorize the integration with OAuth 2.0.

#### Base Command

`cisco-meraki-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### cisco-meraki-auth-test

***
Test the OAuth 2.0 authorization and the connection to Cisco Meraki.

#### Base Command

`cisco-meraki-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### cisco-meraki-auth-reset

***
Reset the OAuth 2.0 authorization. Run cisco-meraki-generate-login-url to authorize again.

#### Base Command

`cisco-meraki-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
