Collects configuration changes, network events, API requests and appliance security events from Cisco Meraki into Cortex XSIAM.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configuration

This integration is configured from the Cisco Meraki Standard Connector page. Authentication (OAuth 2.0 or API key) and the endpoint region are managed by the connector.

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
