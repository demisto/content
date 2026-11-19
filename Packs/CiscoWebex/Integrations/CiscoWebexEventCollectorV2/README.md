Collects Webex admin audit, security audit and compliance officer events using a single OAuth 2.0 integration app authorized from the Cisco Webex connector.

## Configure Cisco Webex Event Collector v2 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| URL |  | True |
| Organization ID | The Webex organization ID. Required for admin audit and security audit events. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Event types to fetch | Security Audit Events require an active Webex Pro Pack license. | True |
| Maximum number of events per fetch | Maximum number of events per event type per fetch. Maximum is 2000. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cisco-webex-v2-get-admin-audit-events

***
Gets admin audit events from Cisco Webex.

#### Base Command

`cisco-webex-v2-get-admin-audit-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required |
| limit | Maximum number of events to return. | Optional |
| since_datetime | Date in ISO format (2023-10-01T20:33:22.123Z) to return events from. | Optional |

#### Context Output

There is no context output for this command.

### cisco-webex-v2-get-security-audit-events

***
Gets security audit events from Cisco Webex. Requires an active Webex Pro Pack license.

#### Base Command

`cisco-webex-v2-get-security-audit-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required |
| limit | Maximum number of events to return. | Optional |
| since_datetime | Date in ISO format (2023-10-01T20:33:22.123Z) to return events from. | Optional |

#### Context Output

There is no context output for this command.

### cisco-webex-v2-get-compliance-officer-events

***
Gets compliance officer events from Cisco Webex.

#### Base Command

`cisco-webex-v2-get-compliance-officer-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required |
| limit | Maximum number of events to return. | Optional |
| since_datetime | Date in ISO format (2023-10-01T20:33:22.123Z) to return events from. | Optional |

#### Context Output

There is no context output for this command.

## Changes from Cisco Webex Event Collector

This integration replaces **Cisco Webex Event Collector** (CiscoWebexEventCollector) for the Cisco Webex connector. Both can run in parallel during migration.

### Authentication

* A single Webex OAuth 2.0 integration app replaces the separate Admin and Compliance Officer apps. The connector runs the authorization and refreshes the token.
* The *cisco-webex-oauth-start*, *cisco-webex-oauth-complete* and *cisco-webex-oauth-test* commands were removed. Use **Authorize** / **Re-authorize** on the connector instead.

### Parameters

* *Fetch security audit events* was replaced by the *Event types to fetch* multi-select.
* The Admin and Compliance Officer client ID, secret and redirect URI parameters were removed.

### Commands

* *cisco-webex-get-admin-audit-events* was replaced by *cisco-webex-v2-get-admin-audit-events*.
* *cisco-webex-get-security-audit-events* was replaced by *cisco-webex-v2-get-security-audit-events*.
* *cisco-webex-get-compliance-officer-events* was replaced by *cisco-webex-v2-get-compliance-officer-events*.

## Additional Considerations for this version

* Events are stored in the `cisco_webex_v2_raw` dataset (previously `cisco_webex_raw`).
* A failure in one event type no longer stops the other event types from being fetched.
* Test connection checks each selected event type and reports missing scopes or a missing Pro Pack license per event type.
