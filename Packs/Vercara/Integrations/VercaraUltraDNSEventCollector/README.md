Collects Vercara UltraDNS events (e.g., audit logs) into Cortex XSIAM.

This integration is modeled after the standard XSIAM Event Collector pattern. It supports previewing events via a manual command and scheduled ingestion via Fetch Events.

## Configure Vercara UltraDNS Event Collector in Cortex

| Parameter | Description | Required |
| --- | --- | --- |
| Your server URL | Base URL of the UltraDNS API endpoint. | True |
| API Token | API token used for authentication. | True |
| First fetch time | Initial time range to fetch from on first run (e.g., `3 days`, `1 hour`). | False |
| Fetch Limit | Maximum number of events to fetch per request (subject to UltraDNS API limits). | False |
| Trust any certificate (not secure) | Whether to trust self-signed/invalid certificates. | False |
| Use system proxy settings | Whether to use the system proxy settings. | False |
| Events/Audit endpoint path | Optional relative path for the events/audit API (e.g., `/v2/report/auditlogs`). | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

### vercara-ultradns-get-events

Fetches events from Vercara UltraDNS and optionally pushes them to XSIAM.

#### Base Command

`vercara-ultradns-get-events`

#### Input

| Argument | Description | Required |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: `true`, `false`. | Required |

#### Context Output

There is no context output for this command.

## Fetch Events

When the integration instance is configured to Fetch Events, the `fetch-events` command is executed periodically. The integration maintains an internal cursor to avoid duplicates and will add a `_time` field to each event for XSIAM ingestion.

## Troubleshooting

- Ensure the API token has sufficient permissions to read the desired event/audit endpoints.
- Verify the `Events/Audit endpoint path` matches your UltraDNS environment (for example: `/v2/report/auditlogs`).
- Check proxy and certificate settings if connectivity fails.
