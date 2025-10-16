Use this integration to fetch BitSight security findings as events in Cortex XSIAM. This is important for organizations that wish to integrate BitSight programmatically into their security operations.

When configured as a fetching integration, it will continuously fetch new findings starting from the current day. The manual `bitsight-get-events` command fetches findings from the last 2 days (48 hours).

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure BitSight Event Collector in Cortex

| Parameter | Description | Required | Default Value |
| --- | --- | --- | --- |
| Server URL | REST API Endpoint of BitSight server. | True | https://api.bitsighttech.com |
| API Key | BitSight API token. | True | - |
| Company's GUID | Optional. If provided, findings for this company and its subsidiaries will be collected. If omitted, the collector attempts to use `myCompany.guid`. | False | - |
| Trust any certificate (not secure) |  | False | - |
| Use system proxy settings |  | False | - |
| Max events per fetch | Maximum number of findings to fetch at a time. | False | 1000 |
| Events Fetch Interval | Interval between fetch operations. | False | 5 |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### bitsight-get-events

***
Gets findings as events from BitSight Event Collector. The command fetches findings from the last 2 days (48 hours).

#### Base Command

`bitsight-get-events`

#### Input

| Argument Name | Description | Required | Default Value |
| --- | --- | --- | --- |
| limit | The number of events to return. | Optional | 5 |
| guid | Override the Company GUID for this command only. | Optional | - |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. | Required | false |

#### Context Output

There is no context output for this command.

## Notes

**API Date Format Limitation:** The BitSight API returns `first_seen` timestamps in date-only format (YYYY-MM-DD) without hours or minutes. The integration converts these to full timestamps in the `_time` field for XSIAM compatibility. This means all events will show timestamps like `2025-08-30T00:00:00` (midnight UTC) regardless of when during that day the finding was actually discovered.
