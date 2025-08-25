Use this integration to fetch BitSight security findings as events in Cortex XSIAM. This is important for organizations that wish to integrate BitSight programmatically into their security operations.

When configured as a fetching integration, it will continuously fetch new findings from the current time forward. The manual `bitsight-get-events` command fetches findings from the last 1 day (24 hours).

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure BitSight Event Collector in Cortex

| Parameter | Description | Required | Default Value |
| --- | --- | --- | --- |
| Server URL | REST API Endpoint of BitSight server. | True | https://api.bitsighttech.com |
| API Key | BitSight API token (Basic Auth, token as username, blank password). | True | - |
| Company's GUID | Optional. If provided, findings for this company and its subsidiaries will be collected. If omitted, the collector attempts to use `myCompany.guid`. | False | - |
| Trust any certificate (not secure) |  | False | - |
| Use system proxy settings |  | False | - |
| Max events per fetch | Maximum number of findings to fetch at a time. | False | 1000 |
| Events Fetch Interval | Interval between fetch operations. | False | 1 |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### bitsight-get-events

***
Gets findings as events from BitSight Event Collector. The command fetches findings from the last 1 day (24 hours).

#### Base Command

`bitsight-get-events`

#### Input

| Argument Name | Description | Required | Default Value |
| --- | --- | --- | --- |
| limit | The number of events to return. | Optional | 100 |
| guid | Override the Company GUID for this command only. | Optional | - |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. | Required | false |

#### Context Output

There is no context output for this command.