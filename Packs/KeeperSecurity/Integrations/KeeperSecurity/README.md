Use this integration to fetch audit events from the Keeper Security Admin REST API as XSIAM events.
This integration uses the `GET /api/rest/public/events` endpoint (ARAM Events) and authenticates with an Admin REST API key.

## Configure Keeper Security Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The server URL of your Keeper region. For more help, checkout the 'Server Regions' section in the description. | True |
| API Key | A Keeper Admin REST API key with the SIEM:1 (read) scope. | True |
| First fetch time | How far back to fetch events on the first run, for example "1 hour" or "3 days". | False |
| Maximum number of Alerts to fetch. | The maximum number of events to fetch per run. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### keeper-security-get-events

***
Gets audit events from Keeper Security. This command is used for development and debugging and might create duplicate events when should_push_events is true.

#### Base Command

`keeper-security-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of events to return. Default is 50. | Optional |
| start_date | Start of the time range, for example "1 hour" or "2024-01-01T00:00:00Z". Defaults to 1 hour ago. | Optional |
| end_date | End of the time range. Defaults to now. | Optional |
| should_push_events | Set to true to create events from the retrieved results, otherwise they are only displayed. Possible values are: true, false. Default is false. | Optional |

#### Context Output

There is no context output for this command.

## Notes

- The API does not return an event ID, so events are de-duplicated by a hash of their fields.
- The API is limited to 10 requests per 10 seconds per API key; the integration paces its requests accordingly.
