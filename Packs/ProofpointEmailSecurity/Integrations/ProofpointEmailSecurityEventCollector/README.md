Collects events for Proofpoint using the streaming API.
This integration was integrated and tested Proofpoint Email Security.

## Configure Proofpoint Email Security Event Collector in Cortex

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Proofpoint Email Security Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server Host | True |
    | Cluster ID | True |
    | API key | True |
    | Fetch Events | False |
    | Fetch interval in seconds | True |
    | Use system proxy settings | False |
    | Event types to fetch | False |

4. Select **Long running instance**.
5. Click **Test** to validate the URLs, token, and connection.

## Commands

### proofpoint-es-get-last-run-results

***
Retrieves the results of a connection attempt to Proofpoint, indicating whether it was successful or failed and why. If event fetching has been initiated, this command provides the results of the most recent fetch attempt.

### proofpoint-es-get-events

***
Retrieves events from the Proofpoint Email Security PoD archive for a specified time range to backfill gaps in fetched events. This command is intended for development and debugging purposes and is to be used with caution after consulting with engineering, as it may create duplicate events, exceed API request rate limits, and disrupt the fetch events mechanism. Review the list of [known limitations](#known-limitations) below for additional details.

#### Base Command

`proofpoint-es-get-events`

#### Input

| **Argument** | **Description** | **Required** |
| --- | --- | --- |
| since_time | The start of the time range to fetch events from. E.g., '3 days ago', '2025-01-01T10:00:00'. Rounds down to the nearest hour. | Required |
| to_time | The end of the time range to fetch events from. E.g., '2 days ago', '2025-01-01T11:00:00'. Rounds up to the nearest hour. | Required |
| timezone_offset | The UTC timezone offset in hours to apply to the since_time and to_time arguments. E.g. -5 for UTC-5. | Optional |
| event_types | A comma-separated list of event types to fetch. If not provided, all types will be retrieved. | Optional |
| limit | The maximum number of events to fetch per specified event type. | Optional |
| should_push_events | If true, the command will push the events to the Cortex XSIAM dataset; otherwise, it will only display them. | Optional |

#### Context Output

There is no context output for this command.

## Known Limitations

1. The API does not allow use of the same API Key for more than one session at the same time. To open more multiple simultaneous websocket connections to receive the same event type, additional API Key(s) must be generated via the Proofpoint PoD dashboard.
2. When running `proofpoint-es-get-events` command,  HTTP 409 (Conflict) errors may be raised if the integration instance has "Fetch Events" enabled. Ensure the "Fetch Events" checkbox is unchecked before triggering this command.
3. When running `proofpoint-es-get-events` command,  the HTTP 400 (Bad Request) errors may be raised if the time range is older than 30 days. Ensure both the `since_time` and `to_time` arguments fall within the last 30 days.

## Troubleshooting

In case of data ingestion delays or missing events, it is recommended to configure a separate integration instance per event type.
