This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM. This integration was developed and tested using Mimecast API 2.0.

## Configure Mimecast Event Collector in Cortex

**Note**: Following [the announcement about Mimecast API 1.0 End of Life](https://mimecastsupport.zendesk.com/hc/en-us/articles/39704312201235-API-Integrations-API-1-0-End-of-Life-Mar-2025), the legacy authentication model (using Application ID, Application Key, Access Key, and Secret Key) is no longer supported by this integration. This has been replaced by the new client credentials flow in Mimecast API 2.0.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL | Use `https://api.services.mimecast.com` for the Global region or review the [Mimecast guide on per-region Base URLs](https://integrations.mimecast.com/documentation/api-overview/global-base-urls/) to find the suitable Base URL. | True |
| Client ID | Refer to the help section for instructions on how to obtain API 2.0 OAuth2 credentials. | True |
| Client secret | Refer to the help section for instructions on how to obtain API 2.0 OAuth2 credentials. | True |
| Fetch events | | False |
| Fetch event types | Possible values are: audit, av, delivery, internal email protect, impersonation protect, journal, process, receipt, attachment protect, spam, url protect. | False |
| Maximum number of events per fetch | Default is 1000. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### mimecast-get-events

***
Retrieve Mimecast audit and SIEM events. This command is intended for development and debugging purposes, as it may produce duplicate events, exceed API request rate limits, and disrupt the fetch events mechanism.

#### Base Command

`mimecast-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If True, the command will push the events to the Cortex XSIAM dataset; otherwise, it will only display them. Default is False. | Required |
| event_types | Event types to retrieve. Possible values are: audit, av, delivery, internal email protect, impersonation protect, journal, process, receipt, attachment protect, spam, url protect. | Optional |
| limit | Maximum number of events to retrieve per event type. Default is 10. | Optional |
| start_date | The start date for retrieving events as a relative time expression (e.g., '3 hours ago') or an absolute time in ISO 8601 format (e.g., '2025-12-01T00:00:00Z'). Must be within the last 24 hours if retrieving SIEM events. Default is 1 hour ago. | Optional |
| end_date | The end date for retrieving events as a relative time expression (e.g., '2 hours ago') or an absolute time in ISO 8601 format (e.g., '2025-12-02T00:00:00Z'). Must be within the last 24 hours if retrieving SIEM events. Default is now. | Optional |

#### Context Output

There is no context output for this command.

## Limitations

Due to the data retention period of the Mimecast SIEM CG events endpoint, SIEM events are only available for fetching within a 24-hour rolling window. This limitation applies to all SIEM event types (av, delivery, internal email protect, impersonation protect, journal, process, receipt, attachment protect, spam, url protect) but does _not_ apply to audit events.

* When retrieving SIEM events using the ***mimecast-get-events*** command, ensure both the `start_date` and `end_date` arguments are within the last 24 hours in the UTC timezone. Values outside this time window will return an error for SIEM event types.

* If the integration instance is disabled or the ***Fetch events*** checkbox is unchecked for a period of more than 24 hours, the event collector will automatically adjust the SIEM collection start time to the most recent available data (within the last 24 hours) upon resumption. This prevents collection failures but may result in a gap in SIEM event coverage during the downtime period.
