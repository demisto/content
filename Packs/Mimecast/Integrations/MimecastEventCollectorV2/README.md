This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM. This integration was developed and tested using Mimecast API 2.0.

## Configure Mimecast Event Collector v2 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL | Use the https://api.services.mimecast.com/ Base URL for the Global region. See the the [Mimecast guide on API Gateway Options](https://developer.services.mimecast.com/api-overview#api-gateway-options) to find the relevant Base URL for other regions. | True |
| Client ID | Refer to the help section for instructions on how to obtain the API 2.0 OAuth2 client credentials. | True |
| Client secret | Refer to the help section for instructions on how to obtain the API 2.0 OAuth2 client credentials. | True |
| Fetch events | | False |
| Fetch event types | Possible values are: Audit, SIEM. | False |
| First fetch timestamp (Audit Events only) | Should be in the &lt;number&gt; &lt;time unit&gt; format (for example, 12 hours, 7 days, 3 months, 1 year). This parameter is only relevant to Audit events. The first fetch timestamp of SIEM logs is internally set to the last minute due to API-side restrictions. | False |
| Maximum number of events per fetch | Default is 1000. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Permissions

Ensure the following permissions when generating OAuth2 credentials for integrating with Mimecast API 2.0:

* To fetch Audit events, ensure the role assigned to the application is granted the **Account | Logs | Read** permission.
* To fetch SIEM logs, the logged-in user must be a Mimecast Administrator with the **Security Events and Data Retrieval | Threat and Security Events (SIEM) | Read** permission or higher.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### mimecast-get-events

***
Retrieves Mimecast Audit events and SIEM logs. Use this command for development and debugging only, as it may produce duplicate events, exceed API rate limits, or disrupt the fetch mechanism.

#### Base Command

`mimecast-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If True, pushes the events to the Cortex XSIAM dataset. If False, only displays them. Default is False. | Required |
| event_types | The event types to retrieve. Possible values are: Audit, SIEM. | Optional |
| limit | The maximum number of events to retrieve per event type. Default is 10. | Optional |
| start_date | The start date for retrieving events, expressed as relative time (for example, '3 hours ago') or an absolute time in the ISO 8601 format (for example, '2025-12-01T00:00:00Z'). Must be within the last 24 hours if retrieving SIEM logs. Default is 1 hour ago. | Optional |
| end_date | The end date for retrieving events, expressed as relative time (for example, '2 hours ago') or an absolute time in the ISO 8601 format (for example, '2025-12-02T00:00:00Z'). Must be within the last 24 hours if retrieving SIEM logs. Default is now. | Optional |

#### Context Output

There is no context output for this command.

## Limitations

Due to the data retention period of the Mimecast SIEM CG events endpoint, SIEM logs are only available for fetching within a 24-hour rolling window.

* If the integration instance is disabled or the _**Fetch events**_ checkbox is unchecked for a period of more than 24 hours, the event collector will automatically adjust the SIEM collection start time to the most recent available data (within the last 24 hours) upon resumption. This prevents collection failures but may result in a gap in SIEM log coverage during the downtime period.

* When retrieving SIEM logs using the _**mimecast-get-events**_ command, ensure both the `start_date` and `end_date` arguments are within the last 24 hours in the UTC timezone. Values outside this time window will return an error.
