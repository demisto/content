IBM Security Guardium is a comprehensive data security platform that provides visibility and protection for sensitive data across databases, data warehouses, big data platforms, and cloud environments.

This integration enables the collection of security events from IBM Guardium Data Security Center.

## Configure IBM Security Guardium in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The URL of your IBM Guardium instance. The default value is an example - replace it with your specific instance URL. | True |
| API Key | The API Key for authentication | True |
| API Secret | The API Secret for authentication | True |
| Report ID | The ID of the report to fetch events from. | True |
| Fetch events | Whether to automatically fetch events. | False |
| Maximum number of events to fetch | Maximum number of events to fetch per run. Default is 10000. Recommended maximum is 10000. | False |
| Timestamp Field Name | The display name of the header in the report that contains the timestamp field, e.g., "Date created (local time)".<br> Note: This field name varies between different reports. | False (Required when Fetch events is enabled) |
| Trust any certificate (not secure) | Trust any certificate (not secure). | False |
| Use system proxy settings | Use system proxy settings. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ibm-guardium-get-events

***
Manual command to fetch and display events.

#### Base Command

`ibm-guardium-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command creates events; otherwise, it only displays them. Possible values are: true, false. Default is false. | Required |
| timestamp_field | The name of the field in the event data that contains the timestamp. <br>Note: This field name varies between different reports. If not provided, uses the value from integration configuration. | Optional (Required when should_push_events is true) |
| limit | Maximum number of results to return. Maximum allowed is 1000. Default is 50. | Optional |
| start_time | Start time for fetching events. Supports ISO format ("2023-01-01T00:00:00") or natural language ("7 days ago", "yesterday", "1 week ago"). Defaults to 1 hour ago if not provided. | Optional |
| end_time | End time for fetching events. Supports ISO format ("2023-01-01T23:59:59") or natural language ("2 hours ago", "now"). If not provided, defaults to now. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!ibm-guardium-get-events limit=50 start_time="2024-01-01T00:00:00" end_time="2024-01-01T23:59:59" should_push_events=true```

#### Human Readable Output

>### IBM Guardium Events
>
>| Client IP | Database User | Source Program | Server IP | Service Name | Database Name | Session Start Time |
>| --- | --- | --- | --- | --- | --- | --- |
>| 10.0.0.1 | admin | SQLClient | 10.0.0.100 | PROD_DB | customers | 2024-01-01 10:30:00 |
>| 10.0.0.2 | user1 | AppServer | 10.0.0.100 | PROD_DB | orders | 2024-01-01 10:31:15 |

## Additional Information

**Note:** The integration fetches events from the last 12 hours by default on first run. This accounts for IBM Guardium's event indexing delays and ensures events are captured even when indexed with significant delays.
