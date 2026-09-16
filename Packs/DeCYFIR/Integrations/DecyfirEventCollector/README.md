Collects event logs from DeCYFIR for ingestion into Cortex XSIAM.

Once configured, the integration periodically fetches event logs from DeCYFIR’s APIs and sends them to **Cortex XSIAM** for ingestion and analysis.

- Events are fetched in real time (starting from the moment the integration is enabled).  
- Each event type (`Access Logs`, `Assets Logs`, `Digital Risk Keywords Logs`) is fetched separately using its own pagination and limit.  
- The integration automatically tracks and stores the last fetched timestamp and event IDs to prevent duplication.

## Configure DeCYFIR Event Collector in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API Key | True |
| Event types to fetch | True |
| Maximum number of Access Logs events per fetch | False |
| Maximum number of Assets Logs events per fetch | False |
| Maximum number of Digital Risk Keywords Logs events per fetch | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### decyfir-get-events

***
Retrieve Decyfir events manually. This command is used for developing/ debugging and is to be used with caution, as it can create events, leading to events duplication and exceeding the API request limitation.

#### Base Command

`decyfir-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_types | Comma-separated list of event types to fetch. Possible values are: Access Logs, Assets Logs, Digital Risk Keywords Logs. Default is Access Logs,Assets Logs,Digital Risk Keywords Logs. | Required |
| should_push_events | Set this argument to True to send the fetched events to Cortex XSIAM.  If False, the command will only display them in the War Room.<br/>. Possible values are: True, False. Default is False. | Required |
| from_date | Fetch events created after the specified time (e.g., "12 hours", "7 days").  If not provided, defaults to "3 months".<br/>. Default is 3 months. | Optional |

#### Context Output

There is no context output for this command.
