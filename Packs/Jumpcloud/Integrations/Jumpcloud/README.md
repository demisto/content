## Jumpcloud

Fetches directory, system, alert, and object storage events from JumpCloud Directory Insights.

### Configuration

| Parameter | Description | Required |
|---|---|---|
| Server URL | The JumpCloud API server URL. | True |
| API Key | The API key for authenticating with the JumpCloud API. | True |
| Fetch event filter | Select which event types to fetch. Default: all. | False |
| The maximum number of events per fetch | Maximum number of events to fetch per type per fetch cycle. Default: 5000. | True |

### Commands

#### jumpcloud-get-events

Gets events from JumpCloud. This command is used for developing/debugging.

| Argument | Description | Required |
|---|---|---|
| event_type | The type of events to retrieve. | Optional |
| limit | The maximum number of events to return per type. Default: 50. | Optional |
| start_time | Filter events created at or after this time. | Optional |
| end_time | Filter events created at or before this time. | Optional |
| should_push_events | If true, the command creates events in XSIAM. Default: false. | Optional |
