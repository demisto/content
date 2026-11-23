Collect ChatGPT Compliance logs from a ChatGPT workspace. This integration is configured automatically as part of the OpenAI Standard Connector. Do not configure it directly - set it up from the connector page instead.
This integration was integrated and tested with version xx of OpenAIWorkspaceStandardConnector.

## Configure ChatGPT Workspace (Standard Connector) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Organization ID | The OpenAI Organization ID \(org-...\). Sent as the OpenAI-Organization header on API Platform requests. | False |
| ChatGPT Server URL | The base URL for the ChatGPT Platform Compliance APIs. | False |
| Compliance API Key | The Compliance API key for the ChatGPT Platform. Required when fetching Compliance event types. | False |
| Workspace ID | The Compliance workspace UUID \(for example, 4a4676f3-3d74-4723-b696-c93e6d01078a\). Required when fetching Compliance event types. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Events types to fetch | The ChatGPT Compliance event types to fetch. | False |
| Maximum number of Compliance events per fetch | The maximum number of Compliance events to return per fetch. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### openai-workspace-get-events

***
Manually retrieves ChatGPT Compliance log events from OpenAI. Use this command for development and debugging only, as it may produce duplicate events, exceed API rate limits, or disrupt the fetch mechanism.

#### Base Command

`openai-workspace-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_type | A comma-separated list of event types to retrieve. If not specified, uses the value configured in the integration parameters. Possible values are: Conversation Messages, Apps, Apps Auth, Compliance Audit, Auth, Codex, ChatGPT, Codex Security, Workspace Agents. | Optional | 
| limit | The maximum number of events to return per stream. Default is 50. | Optional | 
| start_time | The lookback start time for the fetch. Supports ISO 8601 or relative time (for example, "3 days ago", "2099-01-01T00:00:00Z"). | Optional | 
| should_push_events | Whether retrieved events are also ingested by Cortex. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenAI.Event.id | String | The unique identifier of the event. | 
| OpenAI.Event._event_type | String | The upstream event_type for Compliance events. Left empty for Audit events. | 
| OpenAI.Event.source_log_type | String | The source log type used by downstream parsing rules. | 
| OpenAI.Event._time | Date | The event timestamp in ISO 8601 format. | 
