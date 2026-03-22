Use this integration to collect risk event data from FireCompass's Attack Surface Management (ASM) platform into Cortex.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex.

## Configure FireCompass in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The base URL of the FireCompass API. Default is `https://apis.firecompass.com`. | True |
| API Key | The API key for authenticating with the FireCompass API. | True |
| Fetch events | Whether to fetch events. | False |
| Maximum number of events per fetch | The maximum number of risk events to fetch per cycle. Maximum page size from the API is 100. Default is 1000. | False |
| Trust any certificate (not secure) | Use SSL secure connection or not. | False |
| Use system proxy settings | Use proxy settings for connection or not. | False |

## FireCompass Authentication

To use this integration, you need a FireCompass API key.

1. Log in to the FireCompass portal.
2. Navigate to **Settings** > **Account** to find or generate your API key.
3. Enter the API key in the **API Key** field in the integration configuration.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### firecompass-get-events

***
Fetches risk events from FireCompass. This manual command is used for developing or debugging and should be used with caution, as it can create events, leading to event duplication and exceeding API request limits.

#### Base Command

`firecompass-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command creates events; otherwise, it only displays them. Possible values are true and false. The default value is false. | Required |
| limit | Maximum number of results to return. Default is 50. | Optional |
| from_date | Start date from which to get events. Supports ISO format or natural language (e.g., "7 days ago", "1 hour ago"). Default is 3 days ago. | Optional |
| to_date | End date until which to get events. Supports ISO format or natural language (e.g., "now", "30 minutes ago"). Default is now. | Optional |

#### Context Output

There is no context output for this command.

