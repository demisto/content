Twilio SendGrid is a cloud-based email delivery platform that provides email activity tracking and analytics. Use this integration to collect email activity events such as deliveries, opens, clicks, bounces, and spam reports.
**Note:** You must purchase [additional email activity history](https://app.sendgrid.com/settings/billing/addons/email_activity) to access the Email Activity Feed API.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Twilio SendGrid in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The SendGrid API base URL. Default: api.sendgrid.com | True |
| API Secret Key | Your SendGrid API key with Email Activity read permissions. | True |
| Maximum Email Activity Messages per fetch | Maximum number of events to fetch per fetch run. The API is limited to 1000 events per call, so multiple calls will be made if needed. Default is 10000. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### twilio-sendgrid-get-events

***
Returns email activity events from Twilio SendGrid. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to event duplication and exceeding the API request limitation.

#### Base Command

`twilio-sendgrid-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required |
| limit | Maximum number of events to retrieve. The API is limited to 1000 events per call. Default is 1000. | Optional |
| from_date | Start time for event retrieval. Supports relative times (e.g., "3 days") or ISO format (e.g., "2024-01-15T00:00:00Z"). | Optional |
| to_date | End time for event retrieval. Supports relative times or ISO format. | Optional |

#### Context Output

There is no context output for this command.
