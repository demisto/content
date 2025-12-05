Use this integration to fetch email security incidents from Ironscales as XSIAM events.

## Configure Ironscales Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://appapi.ironscales.com) |  | True |
| API Key |  | True |
| Company ID |  | True |
| Scopes (e.g., "company.all") |  | True |
| Maximum number of events per fetch |  | False |
| First fetch |  | False |
| Collect all events | Fetch all events instead of only open events. | False |
| Fetch Mailbox | Fetch the affected mailbox mitigation details as part of the event data. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Scopes

partner.all
company.all
partner.company.view
company.view

## Collect All Events

Checking this box will fetch all events, not just open ones.
Note: Currently, ATO and MTS event types are not supported.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ironscales-get-events

***
Gets events from Ironscales. This command is intended for development and debugging purposes and is to be used with caution as it may create duplicate events, exceed API request rate limits, and disrupt the fetch events mechanism.

#### Base Command

`ironscales-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of events to return. Default is 10. | Optional |
| since_time | The start time by which to filter events. Date format will be the same as in the first_fetch parameter. Default is 3 days. | Optional |
| mailbox_enrichment | Set this argument to True in order to include the affected mailboxes mitigation details in the event data. Possible values are: true, false. Default is false. | Optional |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required |

#### Context Output

There is no context output for this command.
