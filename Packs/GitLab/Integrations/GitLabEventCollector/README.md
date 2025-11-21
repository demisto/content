An event collector for Gitlab audit events using Gitlab's API.  

[Audit events API documentation](https://docs.gitlab.com/ee/api/audit_events.html)

## Configure Gitlab Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Key | The API Key to use for connection. | True |
| Fetch Instance Audit Events | When checked, the fetch mechanism will fetch events from the audit_events endpoint. That endpoint requires a higher level of authorization, see description for more details. |  |
| Groups IDs |  | False |
| Projects IDS |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, for example, 12 hours, 7 days, 3 months, 1 year) |  | True |
| The maximum number of events per fetch for each event type | Each fetch will bring the \`limit\` number of events for each type \(audits, groups and projects\) and each group/project ID. For example, if \`limit\` is set to 500 and groups/projects IDs are given as well, then the fetch will bring 500 audit events and 500 group/project events for each group/project ID. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute the following command from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

#### gitlab-get-events

***
Manual command to fetch events and display them.

#### Base Command

`gitlab-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Default is False. | True |

#### Context Output

There is no context output for this command.
