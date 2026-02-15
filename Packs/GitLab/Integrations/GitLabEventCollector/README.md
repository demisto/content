An event collector for Gitlab audit events using Gitlab's API.

[Audit events API documentation](https://docs.gitlab.com/ee/api/audit_events.html)

## Prerequisites

To retrieve audit events using the API, you must authenticate yourself as an Administrator.

You must use [Personal access tokens](https://docs.gitlab.com/user/profile/personal_access_tokens.html):

### Create a personal access token:

1. In the upper-right corner, select your avatar.
2. Select **Edit profile**.
3. On the left sidebar, select **Personal access tokens**.
4. Select **Add new token**.
5. In **Token name**, enter a name for the token.
6. Optional. In **Token description**, enter a description for the token.
7. In **Expiration date**, enter an expiration date for the token.
   - The token expires on that date at midnight UTC. A token with the expiration date of 2024-01-01 expires at 00:00:00 UTC on 2024-01-01.
   - If you do not enter an expiry date, the expiry date is automatically set to 365 days later than the current date.
   - By default, this date can be a maximum of 365 days later than the current date. In GitLab 17.6 or later, you can extend this limit to 400 days.
8. Select the desired scopes (see [PAT scopes](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html)).
9. Select **Create personal access token**.

## Configure Gitlab Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Key | The personal access token created above with administrator authorization. | True |
| Fetch Instance Audit Events | When checked, the fetch mechanism will fetch events from the audit_events endpoint. That endpoint requires administrator authorization. See [Audit Events API documentation](https://docs.gitlab.com/api/audit_events/) for more details. |  |
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
