An event collector for Gitlab audit events and events using Gitlab's API.  

[Audit events API documentation](https://docs.gitlab.com/ee/api/audit_events.html)  
[Events API documentation](https://docs.gitlab.com/ee/api/events.html)
## Configure Gitlab Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
|-------|-----------|-------|
| Server Host   | Gitlab Git URL. | True     |
| API key  | The request API key provided by Gitlab.  | True   |
| Groups IDs  | A comma-separated list of group IDs to retrieve. To view your groups or to create a group, see [Manage Groups](https://docs.gitlab.com/ee/user/group/manage.html) in the Gitlab documentation. | False   |
| Projects IDs    | A comma-separated list of project IDs to get. To view your projects or to create a project, see [Manage Projects](https://docs.gitlab.com/ee/user/project/working_with_projects.html#manage-projects) in the Gitlab documentation. | True         |
| First fetch timestamp    | The period to retrieve events for.  In the format (\[number] \[time unit]). For example, 12 hours, 1 day, 3 months. | False |
| The maximum number of events to fetch for each event type | Each fetch will bring the `limit` number of events for each type (audits, groups and projects) and each group/project ID. For example, if `limit` is set to 500 and groups/projects IDs are given as well, then the fetch will bring 500 audit events and 500 group/project events for each group/project ID. | False |
| Trust any certificate (not secure) | Use SSL secure connection or ‘None’.  | False  |
| User system proxy settings  | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration.  | False  |

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