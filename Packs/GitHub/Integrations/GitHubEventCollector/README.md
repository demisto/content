Github logs event collector integration for XSIAM.
This integration was integrated and tested with Github REST API V3

## Configure Github Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Github Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. 'https://api.github.com/orgs/XXXXX/audit-log') |  | True |
    | API Key |  | True |
    | Number of incidents to fetch per fetch. |  | False |
    | First fetch time interval |  | False |
    | The event types to include. | web - returns web \(non-Git\) events, git - returns Git events, all - returns both web and Git events. | False |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### github-get-events
***
Manual command to fetch events and display them.


#### Base Command

`github-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in orfer to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 


#### Context Output

There is no context output for this command.