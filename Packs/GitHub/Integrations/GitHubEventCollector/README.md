Github logs event collector integration for XSIAM.
This integration was integrated and tested with Github REST API V3

## Configure Github Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Github Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. 'https://api.github.com/orgs/XXXXX/audit-log') | True |
    | HTTP Method | True |
    | Headers | True |
    | API Key | True |
    | Use system proxy settings | False |
    | Use Secured Connection | False |
    | How many logs to fetch | False |
    | XSIAM update limit per request | False |
    | First fetch time interval | False |
    | Event types to include | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fetch-events
***
Command that is activated by the engine to fetch event.


#### Base Command

`fetch-events`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### github-get-events
***
Manual command to fetch events and display them.


#### Base Command

`github-get-events`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.