Salesforce logs event collector integration for XSIAM.
This integration was integrated and tested with Salesforce REST API V54.0

## Configure Salesforce Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Salesforce Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | HTTP Method | True |
    | Client ID | True |
    | Client secret | True |
    | Username | True |
    | Password | True |
    | Query to get Hourly Event Log Files | True |
    | Use system proxy settings | False |
    | Use Secured Connection | False |
    | How many log files to fetch | False |
    | First fetch time interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### salesforce-get-events
***
Manual command to fetch events and display them.


#### Base Command

`salesforce-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | How many log files to fetch. Default is 1. | Optional | 


#### Context Output

There is no context output for this command.