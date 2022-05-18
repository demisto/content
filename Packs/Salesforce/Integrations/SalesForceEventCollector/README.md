Salesforce logs event collector integration for XSIAM.
This integration was integrated and tested with Salesforce REST API V54.0

## Configure Salesforce Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Salesforce Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Client ID |  | True |
    | Client Secret |  | True |
    | Username |  | True |
    | Password |  | True |
    | Query to get Hourly Event Log Files | For more Information visit the Query Hourly Event Log Files documentation https://developer.salesforce.com/docs/atlas.en-us.234.0.api_rest.meta/api_rest/event_log_file_hourly_query.htm | True |
    | How many log files to fetch. |  | True |
    | XSIAM update limit per request |  | False |
    | First fetch time interval |  | False |
    | The product corresponding to the integration that originated the events. |  | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### salesforce-get-events
***
Manual command to fetch events.


#### Base Command

`salesforce-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| files_limit | How many log files to fetch. Default is 1. | Optional | 


#### Context Output

There is no context output for this command.