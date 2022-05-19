Alibaba logs event collector integration for XSIAM.
This integration was integrated and tested with API version 0.6 of Alicloud Log Service.

## Configure Alibaba Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Alibaba Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Endpoint | True |
    | Access key id | True |
    | Access key | True |
    | Project name | True |
    | Logstore name | True |
    | Query | True |
    | Number of incidents to fetch per fetch. | False |
    | First fetch time interval | False |
    | The product corresponding to the integration that originated the events. | True |
    | XSIAM update limit per request | False |
    | Use system proxy settings | False |
    | Use Secured Connection | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### alibaba-get-events
***
Manual command to fetch events and display them.


#### Base Command

`alibaba-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | The date after which to search for logs in in Unix epoch Example: 1652617222. | Optional | 


#### Context Output

There is no context output for this command.