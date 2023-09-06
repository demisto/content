Palo Alto Networks FireEye HX Event Collector integration for XSIAM.

## Configure FireEye HX Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**.
2. Search for FireEye HX Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://192.168.0.1:3000) |  | True |
    | User Name |  | True |
    | Password |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | The maximum number of events per fetch. | The maximum number of events to fetch every time fetch is executed. | False |
    | First Fetch Time | The First Fetch Time, e.g., 1 hour, 3 days | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fireeye-hx-get-events

***
Manual command to fetch events and display them.

#### Base Command

`fireeye-hx-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events to get. | Optional | 
| since | Occurrence time of the least recent event to include (inclusive). Default is 3 days. | Optional | 
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 

#### Context Output

There is no context output for this command.