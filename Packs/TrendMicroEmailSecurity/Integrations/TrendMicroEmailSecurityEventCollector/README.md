Palo Alto Networks Trend Micro Email Security Event Collector integration for XSIAM.
This integration was integrated and tested with version xx of Trend Micro Email Security Event Collector

## Configure Trend Micro Email Security Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Trend Micro Email Security Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Service URL |  | True |
    | USER NAME |  | True |
    | API Key |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | The maximum number of events per fetch. | The maximum number of events to fetch every time fetch is executed. | False |
    | First Fetch Time | "The first fetch time, e.g., 1 hour, 3 days,<br/>Note: The request retrieves logs created within 72 hours at most before sending the request,<br/>Please put in the First Fetch Time parameter a value that is at most 72 hours / 3 days"<br/> | False |

4. Click **Test** to validate the URLs, token, and connection.

**Note**: There are three types of fetches that the integration fetches, when the max fetch parameter is set to 1000 then 1000 logs will be retrieved from each type so that a total of 3000 logs can be retrieved.
## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### trend-micro-get-events

***
Manual command to fetch events and display them.

#### Base Command

`trend-micro-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events to get. Default is 500. | Optional | 
| since | Occurrence time of the least recent event to include (inclusive). Default is 3 days. | Optional | 
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 

#### Context Output

There is no context output for this command.
