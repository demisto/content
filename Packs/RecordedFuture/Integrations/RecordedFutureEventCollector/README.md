This integration fetches alerts from Recorded Future.
This integration was integrated and tested with version 2 of the Recorded Future API.

## Configure Recorded Future Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for Recorded Future Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API token | The API token to use for the connection. | True |
    | Trust any certificate (not secure) | Use SSL secure connection or not. | False |
    | Use system proxy settings | Use proxy settings for connection or not. | False |
    | First fetch time |  First fetch query `<number> <time unit>`, e.g., `7 days`. Default `3 days`. | False |
    | Max fetch | The maximum number of events per fetch. Default and maximum is 1000. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### recorded-future-get-events

***
Gets events from Recorded Future.

#### Base Command

`recorded-future-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum results to return. Default is 10. | Optional | 

#### Context Output

There is no context output for this command.