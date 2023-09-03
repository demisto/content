Use the Workday Sign On Event Collector integration to get sign on logs from Workday.
This integration was integrated and tested with version xx of Workday Sign On Event Collector

## Configure Workday Sign On Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Workday Sign On Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://WORKDAY-HOST/ccx/api/v1/TENANT-NAME) | API Endpoint of Workday server. Can be obtained from View API Clients report in Workday application. | True |
    | Username |  | True |
    | Password |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Max events per fetch | The maximum number of sign on events to retrieve. Large amount of events can cause performance issues. | False |
    | Events Fetch Interval |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### workday-get-sign-on-events

***
Returns Sign On events extracted from Workday. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to events duplication and exceeding the API request limitation.

#### Base Command

`workday-get-sign-on-events`

#### Input

| **Argument Name**  | **Description**                                                                                                                                                                                                             | **Required** |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False.                                                                      | Required     | 
| limit              | The maximum number of events to return. Possible values are: . Default is 1000.                                                                                                                                             | Optional     | 
| from_date          | The date and time of the earliest event. The default timezone is UTC/GMT. The time format is "{yyyy}-{mm}-{dd}T{hh}:{mm}:{ss}Z". Example: "2021-05-18T13:45:14Z" indicates May 18, 2021, 1:45PM UTC. Possible values are: . | Required     | 
| to_date            | The time format is "{yyyy}-{mm}-{dd}T{hh}:{mm}:{ss}Z". Example: "2021-05-18T13:45:14Z" indicates May 18, 2021, 1:45PM UTC. Possible values are: .                                                                           | Required     | 

#### Context Output

There is no context output for this command.
