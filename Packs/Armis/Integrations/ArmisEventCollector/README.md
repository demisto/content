Collects alerts, devices and activities from Armis resources.
This integration was integrated and tested with API V.1.8 of Armis API.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Armis Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | URL of the Armis instance the event collector should connect to. | True |
| API Secret Key | The API Secret Key allows you to programmatically integrate with the Armis ecosystem. | True |
| Maximum number of events per fetch | Alerts and activity events. |  |
| Maximum number of device events per fetch | Devices events. |  |
| Trust any certificate (not secure) |  |  |
| Use system proxy settings |  |  |
| Event types to fetch |  | True |
| Events Fetch Interval | Alerts and activity events. | False |
| Minutes to delay | Number of minutes to delay when fetching events (to handle events creation delay in the Armis database). Default is 10 minutes but note a higher value might be needed for users with heavier traffic. | False |
| Device Fetch Interval | Time between fetch of devices \(for example 12 hours, 60 minutes, etc.\). | False |


## Commands

You can execute these commands from a Cortex XSIAM incident War Room ,as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### armis-get-events

***
Manual command to fetch and display events. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to events duplication and exceeding the API request limitation.

#### Base Command

`armis-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required | 
| from_date | The date from which to fetch events. The format should be YYYY-MM-DD or YYYY-MM-DDT:HH:MM:SS. If not specified, the current date will be used. | Optional | 
| event_type | The type of event to fetch. Possible values are: Alerts, Activities, Devices. Default is Alerts. | Optional | 
| aql | Run your own AQL query to fetch events. | Optional | 

#### Context Output

There is no context output for this command.