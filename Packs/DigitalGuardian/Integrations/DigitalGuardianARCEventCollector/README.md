This is the Digital Guardian ARC event collector integration for XSIAM.
This integration was integrated and tested with version 3.10.0 of DigitalGuardianARCEventCollector

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Known Limitations

A maximum of 10,000 events can be retrieved per fetch for each Digital Guardian export profile. To optimize throughput, it is recommended to distribute alerts and events across multiple export profiles and configure the export profile in the Digital Guardian ARC platform to include only relevant alarm and event types.

## Configure Digital Guardian ARC Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Auth Server URL (e.g. https://some_url.com) |  | True |
| Gateway Base URL (e.g. https://some_url.com) |  | True |
| Client ID |  | True |
| Client Secret | Client Secret | True |
| Export Profiles | Internal document names or GUIDs of the Digital Guardian ARC export profiles. Default is defaultExportProfile. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### digital-guardian-get-events

***
Gets events from the configured Digital Guardian ARC export profile.

#### Base Command

`digital-guardian-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum results to return per export profile. Default is 1000. | Optional | 

#### Context Output

There is no context output for this command.