This integration collects event logs from Bitwarden Password Manager to Cortex XSIAM.
This integration was integrated and tested with version 2024.6.2 of Bitwarden Password Manager.

## Configure Bitwarden Password Manager in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g., https://example.bitwarden.com) | True |
| Client ID | True |
| Client Secret | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Maximum number of events per fetch | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### bitwarden-get-events

***
Gets events from Bitwarden.

#### Base Command

`bitwarden-get-events`

#### Input

| **Argument Name**  | **Description**                                                                                                                                               | **Required** |
|--------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| start              | The start date from which to filter events. (e.g., 2024-07-10T08:08:46.76)                                                                                                                   | Optional | 
| end                | The end date from which to filter events. (e.g., 2024-07-11T08:09:47.08)                                                                                                                   | Optional | 
| limit              | The number of events to return. Default is 500.                                                                                                                   | Optional | 
| should_push_events | Set this argument to True in order to save events to XSIAM, otherwise the command will only display them. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.