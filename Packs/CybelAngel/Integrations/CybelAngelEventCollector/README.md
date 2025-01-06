CybelAngel Event Collector receives reports from the CybelAngel platform, which specializes in external attack surface protection and management

## Configure CybelAngel Event Collector in XSIAM


| **Parameter**                                                     | **Required** |
|-------------------------------------------------------------------|--------------|
| Server URL                                                        | True         |
| Client ID                                                         | True         |
| Client Secret                                                     | True         |
| First fetch timestamp (number, time unit, e.g., 12 hours, 7 days) | False        |
| The maximum number of events per fetch                            | True         |
| Trust any certificate (not secure)                                | False        |
| Use system proxy settings                                         | False        |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cybelangel-get-events

***
Send events from CybelAngel to XSIAM. Used mainly for debugging.

#### Base Command

`cybelangel-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Get reports from a specific start date. | Required | 
| end_date | Get reports until a specific end date. If not provided, uses current date. | Required | 

#### Context Output

There is no context output for this command.