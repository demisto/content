Use this integration to fetch audit logs from Keeper Security Admin Console as XSIAM events.
This integration was integrated and tested with version 16.11.8 of Keeper Commander.

## Configure Keeper Secrets Manager Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The server URL. For more help, checkout the 'Server Regions' section in the description. | True |
| Username |  | True |
| Password |  | True |
| Maximum number of Alerts to fetch. | The maximum number of Alert events to fetch. |  |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### keeper-security-register-start

***
Use this command to start the registration process.

#### Base Command

`keeper-security-register-start`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Human Readable Output

>Code was sent successfully to the user's email

### keeper-security-register-complete

***
Use this command to complete the registration process.

#### Base Command

`keeper-security-register-complete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| code | The authorization code retrieved from user's email. | Optional |

#### Context Output

There is no context output for this command.

#### Human Readable Output

>Login completed

### keeper-security-register-test

***
Use this command to test the connectivity of the instance.

#### Base Command

`keeper-security-register-test`

#### Input

There is no context output for this command.

#### Context Output

There is no context output for this command.

#### Human Readable Output

>Successful connection