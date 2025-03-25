Cloud-based SaaS to detect risks found on social media and digital channels.
This integration was integrated and tested with versions xx of ZeroFox.

## Configure ZeroFox_Key_Incidents in Cortex


| **Parameter**                        | **Required** |
| ---                                  | ---          |
| URL (e.g., https://api.zerofox.com/) | True         |
| Username                             | True         |
| Password                             | True         |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### zerofox-get-key-inicident

***
Fetches Key Incidents on a time window.

#### Base Command

`zerofox-get-key-incidents`

#### Input

| **Argument Name** | **Description**                                              | **Required** |
| ---               | ---                                                          | ---          |
| start_time        | The earliest point in time for which data should be fetched. | Required     |
| end_time          | The latest point in time for which data should be fetched.   | Required     |

#### Context Output

| **Path**               | **Type** | **Description**                                              |
| ---                    | ---      | ---                                                          |
| BaseIntegration.Output | String   | \[Enter a description of the data returned in this output.\] |