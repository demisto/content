Generates a Palo Alto Networks WildFire PDF report.

This integration is set up by default on Cortex XSOAR versions 6.5+ with the Threat Intel Module (TIM). It is designed for internal use with the TIM Sample Analysis feature. To run ad hoc CLI commands to generate WildFire reports, use the Palo Alto Networks WildFire v2 integration instead.

This integration was created and tested with version 10.1 of WildFire.

## Configure Palo Alto Networks WildFire Reports in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server base URL (e.g., https://192.168.0.1/publicapi) |  | True |
| API Key |  | False |
| Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
| Use system proxy settings | Use system proxy settings. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### internal-wildfire-get-report
***
Retrieves results for a file hash using WildFire.


#### Base Command

`internal-wildfire-get-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | SHA256 hash to check. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!internal-wildfire-get-report sha256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890```

#### Human Readable Output

