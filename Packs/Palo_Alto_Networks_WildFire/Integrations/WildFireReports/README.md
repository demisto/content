Generates a Palo Alto Networks WildFire PDF report.
This integration was created and tested with version 10.1 of WildFire.

## Configure Palo Alto Networks WildFire Reports on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Palo Alto Networks WildFire Reports.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server base URL (e.g., https://192.168.0.1/publicapi) |  | True |
    | API Key |  | False |
    | Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
    | Use system proxy settings | Use system proxy settings. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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


