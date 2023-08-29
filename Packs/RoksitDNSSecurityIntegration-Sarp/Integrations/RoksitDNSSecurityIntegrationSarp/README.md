This integration provides adding selected domains to the  Roksit Secure DNS's Blacklisted Domain List through API .
## Configure Roksit DNS Security Integration - Sarp on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Roksit DNS Security Integration - Sarp.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |
    | Server URL (e.g. https://portal.roksit.com/api/integration/blacklist) |  | True |
    | Maximum number of incidents per fetch |  | True |
    | API Key |  | True |
    | Score threshold for domain reputation command | Set this to determine the HelloWorld score that will determine if a domain is malicious \(0-100\) | False |
    | Trust any certificate (not secure) |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### roksitdomainblokla

***
roksit

#### Base Command

`roksitdomainblokla`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
