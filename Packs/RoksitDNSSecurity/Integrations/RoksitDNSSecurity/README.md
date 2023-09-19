This integration provides adding selected domains to the Roksit Secure DNS's Blacklisted Domain List through API .
This integration was integrated and tested with version 1.0.0 of Roksit DNS Security (DNSSense).

## Configure Roksit DNS Security (DNSSense) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Roksit DNS Security (DNSSense).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://portal.roksit.com/api/integration/blacklist) | True |
    | API Key | True |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Roksit-add-to-blacklist

***
This command adds a given domain to tha Roksit blacklist.

#### Base Command

`Roksit-add-to-blacklist`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Domain | The Domain to send to the blacklist. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!Roksit-add-to-blacklist Domain=dummy.com```
#### Human Readable Output

>dummy.com was successfully added to the blacklist.
