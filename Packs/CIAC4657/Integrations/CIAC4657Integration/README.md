Some dummy integration to test CIAC-4657
## Configure CIAC-4657-integration on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CIAC-4657-integration.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ciac-4657-get-nothing

***
Dummy command for CIAC-4657

#### Base Command

`ciac-4657-get-nothing`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nothing | Dummy argument for CIAC-4657. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CIAC4657.Output | string | Dummy output for CIAC-4657 | 
