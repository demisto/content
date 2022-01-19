This is a wrapper on top of XSOAR API. Can be used to implement commands that call the XSOAR API in the background.  This is mostly to avoid  constructing raw json strings while calling the demisto rest api integration.

The first implemented command can be used to create an entry on any investigation; playground by default.  An example use-case could be debugging a pre-process script. (Call demisto.execute_command("xsoar-create-entry",{arguments})

The idea is to use the same code to test from a local machine.
python3  Xsoar_Utils.py  xsoar-create-entry  '{"data":"# testapi4","inv_id":"122c7bff-feae-4177-867e-37e2096cd7d9"}'

Read the code to understand more.
This integration was integrated and tested with version xx of Xsoar_Utils

## Configure Xsoar_Utils on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Xsoar_Utils.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | XSOAR Server URL  |  | True |
    | XSOAR Server API_Key |  | True |
    | XSOAR Server playground-id |  | True |
    | Allow Insecure connections to the server | Check this to ignore certificate signature | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### xsoar-create-entry
***
Creates an entry into an investigation warroom or  by default on the playground.


#### Base Command

`xsoar-create-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data | Entry value to be created. | Optional | 
| inv_id | The investigation id on which the entry is created. Defaults to playbook-id. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


