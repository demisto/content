This integration fetches a static file via SCP from a remote server and exposes the file to a specified port (static EDL, file display, etc)
## Configure ExposeStaticEDL on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ExposeStaticEDL.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Incident type | False |
    |  | True |
    |  | True |
    |  | True |
    | Long running instance | False |
    | Port mapping (&lt;port&gt; or &lt;host port&gt;:&lt;docker port&gt;) | True |
    | Username | True |
    | Password | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### long-running-execution

***

#### Base Command

`long-running-execution`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.