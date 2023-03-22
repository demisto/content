DeCYFIR API's provides External Threat Landscape Management insights.
This integration was integrated and tested with version 6.5.0 of decyfir

## Configure DeCYFIR on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DeCYFIR.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Incident type |  | False |
    | DeCYFIR Server URL (e.g. https://example.net) |  | True |
    | DeCYFIR API Key |  | True |
    | Fetch incidents |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | How much time before the first fetch to retrieve incidents |  | False |
    | None | The maximum number of incidents to fetch per sub-category. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.