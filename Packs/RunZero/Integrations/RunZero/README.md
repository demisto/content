RunZero integration for XSOAR.
This integration was integrated and tested with version xx of RunZero

## Configure RunZero on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RunZero.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### runzero-asset-search
***
Get all assets (getAssets)


#### Base Command

`runzero-asset-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_ids | Search assets by ids comma separated. | Optional | 
| search | Search query string. | Optional | 
| ips | Search by IPs. | Optional | 
| hostnames | Search by hostnames. | Optional | 
| display_attributes | Should include attributes section in returned result. | Optional | 
| display_services | Should include services section in returned result. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RunZero.Asset | String | RunZero raw response. | 
