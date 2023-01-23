RunZero is a network discovery and asset inventory
 platform that uncovers every network in use and identifies every device connected–without credentials.
 Scan your network and build your asset inventory in minutes.
This integration was integrated and tested with version 3.3.0 of RunZero

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
| RunZero.Asset | String | RunZero assets raw response. | 

### runzero-service-search
***
Get services.


#### Base Command

`runzero-service-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | UUID of the service to retrieve. | Optional | 
| search | Search query string. | Optional | 
| service_addresses | Search services by addresses. | Optional | 
| display_attributes | Should include attributes section in returned result. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RunZero.Service | String | RunZero services raw response. | 

### runzero-comment-add
***
Add a comment or overrides existing asset comment


#### Base Command

`runzero-comment-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Choose asset. | Required | 
| comment | Comment to add. | Required | 


#### Context Output

There is no context output for this command.
### runzero-tag-add
***
Add tag or tags to asset


#### Base Command

`runzero-tag-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Choose asset. | Required | 
| tags | Tags to add to asset. | Required | 


#### Context Output

There is no context output for this command.