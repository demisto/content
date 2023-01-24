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
    | Server URL |  | True |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### runzero-asset-search
***
Get assets.


#### Base Command

`runzero-asset-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_ids | Search assets by ids comma separated. | Optional | 
| search | Search using RunZero search syntax: https://www.runzero.com/docs/runzero-manual.pdf page 288. | Optional | 
| ips | Search assets by IPs. | Optional | 
| hostnames | Search assets by hostnames. | Optional | 
| display_attributes | Include attributes section in returned result. Possible values are: True, False. | Optional | 
| display_services | Include services section in returned result. Possible values are: True, False. | Optional | 
| limit | Limit the number of assets returned. Default is 50. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RunZero.Asset.ID | UUID | Asset service id. | 
| RunZero.Asset.Addresses | Array | Asset addresses. | 
| RunZero.Asset.Asset_Status | Boolean | Asset asset status. | 
| RunZero.Asset.Hostname | Array | Asset hostname. | 
| RunZero.Asset.OS | String | OS version. | 
| RunZero.Asset.Type | String | Asset type. | 
| RunZero.Asset.Hardware | String | Asset hardware. | 
| RunZero.Asset.Outlier | String | Asset outlier. | 
| RunZero.Asset.MAC_Vendor | String | Asset mac vendor. | 
| RunZero.Asset.MAC_Age | Integer | Asset outlier. | 
| RunZero.Asset.MAC | UUID | Asset MAC address. | 
| RunZero.Asset.OS_EOL | String | Asset OS End of Life. | 
| RunZero.Asset.Sources | String | Asset outlier. | 
| RunZero.Asset.Comments | String | Commets attached to asset. | 
| RunZero.Asset.Tags | Array | Tags attched to asset. | 
| RunZero.Asset.Svcs | Integer | Number of services on asset. | 
| RunZero.Asset.TCP | Integer | Asset outlier. | 
| RunZero.Asset.UDP | Integer | Asset outlier. | 
| RunZero.Asset.ICMP | Integer | Asset outlier. | 
| RunZero.Asset.SW | Integer | Asset outlier. | 
| RunZero.Asset.Vulns | Integer | Asset vulnerability count. | 
| RunZero.Asset.RTT/ms | Integer | Asset Round Trip Time. | 
| RunZero.Asset.Hops | Integer | Asset Time To Live. | 
| RunZero.Asset.Detected | String | Asset is detected by. | 
| RunZero.Asset.First_Seen | String | Asset date time first seen. | 
| RunZero.Asset.Last_Seen | String | Asset date time last seen. | 
| RunZero.Asset.Explorer | String | Asset detected by which agent. | 
| RunZero.Asset.Hosted_Zone | String | Asset hosted zone. | 
| RunZero.Asset.Site | String | Asset site name. | 

### runzero-service-search
***
Get services.


#### Base Command

`runzero-service-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | UUID of the service to retrieve. | Optional | 
| search | Search using RunZero search syntax: https://www.runzero.com/docs/runzero-manual.pdf page 288. | Optional | 
| service_addresses | Search services by addresses. | Optional | 
| display_attributes | Include attributes section in returned result. Possible values are: True, False. | Optional | 
| limit | Limit the number of assets returned. Default is 50. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RunZero.Service.ID | UUID | Service service id. | 
| RunZero.Service.Address | String | Service addresses. | 
| RunZero.Service.Asset_Status | Boolean | Service asset status. | 
| RunZero.Service.Hostname | Array | Service hostname. | 
| RunZero.Service.Transport | String | Service hostname. | 
| RunZero.Service.Port | Integer | Service hostname. | 
| RunZero.Service.Protocol | Array | Service hostname. | 
| RunZero.Service.VHost | Array | Service hostname. | 
| RunZero.Service.Summary | Array | Service hostname. | 
| RunZero.Service.OS | String | OS version. | 
| RunZero.Service.Type | String | Service type. | 
| RunZero.Service.Hardware | String | Service hardware. | 
| RunZero.Service.Outlier | String | Service outlier. | 
| RunZero.Service.MAC_Vendor | String | Service mac vendor. | 
| RunZero.Service.MAC_Age | Integer | Service outlier. | 
| RunZero.Service.MAC | UUID | Service MAC address. | 
| RunZero.Service.OS_EOL | String | Service OS End of Life. | 
| RunZero.Service.Comments | String | Commets attached to asset. | 
| RunZero.Service.Tags | Array | Tags attched to asset. | 
| RunZero.Service.Svcs | Integer | Number of services on asset. | 
| RunZero.Service.TCP | Integer | Service outlier. | 
| RunZero.Service.UDP | Integer | Service outlier. | 
| RunZero.Service.ICMP | Integer | Service outlier. | 
| RunZero.Service.SW | Integer | Service outlier. | 
| RunZero.Service.Vulns | Integer | Service vulnerability count. | 
| RunZero.Service.RTT/ms | Integer | Service Round Trip Time. | 
| RunZero.Service.Hops | Integer | Service Time To Live. | 
| RunZero.Service.Detected | String | Service is detected by. | 
| RunZero.Service.First_Seen | String | Service date time first seen. | 
| RunZero.Service.Last_Seen | String | Service date time last seen. | 
| RunZero.Service.Explorer | String | Service detected by which agent. | 
| RunZero.Service.Hosted_Zone | String | Service hosted zone. | 
| RunZero.Service.Site | String | Service site name. | 

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
### runzero-api-key-info
***
Get information about the key used. Type, Limit, usage etc.


#### Base Command

`runzero-api-key-info`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### runzero-bulk-clear-tags
***
Bulk clear tags according to RunZero query search


#### Base Command

`runzero-bulk-clear-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Search using RunZero search syntax: https://www.runzero.com/docs/runzero-manual.pdf page 288. | Required | 


#### Context Output

There is no context output for this command.