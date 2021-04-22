Automate your AppID Adoption by using this integration together with your Palo Alto Networks Next-Generation Firewall or Panorama.
This integration was integrated and tested with version xx of PAN-OS Policy Optimizer
## Configure PAN-OS Policy Optimizer on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PAN-OS Policy Optimizer.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g., https://192.168.0.1:443) | True |
    | Username | True |
    | Vsys - Firewall instances only | False |
    | Device Group - Panorama instances only | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pan-os-po-get-stats
***
Gets the Policy Optimizer statistics.


#### Base Command

`pan-os-po-get-stats`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.Stats.no_app_specified | Number | Number of rules with no apps specified. | 
| PanOS.PolicyOptimizer.Stats.unused | Number | Number of unused security policies. | 
| PanOS.PolicyOptimizer.Stats.unused_apps | Number | Number of unused apps in security policies. | 
| PanOS.PolicyOptimizer.Stats.unused_in_30_days | Number | Number of unused security policies in 30 days. | 
| PanOS.PolicyOptimizer.Stats.unused_in_90_days | Number | Number of unused security policies in 90 days. | 


#### Command Example
``` ```

#### Human Readable Output



### pan-os-po-no-apps
***
Shows all security policies with no apps specified.


#### Base Command

`pan-os-po-no-apps`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.NoApps | Unknown | Contains information about the rules that have no apps specified. i.e., Source, Destination, etc. | 


#### Command Example
``` ```

#### Human Readable Output



### pan-os-po-unused-apps
***
Gets the unused apps.


#### Base Command

`pan-os-po-unused-apps`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.UnusedApps | String | Shows all security rules with unused apps. | 


#### Command Example
``` ```

#### Human Readable Output



### pan-os-po-get-rules
***
Gets unused, used, or any rules


#### Base Command

`pan-os-po-get-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeframe | The time frame in days for which to show the unused rules. Default is 30. Default is 30. | Optional | 
| usage | Rule usage type. The values by which you want to filter. Possible values are: Unused, Used, Any. Default is Unused. | Optional | 
| exclude | Whether to exclude rules reset during the last x days, where x is the value defined in the timeframe argument. It will not exclude rules by default. Possible values are: false, true. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.UnusedRules | String | Shows all unused security rules. | 
| PanOS.PolicyOptimizer.AnyRules | String | Shows all security rules. | 
| PanOS.PolicyOptimizer.UsedRules | String | Shows all used security rules. | 


#### Command Example
``` ```

#### Human Readable Output



### pan-os-po-app-and-usage
***
Gets the app usage statistics for a specific security rule.


#### Base Command

`pan-os-po-app-and-usage`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_uuid | The UUID of the security rule. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.AppsAndUsage | Unknown | Shows detailed app usage statistics for specific security rules. | 


#### Command Example
``` ```

#### Human Readable Output



### pan-os-get-dag
***
Gets a specific dynamic address group.


#### Base Command

`pan-os-get-dag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dag | Dynamic address group name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


