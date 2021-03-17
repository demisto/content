Automate your AppID Adoption by using this integration together with your Palo Alto Networks Next-Generation Firewall or Panorama
This integration was integrated and tested with version xx of PAN-OS Policy Optimizer
## Configure PAN-OS Policy Optimizer on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PAN-OS Policy Optimizer.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g., https://192.168.0.1) | True |
    | Port (e.g 443) | False |
    | Username | True |
    | Device group - Panorama instances only (write shared for Shared location) | False |
    | Vsys - Firewall instances only | False |
    | Template - Panorama instances only. | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pan-os-po-getstats
***
Gets the Policy Optimizer statistics


#### Base Command

`pan-os-po-getstats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.Stats.no_app_specified | Number | Number of rules with no apps specified | 
| PanOS.PolicyOptimizer.Stats.unused | Number | Number of unused security policies | 
| PanOS.PolicyOptimizer.Stats.unused_apps | Number | Number of unused apps in security policies | 
| PanOS.PolicyOptimizer.Stats.unused_in_30_days	 | Number | Number of unused security policies in 30 days | 
| PanOS.PolicyOptimizer.Stats.unused_in_90_days | Number | Number of unused security policies in 90 days | 


#### Command Example
``` ```

#### Human Readable Output



### pan-os-po-noapps
***
Shows all security policies with no apps specified


#### Base Command

`pan-os-po-noapps`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.NoApps | Unknown | Contains informatios about the rules that have no apps specified. i.e Source, Destination etc. | 


#### Command Example
``` ```

#### Human Readable Output



### pan-os-po-unusedapps
***
 


#### Base Command

`pan-os-po-unusedapps`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.UnusedApps | Unknown | Shows all security polices with unused apps | 


#### Command Example
``` ```

#### Human Readable Output



### pan-os-po-getrules
***
Gets unused, used or any rules


#### Base Command

`pan-os-po-getrules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeframe | The timeframe in days to show the unused rules for. Default is 30. | Required | 
| usage | Rule usage type. Which values you want to filter by. Possible values are: Unused, Used, Any. Default is unused. | Required | 
| exclude | Exclude rules reset during the last x days. It will not exclude if argument is empty. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.UnusedRules | Unknown | Shows all Unused Rules | 
| PanOS.PolicyOptimizer.AnyRules | Unknown | Shows Any Rules | 
| PanOS.PolicyOptimizer.UsedRules | Unknown | Shows all Used Rules | 


#### Command Example
``` ```

#### Human Readable Output



### pan-os-po-appandusage
***
Gets the App usage statistics for a specific security policy


#### Base Command

`pan-os-po-appandusage`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_uuid | The uuid of the security policy. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.AppsAndUsage | Unknown | Shows detailed App Usage statistics for specific rules | 


#### Command Example
``` ```

#### Human Readable Output



### pan-os-get-dag
***
 


#### Base Command

`pan-os-get-dag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dag | Dynamic Address Group Name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


