Use McAfee Database Activity Monitoring (DAM) Integration to fetch Alerts (incidents) and query Alerts.

This integration was integrated and developed with version 4.6.x of McAfee DAM.

## Configure McAfeeDAM in Cortex

Make sure that the XML API interface is enabled on your McAfee DAM server (**Settings > Interfaces > XML API**), and that the configured user has read permissions to query DAM Alerts and Sensors (XML API).

**Important:** The user configured in McAfee DAM must have the *Use XML API* permission as documented [here](https://docs.mcafee.com/bundle/database-security-4.6.5-product-guide/page/GUID-9018582C-321F-46A3-AB12-FABF16FCE12B.html).

Instructions on how to configure and test the XML API for McAfee DAM are available [here](https://docs.mcafee.com/bundle/database-security-4.6.5-product-guide/page/GUID-E51275F4-B365-499B-879C-51FE6A6989BA.html).


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | URL | True |
| credentials | Credentials | True |
| batchSize | Batch size for incident fetch | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| secure | Validate ceritifacte | False |
| ruleName | Rule Name, If fetch incident is checked, this field is mandatory and will be used to get DAM alerts only triggered by this rule | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### Get information for a single alert
***
Gets a DAM alert from McAfee Database Activity Monitoring by alert ID.
##### Required Permissions
* Alerts Read 
##### Base Command

`dam-get-alert-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The alert ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AlertId | unknown | DAM alert ID. | 
| alertAccessedObjects | unknown | DAM accessed objects. | 
| dbUser | unknown | DAM Database User. | 
| Account.Username | unknown | DAM OS user. | 
| database | unknown | DAM database. | 
| sensor | unknown | DAM sensor. | 
| rules | unknown | DAM rules. | 


### Get the latest DAM alerts
***
Gets the latest DAM alerts by rule name.
##### Required Permissions
* Alerts Read
##### Base Command

`dam-get-latest-by-rule`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ruleName | Name of the rule that triggered the alert. | Required | 
| count | Number of alerts to retrieve. The default is 10. | Optional | 
| timeBack | Filter DAM alerts and import alerts that were created only in the last X minutes. The default is the last 10 minutes. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AlertId | unknown | DAM alert ID. | 
| alertAccessedObjects | unknown | DAM accessed objects. | 
| dbUser | unknown | DAM database user. | 
| Account.Username | unknown | DAM OS user. | 
| database | unknown | DAM database. | 
| sensor | unknown | DAM sensor. | 
| rules | unknown | DAM rules. | 