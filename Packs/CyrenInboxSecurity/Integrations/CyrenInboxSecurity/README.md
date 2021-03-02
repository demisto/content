This Cyren integration imports incidents from Cyren Inbox Security into Cortex XSOAR.
This integration was integrated and tested with version 1.0.0 of Cyren Inbox Security
## Configure Cyren Inbox Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cyren Inbox Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://marketing.plutoserv.com) | The endpoint  provided by your Cyren Representative. | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Feed ID | The ID of the Feed provided by your Cyren Representative. Use "sample" to try it out. | True |
    | Token | The token provided by your Cyren Representative. Use "sample" to try it out. | True |
    | Maximum number of incidents per fetch | This will limit the number of incidents that can be generated per fetch.. | False |
    | Incident Type | Filter incidents created in XSOAR based upon their Cyren type. If left blank, no inbound filtering is performed and all incidents are accepted. | False |
    | Threat Type | Filter incidents created in XSOAR based upon their Threat type. If left blank, no inbound filtering is performed and all incidents are accepted. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | First Fetch Offset | A number \(defaults to 0\) to instruct where in the feed to begin processing. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cyreninboxsecurity-info
***
return information for feed


#### Base Command

`cyreninboxsecurity-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cyreninboxsecurity-simulate-fetch
***
Simulates a fetch operation


#### Base Command

`cyreninboxsecurity-simulate-fetch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance_name | The name of the instance to handle the request. Leave blank for all instances. | Optional | 
| verbose | display verbose information when command executes. Possible values are: yes, no. Default is no. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### url
***
Checks the reputation of a URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | unknown | The URL | 
| URL.Malicious.Vendor | unknown | Vendor reporting | 
| URL.Malicious.Description | unknown | description of url reputation | 
| DBotScore.Indicator | unknown | Indicator that was tested | 
| DBotScore.Type | unknown | indicator type | 
| DBotScore.Score | unknown | actual score | 
| DBotScore.Vendor | unknown | vendor calculating score | 


#### Command Example
``` ```

#### Human Readable Output



### cyreninboxsecurity-dump-urls
***
dump phishing url list


#### Base Command

`cyreninboxsecurity-dump-urls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


