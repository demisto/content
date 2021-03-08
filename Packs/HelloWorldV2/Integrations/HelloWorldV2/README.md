This is the Hello World integration for getting started.
This integration was integrated and tested with version xx of HelloWorld V2
## Configure HelloWorld V2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for HelloWorld V2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://soar.monstersofhack.com) | True |
    | API Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### helloworld-say-hello-new
***
Hello command - prints hello to anyone.


#### Base Command

`helloworld-say-hello-new`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of whom you want to say hello to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| hello | String | Should be Hello \*\*something\*\* here. | 


#### Command Example
``` ```

#### Human Readable Output



### helloworld-get-alert-new
***
Retrieve alert extra data by ID.


#### Base Command

`helloworld-get-alert-new`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Alert.alert_id | String | Alert ID. | 
| HelloWorld.Alert.created | Date | Alert created time. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| HelloWorld.Alert.description | String | Alert description. | 
| HelloWorld.Alert.device_id | String | ID of the device involved in the alert. | 
| HelloWorld.Alert.device_ip | String | IP Address of the device involved in the alert. | 
| HelloWorld.Alert.location | String | Location of the device involved in the alert. | 
| HelloWorld.Alert.user | String | User involved in the alert. | 


#### Command Example
``` ```

#### Human Readable Output


