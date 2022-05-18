An Identity and Access Management integration template.
This integration was integrated and tested with version v2 of Zoom API.

## Configure Zoom_IAM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Zoom_IAM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Key | True |
    | API Secret | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |
    | Allow creating users | False |
    | Allow updating users | False |
    | Allow disabling users | False |
    | Incoming Mapper | True |
    | Outgoing Mapper | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### iam-disable-user
***
Disable an active user.


#### Base Command

`iam-disable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active in the 3rd-party integration. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Provides the raw data from the 3rd-party integration. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
``` !iam-disable-user user-profile=`{"email": "john.doe@example.com", "givenname": "John"}` ```

#### Human Readable Output


