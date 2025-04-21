Manage FileOrbis operations.
This integration was integrated and tested with version >10.0.0 of FileOrbis (You should see XSOAR settings on management).

## Configure the FileOrbis for Cortex XSOAR
1. Navigate to **Security > XSOAR** settings on management.
2. Click **Active** checkbox.
3. Click **Save** button.
4. Copy created **Client Id** and **Client Secret**.

## Configure FileOrbis in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Url | FileOrbis Url. | True |
| Client Id | Client id from FileOrbis XSOAR settings. | True |
| Client Secret | Client secret from FileOrbis XSOAR settings. | True |
| Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
| Use system proxy settings | Use system proxy settings. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fileorbis-change-user-status
***
Changes user status


#### Base Command

`fileorbis-change-user-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Id of the user whose status is to be changed. | Required | 
| status | New status of the user ( 0 = Passive, 1 = Active, 2 = Deleted ). Possible values are: 0, 1, 2. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FileOrbis.UserStatus.UserID | String | User Id to change its status | 
| FileOrbis.UserStatus.Success | Boolean | True if operation completed successfully | 
| FileOrbis.UserStatus.Status | Number | Result code of the operation | 
| FileOrbis.UserStatus.Message | String | User friendly result message of the operation | 


#### Command Example
``` !fileorbis-change-user-status user_id="69a0e65c-54d7-4210-9cc4-08c40d1a0b9d" status="1" ```

#### Context Example
```json
{
    "FileOrbis": {
        "UserStatus": {
            "Success": true,
            "Status": 0,
            "Message": "Your Operation is Completed Successfully",
            "UserID": "69a0e65c-54d7-4210-9cc4-08c40d1a0b9d"
        }
    }
}
```
#### Human Readable Output

| **Success** | **Status** | **Message** | **UserID** |
| --- | --- | --- | --- |
| true | 0 | Your Operation is Completed Successfully | 69a0e65c-54d7-4210-9cc4-08c40d1a0b9d |
