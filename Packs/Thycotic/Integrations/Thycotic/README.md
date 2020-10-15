Secure privileges for service, application, root,
and administrator accounts across your enterprise
This integration was integrated and tested with version 10.9 of Thycotic
## Configure Thycotic on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Thycotic.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL | True |
| credentials | Username | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| max_fetch |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### thycotic-authenticate-token
***
View access token for session


#### Base Command

`thycotic-authenticate-token`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| token | String | Access token | 


#### Command Example
``` ```

#### Human Readable Output



### thycotic-secret-password-get
***
Retrieve password from secret


#### Base Command

`thycotic-secret-password-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID secret | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| secret_password | String | Password | 


#### Command Example
``` ```

#### Human Readable Output



### thycotic-secret-username-get
***
Retrieved username from secret


#### Base Command

`thycotic-secret-username-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID secret | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| secret_username | String | Username from secret | 


#### Command Example
``` ```

#### Human Readable Output


