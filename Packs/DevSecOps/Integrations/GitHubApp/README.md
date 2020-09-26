An App Integration with Github
This integration was integrated and tested with version xx of GitHubApp
## Configure GitHubApp on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GitHubApp.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| app_id | Application ID | False |
| app_secret | Application Secret | False |
| longRunning | Long Running Instance | True |
| longRunningPort | Listen Port | True |
| certificate | Certificate \(Required for HTTPS\) | False |
| private_key | Private Key \(Required for HTTPS\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### github-set-context
***
Set the Integration Context


#### Base Command

`github-set-context`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context | The Integration Context as JSON Dictionary | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### github-get-context
***
Get the Integration Context


#### Base Command

`github-get-context`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### github-import-delivery
***
Import a new GitHub Delivery as a JSON Dictionary


#### Base Command

`github-import-delivery`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| delivery | GitHub Delivery | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### github-find-pr
***
Return the incident ID of a PR


#### Base Command

`github-find-pr`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | Repository Name | Optional | 
| number | PR Number | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


