Aha!
This integration was integrated and tested with version xx of Aha

## Configure AHA on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AHA.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Api Key | API Key to access service REST API  | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### get-all-features
***
will get all features from service


#### Base Command

`get-all-features`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | Get features from a date. Possible values are: . Default is 2020-01-01. | Optional | 


#### Context Output

There is no context output for this command.
### get-feature
***
returns a specific feature


#### Base Command

`get-feature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| featureName | Get a feature with the name specified. Possible values are: . | Required | 


#### Context Output

There is no context output for this command.
### edit-feature
***
change value of a field in feature


#### Base Command

`edit-feature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| featureName | Select features to edit. Possible values are: . | Required | 
| fields | Fields to edit in a feature. Possible values are: . Default is {workflow_status": {"name": "Closed"}}. | Required | 


#### Context Output

There is no context output for this command.
### close-feature
***
Sets a feature status to closed


#### Base Command

`close-feature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| featureName | Select a specific feature to close. Possible values are: . | Required | 


#### Context Output

There is no context output for this command.