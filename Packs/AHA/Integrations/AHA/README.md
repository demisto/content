Use the Aha! integration to list and manage Cortex XSOAR features from Aha.
This integration was integrated and tested with API version 1.0 of Aha

## Configure Aha on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Aha.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Api Key | API Key to access service REST API  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aha-get-features
***
Will list all features from service, unless a specific feature is specified


#### Base Command

`aha-get-features`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | Show features created after that date. Default is 2020-01-01. | Optional | 
| feature_name | get a specific feature. Possible values are: . | Optional | 
| fields | Specify fields in comma sepereated manner to include in Aha! service response. Possible values are: . Default is name,reference_num,id,created_at. | Optional | 
| page | result set pagination: get a specific result page. Possible values are: . Default is 1. | Optional | 
| per_page | result set pagination: set max items per page. Possible values are: . Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| feature.id | UUID | The feature ID. | 
| feature.name | String | The feature name. | 
| feature.reference_num | String | A feature reference num unique. | 
| feature.workflow_status | String | Feature status description. | 
| feature.description | String | Description of the feature. | 
| feature.created_at | Date | Feature creation date. | 

#### Command example
```!aha-get-features```
```!aha-get-features feature_name=DEMO-10 fields=workflow_status```
```!aha-get-features fields=workflow_status page=2 per_page=30```

### aha-edit-feature
***
Edit of the following fields in a feature: Name, Status and Description


#### Base Command

`aha-edit-feature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feature_name | Select features to edit. Possible values are: . | Required | 
| fields | Fields in JSON format to edit in a feature. Possible fields are name, description, status. Status should match Aha values under workflow_status. Possible values are: . Default is {"name": "name", "description": "desc", "status" : "Closed"}. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aha.feature.id | UUID | The feature ID. | 
| feature.name | String | The feature name. | 
| feature.reference_num | String | A feature reference number. | 
| feature.workflow_status | String | Status name. | 
| feature.description | String | Description of the feature. | 
| feature.created_at | Date | Feature creation date. | 

#### Command example
```!aha-edit-feature feature_name=DEMO-10 fields=`{"name":"the_new_name", "description":"the_new_desc", "status":"Closed"}```
