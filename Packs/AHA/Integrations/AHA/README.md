Use the Aha! integration to list and manage Cortex XSOAR features from Aha.
This integration was integrated and tested with API version September 30, 2022 release of Aha.
## Configure Aha on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Aha.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Project Name | Check the Aha\! project name in the URL. Replace the &amp;lt;PROJECT_NAME&amp;gt; placeholder in the following : example.com.aha.io/products/&amp;lt;PROJECT_NAME&amp;gt;/features | True |
    | Api Key | API Key to access the service REST API,  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aha-get-features
***
Lists all features from service, unless a specific feature is specified.


#### Base Command

`aha-get-features`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | Show features created after that date. Default is 2020-01-01. | Optional | 
| feature_name | The name of a specific feature to retrieve. | Optional | 
| fields | A comma-separated list of fields to include in the Aha! service response. Default is name,reference_num,id,created_at. | Optional | 
| page | The specific results page to retrieve. Default is 1. | Optional | 
| per_page | The maximum number of results per page. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AHA.Feature.id | UUID | The feature ID. | 
| AHA.Feature.name | String | The feature name. | 
| AHA.Feature.reference_num | String | The feature reference number. | 
| AHA.Feature.workflow_status | String | The feature workflow status. | 
| AHA.Feature.description | String | The feature description. | 
| AHA.Feature.created_at | Date | The feature creation date. | 

#### Command example
```!aha-get-features```
```!aha-get-features feature_name=DEMO-10 fields=workflow_status```
```!aha-get-features fields=workflow_status page=2 per_page=30```

### aha-edit-feature
***
Edit any of the following fields in a feature: Name, Status and Description.


#### Base Command

`aha-edit-feature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feature_name | The name of the features to edit. | Required | 
| fields | Fields in JSON format to edit in a feature. Possible fields are name, description and status. Status should match Aha values under workflow_status. Example:" {"name": "name", "description": "desc", "status" : "Closed"}. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AHA.Feature.id | UUID | The feature ID. | 
| AHA.Feature.name | String | The feature name. | 
| AHA.Feature.reference_num | String | The feature reference number. | 
| AHA.Feature.workflow_status | String | The feature workflow status. | 
| AHA.Feature.description | String | The feature description. | 
| AHA.Feature.created_at | Date | The feature creation date. | 

#### Command example
```!aha-edit-feature feature_name=DEMO-10 fields=`{"name":"the_new_name", "description":"the_new_desc", "status":"Closed"}```
