Integration for AWX
This integration was integrated and tested with version xx of IntegrationForAWX
## Configure IntegrationForAWX on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IntegrationForAWX.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://awx.my.example.net:8443\) | True |
| credentials | Credentials | True |
| ssl_verify | Verify SSL certificate | False |
| incidentType | Incident type | False |
| isFetch | Fetch incidents | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### awx-stdout
***
Query the AWX API for the jobs stdout


#### Base Command

`awx-stdout`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job Id use to query | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntegrationForAWX.jobout.result | Unknown | Result of the Job | 


#### Command Example
``` ```

#### Human Readable Output



### awx-query
***
Query the AWX API


#### Base Command

`awx-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | dictionary use to query | Optional | 
| path | path in the api | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntegrationForAWX.query.results | Unknown | Result of the query | 


#### Command Example
``` ```

#### Human Readable Output



### awx-launch-template
***
Run a Job or Workflow template


#### Base Command

`awx-launch-template`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | What type of template is this | Required | 
| template_id | template id | Required | 
| extra_vars | additional variables to send with template | Optional | 
| asynchronous | Async | Optional | 
| timeout | how long to wait for the playbook to finish | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntegrationForAWX.template.id | String | Id of Template Job run | 
| IntegrationForAWX.template.type | String | Type of Template run | 
| IntegrationForAWX.template.status | String | Status of Template run | 


#### Command Example
``` ```

#### Human Readable Output



### awx-launch-adhoc
***
Run a ad-hoc command through Awx


#### Base Command

`awx-launch-adhoc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| inventory_id | Id of the Ansible Inventory | Required | 
| credential_id | Credentials used to log into systems | Required | 
| module_name | Name of the module to run | Required | 
| module_args | additional variables to send with the module | Optional | 
| limit | Ansible syntax to limit inventory scope | Required | 
| extra_vars | additional variables to send with template | Optional | 
| asynchronous | Async | Optional | 
| timeout | how long to wait for the playbook to finish | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntegrationForAWX.adhoc.id | String | Id of Template Job run | 
| IntegrationForAWX.adhoc.module | String | Type of Template run | 
| IntegrationForAWX.adhoc.status | String | Status of Template run | 


#### Command Example
``` ```

#### Human Readable Output


