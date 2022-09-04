This is a simple web-server that as of now, supports handling configurable user responses (like Yes/No/Maybe) and data collection tasks that can be used to fetch key value pairs. What makes it different from Data collection tasks is that, the URL to perform a certain action is predictable and written to the incident context when an action is setup.This URL can be inserted to for eg: an HTML email.  User clicks are  are recorded in the integration context and can be polled by Scheduled Commands/ Generic Polling
This integration was integrated and tested with version 1.0 of XSOAR-Web-Server

## Configure XSOAR-Web-Server on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for XSOAR-Web-Server.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Incident type |  | False |
    | Long running instance |  | False |
    | Server Listening Port | The port on which the integration instance will listen | True |
    |  | The URL on which the user should send the response to. | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### xsoar-ws-setup-simple-action
***
setup the web server to handle URL clicks for each action specified from single or multiple recipients


#### Base Command

`xsoar-ws-setup-simple-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| actions | Comma separated possible values for each action. Mandatory for get requests. | Required | 
| emailaddresses | Comma separated email addresses of the recipients. | Required | 
| userstring | User defined string that has to be set from the playbook. This is  used to differentiate between multiple jobs running on the same incident. | Required | 
| htmltemplate | template to construct the html mail. | Required | 
| xsoarproxy | Used to specify what endpoint to submit the responses. If set to false, the  html template will have the endpoint containing the custom port. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WS-ActionDetails | unknown | The current status of the action's  configuration details | 
| WS-ActionDetails.job_uuid | unknown | Subset of action details, added for ease of configuration in playbooks | 

### xsoar-ws-clear-cache
***
Clear the backend storage containing all session information.


#### Base Command

`xsoar-ws-clear-cache`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### xsoar-ws-show-cache
***
Show the details of all the setup actions from the backend


#### Base Command

`xsoar-ws-show-cache`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### xsoar-ws-remove-action
***
Remove a certain job from the backend


#### Base Command

`xsoar-ws-remove-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Job's uuid. | Required | 


#### Context Output

There is no context output for this command.
### xsoar-ws-get-action-status
***
Gets the current status of an action that was setup; Used to track if the user responded to the action.


#### Base Command

`xsoar-ws-get-action-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Job's uuid. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WS-ActionStatus | unknown | The current status of the action with some configuration data. Is used for polling the status | 
| WS-ActionStatus.link_tracker | unknown | Subset of action status; tracked here to make it easier for configuring playbooks | 

### xsoar-ws-set-job-complete
***
Set a job to complete. Usually called from the automation that is polling the result


#### Base Command

`xsoar-ws-set-job-complete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Job's uuid. | Required | 


#### Context Output

There is no context output for this command.
### xsoar-ws-setup-form-submission
***
setup a form submission job that can take multiple values from multiple users


#### Base Command

`xsoar-ws-setup-form-submission`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| emailaddresses | Comma separated email addresses of the recipients. | Required | 
| userstring | Optional user string that can be set from the playbook. Can be used to differentiate between multiple jobs running on the same incident. | Optional | 
| htmltemplate | The template to build the email content. | Required | 
| xsoarproxy | Used to specify what endpoint to submit the responses. If set to false, the  html template will have the endpoint containing the custom port. Default is true. | Optional | 


#### Context Output

There is no context output for this command.