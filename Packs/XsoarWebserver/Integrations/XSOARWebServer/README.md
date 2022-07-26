This is a simple web-server that as of now, supports handling configurable user responses (like Yes/No/Maybe). What makes it different from Data collection tasks is that, the URL to perform a certain action is predictable and written to the incident context when an action is setup. This URL can be inserted to for eg: an HTML email.  User clicks are  are recorded in the integration context and can be polled by Scheduled Commands/ Generic Polling
This integration was integrated and tested with version 6.6 of XSOAR, but is expected to work from XSOAR version 6.2 and on 6.1 with Generic polling (instead of using the automation).

## Configure XSOAR-Web-Server on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for XSOAR-Web-Server.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | xsoar-external-url | The URL on which the user should send the response to. | True |
    | Server Listening Port | The port on which the integration instance will listen | True |
    | Long running instance | To enable the long running instance feature of XSOAR | True |
4. Optionally enable the XSOAR proxy feature mentioned [here](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke)

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### xsoar-ws-setup-simple-action
***
setup the web server to handle URL clicks for each action specified


#### Base Command

`xsoar-ws-setup-simple-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| actions | comma separated possible values for each action. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WS-ActionDetails | unknown | The details of the URLs that are generated, along with the uuid | 
| WS-ActionDetails.uuid | unknown | uuid of the setup actoin | 

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
Remove a certain action from the backend


#### Base Command

`xsoar-ws-remove-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | uuid of the action to remove from the backend. | Required | 


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
| uuid | uuid of the action to fetch from the backend. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WS-ActionStatus | unknown | The data structure holding the details of the fetched action | 
