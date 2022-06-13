Collect events from Dropbox's logs.
This integration was integrated and tested with version xx of DropboxEventsCollector

## Configure Dropbox Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Dropbox Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                                                                             | **Description** | **Required** |
-------------------------------------------------------------------------------------------| --- | --- | --- |
    | App Key | The App key | True |
    | App Secret | The App secret | True |
    | First fetch in timestamp format | First fetch in timestamp format (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
    | The maximum number of events per fetch |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Vendor name | For the dataset name for example: dropbox | False |
    | Product name | For the dataset name for example: dropbox | False |


## Commands
You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dropbox-auth-start
***
Starts the authentication.


#### Base Command

`dropbox-auth-start`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### dropbox-auth-complete
***
Completes the authentication.


#### Base Command

`dropbox-auth-complete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| code | The code that returns from Dropbox. | Required | 


#### Context Output

There is no context output for this command.

### dropbox-auth-test
***
Tests the authentication.


#### Base Command

`dropbox-auth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### dropbox-auth-reset
***
Resets the authentication.


#### Base Command

`dropbox-auth-reset`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### dropbox-get-events
***
Get events.


#### Base Command

`dropbox-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum events to fetch. Default is 500. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 
| from | Fetch events from this time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). Default is 3 days. | Optional | 


#### Context Output

There is no context output for this command.