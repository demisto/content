This integration can monitor EDLs by emailing the content of an EDL as a zipped file to a specified user at an interval (when run with a job), and/or simply monitor the EDL for availability and email the user if the EDL is not available in other playbooks

## Configure EDL Monitor in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Timeout: | Timeout \(in seconds\) for how long to wait for EDL response before detecting as down \(default 2 minutes\) | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Email server: |  | False |
| Email username |  | False |
| Email password |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### get-edl-contents

***
Gets the current contents of an EDL

#### Base Command

`get-edl-contents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EDL | EDL IP or URL (e.g. http://xsoarserver.com:10009 or https://xsoarserver.com/instance/execute/instance_name). | Required | 
| EDL_username | EDL username, for auth to the EDL (optional). | Optional | 
| EDL_password | EDL password, for auth to the EDL (optional). | Optional | 

#### Context Output

There is no context output for this command.
### email-edl-contents

***
Gets the current contents of an EDL and emails it to a specified email address

#### Base Command

`email-edl-contents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EDL | EDL IP or URL (e.g. http://xsoarserver.com:10009 or https://xsoarserver.com/instance/execute/instance_name). | Required | 
| Email | Email address that you want to send the EDL contents to. | Required | 
| EDL_username | EDL username, for auth to the EDL (optional). | Optional | 
| EDL_password | EDL password, for auth to the EDL (optional). | Optional | 

#### Context Output

There is no context output for this command.
### check-status

***
Return the response code of the EDL

#### Base Command

`check-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EDL | EDL IP or URL (e.g. http://xsoarserver.com:10009 or https://xsoarserver.com/instance/execute/instance_name). | Required | 
| EDL_username | EDL username, for auth to the EDL (optional). | Optional | 
| EDL_password | EDL password, for auth to the EDL (optional). | Optional | 
| Email | Email. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ResponseCode | number | The response code. | 