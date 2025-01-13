Use this integration to handle Beyond Trust authorization requests through XSOAR.
This integration was integrated and tested with version 2 of BeyondTrust - Authorization Requests.

## Configure BeyondTrust - Authorization Requests in Cortex


| **Parameter** | **Required** |
| --- | --- |
|  | True |
|  | True |
|  | True |
|  | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### bt-authorize-ticket

***
approve or deny authorization requests for BT.

#### Base Command

`bt-authorize-ticket`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sys_id | sctask id. | Required | 
| record_id | PMC record Id. | Required | 
| decision | The decision regarding the authorization request. Possible values are: Denied, Approved, Pending. | Required | 
| duration | action duration (once or in seconds). Possible values are: Once. | Required | 
| user | The request's user. | Optional | 

#### Context Output

There is no context output for this command.
### bt-get-ticket

***
retrieves an existing ticket.

#### Base Command

`bt-get-ticket`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sys_id | the ticket system ID. | Required | 

#### Context Output

There is no context output for this command.
