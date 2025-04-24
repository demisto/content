The Imperva Skyfence Cloud Gateway is a Cloud Access Security Broker (CASB) that provides visibility and control over sanctioned and unsanctioned cloud apps to enable their safe and productive use.
This integration was integrated and tested with version 1.0.8 of Imperva Skyfence

## Configure Imperva Skyfence in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g., 123.168.01.222) | True |
| Client ID | False |
| Client ID | False |
| Client Secret | False |
| Client Secret | False |
| Trust any certificate (not secure) | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### imp-sf-list-endpoints

***
Returns a list of, and basic details for, all managed and un-managed endpoints.

#### Base Command

`imp-sf-list-endpoints`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### imp-sf-set-endpoint-status

***
Updates the status (enroll or revoke) of an endpoint. You can run this command on an endpoint with any status, but the most common use case is endpoints with a status of pending.

#### Base Command

`imp-sf-set-endpoint-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpointId | The ID of the endpoint. Run the "imp-sf-list-endpoints" command to return a list. | Required | 
| action | Enroll/Revoke endpoint status. Can be "enroll" or "revoke". | Required | 

#### Context Output

There is no context output for this command.