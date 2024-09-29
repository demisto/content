This integration is intended to aid companies in integrating with the Stealth EcoAPI service.  Using the included commands, security teams can trigger dynamically isolation of users or endpoints from the rest of the Stealth network.  

## Configure Unisys Stealth in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Stealth Eco API IP Address or Hostname | True |
| Stealth Eco API Port | True |
| Credentials | True |
| Isolation Role ID | False |
| Trust any certificate (unsecure) | False |
| Use Proxy? | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### stealth-isolate-machine
***
This is the command which will isolate an endpoint from the Stealth Network


#### Base Command

`stealth-isolate-machine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | FQDN of machine to isolate. | Required | 


#### Context Output

There is no context output for this command.

### stealth-unisolate-machine
***
This is the command which will un-isolate an endpoint from Stealth Network


#### Base Command

`stealth-unisolate-machine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | FQDN of machine to isolate. | Required | 


#### Context Output

There is no context output for this command.

### stealth-get-stealth-roles
***
Retrieve roles from Stealth Network


#### Base Command

`stealth-get-stealth-roles`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### stealth-isolate-user
***
This is the command which will isolate an user from the Stealth Network


#### Base Command

`stealth-isolate-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | Hostname of machine to isolate. | Optional | 


#### Context Output

There is no context output for this command.

### stealth-unisolate-user
***
This is the command which will un-isolate an user from Stealth Network


#### Base Command

`stealth-unisolate-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | Username to un-isolate. | Optional | 


#### Context Output

There is no context output for this command.

### stealth-isolate-machine-and-user
***
This is the command which will isolate an endpoint and user from the Stealth Network


#### Base Command

`stealth-isolate-machine-and-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | FQDN of machine to isolate. | Optional | 
| user | Username to isolate. | Optional | 


#### Context Output

There is no context output for this command.

### stealth-unisolate-machine-and-user
***
This is the command which will un-isolate an endpoint and user from Stealth Network


#### Base Command

`stealth-unisolate-machine-and-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | FQDN of machine to isolate. | Optional | 
| user | Username to un-isolate. | Optional | 


#### Context Output

There is no context output for this command.