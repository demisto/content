Drift integration to fetch, modify, create and delete contacts within the Drift Plattform's Contact API.
This integration was integrated and tested with version 1.7 of Drift

## Configure Drift in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Access Token | API Access Token | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Fetch indicators |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### drift-get-contact
***
Retrieve a contact using their email address (for multiple) or ID (for single).


#### Base Command

`drift-get-contact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the contact (overrides the email input). | Optional | 
| email | Email of the contact. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Drift.Contacts.id | number | ID of the contact | 
| Drift.Contacts.createdAt | number | Created at timestamp \(Epoch Unix Timestamp\) | 
| Drift.Contacts.Attributes | unknown | Attributes of the contact \(JSON dict\). | 

### drift-update-contact
***
Patch Contact Updates using contact ID


#### Base Command

`drift-update-contact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Contact ID. | Required | 
| attributes | Attributes to be updates. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Drift.Contacts.id | number | ID of the created contact | 
| Drift.Contacts.createdAt | number | Created at timestamp \(Epoch Unix Timestamp\) | 
| Drift.Contacts.attributes | unknown | Attributes of the contact \(JSON dict\). | 

### drift-delete-contact
***
Delete Contact using contact ID


#### Base Command

`drift-delete-contact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Contact ID. | Required | 


#### Context Output

There is no context output for this command.
### drift-post-contact
***
Post New Contact using a new contact Email 


#### Base Command

`drift-post-contact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | New Contact Email. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Drift.Contacts.id | number | ID of the created contact | 
| Drift.Contacts.createdAt | number | Created at timestamp \(Epoch Unix Timestamp\) | 
| Drift.Contacts.Attributes | unknown | Attributes of the contact \(JSON dict\). | 