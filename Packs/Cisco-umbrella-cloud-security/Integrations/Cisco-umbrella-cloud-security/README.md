
This integration was integrated and tested with version 1.0 of Cisco Umbrella Cloud Security.
## Configure Cisco Umbrella Cloud Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco Umbrella Cloud Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Organization ID | True |
    | API Key | True |
    | API Secret | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### umbrella-get-destination-lists
***
Get's all destination lists in organization


#### Base Command

`umbrella-get-destination-lists`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| orgId | Organization ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.DestinationLists | Unknown |  | 


#### Command Example
``` ```

#### Human Readable Output



### umbrella-add-domain
***
Adds domains to given destination list


#### Base Command

`umbrella-add-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| orgId | Optional organization ID. If not provided, will use the one provided in the integration configuration. | Optional | 
| destId | Destination list ID. | Required | 
| domains | List of domains to add to destination list (Format: domain1.com,domain2.com). | Required | 
| comment | Note on what the domain is or why it is being added. Default is Added from XSOAR. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### umbrella-get-destination-domains
***
Get's the domains listed in a destination list


#### Base Command

`umbrella-get-destination-domains`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| orgId | Optional orgId, by default uses the one set in the instance configuration. | Optional | 
| destId | Destination list ID to get domains from. Use umbrella-get-destination-lists to get the list ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### umbrella-remove-domain
***
Removes domains to given destination list


#### Base Command

`umbrella-remove-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| orgId | Optional organization ID. If not provided, will use the one provided in the integration configuration. | Optional | 
| destId | Destination list ID. | Required | 
| domainIds | List of entry IDs to remove from destination list (Format: 1234,1235). | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


