
This integration was integrated and tested with version 1.0 of Cisco Umbrella Cloud Security.
## Configure Cisco Umbrella Cloud Security in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Organization ID | True |
| API Key | True |
| API Secret | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.Destinations.createdAt | Unknown | When the domain within destination list was created | 
| Umbrella.Destinations.type | Unknown | Type of destination within destination list | 
| Umbrella.Destinations.destination | Unknown | Domain within destination list | 
| Umbrella.Destinations.id | Unknown | ID of domain within destination list | 
| Umbrella.Destinations.comment | Unknown | Comment associated with domain within destination list | 

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

### umbrella-get-destination-domain
***
Gets the domain from a destination list


#### Base Command

`umbrella-get-destination-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| orgId | Optional orgId, by default uses the one set in the instance configuration. | Optional | 
| destId | Destination list ID to get domains from. Use umbrella-get-destination-lists to get the list ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.Destinations.createdAt | Unknown | When the domain within destination list was created | 
| Umbrella.Destinations.type | Unknown | Type of destination within destination list | 
| Umbrella.Destinations.destination | Unknown | Domain within destination list | 
| Umbrella.Destinations.id | Unknown | ID of domain within destination list | 
| Umbrella.Destinations.comment | Unknown | Comment associated with domain within destination list | 

### umbrella-search-destination-domains
***
Search for multiple domains in a destination list


#### Base Command

`umbrella-search-destination-domains`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| orgId | Optional orgId, by default uses the one set in the instance configuration. | Optional | 
| destId | Destination list ID to get domains from. Use umbrella-get-destination-lists to get the list ID. | Required | 
| domains | Domains to search for in a destination list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.Destinations.createdAt | date | When the domain within destination list was created | 
| Umbrella.Destinations.type | string | Type of destination within destination list | 
| Umbrella.Destinations.destination | string | Domain within destination list | 
| Umbrella.Destinations.id | number | ID of domain within destination list | 
| Umbrella.Destinations.comment | string | Comment associated with domain within destination list | 