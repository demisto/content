Use the Akamai WAF integration to manage common sets of lists used by various Akamai security products and features.
This integration was integrated and tested with version xx of Akamai WAF_copy

## Configure Akamai WAF_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Akamai WAF_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g., https://example.net) | True |
    | Client token | True |
    | Access token | True |
    | Client secret | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### akamai-get-network-lists
***
Returns a list of all network lists available for an authenticated user who belongs to a group.


#### Base Command

`akamai-get-network-lists`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | The network list type by which to filter the results. Can be "IP" or "GEO". Possible values are: IP, GEO. | Optional | 
| search | The query by which to search for list names and list items. | Optional | 
| extended | When enabled, provides additional response data identifying who created and updated the list and when, and the network list’s deployment status in both STAGING and PRODUCTION environments. This data takes longer to provide. Possible values are: true, false. Default is true. | Optional | 
| include_elements | If enabled, the response list includes all items. For large network lists, this may slow responses and yield large response objects. The default false value when listing more than one network list omits the network list’s elements and only provides higher-level metadata. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.NetworkLists.Lists.Name | String | The network list name. | 
| Akamai.NetworkLists.Lists.Type | String | The network list type. | 
| Akamai.NetworkLists.Lists.UniqueID | String | The network list unique ID. | 
| Akamai.NetworkLists.Lists.ElementCount | String | The number of network list elements. | 
| Akamai.NetworkLists.Lists.CreateDate | Date | The network list creation date. | 
| Akamai.NetworkLists.Lists.CreatedBy | String | The network list creator. | 
| Akamai.NetworkLists.Lists.ExpeditedProductionActivationStatus | String | The expedited production activation status. | 
| Akamai.NetworkLists.Lists.ExpeditedStagingActivationStatus | String | The expedited staging activation status. | 
| Akamai.NetworkLists.Lists.ProductionActivationStatus | String | The production activation status. | 
| Akamai.NetworkLists.Lists.StagingActivationStatus | String | The staging activation status. | 
| Akamai.NetworkLists.Lists.UpdateDate | String | The date that the network list was updated. | 
| Akamai.NetworkLists.Lists.UpdatedBy | String | The last user that updated the network list. | 
| Akamai.NetworkLists.Lists.Elements | String | The elements in the network list. | 


#### Command Example
``` ```

#### Human Readable Output



### akamai-get-network-list-by-id
***
Gets a network list by the network list ID.


#### Base Command

`akamai-get-network-list-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_id | The network list ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.NetworkLists.Lists.Name | String | The network list name. | 
| Akamai.NetworkLists.Lists.Type | String | The network list type. | 
| Akamai.NetworkLists.Lists.UniqueID | String | The network list unique ID. | 
| Akamai.NetworkLists.Lists.ElementCount | String | The number of network list elements. | 
| Akamai.NetworkLists.Lists.CreateDate | Date | The network list creation date. | 
| Akamai.NetworkLists.Lists.CreatedBy | String | The network list creator. | 
| Akamai.NetworkLists.Lists.ExpeditedProductionActivationStatus | String | The expedited production activation status. | 
| Akamai.NetworkLists.Lists.ExpeditedStagingActivationStatus | String | The expedited staging activation status. | 
| Akamai.NetworkLists.Lists.ProductionActivationStatus | String | The production activation status. | 
| Akamai.NetworkLists.Lists.StagingActivationStatus | String | The staging activation status. | 
| Akamai.NetworkLists.Lists.UpdateDate | String | The network list update date. | 
| Akamai.NetworkLists.Lists.UpdatedBy | String | The last user that updated the network list. | 
| Akamai.NetworkLists.Lists.Elements | String | The elements in the network list. | 


#### Command Example
``` ```

#### Human Readable Output



### akamai-create-network-list
***
Creates a new network list. Supports TXT file upload for elements.


#### Base Command

`akamai-create-network-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | The network list name. | Required | 
| list_type | The network list type. Can be "IP" or "GEO". Possible values are: IP, GEO. | Required | 
| elements | The network list elements. | Optional | 
| entry_id | The War Room entry ID of the sample file. | Optional | 
| description | The network list description. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.NetworkLists.Lists.Name | String | The network list name. | 
| Akamai.NetworkLists.Lists.UniqueID | String | The network list ID. | 
| Akamai.NetworkLists.Lists.Type | String | The network list type. | 
| Akamai.NetworkLists.Lists.ElementCount | Number | The number of elements in the list. | 
| Akamai.NetworkLists.Lists.Elements | String | The elements in the list. | 


#### Command Example
``` ```

#### Human Readable Output



### akamai-delete-network-list
***
Deletes the specified network list.


#### Base Command

`akamai-delete-network-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_id | The ID of the network list to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### akamai-activate-network-list
***
Activates a network list on the specified environment.


#### Base Command

`akamai-activate-network-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_ids | A comma-separated list of network list IDs to activate. For example: list (list1,list2). | Required | 
| env | The environment type to activate the network list. Can be "STAGING" OR "PRODUCTION". Possible values are: STAGING, PRODUCTION. | Required | 
| comment | A comment to be logged. | Optional | 
| notify | A comma-separated list of email addresses. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### akamai-add-elements-to-network-list
***
Adds elements to the specified network list.


#### Base Command

`akamai-add-elements-to-network-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_id | The ID of the network in which to add elements. | Required | 
| entry_id | The War Room entry ID of the sample file. | Optional | 
| elements | A comma-separated list of elements to add to the network list. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### akamai-remove-element-from-network-list
***
Removes elements from the specified network list.


#### Base Command

`akamai-remove-element-from-network-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_id | The ID of the network list from which to remove elements. | Required | 
| element | The element to remove from the network list. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### akamai-get-network-list-activation-status
***
Gets the activation status of the specified network list.


#### Base Command

`akamai-get-network-list-activation-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_ids | A comma-separated list of network list IDs for which to get the activation status. For example: (support list - list1,list2). | Required | 
| env | The environment type. Can be "PRODUCTION" or "STAGING". Possible values are: PRODUCTION, STAGING. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.NetworkLists.ActivationStatus.UniqueID | String | The network list ID. | 
| Akamai.NetworkLists.ActivationStatus.StagingStatus | String | The network list environment. | 
| Akamai.NetworkLists.ActivationStatus.ProductionStatus | String | The network list environment activation status. | 


#### Command Example
``` ```

#### Human Readable Output


