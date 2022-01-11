Block URLs, domains and file hashes.
This integration was integrated and tested with version xx of Netskope v2_for contribution to marketplace

## Configure Netskope v2_for contribution to marketplace on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Netskope v2_for contribution to marketplace.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | URL of Netskope Tenant (e.g. https://tenant.goskope.com) | True |
    | API Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### netskopev2-add-url
***
Add URLs to the Netskope URL block list


#### Base Command

`netskopev2-add-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | Name of the URL list. | Required | 
| url | URLs to add to the list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.URLList.id | number |  | 
| Netskope.URLList.name | string |  | 
| Netskope.URLList.data | unknown |  | 
| Netskope.URLList.data.urls | unknown |  | 
| Netskope.URLList.data.type | string |  | 
| Netskope.URLList.modify_by | string |  | 
| Netskope.URLList.modify_time | date |  | 
| Netskope.URLList.modify_type | string |  | 
| Netskope.URLList.pending | number |  | 


#### Command Example
``` ```

#### Human Readable Output



### netskopev2-remove-url
***
Remove URLs from the Netskope URL block list


#### Base Command

`netskopev2-remove-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | Name of the URL list. | Required | 
| url | URLs to remove from the list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.URLList.id | number |  | 
| Netskope.URLList.name | string |  | 
| Netskope.URLList.data | unknown |  | 
| Netskope.URLList.data.urls | unknown |  | 
| Netskope.URLList.data.type | string |  | 
| Netskope.URLList.modify_by | string |  | 
| Netskope.URLList.modify_time | date |  | 
| Netskope.URLList.modify_type | string |  | 
| Netskope.URLList.pending | number |  | 


#### Command Example
``` ```

#### Human Readable Output



### netskopev2-get-lists
***
Get all applied and pending URL lists


#### Base Command

`netskopev2-get-lists`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.List.id | number |  | 
| Netskope.List.name | string |  | 
| Netskope.List.data | unknown |  | 
| Netskope.List.data.urls | unknown |  | 
| Netskope.List.data.type | string |  | 
| Netskope.List.modify_by | string |  | 
| Netskope.List.modify_time | date |  | 
| Netskope.List.modify_type | string |  | 
| Netskope.List.pending | number |  | 


#### Command Example
``` ```

#### Human Readable Output



### netskopev2-get-list
***
Get URL list by ID


#### Base Command

`netskopev2-get-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | Name of the URL list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.List.id | number |  | 
| Netskope.List.name | string |  | 
| Netskope.List.data | unknown |  | 
| Netskope.List.data.urls | unknown |  | 
| Netskope.List.data.type | string |  | 
| Netskope.List.modify_by | string |  | 
| Netskope.List.modify_time | date |  | 
| Netskope.List.modify_type | string |  | 
| Netskope.List.pending | number |  | 


#### Command Example
``` ```

#### Human Readable Output


