Block URLs, domains and file hashes.
This integration was integrated and tested with version 91.0.6.575 of Netskope (API v2) for contribution to marketplace

## Configure Netskope (API v2) for contribution to marketplace in Cortex


| **Parameter** | **Required** |
| --- | --- |
| URL of Netskope Tenant (e.g. https://tenant.goskope.com) | True |
| API Key | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| Netskope.URLList.id | number | URL List ID | 
| Netskope.URLList.name | string | URL List name | 
| Netskope.URLList.data | unknown | URL List contents | 
| Netskope.URLList.data.urls | unknown | List of URLs in URL List | 
| Netskope.URLList.data.type | string | URL List type ('exact' or 'regex') | 
| Netskope.URLList.modify_by | string | User which last modified URL List | 
| Netskope.URLList.modify_time | date | Time which URL List was last modified | 
| Netskope.URLList.modify_type | string | URL List modification type ('Created', 'Edited' or 'Deleted') | 
| Netskope.URLList.pending | number | URL List pending status ('1' if pending, '0' if not) | 


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
| Netskope.URLList.id | number | URL List ID | 
| Netskope.URLList.name | string | URL List name | 
| Netskope.URLList.data | unknown | URL List contents | 
| Netskope.URLList.data.urls | unknown | List of URLs in URL List | 
| Netskope.URLList.data.type | string | URL List type ('exact' or 'regex') | 
| Netskope.URLList.modify_by | string | User which last modified URL List | 
| Netskope.URLList.modify_time | date | Time which URL List was last modified | 
| Netskope.URLList.modify_type | string | URL List modification type ('Created', 'Edited' or 'Deleted') | 
| Netskope.URLList.pending | number | URL List pending status ('1' if pending, '0' if not) | 


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
| Netskope.List.id | number | URL List ID | 
| Netskope.List.name | string | URL List name | 
| Netskope.List.data | unknown | URL List contents | 
| Netskope.List.data.urls | unknown | List of URLs in URL List | 
| Netskope.List.data.type | string | URL List type ('exact' or 'regex') | 
| Netskope.List.modify_by | string | User which last modified URL List | 
| Netskope.List.modify_time | date | Time which URL List was last modified | 
| Netskope.List.modify_type | string | URL List modification type ('Created', 'Edited' or 'Deleted') | 
| Netskope.List.pending | number | URL List pending status ('1' if pending, '0' if not) | 


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
| Netskope.List.id | number | URL List ID | 
| Netskope.List.name | string | URL List name | 
| Netskope.List.data | unknown | URL List contents | 
| Netskope.List.data.urls | unknown | List of URLs in URL List | 
| Netskope.List.data.type | string | URL List type ('exact' or 'regex') | 
| Netskope.List.modify_by | string | User which last modified URL List | 
| Netskope.List.modify_time | date | Time which URL List was last modified | 
| Netskope.List.modify_type | string | URL List modification type ('Created', 'Edited' or 'Deleted') | 
| Netskope.List.pending | number | URL List pending status ('1' if pending, '0' if not) | 


#### Command Example
``` ```

#### Human Readable Output
