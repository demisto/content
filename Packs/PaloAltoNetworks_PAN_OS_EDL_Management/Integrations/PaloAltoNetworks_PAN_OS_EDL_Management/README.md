Deprecated. Use the Generic Export Indicators Service integration instead. This integration is still supported however, for customers with over 1000 Firewalls.
This integration requires root access in order to execute ssh commands. 
If you've configured the server to run Docker images with a non-root internal user make sure to exclude the demisto/openssh Docker image as documented [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users).

## Configure Palo Alto Networks PAN-OS EDL Management in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Hostname or IP of server | True |
| Server port | False |
| SSH credentials to server (username and certificate, see in the credential manager) | True |
| Password | True |
| SSH extra parameters (e.g., "-c ChaCha20") | False |
| SCP extra parameters (e.g., "-c ChaCha20 -l 8000") | False |
| Document root (e.g., var/www/html/files) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pan-os-edl-get-external-file
***
Displays the contents of the specified remote file located in the War Room.


#### Base Command

`pan-os-edl-get-external-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | Unique path to the file on a remote server. | Required | 
| retries | Number of retries. Default is 5. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pan-os-edl-get-external-file file_path=test_playbook_list4.txt```

#### Human Readable Output

>### File Content:
>|List|
>|---|
>| jojo.com |
>| koko.com |
>| upload.wikimedia.org |


### pan-os-edl-search-external-file
***
Searches for a string in a remote file.


#### Base Command

`pan-os-edl-search-external-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | Unique path to the file on a remote server. | Required | 
| search_string | String to search for in the remote file. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pan-os-edl-search-external-file file_path=test_playbook_list4.txt search_string=koko```

#### Human Readable Output

>### Search Results for koko:
>|Result|
>|---|
>|  |
>| koko.com |


### pan-os-edl-update
***
Updates the instance context with the specified list name and list items, and then overrides the path of the remote file with the internal list.


#### Base Command

`pan-os-edl-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | List from the instance context with which to override the remote file. | Required | 
| file_path | Unique path to file. | Required | 
| verbose | Prints the updated remote file to the War Room. Default is "false". Possible values are: true, false. Default is false. | Optional | 
| list_items | List items. | Required | 
| add_or_remove | Whether to add to, or remove from the list. Default is "add". Possible values are: add, remove. Default is add. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pan-os-edl-update add_or_remove=remove file_path=test_playbook_list4.txt list_items=toto.com list_name=test_playbook_list4 verbose=true```

#### Human Readable Output

>### Updated File Data:
>|Data|
>|---|
>| jojo.com<br/>koko.com<br/>upload.wikimedia.org |


### pan-os-edl-update-from-external-file
***
Updates internal list data with the contents of a remote file.


#### Base Command

`pan-os-edl-update-from-external-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | Unique path to the file on a remote server. | Required | 
| list_name | List name. | Required | 
| type | Update type. "Merge" adds non-duplicate values, "Override" deletes existing data in the internal list. Default is "merge". Possible values are: merge, override. Default is merge. | Required | 
| verbose | Prints the updated internal list to the War Room. Default is "false". Possible values are: true, false. Default is false. | Optional | 
| retries | Number of retries. Default is 5. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pan-os-edl-update-from-external-file file_path=test_playbook_list4.txt list_name=test_playbook_list4 type=override```

#### Human Readable Output

>Instance context updated successfully

### pan-os-edl-delete-external-file
***
Deletes a file from a remote server.


#### Base Command

`pan-os-edl-delete-external-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | Unique path to the file on a remote server. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pan-os-edl-delete-external-file file_path=test_playbook_list5.txt```

#### Human Readable Output

>File deleted successfully

### pan-os-edl-print-internal-list
***
Displays internal list data in the War Room.


#### Base Command

`pan-os-edl-print-internal-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | List name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pan-os-edl-print-internal-list list_name=test_playbook_list4```

#### Human Readable Output

>### List items:
>|test_playbook_list4|
>|---|
>| jojo.com |
>| koko.com |
>| upload.wikimedia.org |


### pan-os-edl-dump-internal-list
***
Dumps (copies) instance context to either the incident context or a file.


#### Base Command

`pan-os-edl-dump-internal-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| destination | List data destination. Default is "file". Possible values are: file, incident_context. Default is file. | Required | 
| list_name | List name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOSEDL.ListItems | string | Items of the internal list. | 
| PANOSEDL.ListName | string | Name of the internal list. | 


#### Command Example
```!pan-os-edl-dump-internal-list list_name=test_playbook_list4 destination=incident_context```

#### Context Example
```json
{
    "PANOSEDL": {
        "ListItems": [
            "jojo.com",
            "koko.com",
            "upload.wikimedia.org"
        ],
        "ListName": "test_playbook_list4"
    }
}
```

#### Human Readable Output

>### List items:
>|test_playbook_list4|
>|---|
>| jojo.com |
>| koko.com |
>| upload.wikimedia.org |


### pan-os-edl-list-internal-lists
***
Displays instance context list names.


#### Base Command

`pan-os-edl-list-internal-lists`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!pan-os-edl-list-internal-lists```

#### Human Readable Output

>### Instance context Lists:
>|List names|
>|---|
>| test_playbook_list4 |


### pan-os-edl-search-internal-list
***
Search for a string in internal list.


#### Base Command

`pan-os-edl-search-internal-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | Name of list. | Required | 
| search_string | String to search for in the remote file. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pan-os-edl-search-internal-list list_name=test_playbook_list4 search_string=koko.com```

#### Human Readable Output

>Search string koko.com is in the internal list test_playbook_list4.

### pan-os-edl-compare
***
Compares internal list and external file contents.


#### Base Command

`pan-os-edl-compare`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | List name. | Required | 
| file_path | Unique path to the file on a remote server. | Required | 
| retries | Number of retries. Default is 5. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pan-os-edl-compare file_path=test_playbook_list4.txt list_name=list_name=test_playbook_list4```

#### Human Readable Output

>List was not found in instance context.

### pan-os-edl-get-external-file-metadata
***
Gets metadata for an external file.


#### Base Command

`pan-os-edl-get-external-file-metadata`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | Unique path to the file on a remote server. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOSEDL.FileName | String | Name of the external file. | 
| PANOSEDL.Size | Number | File size. | 
| PANOSEDL.NumberOfLines | Number | Number of lines. | 
| PANOSEDL.LastModified | String | Date that the file was last modified. | 


#### Command Example
```!pan-os-edl-get-external-file-metadata file_path=test_playbook_list4.txt```

#### Context Example
```json
{
    "PANOSEDL": {
        "FileName": "test_playbook_list4.txt",
        "LastModified": "2021-07-11 06:46:21.290803188",
        "NumberOfLines": 3,
        "Size": 38
    }
}
```

#### Human Readable Output

>### File metadata:
>|FileName|Size|NumberOfLines|LastModified|
>|---|---|---|---|
>| test_playbook_list4.txt | 38 | 3 | 2021-07-11 06:46:21.290803188 |


### pan-os-edl-update-internal-list
***
Updates the instance context with the specified list name and list items.


#### Base Command

`pan-os-edl-update-internal-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | The list from the instance context to update. | Required | 
| list_items | An array of list items. | Required | 
| verbose | Whether to print the updated remote file to the War Room. Can ve "true" or "false". Default is "false". Possible values are: true, false. Default is false. | Optional | 
| add_or_remove | Whether to add to, or remove from the list. Can be "add" or "remove". Default is "add". Possible values are: add, remove. Default is add. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pan-os-edl-update-internal-list add_or_remove=add list_items=toto.com list_name=test_playbook_list4```

#### Human Readable Output

>Instance context updated successfully.

### pan-os-edl-update-external-file
***
Updates a remote file with the contents of an internal list.


#### Base Command

`pan-os-edl-update-external-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | Unique path to the file on a remote server. | Required | 
| list_name | List name. | Required | 
| verbose | Whether to add to, or remove from the list. Can be "add" or "remove". Default is "add". Possible values are: true, false. Default is false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pan-os-edl-update-external-file file_path=test_playbook_list4.txt list_name=test_playbook_list4 verbose=true```

#### Human Readable Output

>### Updated File Data:
>|Data|
>|---|
>| jojo.com<br/>koko.com<br/>toto.com<br/>upload.wikimedia.org |
