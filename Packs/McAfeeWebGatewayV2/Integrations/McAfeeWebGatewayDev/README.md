Blacklist/Whitelist handling
This integration was integrated and tested with version xx of McAfee Web Gateway_dev

## Configure McAfee Web Gateway_dev on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for McAfee Web Gateway_dev.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://192.168.100.55) | True |
    | Server Port | True |
    | Username | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### mwg-get-available-lists
***
Get all available lists


#### Base Command

`mwg-get-available-lists`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | When given, the command will return the list matching this name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MWG.Lists.ID | unknown | List ID | 
| MWG.Lists.Index | unknown | List Index | 


#### Command Example
``` ```

#### Human Readable Output



### mwg-get-list
***
Retrieve a specific list


#### Base Command

`mwg-get-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | List ID. | Optional | 
| list_name | List Name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MWG.ListEntries.ListID | unknown | List ID of entry's list | 
| MWG.ListEntries.Name | unknown | Entry name | 
| MWG.ListEntries.Description | unknown | Entry Description | 
| MWG.ListEntries.Position | unknown | Entry position in list | 
| MWG.Lists.ID | unknown | List ID | 
| MWG.Lists.Name | unknown | List Name | 
| MWG.Lists.Type | unknown | List Type | 
| MWG.Lists.Description | unknown | List Description | 


#### Command Example
``` ```

#### Human Readable Output



### mwg-get-list-entry
***
Retrieve a specific entry from a list


#### Base Command

`mwg-get-list-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | List ID. | Optional | 
| entry_pos | Entry Position in table. | Required | 
| list_name | List Name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MWG.ListEntries.ListID | unknown | List ID of entry's list | 
| MWG.ListEntries.Name | unknown | Entry name | 
| MWG.ListEntries.Description | unknown | Entry Description | 
| MWG.List.Entries.Position | unknown | Entry position in list | 


#### Command Example
``` ```

#### Human Readable Output



### mwg-insert-entry
***
Insert a new entry to a list  (use list_id or list_name)


#### Base Command

`mwg-insert-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | List ID. | Optional | 
| name | Entry Name. | Required | 
| entry_pos | Entry Position in table. | Optional | 
| description | Entry description. | Optional | 
| list_name | List Name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MWG.ListEntries.ListID | unknown | List ID of entry's list | 
| MWG.ListEntries.Name | unknown | Entry name | 
| MWG.ListEntries.Description | unknown | Entry Description | 
| MWG.List.Entries.Position | unknown | Entry position in list | 


#### Command Example
``` ```

#### Human Readable Output



### mwg-delete-entry
***
Delete an entry from a list (use list_id or list_name)


#### Base Command

`mwg-delete-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | List ID. | Optional | 
| entry_pos | Entry Position in table. | Optional | 
| list_name | List Name. | Optional | 
| value | use value instead of entry_pos to delete the exact values. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


