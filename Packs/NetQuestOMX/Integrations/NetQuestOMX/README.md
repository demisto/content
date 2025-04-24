NetQuest’s products are high-capacity service nodes that help security teams access and analyze network traffic. Powerful packet and flow processing features assist security tools in detecting and mitigating security threats as cost effectively as possible.
This integration was integrated and tested with version 3.7.5a of NetQuest OMX.

## Configure NetQuest OMX in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The IP of the 5G device using NetQuest OMX, formatted as https://X.X.X.X | True |
| Username |  | True |
| Password |  | True |
| Slot number | Target NetQuest device slot number. | True |
| Port number | Target NetQuest device port number. | True |
| Fetch Events | Whether to collect events. | False |
| Statistic types to fetch |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### netquest-address-list-upload

***
Uploads a .txt file with the address list to the appliance. The appliance temporarily stores the file until it is saved to the Library and replaces any previously loaded list file.

#### Base Command

`netquest-address-list-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The entry ID of the file to upload. | Required | 

#### Context Output

There is no context output for this command.
### netquest-address-list-optimize

***
Optimizes the updated address list. If the traffic elements are IP addresses, the integration will optimize the list by compressing IP addresses into CIDR groups.

#### Base Command

`netquest-address-list-optimize`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetQuest.AddressList.OverlappingAddresses | list | A list of overlapping addresses in the address list. | 
| NetQuest.AddressList.OverlapsPresent | boolean | A boolean field that indicates whether overlapping IP address ranges are present in the address list. | 
| NetQuest.AddressList.MergedAddresses | list | A list that contains consolidated IP address ranges, combining overlapping or contiguous addresses into a unified set. | 
| NetQuest.AddressList.MergesPresent | boolean | A boolean field that indicates whether any address ranges in the list have been merged to eliminate overlaps or contiguous entries. | 
| NetQuest.AddressList.CountsBefore | Dictionary | A dictionary that stores the number of occurrences of each IP address or address range before any processing or modifications were applied. | 
| NetQuest.AddressList.CountsAfter | Dictionary | A dictionary that stores the number of occurrences of each IP address or address range after processing or modifications have been applied. | 

### netquest-address-list-create

***
Creates a new address list.  This list will replace and override the old list entity.

#### Base Command

`netquest-address-list-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name for the new address list. | Required | 

#### Context Output

There is no context output for this command.
### netquest-address-list-rename

***
Renames an address list. This is only meant to change the name of the list. If you try to give the value of the new_name argument to an existing address list, the command will fail.

#### Base Command

`netquest-address-list-rename`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| new_name | The new name for an existing address list. | Required | 
| existing_name | The name of the address list that you want to modify. | Required | 

#### Context Output

There is no context output for this command.
### netquest-address-list-delete

***
Deletes the address list of the name provided.

#### Base Command

`netquest-address-list-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the address list to delete. | Required | 

#### Context Output

There is no context output for this command.
### get-events

***
Gets events from NetQuest OMX. Each event is a report for the specified statistic type. Available only for Cortex XSIAM.

#### Base Command

`get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | When true, the integration creates Cortex XSIAM events. Otherwise, they will only be displayed. Possible values are: true, false. Default is false. | Required | 
| statistic_types_to_fetch | Comma-separated list of statistic types to return. Default is Metering Stats,Export Stats,Export Peaks FPS,Optimization Stats. | Required | 

#### Context Output

There is no context output for this command.
