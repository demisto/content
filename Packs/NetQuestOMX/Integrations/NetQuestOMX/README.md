NetQuest’s products are high-capacity service nodes that help security teams access and analyze network traffic. Powerful packet & flow processing features assist security tools in detecting and mitigating security threats as cost effectively as possible.
This integration was integrated and tested with version xx of NetQuestOMX.

## Configure NetQuestOMX in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The IP of the device, formatted as https://X.X.X.X | True |
| Username |  | True |
| Password |  | True |
| Slot number |  | True |
| Port number |  | True |
| Fetch Events | Whether to collect events. | False |
| Statistic types to fetch |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### netquest-address-list-upload

***
Address List-Upload - uploads a .txt file with address list to the appliance. The appliance temporarily stores the file until it is saved to the Library and replaces any previously loaded list file.

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
Optimize Updated Address List - If the traffic elements are IP addresses, the integration should optimize the list by compressing IP addresses into CIDR groups.

#### Base Command

`netquest-address-list-optimize`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetQuest.AddressList.OverlappingAddresses | list | Overlapping Addresses. | 
| NetQuest.AddressList.OverlapsPresent | boolean | OverlapsPresent. | 
| NetQuest.AddressList.MergedAddresses | list | MergedAddresses. | 
| NetQuest.AddressList.MergesPresent | boolean | MergesPresent. | 
| NetQuest.AddressList.CountsBefore | Dictionary | CountsBefore. | 
| NetQuest.AddressList.CountsAfter | Dictionary | CountsAfter. | 

### netquest-address-list-create

***
This replaces the old list entity and overrides it.

#### Base Command

`netquest-address-list-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | What to name the new address list. | Required | 

#### Context Output

There is no context output for this command.
### netquest-address-list-rename

***
This is only meant to change the name of the list. Nothing else. If we try to give as a new_name, an existing list name, it will fail and we’ll get an error.

#### Base Command

`netquest-address-list-rename`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| new_name | The new name for an existing address list. | Required | 
| existing_name | The existing list name of the address list that we want to modify. | Required | 

#### Context Output

There is no context output for this command.
### netquest-address-list-delete

***
This command deletes the list by the given address.

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
Gets events from NetQuestOMX. Actually each event is a report for the suitable type. Only for XSIAM.

#### Base Command

`get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | When true, the integration creates Cortex XSIAM events. Otherwise, they will only be displayed. Possible values are: true, false. Default is false. | Required | 
| statistic_types_to_fetch | Comma-separated list of statistic types to return. Default is Metering Stats,Export Stats,Export Peaks FPS,Optimization Stats. | Required | 

#### Context Output

There is no context output for this command.
