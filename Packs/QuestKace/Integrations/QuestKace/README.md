This is the Quest KACE integration.
This integration was integrated and tested with version v10.0.290 of QuestKace

## Limitations
For **kace-ticket-create** and **kace-ticket-update**, When the queue_id is not the default:
Status,Category,Priority,Impact - values from the option list might cause an error as they correspond to different values.
If a value not from the list will be inserted - This value will pass to the API as is.
e.g. **kace-ticket-create status="Opened" impact=13 Priority=25**

Tickets custom fields will not be returned in the **kace-tickets-list** command and not in fetch incidents due to API limitation.

Custom fields of tickets are represented by their custom number and not but their display name. e.g. For custom field: custom_1 with display name: date, the command should be **!kace-ticket-create custom_fields=`custom_1=testfromdemisto`**



## Configure QuestKace in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Quest KACE URL, in the format: `https://company.works.com/` | True |
| credentials | Username | True |
| isFetch | Fetch incidents | False |
| fetch_time | First fetch time range \(&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes\) | False |
| fetch_shaping | Shaping query parameter for tickets | False |
| fetch_filter | Filter for the tickets | False |
| fetch_limit | Fetch limit per query | False |
| fetch_queue_id | Queue number for fetch query | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### kace-machines-list
***
Returns a list of all machines in system.


#### Base Command

`kace-machines-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of machines to return. The default value is 50. | Optional | 
| custom_filter | Filter for the query. Each filter is specified by an optional entity name, a field name, an<br/>operator, and a value. e.g. "title eq test" / "id gt 1 / hd_queue_id in 1;2;3" . Combination of filters is seperated by comma. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QuestKace.Machine.ID | String | ID of machine | 
| QuestKace.Machine.Modified | String | Last modified date of the machine. | 
| QuestKace.Machine.Created | String | Created date of the machine in KACE system. | 
| QuestKace.Machine.User | String | User of the machine. | 
| QuestKace.Machine.Name | String | Name of the machine. | 
| QuestKace.Machine.IP | String | IP address of the machine. | 
| QuestKace.Machine.OSName | String | OS name of the machine. | 
| QuestKace.Machine.OSNumber | String | Number of operating systems of the machine. | 
| QuestKace.Machine.LastInventory | String | Last inventory date of the machine. | 
| QuestKace.Machine.LastSync | String | Last sync date of the machine. | 
| QuestKace.Machine.RamTotal | String | Total RAM of the machine in bytes. | 
| QuestKace.Machine.RamUsed | String | Used RAM of the machine. | 
| QuestKace.Machine.RamMax | String | Maximum RAM of the machine. | 
| QuestKace.Machine.BiosIdentificationCode | String | BIOS identification code of the machine. | 
| QuestKace.Machine.SoundDevices | String | Connected sound devices of the machine. | 
| QuestKace.Machine.CdromDevices | String | Connected CD\-ROM devices to the machine. | 
| QuestKace.Machine.VideoControllers | String | Video controllers of the machine. | 
| QuestKace.Machine.Monitor | String | Monitor of the machine. | 
| QuestKace.Machine.RegistrySize | String | Registry size of the machine. | 
| QuestKace.Machine.RegistryMaxSize | String | Maximum size of the registry of the machine. | 
| QuestKace.Machine.PagefileSize | String | Size of the page file of the machine. | 
| QuestKace.Machine.PagefileMaxSize | String | Maximum size of the page file of the machine. | 
| QuestKace.Machine.ManualEntry | String | Number of manual entries to the machine. | 


#### Command Example
```!kace-machines-list custom_filter="id gt 1"```

#### Context Example
```
{
    "QuestKace": {
        "Machine": null
    }
}
```

#### Human Readable Output

>### Quest Kace Machines
>**No entries.**


### kace-assets-list
***
Returns a list of all assets in Quest KACE.


#### Base Command

`kace-assets-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of assets to return. The default value is 50. | Optional | 
| custom_filter | Filter for the query. Each filter is specified by an optional entity name, a field name, an<br/>operator, and a value. e.g. "title eq test" / "id gt 1 / hd_queue_id in 1;2;3" . Combination of filters is seperated by comma. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QuestKace.Asset.ID | Number | ID of the asset. | 
| QuestKace.Asset.AssetTypeID | Number | Type ID of the asset. | 
| QuestKace.Asset.Name | String | Name of the asset. | 
| QuestKace.Asset.AssetDataID | Number | Data ID of the asset. | 
| QuestKace.Asset.OwnerID | Number | Owner ID of the asset. | 
| QuestKace.Asset.Modified | String | Last modified date of the asset. | 
| QuestKace.Asset.Created | String | Created date of the asset. | 
| QuestKace.Asset.MappedID | Number | Mapped ID of the asset. | 
| QuestKace.Asset.AssetClassID | Number | Class ID of the asset. | 
| QuestKace.Asset.Archieve | String | Archive of the asset. | 
| QuestKace.Asset.AssetStatusID | Number | Status ID of the asset. | 
| QuestKace.Asset.AssetTypeName | String | Type name of the asset. | 


#### Command Example
```!kace-assets-list custom_filter="name eq Mac"```

#### Context Example
```
{
    "QuestKace": {
        "Asset": {
            "Archive": "",
            "AssetClassID": 10000,
            "AssetDataID": 1,
            "AssetStatusID": 0,
            "AssetSubtypeName": "Laser Printer: Color",
            "AssetTypeID": 5,
            "AssetTypeName": "Device",
            "Created": "2020-06-09 03:57:30",
            "ID": 2,
            "MappedID": 0,
            "Modified": "2020-06-09 03:57:30",
            "Name": "Mac",
            "OwnerID": 0
        }
    }
}
```

#### Human Readable Output

>### Quest Kace Assets
>|ID|Name|Created|Modified|OwnerID|MappedID|AssetClassID|AssetDataID|AssetStatusID|AssetTypeID|AssetTypeName|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 2 | Mac | 2020-06-09 03:57:30 | 2020-06-09 03:57:30 | 0 | 0 | 10000 | 1 | 0 | 5 | Device |


### kace-queues-list
***
Returns a list of all queues in Quest KACE.


#### Base Command

`kace-queues-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of tickets to return. The default value is 50. | Optional | 
| custom_filter | Filter for the query. Each filter is specified by an optional entity name, a field name, an<br/>operator, and a value. e.g. "title eq test" / "id gt 1 / hd_queue_id in 1;2;3" . Combination of filters is seperated by comma. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QuestKace.Queue.ID | Number | ID of the queue. | 
| QuestKace.Queue.Name | String | Name of the queue. | 
| QuestKace.Queue.Field.ID | Number | ID of the field of the queue. | 
| QuestKace.Queue.Field.HdQueueID | Number | Queue ID of the field. | 
| QuestKace.Queue.Field.Name | String | Name of the field. | 
| QuestKace.Queue.Field.HdTicketFieldName | String | View field name. | 
| QuestKace.Queue.Field.Ordinal | Number | Ordinal of the field. | 
| QuestKace.Queue.Field.RequiredState | String | Required state of the field, if exists. | 
| QuestKace.Queue.Field.FieldLabel | String | Field label. | 
| QuestKace.Queue.Field.Visible | String | Visibility of the field. | 


#### Command Example
```!kace-queues-list custom_filter="id neq 1"```

#### Context Example
```
{
    "QuestKace": {
        "Queue": {
            "Fields": [
                {
                    "FieldLabel": "Please tell us about your recent help desk experience",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "sat_survey",
                    "ID": 36,
                    "Name": "SAT_SURVEY",
                    "Ordinal": 0,
                    "RequiredState": "none",
                    "Visible": "usermodify"
                },
                {
                    "FieldLabel": "Title",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "title",
                    "ID": 37,
                    "Name": "TITLE",
                    "Ordinal": 1,
                    "RequiredState": "all",
                    "Visible": "usercreate"
                },
                {
                    "FieldLabel": "Summary",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "summary",
                    "ID": 38,
                    "Name": "SUMMARY",
                    "Ordinal": 2,
                    "RequiredState": "none",
                    "Visible": "usercreate"
                },
                {
                    "FieldLabel": "Impact",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "impact_id",
                    "ID": 39,
                    "Name": "IMPACT",
                    "Ordinal": 3,
                    "RequiredState": "none",
                    "Visible": "usercreate"
                },
                {
                    "FieldLabel": "Category",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "category_id",
                    "ID": 40,
                    "Name": "CATEGORY",
                    "Ordinal": 4,
                    "RequiredState": "none",
                    "Visible": "usercreate"
                },
                {
                    "FieldLabel": "Status",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "status_id",
                    "ID": 41,
                    "Name": "STATUS",
                    "Ordinal": 5,
                    "RequiredState": "none",
                    "Visible": "uservisible"
                },
                {
                    "FieldLabel": "Priority",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "priority_id",
                    "ID": 42,
                    "Name": "PRIORITY",
                    "Ordinal": 6,
                    "RequiredState": "none",
                    "Visible": "uservisible"
                },
                {
                    "FieldLabel": "Owner",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "owner_id",
                    "ID": 43,
                    "Name": "OWNER",
                    "Ordinal": 7,
                    "RequiredState": "none",
                    "Visible": "uservisible"
                },
                {
                    "FieldLabel": "Device",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "machine_id",
                    "ID": 44,
                    "Name": "MACHINE",
                    "Ordinal": 8,
                    "RequiredState": "none",
                    "Visible": "uservisible"
                },
                {
                    "FieldLabel": "Asset",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "asset_id",
                    "ID": 45,
                    "Name": "ASSET",
                    "Ordinal": 9,
                    "RequiredState": "none",
                    "Visible": "uservisible"
                },
                {
                    "FieldLabel": "Due Date",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "due_date",
                    "ID": 61,
                    "Name": "DUE_DATE",
                    "Ordinal": 25,
                    "RequiredState": "none",
                    "Visible": "userhidden"
                },
                {
                    "FieldLabel": "CC List",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "cc_list",
                    "ID": 62,
                    "Name": "CC_LIST",
                    "Ordinal": 26,
                    "RequiredState": "none",
                    "Visible": "userhidden"
                },
                {
                    "FieldLabel": "Created",
                    "HdQueueID": 3,
                    "ID": 63,
                    "Name": "CREATED",
                    "Ordinal": 27,
                    "RequiredState": "none",
                    "Visible": "uservisible"
                },
                {
                    "FieldLabel": "Modified",
                    "HdQueueID": 3,
                    "ID": 64,
                    "Name": "MODIFIED",
                    "Ordinal": 28,
                    "RequiredState": "none",
                    "Visible": "uservisible"
                },
                {
                    "FieldLabel": "Submitter",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "submitter_id",
                    "ID": 65,
                    "Name": "SUBMITTER",
                    "Ordinal": 29,
                    "RequiredState": "none",
                    "Visible": "usercreate"
                },
                {
                    "FieldLabel": "See Also",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "related_ticket_ids",
                    "ID": 68,
                    "Name": "SEE_ALSO",
                    "Ordinal": 32,
                    "RequiredState": "none",
                    "Visible": "userhidden"
                },
                {
                    "FieldLabel": "Referrers",
                    "HdQueueID": 3,
                    "ID": 69,
                    "Name": "REFERRERS",
                    "Ordinal": 33,
                    "RequiredState": "none",
                    "Visible": "userhidden"
                },
                {
                    "FieldLabel": "Resolution",
                    "HdQueueID": 3,
                    "HdTicketFieldName": "resolution",
                    "ID": 70,
                    "Name": "RESOLUTION",
                    "Ordinal": 34,
                    "RequiredState": "none",
                    "Visible": "uservisible"
                }
            ],
            "ID": 3,
            "Name": "New Queue 2"
        }
    }
}
```

#### Human Readable Output

>### Quest Kace Queues
>|ID|Name|Fields|
>|---|---|---|
>| 3 | New Queue 2 | {'ID': 36, 'HdQueueID': 3, 'Name': 'SAT_SURVEY', 'HdTicketFieldName': 'sat_survey', 'Ordinal': 0, 'RequiredState': 'none', 'FieldLabel': 'Please tell us about your recent help desk experience', 'Visible': 'usermodify'},<br/>{'ID': 37, 'HdQueueID': 3, 'Name': 'TITLE', 'HdTicketFieldName': 'title', 'Ordinal': 1, 'RequiredState': 'all', 'FieldLabel': 'Title', 'Visible': 'usercreate'},<br/>{'ID': 38, 'HdQueueID': 3, 'Name': 'SUMMARY', 'HdTicketFieldName': 'summary', 'Ordinal': 2, 'RequiredState': 'none', 'FieldLabel': 'Summary', 'Visible': 'usercreate'},<br/>{'ID': 39, 'HdQueueID': 3, 'Name': 'IMPACT', 'HdTicketFieldName': 'impact_id', 'Ordinal': 3, 'RequiredState': 'none', 'FieldLabel': 'Impact', 'Visible': 'usercreate'},<br/>{'ID': 40, 'HdQueueID': 3, 'Name': 'CATEGORY', 'HdTicketFieldName': 'category_id', 'Ordinal': 4, 'RequiredState': 'none', 'FieldLabel': 'Category', 'Visible': 'usercreate'},<br/>{'ID': 41, 'HdQueueID': 3, 'Name': 'STATUS', 'HdTicketFieldName': 'status_id', 'Ordinal': 5, 'RequiredState': 'none', 'FieldLabel': 'Status', 'Visible': 'uservisible'},<br/>{'ID': 42, 'HdQueueID': 3, 'Name': 'PRIORITY', 'HdTicketFieldName': 'priority_id', 'Ordinal': 6, 'RequiredState': 'none', 'FieldLabel': 'Priority', 'Visible': 'uservisible'},<br/>{'ID': 43, 'HdQueueID': 3, 'Name': 'OWNER', 'HdTicketFieldName': 'owner_id', 'Ordinal': 7, 'RequiredState': 'none', 'FieldLabel': 'Owner', 'Visible': 'uservisible'},<br/>{'ID': 44, 'HdQueueID': 3, 'Name': 'MACHINE', 'HdTicketFieldName': 'machine_id', 'Ordinal': 8, 'RequiredState': 'none', 'FieldLabel': 'Device', 'Visible': 'uservisible'},<br/>{'ID': 45, 'HdQueueID': 3, 'Name': 'ASSET', 'HdTicketFieldName': 'asset_id', 'Ordinal': 9, 'RequiredState': 'none', 'FieldLabel': 'Asset', 'Visible': 'uservisible'},<br/>{'ID': 61, 'HdQueueID': 3, 'Name': 'DUE_DATE', 'HdTicketFieldName': 'due_date', 'Ordinal': 25, 'RequiredState': 'none', 'FieldLabel': 'Due Date', 'Visible': 'userhidden'},<br/>{'ID': 62, 'HdQueueID': 3, 'Name': 'CC_LIST', 'HdTicketFieldName': 'cc_list', 'Ordinal': 26, 'RequiredState': 'none', 'FieldLabel': 'CC List', 'Visible': 'userhidden'},<br/>{'ID': 63, 'HdQueueID': 3, 'Name': 'CREATED', 'Ordinal': 27, 'RequiredState': 'none', 'FieldLabel': 'Created', 'Visible': 'uservisible'},<br/>{'ID': 64, 'HdQueueID': 3, 'Name': 'MODIFIED', 'Ordinal': 28, 'RequiredState': 'none', 'FieldLabel': 'Modified', 'Visible': 'uservisible'},<br/>{'ID': 65, 'HdQueueID': 3, 'Name': 'SUBMITTER', 'HdTicketFieldName': 'submitter_id', 'Ordinal': 29, 'RequiredState': 'none', 'FieldLabel': 'Submitter', 'Visible': 'usercreate'},<br/>{'ID': 68, 'HdQueueID': 3, 'Name': 'SEE_ALSO', 'HdTicketFieldName': 'related_ticket_ids', 'Ordinal': 32, 'RequiredState': 'none', 'FieldLabel': 'See Also', 'Visible': 'userhidden'},<br/>{'ID': 69, 'HdQueueID': 3, 'Name': 'REFERRERS', 'Ordinal': 33, 'RequiredState': 'none', 'FieldLabel': 'Referrers', 'Visible': 'userhidden'},<br/>{'ID': 70, 'HdQueueID': 3, 'Name': 'RESOLUTION', 'HdTicketFieldName': 'resolution', 'Ordinal': 34, 'RequiredState': 'none', 'FieldLabel': 'Resolution', 'Visible': 'uservisible'} |


### kace-tickets-list
***
Returns a list of all tickets in Quest KACE.


#### Base Command

`kace-tickets-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| custom_shaping | The shaping query parameter limits the amount of returned data is specified. The returned fields for each<br/>associated entity is controlled by two query values. The first is the name of the entity, while the second half of the<br/>pair is the associated level. e.g. "submitter all, asset limited". | Optional | 
| limit | The maximum number of tickets to return. The default value is 50. | Optional | 
| custom_filter | Filter for the query. Each filter is specified by an optional entity name, a field name, an<br/>operator, and a value. e.g. "title eq test" / "id gt 1 / hd_queue_id in 1;2;3" . Combination of filters is seperated by comma. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QuestKace.Ticket.Submitter.ID | Number | Submitter id of the ticket. | 
| QuestKace.Ticket.Submitter.UserName | String | Submitter user name of the ticket. | 
| QuestKace.Ticket.Submitter.Email | String | Email address of user that submitted the email. | 
| QuestKace.Ticket.Submitter.FullName | String | Full name of the user that submitted the ticket. | 
| QuestKace.Ticket.Asset.ID | Number | ID of the asset of the ticket. | 
| QuestKace.Ticket.Asset.AssetTypeId | Number | Asset type ID of the ticket. | 
| QuestKace.Ticket.Asset.Name | String | Name of the asset of the ticket. | 
| QuestKace.Ticket.Asset.OwnerId | Number | Owner ID of the asset of the ticket. | 
| QuestKace.Ticket.Asset.AssetClassId | Number | Asset class id of the ticket. | 
| QuestKace.Ticket.Machine.ID | Number | ID of the machine of the ticket. | 
| QuestKace.Ticket.Machine.Name | String | Name of the machine of the ticket. | 
| QuestKace.Ticket.Priority.ID | Number | Priority id of the ticket. | 
| QuestKace.Ticket.Priority.Name | String | Priority name of the ticket. | 
| QuestKace.Ticket.Priority.Ordinal | Number | Priority ordinal of the ticket. | 
| QuestKace.Ticket.Priority.Color | String | Priority color of the ticket. | 
| QuestKace.Ticket.Priority.IsSlaEnable | Number | Whether SLA is enabled on the priority of the ticket. | 
| QuestKace.Ticket.Category.ID | Number | Category ID of the ticket. | 
| QuestKace.Ticket.Category.Name | String | Category name of the ticket. | 
| QuestKace.Ticket.Impact.ID | Number | ID of the impact of the ticket. | 
| QuestKace.Ticket.Impact.Ordinal | Number | Ordinal of the impact of the ticket. | 
| QuestKace.Ticket.Impact.Name | String | Name of the impact of the ticket. | 
| QuestKace.Ticket.Status.ID | Number | ID of the status of the ticket. | 
| QuestKace.Ticket.Status.Name | String | Name of the status of the tickets. | 
| QuestKace.Ticket.Status.Ordinal | Number | Ordinal of the status of the ticket. | 
| QuestKace.Ticket.Status.State | String | State of the status of the ticket. | 
| QuestKace.Ticket.ID | Number | ID of the ticket. | 
| QuestKace.Ticket.Title | String | Title of the ticket. | 
| QuestKace.Ticket.Summary | String | Summary of the ticket. | 
| QuestKace.Ticket.Modified | String | Last modified date of the ticket. | 
| QuestKace.Ticket.Created | String | Created date of the ticket. | 
| QuestKace.Ticket.HdQueueID | Number | Queue number that the ticket is related to. | 
| QuestKace.Ticket.CcList | String | CC list of the ticket. | 
| QuestKace.Ticket.IsManualDueDate | Number | Whether the due date is manual. | 
| QuestKace.Ticket.Resolution | String | Resolution of the ticket. | 
| QuestKace.Ticket.DueDate | String | Dua date of the ticket. | 


#### Command Example
```!kace-tickets-list custom_shaping="hd_ticket all,submitter limited,owner limited, asset limited,machine limited,priority limited,category limited, impact limited,status limited"```

#### Context Example
```
{
    "QuestKace": {
        "Ticket": [
            {
                "Category": {
                    "ID": 2,
                    "Name": "Other"
                },
                "CcList": "",
                "Created": "2020-05-19 05:54:42",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 11,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-05-19 05:54:42",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 4,
                    "Name": "New",
                    "Ordinal": 0,
                    "State": "stalled"
                },
                "Summary": "",
                "Title": "Untitled"
            },
            {
                "Category": {
                    "ID": 2,
                    "Name": "Other"
                },
                "CcList": "",
                "Created": "2020-05-19 05:55:43",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 12,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-05-19 05:55:43",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 4,
                    "Name": "New",
                    "Ordinal": 0,
                    "State": "stalled"
                },
                "Summary": "",
                "Title": "test num 2 from demisto"
            },
            {
                "Category": {
                    "ID": 2,
                    "Name": "Other"
                },
                "CcList": "",
                "Created": "2020-05-19 05:56:08",
                "HdQueueID": 1,
                "ID": 13,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-05-19 06:16:17",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 2,
                    "Name": "Closed",
                    "Ordinal": 3,
                    "State": "closed"
                },
                "Summary": "",
                "Title": "test num 4 from demisto"
            },
            {
                "Category": {
                    "ID": 2,
                    "Name": "Other"
                },
                "CcList": "",
                "Created": "2020-05-19 06:15:48",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 14,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-05-19 06:15:48",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 2,
                    "Name": "Closed",
                    "Ordinal": 3,
                    "State": "closed"
                },
                "Summary": "dont know",
                "Title": "test num 3 from demisto"
            },
            {
                "Category": {
                    "ID": 2,
                    "Name": "Other"
                },
                "CcList": "",
                "Created": "2020-05-19 07:01:12",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 15,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-05-19 07:01:12",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 4,
                    "Name": "New",
                    "Ordinal": 0,
                    "State": "stalled"
                },
                "Submitter": {
                    "Email": "tmalache@paloaltonetworks.com",
                    "FullName": "admin",
                    "ID": 10,
                    "UserName": "admin"
                },
                "Summary": "",
                "Title": "TestCustomFieldsUI"
            },
            {
                "Category": {
                    "ID": 3,
                    "Name": "Hardware"
                },
                "CcList": "",
                "Created": "2020-05-19 07:02:30",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 16,
                "Impact": {
                    "ID": 3,
                    "Name": "1 person inconvenienced",
                    "Ordinal": 3
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-05-19 07:02:30",
                "Priority": {
                    "Color": "gray",
                    "ID": 3,
                    "IsSlaEnabled": 0,
                    "Name": "Low",
                    "Ordinal": 2
                },
                "Resolution": "",
                "Status": {
                    "ID": 8,
                    "Name": "Waiting on Third Party",
                    "Ordinal": 7,
                    "State": "stalled"
                },
                "Summary": "just checking",
                "Title": "TATATA"
            },
            {
                "Category": {
                    "ID": 2,
                    "Name": "Other"
                },
                "CcList": "",
                "Created": "2020-05-19 07:03:30",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 17,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-05-19 07:03:30",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 2,
                    "Name": "Closed",
                    "Ordinal": 3,
                    "State": "closed"
                },
                "Summary": "dont know",
                "Title": "test num 3 from demisto"
            },
            {
                "Category": {
                    "ID": 1,
                    "Name": "Network"
                },
                "CcList": "",
                "Created": "2020-06-09 03:52:25",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 23,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-06-09 03:52:25",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 1,
                    "Name": "Opened",
                    "Ordinal": 1,
                    "State": "opened"
                },
                "Summary": "test of Quest Kace integration ticket create",
                "Title": "test1"
            },
            {
                "Category": {
                    "ID": 2,
                    "Name": "Other"
                },
                "CcList": "",
                "Created": "2020-06-09 03:55:07",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 24,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-06-09 03:55:07",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 4,
                    "Name": "New",
                    "Ordinal": 0,
                    "State": "stalled"
                },
                "Submitter": {
                    "Email": "tmalache@paloaltonetworks.com",
                    "FullName": "admin",
                    "ID": 10,
                    "UserName": "admin"
                },
                "Summary": "",
                "Title": "test"
            },
            {
                "Category": {
                    "ID": 1,
                    "Name": "Network"
                },
                "CcList": "",
                "Created": "2020-06-09 03:59:41",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 25,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-06-09 03:59:41",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 1,
                    "Name": "Opened",
                    "Ordinal": 1,
                    "State": "opened"
                },
                "Summary": "test of Quest Kace integration ticket create",
                "Title": "test1"
            },
            {
                "Category": {
                    "ID": 1,
                    "Name": "Network"
                },
                "CcList": "",
                "Created": "2020-06-09 04:00:03",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 26,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-06-09 04:00:03",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 1,
                    "Name": "Opened",
                    "Ordinal": 1,
                    "State": "opened"
                },
                "Summary": "test of Quest Kace integration ticket create",
                "Title": "test1"
            },
            {
                "Category": {
                    "ID": 1,
                    "Name": "Network"
                },
                "CcList": "",
                "Created": "2020-06-09 04:00:33",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 27,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-06-09 04:00:33",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 1,
                    "Name": "Opened",
                    "Ordinal": 1,
                    "State": "opened"
                },
                "Summary": "test of Quest Kace integration ticket create",
                "Title": "test1"
            },
            {
                "Category": {
                    "ID": 1,
                    "Name": "Network"
                },
                "CcList": "",
                "Created": "2020-06-09 04:57:39",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 28,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-06-09 04:57:39",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 1,
                    "Name": "Opened",
                    "Ordinal": 1,
                    "State": "opened"
                },
                "Summary": "test of Quest Kace integration ticket create",
                "Title": "test1"
            },
            {
                "Category": {
                    "ID": 3,
                    "Name": "Hardware"
                },
                "CcList": "",
                "Created": "2020-06-09 05:12:37",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 30,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-06-09 05:12:37",
                "Priority": {
                    "Color": "red",
                    "ID": 2,
                    "IsSlaEnabled": 0,
                    "Name": "High",
                    "Ordinal": 0
                },
                "Resolution": "",
                "Status": {
                    "ID": 2,
                    "Name": "Closed",
                    "Ordinal": 3,
                    "State": "closed"
                },
                "Summary": "Test docs",
                "Title": "Test"
            },
            {
                "CcList": "",
                "Created": "2020-06-09 05:14:51",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 31,
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-06-09 05:14:51",
                "Resolution": "",
                "Summary": "blah blah",
                "Title": "foo foo"
            },
            {
                "Category": {
                    "ID": 1,
                    "Name": "Network"
                },
                "CcList": "",
                "Created": "2020-06-09 05:18:10",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 33,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-06-09 05:18:10",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 1,
                    "Name": "Opened",
                    "Ordinal": 1,
                    "State": "opened"
                },
                "Summary": "test of Quest Kace integration ticket create",
                "Title": "test1"
            },
            {
                "Category": {
                    "ID": 1,
                    "Name": "Network"
                },
                "CcList": "",
                "Created": "2020-06-09 05:19:13",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 1,
                "ID": 34,
                "Impact": {
                    "ID": 1,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-06-09 05:19:13",
                "Priority": {
                    "Color": "",
                    "ID": 1,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 1,
                    "Name": "Opened",
                    "Ordinal": 1,
                    "State": "opened"
                },
                "Summary": "test of Quest Kace integration ticket create",
                "Title": "test1"
            },
            {
                "Category": {
                    "ID": 5,
                    "Name": "Software"
                },
                "CcList": "",
                "Created": "2020-06-09 05:11:59",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 3,
                "ID": 29,
                "Impact": {
                    "ID": 7,
                    "Name": "1 person cannot work",
                    "Ordinal": 2
                },
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-06-09 05:11:59",
                "Priority": {
                    "Color": "",
                    "ID": 5,
                    "IsSlaEnabled": 0,
                    "Name": "Medium",
                    "Ordinal": 1
                },
                "Resolution": "",
                "Status": {
                    "ID": 9,
                    "Name": "New",
                    "Ordinal": 0,
                    "State": "stalled"
                },
                "Submitter": {
                    "Email": "tmalache@paloaltonetworks.com",
                    "FullName": "admin",
                    "ID": 10,
                    "UserName": "admin"
                },
                "Summary": "",
                "Title": "Tests"
            },
            {
                "CcList": "",
                "Created": "2020-06-09 05:14:55",
                "DueDate": "0000-00-00 00:00:00",
                "HdQueueID": 3,
                "ID": 32,
                "IsDeleted": false,
                "IsManualDueDate": 0,
                "Modified": "2020-06-09 05:14:55",
                "Resolution": "",
                "Summary": "blah blah",
                "Title": "foo foo"
            }
        ]
    }
}
```

#### Human Readable Output

>### Quest Kace Tickets
>|ID|Title|Created|Modified|HdQueueID|DueDate|
>|---|---|---|---|---|---|
>| 11 | Untitled | 2020-05-19 05:54:42 | 2020-05-19 05:54:42 | 1 | 0000-00-00 00:00:00 |
>| 12 | test num 2 from demisto | 2020-05-19 05:55:43 | 2020-05-19 05:55:43 | 1 | 0000-00-00 00:00:00 |
>| 13 | test num 4 from demisto | 2020-05-19 05:56:08 | 2020-05-19 06:16:17 | 1 |  |
>| 14 | test num 3 from demisto | 2020-05-19 06:15:48 | 2020-05-19 06:15:48 | 1 | 0000-00-00 00:00:00 |
>| 15 | TestCustomFieldsUI | 2020-05-19 07:01:12 | 2020-05-19 07:01:12 | 1 | 0000-00-00 00:00:00 |
>| 16 | TATATA | 2020-05-19 07:02:30 | 2020-05-19 07:02:30 | 1 | 0000-00-00 00:00:00 |
>| 17 | test num 3 from demisto | 2020-05-19 07:03:30 | 2020-05-19 07:03:30 | 1 | 0000-00-00 00:00:00 |
>| 23 | test1 | 2020-06-09 03:52:25 | 2020-06-09 03:52:25 | 1 | 0000-00-00 00:00:00 |
>| 24 | test | 2020-06-09 03:55:07 | 2020-06-09 03:55:07 | 1 | 0000-00-00 00:00:00 |
>| 25 | test1 | 2020-06-09 03:59:41 | 2020-06-09 03:59:41 | 1 | 0000-00-00 00:00:00 |
>| 26 | test1 | 2020-06-09 04:00:03 | 2020-06-09 04:00:03 | 1 | 0000-00-00 00:00:00 |
>| 27 | test1 | 2020-06-09 04:00:33 | 2020-06-09 04:00:33 | 1 | 0000-00-00 00:00:00 |
>| 28 | test1 | 2020-06-09 04:57:39 | 2020-06-09 04:57:39 | 1 | 0000-00-00 00:00:00 |
>| 30 | Test | 2020-06-09 05:12:37 | 2020-06-09 05:12:37 | 1 | 0000-00-00 00:00:00 |
>| 31 | foo foo | 2020-06-09 05:14:51 | 2020-06-09 05:14:51 | 1 | 0000-00-00 00:00:00 |
>| 33 | test1 | 2020-06-09 05:18:10 | 2020-06-09 05:18:10 | 1 | 0000-00-00 00:00:00 |
>| 34 | test1 | 2020-06-09 05:19:13 | 2020-06-09 05:19:13 | 1 | 0000-00-00 00:00:00 |
>| 29 | Tests | 2020-06-09 05:11:59 | 2020-06-09 05:11:59 | 3 | 0000-00-00 00:00:00 |
>| 32 | foo foo | 2020-06-09 05:14:55 | 2020-06-09 05:14:55 | 3 | 0000-00-00 00:00:00 |


### kace-ticket-create
***
Creates a new ticket to the system.


#### Base Command

`kace-ticket-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | Title of the new ticket. | Optional | 
| summary | Summary of the new ticket. | Optional | 
| impact | Name of the impact of the new ticket. | Optional | 
| category | Category of the new ticket. | Optional | 
| status | Status of the new ticket. | Optional | 
| priority | Priority of the new ticket. | Optional | 
| machine | Name of the machine of the new ticket. | Optional | 
| asset | Name of the asset of the new ticket. | Optional | 
| custom_fields | Custom (user defined) fields in the format - fieldname1=value;fieldname2=value. | Optional | 
| queue_id | Queue to which the new ticket should be related. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!kace-ticket-create title="test1" status="Opened" summary="test of Quest Kace integration ticket create" category="Network" queue_id=1```

#### Context Example
```
{}
```

#### Human Readable Output

>### New ticket was added successfully, ticket number 35.
>
>|created|due_date|hd_queue_id|id|modified|title|
>|---|---|---|---|---|---|
>| 2020-06-09 05:19:37 | 0000-00-00 00:00:00 | 1 | 35 | 2020-06-09 05:19:37 | test1 |


### kace-ticket-update
***
Updates a ticket in the system.


#### Base Command

`kace-ticket-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | Updated title of the ticket. | Optional | 
| summary | Updated summary for the ticket. | Optional | 
| impact | Updated impact of the ticket. | Optional | 
| category | Updated category of the ticket. | Optional | 
| status | Updated status of the ticket. | Optional | 
| priority | Updated priority of the ticket. | Optional | 
| machine | Updated machine of the ticket. | Optional | 
| asset | Updated asset of the ticket. | Optional | 
| custom_fields | Custom (user defined) fields in the format - fieldname1=value;fieldname2=value. | Optional | 
| ticket_id | ID of the ticket to update. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!kace-ticket-update ticket_id=11 title="updated test1"```

#### Context Example
```
{}
```

#### Human Readable Output

>### Ticket number 11 was updated successfully.
>
>|created|hd_queue_id|id|modified|title|
>|---|---|---|---|---|
>| 2020-05-19 05:54:42 | 1 | 11 | 2020-06-09 05:19:38 | updated test1 |


### kace-ticket-delete
***
Deletes the specified ticket.


#### Base Command

`kace-ticket-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | Ticket ID to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!kace-ticket-delete ticket_id=11```

#### Context Example
```
{}
```

#### Human Readable Output

>Ticket was deleted successfully. Ticket number 11