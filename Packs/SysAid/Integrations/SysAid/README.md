SysAid is a robust IT management system designed to meet all of the needs of an IT department.
This integration was integrated and tested with version 21.4.44 of SysAid.

## Configure SysAid in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Username |  | True |
| Password |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incident type |  | False |
| Maximum number of incidents to fetch | Maximum is limited to 200. | False |
| Fetch incidents |  | False |
| First fetch time interval |  | False |
| Fetch types | Choose which service record type to fetch - incidents, requests, problems, changes, or all. | False |
| Included statuses | A comma separated list of statuses to return. Default value includes "open classes". You may add/remove statuses according to your needs. The list of status numbers and their values can be retrieved by running the "sysaid-table-list" command with the "list_id=status" argument. | False |
| Include Archived |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sysaid-table-list
***
Retrieve all lists (tables) related to a specific entity, or a specific list from an entity.


#### Base Command

`sysaid-table-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | A SysAid entity by which to retrieve the available lists. Defaults to service record. Options are: sr - Service record related lists, asset - Asset related lists, user - User related lists, ci - CI related lists, company - Company related lists, action_item - Action item related lists, project - Service record Sub Tabs lists, task - Task related lists, catalog - Catalog related lists, software - Software related lists, sr_activity - Service Record activity related lists, supplier - Supplier related lists, task_activity - Task activity related lists, user_groups - User Group related lists. Possible values are: sr, asset, user, ci, company, action_item, project, task, catalog, software, sr_activity, supplier, task_activity, user_groups. | Optional | 
| entity_id | The entity's ID. For example, in service record Form lists, send the service record ID to populate additional filters on the lists. For example, the responsibility list may be filtered by the admin group of the service record. | Optional | 
| entity_type | Numeric. For example, in sr entity, send the sr_type ID, for ci entity, send the ci type ID (for retrieving the list of CI sub-types). | Optional | 
| list_id | Desired list ID. | Optional | 
| key | Relevant for users/groups related fields. Defines whether to use the ID or the name as the key for each value in the result. Available values are "name" or "id". Defaults to "id". Possible values are: id, name. | Optional | 
| fields | A comma separated list of fields to return. Available fields are: id (always returned), caption, and values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SysAid.List.id | String | The ID of the list. | 
| SysAid.List.caption | String | The caption of the list. | 
| SysAid.List.values | String | The values of the list. | 

#### Command example
```!sysaid-table-list list_id=known_error```
#### Context Example
```json
{
    "SysAid": {
        "List": {
            "caption": "Known Error",
            "id": "known_error",
            "values": [
                {
                    "caption": "Production",
                    "id": "P"
                },
                {
                    "caption": "Development",
                    "id": "D"
                },
                {
                    "caption": "No",
                    "id": "N"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### List ID known_error Results:
>|Id|Caption|Values|
>|---|---|---|
>| known_error | Known Error | {'id': 'P', 'caption': 'Production'},<br/>{'id': 'D', 'caption': 'Development'},<br/>{'id': 'N', 'caption': 'No'} |


### sysaid-asset-list
***
List all assets or get a specific asset by ID. Cortex XSOAR recommends filtering the results by the desired fields.


#### Base Command

`sysaid-asset-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The ID of the asset to return. | Optional | 
| fields | Comma separated list of fields to return to context data. The valid fields can be retrieved using the "sysaid-table-list" command with the "entity=asset" argument. You can send "all" for debugging purposes. | Required | 
| page_number | Index of the page of results to retrieve. Default is 1. | Optional | 
| page_size | The number of assets to return on a page. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SysAid.Asset.id | String | The ID of the asset. | 
| SysAid.Asset.name | String | The name of the asset. | 
| SysAid.Asset.info | String | The info of the asset. | 

#### Command example
```!sysaid-asset-list fields=all```
#### Context Example
```json
{
    "SysAid": {
        "Asset": [
            {
                "group": "\\",
                "id": "0A-3E-E9-13-2B-E4",
                "info": [
                    {
                        "key": "cust_list1",
                        "keyCaption": "Asset Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_space",
                        "keyCaption": "HDD Total Space",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "last_boot",
                        "keyCaption": "Last Boot",
                        "value": 1643281586000,
                        "valueCaption": "2022-01-27 11:06:26.0",
                        "valueClass": ""
                    },
                    {
                        "key": "software",
                        "keyCaption": "Software",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_service_pack",
                        "keyCaption": "Service Pack",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "child_assets",
                        "keyCaption": "Child Assets",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "device_ownership",
                        "keyCaption": "Ownership",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "collection_type",
                        "keyCaption": "Source",
                        "value": 2,
                        "valueCaption": "Agent",
                        "valueClass": ""
                    },
                    {
                        "key": "building",
                        "keyCaption": "Building",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "Asset Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "supplier",
                        "keyCaption": "Supplier",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "model",
                        "keyCaption": "Model",
                        "value": "t3.large",
                        "valueCaption": "t3.large",
                        "valueClass": ""
                    },
                    {
                        "key": "designated_rds",
                        "keyCaption": "RDS",
                        "value": "SysAid Server",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "warranty_expiration",
                        "keyCaption": "Warranty Expiration",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hardware",
                        "keyCaption": "Hardware",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "patches",
                        "keyCaption": "Patch Management List",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_speed",
                        "keyCaption": "CPU Speed",
                        "value": "2500",
                        "valueCaption": "2500",
                        "valueClass": ""
                    },
                    {
                        "key": "external_serial",
                        "keyCaption": "External Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "monitoring",
                        "keyCaption": "Monitoring",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 7,
                        "valueCaption": "7",
                        "valueClass": ""
                    },
                    {
                        "key": "missing_patches_list",
                        "keyCaption": "Missing Patches List",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "rc",
                        "keyCaption": "RC",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "device_phone_number",
                        "keyCaption": "Phone Number",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_adapter",
                        "keyCaption": "Display Adapter",
                        "value": "Microsoft Basic Display Adapter",
                        "valueCaption": "Microsoft Basic Display Adapter",
                        "valueClass": ""
                    },
                    {
                        "key": "os_type",
                        "keyCaption": "Operating System Type",
                        "value": "Windows Server 2019 Datacenter ServerDatacenter",
                        "valueCaption": "Windows Server 2019 Datacenter ServerDatacenter",
                        "valueClass": ""
                    },
                    {
                        "key": "pending_patches",
                        "keyCaption": "Pending Patches",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "purchase_date",
                        "keyCaption": "Purchase Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "vpro",
                        "keyCaption": "vPro",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "free_mem_banks",
                        "keyCaption": "Free Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "attachments",
                        "keyCaption": "Attachments",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "activity",
                        "keyCaption": "Activity Log",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "packets_out",
                        "keyCaption": "Bytes out",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "approved_patches",
                        "keyCaption": "Approved Patches",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "availability",
                        "keyCaption": "Availability",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_count",
                        "keyCaption": "CPU Count",
                        "value": "1",
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "manufacturer",
                        "keyCaption": "Manufacturer",
                        "value": "Amazon EC2",
                        "valueCaption": "Amazon EC2",
                        "valueClass": ""
                    },
                    {
                        "key": "missing_patches",
                        "keyCaption": "Missing Patches",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_20",
                        "keyCaption": "Snmp Custom Text 20",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Update Time",
                        "value": 1647220040293,
                        "valueCaption": "03/13/2022 08:07:20 PM",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "Asset Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_free_space",
                        "keyCaption": "HDD Total Free Space",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_model",
                        "keyCaption": "CPU Model",
                        "value": "Xeon Platinum 8175M",
                        "valueCaption": "Xeon Platinum 8175M",
                        "valueClass": ""
                    },
                    {
                        "key": "purchase_cost",
                        "keyCaption": "Purchase Cost",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "freespace",
                        "keyCaption": "Free Space",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "patch_enabled",
                        "keyCaption": "Patch Management",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "last_maintenance",
                        "keyCaption": "Last Maintenance",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "CI Attachment",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_version",
                        "keyCaption": "Operating System Version",
                        "value": "10.0.17763 Multiprocessor Free",
                        "valueCaption": "10.0.17763 Multiprocessor Free",
                        "valueClass": ""
                    },
                    {
                        "key": "display",
                        "keyCaption": "Display",
                        "value": "Microsoft Basic Display Adapter adapter, Generic Non-PnP Monitor monitor.",
                        "valueCaption": "Microsoft Basic Display Adapter adapter, Generic Non-PnP Monitor monitor.",
                        "valueClass": ""
                    },
                    {
                        "key": "onlineUsers",
                        "keyCaption": "Online Users",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_used_space",
                        "keyCaption": "HDD Total Used Space",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "Asset Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "Asset Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_vendor",
                        "keyCaption": "CPU Vendor",
                        "value": "Intel Corporation",
                        "valueCaption": "Intel Corporation",
                        "valueClass": ""
                    },
                    {
                        "key": "last_patch_time",
                        "keyCaption": "Last Patch",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "settings_id",
                        "keyCaption": "Agent Settings",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "changeSR_patches",
                        "keyCaption": "Change SR Patches",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "monitor_serial",
                        "keyCaption": "Monitor Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disable",
                        "keyCaption": "Disabled",
                        "value": "N",
                        "valueCaption": "N",
                        "valueClass": ""
                    },
                    {
                        "key": "os_name",
                        "keyCaption": "OS Name",
                        "value": "Windows Server 2019 Datacenter ServerDatacenter",
                        "valueCaption": "Windows Server 2019 Datacenter ServerDatacenter",
                        "valueClass": ""
                    },
                    {
                        "key": "mem_banks",
                        "keyCaption": "Total Memory Banks",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "last_access",
                        "keyCaption": "Last Access Time",
                        "value": 1647793045000,
                        "valueCaption": "2022-03-20 16:17:25.0",
                        "valueClass": ""
                    },
                    {
                        "key": "failed_patches",
                        "keyCaption": "Failed Patches",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "disks_count",
                        "keyCaption": "Storage Devices",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "device_home_carrier",
                        "keyCaption": "Home Carrier",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_type",
                        "keyCaption": "Type",
                        "value": "Server",
                        "valueCaption": "Server",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_count",
                        "keyCaption": "HDD count",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "mouse",
                        "keyCaption": "Mouse",
                        "value": "PS/2 Compatible Mouse",
                        "valueCaption": "PS/2 Compatible Mouse",
                        "valueClass": ""
                    },
                    {
                        "key": "display_resolution",
                        "keyCaption": "Display Resolution",
                        "value": "1024x768",
                        "valueCaption": "1024x768",
                        "valueClass": ""
                    },
                    {
                        "key": "company_serial",
                        "keyCaption": "Company Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "links",
                        "keyCaption": "Links",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "bios_type",
                        "keyCaption": "BIOS Type",
                        "value": "AMAZON - 1",
                        "valueCaption": "AMAZON - 1",
                        "valueClass": ""
                    },
                    {
                        "key": "maintenance_supplier",
                        "keyCaption": "Support provider",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "installed_patches",
                        "keyCaption": "Installed Patches",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "device_status",
                        "keyCaption": "Status",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "Asset Custom Int 2",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "Asset Custom Int 1",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "Asset Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "getLogs",
                        "keyCaption": "Get Logs",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "03/13/2022 08:07:20 PM",
                        "valueClass": ""
                    },
                    {
                        "key": "occupied_mem_banks",
                        "keyCaption": "Occupied Memory Banks",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu",
                        "keyCaption": "CPU",
                        "value": "1 x Intel Corporation Xeon Platinum 8175M 2.5 Ghz.",
                        "valueCaption": "1 x Intel Corporation Xeon Platinum 8175M 2.5 Ghz.",
                        "valueClass": ""
                    },
                    {
                        "key": "packets_in",
                        "keyCaption": "Bytes in",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "Asset Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history",
                        "keyCaption": "History",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "helpdesk",
                        "keyCaption": "Service Desk",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "users",
                        "keyCaption": "Users",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_11",
                        "keyCaption": "Snmp Custom Text 11",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_10",
                        "keyCaption": "Snmp Custom Text 10",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "device_icc",
                        "keyCaption": "ICC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "catalog_number",
                        "keyCaption": "Catalog number",
                        "value": "t3.large",
                        "valueCaption": "t3.large Amazon EC2 Server",
                        "valueClass": ""
                    },
                    {
                        "key": "location_idx",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_17",
                        "keyCaption": "Snmp Custom Text 17",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_16",
                        "keyCaption": "Snmp Custom Text 16",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_19",
                        "keyCaption": "Snmp Custom Text 19",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_18",
                        "keyCaption": "Snmp Custom Text 18",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_13",
                        "keyCaption": "Snmp Custom Text 13",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_12",
                        "keyCaption": "Snmp Custom Text 12",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_15",
                        "keyCaption": "Snmp Custom Text 15",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_14",
                        "keyCaption": "Snmp Custom Text 14",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "relation_graph",
                        "keyCaption": "CI Relations Graph",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "policy_id",
                        "keyCaption": "Patch Management Policy",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_asset",
                        "keyCaption": "Parent Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "storage",
                        "keyCaption": "Storage",
                        "value": "100 Gb",
                        "valueCaption": "100 Gb",
                        "valueClass": ""
                    },
                    {
                        "key": "network",
                        "keyCaption": "Network",
                        "value": "Host EC2AMAZ-S0GM752@UnknownAdapter Amazon Elastic Network Adapter, IP Address 172.31.12.179",
                        "valueCaption": "Host EC2AMAZ-S0GM752@UnknownAdapter Amazon Elastic Network Adapter, IP Address 172.31.12.179",
                        "valueClass": ""
                    },
                    {
                        "key": "mem",
                        "keyCaption": "Memory",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "mac_address",
                        "keyCaption": "MAC Address",
                        "value": "0A:3E:E9:13:2B:E4 (fe80::938:a6b0:f84e:180d%7,172.31.12.179)",
                        "valueCaption": "0A:3E:E9:13:2B:E4 (fe80::938:a6b0:f84e:180d%7,172.31.12.179)",
                        "valueClass": ""
                    },
                    {
                        "key": "display_memory",
                        "keyCaption": "Display Memory",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "floor",
                        "keyCaption": "Floor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "denied_patches",
                        "keyCaption": "Denied Patches",
                        "value": "0A-3E-E9-13-2B-E4",
                        "valueCaption": "0A-3E-E9-13-2B-E4",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_5",
                        "keyCaption": "Snmp Custom Text 5",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "registry",
                        "keyCaption": "Registry Values",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_6",
                        "keyCaption": "Snmp Custom Text 6",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "printers",
                        "keyCaption": "Printers",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_3",
                        "keyCaption": "Snmp Custom Text 3",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cubic",
                        "keyCaption": "Cubic",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_4",
                        "keyCaption": "Snmp Custom Text 4",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os",
                        "keyCaption": "Operating System",
                        "value": "Windows Server 2019 Datacenter ServerDatacenter ServerDatacenter [10.0.17763 Multiprocessor Free].",
                        "valueCaption": "Windows Server 2019 Datacenter ServerDatacenter ServerDatacenter [10.0.17763 Multiprocessor Free].",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_1",
                        "keyCaption": "Snmp Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_2",
                        "keyCaption": "Snmp Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "memory_physical",
                        "keyCaption": "Memory",
                        "value": 8482484224,
                        "valueCaption": "8482484224",
                        "valueClass": ""
                    },
                    {
                        "key": "monitor",
                        "keyCaption": "Monitor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_serial",
                        "keyCaption": "OS Serial",
                        "value": "R24JD-JYQF3-D6P9P-XFDKH-KHMMT",
                        "valueCaption": "R24JD-JYQF3-D6P9P-XFDKH-KHMMT",
                        "valueClass": ""
                    },
                    {
                        "key": "ip_address",
                        "keyCaption": "IP Address",
                        "value": "172.31.12.179",
                        "valueCaption": "172.31.12.179",
                        "valueClass": ""
                    },
                    {
                        "key": "software_products",
                        "keyCaption": "Software Products",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "agent_version",
                        "keyCaption": "SysAid agent version",
                        "value": "21.4.44.88",
                        "valueCaption": "21.4.44.88",
                        "valueClass": ""
                    },
                    {
                        "key": "linkedItems",
                        "keyCaption": "Links to other Items",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "serial",
                        "keyCaption": "Serial",
                        "value": "ec26dedd-f98f-981f-6cba-1ff7b4de08b9",
                        "valueCaption": "ec26dedd-f98f-981f-6cba-1ff7b4de08b9",
                        "valueClass": ""
                    },
                    {
                        "key": "collection_params",
                        "keyCaption": "Snmp Params",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disks_size",
                        "keyCaption": "Storage Capacity",
                        "value": 100,
                        "valueCaption": "100",
                        "valueClass": ""
                    },
                    {
                        "key": "device_current_carrier",
                        "keyCaption": "Current Carrier",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_9",
                        "keyCaption": "Snmp Custom Text 9",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_scan_time",
                        "keyCaption": "Last Scan",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_7",
                        "keyCaption": "Snmp Custom Text 7",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_8",
                        "keyCaption": "Snmp Custom Text 8",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "username",
                        "keyCaption": "Owner",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    }
                ],
                "name": "EC2AMAZ-S0GM752"
            },
            {
                "group": "\\",
                "id": "5171019c-fa80-4905-a577-c95eb518de90",
                "info": [
                    {
                        "key": "cust_list1",
                        "keyCaption": "Asset Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_space",
                        "keyCaption": "HDD Total Space",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "last_boot",
                        "keyCaption": "Last Boot",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "software",
                        "keyCaption": "Software",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_service_pack",
                        "keyCaption": "Service Pack",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "child_assets",
                        "keyCaption": "Child Assets",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "device_ownership",
                        "keyCaption": "Ownership",
                        "value": 2,
                        "valueCaption": "Corporate Owned",
                        "valueClass": ""
                    },
                    {
                        "key": "collection_type",
                        "keyCaption": "Source",
                        "value": 3,
                        "valueCaption": "Manual",
                        "valueClass": ""
                    },
                    {
                        "key": "building",
                        "keyCaption": "Building",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "Asset Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "supplier",
                        "keyCaption": "Supplier",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "model",
                        "keyCaption": "Model",
                        "value": "Galaxy S22",
                        "valueCaption": "Galaxy S22",
                        "valueClass": ""
                    },
                    {
                        "key": "designated_rds",
                        "keyCaption": "RDS",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "warranty_expiration",
                        "keyCaption": "Warranty Expiration",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hardware",
                        "keyCaption": "Hardware",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "patches",
                        "keyCaption": "Patch Management List",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_speed",
                        "keyCaption": "CPU Speed",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "external_serial",
                        "keyCaption": "External Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "monitoring",
                        "keyCaption": "Monitoring",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "missing_patches_list",
                        "keyCaption": "Missing Patches List",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "rc",
                        "keyCaption": "RC",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "device_phone_number",
                        "keyCaption": "Phone Number",
                        "value": "+123456789",
                        "valueCaption": "+123456789",
                        "valueClass": ""
                    },
                    {
                        "key": "display_adapter",
                        "keyCaption": "Display Adapter",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_type",
                        "keyCaption": "Operating System Type",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "pending_patches",
                        "keyCaption": "Pending Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "purchase_date",
                        "keyCaption": "Purchase Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "vpro",
                        "keyCaption": "vPro",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "free_mem_banks",
                        "keyCaption": "Free Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "attachments",
                        "keyCaption": "Attachments",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "activity",
                        "keyCaption": "Activity Log",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "packets_out",
                        "keyCaption": "Bytes out",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "approved_patches",
                        "keyCaption": "Approved Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "availability",
                        "keyCaption": "Availability",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_count",
                        "keyCaption": "CPU Count",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "manufacturer",
                        "keyCaption": "Manufacturer",
                        "value": "Samsung",
                        "valueCaption": "Samsung",
                        "valueClass": ""
                    },
                    {
                        "key": "missing_patches",
                        "keyCaption": "Missing Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_20",
                        "keyCaption": "Snmp Custom Text 20",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Update Time",
                        "value": 1646661843140,
                        "valueCaption": "03/07/2022 09:04:03 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "Asset Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_free_space",
                        "keyCaption": "HDD Total Free Space",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_model",
                        "keyCaption": "CPU Model",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "purchase_cost",
                        "keyCaption": "Purchase Cost",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "freespace",
                        "keyCaption": "Free Space",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "patch_enabled",
                        "keyCaption": "Patch Management",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "last_maintenance",
                        "keyCaption": "Last Maintenance",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "CI Attachment",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_version",
                        "keyCaption": "Operating System Version",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display",
                        "keyCaption": "Display",
                        "value": " adapter",
                        "valueCaption": " adapter",
                        "valueClass": ""
                    },
                    {
                        "key": "onlineUsers",
                        "keyCaption": "Online Users",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_used_space",
                        "keyCaption": "HDD Total Used Space",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "Asset Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "Asset Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_vendor",
                        "keyCaption": "CPU Vendor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_patch_time",
                        "keyCaption": "Last Patch",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "settings_id",
                        "keyCaption": "Agent Settings",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "changeSR_patches",
                        "keyCaption": "Change SR Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "monitor_serial",
                        "keyCaption": "Monitor Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disable",
                        "keyCaption": "Disabled",
                        "value": "N",
                        "valueCaption": "N",
                        "valueClass": ""
                    },
                    {
                        "key": "os_name",
                        "keyCaption": "OS Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "mem_banks",
                        "keyCaption": "Total Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "last_access",
                        "keyCaption": "Last Access Time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "failed_patches",
                        "keyCaption": "Failed Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "disks_count",
                        "keyCaption": "Storage Devices",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "device_home_carrier",
                        "keyCaption": "Home Carrier",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_type",
                        "keyCaption": "Type",
                        "value": "PDA",
                        "valueCaption": "PDA",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_count",
                        "keyCaption": "HDD count",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "mouse",
                        "keyCaption": "Mouse",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_resolution",
                        "keyCaption": "Display Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "company_serial",
                        "keyCaption": "Company Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "links",
                        "keyCaption": "Links",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "bios_type",
                        "keyCaption": "BIOS Type",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "maintenance_supplier",
                        "keyCaption": "Support provider",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "installed_patches",
                        "keyCaption": "Installed Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "device_status",
                        "keyCaption": "Status",
                        "value": 2,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "Asset Custom Int 2",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "Asset Custom Int 1",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "Asset Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "getLogs",
                        "keyCaption": "Get Logs",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "03/07/2022 09:04:03 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "occupied_mem_banks",
                        "keyCaption": "Occupied Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu",
                        "keyCaption": "CPU",
                        "value": "0 x   0 Mhz.",
                        "valueCaption": "0 x   0 Mhz.",
                        "valueClass": ""
                    },
                    {
                        "key": "packets_in",
                        "keyCaption": "Bytes in",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "Asset Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history",
                        "keyCaption": "History",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "helpdesk",
                        "keyCaption": "Service Desk",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "users",
                        "keyCaption": "Users",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_11",
                        "keyCaption": "Snmp Custom Text 11",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_10",
                        "keyCaption": "Snmp Custom Text 10",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "device_icc",
                        "keyCaption": "ICC",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "catalog_number",
                        "keyCaption": "Catalog number",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location_idx",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_17",
                        "keyCaption": "Snmp Custom Text 17",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_16",
                        "keyCaption": "Snmp Custom Text 16",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_19",
                        "keyCaption": "Snmp Custom Text 19",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_18",
                        "keyCaption": "Snmp Custom Text 18",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_13",
                        "keyCaption": "Snmp Custom Text 13",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_12",
                        "keyCaption": "Snmp Custom Text 12",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_15",
                        "keyCaption": "Snmp Custom Text 15",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_14",
                        "keyCaption": "Snmp Custom Text 14",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "relation_graph",
                        "keyCaption": "CI Relations Graph",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "policy_id",
                        "keyCaption": "Patch Management Policy",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Test smartphone",
                        "valueCaption": "Test smartphone",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_asset",
                        "keyCaption": "Parent Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "storage",
                        "keyCaption": "Storage",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "network",
                        "keyCaption": "Network",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "mem",
                        "keyCaption": "Memory",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "mac_address",
                        "keyCaption": "MAC Address",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_memory",
                        "keyCaption": "Display Memory",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "floor",
                        "keyCaption": "Floor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "denied_patches",
                        "keyCaption": "Denied Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_5",
                        "keyCaption": "Snmp Custom Text 5",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "registry",
                        "keyCaption": "Registry Values",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_6",
                        "keyCaption": "Snmp Custom Text 6",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "printers",
                        "keyCaption": "Printers",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_3",
                        "keyCaption": "Snmp Custom Text 3",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cubic",
                        "keyCaption": "Cubic",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_4",
                        "keyCaption": "Snmp Custom Text 4",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os",
                        "keyCaption": "Operating System",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_1",
                        "keyCaption": "Snmp Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_2",
                        "keyCaption": "Snmp Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "memory_physical",
                        "keyCaption": "Memory",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "monitor",
                        "keyCaption": "Monitor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_serial",
                        "keyCaption": "OS Serial",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ip_address",
                        "keyCaption": "IP Address",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "software_products",
                        "keyCaption": "Software Products",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "agent_version",
                        "keyCaption": "SysAid agent version",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "linkedItems",
                        "keyCaption": "Links to other Items",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "serial",
                        "keyCaption": "Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "collection_params",
                        "keyCaption": "Snmp Params",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disks_size",
                        "keyCaption": "Storage Capacity",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "device_current_carrier",
                        "keyCaption": "Current Carrier",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_9",
                        "keyCaption": "Snmp Custom Text 9",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_scan_time",
                        "keyCaption": "Last Scan",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_7",
                        "keyCaption": "Snmp Custom Text 7",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_8",
                        "keyCaption": "Snmp Custom Text 8",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "username",
                        "keyCaption": "Owner",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    }
                ],
                "name": "Test Phone"
            },
            {
                "group": "\\",
                "id": "93c18412-a672-4a3d-8b02-6f91ee963918",
                "info": [
                    {
                        "key": "cust_list1",
                        "keyCaption": "Asset Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_space",
                        "keyCaption": "HDD Total Space",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "last_boot",
                        "keyCaption": "Last Boot",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "software",
                        "keyCaption": "Software",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_service_pack",
                        "keyCaption": "Service Pack",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "child_assets",
                        "keyCaption": "Child Assets",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "device_ownership",
                        "keyCaption": "Ownership",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "collection_type",
                        "keyCaption": "Source",
                        "value": 3,
                        "valueCaption": "Manual",
                        "valueClass": ""
                    },
                    {
                        "key": "building",
                        "keyCaption": "Building",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "Asset Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "supplier",
                        "keyCaption": "Supplier",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "model",
                        "keyCaption": "Model",
                        "value": "Dell Inspirion 3556",
                        "valueCaption": "Dell Inspirion 3556",
                        "valueClass": ""
                    },
                    {
                        "key": "designated_rds",
                        "keyCaption": "RDS",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "warranty_expiration",
                        "keyCaption": "Warranty Expiration",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hardware",
                        "keyCaption": "Hardware",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "patches",
                        "keyCaption": "Patch Management List",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_speed",
                        "keyCaption": "CPU Speed",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "external_serial",
                        "keyCaption": "External Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "monitoring",
                        "keyCaption": "Monitoring",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "missing_patches_list",
                        "keyCaption": "Missing Patches List",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "rc",
                        "keyCaption": "RC",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "device_phone_number",
                        "keyCaption": "Phone Number",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_adapter",
                        "keyCaption": "Display Adapter",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_type",
                        "keyCaption": "Operating System Type",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "pending_patches",
                        "keyCaption": "Pending Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "purchase_date",
                        "keyCaption": "Purchase Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "vpro",
                        "keyCaption": "vPro",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "free_mem_banks",
                        "keyCaption": "Free Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "attachments",
                        "keyCaption": "Attachments",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "activity",
                        "keyCaption": "Activity Log",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "packets_out",
                        "keyCaption": "Bytes out",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "approved_patches",
                        "keyCaption": "Approved Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "availability",
                        "keyCaption": "Availability",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_count",
                        "keyCaption": "CPU Count",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "manufacturer",
                        "keyCaption": "Manufacturer",
                        "value": "Dell",
                        "valueCaption": "Dell",
                        "valueClass": ""
                    },
                    {
                        "key": "missing_patches",
                        "keyCaption": "Missing Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_20",
                        "keyCaption": "Snmp Custom Text 20",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Update Time",
                        "value": 1646661758293,
                        "valueCaption": "03/07/2022 09:02:38 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "Asset Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_free_space",
                        "keyCaption": "HDD Total Free Space",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_model",
                        "keyCaption": "CPU Model",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "purchase_cost",
                        "keyCaption": "Purchase Cost",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "freespace",
                        "keyCaption": "Free Space",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "patch_enabled",
                        "keyCaption": "Patch Management",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "last_maintenance",
                        "keyCaption": "Last Maintenance",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "CI Attachment",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_version",
                        "keyCaption": "Operating System Version",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display",
                        "keyCaption": "Display",
                        "value": " adapter",
                        "valueCaption": " adapter",
                        "valueClass": ""
                    },
                    {
                        "key": "onlineUsers",
                        "keyCaption": "Online Users",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_used_space",
                        "keyCaption": "HDD Total Used Space",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "Asset Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "Asset Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_vendor",
                        "keyCaption": "CPU Vendor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_patch_time",
                        "keyCaption": "Last Patch",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "settings_id",
                        "keyCaption": "Agent Settings",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "changeSR_patches",
                        "keyCaption": "Change SR Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "monitor_serial",
                        "keyCaption": "Monitor Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disable",
                        "keyCaption": "Disabled",
                        "value": "N",
                        "valueCaption": "N",
                        "valueClass": ""
                    },
                    {
                        "key": "os_name",
                        "keyCaption": "OS Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "mem_banks",
                        "keyCaption": "Total Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "last_access",
                        "keyCaption": "Last Access Time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "failed_patches",
                        "keyCaption": "Failed Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "disks_count",
                        "keyCaption": "Storage Devices",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "device_home_carrier",
                        "keyCaption": "Home Carrier",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_type",
                        "keyCaption": "Type",
                        "value": "Laptop",
                        "valueCaption": "Laptop",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_count",
                        "keyCaption": "HDD count",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "mouse",
                        "keyCaption": "Mouse",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_resolution",
                        "keyCaption": "Display Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "company_serial",
                        "keyCaption": "Company Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "links",
                        "keyCaption": "Links",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "bios_type",
                        "keyCaption": "BIOS Type",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "maintenance_supplier",
                        "keyCaption": "Support provider",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "installed_patches",
                        "keyCaption": "Installed Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "device_status",
                        "keyCaption": "Status",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "Asset Custom Int 2",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "Asset Custom Int 1",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "Asset Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "getLogs",
                        "keyCaption": "Get Logs",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "03/07/2022 09:02:38 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "occupied_mem_banks",
                        "keyCaption": "Occupied Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu",
                        "keyCaption": "CPU",
                        "value": "0 x   0 Mhz.",
                        "valueCaption": "0 x   0 Mhz.",
                        "valueClass": ""
                    },
                    {
                        "key": "packets_in",
                        "keyCaption": "Bytes in",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "Asset Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history",
                        "keyCaption": "History",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "helpdesk",
                        "keyCaption": "Service Desk",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "users",
                        "keyCaption": "Users",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_11",
                        "keyCaption": "Snmp Custom Text 11",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_10",
                        "keyCaption": "Snmp Custom Text 10",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "device_icc",
                        "keyCaption": "ICC",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "catalog_number",
                        "keyCaption": "Catalog number",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location_idx",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_17",
                        "keyCaption": "Snmp Custom Text 17",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_16",
                        "keyCaption": "Snmp Custom Text 16",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_19",
                        "keyCaption": "Snmp Custom Text 19",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_18",
                        "keyCaption": "Snmp Custom Text 18",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_13",
                        "keyCaption": "Snmp Custom Text 13",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_12",
                        "keyCaption": "Snmp Custom Text 12",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_15",
                        "keyCaption": "Snmp Custom Text 15",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_14",
                        "keyCaption": "Snmp Custom Text 14",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "relation_graph",
                        "keyCaption": "CI Relations Graph",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "policy_id",
                        "keyCaption": "Patch Management Policy",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Test LP",
                        "valueCaption": "Test LP",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_asset",
                        "keyCaption": "Parent Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "storage",
                        "keyCaption": "Storage",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "network",
                        "keyCaption": "Network",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "mem",
                        "keyCaption": "Memory",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "mac_address",
                        "keyCaption": "MAC Address",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_memory",
                        "keyCaption": "Display Memory",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "floor",
                        "keyCaption": "Floor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "denied_patches",
                        "keyCaption": "Denied Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_5",
                        "keyCaption": "Snmp Custom Text 5",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "registry",
                        "keyCaption": "Registry Values",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_6",
                        "keyCaption": "Snmp Custom Text 6",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "printers",
                        "keyCaption": "Printers",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_3",
                        "keyCaption": "Snmp Custom Text 3",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cubic",
                        "keyCaption": "Cubic",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_4",
                        "keyCaption": "Snmp Custom Text 4",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os",
                        "keyCaption": "Operating System",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_1",
                        "keyCaption": "Snmp Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_2",
                        "keyCaption": "Snmp Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "memory_physical",
                        "keyCaption": "Memory",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "monitor",
                        "keyCaption": "Monitor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_serial",
                        "keyCaption": "OS Serial",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ip_address",
                        "keyCaption": "IP Address",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "software_products",
                        "keyCaption": "Software Products",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "agent_version",
                        "keyCaption": "SysAid agent version",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "linkedItems",
                        "keyCaption": "Links to other Items",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "serial",
                        "keyCaption": "Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "collection_params",
                        "keyCaption": "Snmp Params",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disks_size",
                        "keyCaption": "Storage Capacity",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "device_current_carrier",
                        "keyCaption": "Current Carrier",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_9",
                        "keyCaption": "Snmp Custom Text 9",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_scan_time",
                        "keyCaption": "Last Scan",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_7",
                        "keyCaption": "Snmp Custom Text 7",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_8",
                        "keyCaption": "Snmp Custom Text 8",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "username",
                        "keyCaption": "Owner",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    }
                ],
                "name": "Test LP"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 100 results from page 1:
>### Asset Results:
>|Id|Name|Info|
>|---|---|---|
>| 0A-3E-E9-13-2B-E4 | EC2AMAZ-S0GM752 | Model: t3.large |
>| 5171019c-fa80-4905-a577-c95eb518de90 | Test Phone | Model: Galaxy S22,<br/>Description: Test smartphone |
>| 93c18412-a672-4a3d-8b02-6f91ee963918 | Test LP | Model: Dell Inspirion 3556,<br/>Description: Test LP |


### sysaid-asset-search
***
Get information about a specific asset. Cortex XSOAR recommends filtering the results by the desired fields.


#### Base Command

`sysaid-asset-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The search criteria. | Required | 
| fields | Comma separated list of fields to return to context data. The valid fields can be retrieved using the "sysaid-table-list" command with the "entity=asset" argument. You can send "all" for debugging purposes. | Required | 
| page_size | The number of assets to return on a page. Default is 100. | Optional | 
| page_number | Index of the page of results to retrieve. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SysAid.Asset.id | String | The ID of the asset. | 
| SysAid.Asset.name | String | The name of the asset. | 
| SysAid.Asset.info | String | The info of the asset. | 

#### Command example
```!sysaid-asset-search query=Test fields=all```
#### Context Example
```json
{
    "SysAid": {
        "Asset": [
            {
                "group": "\\",
                "id": "5171019c-fa80-4905-a577-c95eb518de90",
                "info": [
                    {
                        "key": "cust_list1",
                        "keyCaption": "Asset Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_space",
                        "keyCaption": "HDD Total Space",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "last_boot",
                        "keyCaption": "Last Boot",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "software",
                        "keyCaption": "Software",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_service_pack",
                        "keyCaption": "Service Pack",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "child_assets",
                        "keyCaption": "Child Assets",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "device_ownership",
                        "keyCaption": "Ownership",
                        "value": 2,
                        "valueCaption": "Corporate Owned",
                        "valueClass": ""
                    },
                    {
                        "key": "collection_type",
                        "keyCaption": "Source",
                        "value": 3,
                        "valueCaption": "Manual",
                        "valueClass": ""
                    },
                    {
                        "key": "building",
                        "keyCaption": "Building",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "Asset Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "supplier",
                        "keyCaption": "Supplier",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "model",
                        "keyCaption": "Model",
                        "value": "Galaxy S22",
                        "valueCaption": "Galaxy S22",
                        "valueClass": ""
                    },
                    {
                        "key": "designated_rds",
                        "keyCaption": "RDS",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "warranty_expiration",
                        "keyCaption": "Warranty Expiration",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hardware",
                        "keyCaption": "Hardware",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "patches",
                        "keyCaption": "Patch Management List",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_speed",
                        "keyCaption": "CPU Speed",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "external_serial",
                        "keyCaption": "External Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "monitoring",
                        "keyCaption": "Monitoring",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "missing_patches_list",
                        "keyCaption": "Missing Patches List",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "rc",
                        "keyCaption": "RC",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "device_phone_number",
                        "keyCaption": "Phone Number",
                        "value": "+123456789",
                        "valueCaption": "+123456789",
                        "valueClass": ""
                    },
                    {
                        "key": "display_adapter",
                        "keyCaption": "Display Adapter",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_type",
                        "keyCaption": "Operating System Type",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "pending_patches",
                        "keyCaption": "Pending Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "purchase_date",
                        "keyCaption": "Purchase Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "vpro",
                        "keyCaption": "vPro",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "free_mem_banks",
                        "keyCaption": "Free Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "attachments",
                        "keyCaption": "Attachments",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "activity",
                        "keyCaption": "Activity Log",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "packets_out",
                        "keyCaption": "Bytes out",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "approved_patches",
                        "keyCaption": "Approved Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "availability",
                        "keyCaption": "Availability",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_count",
                        "keyCaption": "CPU Count",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "manufacturer",
                        "keyCaption": "Manufacturer",
                        "value": "Samsung",
                        "valueCaption": "Samsung",
                        "valueClass": ""
                    },
                    {
                        "key": "missing_patches",
                        "keyCaption": "Missing Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_20",
                        "keyCaption": "Snmp Custom Text 20",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Update Time",
                        "value": 1646661843140,
                        "valueCaption": "03/07/2022 09:04:03 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "Asset Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_free_space",
                        "keyCaption": "HDD Total Free Space",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_model",
                        "keyCaption": "CPU Model",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "purchase_cost",
                        "keyCaption": "Purchase Cost",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "freespace",
                        "keyCaption": "Free Space",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "patch_enabled",
                        "keyCaption": "Patch Management",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "last_maintenance",
                        "keyCaption": "Last Maintenance",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "CI Attachment",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_version",
                        "keyCaption": "Operating System Version",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display",
                        "keyCaption": "Display",
                        "value": " adapter",
                        "valueCaption": " adapter",
                        "valueClass": ""
                    },
                    {
                        "key": "onlineUsers",
                        "keyCaption": "Online Users",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_used_space",
                        "keyCaption": "HDD Total Used Space",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "Asset Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "Asset Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_vendor",
                        "keyCaption": "CPU Vendor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_patch_time",
                        "keyCaption": "Last Patch",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "settings_id",
                        "keyCaption": "Agent Settings",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "changeSR_patches",
                        "keyCaption": "Change SR Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "monitor_serial",
                        "keyCaption": "Monitor Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disable",
                        "keyCaption": "Disabled",
                        "value": "N",
                        "valueCaption": "N",
                        "valueClass": ""
                    },
                    {
                        "key": "os_name",
                        "keyCaption": "OS Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "mem_banks",
                        "keyCaption": "Total Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "last_access",
                        "keyCaption": "Last Access Time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "failed_patches",
                        "keyCaption": "Failed Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "disks_count",
                        "keyCaption": "Storage Devices",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "device_home_carrier",
                        "keyCaption": "Home Carrier",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_type",
                        "keyCaption": "Type",
                        "value": "PDA",
                        "valueCaption": "PDA",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_count",
                        "keyCaption": "HDD count",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "mouse",
                        "keyCaption": "Mouse",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_resolution",
                        "keyCaption": "Display Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "company_serial",
                        "keyCaption": "Company Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "links",
                        "keyCaption": "Links",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "bios_type",
                        "keyCaption": "BIOS Type",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "maintenance_supplier",
                        "keyCaption": "Support provider",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "installed_patches",
                        "keyCaption": "Installed Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "device_status",
                        "keyCaption": "Status",
                        "value": 2,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "Asset Custom Int 2",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "Asset Custom Int 1",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "Asset Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "getLogs",
                        "keyCaption": "Get Logs",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "03/07/2022 09:04:03 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "occupied_mem_banks",
                        "keyCaption": "Occupied Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu",
                        "keyCaption": "CPU",
                        "value": "0 x   0 Mhz.",
                        "valueCaption": "0 x   0 Mhz.",
                        "valueClass": ""
                    },
                    {
                        "key": "packets_in",
                        "keyCaption": "Bytes in",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "Asset Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history",
                        "keyCaption": "History",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "helpdesk",
                        "keyCaption": "Service Desk",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "users",
                        "keyCaption": "Users",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_11",
                        "keyCaption": "Snmp Custom Text 11",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_10",
                        "keyCaption": "Snmp Custom Text 10",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "device_icc",
                        "keyCaption": "ICC",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "catalog_number",
                        "keyCaption": "Catalog number",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location_idx",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_17",
                        "keyCaption": "Snmp Custom Text 17",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_16",
                        "keyCaption": "Snmp Custom Text 16",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_19",
                        "keyCaption": "Snmp Custom Text 19",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_18",
                        "keyCaption": "Snmp Custom Text 18",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_13",
                        "keyCaption": "Snmp Custom Text 13",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_12",
                        "keyCaption": "Snmp Custom Text 12",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_15",
                        "keyCaption": "Snmp Custom Text 15",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_14",
                        "keyCaption": "Snmp Custom Text 14",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "relation_graph",
                        "keyCaption": "CI Relations Graph",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "policy_id",
                        "keyCaption": "Patch Management Policy",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Test smartphone",
                        "valueCaption": "Test smartphone",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_asset",
                        "keyCaption": "Parent Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "storage",
                        "keyCaption": "Storage",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "network",
                        "keyCaption": "Network",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "mem",
                        "keyCaption": "Memory",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "mac_address",
                        "keyCaption": "MAC Address",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_memory",
                        "keyCaption": "Display Memory",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "floor",
                        "keyCaption": "Floor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "denied_patches",
                        "keyCaption": "Denied Patches",
                        "value": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueCaption": "5171019c-fa80-4905-a577-c95eb518de90",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_5",
                        "keyCaption": "Snmp Custom Text 5",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "registry",
                        "keyCaption": "Registry Values",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_6",
                        "keyCaption": "Snmp Custom Text 6",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "printers",
                        "keyCaption": "Printers",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_3",
                        "keyCaption": "Snmp Custom Text 3",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cubic",
                        "keyCaption": "Cubic",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_4",
                        "keyCaption": "Snmp Custom Text 4",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os",
                        "keyCaption": "Operating System",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_1",
                        "keyCaption": "Snmp Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_2",
                        "keyCaption": "Snmp Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "memory_physical",
                        "keyCaption": "Memory",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "monitor",
                        "keyCaption": "Monitor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_serial",
                        "keyCaption": "OS Serial",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ip_address",
                        "keyCaption": "IP Address",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "software_products",
                        "keyCaption": "Software Products",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "agent_version",
                        "keyCaption": "SysAid agent version",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "linkedItems",
                        "keyCaption": "Links to other Items",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "serial",
                        "keyCaption": "Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "collection_params",
                        "keyCaption": "Snmp Params",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disks_size",
                        "keyCaption": "Storage Capacity",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "device_current_carrier",
                        "keyCaption": "Current Carrier",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_9",
                        "keyCaption": "Snmp Custom Text 9",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_scan_time",
                        "keyCaption": "Last Scan",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_7",
                        "keyCaption": "Snmp Custom Text 7",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_8",
                        "keyCaption": "Snmp Custom Text 8",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "username",
                        "keyCaption": "Owner",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    }
                ],
                "name": "Test Phone"
            },
            {
                "group": "\\",
                "id": "93c18412-a672-4a3d-8b02-6f91ee963918",
                "info": [
                    {
                        "key": "cust_list1",
                        "keyCaption": "Asset Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_space",
                        "keyCaption": "HDD Total Space",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "last_boot",
                        "keyCaption": "Last Boot",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "software",
                        "keyCaption": "Software",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_service_pack",
                        "keyCaption": "Service Pack",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "child_assets",
                        "keyCaption": "Child Assets",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "device_ownership",
                        "keyCaption": "Ownership",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "collection_type",
                        "keyCaption": "Source",
                        "value": 3,
                        "valueCaption": "Manual",
                        "valueClass": ""
                    },
                    {
                        "key": "building",
                        "keyCaption": "Building",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "Asset Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "supplier",
                        "keyCaption": "Supplier",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "model",
                        "keyCaption": "Model",
                        "value": "Dell Inspirion 3556",
                        "valueCaption": "Dell Inspirion 3556",
                        "valueClass": ""
                    },
                    {
                        "key": "designated_rds",
                        "keyCaption": "RDS",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "warranty_expiration",
                        "keyCaption": "Warranty Expiration",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hardware",
                        "keyCaption": "Hardware",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "patches",
                        "keyCaption": "Patch Management List",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_speed",
                        "keyCaption": "CPU Speed",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "external_serial",
                        "keyCaption": "External Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "monitoring",
                        "keyCaption": "Monitoring",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "missing_patches_list",
                        "keyCaption": "Missing Patches List",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "rc",
                        "keyCaption": "RC",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "device_phone_number",
                        "keyCaption": "Phone Number",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_adapter",
                        "keyCaption": "Display Adapter",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_type",
                        "keyCaption": "Operating System Type",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "pending_patches",
                        "keyCaption": "Pending Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "purchase_date",
                        "keyCaption": "Purchase Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "vpro",
                        "keyCaption": "vPro",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "free_mem_banks",
                        "keyCaption": "Free Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "attachments",
                        "keyCaption": "Attachments",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "activity",
                        "keyCaption": "Activity Log",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "packets_out",
                        "keyCaption": "Bytes out",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "approved_patches",
                        "keyCaption": "Approved Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "availability",
                        "keyCaption": "Availability",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_count",
                        "keyCaption": "CPU Count",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "manufacturer",
                        "keyCaption": "Manufacturer",
                        "value": "Dell",
                        "valueCaption": "Dell",
                        "valueClass": ""
                    },
                    {
                        "key": "missing_patches",
                        "keyCaption": "Missing Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_20",
                        "keyCaption": "Snmp Custom Text 20",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Update Time",
                        "value": 1646661758293,
                        "valueCaption": "03/07/2022 09:02:38 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "Asset Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_free_space",
                        "keyCaption": "HDD Total Free Space",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_model",
                        "keyCaption": "CPU Model",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "purchase_cost",
                        "keyCaption": "Purchase Cost",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "freespace",
                        "keyCaption": "Free Space",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "patch_enabled",
                        "keyCaption": "Patch Management",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "last_maintenance",
                        "keyCaption": "Last Maintenance",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "CI Attachment",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_version",
                        "keyCaption": "Operating System Version",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display",
                        "keyCaption": "Display",
                        "value": " adapter",
                        "valueCaption": " adapter",
                        "valueClass": ""
                    },
                    {
                        "key": "onlineUsers",
                        "keyCaption": "Online Users",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_total_used_space",
                        "keyCaption": "HDD Total Used Space",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "Asset Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "Asset Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu_vendor",
                        "keyCaption": "CPU Vendor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_patch_time",
                        "keyCaption": "Last Patch",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "settings_id",
                        "keyCaption": "Agent Settings",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "changeSR_patches",
                        "keyCaption": "Change SR Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "monitor_serial",
                        "keyCaption": "Monitor Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disable",
                        "keyCaption": "Disabled",
                        "value": "N",
                        "valueCaption": "N",
                        "valueClass": ""
                    },
                    {
                        "key": "os_name",
                        "keyCaption": "OS Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "mem_banks",
                        "keyCaption": "Total Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "last_access",
                        "keyCaption": "Last Access Time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "failed_patches",
                        "keyCaption": "Failed Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "disks_count",
                        "keyCaption": "Storage Devices",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "device_home_carrier",
                        "keyCaption": "Home Carrier",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_type",
                        "keyCaption": "Type",
                        "value": "Laptop",
                        "valueCaption": "Laptop",
                        "valueClass": ""
                    },
                    {
                        "key": "hdd_count",
                        "keyCaption": "HDD count",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "mouse",
                        "keyCaption": "Mouse",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_resolution",
                        "keyCaption": "Display Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "company_serial",
                        "keyCaption": "Company Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "links",
                        "keyCaption": "Links",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "bios_type",
                        "keyCaption": "BIOS Type",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "maintenance_supplier",
                        "keyCaption": "Support provider",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "installed_patches",
                        "keyCaption": "Installed Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "device_status",
                        "keyCaption": "Status",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "Asset Custom Int 2",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "Asset Custom Int 1",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "Asset Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "getLogs",
                        "keyCaption": "Get Logs",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "03/07/2022 09:02:38 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "occupied_mem_banks",
                        "keyCaption": "Occupied Memory Banks",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cpu",
                        "keyCaption": "CPU",
                        "value": "0 x   0 Mhz.",
                        "valueCaption": "0 x   0 Mhz.",
                        "valueClass": ""
                    },
                    {
                        "key": "packets_in",
                        "keyCaption": "Bytes in",
                        "value": 0,
                        "valueCaption": "0.0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "Asset Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history",
                        "keyCaption": "History",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "helpdesk",
                        "keyCaption": "Service Desk",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "users",
                        "keyCaption": "Users",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_11",
                        "keyCaption": "Snmp Custom Text 11",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_10",
                        "keyCaption": "Snmp Custom Text 10",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "device_icc",
                        "keyCaption": "ICC",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "catalog_number",
                        "keyCaption": "Catalog number",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location_idx",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_17",
                        "keyCaption": "Snmp Custom Text 17",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_16",
                        "keyCaption": "Snmp Custom Text 16",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_19",
                        "keyCaption": "Snmp Custom Text 19",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_18",
                        "keyCaption": "Snmp Custom Text 18",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_13",
                        "keyCaption": "Snmp Custom Text 13",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_12",
                        "keyCaption": "Snmp Custom Text 12",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_15",
                        "keyCaption": "Snmp Custom Text 15",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_14",
                        "keyCaption": "Snmp Custom Text 14",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "relation_graph",
                        "keyCaption": "CI Relations Graph",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "policy_id",
                        "keyCaption": "Patch Management Policy",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Test LP",
                        "valueCaption": "Test LP",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_asset",
                        "keyCaption": "Parent Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "storage",
                        "keyCaption": "Storage",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "network",
                        "keyCaption": "Network",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "mem",
                        "keyCaption": "Memory",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "mac_address",
                        "keyCaption": "MAC Address",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_memory",
                        "keyCaption": "Display Memory",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "floor",
                        "keyCaption": "Floor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "denied_patches",
                        "keyCaption": "Denied Patches",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_5",
                        "keyCaption": "Snmp Custom Text 5",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "registry",
                        "keyCaption": "Registry Values",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_6",
                        "keyCaption": "Snmp Custom Text 6",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "printers",
                        "keyCaption": "Printers",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_3",
                        "keyCaption": "Snmp Custom Text 3",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cubic",
                        "keyCaption": "Cubic",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_4",
                        "keyCaption": "Snmp Custom Text 4",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os",
                        "keyCaption": "Operating System",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_1",
                        "keyCaption": "Snmp Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_2",
                        "keyCaption": "Snmp Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "memory_physical",
                        "keyCaption": "Memory",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "monitor",
                        "keyCaption": "Monitor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "os_serial",
                        "keyCaption": "OS Serial",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ip_address",
                        "keyCaption": "IP Address",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "software_products",
                        "keyCaption": "Software Products",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "agent_version",
                        "keyCaption": "SysAid agent version",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "linkedItems",
                        "keyCaption": "Links to other Items",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "serial",
                        "keyCaption": "Serial",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "collection_params",
                        "keyCaption": "Snmp Params",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disks_size",
                        "keyCaption": "Storage Capacity",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "device_current_carrier",
                        "keyCaption": "Current Carrier",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_9",
                        "keyCaption": "Snmp Custom Text 9",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_scan_time",
                        "keyCaption": "Last Scan",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_7",
                        "keyCaption": "Snmp Custom Text 7",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "snmp_cust_text_8",
                        "keyCaption": "Snmp Custom Text 8",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "username",
                        "keyCaption": "Owner",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    }
                ],
                "name": "Test LP"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 100 results from page 1:
>### Asset Results:
>|Id|Name|Info|
>|---|---|---|
>| 5171019c-fa80-4905-a577-c95eb518de90 | Test Phone | Model: Galaxy S22,<br/>Description: Test smartphone |
>| 93c18412-a672-4a3d-8b02-6f91ee963918 | Test LP | Model: Dell Inspirion 3556,<br/>Description: Test LP |


### sysaid-filter-list
***
List all filters. Cortex XSOAR recommends filtering the results by the desired fields.


#### Base Command

`sysaid-filter-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Comma separated list of fields to return to context data. You can send "all" for debugging purposes. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SysAid.Filter.id | String | The ID of the filter. | 
| SysAid.Filter.type | String | The type of the filter. | 
| SysAid.Filter.caption | String | The caption of the filter. | 
| SysAid.Filter.values | String | The values of the filter. | 

#### Command example
```!sysaid-filter-list fields=all```
#### Context Example
```json
{
    "SysAid": {
        "Filter": [
            {
                "caption": "Priority",
                "id": "priority",
                "metadata": {
                    "limit": 500,
                    "offset": 0,
                    "total": 6
                },
                "type": "list",
                "values": [
                    {
                        "caption": "All",
                        "id": "${list.all}"
                    },
                    {
                        "caption": "Highest",
                        "id": "1"
                    },
                    {
                        "caption": "Very High",
                        "id": "2"
                    },
                    {
                        "caption": "High",
                        "id": "3"
                    },
                    {
                        "caption": "Normal",
                        "id": "4"
                    },
                    {
                        "caption": "Low",
                        "id": "5"
                    }
                ]
            },
            {
                "caption": "Assigned to",
                "id": "responsibility",
                "metadata": {
                    "limit": 500,
                    "offset": 0,
                    "total": 1
                },
                "type": "list",
                "values": [
                    {
                        "caption": "sysaid-dmst",
                        "id": "1"
                    }
                ]
            },
            {
                "caption": "Status",
                "id": "status",
                "metadata": {
                    "limit": 500,
                    "offset": 0,
                    "total": 32
                },
                "type": "list",
                "values": [
                    {
                        "caption": "Active",
                        "id": "${list.active}"
                    },
                    {
                        "caption": "All",
                        "id": "${list.all}"
                    },
                    {
                        "caption": "Closed Class",
                        "id": "${list.close}"
                    },
                    {
                        "caption": "New",
                        "id": "1"
                    },
                    {
                        "caption": "Open",
                        "id": "2"
                    },
                    {
                        "caption": "Closed",
                        "id": "3"
                    },
                    {
                        "caption": "Verified closed",
                        "id": "4"
                    },
                    {
                        "caption": "Pending",
                        "id": "5"
                    },
                    {
                        "caption": "Postponed",
                        "id": "6"
                    },
                    {
                        "caption": "Deleted",
                        "id": "7"
                    },
                    {
                        "caption": "Reopened by End User",
                        "id": "8"
                    },
                    {
                        "caption": "Change opened and being analyzed",
                        "id": "18"
                    },
                    {
                        "caption": "Change Approved",
                        "id": "19"
                    },
                    {
                        "caption": "Change Rejected",
                        "id": "20"
                    },
                    {
                        "caption": "Change Completed",
                        "id": "21"
                    },
                    {
                        "caption": "Being Analyzed",
                        "id": "22"
                    },
                    {
                        "caption": "In Approval Process",
                        "id": "23"
                    },
                    {
                        "caption": "In Implementation",
                        "id": "24"
                    },
                    {
                        "caption": "In Release",
                        "id": "25"
                    },
                    {
                        "caption": "Waiting to be closed",
                        "id": "26"
                    },
                    {
                        "caption": "Problem Identified",
                        "id": "27"
                    },
                    {
                        "caption": "Problem Solved",
                        "id": "28"
                    },
                    {
                        "caption": "Closed unresolved problem",
                        "id": "29"
                    },
                    {
                        "caption": "Analyzing the solution for the problem",
                        "id": "30"
                    },
                    {
                        "caption": "User Responded",
                        "id": "31"
                    },
                    {
                        "caption": "Pending Problem resolution",
                        "id": "32"
                    },
                    {
                        "caption": "Request opened and being analyzed",
                        "id": "33"
                    },
                    {
                        "caption": "Request Completed",
                        "id": "34"
                    },
                    {
                        "caption": "Request Rejected",
                        "id": "35"
                    },
                    {
                        "caption": "Request Cancelled",
                        "id": "36"
                    },
                    {
                        "caption": "Merge Deleted",
                        "id": "39"
                    },
                    {
                        "caption": "Merge Closed",
                        "id": "40"
                    }
                ]
            },
            {
                "caption": "Urgency",
                "id": "urgency",
                "metadata": {
                    "limit": 500,
                    "offset": 0,
                    "total": 6
                },
                "type": "list",
                "values": [
                    {
                        "caption": "All",
                        "id": "${list.all}"
                    },
                    {
                        "caption": "Urgent",
                        "id": "1"
                    },
                    {
                        "caption": "Very High",
                        "id": "2"
                    },
                    {
                        "caption": "High",
                        "id": "3"
                    },
                    {
                        "caption": "Normal",
                        "id": "4"
                    },
                    {
                        "caption": "Low",
                        "id": "5"
                    }
                ]
            },
            {
                "caption": "Request user",
                "id": "request_user",
                "metadata": {
                    "limit": 500,
                    "offset": 0,
                    "total": 3
                },
                "type": "list",
                "values": [
                    {
                        "caption": "Adi Dmst",
                        "id": "3"
                    },
                    {
                        "caption": "sysaid-dmst",
                        "id": "1"
                    },
                    {
                        "caption": "Test User",
                        "id": "2"
                    }
                ]
            },
            {
                "caption": "Category",
                "id": "problem_type",
                "metadata": {
                    "limit": 500,
                    "offset": 0,
                    "total": 1
                },
                "type": "nested",
                "values": [
                    {
                        "caption": "problem_type",
                        "id": "problem_type",
                        "values": [
                            {
                                "caption": "Application ABC",
                                "id": "Application ABC",
                                "values": [
                                    {
                                        "caption": "Administration",
                                        "id": "Application ABC_Administration",
                                        "values": [
                                            {
                                                "caption": "Login/Password problem",
                                                "id": "Application ABC_Administration_Login/Password problem"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Application ABC_Administration_Other"
                                            },
                                            {
                                                "caption": "Permission request",
                                                "id": "Application ABC_Administration_Permission request"
                                            },
                                            {
                                                "caption": "Software Upgrade",
                                                "id": "Application ABC_Administration_Software Upgrade"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Module A",
                                        "id": "Application ABC_Module A",
                                        "values": [
                                            {
                                                "caption": "Error Message",
                                                "id": "Application ABC_Module A_Error Message"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Application ABC_Module A_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Module B",
                                        "id": "Application ABC_Module B",
                                        "values": [
                                            {
                                                "caption": "Error Message",
                                                "id": "Application ABC_Module B_Error Message"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Application ABC_Module B_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Module C",
                                        "id": "Application ABC_Module C",
                                        "values": [
                                            {
                                                "caption": "Error Message",
                                                "id": "Application ABC_Module C_Error Message"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Application ABC_Module C_Other"
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                "caption": "Basic Software",
                                "id": "Basic Software",
                                "values": [
                                    {
                                        "caption": "Adobe Reader",
                                        "id": "Basic Software_Adobe Reader",
                                        "values": [
                                            {
                                                "caption": "Does not work properly",
                                                "id": "Basic Software_Adobe Reader_Does not work properly"
                                            },
                                            {
                                                "caption": "How to?",
                                                "id": "Basic Software_Adobe Reader_How to?"
                                            },
                                            {
                                                "caption": "Install/Uninstall Software",
                                                "id": "Basic Software_Adobe Reader_Install/Uninstall Software"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Basic Software_Adobe Reader_Other"
                                            },
                                            {
                                                "caption": "Upgrade to newer version",
                                                "id": "Basic Software_Adobe Reader_Upgrade to newer version"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Office",
                                        "id": "Basic Software_Office",
                                        "values": [
                                            {
                                                "caption": "Does not work properly",
                                                "id": "Basic Software_Office_Does not work properly"
                                            },
                                            {
                                                "caption": "Error Message",
                                                "id": "Basic Software_Office_Error Message"
                                            },
                                            {
                                                "caption": "How to?",
                                                "id": "Basic Software_Office_How to?"
                                            },
                                            {
                                                "caption": "Install/Uninstall Software",
                                                "id": "Basic Software_Office_Install/Uninstall Software"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Basic Software_Office_Other"
                                            },
                                            {
                                                "caption": "Upgrade to newer version",
                                                "id": "Basic Software_Office_Upgrade to newer version"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Other",
                                        "id": "Basic Software_Other",
                                        "values": [
                                            {
                                                "caption": "Does not work properly",
                                                "id": "Basic Software_Other_Does not work properly"
                                            },
                                            {
                                                "caption": "Error Message",
                                                "id": "Basic Software_Other_Error Message"
                                            },
                                            {
                                                "caption": "How to?",
                                                "id": "Basic Software_Other_How to?"
                                            },
                                            {
                                                "caption": "Install/Uninstall Software",
                                                "id": "Basic Software_Other_Install/Uninstall Software"
                                            },
                                            {
                                                "caption": "Upgrade to newer version",
                                                "id": "Basic Software_Other_Upgrade to newer version"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Outlook",
                                        "id": "Basic Software_Outlook",
                                        "values": [
                                            {
                                                "caption": "Can not send/receive email",
                                                "id": "Basic Software_Outlook_Can not send/receive email"
                                            },
                                            {
                                                "caption": "Does not work properly",
                                                "id": "Basic Software_Outlook_Does not work properly"
                                            },
                                            {
                                                "caption": "Error Message",
                                                "id": "Basic Software_Outlook_Error Message"
                                            },
                                            {
                                                "caption": "How to?",
                                                "id": "Basic Software_Outlook_How to?"
                                            },
                                            {
                                                "caption": "Install/Uninstall Software",
                                                "id": "Basic Software_Outlook_Install/Uninstall Software"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Basic Software_Outlook_Other"
                                            },
                                            {
                                                "caption": "Upgrade to newer version",
                                                "id": "Basic Software_Outlook_Upgrade to newer version"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Patch Approval",
                                        "id": "Basic Software_Patch Approval",
                                        "values": [
                                            {
                                                "caption": " ",
                                                "id": "Basic Software_Patch Approval_ "
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                "caption": "Data Center",
                                "id": "Data Center",
                                "values": [
                                    {
                                        "caption": "Air conditioners",
                                        "id": "Data Center_Air conditioners",
                                        "values": [
                                            {
                                                "caption": "Other",
                                                "id": "Data Center_Air conditioners_Other"
                                            },
                                            {
                                                "caption": "Temperature too high",
                                                "id": "Data Center_Air conditioners_Temperature too high"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Availability",
                                        "id": "Data Center_Availability",
                                        "values": [
                                            {
                                                "caption": "Other",
                                                "id": "Data Center_Availability_Other"
                                            },
                                            {
                                                "caption": "Shutdown",
                                                "id": "Data Center_Availability_Shutdown"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Backup robot",
                                        "id": "Data Center_Backup robot",
                                        "values": [
                                            {
                                                "caption": "Error",
                                                "id": "Data Center_Backup robot_Error"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Data Center_Backup robot_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Electricity",
                                        "id": "Data Center_Electricity",
                                        "values": [
                                            {
                                                "caption": "Other",
                                                "id": "Data Center_Electricity_Other"
                                            },
                                            {
                                                "caption": "Power Problem",
                                                "id": "Data Center_Electricity_Power Problem"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Other",
                                        "id": "Data Center_Other",
                                        "values": [
                                            {
                                                "caption": "Other",
                                                "id": "Data Center_Other_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "UPS",
                                        "id": "Data Center_UPS",
                                        "values": [
                                            {
                                                "caption": "Error",
                                                "id": "Data Center_UPS_Error"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Data Center_UPS_Other"
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                "caption": "ERP",
                                "id": "ERP",
                                "values": [
                                    {
                                        "caption": "Administration",
                                        "id": "ERP_Administration",
                                        "values": [
                                            {
                                                "caption": "Login/Password problem",
                                                "id": "ERP_Administration_Login/Password problem"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "ERP_Administration_Other"
                                            },
                                            {
                                                "caption": "Permission request",
                                                "id": "ERP_Administration_Permission request"
                                            },
                                            {
                                                "caption": "Software Upgrade",
                                                "id": "ERP_Administration_Software Upgrade"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Finance",
                                        "id": "ERP_Finance",
                                        "values": [
                                            {
                                                "caption": "Error Message",
                                                "id": "ERP_Finance_Error Message"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "ERP_Finance_Other"
                                            },
                                            {
                                                "caption": "Problem with an invoice",
                                                "id": "ERP_Finance_Problem with an invoice"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "HR",
                                        "id": "ERP_HR",
                                        "values": [
                                            {
                                                "caption": "Can not update Employee data",
                                                "id": "ERP_HR_Can not update Employee data"
                                            },
                                            {
                                                "caption": "Error Message",
                                                "id": "ERP_HR_Error Message"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "ERP_HR_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Logistics",
                                        "id": "ERP_Logistics",
                                        "values": [
                                            {
                                                "caption": "Can not perform warehouse Exit",
                                                "id": "ERP_Logistics_Can not perform warehouse Exit"
                                            },
                                            {
                                                "caption": "Error Message",
                                                "id": "ERP_Logistics_Error Message"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "ERP_Logistics_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Other Module",
                                        "id": "ERP_Other Module",
                                        "values": [
                                            {
                                                "caption": "Error Message",
                                                "id": "ERP_Other Module_Error Message"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "ERP_Other Module_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Sales",
                                        "id": "ERP_Sales",
                                        "values": [
                                            {
                                                "caption": "Can not place an order",
                                                "id": "ERP_Sales_Can not place an order"
                                            },
                                            {
                                                "caption": "Error Message",
                                                "id": "ERP_Sales_Error Message"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "ERP_Sales_Other"
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                "caption": "Mobile Devices",
                                "id": "Mobile Devices",
                                "values": [
                                    {
                                        "caption": "Smartphone",
                                        "id": "Mobile Devices_Smartphone",
                                        "values": [
                                            {
                                                "caption": "Cannot access email",
                                                "id": "Mobile Devices_Smartphone_Cannot access email"
                                            },
                                            {
                                                "caption": "Communication Problem",
                                                "id": "Mobile Devices_Smartphone_Communication Problem"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Mobile Devices_Smartphone_Other"
                                            },
                                            {
                                                "caption": "WiFi/3G Error",
                                                "id": "Mobile Devices_Smartphone_WiFi/3G Error"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Tablet",
                                        "id": "Mobile Devices_Tablet",
                                        "values": [
                                            {
                                                "caption": "Cannot access email",
                                                "id": "Mobile Devices_Tablet_Cannot access email"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Mobile Devices_Tablet_Other"
                                            },
                                            {
                                                "caption": "WiFi/3G Error",
                                                "id": "Mobile Devices_Tablet_WiFi/3G Error"
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                "caption": "Network Equipment",
                                "id": "Network Equipment",
                                "values": [
                                    {
                                        "caption": "Firewall",
                                        "id": "Network Equipment_Firewall",
                                        "values": [
                                            {
                                                "caption": "Change Configuration",
                                                "id": "Network Equipment_Firewall_Change Configuration"
                                            },
                                            {
                                                "caption": "Error",
                                                "id": "Network Equipment_Firewall_Error"
                                            },
                                            {
                                                "caption": "Install new",
                                                "id": "Network Equipment_Firewall_Install new"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Network Equipment_Firewall_Other"
                                            },
                                            {
                                                "caption": "Policy update",
                                                "id": "Network Equipment_Firewall_Policy update"
                                            },
                                            {
                                                "caption": "Upgrade",
                                                "id": "Network Equipment_Firewall_Upgrade"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Other",
                                        "id": "Network Equipment_Other",
                                        "values": [
                                            {
                                                "caption": "Other",
                                                "id": "Network Equipment_Other_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Router",
                                        "id": "Network Equipment_Router",
                                        "values": [
                                            {
                                                "caption": "Change Configuration",
                                                "id": "Network Equipment_Router_Change Configuration"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Network Equipment_Router_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Switch",
                                        "id": "Network Equipment_Switch",
                                        "values": [
                                            {
                                                "caption": "Change Configuration",
                                                "id": "Network Equipment_Switch_Change Configuration"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Network Equipment_Switch_Other"
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                "caption": "Other Equipment",
                                "id": "Other Equipment",
                                "values": [
                                    {
                                        "caption": "Faxes",
                                        "id": "Other Equipment_Faxes",
                                        "values": [
                                            {
                                                "caption": "Error",
                                                "id": "Other Equipment_Faxes_Error"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Other Equipment_Faxes_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "HandHelds",
                                        "id": "Other Equipment_HandHelds",
                                        "values": [
                                            {
                                                "caption": "Error",
                                                "id": "Other Equipment_HandHelds_Error"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Other Equipment_HandHelds_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Network printers",
                                        "id": "Other Equipment_Network printers",
                                        "values": [
                                            {
                                                "caption": "Does not work (Not Printing)",
                                                "id": "Other Equipment_Network printers_Does not work (Not Printing)"
                                            },
                                            {
                                                "caption": "Error",
                                                "id": "Other Equipment_Network printers_Error"
                                            },
                                            {
                                                "caption": "Install",
                                                "id": "Other Equipment_Network printers_Install"
                                            },
                                            {
                                                "caption": "Noisy",
                                                "id": "Other Equipment_Network printers_Noisy"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Other Equipment_Network printers_Other"
                                            },
                                            {
                                                "caption": "Paper stuck",
                                                "id": "Other Equipment_Network printers_Paper stuck"
                                            },
                                            {
                                                "caption": "Printout is weak and unclear",
                                                "id": "Other Equipment_Network printers_Printout is weak and unclear"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Others",
                                        "id": "Other Equipment_Others",
                                        "values": [
                                            {
                                                "caption": "Error",
                                                "id": "Other Equipment_Others_Error"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Other Equipment_Others_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "PhotoCopy Machine",
                                        "id": "Other Equipment_PhotoCopy Machine",
                                        "values": [
                                            {
                                                "caption": "Error",
                                                "id": "Other Equipment_PhotoCopy Machine_Error"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Other Equipment_PhotoCopy Machine_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Projectors",
                                        "id": "Other Equipment_Projectors",
                                        "values": [
                                            {
                                                "caption": "Error",
                                                "id": "Other Equipment_Projectors_Error"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Other Equipment_Projectors_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Terminals",
                                        "id": "Other Equipment_Terminals",
                                        "values": [
                                            {
                                                "caption": "Error",
                                                "id": "Other Equipment_Terminals_Error"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Other Equipment_Terminals_Other"
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                "caption": "Servers",
                                "id": "Servers",
                                "values": [
                                    {
                                        "caption": "Active Directory",
                                        "id": "Servers_Active Directory",
                                        "values": [
                                            {
                                                "caption": "Add user",
                                                "id": "Servers_Active Directory_Add user"
                                            },
                                            {
                                                "caption": "Cannot Connect to the server",
                                                "id": "Servers_Active Directory_Cannot Connect to the server"
                                            },
                                            {
                                                "caption": "Error message",
                                                "id": "Servers_Active Directory_Error message"
                                            },
                                            {
                                                "caption": "Install/Uninstall",
                                                "id": "Servers_Active Directory_Install/Uninstall"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Servers_Active Directory_Other"
                                            },
                                            {
                                                "caption": "Performance issues",
                                                "id": "Servers_Active Directory_Performance issues"
                                            },
                                            {
                                                "caption": "Permissions",
                                                "id": "Servers_Active Directory_Permissions"
                                            },
                                            {
                                                "caption": "Remove user",
                                                "id": "Servers_Active Directory_Remove user"
                                            },
                                            {
                                                "caption": "Reset password",
                                                "id": "Servers_Active Directory_Reset password"
                                            },
                                            {
                                                "caption": "Unlock account",
                                                "id": "Servers_Active Directory_Unlock account"
                                            },
                                            {
                                                "caption": "Update group policy",
                                                "id": "Servers_Active Directory_Update group policy"
                                            },
                                            {
                                                "caption": "Update user",
                                                "id": "Servers_Active Directory_Update user"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "DHCP",
                                        "id": "Servers_DHCP",
                                        "values": [
                                            {
                                                "caption": "Cannot Connect",
                                                "id": "Servers_DHCP_Cannot Connect"
                                            },
                                            {
                                                "caption": "Error message",
                                                "id": "Servers_DHCP_Error message"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Servers_DHCP_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "DNS",
                                        "id": "Servers_DNS",
                                        "values": [
                                            {
                                                "caption": "Cannot Connect",
                                                "id": "Servers_DNS_Cannot Connect"
                                            },
                                            {
                                                "caption": "Error message",
                                                "id": "Servers_DNS_Error message"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Servers_DNS_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Exchange Server",
                                        "id": "Servers_Exchange Server",
                                        "values": [
                                            {
                                                "caption": "Cannot Connect to the server",
                                                "id": "Servers_Exchange Server_Cannot Connect to the server"
                                            },
                                            {
                                                "caption": "Error message",
                                                "id": "Servers_Exchange Server_Error message"
                                            },
                                            {
                                                "caption": "Hardware Problems",
                                                "id": "Servers_Exchange Server_Hardware Problems"
                                            },
                                            {
                                                "caption": "Hardware Upgrade",
                                                "id": "Servers_Exchange Server_Hardware Upgrade"
                                            },
                                            {
                                                "caption": "Install/Uninstall",
                                                "id": "Servers_Exchange Server_Install/Uninstall"
                                            },
                                            {
                                                "caption": "Move",
                                                "id": "Servers_Exchange Server_Move"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Servers_Exchange Server_Other"
                                            },
                                            {
                                                "caption": "Performance issues",
                                                "id": "Servers_Exchange Server_Performance issues"
                                            },
                                            {
                                                "caption": "Permissions",
                                                "id": "Servers_Exchange Server_Permissions"
                                            },
                                            {
                                                "caption": "Software Upgrade",
                                                "id": "Servers_Exchange Server_Software Upgrade"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "File Server",
                                        "id": "Servers_File Server",
                                        "values": [
                                            {
                                                "caption": "Cannot Connect to the server",
                                                "id": "Servers_File Server_Cannot Connect to the server"
                                            },
                                            {
                                                "caption": "Error message",
                                                "id": "Servers_File Server_Error message"
                                            },
                                            {
                                                "caption": "Hardware Problems",
                                                "id": "Servers_File Server_Hardware Problems"
                                            },
                                            {
                                                "caption": "Hardware Upgrade",
                                                "id": "Servers_File Server_Hardware Upgrade"
                                            },
                                            {
                                                "caption": "Install/Uninstall",
                                                "id": "Servers_File Server_Install/Uninstall"
                                            },
                                            {
                                                "caption": "Move",
                                                "id": "Servers_File Server_Move"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Servers_File Server_Other"
                                            },
                                            {
                                                "caption": "Performance issues",
                                                "id": "Servers_File Server_Performance issues"
                                            },
                                            {
                                                "caption": "Permissions",
                                                "id": "Servers_File Server_Permissions"
                                            },
                                            {
                                                "caption": "Restore a file/directory",
                                                "id": "Servers_File Server_Restore a file/directory"
                                            },
                                            {
                                                "caption": "Software Upgrade",
                                                "id": "Servers_File Server_Software Upgrade"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Other",
                                        "id": "Servers_Other",
                                        "values": [
                                            {
                                                "caption": "Hardware Problems",
                                                "id": "Servers_Other_Hardware Problems"
                                            },
                                            {
                                                "caption": "Hardware Upgrade",
                                                "id": "Servers_Other_Hardware Upgrade"
                                            },
                                            {
                                                "caption": "Move",
                                                "id": "Servers_Other_Move"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Servers_Other_Other"
                                            },
                                            {
                                                "caption": "Software Upgrade",
                                                "id": "Servers_Other_Software Upgrade"
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                "caption": "Telephony / Voice",
                                "id": "Telephony / Voice",
                                "values": [
                                    {
                                        "caption": "Mobile phone",
                                        "id": "Telephony / Voice_Mobile phone",
                                        "values": [
                                            {
                                                "caption": "How to ?",
                                                "id": "Telephony / Voice_Mobile phone_How to ?"
                                            },
                                            {
                                                "caption": "New",
                                                "id": "Telephony / Voice_Mobile phone_New"
                                            },
                                            {
                                                "caption": "No dial tone",
                                                "id": "Telephony / Voice_Mobile phone_No dial tone"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Telephony / Voice_Mobile phone_Other"
                                            },
                                            {
                                                "caption": "Replace",
                                                "id": "Telephony / Voice_Mobile phone_Replace"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Office Phones",
                                        "id": "Telephony / Voice_Office Phones",
                                        "values": [
                                            {
                                                "caption": "How to ?",
                                                "id": "Telephony / Voice_Office Phones_How to ?"
                                            },
                                            {
                                                "caption": "Install new",
                                                "id": "Telephony / Voice_Office Phones_Install new"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "Telephony / Voice_Office Phones_Other"
                                            },
                                            {
                                                "caption": "Replace",
                                                "id": "Telephony / Voice_Office Phones_Replace"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Other",
                                        "id": "Telephony / Voice_Other",
                                        "values": [
                                            {
                                                "caption": "Other",
                                                "id": "Telephony / Voice_Other_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Telephone System",
                                        "id": "Telephony / Voice_Telephone System",
                                        "values": [
                                            {
                                                "caption": "Does not work properly",
                                                "id": "Telephony / Voice_Telephone System_Does not work properly"
                                            },
                                            {
                                                "caption": "Upgrade",
                                                "id": "Telephony / Voice_Telephone System_Upgrade"
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                "caption": "User Workstation",
                                "id": "User Workstation",
                                "values": [
                                    {
                                        "caption": "Keyboard",
                                        "id": "User Workstation_Keyboard",
                                        "values": [
                                            {
                                                "caption": "Does not respond",
                                                "id": "User Workstation_Keyboard_Does not respond"
                                            },
                                            {
                                                "caption": "Install new",
                                                "id": "User Workstation_Keyboard_Install new"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "User Workstation_Keyboard_Other"
                                            },
                                            {
                                                "caption": "Replace",
                                                "id": "User Workstation_Keyboard_Replace"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Laptop",
                                        "id": "User Workstation_Laptop",
                                        "values": [
                                            {
                                                "caption": "Add Memory",
                                                "id": "User Workstation_Laptop_Add Memory"
                                            },
                                            {
                                                "caption": "Authorizations (add  change)",
                                                "id": "User Workstation_Laptop_Authorizations (add  change)"
                                            },
                                            {
                                                "caption": "Battery Replacement",
                                                "id": "User Workstation_Laptop_Battery Replacement"
                                            },
                                            {
                                                "caption": "Can not access Internet",
                                                "id": "User Workstation_Laptop_Can not access Internet"
                                            },
                                            {
                                                "caption": "Can not access network drive",
                                                "id": "User Workstation_Laptop_Can not access network drive"
                                            },
                                            {
                                                "caption": "Can not access page - Blocked",
                                                "id": "User Workstation_Laptop_Can not access page - Blocked"
                                            },
                                            {
                                                "caption": "Can not Open File",
                                                "id": "User Workstation_Laptop_Can not Open File"
                                            },
                                            {
                                                "caption": "Communication Problems",
                                                "id": "User Workstation_Laptop_Communication Problems"
                                            },
                                            {
                                                "caption": "Does not turn on",
                                                "id": "User Workstation_Laptop_Does not turn on"
                                            },
                                            {
                                                "caption": "Does not work correctly",
                                                "id": "User Workstation_Laptop_Does not work correctly"
                                            },
                                            {
                                                "caption": "Error in Browser",
                                                "id": "User Workstation_Laptop_Error in Browser"
                                            },
                                            {
                                                "caption": "How to?",
                                                "id": "User Workstation_Laptop_How to?"
                                            },
                                            {
                                                "caption": "Install new",
                                                "id": "User Workstation_Laptop_Install new"
                                            },
                                            {
                                                "caption": "Internet Very Slow",
                                                "id": "User Workstation_Laptop_Internet Very Slow"
                                            },
                                            {
                                                "caption": "Is working slow",
                                                "id": "User Workstation_Laptop_Is working slow"
                                            },
                                            {
                                                "caption": "Login/Password Problem",
                                                "id": "User Workstation_Laptop_Login/Password Problem"
                                            },
                                            {
                                                "caption": "Move (User  Location)",
                                                "id": "User Workstation_Laptop_Move (User  Location)"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "User Workstation_Laptop_Other"
                                            },
                                            {
                                                "caption": "Replace",
                                                "id": "User Workstation_Laptop_Replace"
                                            },
                                            {
                                                "caption": "Replace CPU",
                                                "id": "User Workstation_Laptop_Replace CPU"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Mouse",
                                        "id": "User Workstation_Mouse",
                                        "values": [
                                            {
                                                "caption": "Does not respond",
                                                "id": "User Workstation_Mouse_Does not respond"
                                            },
                                            {
                                                "caption": "Install new",
                                                "id": "User Workstation_Mouse_Install new"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "User Workstation_Mouse_Other"
                                            },
                                            {
                                                "caption": "Replace",
                                                "id": "User Workstation_Mouse_Replace"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Other",
                                        "id": "User Workstation_Other",
                                        "values": [
                                            {
                                                "caption": "Other",
                                                "id": "User Workstation_Other_Other"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "PC",
                                        "id": "User Workstation_PC",
                                        "values": [
                                            {
                                                "caption": "Add Memory",
                                                "id": "User Workstation_PC_Add Memory"
                                            },
                                            {
                                                "caption": "Authorizations (add  change)",
                                                "id": "User Workstation_PC_Authorizations (add  change)"
                                            },
                                            {
                                                "caption": "Can not access Internet",
                                                "id": "User Workstation_PC_Can not access Internet"
                                            },
                                            {
                                                "caption": "Can not access network drive",
                                                "id": "User Workstation_PC_Can not access network drive"
                                            },
                                            {
                                                "caption": "Can not access page - Blocked",
                                                "id": "User Workstation_PC_Can not access page - Blocked"
                                            },
                                            {
                                                "caption": "Can not Open File",
                                                "id": "User Workstation_PC_Can not Open File"
                                            },
                                            {
                                                "caption": "Communication Problems",
                                                "id": "User Workstation_PC_Communication Problems"
                                            },
                                            {
                                                "caption": "Does not turn on",
                                                "id": "User Workstation_PC_Does not turn on"
                                            },
                                            {
                                                "caption": "Does not work properly",
                                                "id": "User Workstation_PC_Does not work properly"
                                            },
                                            {
                                                "caption": "Error in Browser",
                                                "id": "User Workstation_PC_Error in Browser"
                                            },
                                            {
                                                "caption": "How to?",
                                                "id": "User Workstation_PC_How to?"
                                            },
                                            {
                                                "caption": "Install new",
                                                "id": "User Workstation_PC_Install new"
                                            },
                                            {
                                                "caption": "Internet Very Slow",
                                                "id": "User Workstation_PC_Internet Very Slow"
                                            },
                                            {
                                                "caption": "Is working slow",
                                                "id": "User Workstation_PC_Is working slow"
                                            },
                                            {
                                                "caption": "Login/Password Problem",
                                                "id": "User Workstation_PC_Login/Password Problem"
                                            },
                                            {
                                                "caption": "Move (User  Location)",
                                                "id": "User Workstation_PC_Move (User  Location)"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "User Workstation_PC_Other"
                                            },
                                            {
                                                "caption": "Replace",
                                                "id": "User Workstation_PC_Replace"
                                            },
                                            {
                                                "caption": "Replace CPU",
                                                "id": "User Workstation_PC_Replace CPU"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Printer",
                                        "id": "User Workstation_Printer",
                                        "values": [
                                            {
                                                "caption": "Does not turn on",
                                                "id": "User Workstation_Printer_Does not turn on"
                                            },
                                            {
                                                "caption": "Does not work (Not Printing)",
                                                "id": "User Workstation_Printer_Does not work (Not Printing)"
                                            },
                                            {
                                                "caption": "Install new",
                                                "id": "User Workstation_Printer_Install new"
                                            },
                                            {
                                                "caption": "Move",
                                                "id": "User Workstation_Printer_Move"
                                            },
                                            {
                                                "caption": "No Paper",
                                                "id": "User Workstation_Printer_No Paper"
                                            },
                                            {
                                                "caption": "Noisy",
                                                "id": "User Workstation_Printer_Noisy"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "User Workstation_Printer_Other"
                                            },
                                            {
                                                "caption": "Paper stuck",
                                                "id": "User Workstation_Printer_Paper stuck"
                                            },
                                            {
                                                "caption": "Printout is weak and unclear",
                                                "id": "User Workstation_Printer_Printout is weak and unclear"
                                            },
                                            {
                                                "caption": "Replace",
                                                "id": "User Workstation_Printer_Replace"
                                            }
                                        ]
                                    },
                                    {
                                        "caption": "Screen",
                                        "id": "User Workstation_Screen",
                                        "values": [
                                            {
                                                "caption": "Does not turn on",
                                                "id": "User Workstation_Screen_Does not turn on"
                                            },
                                            {
                                                "caption": "Does not work properly",
                                                "id": "User Workstation_Screen_Does not work properly"
                                            },
                                            {
                                                "caption": "Install new",
                                                "id": "User Workstation_Screen_Install new"
                                            },
                                            {
                                                "caption": "Other",
                                                "id": "User Workstation_Screen_Other"
                                            },
                                            {
                                                "caption": "Replace",
                                                "id": "User Workstation_Screen_Replace"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                ]
            },
            {
                "caption": "Archive",
                "id": "archive",
                "metadata": {
                    "limit": 500,
                    "offset": 0,
                    "total": 0
                },
                "type": "boolean",
                "values": []
            },
            {
                "caption": "Admin Group",
                "id": "assigned_group",
                "metadata": {
                    "limit": 500,
                    "offset": 0,
                    "total": 3
                },
                "type": "list",
                "values": [
                    {
                        "caption": "All Groups",
                        "id": "${list.group.all}"
                    },
                    {
                        "caption": "none",
                        "id": "${list.group.none}"
                    },
                    {
                        "caption": "Support",
                        "id": "1"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Filter Results:
>|Id|Caption|Type|Values|
>|---|---|---|---|
>| priority | Priority | list | ${list.all}: All,<br/>1: Highest,<br/>2: Very High,<br/>3: High,<br/>4: Normal,<br/>5: Low |
>| responsibility | Assigned to | list | 1: sysaid-dmst |
>| status | Status | list | ${list.active}: Active,<br/>${list.all}: All,<br/>${list.close}: Closed Class,<br/>1: New,<br/>2: Open,<br/>3: Closed,<br/>4: Verified closed,<br/>5: Pending,<br/>6: Postponed,<br/>7: Deleted,<br/>8: Reopened by End User,<br/>18: Change opened and being analyzed,<br/>19: Change Approved,<br/>20: Change Rejected,<br/>21: Change Completed,<br/>22: Being Analyzed,<br/>23: In Approval Process,<br/>24: In Implementation,<br/>25: In Release,<br/>26: Waiting to be closed,<br/>27: Problem Identified,<br/>28: Problem Solved,<br/>29: Closed unresolved problem,<br/>30: Analyzing the solution for the problem,<br/>31: User Responded,<br/>32: Pending Problem resolution,<br/>33: Request opened and being analyzed,<br/>34: Request Completed,<br/>35: Request Rejected,<br/>36: Request Cancelled,<br/>39: Merge Deleted,<br/>40: Merge Closed |
>| urgency | Urgency | list | ${list.all}: All,<br/>1: Urgent,<br/>2: Very High,<br/>3: High,<br/>4: Normal,<br/>5: Low |
>| request_user | Request user | list | 3: Adi Dmst,<br/>1: sysaid-dmst,<br/>2: Test User |
>| problem_type | Category | nested | problem_type: problem_type |
>| archive | Archive | boolean |  |
>| assigned_group | Admin Group | list | ${list.group.all}: All Groups,<br/>${list.group.none}: none,<br/>1: Support |


### sysaid-user-list
***
Get list of users in SysAid. Cortex XSOAR recommends filtering the results by the desired fields.


#### Base Command

`sysaid-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Comma separated list of fields to return to context data. The valid fields can be retrieved using the "sysaid-table-list" command with the "entity=user" argument. You can send "all" for debugging purposes. | Required | 
| type | The user type to retrieve. Defaults to all user types if not specified. Possible values are: admin, user, manager. | Optional | 
| page_number | Index of the page of results to retrieve. Default is 1. | Optional | 
| page_size | The number of users to return on a page. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SysAid.User.id | String | The ID of the user. | 
| SysAid.User.name | String | The name of the user. | 
| SysAid.User.isAdmin | Boolean | Whether the SysAid user is an admin or not. | 
| SysAid.User.isSysAidAdmin | Boolean | Whether the SysAid user is a SysAid admin or not. | 
| SysAid.User.isManager | Boolean | Whether the SysAid user is a manager or not. | 
| SysAid.User.isGuest | Boolean | Whether the SysAid user is a guest or not. | 

#### Command example
```!sysaid-user-list fields=all```
#### Context Example
```json
{
    "SysAid": {
        "User": [
            {
                "id": "3",
                "info": [
                    {
                        "key": "cust_list1",
                        "keyCaption": "User Custom List 1",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "notes",
                        "keyCaption": "Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "login_domain",
                        "keyCaption": "Domain",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "secondary_email",
                        "keyCaption": "Secondary Email",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "building",
                        "keyCaption": "Building",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "User Custom List 2",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_type",
                        "keyCaption": "User Type",
                        "value": "End user",
                        "valueCaption": "End user",
                        "valueClass": ""
                    },
                    {
                        "key": "links",
                        "keyCaption": "Links",
                        "value": "sysaid-adi-dmst",
                        "valueCaption": "sysaid-adi-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Manager",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history_version",
                        "keyCaption": "History Version",
                        "value": "1",
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "User Custom Int 2",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "User Custom Int 1",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "User Custom Date 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "User Custom Date 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history",
                        "keyCaption": "History",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_name",
                        "keyCaption": "Display Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "helpdesk",
                        "keyCaption": "Service Desk",
                        "value": "sysaid-adi-dmst",
                        "valueCaption": "sysaid-adi-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cell_phone",
                        "keyCaption": "Cellular phone",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "login_user",
                        "keyCaption": "User Name",
                        "value": "sysaid-adi-dmst",
                        "valueCaption": "sysaid-adi-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "phone",
                        "keyCaption": "Phone",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_notifications",
                        "keyCaption": "Receive automatic SR email notifications",
                        "value": "true",
                        "valueCaption": "true",
                        "valueClass": ""
                    },
                    {
                        "key": "enable_login_to_eup",
                        "keyCaption": "Enable login to the End User Portal",
                        "value": "Y",
                        "valueCaption": "Y",
                        "valueClass": ""
                    },
                    {
                        "key": "relation_graph",
                        "keyCaption": "CI Relations Graph",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "chat_nick_name",
                        "keyCaption": "Chat Nickname",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "attachments",
                        "keyCaption": "Attachments",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "User Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "calculated_user_name",
                        "keyCaption": "Calculated User Name",
                        "value": "Adi Dmst",
                        "valueCaption": "Adi Dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "floor",
                        "keyCaption": "Floor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "first_name",
                        "keyCaption": "First Name",
                        "value": "Adi",
                        "valueCaption": "Adi",
                        "valueClass": ""
                    },
                    {
                        "key": "cubic",
                        "keyCaption": "Cubicle",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "expiration_time",
                        "keyCaption": "Expiration Date",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_name",
                        "keyCaption": "Last Name",
                        "value": "Dmst",
                        "valueCaption": "Dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "groups",
                        "keyCaption": "Groups",
                        "value": "sysaid-adi-dmst",
                        "valueCaption": "sysaid-adi-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "User Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "User Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ldap_user_guid",
                        "keyCaption": "User GUID",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_address",
                        "keyCaption": "Email",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disable",
                        "keyCaption": "Disabled",
                        "value": "N",
                        "valueCaption": "N",
                        "valueClass": ""
                    },
                    {
                        "key": "car_number",
                        "keyCaption": "Car license",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "my_photo_url",
                        "keyCaption": "My Photo",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ldap_distinguished_name",
                        "keyCaption": "User Distinguished Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sms_number",
                        "keyCaption": "Text message",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "openServiceRequest",
                        "keyCaption": "Active Service Record",
                        "value": "1",
                        "valueCaption": "1",
                        "valueClass": ""
                    }
                ],
                "isAdmin": false,
                "isGuest": false,
                "isManager": false,
                "isSysAidAdmin": false,
                "name": "sysaid-adi-dmst"
            },
            {
                "id": "1",
                "info": [
                    {
                        "key": "cust_list1",
                        "keyCaption": "User Custom List 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "notes",
                        "keyCaption": "Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "login_domain",
                        "keyCaption": "Domain",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "secondary_email",
                        "keyCaption": "Secondary Email",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "building",
                        "keyCaption": "Building",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "User Custom List 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_type",
                        "keyCaption": "User Type",
                        "value": "Administrator",
                        "valueCaption": "Administrator",
                        "valueClass": ""
                    },
                    {
                        "key": "links",
                        "keyCaption": "Links",
                        "value": "sysaid-dmst",
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history_version",
                        "keyCaption": "History Version",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "User Custom Int 2",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "User Custom Int 1",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "User Custom Date 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "User Custom Date 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history",
                        "keyCaption": "History",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_name",
                        "keyCaption": "Display Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "helpdesk",
                        "keyCaption": "Service Desk",
                        "value": "sysaid-dmst",
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cell_phone",
                        "keyCaption": "Cellular phone",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "login_user",
                        "keyCaption": "User Name",
                        "value": "sysaid-dmst",
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "phone",
                        "keyCaption": "Phone",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_notifications",
                        "keyCaption": "Receive automatic SR email notifications",
                        "value": "true",
                        "valueCaption": "true",
                        "valueClass": ""
                    },
                    {
                        "key": "enable_login_to_eup",
                        "keyCaption": "Enable login to the End User Portal",
                        "value": "Y",
                        "valueCaption": "Y",
                        "valueClass": ""
                    },
                    {
                        "key": "relation_graph",
                        "keyCaption": "CI Relations Graph",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "chat_nick_name",
                        "keyCaption": "Chat Nickname",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "attachments",
                        "keyCaption": "Attachments",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "User Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "calculated_user_name",
                        "keyCaption": "Calculated User Name",
                        "value": "sysaid-dmst",
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "floor",
                        "keyCaption": "Floor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "first_name",
                        "keyCaption": "First Name",
                        "value": "sysaid-dmst",
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cubic",
                        "keyCaption": "Cubicle",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "expiration_time",
                        "keyCaption": "Expiration Date",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_name",
                        "keyCaption": "Last Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "groups",
                        "keyCaption": "Groups",
                        "value": "sysaid-dmst",
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "User Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "User Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ldap_user_guid",
                        "keyCaption": "User GUID",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_address",
                        "keyCaption": "Email",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disable",
                        "keyCaption": "Disabled",
                        "value": "N",
                        "valueCaption": "N",
                        "valueClass": ""
                    },
                    {
                        "key": "car_number",
                        "keyCaption": "Car license",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "my_photo_url",
                        "keyCaption": "My Photo",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ldap_distinguished_name",
                        "keyCaption": "User Distinguished Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sms_number",
                        "keyCaption": "Text message",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "openServiceRequest",
                        "keyCaption": "Active Service Record",
                        "value": "4",
                        "valueCaption": "4",
                        "valueClass": ""
                    }
                ],
                "isAdmin": true,
                "isGuest": false,
                "isManager": true,
                "isSysAidAdmin": true,
                "name": "sysaid-dmst"
            },
            {
                "id": "2",
                "info": [
                    {
                        "key": "cust_list1",
                        "keyCaption": "User Custom List 1",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "notes",
                        "keyCaption": "Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "login_domain",
                        "keyCaption": "Domain",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "secondary_email",
                        "keyCaption": "Secondary Email",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "building",
                        "keyCaption": "Building",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "User Custom List 2",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_type",
                        "keyCaption": "User Type",
                        "value": "End user",
                        "valueCaption": "End user",
                        "valueClass": ""
                    },
                    {
                        "key": "links",
                        "keyCaption": "Links",
                        "value": "Test-User",
                        "valueCaption": "Test-User",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Manager",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history_version",
                        "keyCaption": "History Version",
                        "value": "1",
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "User Custom Int 2",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "User Custom Int 1",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "User Custom Date 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "User Custom Date 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history",
                        "keyCaption": "History",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_name",
                        "keyCaption": "Display Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "helpdesk",
                        "keyCaption": "Service Desk",
                        "value": "Test-User",
                        "valueCaption": "Test-User",
                        "valueClass": ""
                    },
                    {
                        "key": "cell_phone",
                        "keyCaption": "Cellular phone",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "login_user",
                        "keyCaption": "User Name",
                        "value": "Test-User",
                        "valueCaption": "Test-User",
                        "valueClass": ""
                    },
                    {
                        "key": "phone",
                        "keyCaption": "Phone",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_notifications",
                        "keyCaption": "Receive automatic SR email notifications",
                        "value": "true",
                        "valueCaption": "true",
                        "valueClass": ""
                    },
                    {
                        "key": "enable_login_to_eup",
                        "keyCaption": "Enable login to the End User Portal",
                        "value": "Y",
                        "valueCaption": "Y",
                        "valueClass": ""
                    },
                    {
                        "key": "relation_graph",
                        "keyCaption": "CI Relations Graph",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "chat_nick_name",
                        "keyCaption": "Chat Nickname",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "attachments",
                        "keyCaption": "Attachments",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "User Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "calculated_user_name",
                        "keyCaption": "Calculated User Name",
                        "value": "Test User",
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "floor",
                        "keyCaption": "Floor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "first_name",
                        "keyCaption": "First Name",
                        "value": "Test",
                        "valueCaption": "Test",
                        "valueClass": ""
                    },
                    {
                        "key": "cubic",
                        "keyCaption": "Cubicle",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "expiration_time",
                        "keyCaption": "Expiration Date",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_name",
                        "keyCaption": "Last Name",
                        "value": "User",
                        "valueCaption": "User",
                        "valueClass": ""
                    },
                    {
                        "key": "groups",
                        "keyCaption": "Groups",
                        "value": "Test-User",
                        "valueCaption": "Test-User",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "User Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "User Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ldap_user_guid",
                        "keyCaption": "User GUID",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_address",
                        "keyCaption": "Email",
                        "value": "Test@dmstdev.com",
                        "valueCaption": "Test@dmstdev.com",
                        "valueClass": ""
                    },
                    {
                        "key": "disable",
                        "keyCaption": "Disabled",
                        "value": "N",
                        "valueCaption": "N",
                        "valueClass": ""
                    },
                    {
                        "key": "car_number",
                        "keyCaption": "Car license",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "my_photo_url",
                        "keyCaption": "My Photo",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ldap_distinguished_name",
                        "keyCaption": "User Distinguished Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sms_number",
                        "keyCaption": "Text message",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "openServiceRequest",
                        "keyCaption": "Active Service Record",
                        "value": "4",
                        "valueCaption": "4",
                        "valueClass": ""
                    }
                ],
                "isAdmin": false,
                "isGuest": false,
                "isManager": false,
                "isSysAidAdmin": false,
                "name": "Test-User"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 100 results from page 1:
>### Filter Results:
>|id|name|isAdmin|isManager|isSysAidAdmin|isGuest|
>|---|---|---|---|---|---|
>| 3 | sysaid-adi-dmst | false | false | false | false |
>| 1 | sysaid-dmst | true | true | true | false |
>| 2 | Test-User | false | false | false | false |


### sysaid-user-search
***
Get information about a specific asset. Cortex XSOAR recommends filtering the results by the desired fields.


#### Base Command

`sysaid-user-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The search criteria. | Required | 
| fields | Comma separated list of fields to return to context data. The valid fields can be retrieved using the "sysaid-table-list" command with the "entity=user" argument. You can send "all" for debugging purposes. | Required | 
| type | The user types to retrieve. Defaults to all user types if not specified. Possible values are: admin, user, manager. | Optional | 
| page_number | Index of the page of results to retrieve. Default is 1. | Optional | 
| page_size | The number of users to return on a page. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SysAid.User.id | String | The ID of the user. | 
| SysAid.User.name | String | The name of the user. | 
| SysAid.User.isAdmin | Boolean | Whether the SysAid user is an admin or not. | 
| SysAid.User.isSysAidAdmin | Boolean | Whether the SysAid user is a SysAid admin or not. | 
| SysAid.User.isManager | Boolean | Whether the SysAid user is a manager or not. | 
| SysAid.User.isGuest | Boolean | Whether the SysAid user is a guest or not. | 

#### Command example
```!sysaid-user-search query=dmst fields=all```
#### Context Example
```json
{
    "SysAid": {
        "User": [
            {
                "id": "3",
                "info": [
                    {
                        "key": "cust_list1",
                        "keyCaption": "User Custom List 1",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "notes",
                        "keyCaption": "Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "login_domain",
                        "keyCaption": "Domain",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "secondary_email",
                        "keyCaption": "Secondary Email",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "building",
                        "keyCaption": "Building",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "User Custom List 2",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_type",
                        "keyCaption": "User Type",
                        "value": "End user",
                        "valueCaption": "End user",
                        "valueClass": ""
                    },
                    {
                        "key": "links",
                        "keyCaption": "Links",
                        "value": "sysaid-adi-dmst",
                        "valueCaption": "sysaid-adi-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Manager",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history_version",
                        "keyCaption": "History Version",
                        "value": "1",
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "User Custom Int 2",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "User Custom Int 1",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "User Custom Date 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "User Custom Date 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history",
                        "keyCaption": "History",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_name",
                        "keyCaption": "Display Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "helpdesk",
                        "keyCaption": "Service Desk",
                        "value": "sysaid-adi-dmst",
                        "valueCaption": "sysaid-adi-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cell_phone",
                        "keyCaption": "Cellular phone",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "login_user",
                        "keyCaption": "User Name",
                        "value": "sysaid-adi-dmst",
                        "valueCaption": "sysaid-adi-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "phone",
                        "keyCaption": "Phone",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_notifications",
                        "keyCaption": "Receive automatic SR email notifications",
                        "value": "true",
                        "valueCaption": "true",
                        "valueClass": ""
                    },
                    {
                        "key": "enable_login_to_eup",
                        "keyCaption": "Enable login to the End User Portal",
                        "value": "Y",
                        "valueCaption": "Y",
                        "valueClass": ""
                    },
                    {
                        "key": "relation_graph",
                        "keyCaption": "CI Relations Graph",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "chat_nick_name",
                        "keyCaption": "Chat Nickname",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "attachments",
                        "keyCaption": "Attachments",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "User Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "calculated_user_name",
                        "keyCaption": "Calculated User Name",
                        "value": "Adi Dmst",
                        "valueCaption": "Adi Dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "floor",
                        "keyCaption": "Floor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "first_name",
                        "keyCaption": "First Name",
                        "value": "Adi",
                        "valueCaption": "Adi",
                        "valueClass": ""
                    },
                    {
                        "key": "cubic",
                        "keyCaption": "Cubicle",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "expiration_time",
                        "keyCaption": "Expiration Date",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_name",
                        "keyCaption": "Last Name",
                        "value": "Dmst",
                        "valueCaption": "Dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "groups",
                        "keyCaption": "Groups",
                        "value": "sysaid-adi-dmst",
                        "valueCaption": "sysaid-adi-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "User Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "User Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ldap_user_guid",
                        "keyCaption": "User GUID",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_address",
                        "keyCaption": "Email",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disable",
                        "keyCaption": "Disabled",
                        "value": "N",
                        "valueCaption": "N",
                        "valueClass": ""
                    },
                    {
                        "key": "car_number",
                        "keyCaption": "Car license",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "my_photo_url",
                        "keyCaption": "My Photo",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": "0",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ldap_distinguished_name",
                        "keyCaption": "User Distinguished Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sms_number",
                        "keyCaption": "Text message",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "openServiceRequest",
                        "keyCaption": "Active Service Record",
                        "value": "1",
                        "valueCaption": "1",
                        "valueClass": ""
                    }
                ],
                "isAdmin": false,
                "isGuest": false,
                "isManager": false,
                "isSysAidAdmin": false,
                "name": "sysaid-adi-dmst"
            },
            {
                "id": "1",
                "info": [
                    {
                        "key": "cust_list1",
                        "keyCaption": "User Custom List 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "notes",
                        "keyCaption": "Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "login_domain",
                        "keyCaption": "Domain",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "secondary_email",
                        "keyCaption": "Secondary Email",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "building",
                        "keyCaption": "Building",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "User Custom List 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_type",
                        "keyCaption": "User Type",
                        "value": "Administrator",
                        "valueCaption": "Administrator",
                        "valueClass": ""
                    },
                    {
                        "key": "links",
                        "keyCaption": "Links",
                        "value": "sysaid-dmst",
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history_version",
                        "keyCaption": "History Version",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "User Custom Int 2",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "User Custom Int 1",
                        "value": "0",
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "User Custom Date 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "User Custom Date 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "history",
                        "keyCaption": "History",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "display_name",
                        "keyCaption": "Display Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "helpdesk",
                        "keyCaption": "Service Desk",
                        "value": "sysaid-dmst",
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cell_phone",
                        "keyCaption": "Cellular phone",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "login_user",
                        "keyCaption": "User Name",
                        "value": "sysaid-dmst",
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "phone",
                        "keyCaption": "Phone",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_notifications",
                        "keyCaption": "Receive automatic SR email notifications",
                        "value": "true",
                        "valueCaption": "true",
                        "valueClass": ""
                    },
                    {
                        "key": "enable_login_to_eup",
                        "keyCaption": "Enable login to the End User Portal",
                        "value": "Y",
                        "valueCaption": "Y",
                        "valueClass": ""
                    },
                    {
                        "key": "relation_graph",
                        "keyCaption": "CI Relations Graph",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "chat_nick_name",
                        "keyCaption": "Chat Nickname",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "attachments",
                        "keyCaption": "Attachments",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "User Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "calculated_user_name",
                        "keyCaption": "Calculated User Name",
                        "value": "sysaid-dmst",
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "floor",
                        "keyCaption": "Floor",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "first_name",
                        "keyCaption": "First Name",
                        "value": "sysaid-dmst",
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cubic",
                        "keyCaption": "Cubicle",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "expiration_time",
                        "keyCaption": "Expiration Date",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "last_name",
                        "keyCaption": "Last Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "groups",
                        "keyCaption": "Groups",
                        "value": "sysaid-dmst",
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "User Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "User Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ldap_user_guid",
                        "keyCaption": "User GUID",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_address",
                        "keyCaption": "Email",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "disable",
                        "keyCaption": "Disabled",
                        "value": "N",
                        "valueCaption": "N",
                        "valueClass": ""
                    },
                    {
                        "key": "car_number",
                        "keyCaption": "Car license",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "my_photo_url",
                        "keyCaption": "My Photo",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ldap_distinguished_name",
                        "keyCaption": "User Distinguished Name",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sms_number",
                        "keyCaption": "Text message",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "openServiceRequest",
                        "keyCaption": "Active Service Record",
                        "value": "4",
                        "valueCaption": "4",
                        "valueClass": ""
                    }
                ],
                "isAdmin": true,
                "isGuest": false,
                "isManager": true,
                "isSysAidAdmin": true,
                "name": "sysaid-dmst"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 100 results from page 1:
>### User Results:
>|id|name|isAdmin|isManager|isSysAidAdmin|isGuest|
>|---|---|---|---|---|---|
>| 3 | sysaid-adi-dmst | false | false | false | false |
>| 1 | sysaid-dmst | true | true | true | false |


### sysaid-service-record-list
***
List all service requests. Cortex XSOAR recommends filtering the results by the desired fields.


#### Base Command

`sysaid-service-record-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The requested service record type. Possible values are: incident, request, problem, change, all. | Required | 
| fields | Comma separated list of fields to return to context data. You can send "all" for debugging purposes. | Required | 
| page_number | Index of the page of results to retrieve. Default is 1. | Optional | 
| page_size | The number of service records to return on a page. Default is 100. | Optional | 
| ids | The list of service records IDs to return, comma separated. | Optional | 
| archive | Whether to return archived service records. Possible values are: 0, 1. | Optional | 
| custom_fields_keys | Comma separated list of filters' IDs. | Optional | 
| custom_fields_values | Comma separated list of the values of the filters' IDs. For example, custom_fields_keys:key1,key2, custom_fields_values:value1,value2. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SysAid.ServiceRecord.id | String | The ID of the service record. | 
| SysAid.ServiceRecord.title | String | The title of the service record. | 
| SysAid.ServiceRecord.status | String | The status of the service record. | 
| SysAid.ServiceRecord.update_time | Date | The modify time of the service record. | 
| SysAid.ServiceRecord.sr_type | String | The type of the service record. | 
| SysAid.ServiceRecord.notes | String | The notes of the service record. | 

#### Command example
```!sysaid-service-record-list type=all fields=all```
#### Context Example
```json
{
    "SysAid": {
        "ServiceRecord": [
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "25",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Cannot access email",
                        "valueCaption": "Cannot access email",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Cannot access email - Test ",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 25,
                        "valueCaption": "25",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 4,
                        "valueCaption": "Self-Service Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 25,
                        "valueCaption": "25",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 6,
                        "valueCaption": "6",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": "Demo Test",
                        "valueCaption": "Demo Test",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "Mobile Devices",
                        "valueCaption": "Mobile Devices",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 25,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Tablet",
                        "valueCaption": "Tablet",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "This is a test incident",
                        "valueCaption": "This is a test incident",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646661395760,
                        "valueCaption": "03/07/2022 08:56:35 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Cannot access email - Test ",
                        "valueCaption": "Cannot access email - Test ",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1647338000987,
                        "valueCaption": "03/15/2022 04:53:20 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "This is a note for the API",
                        "valueCaption": "This is a note for the API",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 4,
                        "valueCaption": "Normal",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 6,
                        "valueCaption": "DEFAULT",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 25,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": 1131881301,
                        "valueCaption": "1131881301",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": 1131881301,
                        "valueCaption": "1131881301",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 1,
                        "valueCaption": "Incident",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "28",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Can not access Internet",
                        "valueCaption": "Can not access Internet",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Cannot connect to a Wi-Fi network",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 28,
                        "valueCaption": "28",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 4,
                        "valueCaption": "Self-Service Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 28,
                        "valueCaption": "28",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 4,
                        "valueCaption": "Normal",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "User Workstation",
                        "valueCaption": "User Workstation",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 28,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Laptop",
                        "valueCaption": "Laptop",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "I test this",
                        "valueCaption": "I test this",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646662081400,
                        "valueCaption": "03/07/2022 09:08:01 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Cannot connect to a Wi-Fi network",
                        "valueCaption": "Cannot connect to a Wi-Fi network",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1646662081400,
                        "valueCaption": "03/07/2022 09:08:01 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 1,
                        "valueCaption": "Urgent",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 6,
                        "valueCaption": "DEFAULT",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 28,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": 1131195665,
                        "valueCaption": "1131195665",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": "Test LP",
                        "valueCaption": "Test LP",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": 1131195665,
                        "valueCaption": "1131195665",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 1,
                        "valueCaption": "Incident",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "33",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Shutdown",
                        "valueCaption": "Shutdown",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Try Test",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 33,
                        "valueCaption": "33",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 1,
                        "valueCaption": "Administrator Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 33,
                        "valueCaption": "33",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 3,
                        "valueCaption": "Medium",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 4,
                        "valueCaption": "Normal",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "Data Center",
                        "valueCaption": "Data Center",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 33,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Availability",
                        "valueCaption": "Availability",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "desc",
                        "valueCaption": "desc",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1647792536563,
                        "valueCaption": "03/20/2022 11:08:56 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Try Test",
                        "valueCaption": "Try Test",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 3,
                        "valueCaption": "Adi Dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1647792536563,
                        "valueCaption": "03/20/2022 11:08:56 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 2,
                        "valueCaption": "Very High",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 3,
                        "valueCaption": "Adi Dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 6,
                        "valueCaption": "DEFAULT",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 33,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": 740616,
                        "valueCaption": "740616",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": 740616,
                        "valueCaption": "740616",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 1,
                        "valueCaption": "Incident",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "26",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Does not work (Not Printing)",
                        "valueCaption": "Does not work (Not Printing)",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Paper jam - Test",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 26,
                        "valueCaption": "26",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 4,
                        "valueCaption": "Self-Service Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 26,
                        "valueCaption": "26",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 2,
                        "valueCaption": "2",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 30,
                        "valueCaption": "30",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "User Workstation",
                        "valueCaption": "User Workstation",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 26,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 2,
                        "valueCaption": "Open",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Printer",
                        "valueCaption": "Printer",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Update test through API",
                        "valueCaption": "Update test through API",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646661469350,
                        "valueCaption": "03/07/2022 08:57:49 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Paper jam - Test",
                        "valueCaption": "Paper jam - Test",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1647781001463,
                        "valueCaption": "03/20/2022 07:56:41 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 3,
                        "valueCaption": "High",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 7,
                        "valueCaption": "Printer failure",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 26,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": 1131180487,
                        "valueCaption": "1131180487",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": 153595765,
                        "valueCaption": "153595765",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 1,
                        "valueCaption": "Incident",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "6",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "How to?",
                        "valueCaption": "How to?",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Welcome to SysAid!",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 6,
                        "valueCaption": "6",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 0,
                        "valueCaption": "Administrator - Other",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "Closing via API call",
                        "valueCaption": "Closing via API call",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 6,
                        "valueCaption": "6",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": 1647782293393,
                        "valueCaption": "03/20/2022 08:18:13 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 4,
                        "valueCaption": "4",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "Basic Software",
                        "valueCaption": "Basic Software",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 6,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 3,
                        "valueCaption": "Closed",
                        "valueClass": 1
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Other",
                        "valueCaption": "Other",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "This is your first service record in your Service Desk list.\nNow you can get started with everything SysAid has to offer!\n\nFor every page in SysAid, you can access instructions and help relevant for that page.\nTo access the online help, click your profile name on the top-right corner of the screen and select Online Aid. Help for the current page opens in a new window.\n\nOur Online Help is completely integrated with the SysAid Community. We highly recommend you visit there to ask questions, read what other SysAiders have posted, and enrich your knowledge of SysAid.\nFor further documentation on SysAid's modules, functionality, setup, and more, visit http://www.sysaid.com/documentation.htm.\n\nOur support team is always ready and eager to answer any of your questions.  Feel free to contact us at support@sysaid.com or submit a service record at http://helpdesk.sysaid.com/EndUserPortal.jsp.\n\nEnjoy SysAid!\n",
                        "valueCaption": "This is your first service record in your Service Desk list.\nNow you can get started with everything SysAid has to offer!\n\nFor every page in SysAid, you can access instructions and help relevant for that page.\nTo access the online help, click your profile name on the top-right corner of the screen and select Online Aid. Help for the current page opens in a new window.\n\nOur Online Help is completely integrated with the SysAid Community. We highly recommend you visit there to ask questions, read what other SysAiders have posted, and enrich your knowledge of SysAid.\nFor further documentation on SysAid's modules, functionality, setup, and more, visit http://www.sysaid.com/documentation.htm.\n\nOur support team is always ready and eager to answer any of your questions.  Feel free to contact us at support@sysaid.com or submit a service record at http://helpdesk.sysaid.com/EndUserPortal.jsp.\n\nEnjoy SysAid!\n",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1643530079200,
                        "valueCaption": "01/30/2022 03:07:59 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Welcome to SysAid!",
                        "valueCaption": "Welcome to SysAid!",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1647782293393,
                        "valueCaption": "03/20/2022 08:18:13 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 6,
                        "valueCaption": "DEFAULT",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 6,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": 3292067858,
                        "valueCaption": "3292067858",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": 3292064351,
                        "valueCaption": "3292064351",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 1,
                        "valueCaption": "Incident",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "30",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Other",
                        "valueCaption": "Other",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Standard Change Process",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 30,
                        "valueCaption": "30",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 1,
                        "valueCaption": "Administrator Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 30,
                        "valueCaption": "30",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "User Workstation",
                        "valueCaption": "User Workstation",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 30,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Keyboard",
                        "valueCaption": "Keyboard",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Standard Change Process",
                        "valueCaption": "Standard Change Process",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646662345657,
                        "valueCaption": "03/07/2022 09:12:25 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Standard Change Process",
                        "valueCaption": "Standard Change Process",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1646662345657,
                        "valueCaption": "03/07/2022 09:12:25 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 5,
                        "valueCaption": "Standard Change",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 30,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": "Test LP",
                        "valueCaption": "Test LP",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 1,
                        "valueCaption": "Minor",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 4,
                        "valueCaption": "Change",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "27",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "How to?",
                        "valueCaption": "How to?",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Install Adobe Acrobat Reader - Test",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 27,
                        "valueCaption": "27",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 4,
                        "valueCaption": "Self-Service Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 27,
                        "valueCaption": "27",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "Basic Software",
                        "valueCaption": "Basic Software",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 27,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Adobe Reader",
                        "valueCaption": "Adobe Reader",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Install Adobe Acrobat Reader - how to test",
                        "valueCaption": "Install Adobe Acrobat Reader - how to test",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646661563163,
                        "valueCaption": "03/07/2022 08:59:23 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Install Adobe Acrobat Reader - Test",
                        "valueCaption": "Install Adobe Acrobat Reader - Test",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1646661563163,
                        "valueCaption": "03/07/2022 08:59:23 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 10,
                        "valueCaption": "Basic Request",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 27,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 10,
                        "valueCaption": "Request",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "29",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Other",
                        "valueCaption": "Other",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Permissions to use printer",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 29,
                        "valueCaption": "29",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 4,
                        "valueCaption": "Self-Service Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 29,
                        "valueCaption": "29",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "User Workstation",
                        "valueCaption": "User Workstation",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 29,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Printer",
                        "valueCaption": "Printer",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Permissions to use printer",
                        "valueCaption": "Permissions to use printer",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646662116607,
                        "valueCaption": "03/07/2022 09:08:36 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Permissions to use printer",
                        "valueCaption": "Permissions to use printer",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1646662116607,
                        "valueCaption": "03/07/2022 09:08:36 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 4,
                        "valueCaption": "Normal",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 9,
                        "valueCaption": "Advanced Request",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 29,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": "Test LP",
                        "valueCaption": "Test LP",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 10,
                        "valueCaption": "Request",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "31",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Cannot access email",
                        "valueCaption": "Cannot access email",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Reset my password",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 31,
                        "valueCaption": "31",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 4,
                        "valueCaption": "Self-Service Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 31,
                        "valueCaption": "31",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 4,
                        "valueCaption": "Normal",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "Mobile Devices",
                        "valueCaption": "Mobile Devices",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 31,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Smartphone",
                        "valueCaption": "Smartphone",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Reset my password",
                        "valueCaption": "Reset my password",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646662419673,
                        "valueCaption": "03/07/2022 09:13:39 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Reset my password",
                        "valueCaption": "Reset my password",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1646662419673,
                        "valueCaption": "03/07/2022 09:13:39 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 2,
                        "valueCaption": "Very High",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 10,
                        "valueCaption": "Basic Request",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 31,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 10,
                        "valueCaption": "Request",
                        "valueClass": ""
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 100 results from page 1:
>### Service Record Results:
>|Id|Title|Status|Modify Time|Service Record Type|
>|---|---|---|---|---|
>| 25 | Cannot access email - Test  | New | 03/15/2022 04:53:20 AM | Incident |
>| 28 | Cannot connect to a Wi-Fi network | New | 03/07/2022 09:08:01 AM | Incident |
>| 33 | Try Test | New | 03/20/2022 11:08:56 AM | Incident |
>| 34 | try arc | New | 03/22/2022 05:05:28 AM | Incident |
>| 26 | Paper jam - Test | Open | 03/20/2022 07:56:41 AM | Incident |
>| 6 | Welcome to SysAid! | Closed | 03/31/2022 10:16:10 AM | Incident |
>| 30 | Standard Change Process | New | 03/07/2022 09:12:25 AM | Change |
>| 36 | Minor Problem try | New | 03/27/2022 09:24:29 AM | Problem |
>| 27 | Install Adobe Acrobat Reader - Test | New | 03/07/2022 08:59:23 AM | Request |
>| 29 | Permissions to use printer | New | 03/07/2022 09:08:36 AM | Request |
>| 31 | Reset my password | New | 03/07/2022 09:13:39 AM | Request |
>| 35 | Advanced Request Process try | New | 03/27/2022 09:23:57 AM | Request |
>| 37 | Basic Request Process2 | New | 03/30/2022 01:56:47 AM | Request |


### sysaid-service-record-search
***
Search by a query through all service records. Cortex XSOAR recommends filtering the results by the desired fields.


#### Base Command

`sysaid-service-record-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The requested service record type. Possible values are: incident, request, problem, change, all. | Required | 
| fields | Comma separated list of fields to return to context data. You can send "all" for debugging purposes. | Required | 
| page_number | Index of the page of results to retrieve. Default is 1. | Optional | 
| page_size | The number of service records to return on a page. Default is 100. | Optional | 
| query | The search criteria. | Required | 
| archive | Whether to return archived service records. Possible values are: 0, 1. | Optional | 
| custom_fields_keys | Comma separated list of filters' IDs. | Optional | 
| custom_fields_values | Comma separated list of the values of the filters' IDs. For example, custom_fields_keys:key1,key2, custom_fields_values:value1,value2. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SysAid.ServiceRecord.id | String | The ID of the service record. | 
| SysAid.ServiceRecord.title | String | The title of the service record. | 
| SysAid.ServiceRecord.status | String | The status of the service record. | 
| SysAid.ServiceRecord.update_time | Date | The modify time of the service record. | 
| SysAid.ServiceRecord.sr_type | String | The type of the service record. | 
| SysAid.ServiceRecord.notes | String | The notes of the service record. | 

#### Command example
```!sysaid-service-record-search type=all query=test fields=all```
#### Context Example
```json
{
    "SysAid": {
        "ServiceRecord": [
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "25",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Cannot access email",
                        "valueCaption": "Cannot access email",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Cannot access email - Test ",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 25,
                        "valueCaption": "25",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 4,
                        "valueCaption": "Self-Service Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 25,
                        "valueCaption": "25",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 6,
                        "valueCaption": "6",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": "Demo Test",
                        "valueCaption": "Demo Test",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "Mobile Devices",
                        "valueCaption": "Mobile Devices",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 25,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Tablet",
                        "valueCaption": "Tablet",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "This is a test incident",
                        "valueCaption": "This is a test incident",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646661395760,
                        "valueCaption": "03/07/2022 08:56:35 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Cannot access email - Test ",
                        "valueCaption": "Cannot access email - Test ",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1647338000987,
                        "valueCaption": "03/15/2022 04:53:20 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "This is a note for the API",
                        "valueCaption": "This is a note for the API",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 4,
                        "valueCaption": "Normal",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 6,
                        "valueCaption": "DEFAULT",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 25,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": 1131881301,
                        "valueCaption": "1131881301",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": 1131881301,
                        "valueCaption": "1131881301",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 1,
                        "valueCaption": "Incident",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "28",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Can not access Internet",
                        "valueCaption": "Can not access Internet",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Cannot connect to a Wi-Fi network",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 28,
                        "valueCaption": "28",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 4,
                        "valueCaption": "Self-Service Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 28,
                        "valueCaption": "28",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 4,
                        "valueCaption": "Normal",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "User Workstation",
                        "valueCaption": "User Workstation",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 28,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Laptop",
                        "valueCaption": "Laptop",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "I test this",
                        "valueCaption": "I test this",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646662081400,
                        "valueCaption": "03/07/2022 09:08:01 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Cannot connect to a Wi-Fi network",
                        "valueCaption": "Cannot connect to a Wi-Fi network",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1646662081400,
                        "valueCaption": "03/07/2022 09:08:01 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 1,
                        "valueCaption": "Urgent",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 6,
                        "valueCaption": "DEFAULT",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 28,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": 1131195665,
                        "valueCaption": "1131195665",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": "Test LP",
                        "valueCaption": "Test LP",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": 1131195665,
                        "valueCaption": "1131195665",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 1,
                        "valueCaption": "Incident",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "33",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Shutdown",
                        "valueCaption": "Shutdown",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Try Test",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 33,
                        "valueCaption": "33",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 1,
                        "valueCaption": "Administrator Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 33,
                        "valueCaption": "33",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 3,
                        "valueCaption": "Medium",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 4,
                        "valueCaption": "Normal",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "Data Center",
                        "valueCaption": "Data Center",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 33,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Availability",
                        "valueCaption": "Availability",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "desc",
                        "valueCaption": "desc",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1647792536563,
                        "valueCaption": "03/20/2022 11:08:56 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Try Test",
                        "valueCaption": "Try Test",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 3,
                        "valueCaption": "Adi Dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1647792536563,
                        "valueCaption": "03/20/2022 11:08:56 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 2,
                        "valueCaption": "Very High",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 3,
                        "valueCaption": "Adi Dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 6,
                        "valueCaption": "DEFAULT",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 33,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": 740616,
                        "valueCaption": "740616",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": 740616,
                        "valueCaption": "740616",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 1,
                        "valueCaption": "Incident",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "26",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Does not work (Not Printing)",
                        "valueCaption": "Does not work (Not Printing)",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Paper jam - Test",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 26,
                        "valueCaption": "26",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 4,
                        "valueCaption": "Self-Service Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 26,
                        "valueCaption": "26",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 2,
                        "valueCaption": "2",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 30,
                        "valueCaption": "30",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "User Workstation",
                        "valueCaption": "User Workstation",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 26,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 2,
                        "valueCaption": "Open",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Printer",
                        "valueCaption": "Printer",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Update test through API",
                        "valueCaption": "Update test through API",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646661469350,
                        "valueCaption": "03/07/2022 08:57:49 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Paper jam - Test",
                        "valueCaption": "Paper jam - Test",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1647781001463,
                        "valueCaption": "03/20/2022 07:56:41 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 3,
                        "valueCaption": "High",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 7,
                        "valueCaption": "Printer failure",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 26,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": 1131180487,
                        "valueCaption": "1131180487",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": 153595765,
                        "valueCaption": "153595765",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 1,
                        "valueCaption": "Incident",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "30",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Other",
                        "valueCaption": "Other",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Standard Change Process",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 30,
                        "valueCaption": "30",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 1,
                        "valueCaption": "Administrator Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 30,
                        "valueCaption": "30",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "User Workstation",
                        "valueCaption": "User Workstation",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 30,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Keyboard",
                        "valueCaption": "Keyboard",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Standard Change Process",
                        "valueCaption": "Standard Change Process",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646662345657,
                        "valueCaption": "03/07/2022 09:12:25 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Standard Change Process",
                        "valueCaption": "Standard Change Process",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1646662345657,
                        "valueCaption": "03/07/2022 09:12:25 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 5,
                        "valueCaption": "Standard Change",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 30,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": "Test LP",
                        "valueCaption": "Test LP",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 1,
                        "valueCaption": "Minor",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 4,
                        "valueCaption": "Change",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "27",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "How to?",
                        "valueCaption": "How to?",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Install Adobe Acrobat Reader - Test",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 27,
                        "valueCaption": "27",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 4,
                        "valueCaption": "Self-Service Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 27,
                        "valueCaption": "27",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "Basic Software",
                        "valueCaption": "Basic Software",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 27,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Adobe Reader",
                        "valueCaption": "Adobe Reader",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Install Adobe Acrobat Reader - how to test",
                        "valueCaption": "Install Adobe Acrobat Reader - how to test",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646661563163,
                        "valueCaption": "03/07/2022 08:59:23 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Install Adobe Acrobat Reader - Test",
                        "valueCaption": "Install Adobe Acrobat Reader - Test",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1646661563163,
                        "valueCaption": "03/07/2022 08:59:23 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 10,
                        "valueCaption": "Basic Request",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 27,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 10,
                        "valueCaption": "Request",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "29",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Other",
                        "valueCaption": "Other",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Permissions to use printer",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 29,
                        "valueCaption": "29",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 4,
                        "valueCaption": "Self-Service Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 29,
                        "valueCaption": "29",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 5,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "User Workstation",
                        "valueCaption": "User Workstation",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 29,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Printer",
                        "valueCaption": "Printer",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Permissions to use printer",
                        "valueCaption": "Permissions to use printer",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646662116607,
                        "valueCaption": "03/07/2022 09:08:36 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Permissions to use printer",
                        "valueCaption": "Permissions to use printer",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1646662116607,
                        "valueCaption": "03/07/2022 09:08:36 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 4,
                        "valueCaption": "Normal",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 9,
                        "valueCaption": "Advanced Request",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 29,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueCaption": "93c18412-a672-4a3d-8b02-6f91ee963918",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": "Test LP",
                        "valueCaption": "Test LP",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 10,
                        "valueCaption": "Request",
                        "valueClass": ""
                    }
                ]
            },
            {
                "canArchive": true,
                "canDelete": true,
                "canUpdate": true,
                "hasChildren": false,
                "id": "31",
                "info": [
                    {
                        "key": "third_level_category",
                        "keyCaption": "Third Level Category",
                        "value": "Cannot access email",
                        "valueCaption": "Cannot access email",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list1",
                        "keyCaption": "SR Custom List 1",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "max_support_level",
                        "keyCaption": "Max Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "quick_name",
                        "keyCaption": "Template",
                        "value": "Reset my password",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "lock_field",
                        "keyCaption": "=== Hide/Show Divider ===",
                        "value": 31,
                        "valueCaption": "31",
                        "valueClass": ""
                    },
                    {
                        "key": "source",
                        "keyCaption": "Source",
                        "value": 4,
                        "valueCaption": "Self-Service Portal",
                        "valueClass": ""
                    },
                    {
                        "key": "resolution",
                        "keyCaption": "Resolution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_list2",
                        "keyCaption": "SR Custom List 2",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "parent_link",
                        "keyCaption": "Parent ID",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "solution",
                        "keyCaption": "Solution",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "user_manager_name",
                        "keyCaption": "Request User Manager",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "survey_status",
                        "keyCaption": "Survey Status",
                        "value": 0,
                        "valueCaption": "The survey has not been sent.",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_weight",
                        "keyCaption": "Weight",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_planned_date",
                        "keyCaption": "Followup Planned Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "submit_user",
                        "keyCaption": "Submit user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "agreement",
                        "keyCaption": "Agreement",
                        "value": 1,
                        "valueCaption": "DEFAULT SLA",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int2",
                        "keyCaption": "SR Custom Int 2",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date1",
                        "keyCaption": "SR Custom Date 1",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_int1",
                        "keyCaption": "SR Custom Int 1",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "totalTime",
                        "keyCaption": "Total Activities time",
                        "value": 31,
                        "valueCaption": "31",
                        "valueClass": ""
                    },
                    {
                        "key": "impact",
                        "keyCaption": "Impact",
                        "value": 4,
                        "valueCaption": "Low",
                        "valueClass": ""
                    },
                    {
                        "key": "reopen_counter",
                        "keyCaption": "Reopen Counter",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_date2",
                        "keyCaption": "SR Custom Date 2",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "archive",
                        "keyCaption": "Archive",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "close_time",
                        "keyCaption": "Close time",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "priority",
                        "keyCaption": "Priority",
                        "value": 4,
                        "valueCaption": "Normal",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_service_records",
                        "keyCaption": "Merged service records",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "version",
                        "keyCaption": "Version",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "is_escalated",
                        "keyCaption": "Is Escalated",
                        "value": 0,
                        "valueCaption": "No",
                        "valueClass": ""
                    },
                    {
                        "key": "CustomColumn3sr",
                        "keyCaption": "Test Field",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "closure_information",
                        "keyCaption": "Closure Information",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assign_counter",
                        "keyCaption": "Assigned Counter",
                        "value": 1,
                        "valueCaption": "1",
                        "valueClass": ""
                    },
                    {
                        "key": "problem_type",
                        "keyCaption": "Category",
                        "value": "Mobile Devices",
                        "valueCaption": "Mobile Devices",
                        "valueClass": ""
                    },
                    {
                        "key": "alertID",
                        "keyCaption": "Alert",
                        "value": 31,
                        "valueCaption": "green",
                        "valueClass": ""
                    },
                    {
                        "key": "status",
                        "keyCaption": "Status",
                        "value": 1,
                        "valueCaption": "New",
                        "valueClass": 0
                    },
                    {
                        "key": "problem_sub_type",
                        "keyCaption": "Sub-Category",
                        "value": "Smartphone",
                        "valueCaption": "Smartphone",
                        "valueClass": ""
                    },
                    {
                        "key": "known_error",
                        "keyCaption": "Known Error",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "description",
                        "keyCaption": "Description",
                        "value": "Reset my password",
                        "valueCaption": "Reset my password",
                        "valueClass": ""
                    },
                    {
                        "key": "insert_time",
                        "keyCaption": "Request time",
                        "value": 1646662419673,
                        "valueCaption": "03/07/2022 09:13:39 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "task_id",
                        "keyCaption": "Main task",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "title",
                        "keyCaption": "Title",
                        "value": "Reset my password",
                        "valueCaption": "Reset my password",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user_name",
                        "keyCaption": "Request username",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_user",
                        "keyCaption": "Followup User",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "workaround",
                        "keyCaption": "Workaround",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "current_support_level",
                        "keyCaption": "Current Support Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_time",
                        "keyCaption": "Modify time",
                        "value": 1646662419673,
                        "valueCaption": "03/07/2022 09:13:39 AM",
                        "valueClass": ""
                    },
                    {
                        "key": "success_rating",
                        "keyCaption": "Success Rating",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "update_user",
                        "keyCaption": "Modify User",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_notes",
                        "keyCaption": "SR Custom Notes",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_text",
                        "keyCaption": "Followup Text",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "email_account",
                        "keyCaption": "Email Account",
                        "value": " ",
                        "valueCaption": " ",
                        "valueClass": ""
                    },
                    {
                        "key": "responsibility",
                        "keyCaption": "Process manager",
                        "value": 1,
                        "valueCaption": "sysaid-dmst",
                        "valueClass": ""
                    },
                    {
                        "key": "urgency",
                        "keyCaption": "Urgency",
                        "value": 2,
                        "valueCaption": "Very High",
                        "valueClass": ""
                    },
                    {
                        "key": "request_user",
                        "keyCaption": "Request user",
                        "value": 2,
                        "valueCaption": "Test User",
                        "valueClass": ""
                    },
                    {
                        "key": "sub_type",
                        "keyCaption": "Sub Type",
                        "value": 10,
                        "valueCaption": "Basic Request",
                        "valueClass": ""
                    },
                    {
                        "key": "company",
                        "keyCaption": "Company",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "followup_actual_date",
                        "keyCaption": "Followup Actual Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "department",
                        "keyCaption": "Department",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "all_active_assigned_to",
                        "keyCaption": "Users assigned to active action items",
                        "value": 31,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_id",
                        "keyCaption": "Asset ID",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cc",
                        "keyCaption": "CC",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer1",
                        "keyCaption": "Time to Repair",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "computer_name",
                        "keyCaption": "Main Asset",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "timer2",
                        "keyCaption": "Time to Respond",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "ci",
                        "keyCaption": "Main CI",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "due_date",
                        "keyCaption": "Due Date",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text1",
                        "keyCaption": "SR Custom Text 1",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "cust_text2",
                        "keyCaption": "SR Custom Text 2",
                        "value": "",
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "merged_to",
                        "keyCaption": "Merged to",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "responsible_manager",
                        "keyCaption": "Responsible Admin",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "account_id",
                        "keyCaption": "Account",
                        "value": "paloaltonetworks_trial",
                        "valueCaption": "paloaltonetworks_trial",
                        "valueClass": ""
                    },
                    {
                        "key": "escalation",
                        "keyCaption": "Escalation Level",
                        "value": 0,
                        "valueCaption": "0",
                        "valueClass": ""
                    },
                    {
                        "key": "change_category",
                        "keyCaption": "Classification",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "assigned_group",
                        "keyCaption": "Admin group",
                        "value": null,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "location",
                        "keyCaption": "Location",
                        "value": 0,
                        "valueCaption": "",
                        "valueClass": ""
                    },
                    {
                        "key": "sr_type",
                        "keyCaption": "Service Record Type",
                        "value": 10,
                        "valueCaption": "Request",
                        "valueClass": ""
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 100 results from page 1:
>### Service Record Results:
>|Id|Title|Status|Modify Time|Service Record Type|
>|---|---|---|---|---|
>| 25 | Cannot access email - Test  | New | 03/15/2022 04:53:20 AM | Incident |
>| 28 | Cannot connect to a Wi-Fi network | New | 03/07/2022 09:08:01 AM | Incident |
>| 33 | Try Test | New | 03/20/2022 11:08:56 AM | Incident |
>| 26 | Paper jam - Test | Open | 03/20/2022 07:56:41 AM | Incident |
>| 30 | Standard Change Process | New | 03/07/2022 09:12:25 AM | Change |
>| 27 | Install Adobe Acrobat Reader - Test | New | 03/07/2022 08:59:23 AM | Request |
>| 29 | Permissions to use printer | New | 03/07/2022 09:08:36 AM | Request |
>| 31 | Reset my password | New | 03/07/2022 09:13:39 AM | Request |
>| 37 | Basic Request Process2 | New | 03/30/2022 01:56:47 AM | Request |


### sysaid-service-record-update
***
The valid statuses can be retrieved using the "sysaid-table-list" command.


#### Base Command

`sysaid-service-record-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The service record ID. | Required | 
| impact | The new impact of the service record. | Optional | 
| priority | The new priority of the service record. | Optional | 
| status | The new status of the service record. | Optional | 
| description | The new description of the service record. | Optional | 
| solution | The new solution of the service record. | Optional | 
| problem_type | The new problem type of the service record. | Optional | 
| problem_sub_type | The new problem sub-type of the service record. | Optional | 
| third_level_category | The new third level category of the service record. | Optional | 
| sr_type | The new service record type of the service record. | Optional | 
| sub_type | The new sub-type of the service record. | Optional | 
| agreement | The new agreement of the service record. | Optional | 
| title | The new title of the service record. | Optional | 
| followup_user | The new follow up user of the service record. | Optional | 
| followup_text | The new follow up text of the service record. | Optional | 
| cust_notes | The new custom notes of the service record. | Optional | 
| email_account | The new email account of the service record. | Optional | 
| responsibility | The new responsibility of the service record. | Optional | 
| urgency | The new urgency of the service record. | Optional | 
| company | The new company of the service record. | Optional | 
| department | The new department of the service record. | Optional | 
| computer_id | The new computer ID of the service record. | Optional | 
| due_date | The new due date of the service record. | Optional | 
| escalation | The new escalation of the service record. | Optional | 
| change_category | The new change category of the service record. | Optional | 
| assigned_group | The new assigned group of the service record. | Optional | 
| location | The new location of the service record. | Optional | 
| custom_fields_keys | Comma separated list of filters' IDs. | Optional | 
| custom_fields_values | Comma separated list of the values of the filters' IDs. For example, custom_fields_keys:key1,key2, custom_fields_values:value1,value2. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!sysaid-service-record-update id=6 status=2```
#### Human Readable Output

>Service Record 6 Updated Successfully.

### sysaid-service-record-close
***
Close a service record. Sets the service record status to the default Close status, as defined in the Help Desk settings.


#### Base Command

`sysaid-service-record-close`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The service record ID. | Required | 
| solution | The solution for closing the service record. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!sysaid-service-record-close id=6 solution="Closing via API call"```
#### Human Readable Output

>Service Record 6 Closed Successfully.

### sysaid-service-record-template-get
***
Gets the template of a service record. Cortex XSOAR recommends filtering the results by the desired fields.


#### Base Command

`sysaid-service-record-template-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Comma separated list of fields to return to context data. The valid fields can be retrieved using the "sysaid-table-list" command with the "entity=sr" argument. You can send "all" for debugging purposes. | Required | 
| type | The requested service record type. Possible values are: incident, request, problem, change. | Required | 
| template_id | The service record template ID, according to service record type. Defaults to the first/default template. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SysAid.ServiceRecordTemplate.key | String | The key of the service record template entry. | 
| SysAid.ServiceRecordTemplate.value | String | The value of the service record template entry. | 
| SysAid.ServiceRecordTemplate.mandatory | String | Whether the template entry is mandatory or not. | 
| SysAid.ServiceRecordTemplate.editable | Boolean | Whether the template entry is editable or not. | 
| SysAid.ServiceRecordTemplate.type | Boolean | The type of the service record template entry. | 
| SysAid.ServiceRecordTemplate.defaultValue | String | The default value of the service record template entry. | 
| SysAid.ServiceRecordTemplate.keyCaption | String | The key caption of the service record template entry. | 

#### Command example
```!sysaid-service-record-template-get type=incident fields=all```
#### Context Example
```json
{
    "SysAid": {
        "ServiceRecordTemplate": {
            "canArchive": true,
            "canDelete": true,
            "canUpdate": true,
            "hasChildren": false,
            "id": "0",
            "info": [
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "third_level_category",
                    "keyCaption": "Third Level Category",
                    "mandatory": false,
                    "type": "list",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_list1",
                    "keyCaption": "SR Custom List 1",
                    "mandatory": false,
                    "type": "list",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "notes",
                    "keyCaption": "Notes",
                    "mandatory": false,
                    "type": "object",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "screen",
                    "keyCaption": "Screen capture",
                    "mandatory": false,
                    "type": "object",
                    "value": {
                        "captureExists": false,
                        "sendScreenCapture": "NO"
                    },
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "resolution",
                    "keyCaption": "Resolution",
                    "mandatory": false,
                    "type": "text",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "childs",
                    "keyCaption": "Child Service Records",
                    "mandatory": false,
                    "type": "object",
                    "value": [],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_list2",
                    "keyCaption": "SR Custom List 2",
                    "mandatory": false,
                    "type": "list",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "parent_link",
                    "keyCaption": "Parent ID",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "solution",
                    "keyCaption": "Solution",
                    "mandatory": false,
                    "type": "text",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "project_id",
                    "keyCaption": "Main project",
                    "mandatory": false,
                    "type": "object",
                    "value": {},
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "links",
                    "keyCaption": "Links",
                    "mandatory": false,
                    "type": "object",
                    "value": [],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "sr_weight",
                    "keyCaption": "Weight",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "0",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "followup_planned_date",
                    "keyCaption": "Followup Planned Date",
                    "mandatory": false,
                    "type": "date",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_int2",
                    "keyCaption": "SR Custom Int 2",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "0",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_date1",
                    "keyCaption": "SR Custom Date 1",
                    "mandatory": false,
                    "type": "date",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_int1",
                    "keyCaption": "SR Custom Int 1",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "0",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "impact",
                    "keyCaption": "Impact",
                    "mandatory": false,
                    "type": "list",
                    "value": 4,
                    "valueCaption": "Low",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_date2",
                    "keyCaption": "SR Custom Date 2",
                    "mandatory": false,
                    "type": "date",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "priority",
                    "keyCaption": "Priority",
                    "mandatory": false,
                    "type": "list",
                    "value": 5,
                    "valueCaption": "Low",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "merged_service_records",
                    "keyCaption": "Merged service records",
                    "mandatory": false,
                    "type": "text",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": "string",
                    "defaultValue": null,
                    "editable": true,
                    "key": "CustomColumn3sr",
                    "keyCaption": "Test Field",
                    "mandatory": false,
                    "type": "text",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "messages",
                    "keyCaption": "Messages",
                    "mandatory": false,
                    "type": "object",
                    "value": [],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "problem_type",
                    "keyCaption": "Category",
                    "mandatory": false,
                    "type": "nested",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "alertID",
                    "keyCaption": "Alert",
                    "mandatory": false,
                    "type": "calculated",
                    "value": null,
                    "valueCaption": "green",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "actions",
                    "keyCaption": "Actions",
                    "mandatory": false,
                    "type": "object",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "status",
                    "keyCaption": "Status",
                    "mandatory": false,
                    "type": "list",
                    "value": 1,
                    "valueCaption": "New",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "attachments",
                    "keyCaption": "Attachments",
                    "mandatory": false,
                    "type": "object",
                    "value": [],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "problem_sub_type",
                    "keyCaption": "Sub-Category",
                    "mandatory": false,
                    "type": "list",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "linkedSRs",
                    "keyCaption": "Links to other Items",
                    "mandatory": false,
                    "type": "object",
                    "value": [],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "description",
                    "keyCaption": "Description",
                    "mandatory": false,
                    "type": "text",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "task_id",
                    "keyCaption": "Main task",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "video",
                    "keyCaption": "Video capture",
                    "mandatory": false,
                    "type": "object",
                    "value": {
                        "captureExists": false,
                        "filePath": null,
                        "sendVideoRecording": "NO"
                    },
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "title",
                    "keyCaption": "Title",
                    "mandatory": false,
                    "type": "text",
                    "value": "DEFAULT",
                    "valueCaption": "DEFAULT",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "followup_user",
                    "keyCaption": "Followup User",
                    "mandatory": false,
                    "type": "list",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "workaround",
                    "keyCaption": "Workaround",
                    "mandatory": false,
                    "type": "text",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "success_rating",
                    "keyCaption": "Success Rating",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "0",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_notes",
                    "keyCaption": "SR Custom Notes",
                    "mandatory": false,
                    "type": "text",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "followup_text",
                    "keyCaption": "Followup Text",
                    "mandatory": false,
                    "type": "text",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "responsibility",
                    "keyCaption": "Assigned to",
                    "mandatory": false,
                    "type": "list",
                    "value": 1,
                    "valueCaption": "sysaid-dmst",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "urgency",
                    "keyCaption": "Urgency",
                    "mandatory": false,
                    "type": "list",
                    "value": 5,
                    "valueCaption": "Low",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "request_user",
                    "keyCaption": "Request user",
                    "mandatory": false,
                    "type": "list",
                    "value": 1,
                    "valueCaption": "sysaid-dmst",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "sub_type",
                    "keyCaption": "Sub Type",
                    "mandatory": false,
                    "type": "list",
                    "value": 6,
                    "valueCaption": "DEFAULT",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "company",
                    "keyCaption": "Company",
                    "mandatory": false,
                    "type": "list",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "followup_actual_date",
                    "keyCaption": "Followup Actual Date",
                    "mandatory": false,
                    "type": "date",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "computer_id",
                    "keyCaption": "Asset ID",
                    "mandatory": false,
                    "type": "text",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cc",
                    "keyCaption": "CC",
                    "mandatory": false,
                    "type": "list",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "ci",
                    "keyCaption": "Main CI",
                    "mandatory": false,
                    "type": "list",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "due_date",
                    "keyCaption": "Due Date",
                    "mandatory": false,
                    "type": "date",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_text1",
                    "keyCaption": "SR Custom Text 1",
                    "mandatory": false,
                    "type": "text",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_text2",
                    "keyCaption": "SR Custom Text 2",
                    "mandatory": false,
                    "type": "text",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "merged_to",
                    "keyCaption": "Merged to",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "0",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "responsible_manager",
                    "keyCaption": "Responsible Admin",
                    "mandatory": false,
                    "type": "list",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "solutionModel",
                    "keyCaption": "Solution Model",
                    "mandatory": false,
                    "type": "object",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "activities",
                    "keyCaption": "Activities",
                    "mandatory": false,
                    "type": "object",
                    "value": [],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "relatedProblems",
                    "keyCaption": "Potential Related Problems",
                    "mandatory": false,
                    "type": "object",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "change_category",
                    "keyCaption": "Classification",
                    "mandatory": false,
                    "type": "list",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "assigned_group",
                    "keyCaption": "Admin group",
                    "mandatory": false,
                    "type": "list",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "location",
                    "keyCaption": "Location",
                    "mandatory": false,
                    "type": "list",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "sr_type",
                    "keyCaption": "Service Record Type",
                    "mandatory": false,
                    "type": "list",
                    "value": 2,
                    "valueCaption": "Incident Template",
                    "valueClass": ""
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Service Record Results:
>|Key|Value|Mandatory|Editable|Type|Key Caption|
>|---|---|---|---|---|---|
>| third_level_category |  | false | true | list | Third Level Category |
>| cust_list1 | 0 | false | true | list | SR Custom List 1 |
>| notes |  | false | true | object | Notes |
>| screen | sendScreenCapture: NO<br/>captureExists: false | false | true | object | Screen capture |
>| resolution |  | false | true | text | Resolution |
>| childs |  | false | true | object | Child Service Records |
>| cust_list2 | 0 | false | true | list | SR Custom List 2 |
>| parent_link | 0 | false | true | numeric | Parent ID |
>| solution |  | false | true | text | Solution |
>| project_id |  | false | true | object | Main project |
>| links |  | false | true | object | Links |
>| sr_weight | 0 | false | true | numeric | Weight |
>| followup_planned_date |  | false | true | date | Followup Planned Date |
>| cust_int2 | 0 | false | true | numeric | SR Custom Int 2 |
>| cust_date1 |  | false | true | date | SR Custom Date 1 |
>| cust_int1 | 0 | false | true | numeric | SR Custom Int 1 |
>| impact | 4 | false | true | list | Impact |
>| cust_date2 |  | false | true | date | SR Custom Date 2 |
>| priority | 5 | false | true | list | Priority |
>| merged_service_records |  | false | true | text | Merged service records |
>| CustomColumn3sr |  | false | true | text | Test Field |
>| messages |  | false | true | object | Messages |
>| problem_type |  | false | true | nested | Category |
>| alertID |  | false | true | calculated | Alert |
>| actions |  | false | true | object | Actions |
>| status | 1 | false | true | list | Status |
>| attachments |  | false | true | object | Attachments |
>| problem_sub_type |  | false | true | list | Sub-Category |
>| linkedSRs |  | false | true | object | Links to other Items |
>| description |  | false | true | text | Description |
>| task_id | 0 | false | true | numeric | Main task |
>| video | sendVideoRecording: NO<br/>captureExists: false<br/>filePath: null | false | true | object | Video capture |
>| title | DEFAULT | false | true | text | Title |
>| followup_user |  | false | true | list | Followup User |
>| workaround |  | false | true | text | Workaround |
>| success_rating | 0 | false | true | numeric | Success Rating |
>| cust_notes |  | false | true | text | SR Custom Notes |
>| followup_text |  | false | true | text | Followup Text |
>| responsibility | 1 | false | true | list | Assigned to |
>| urgency | 5 | false | true | list | Urgency |
>| request_user | 1 | false | true | list | Request user |
>| sub_type | 6 | false | true | list | Sub Type |
>| company | 0 | false | true | list | Company |
>| followup_actual_date |  | false | true | date | Followup Actual Date |
>| computer_id |  | false | true | text | Asset ID |
>| cc |  | false | true | list | CC |
>| ci | 0 | false | true | list | Main CI |
>| due_date |  | false | true | date | Due Date |
>| cust_text1 |  | false | true | text | SR Custom Text 1 |
>| cust_text2 |  | false | true | text | SR Custom Text 2 |
>| merged_to | 0 | false | true | numeric | Merged to |
>| responsible_manager |  | false | true | list | Responsible Admin |
>| solutionModel |  | false | true | object | Solution Model |
>| activities |  | false | true | object | Activities |
>| relatedProblems |  | false | true | object | Potential Related Problems |
>| change_category | 0 | false | true | list | Classification |
>| assigned_group |  | false | true | list | Admin group |
>| location |  | false | true | list | Location |
>| sr_type | 2 | false | true | list | Service Record Type |


### sysaid-service-record-create
***
Create a new service record and return the newly created service record. The valid statuses can be retrieved using the "sysaid-table-list" command. Cortex XSOAR recommends filtering the results by the desired fields.


#### Base Command

`sysaid-service-record-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Comma separated list of fields to return to context data. The valid fields can be retrieved using the "sysaid-table-list" command with the "entity=sr" argument. You can send "all" for debugging purposes. | Required | 
| type | The requested service record type. Possible values are: incident, request, problem, change. | Required | 
| template_id | The service record template ID, according to service record type. Defaults to the first/default template. | Optional | 
| description | The new description of the service record. | Required | 
| title | The new title of the service record. | Required | 
| impact | The new impact of the service record. | Optional | 
| priority | The new priority of the service record. | Optional | 
| status | The new status of the service record. | Optional | 
| solution | The new solution of the service record. | Optional | 
| problem_type | The new problem type of the service record. | Optional | 
| problem_sub_type | The new problem sub-type of the service record. | Optional | 
| third_level_category | The new third level category of the service record. | Optional | 
| sr_type | The new service record type of the service record. | Optional | 
| sub_type | The new sub-type of the service record. | Optional | 
| agreement | The new agreement of the service record. | Optional | 
| followup_user | The new follow up user of the service record. | Optional | 
| followup_text | The new follow up text of the service record. | Optional | 
| cust_notes | The new custom notes of the service record. | Optional | 
| email_account | The new email account of the service record. | Optional | 
| responsibility | The new responsibility of the service record. | Optional | 
| urgency | The new urgency of the service record. | Optional | 
| company | The new company of the service record. | Optional | 
| department | The new department of the service record. | Optional | 
| computer_id | The new computer ID of the service record. | Optional | 
| due_date | The new due date of the service record. | Optional | 
| escalation | The new escalation of the service record. | Optional | 
| change_category | The new change category of the service record. | Optional | 
| assigned_group | The new assigned group of the service record. | Optional | 
| location | The new location of the service record. | Optional | 
| custom_fields_keys | Comma separated list of filters' IDs. | Optional | 
| custom_fields_values | Comma separated list of the values of the filters' IDs. For example, custom_fields_keys:key1,key2, custom_fields_values:value1,value2. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SysAid.ServiceRecord.id | String | The ID of the service record. | 
| SysAid.ServiceRecord.title | String | The title of the service record. | 
| SysAid.ServiceRecord.status | String | The status of the service record. | 
| SysAid.ServiceRecord.update_time | Date | The modify time of the service record. | 
| SysAid.ServiceRecord.sr_type | String | The type of the service record. | 
| SysAid.ServiceRecord.notes | String | The notes of the service record. | 

#### Command example
```!sysaid-service-record-create type=request description="This is a test" title="Test SR from API" sr_type=6 fields=all```
#### Context Example
```json
{
    "SysAid": {
        "ServiceRecord": {
            "canArchive": true,
            "canDelete": true,
            "canUpdate": true,
            "hasChildren": false,
            "id": "0",
            "info": [
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "third_level_category",
                    "keyCaption": "Third Level Category",
                    "mandatory": false,
                    "type": "list",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_list1",
                    "keyCaption": "SR Custom List 1",
                    "mandatory": false,
                    "type": "list",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "notes",
                    "keyCaption": "Notes",
                    "mandatory": false,
                    "type": "object",
                    "value": [
                        "If relevant, add this Request details to the Knowledge base. Close the Request."
                    ],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "screen",
                    "keyCaption": "Screen capture",
                    "mandatory": false,
                    "type": "object",
                    "value": {
                        "captureExists": false,
                        "sendScreenCapture": "NO"
                    },
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "resolution",
                    "keyCaption": "Resolution",
                    "mandatory": false,
                    "type": "text",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "childs",
                    "keyCaption": "Child Service Records",
                    "mandatory": false,
                    "type": "object",
                    "value": [],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_list2",
                    "keyCaption": "SR Custom List 2",
                    "mandatory": false,
                    "type": "list",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "parent_link",
                    "keyCaption": "Parent ID",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "solution",
                    "keyCaption": "Solution",
                    "mandatory": false,
                    "type": "text",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "project_id",
                    "keyCaption": "Main project",
                    "mandatory": false,
                    "type": "object",
                    "value": {},
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "links",
                    "keyCaption": "Links",
                    "mandatory": false,
                    "type": "object",
                    "value": [],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "sr_weight",
                    "keyCaption": "Weight",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "0",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "followup_planned_date",
                    "keyCaption": "Followup Planned Date",
                    "mandatory": false,
                    "type": "date",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_int2",
                    "keyCaption": "SR Custom Int 2",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "0",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_date1",
                    "keyCaption": "SR Custom Date 1",
                    "mandatory": false,
                    "type": "date",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_int1",
                    "keyCaption": "SR Custom Int 1",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "0",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "impact",
                    "keyCaption": "Impact",
                    "mandatory": false,
                    "type": "list",
                    "value": 4,
                    "valueCaption": "Low",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_date2",
                    "keyCaption": "SR Custom Date 2",
                    "mandatory": false,
                    "type": "date",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "priority",
                    "keyCaption": "Priority",
                    "mandatory": false,
                    "type": "list",
                    "value": 5,
                    "valueCaption": "Low",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "merged_service_records",
                    "keyCaption": "Merged service records",
                    "mandatory": false,
                    "type": "text",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": "string",
                    "defaultValue": null,
                    "editable": true,
                    "key": "CustomColumn3sr",
                    "keyCaption": "Test Field",
                    "mandatory": false,
                    "type": "text",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "messages",
                    "keyCaption": "Messages",
                    "mandatory": false,
                    "type": "object",
                    "value": [],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "problem_type",
                    "keyCaption": "Category",
                    "mandatory": false,
                    "type": "nested",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "alertID",
                    "keyCaption": "Alert",
                    "mandatory": false,
                    "type": "calculated",
                    "value": null,
                    "valueCaption": "green",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "actions",
                    "keyCaption": "Actions",
                    "mandatory": false,
                    "type": "object",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "status",
                    "keyCaption": "Status",
                    "mandatory": false,
                    "type": "list",
                    "value": 1,
                    "valueCaption": "New",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "attachments",
                    "keyCaption": "Attachments",
                    "mandatory": false,
                    "type": "object",
                    "value": [],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "problem_sub_type",
                    "keyCaption": "Sub-Category",
                    "mandatory": false,
                    "type": "list",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "linkedSRs",
                    "keyCaption": "Links to other Items",
                    "mandatory": false,
                    "type": "object",
                    "value": [],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "description",
                    "keyCaption": "Description",
                    "mandatory": false,
                    "type": "text",
                    "value": "Basic Request Process",
                    "valueCaption": "Basic Request Process",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "task_id",
                    "keyCaption": "Main task",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "video",
                    "keyCaption": "Video capture",
                    "mandatory": false,
                    "type": "object",
                    "value": {
                        "captureExists": false,
                        "filePath": null,
                        "sendVideoRecording": "NO"
                    },
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "title",
                    "keyCaption": "Title",
                    "mandatory": false,
                    "type": "text",
                    "value": "Basic Request Process",
                    "valueCaption": "Basic Request Process",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "followup_user",
                    "keyCaption": "Followup User",
                    "mandatory": false,
                    "type": "list",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "workaround",
                    "keyCaption": "Workaround",
                    "mandatory": false,
                    "type": "text",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "success_rating",
                    "keyCaption": "Success Rating",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "0",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_notes",
                    "keyCaption": "SR Custom Notes",
                    "mandatory": false,
                    "type": "text",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "followup_text",
                    "keyCaption": "Followup Text",
                    "mandatory": false,
                    "type": "text",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "responsibility",
                    "keyCaption": "Process manager",
                    "mandatory": false,
                    "type": "list",
                    "value": 1,
                    "valueCaption": "sysaid-dmst",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "urgency",
                    "keyCaption": "Urgency",
                    "mandatory": false,
                    "type": "list",
                    "value": 5,
                    "valueCaption": "Low",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "request_user",
                    "keyCaption": "Request user",
                    "mandatory": false,
                    "type": "list",
                    "value": 1,
                    "valueCaption": "sysaid-dmst",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "sub_type",
                    "keyCaption": "Sub Type",
                    "mandatory": false,
                    "type": "text",
                    "value": 10,
                    "valueCaption": "10",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "company",
                    "keyCaption": "Company",
                    "mandatory": false,
                    "type": "list",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "followup_actual_date",
                    "keyCaption": "Followup Actual Date",
                    "mandatory": false,
                    "type": "date",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "computer_id",
                    "keyCaption": "Asset ID",
                    "mandatory": false,
                    "type": "text",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cc",
                    "keyCaption": "CC",
                    "mandatory": false,
                    "type": "list",
                    "value": "",
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "ci",
                    "keyCaption": "Main CI",
                    "mandatory": false,
                    "type": "list",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "due_date",
                    "keyCaption": "Due Date",
                    "mandatory": false,
                    "type": "date",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_text1",
                    "keyCaption": "SR Custom Text 1",
                    "mandatory": false,
                    "type": "text",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "cust_text2",
                    "keyCaption": "SR Custom Text 2",
                    "mandatory": false,
                    "type": "text",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "merged_to",
                    "keyCaption": "Merged to",
                    "mandatory": false,
                    "type": "numeric",
                    "value": 0,
                    "valueCaption": "0",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "responsible_manager",
                    "keyCaption": "Responsible Admin",
                    "mandatory": false,
                    "type": "list",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "solutionModel",
                    "keyCaption": "Solution Model",
                    "mandatory": false,
                    "type": "object",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "activities",
                    "keyCaption": "Activities",
                    "mandatory": false,
                    "type": "object",
                    "value": [],
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "change_category",
                    "keyCaption": "Classification",
                    "mandatory": false,
                    "type": "list",
                    "value": 0,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "assigned_group",
                    "keyCaption": "Admin group",
                    "mandatory": false,
                    "type": "list",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "location",
                    "keyCaption": "Location",
                    "mandatory": false,
                    "type": "list",
                    "value": null,
                    "valueCaption": "",
                    "valueClass": ""
                },
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "sr_type",
                    "keyCaption": "Service Record Type",
                    "mandatory": false,
                    "type": "list",
                    "value": 11,
                    "valueCaption": "Request Template",
                    "valueClass": ""
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Service Record Results:
>|Id|Title|Status|Service Record Type|Notes|
>|---|---|---|---|---|
>| 0 | Basic Request Process | New | Request Template | If relevant, add this Request details to the Knowledge base. Close the Request. |


### sysaid-service-record-delete
***
Delete one or more service records.


#### Base Command

`sysaid-service-record-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The service record ID. | Required | 
| solution | The solution for deleting the service record. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!sysaid-service-record-delete ids=2,32```
#### Human Readable Output

>Service Records 2,32 Deleted Successfully.

### sysaid-service-record-attach-file

***
Add an attachment to a service record.

#### Base Command

`sysaid-service-record-attach-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The service record ID. | Required | 
| file_id | File file ID to upload. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!sysaid-service-record-attach-file file_id=110@51d40811-801a-4b26-8861-68474c40b347 id=25```
#### Human Readable Output

>File uploaded to Service Record 25 successfully.

### sysaid-service-record-get-file

***
Download an attachment to a service record.

#### Base Command

`sysaid-service-record-get-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The service record ID. | Required | 
| file_id | The ID of the file to download. | Required | 
| file_name | The full name with extension of the file to be downloaded. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Integer | The size of the file. | 
| File.SHA1 | String | The SHA1 of the file. | 
| File.SHA256 | String | The SHA256 of the file. | 
| File.SHA512 | String | The SHA512 of the file. |
| File.Name | String | The full name with extension of the file. | 
| File.SSDeep | String | The SSDeep of the file. | 
| File.EntryID | String | The entryId of the file. | 
| File.Info | String | The info of the file. | 
| File.Type | String | The type of the file. | 
| File.MD5 | String | The MD5 of the file. | 
| File.Extension | String | The extension of the file. | 

#### Command example
```!sysaid-service-record-get-file file_id="-80357423_-1872498142" id=37 file_name="file_name.png"```

#### Context Example
```json
{
    "File": {
        "Size": 12345,
            "SHA1": "6d9ea21dcb062e9ba8cd20f7a9982726efc7a3a9",
            "SHA256": "44acf94aacf694950485c6fb0ff36f9aa72273479780abf591e052ba4d31e6ae",
            "SHA512": "36a0ea76413cf38f6de997c3e1d5229ee242458b024a6869f69054bdcbd61bcf572ba430e2b69d24ee8b7d3a5b94ae20fdc6fdafdf607407ac24bd9b6a88dc71",
            "Name": "file_name.png",
            "SSDeep": "1536:qCv/2+0gCPs0hzlUXOMvVAN50PjPS4ScOcy/Va/QgGZcm4p4/iuI:1/Vus0hzlqOMpj6Xcy/Va/Cgp4C",
            "EntryID": "112@6840e1fb-a9e6-4a66-8454-cdeaf5b98639",
            "Info": "image/png",
            "Type": "PNG image data, 2560 x 1773, 8-bit/color RGBA, non-interlaced",
            "MD5": "e0cca2f09d13bc2c7729b7caacbe2b6f",
            "Extension": "png",
    }
}
```

#### Human Readable Output

There is no human readable output for this command.

### sysaid-service-record-delete-file

***
Delete an attachment from a service record.

#### Base Command

`sysaid-service-record-delete-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The service record ID. | Required | 
| file_id | The attachment file ID to delete. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!sysaid-service-record-delete-file id=25 file_id=534492489_354835714```
#### Human Readable Output

>File deleted from Service Record 25 successfully.

### sysaid-service-record-get

***
Returns the information for the specified service record.

#### Base Command

`sysaid-service-record-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The service record ID. | Required | 
| fields | List of fields to return, comma separated. If sent together with view parameter, returns both view’s fields and the requested fields. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SysAid.ServiceRecord.id | String | The ID of the service record. | 
| SysAid.ServiceRecord.title | String | The title of the service record. | 
| SysAid.ServiceRecord.status | String | The status of the service record. | 
| SysAid.ServiceRecord.update_time | Date | The modify time of the service record. | 
| SysAid.ServiceRecord.sr_type | String | The type of the service record. | 
| SysAid.ServiceRecord.notes | String | The notes of the service record. | 

#### Command example
```!sysaid-service-record-get id=25 fields=all```
#### Context Example
```json
{
    "SysAid": {
        "ServiceRecord": {
            "CustomColumn3sr": "Demo Test",
            "account_id": "paloaltonetworks_trial",
            "actions": null,
            "activities": null,
            "agreement": "DEFAULT SLA",
            "alertID": "green",
            "all_active_assigned_to": "",
            "archive": "No",
            "assign_counter": "1",
            "assigned_group": "",
            "attachments": null,
            "canArchive": true,
            "canDelete": true,
            "canUpdate": true,
            "cc": "",
            "change_category": "",
            "childs": null,
            "ci": "",
            "close_time": "",
            "closure_information": "",
            "company": "",
            "computer_id": "",
            "computer_name": "",
            "current_support_level": "0",
            "cust_date1": "",
            "cust_date2": "",
            "cust_int1": "0",
            "cust_int2": "0",
            "cust_list1": "",
            "cust_list2": "",
            "cust_notes": "This is a note for the API",
            "cust_text1": "",
            "cust_text2": "",
            "department": "",
            "description": "This is a test incident",
            "due_date": "",
            "email_account": " ",
            "escalation": "0",
            "followup_actual_date": "",
            "followup_planned_date": "",
            "followup_text": "",
            "followup_user": "",
            "hasChildren": false,
            "history": null,
            "id": "25",
            "impact": "Low",
            "info": [
                {
                    "customColumnType": null,
                    "defaultValue": null,
                    "editable": true,
                    "key": "third_level_category",
                    "keyCaption": "Third Level Category",
                    "mandatory": false,
                    "type": "list",
                    "value": "Cannot access email",
                    "valueCaption": "Cannot access email",
                    "valueClass": ""
                }
              ]
            "insert_time": "03/07/2022 08:56:35 AM",
            "is_escalated": "No",
            "known_error": "",
            "linkedSRs": null,
            "links": null,
            "location": "",
            "lock_field": "25",
            "max_support_level": "0",
            "merged_service_records": "",
            "merged_to": "",
            "messages": null,
            "notes": null,
            "parent_link": "",
            "priority": "Low",
            "problem_sub_type": "Tablet",
            "problem_type": "Mobile Devices",
            "project_id": null,
            "quick_name": "",
            "relation_graph": null,
            "reopen_counter": "0",
            "request_user": "sysaid-dmst",
            "request_user_name": "sysaid-dmst",
            "resolution": "",
            "responsibility": "sysaid-dmst",
            "responsible_manager": "",
            "screen": null,
            "solution": "",
            "solutionModel": null,
            "source": "Self-Service Portal",
            "sr_type": "Incident",
            "sr_weight": "0",
            "status": "New",
            "sub_type": "DEFAULT",
            "submit_user": "sysaid-dmst",
            "success_rating": "0",
            "survey_status": "The survey has not been sent.",
            "task_id": "",
            "third_level_category": "Cannot access email",
            "timer1": "35240361631",
            "timer2": "35240361631",
            "title": "Cannot access email - Test ",
            "totalTime": "25",
            "update_time": "04/19/2023 05:48:02 AM",
            "update_user": "sysaid-dmst",
            "urgency": "Normal",
            "user_manager_name": "",
            "version": "8",
            "video": null,
            "workaround": ""
        }
    }
}
```

#### Human Readable Output

>### Service Record Results:
>|Id|Title|Status|Modify Time|Service Record Type| Notes                                                                                                                                                                                            |
>|---|---|---|---|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---|
>| 25 | Cannot access email - Test  | New | 04/19/2023 05:48:02 AM | Incident | sysaid-dmst (04/19/2023 05:48 AM):<br/>   Note<br/>,<br/><br/>sysaid-dmst (04/19/2023 05:34 AM):<br/>   this is a new note<br/>,<br/><br/>sysaid-dmst (03/10/2022 12:59:20):<br/>   THis is a note |


## Service Record Results:

| | |
| --- | --- |
| Id |	37 |
| Title |	Basic Request Process2 |
| Status |	New |
| Modify Time |	03/30/2022 01:56:47 AM |
| Service Record Type |	Request |
| Notes |	If relevant, add this Request details to the Knowledge base. Close the Request. |


### sysaid-service-record-add-note

***
Add a note to a Service Record

#### Base Command

`sysaid-service-record-add-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The service record ID. | Required | 
| note | The note to be added to the Service Record. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!sysaid-service-record-add-note id=25 note=`this is a new note````
#### Human Readable Output

>Updated record with new note