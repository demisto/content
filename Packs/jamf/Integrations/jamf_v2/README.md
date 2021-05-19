EMM for apple devices (Mac, iPhone, Apple TV, iPad). Can be used to control various configurations via different policies, Install/Uninstall applications, lock devices, smart groups searches and more.
This integration was integrated and tested with version 10.28.0-t1615386406 of jamf v2
JAMF classic API: https://www.jamf.com/developers/apis/classic/reference/#/

## Configure jamf v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for jamf v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Username | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### jamf-get-computers
***
This command will return a list of computers or a single computer based on the parameters being passed. In case no parameter are passed, a list of all computers with their associated IDs will be returned. Please note that only one of the parameters should be passed. By default, will return the first 50 computers to the context (id + name).


#### Base Command

`jamf-get-computers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | get the “general” subset of a specific computer. | Optional | 
| basic_subset | Default is “False”. “True” will return the “basic” subset for all of the computers. Possible values are: True, false. Default is False. | Optional | 
| match | Match computers by specific characteristics (supports wildcards) like: name, udid, serial_number, mac_address, username, realname, email. e.g: “match=john*”, “match=C52F72FACB9T”. Possible values are: . | Optional | 
| limit | The number of results to be returned on each page (default is 50). The maximum size is 200. Relevant only when no “id” is provided. Default is 50. | Optional | 
| page |  number of requested page (relevant when no id is provided). Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.Computer.id | Number | The computer id. | 
| JAMF.Computer.name | String | The computer name. | 
| JAMF.Computer.network_adapter_type | String | The computer network adapter type. | 
| JAMF.Computer.mac_address | Date | The computer mac address. | 
| JAMF.Computer.alt_network_adapter_type | String | The computer alt network adapter type. | 
| JAMF.Computer.alt_mac_address | String | The computer alt mac address. | 
| JAMF.Computer.ip_address | String | The computer IP address. | 
| JAMF.Computer.last_reported_ip | String | The computer last reported IP. | 
| JAMF.Computer.serial_number | String | The computer serial number. | 
| JAMF.Computer.udid | String | The computer udid. | 
| JAMF.Computer.jamf_version | String | The computer jamf version. | 
| JAMF.Computer.platform | String | The computer platform. | 
| JAMF.Computer.barcode_1 | String | The computer barcode_1. | 
| JAMF.Computer.barcode_2 | String | The computer barcode_2. | 
| JAMF.Computer.asset_tag | String | The computer asset tag. | 
| JAMF.Computer.remote_management.managed | Boolean | The computer remote managment. | 
| JAMF.Computer.remote_management.management_username | String | The computer remote managment username. | 
| JAMF.Computer.remote_management.management_password_sha256 | String | The computer remote managment password SHA256. | 
| JAMF.Computer.supervised | Boolean | The computer supervised. | 
| JAMF.Computer.mdm_capable | Boolean | The computer mdm capable. | 
| JAMF.Computer.report_date | Date | The computer report date. | 
| JAMF.Computer.report_date_epoch | Date | The computer repoer date in epoch. | 
| JAMF.Computer.report_date_utc | Date | The computer report date in UTC. | 
| JAMF.Computer.last_contact_time | Date | The computer last contact time. | 
| JAMF.Computer.last_contact_time_epoch | Date | The computer last contact time in epoch. | 
| JAMF.Computer.last_contact_time_utc | Date | The computer last contact time in UTC. | 
| JAMF.Computer.initial_entry_date | Date | The computer initial entry date. | 
| JAMF.Computer.initial_entry_date_epoch | Date | The computer initial entry date in epoch. | 
| JAMF.Computer.initial_entry_date_utc | Date | The computer initial entry date in UTC. | 
| JAMF.Computer.last_cloud_backup_date_epoch | Number | The computer last cloud backup date in epoch. | 
| JAMF.Computer.last_cloud_backup_date_utc | String | The computer last cloud backup date in UTC. | 
| JAMF.Computer.last_enrolled_date_epoch | Date | The computer last enrolled date in epoch. | 
| JAMF.Computer.last_enrolled_date_utc | Date | The computer last enrolled date in UTC. | 
| JAMF.Computer.mdm_profile_expiration_epoch | Number | The computer mdm profile expiration in epoch. | 
| JAMF.Computer.mdm_profile_expiration_utc | String | The computer mdm profile expiration in UTC. | 
| JAMF.Computer.distribution_point | String | The computer distribution point. | 
| JAMF.Computer.sus | String | The computer sus. | 
| JAMF.Computer.netboot_server | String | The computer netbbot server. | 
| JAMF.Computer.site.id | Number | The computer site ID. | 
| JAMF.Computer.site.name | String | The computer site name. | 
| JAMF.Computer.itunes_store_account_is_active | Boolean | The computer itunes store accont | 


#### Command Example
```!jamf-get-computers limit=5```

#### Context Example
```json
{
    "JAMF": {
        "Computer": [
            {
                "id": 1,
                "name": "Computer 95"
            },
            {
                "id": 2,
                "name": "Computer 104"
            },
            {
                "id": 3,
                "name": "Computer 124"
            },
            {
                "id": 4,
                "name": "Computer 43"
            },
            {
                "id": 5,
                "name": "Computer 72"
            }
        ]
    }
}
```

#### Human Readable Output

>### Jamf get computers result
>|ID|Name|
>|---|---|
>| 1 | Computer 95 |
>| 2 | Computer 104 |
>| 3 | Computer 124 |
>| 4 | Computer 43 |
>| 5 | Computer 72 |


### jamf-get-computer-subset
***
Returns a specific subset for a specific computer.


#### Base Command

`jamf-get-computer-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | In order to identify which computer is requested, one of these identifiers should be selected: id, name, udid, serial_number, mac_address. Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the “identifier”. For example, if we choose the “id” identifier, a value of a computer id should be passed. If we choose “mac_address” as the identifier, a value of a computer’s mac address should be passed, etc. | Required | 
| subset | The requested subset. Available Subsets: General, Location, Purchasing, Peripherals, Hardware, Certificates, Software, ExtensionAttributes, GroupsAccounts,  iphones, ConfigurationProfiles. Possible values are: General, Location, Purchasing, Peripherals, Hardware, Certificates, Software, ExtensionAttributes, GroupsAccounts, iphones, ConfigurationProfiles. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerSubset.general.id | Number | The computer ID. | 
| JAMF.ComputerSubset.general.name | String | The computer name. | 
| JAMF.ComputerSubset.general.network_adapter_type | String | The computer network adapter type. | 
| JAMF.ComputerSubset.general.mac_address | Date | The computer mac address. | 
| JAMF.ComputerSubset.general.alt_network_adapter_type | String | The computer alt network adapter type. | 
| JAMF.ComputerSubset.general.alt_mac_address | String | The computer alt mac address. | 
| JAMF.ComputerSubset.general.ip_address | String | The computer IP address. | 
| JAMF.ComputerSubset.general.last_reported_ip | String | The computer last reported IP. | 
| JAMF.ComputerSubset.general.serial_number | String | The computer serial number. | 
| JAMF.ComputerSubset.general.udid | String | The computer udid. | 
| JAMF.ComputerSubset.general.jamf_version | String | The computer Jamf version. | 
| JAMF.ComputerSubset.general.platform | String | The computer platform. | 
| JAMF.ComputerSubset.general.barcode_1 | String | The computer barcode 1. | 
| JAMF.ComputerSubset.general.barcode_2 | String | The computer barcode 2. | 
| JAMF.ComputerSubset.general.asset_tag | String | The computer asset tag. | 
| JAMF.ComputerSubset.general.remote_management.managed | Boolean | If the computer is managed. | 
| JAMF.ComputerSubset.general.remote_management.management_username | String | The computer managment username. | 
| JAMF.ComputerSubset.general.remote_management.management_password_sha256 | String | The computer managment password SHA256. | 
| JAMF.ComputerSubset.general.supervised | Boolean | If the computer is supervised. | 
| JAMF.ComputerSubset.general.mdm_capable | Boolean | If the computer is mdm capable. | 
| JAMF.ComputerSubset.general.report_date | Date | The computer report date. | 
| JAMF.ComputerSubset.general.report_date_epoch | Date | The computer repoer date in epoch. | 
| JAMF.ComputerSubset.general.report_date_utc | Date | The computer report date in UTC. | 
| JAMF.ComputerSubset.general.last_contact_time | Date | The computer last contact time. | 
| JAMF.ComputerSubset.general.last_contact_time_epoch | Date | The computer last contact time in epoch. | 
| JAMF.ComputerSubset.general.last_contact_time_utc | Date | The computer last contact time in UTC. | 
| JAMF.ComputerSubset.general.initial_entry_date | Date | The computer initial entry date. | 
| JAMF.ComputerSubset.general.initial_entry_date_epoch | Date | The computer initial entry date in epoch. | 
| JAMF.ComputerSubset.general.initial_entry_date_utc | Date | The computer initial entry date in UTC. | 
| JAMF.ComputerSubset.general.last_cloud_backup_date_epoch | Number | The computer last cloud backup date in epoch. | 
| JAMF.ComputerSubset.general.last_cloud_backup_date_utc | String | The computer last cloud backup date in UTC. | 
| JAMF.ComputerSubset.general.last_enrolled_date_epoch | Date | The computer last enrolled date in epoch. | 
| JAMF.ComputerSubset.general.last_enrolled_date_utc | Date | The computer last enrolled date in UTC. | 
| JAMF.ComputerSubset.general.mdm_profile_expiration_epoch | Number | The computer mdm profile expiration in epoch. | 
| JAMF.ComputerSubset.general.mdm_profile_expiration_utc | String | The computer mdm profile expiration in UTC. | 
| JAMF.ComputerSubset.general.distribution_point | String | The computer distribution point. | 
| JAMF.ComputerSubset.general.sus | String | The computer sus. | 
| JAMF.ComputerSubset.general.netboot_server | String | The computer netbbot server. | 
| JAMF.ComputerSubset.general.site.id | Number | The computer site ID. | 
| JAMF.ComputerSubset.general.site.name | String | The computer site name. | 
| JAMF.ComputerSubset.general.itunes_store_account_is_active | Boolean | The computer itunes store accont | 
| JAMF.ComputerSubset.location.username | String | The computer username. | 
| JAMF.ComputerSubset.location.realname | String | The computer real name. | 
| JAMF.ComputerSubset.location.real_name | String | The computer real name. | 
| JAMF.ComputerSubset.location.email_address | String | The computer email address. | 
| JAMF.ComputerSubset.location.position | String | The computer position. | 
| JAMF.ComputerSubset.location.phone | String | The computer phone number. | 
| JAMF.ComputerSubset.location.phone_number | String | The computer phone number. | 
| JAMF.ComputerSubset.location.department | String | The computer department. | 
| JAMF.ComputerSubset.location.building | String | The computer building. | 
| JAMF.ComputerSubset.location.room | String | The computer room. | 
| JAMF.ComputerSubset.purchasing.is_purchased | Boolean | If the computer is purchased. | 
| JAMF.ComputerSubset.purchasing.is_leased | Boolean | If the computer is leased. | 
| JAMF.ComputerSubset.purchasing.po_number | String | The computer po number. | 
| JAMF.ComputerSubset.purchasing.vendor | String | The computer vendor. | 
| JAMF.ComputerSubset.purchasing.applecare_id | String | The computer applecare ID. | 
| JAMF.ComputerSubset.purchasing.purchase_price | String | The computer purchase price. | 
| JAMF.ComputerSubset.purchasing.purchasing_account | String | The computer purchase account. | 
| JAMF.ComputerSubset.purchasing.po_date | String | The computer po date. | 
| JAMF.ComputerSubset.purchasing.po_date_epoch | Number | The computer po date in epoch | 
| JAMF.ComputerSubset.purchasing.po_date_utc | String | The computer po date in UTC. | 
| JAMF.ComputerSubset.purchasing.warranty_expires | String | The computer warranty expires date. | 
| JAMF.ComputerSubset.purchasing.warranty_expires_epoch | Number | The computer warranty expires date in epoch. | 
| JAMF.ComputerSubset.purchasing.warranty_expires_utc | String | The computer warranty expires date in UTC. | 
| JAMF.ComputerSubset.purchasing.lease_expires | String | The computer warranty lease expires date. | 
| JAMF.ComputerSubset.purchasing.lease_expires_epoch | Number | The computer warranty lease expires date in epoch. | 
| JAMF.ComputerSubset.purchasing.lease_expires_utc | String | The computer warranty lease expires date in UTC. | 
| JAMF.ComputerSubset.purchasing.life_expectancy | Number | The computer life expectancy. | 
| JAMF.ComputerSubset.purchasing.purchasing_contact | String | The computer purchasing contact. | 
| JAMF.ComputerSubset.purchasing.os_applecare_id | String | The computer OS applecare ID. | 
| JAMF.ComputerSubset.purchasing.os_maintenance_expires | String | The computer OS maintenance expires. | 
| JAMF.ComputerSubset.hardware.make | String | The computer maker. | 
| JAMF.ComputerSubset.hardware.model | String | The computer model. | 
| JAMF.ComputerSubset.hardware.model_identifier | String | The computer model ID. | 
| JAMF.ComputerSubset.hardware.os_name | String | The computer OS name. | 
| JAMF.ComputerSubset.hardware.os_version | String | The computer OS version. | 
| JAMF.ComputerSubset.hardware.os_build | String | The computer OS build. | 
| JAMF.ComputerSubset.hardware.master_password_set | Boolean | If the master password is set for the computer. | 
| JAMF.ComputerSubset.hardware.active_directory_status | String | The computer active directory status. | 
| JAMF.ComputerSubset.hardware.service_pack | String | The computer service pack. | 
| JAMF.ComputerSubset.hardware.processor_type | String | The computer processor type. | 
| JAMF.ComputerSubset.hardware.processor_architecture | String | The computer processor architecture. | 
| JAMF.ComputerSubset.hardware.processor_speed | Number | The computer processor speed. | 
| JAMF.ComputerSubset.hardware.processor_speed_mhz | Number | The computer processor speed in mhz. | 
| JAMF.ComputerSubset.hardware.number_processors | Number | The number of processors in the computer. | 
| JAMF.ComputerSubset.hardware.number_cores | Number | The number of cores in the computer. | 
| JAMF.ComputerSubset.hardware.total_ram | Number | The number of RAM in the computer. | 
| JAMF.ComputerSubset.hardware.total_ram_mb | Number | The number of RAM in the computer in MB. | 
| JAMF.ComputerSubset.hardware.boot_rom | String | The computer boot ROM. | 
| JAMF.ComputerSubset.hardware.bus_speed | Number | The computer bus speed. | 
| JAMF.ComputerSubset.hardware.bus_speed_mhz | Number | The computer bus speed in mhz. | 
| JAMF.ComputerSubset.hardware.battery_capacity | Number | The computer battery capacity. | 
| JAMF.ComputerSubset.hardware.cache_size | Number | The computer cache size. | 
| JAMF.ComputerSubset.hardware.cache_size_kb | Number | The computer cache size in KB. | 
| JAMF.ComputerSubset.hardware.available_ram_slots | Number | The computer available RAM slots. | 
| JAMF.ComputerSubset.hardware.optical_drive | String | The computer optical drive. | 
| JAMF.ComputerSubset.hardware.nic_speed | String | The computer nic speed. | 
| JAMF.ComputerSubset.hardware.smc_version | String | The compute smc version. | 
| JAMF.ComputerSubset.hardware.ble_capable | Boolean | If the computer is ble capable. | 
| JAMF.ComputerSubset.hardware.supports_ios_app_installs | Boolean | If the computer supports ios app installs. | 
| JAMF.ComputerSubset.hardware.sip_status | String | The computer sip status. | 
| JAMF.ComputerSubset.hardware.gatekeeper_status | String | The computer gatekeeper status. | 
| JAMF.ComputerSubset.hardware.xprotect_version | String | The computer xprotect version. | 
| JAMF.ComputerSubset.hardware.institutional_recovery_key | String | The computer institutional recovery key. | 
| JAMF.ComputerSubset.hardware.disk_encryption_configuration | String | The computer disk encryption configuration. | 
| JAMF.ComputerSubset.hardware.storage.disk | String | The computer disk storage. | 
| JAMF.ComputerSubset.hardware.storage.model | String | The computer model storage. | 
| JAMF.ComputerSubset.hardware.storage.revision | String | The computer revision storage. | 
| JAMF.ComputerSubset.hardware.storage.serial_number | String | The computer storage serial number. | 
| JAMF.ComputerSubset.hardware.storage.size | Number | The computer storage size. | 
| JAMF.ComputerSubset.hardware.storage.drive_capacity_mb | Number | The computer storage drive capacity in MB. | 
| JAMF.ComputerSubset.hardware.storage.connection_type | String | The computer storage connection type. | 
| JAMF.ComputerSubset.hardware.storage.smart_status | String | The computer storage smart status. | 
| JAMF.ComputerSubset.hardware.storage.partitions.name | String | The computer storage partition name. | 
| JAMF.ComputerSubset.hardware.storage.partitions.size | Number | The computer storage partition size. | 
| JAMF.ComputerSubset.hardware.storage.partitions.type | String | The computer storage partition type. | 
| JAMF.ComputerSubset.hardware.storage.partitions.partition_capacity_mb | Number | The computer storage partition capacity in MB. | 
| JAMF.ComputerSubset.hardware.storage.partitions.percentage_full | Number | The computer storage partition full percentage. | 
| JAMF.ComputerSubset.hardware.storage.partitions.available_mb | Number | The computer storage partition available in MB. | 
| JAMF.ComputerSubset.hardware.storage.partitions.filevault_status | String | The computer storage partition filevault status. | 
| JAMF.ComputerSubset.hardware.storage.partitions.filevault_percent | Number | The computer storage partition filevault percent. | 
| JAMF.ComputerSubset.hardware.storage.partitions.filevault2_status | String | The computer storage partition second filevault status. | 
| JAMF.ComputerSubset.hardware.storage.partitions.filevault2_percent | Number | The computer storage partition second filevault percent. | 
| JAMF.ComputerSubset.hardware.storage.partitions.boot_drive_available_mb | Number | The computer storage partition boot drive available in MB. | 
| JAMF.ComputerSubset.hardware.storage.partitions.lvgUUID | String | The computer storage partition lvg UUID. | 
| JAMF.ComputerSubset.hardware.storage.partitions.lvUUID | String | The computer storage partition lv UUID. | 
| JAMF.ComputerSubset.hardware.storage.partitions.pvUUID | String | The computer storage partition pv UUID. | 
| JAMF.ComputerSubset.security.activation_lock | Boolean | The computer activation lock. | 
| JAMF.ComputerSubset.security.secure_boot_level | String | The computer secure boot level. | 
| JAMF.ComputerSubset.security.external_boot_level | String | The computer external boot level. | 
| JAMF.ComputerSubset.software.applications.name | String | The computer application name. | 
| JAMF.ComputerSubset.software.applications.path | String | The computer application path. | 
| JAMF.ComputerSubset.software.applications.version | String | The computer application version. | 
| JAMF.ComputerSubset.software.applications.bundle_id | String | The computer application bundle ID. | 
| JAMF.ComputerSubset.extension_attributes.id | Number | The computer extension attributes ID. | 
| JAMF.ComputerSubset.extension_attributes.name | String | The computer extension attributes name. | 
| JAMF.ComputerSubset.extension_attributes.type | String | The computer extension attributes type. | 
| JAMF.ComputerSubset.extension_attributes.multi_value | Boolean | The computer extension attributes multi value. | 
| JAMF.ComputerSubset.extension_attributes.value | String | The computer extension attributes value. | 
| JAMF.ComputerSubset.groups_accounts.user_inventories.disable_automatic_login | Boolean | If the user can automatically. | 
| JAMF.ComputerSubset.id | Number | The computer id | 


#### Command Example
```!jamf-get-computer-subset identifier=name identifier_value="Computer 95" subset=Location```

#### Context Example
```json
{
    "JAMF": {
        "ComputerSubset": {
            "computer": {
                "id": 1,
                "location": {
                    "building": "",
                    "department": "",
                    "email_address": "User91@email.com",
                    "phone": "123-605-6625",
                    "phone_number": "123-605-6625",
                    "position": "",
                    "real_name": "User 91",
                    "realname": "User 91",
                    "room": "100 Walker Street\t \r\nLevel 14, Suite 3",
                    "username": "user91"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf computer subset result
>|Email Address|Phone|Real Name|Room|Username|
>|---|---|---|---|---|
>| User91@email.com | 123-605-6625 | User 91 | 100 Walker Street	 <br/>Level 14, Suite 3 | user91 |


### jamf-computer-lock
***
Will send the "DeviceLock" command to a computer. This command logs the user out of the computer, restarts the computer, and then locks the computer. Optional: Displays a message on the computer when it locks. To unlock the computer, the user must enter the passcode that you specified when you sent the Lock Computer command.
For further information, please read the “Managing Computers → Settings and Security Management for Computers → Remote Commands for Computers” section in the official documentation (choose the relevant version first): https://www.jamf.com/resources/product-documentation/jamf-pro-administrators-guide/


#### Base Command

`jamf-computer-lock`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| passcode | A 6 digits value. This will be the passcode which will lock the computer after being locked. | Required | 
| id | The computer id which you like to lock. | Required | 
| lock_message |  A message to display on the lock screen. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerCommands.name | String | The command name | 
| JAMF.ComputerCommands.command_uuid | String | The command udid. | 
| JAMF.ComputerCommands.computer_id | String | The computer ID. | 


#### Command Example
```!jamf-computer-lock id=138 passcode=123456```

#### Context Example
```json
{
    "JAMF": {
        "ComputeCommands": {
            "CommandUUID": "ab9a9621-3553-4ca9-ac92-78da5a7ff01c",
            "ID": "138",
            "Name": "DeviceLock"
        }
    }
}
```

#### Human Readable Output

>### Computer 138 locked successfully
>|CommandUUID|ID|Name|
>|---|---|---|
>| ab9a9621-3553-4ca9-ac92-78da5a7ff01c | 138 | DeviceLock |


### jamf-computer-erase
***
Will send the “EraseDevice'' command to a computer. Permanently erases all the data on the computer and sets a passcode when required by the computer hardware type. Please note: When the command is sent to a computer with macOS 10.15 or later with an Apple T2 Security Chip, or a computer with Apple silicon (i.e., M1 chip), the computer will be erased and no passcode will be set.
For further information, please read the “Managing Computers → Settings and Security Management for Computers → Remote Commands for Computers” section in the official documentation (choose the relevant version first): https://www.jamf.com/resources/product-documentation/jamf-pro-administrators-guide/

#### Base Command

`jamf-computer-erase`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| passcode | A 6 digits value. This will be the passcode which will lock the computer after being erased. | Required | 
| id | The computer id which you like to erase. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerCommands.name | String | The command name. | 
| JAMF.ComputerCommands.command_uuid | String | The command udid. | 
| JAMF.ComputerCommands.computer_id | String | The computer ID. | 


#### Command Example
```!jamf-computer-erase id=138 passcode=123456```

#### Context Example
```json
{
    "JAMF": {
        "ComputerCommands": {
            "CommandUUID": "127ff865-7d25-4b4c-8ebb-a127cc85ef65",
            "ID": "138",
            "Name": "EraseDevice"
        }
    }
}
```

#### Human Readable Output

>### Computer 138 erase successfully
>|CommandUUID|ID|Name|
>|---|---|---|
>| 127ff865-7d25-4b4c-8ebb-a127cc85ef65 | 138 | EraseDevice |


### jamf-get-users
***
Return a list of users with their IDs or a specific user with general data about the user.


#### Base Command

`jamf-get-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id. | Optional | 
| name | The user name. | Optional | 
| email | The user email. | Optional | 
| limit | Maximum number of users to retrieve (maximal value is 200). Default is 50. | Optional | 
| page | Page number. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.User.id | Number | The user ID. | 
| JAMF.User.name | String | The user name. | 
| JAMF.User.full_name | String | The user full name. | 
| JAMF.User.email | String | The user email. | 
| JAMF.User.email_address | String | The user email address. | 
| JAMF.User.phone_number | String | The user phone number. | 
| JAMF.User.position | String | The user position. | 
| JAMF.User.managed_apple_id | String | The user managed apple ID. | 
| JAMF.User.enable_custom_photo_url | Boolean | If the user custom photo URl is enabled. | 
| JAMF.User.custom_photo_url | String | The user custom photo url. | 
| JAMF.User.ldap_server.id | Number | The user LDAP server ID. | 
| JAMF.User.ldap_server.name | String | The user LDAP server name. | 
| JAMF.User.extension_attributes.id | Number | The user extension attributes ID. | 
| JAMF.User.extension_attributes.name | String | The user extension attributes name. | 
| JAMF.User.extension_attributes.type | String | The user extension attributes type. | 
| JAMF.User.extension_attributes.value | String | The user extension attributes value. | 
| JAMF.User.links.total_vpp_code_count | Number | The user total VPP code acount. | 
| JAMF.User.user_groups.size | Number | The user groups size. | 
| JAMF.User.user_groups.user_group.id | Number | The user group ID. | 
| JAMF.User.user_groups.user_group.name | String | The user group name. | 
| JAMF.User.user_groups.user_group.is_smart | Boolean | If the user group is smart. | 


#### Command Example
```!jamf-get-users limit=3```

#### Context Example
```json
{
    "JAMF": {
        "User": [
            {
                "id": 81,
                "name": "test1"
            },
            {
                "id": 80,
                "name": "test2"
            },
            {
                "id": 76,
                "name": "test3"
            }
        ]
    }
}
```

#### Human Readable Output

>### Jamf get users result
>|ID|Name|
>|---|---|
>| 81 | test 1 |
>| 80 | test 2 |
>| 76 | test 3 |


### jamf-get-mobile-devices
***
Will return a list of all devices with general information on each of them.


#### Base Command

`jamf-get-mobile-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Gets the “general” subset of a specific device. | Optional | 
| match | Match devices by specific characteristics (supports wildcards) like: name, udid, serial_number, mac_address, username, email. e.g: “match=john*”, “match=C52F72FACB9T”. Possible values are: . | Optional | 
| limit | Maximum number of devices to retrieve (maximal value is 200). Default is 50. | Optional | 
| page | Page number. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDevices.id | Number | The mobile device ID. | 
| JAMF.MobileDevices.display_name | String | The mobile device display name. | 
| JAMF.MobileDevices.device_name | String | The mobile device name. | 
| JAMF.MobileDevices.name | String | The mobile device name. | 
| JAMF.MobileDevices.asset_tag | String | The mobile device asset ID. | 
| JAMF.MobileDevices.last_inventory_update | String | The mobile device last inventory update. | 
| JAMF.MobileDevices.last_inventory_update_epoch | Date | The mobile device last inventory update in epoch. | 
| JAMF.MobileDevices.last_inventory_update_utc | Date | The mobile device last inventory update in UTC. | 
| JAMF.MobileDevices.capacity | Number | The mobile device capacity. | 
| JAMF.MobileDevices.capacity_mb | Number | The mobile device capacity MB. | 
| JAMF.MobileDevices.available | Number | The mobile device available. | 
| JAMF.MobileDevices.available_mb | Number | The mobile device available MB. | 
| JAMF.MobileDevices.percentage_used | Number | The mobile device available percentage used. | 
| JAMF.MobileDevices.os_type | String | The mobile device OS type. | 
| JAMF.MobileDevices.os_version | String | The mobile device OS version. | 
| JAMF.MobileDevices.os_build | String | The mobile device OS build. | 
| JAMF.MobileDevices.serial_number | String | The mobile device serial number. | 
| JAMF.MobileDevices.udid | String | The mobile device udid. | 
| JAMF.MobileDevices.initial_entry_date_epoch | Date | The mobile device  initial entry date in epoch. | 
| JAMF.MobileDevices.initial_entry_date_utc | Date | The mobile device  initial entry date in UTC. | 
| JAMF.MobileDevices.phone_number | String | The mobile device phone number. | 
| JAMF.MobileDevices.ip_address | String | The mobile device IP address. | 
| JAMF.MobileDevices.wifi_mac_address | String | The mobile device WIFI mac address. | 
| JAMF.MobileDevices.bluetooth_mac_address | String | The mobile device bluetooth mac address. | 
| JAMF.MobileDevices.modem_firmware | String | The mobile device modem fireware. | 
| JAMF.MobileDevices.model | String | The mobile device model. | 
| JAMF.MobileDevices.model_identifier | String | The mobile device model ID. | 
| JAMF.MobileDevices.model_number | String | The mobile device model number. | 
| JAMF.MobileDevices.modelDisplay | String | The mobile device model display. | 
| JAMF.MobileDevices.model_display | String | The mobile device model display. | 
| JAMF.MobileDevices.device_ownership_level | String | The mobile device ownership level. | 
| JAMF.MobileDevices.enrollment_method | String | The mobile device enrollment method. | 
| JAMF.MobileDevices.last_enrollment_epoch | Number | The mobile device last enrollment in epoch. | 
| JAMF.MobileDevices.last_enrollment_utc | String | The mobile device last enrollment in UTC. | 
| JAMF.MobileDevices.mdm_profile_expiration_epoch | Number | The mobile device mdm profile expiration in epoch. | 
| JAMF.MobileDevices.mdm_profile_expiration_utc | String | The mobile device mdm profile expiration in UTC. | 
| JAMF.MobileDevices.managed | Boolean | If the mobile device is managed. | 
| JAMF.MobileDevices.supervised | Boolean | If the mobile device is supervised. | 
| JAMF.MobileDevices.exchange_activesync_device_identifier | String | The mobile device exchange active sync device ID. | 
| JAMF.MobileDevices.shared | String | The mobile device shared. | 
| JAMF.MobileDevices.diagnostic_submission | String | The mobile device diagnostic submission, | 
| JAMF.MobileDevices.app_analytics | String | The mobile device app analytics. | 
| JAMF.MobileDevices.tethered | String | The mobile device tethered. | 
| JAMF.MobileDevices.battery_level | Number | The mobile device battery level. | 
| JAMF.MobileDevices.ble_capable | Boolean | The mobile device ble capable. | 
| JAMF.MobileDevices.device_locator_service_enabled | Boolean | If the mobile device locator service is enabled. | 
| JAMF.MobileDevices.do_not_disturb_enabled | Boolean | If the mobile device do not disturb is enabled. | 
| JAMF.MobileDevices.cloud_backup_enabled | Boolean | If the mobile device cloud backup is enabled. | 
| JAMF.MobileDevices.last_cloud_backup_date_epoch | Date | The mobie device last cloud update backup date in epoch. | 
| JAMF.MobileDevices.last_cloud_backup_date_utc | Date | The mobie device last cloud update backup date in UTC. | 
| JAMF.MobileDevices.location_services_enabled | Boolean | If the mobile device location services is enabled. | 
| JAMF.MobileDevices.itunes_store_account_is_active | Boolean | If the mobile device itunes store accouns is enabled. | 
| JAMF.MobileDevices.last_backup_time_epoch | Number | The mobile device last backup time in epoch. | 
| JAMF.MobileDevices.last_backup_time_utc | String | The mobile device last backup time in UTC. | 
| JAMF.MobileDevices.site.id | Number | Tyhe mobile device site ID. | 
| JAMF.MobileDevices.site.name | String | The mobile device site name. | 


#### Command Example
```!jamf-get-mobile-devices limit=3```

#### Context Example
```json
{
    "JAMF": {
        "MobileDevice": [
            {
                "device_name": "Device 71",
                "id": 1,
                "managed": true,
                "model": "iPad 3rd Generation (Wi-Fi)",
                "modelDisplay": "iPad 3rd Generation (Wi-Fi)",
                "model_display": "iPad 3rd Generation (Wi-Fi)",
                "model_identifier": "iPad3,1",
                "name": "Device 71",
                "phone_number": "123-605-6625",
                "serial_number": "CA44F4D060A1",
                "supervised": false,
                "udid": "ca44f4c660a311e490b812df261f2c7e",
                "username": "user28",
                "wifi_mac_address": "B0:65:BD:4E:50:5D"
            },
            {
                "device_name": "Device 4",
                "id": 2,
                "managed": true,
                "model": "iPad mini (CDMA)",
                "modelDisplay": "iPad mini (CDMA)",
                "model_display": "iPad mini (CDMA)",
                "model_identifier": "iPad2,7",
                "name": "Device 4",
                "phone_number": "123-605-6625",
                "serial_number": "CA44CA9660A1",
                "supervised": false,
                "udid": "ab44ca8c60a311e490b812df261f2c7e",
                "username": "user82",
                "wifi_mac_address": "5C:96:9D:15:B7:CF"
            },
            {
                "device_name": "Device 68",
                "id": 3,
                "managed": true,
                "model": "iPad mini (Wi-Fi Only)",
                "modelDisplay": "iPad mini (Wi-Fi Only)",
                "model_display": "iPad mini (Wi-Fi Only)",
                "model_identifier": "iPad2,5",
                "name": "Device 68",
                "phone_number": "123-605-6625",
                "serial_number": "CA44F34060A1",
                "supervised": true,
                "udid": "ab44f33660a311e490b812df261f2c7e",
                "username": "user60",
                "wifi_mac_address": "1C:E6:2B:A5:62:51"
            }
        ]
    }
}
```

#### Human Readable Output

>### Jamf get mobile devices result
>|ID|Name|
>|---|---|
>| 1 | Device 71 |
>| 2 | Device 4 |
>| 3 | Device 68 |


### jamf-get-mobile-device-subset
***
Returns a specific subset for a specific mobile device.


#### Base Command

`jamf-get-mobile-device-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | In order to identify which device is requested, one of these identifiers should be selected: id, name, udid, serial_number, mac_address. Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value |  the value of the “identifier”. For example, if we choose the “id” identifier, a value of a mobile device’s id should be passed. If we choose the “mac_address” identifier, a value of a mobile device’s mac address should be passed, etc. | Required | 
| subset | The requested subset. Available Subsets: General, Location, Purchasing, Applications, Security, Network, Certificates, ExtensionAttributes, ProvisioningProfiles, MobileDeviceGroups, ConfigurationProfiles. Possible values are: General, Location, Purchasing, Applications, Security_object, Network, Certificates, ExtensionAttributes, ProvisioningProfiles, MobileDeviceGroups, ConfigurationProfiles. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceSubset.general.id | Number | The mobile device ID. | 
| JAMF.MobileDeviceSubset.general.display_name | String | The mobile device display name. | 
| JAMF.MobileDeviceSubset.general.device_name | String | The mobile device name. | 
| JAMF.MobileDeviceSubset.general.name | String | The mobile device name. | 
| JAMF.MobileDeviceSubset.general.asset_tag | String | The mobile device asset ID. | 
| JAMF.MobileDeviceSubset.general.last_inventory_update | String | The mobile device last inventory update. | 
| JAMF.MobileDeviceSubset.general.last_inventory_update_epoch | Date | The mobile device last inventory update in epoch. | 
| JAMF.MobileDeviceSubset.general.last_inventory_update_utc | Date | The mobile device last inventory update in UTC. | 
| JAMF.MobileDeviceSubset.general.capacity | Number | The mobile device capacity. | 
| JAMF.MobileDeviceSubset.general.capacity_mb | Number | The mobile device capacity MB. | 
| JAMF.MobileDeviceSubset.general.available | Number | The mobile device available. | 
| JAMF.MobileDeviceSubset.general.available_mb | Number | The mobile device available MB. | 
| JAMF.MobileDeviceSubset.general.percentage_used | Number | The mobile device available percentage used. | 
| JAMF.MobileDeviceSubset.general.os_type | String | The mobile device OS type. | 
| JAMF.MobileDeviceSubset.general.os_version | String | The mobile device OS version. | 
| JAMF.MobileDeviceSubset.general.os_build | String | The mobile device OS build. | 
| JAMF.MobileDeviceSubset.general.serial_number | String | The mobile device serial number. | 
| JAMF.MobileDeviceSubset.general.udid | String | The mobile device udid. | 
| JAMF.MobileDeviceSubset.general.initial_entry_date_epoch | Date | The mobile device  initial entry date in epoch. | 
| JAMF.MobileDeviceSubset.general.initial_entry_date_utc | Date | The mobile device  initial entry date in UTC. | 
| JAMF.MobileDeviceSubset.general.phone_number | String | The mobile device phone number. | 
| JAMF.MobileDeviceSubset.general.ip_address | String | The mobile device IP address. | 
| JAMF.MobileDeviceSubset.general.wifi_mac_address | String | The mobile device WIFI mac address. | 
| JAMF.MobileDeviceSubset.general.bluetooth_mac_address | String | The mobile device bluetooth mac address. | 
| JAMF.MobileDeviceSubset.general.modem_firmware | String | The mobile device modem fireware. | 
| JAMF.MobileDeviceSubset.general.model | String | The mobile device model. | 
| JAMF.MobileDeviceSubset.general.model_identifier | String | The mobile device model ID. | 
| JAMF.MobileDeviceSubset.general.model_number | String | The mobile device model number. | 
| JAMF.MobileDeviceSubset.general.modelDisplay | String | The mobile device model display. | 
| JAMF.MobileDeviceSubset.general.model_display | String | The mobile device model display. | 
| JAMF.MobileDeviceSubset.general.device_ownership_level | String | The mobile device ownership level. | 
| JAMF.MobileDeviceSubset.general.enrollment_method | String | The mobile device enrollment method. | 
| JAMF.MobileDeviceSubset.general.last_enrollment_epoch | Number | The mobile device last enrollment in epoch. | 
| JAMF.MobileDeviceSubset.general.last_enrollment_utc | String | The mobile device last enrollment in UTC. | 
| JAMF.MobileDeviceSubset.general.mdm_profile_expiration_epoch | Number | The mobile device mdm profile expiration in epoch. | 
| JAMF.MobileDeviceSubset.general.mdm_profile_expiration_utc | String | The mobile device mdm profile expiration in UTC. | 
| JAMF.MobileDeviceSubset.general.managed | Boolean | If the mobile device is managed. | 
| JAMF.MobileDeviceSubset.general.supervised | Boolean | If the mobile device is supervised. | 
| JAMF.MobileDeviceSubset.general.exchange_activesync_device_identifier | String | The mobile device exchange active sync device ID. | 
| JAMF.MobileDeviceSubset.general.shared | String | The mobile device shared. | 
| JAMF.MobileDeviceSubset.general.diagnostic_submission | String | The mobile device diagnostic submission, | 
| JAMF.MobileDeviceSubset.general.app_analytics | String | The mobile device app analytics. | 
| JAMF.MobileDeviceSubset.general.tethered | String | The mobile device tethered. | 
| JAMF.MobileDeviceSubset.general.battery_level | Number | The mobile device battery level. | 
| JAMF.MobileDeviceSubset.general.ble_capable | Boolean | The mobile device ble capable. | 
| JAMF.MobileDeviceSubset.general.device_locator_service_enabled | Boolean | If the mobile device locator service is enabled. | 
| JAMF.MobileDeviceSubset.general.do_not_disturb_enabled | Boolean | If the mobile device do not disturb is enabled. | 
| JAMF.MobileDeviceSubset.general.cloud_backup_enabled | Boolean | If the mobile device cloud backup is enabled. | 
| JAMF.MobileDeviceSubset.general.last_cloud_backup_date_epoch | Date | The mobie device last cloud update backup date in epoch. | 
| JAMF.MobileDeviceSubset.general.last_cloud_backup_date_utc | Date | The mobie device last cloud update backup date in UTC. | 
| JAMF.MobileDeviceSubset.general.location_services_enabled | Boolean | If the mobile device location services is enabled. | 
| JAMF.MobileDeviceSubset.general.itunes_store_account_is_active | Boolean | If the mobile device itunes store accouns is enabled. | 
| JAMF.MobileDeviceSubset.general.last_backup_time_epoch | Number | The mobile device last backup time in epoch. | 
| JAMF.MobileDeviceSubset.general.last_backup_time_utc | String | The mobile device last backup time in UTC. | 
| JAMF.MobileDeviceSubset.general.site.id | Number | Tyhe mobile device site ID. | 
| JAMF.MobileDeviceSubset.general.site.name | String | The mobile device site name. | 
| JAMF.MobileDeviceSubset.location.username | String | The mobile device username. | 
| JAMF.MobileDeviceSubset.location.realname | String | The mobile device real name. | 
| JAMF.MobileDeviceSubset.location.real_name | String | The mobile device real name. | 
| JAMF.MobileDeviceSubset.location.email_address | String | The mobile device email address. | 
| JAMF.MobileDeviceSubset.location.position | String | The mobile device position. | 
| JAMF.MobileDeviceSubset.location.phone | String | The mobile device phone number. | 
| JAMF.MobileDeviceSubset.location.phone_number | String | The mobile device phone number. | 
| JAMF.MobileDeviceSubset.location.department | String | The mobile device department. | 
| JAMF.MobileDeviceSubset.location.building | String | The mobile device building. | 
| JAMF.MobileDeviceSubset.location.room | String | The mobile device room. | 
| JAMF.MobileDeviceSubset.purchasing.is_purchased | Boolean | If the mobile device is purchased. | 
| JAMF.MobileDeviceSubset.purchasing.is_leased | Boolean | If the mobile device is leased. | 
| JAMF.MobileDeviceSubset.purchasing.po_number | String | The mobile device po number. | 
| JAMF.MobileDeviceSubset.purchasing.vendor | String | The mobile device vendor. | 
| JAMF.MobileDeviceSubset.purchasing.applecare_id | String | The mobile device applecare ID. | 
| JAMF.MobileDeviceSubset.purchasing.purchase_price | String | The mobile device purchase price. | 
| JAMF.MobileDeviceSubset.purchasing.purchasing_account | String | The mobile device purchase account. | 
| JAMF.MobileDeviceSubset.purchasing.po_date | String | The mobile device purchase po date. | 
| JAMF.MobileDeviceSubset.purchasing.po_date_epoch | Number | The mobile device purchase po date in epoch. | 
| JAMF.MobileDeviceSubset.purchasing.po_date_utc | String | The mobile device purchase po date in UTC. | 
| JAMF.MobileDeviceSubset.purchasing.warranty_expires | String | The mobile device warranty expires date. | 
| JAMF.MobileDeviceSubset.purchasing.warranty_expires_epoch | Number | The mobile device warranty expires date in epoch. | 
| JAMF.MobileDeviceSubset.purchasing.warranty_expires_utc | String | The mobile device warranty expires date in UTC. | 
| JAMF.MobileDeviceSubset.purchasing.lease_expires | String | The mobile device lease expires date. | 
| JAMF.MobileDeviceSubset.purchasing.lease_expires_epoch | Number | The mobile device lease expires date in epoch. | 
| JAMF.MobileDeviceSubset.purchasing.lease_expires_utc | String | The mobile device lease expires date in UTC. | 
| JAMF.MobileDeviceSubset.purchasing.life_expectancy | Number | The mobile device life expectancy. | 
| JAMF.MobileDeviceSubset.purchasing.purchasing_contact | String | The mobile device purchasing contact. | 
| JAMF.MobileDeviceSubset.applications.application_name | String | The mobile device application name. | 
| JAMF.MobileDeviceSubset.applications.application_version | String | The mobile device application version. | 
| JAMF.MobileDeviceSubset.applications.application_short_version | String | The mobile device application short version. | 
| JAMF.MobileDeviceSubset.applications.identifier | String | The mobile device application ID. | 
| JAMF.MobileDeviceSubset.security.data_protection | Boolean | If the mobile device has data protection. | 
| JAMF.MobileDeviceSubset.security.block_level_encryption_capable | Boolean | If the mobile device is block level encryption capable. | 
| JAMF.MobileDeviceSubset.security.file_level_encryption_capable | Boolean | If the mobile device is file level encryption capable. | 
| JAMF.MobileDeviceSubset.security.passcode_present | Boolean | If the mobile device has passcode present. | 
| JAMF.MobileDeviceSubset.security.passcode_compliant | Boolean | If the mobile device has passcode compliant. | 
| JAMF.MobileDeviceSubset.security.passcode_compliant_with_profile | Boolean | If the mobile device has passcode compliant with profile. | 
| JAMF.MobileDeviceSubset.security.passcode_lock_grace_period_enforced | String | The mobile device passcode lock grace period enforced. | 
| JAMF.MobileDeviceSubset.security.hardware_encryption | Number | The mobile device hardware encryption. | 
| JAMF.MobileDeviceSubset.security.activation_lock_enabled | Boolean | If the mobile device has activation lock enabled. | 
| JAMF.MobileDeviceSubset.security.jailbreak_detected | String | The mobile device security jailbreak detected. | 
| JAMF.MobileDeviceSubset.security.lost_mode_enabled | String | The mobile device lost mode. | 
| JAMF.MobileDeviceSubset.security.lost_mode_enforced | Boolean | If the mobile device has lost mode enforced. | 
| JAMF.MobileDeviceSubset.security.lost_mode_enable_issued_epoch | Date | Themobile device lost mode enable issued date in epoch. | 
| JAMF.MobileDeviceSubset.security.lost_mode_enable_issued_utc | Date | Themobile device lost mode enable issued date in UTC. | 
| JAMF.MobileDeviceSubset.security.lost_mode_message | String | The mobile device lost mode message. | 
| JAMF.MobileDeviceSubset.security.lost_mode_phone | String | The mobile device lost mode phone. | 
| JAMF.MobileDeviceSubset.security.lost_mode_footnote | String | The mobile device lost mode footnote. | 
| JAMF.MobileDeviceSubset.security.lost_location_epoch | Date | The mobile device lost location date in epoch. | 
| JAMF.MobileDeviceSubset.security.lost_location_utc | Date | The mobile device lost location date in UTC. | 
| JAMF.MobileDeviceSubset.security.lost_location_latitude | Number | The mobile device security lost location latitude. | 
| JAMF.MobileDeviceSubset.security.lost_location_longitude | Number | The mobile device security lost location longitude. | 
| JAMF.MobileDeviceSubset.security.lost_location_altitude | Number | The mobile device security lost location altitude. | 
| JAMF.MobileDeviceSubset.security.lost_location_speed | Number | The mobile device security lost location speed. | 
| JAMF.MobileDeviceSubset.security.lost_location_course | Number | The mobile device security lost location course. | 
| JAMF.MobileDeviceSubset.security.lost_location_horizontal_accuracy | Number | The mobile device security lost location horizontal accuracy. | 
| JAMF.MobileDeviceSubset.security.lost_location_vertical_accuracy | Number | The mobile device security lost location vertical accuracy. | 
| JAMF.MobileDeviceSubset.network.home_carrier_network | String | The mobile device home carrier network. | 
| JAMF.MobileDeviceSubset.network.cellular_technology | String | The mobile device cellular technology. | 
| JAMF.MobileDeviceSubset.network.voice_roaming_enabled | String | The mobile device voice roaming enabled. | 
| JAMF.MobileDeviceSubset.network.imei | String | The mobile device network imei. | 
| JAMF.MobileDeviceSubset.network.iccid | String | The mobile device network iccid. | 
| JAMF.MobileDeviceSubset.network.meid | String | The mobile device network meid. | 
| JAMF.MobileDeviceSubset.network.current_carrier_network | String | The mobile device current carrier network. | 
| JAMF.MobileDeviceSubset.network.carrier_settings_version | String | The mobile device network carrier settings version. | 
| JAMF.MobileDeviceSubset.network.current_mobile_country_code | String | The mobile device current mobile country code. | 
| JAMF.MobileDeviceSubset.network.current_mobile_network_code | String | The mobile device current mobile network codeץ | 
| JAMF.MobileDeviceSubset.network.home_mobile_country_code | String | The mobile device home mobile country codeץ | 
| JAMF.MobileDeviceSubset.network.home_mobile_network_code | String | The mobile device home mobile network codeץ | 
| JAMF.MobileDeviceSubset.network.data_roaming_enabled | Boolean | If the the mobile device has data roaming enabled. | 
| JAMF.MobileDeviceSubset.network.roaming | Boolean | The mobile device network roaming. | 
| JAMF.MobileDeviceSubset.network.phone_number | String | The mobile device network phone number. | 
| JAMF.MobileDeviceSubset.mobile_device_groups.id | Number | The mobile device group ID. | 
| JAMF.MobileDeviceSubset.mobile_device_groups.name | String | The mobile device group name. | 
| JAMF.MobileDeviceSubset.extension_attributes.id | Number | The mobile device extension attribute ID. | 
| JAMF.MobileDeviceSubset.extension_attributes.name | String | The mobile device extension attribute name. | 
| JAMF.MobileDeviceSubset.extension_attributes.type | String | The mobile device extension attribute type. | 
| JAMF.MobileDeviceSubset.extension_attributes.multi_value | Boolean | The mobile device extension attribute multi value. | 
| JAMF.MobileDeviceSubset.extension_attributes.value | String | The mobile device extension attribute value. | 
| JAMF.MobileDeviceSubset.id | String | The mobile device ID. | 


#### Command Example
```!jamf-get-mobile-device-subset identifier=id identifier_value=114 subset=Location```

#### Context Example
```json
{
    "JAMF": {
        "MobileDeviceSubset": {
            "mobiledevice": {
                "id": 114,
                "location": {
                    "building": "",
                    "department": "",
                    "email_address": "",
                    "phone": "",
                    "phone_number": "",
                    "position": "",
                    "real_name": "tomer test",
                    "realname": "tomer test",
                    "room": "",
                    "username": "tomertest"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf mobile device subset result
>|Real Name|Username|
>|---|---|
>| tomer test | tomertest |


### jamf-get-computers-by-application
***
Will return a list of computers with basic information based on an application filter.


#### Base Command

`jamf-get-computers-by-application`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application | the application’s name (supports wildcards). | Required | 
| version | the application’s version (supports wildcards) - applicable only when “application” parameter value is set. | Optional | 
| limit | Maximum number of devices to retrieve (maximal value is 200). Default is 50. | Optional | 
| page | Page number. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputersByApp.id | Number | The computer ID. | 
| JAMF.ComputersByApp.name | String | The computer name. | 
| JAMF.ComputersByApp.udid | String | The computer udid. | 
| JAMF.ComputersByApp.serial_number | String | The computer serial number. | 
| JAMF.ComputersByApp.mac_address | String | The computer mac address. | 
| JAMF.ComputersByApp.application | String | The appliction the user serched for. | 


#### Command Example
```!jamf-get-computers-by-application application=safar* limit=3```

#### Context Example
```json
{
    "JAMF": {
        "ComputersByApp": {
            "application": "safar*",
            "computers": [
                {
                    "id": 69,
                    "mac_address": "B8:E8:56:22:12:3E",
                    "name": "Computer 54",
                    "serial_number": "CA41014A60A1",
                    "udid": "CA410140-60A3-11E4-90B8-12DF261F2C71"
                },
                {
                    "id": 25,
                    "mac_address": "40:6C:8F:1A:4B:10",
                    "name": "Computer 67",
                    "serial_number": "CA40EE4460A1",
                    "udid": "CA40EE3A-60A3-11E4-90B8-12DF261F2C71"
                },
                {
                    "id": 24,
                    "mac_address": "00:88:65:41:14:B0",
                    "name": "Computer 31",
                    "serial_number": "CA40E50C60A1",
                    "udid": "CA40E502-60A3-11E4-90B8-12DF261F2C71"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Jamf computers by application result
>|Sum of computers|version|
>|---|---|
>| 2 | 14.0.3 |
>| 1 | 7.0 |
>| 1 | 7.0.1 |


### jamf-mobile-device-lost-mode
***
Will enable “lost mode” on a specific device. Lost Mode is a feature that allows you to lock a mobile device and track the device's location. The device will report the GPS coordinates of the point where the device receives the command. This feature adds additional protection to mobile devices and their data in the event that a device is lost or stolen.


#### Base Command

`jamf-mobile-device-lost-mode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the mobile device’s id. | Required | 
| lost_mode_message | A message that will be displayed on the device’s lock screen. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceCommands.name | String | The mobile device command name. | 
| JAMF.MobileDeviceCommands.status | String | The mobile device command status. | 
| JAMF.MobileDeviceCommands.management_id | String | The mobile device command managment ID. | 
| JAMF.MobileDeviceCommands.id | String | The mobile device command ID. | 


#### Command Example
```jamf-mobile-device-lost-mode id=114 ```

#### Human Readable Output
>### Computer 114 locked successfully


### jamf-mobile-device-erase
***
Permanently erases all data on the device and deactivates the device.


#### Base Command

`jamf-mobile-device-erase`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The device’s id. | Required | 
| preserve_data_plan | Retain cellular data plans (iOS 11 or later). Possible values are: True, False. Default is False. | Optional | 
| clear_activation_code | Clear Activation Lock on the device. Possible values are: True, False. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceCommands.name | String | The mobile device command name. | 
| JAMF.MobileDeviceCommands.status | String | The mobile device command status. | 
| JAMF.MobileDeviceCommands.management_id | String | The mobile device command managment ID. | 
| JAMF.MobileDeviceCommands.id | String | The mobile device command ID. | 


#### Command Example
```jamf-mobile-device-erase id=114```

#### Human Readable Output

>### Computer 114 erased successfully

