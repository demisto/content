Enterprise Mobility Management (EMM) for Apple devices (Mac, iPhone, Apple TV, iPad). Can be used to control various configurations via different policies, install and uninstall applications, lock devices, smart groups searches, and more.
This integration was integrated and tested with version xx of jamf v2_copy

## Configure jamf v2_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for jamf v2_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Username | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### jamf-get-computers
***
Returns a list of all computers with their associated IDs. By default, returns the first 50 computers to the context (ID + name).


#### Base Command

`jamf-get-computers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to be returned on each page. The maximum size is 200. Default is 50. | Optional | 
| page | The number of the requested page. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.Computer.id | Number | The computer ID. | 
| JAMF.Computer.name | String | The computer name. | 
| JAMF.Computer.Paging.total_results | Number | The number of computers returned in this specific search. | 
| JAMF.Computer.Paging.page_size | Number | The number of computers returned on each page. | 
| JAMF.Computer.Paging.current_page | Number | The number of the requested page. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computers-basic-subset
***
Returns the “basic” subset for all of the computers. The “basic” subset includes: MAC address, model, UDID, name, department, building, serial number, username, ID.


#### Base Command

`jamf-get-computers-basic-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to be returned on each page. The maximum size is 200. Default is 50. | Optional | 
| page | The number of the requested page. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.Computer.id | Number | The computer ID. | 
| JAMF.Computer.name | String | The computer name. | 
| JAMF.Computer.managed | Boolean | Whether the computer is managed. | 
| JAMF.Computer.username | String | The computer username. | 
| JAMF.Computer.model | String | The computer model. | 
| JAMF.Computer.department | String | The computer department. | 
| JAMF.Computer.building | String | The computer building. | 
| JAMF.Computer.mac_address | String | The computer MAC address. | 
| JAMF.Computer.udid | String | The computer UDID. | 
| JAMF.Computer.serial_number | String | The computer serial number. | 
| JAMF.Computer.report_date_utc | Date | The computer report date in UTC format. | 
| JAMF.Computer.report_date_epoch | Number | The computer report date in epoch format. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-by-id
***
Returns the "general" subset of a specific computer, e.g.: name, MAC address, IP, serial number, UDID, etc.


#### Base Command

`jamf-get-computer-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The computer ID.<br/>To get the computer ID, run the `jamf-get-computers` command to get all computers names and IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.Computer.id | Number | The computer ID. | 
| JAMF.Computer.name | String | The computer name. | 
| JAMF.Computer.network_adapter_type | String | The computer network adapter type. | 
| JAMF.Computer.mac_address | Date | The computer MAC address. | 
| JAMF.Computer.alt_network_adapter_type | String | The computer alt network adapter type. | 
| JAMF.Computer.alt_mac_address | String | The computer alt MAC address. | 
| JAMF.Computer.ip_address | String | The computer IP address. | 
| JAMF.Computer.last_reported_ip | String | The computer last reported IP address. | 
| JAMF.Computer.serial_number | String | The computer serial number. | 
| JAMF.Computer.udid | String | The computer UDID. | 
| JAMF.Computer.jamf_version | String | The computer Jamf version. | 
| JAMF.Computer.platform | String | The computer platform. | 
| JAMF.Computer.barcode_1 | String | The computer barcode_1. | 
| JAMF.Computer.barcode_2 | String | The computer barcode_2. | 
| JAMF.Computer.asset_tag | String | The computer asset tag. | 
| JAMF.Computer.remote_management.managed | Boolean | Whether the computer is remotely managed. | 
| JAMF.Computer.remote_management.management_username | String | The computer remote management username. | 
| JAMF.Computer.supervised | Boolean | Whether the computer is supervised. | 
| JAMF.Computer.mdm_capable | Boolean | Whether the computer is enabled for mobile device management \(MDM\). | 
| JAMF.Computer.mdm_capable_users | Boolean | The computer has MDM capable users. | 
| JAMF.Computer.report_date | Date | The computer report date. | 
| JAMF.Computer.report_date_epoch | Date | The computer report date in epoch format. | 
| JAMF.Computer.report_date_utc | Date | The computer report date in UTC format. | 
| JAMF.Computer.last_contact_time | Date | The computer last contact time. | 
| JAMF.Computer.last_contact_time_epoch | Date | The computer last contact time in epoch format. | 
| JAMF.Computer.last_contact_time_utc | Date | The computer last contact time in UTC format. | 
| JAMF.Computer.initial_entry_date | Date | The computer initial entry date. | 
| JAMF.Computer.initial_entry_date_epoch | Date | The computer initial entry date in epoch format. | 
| JAMF.Computer.initial_entry_date_utc | Date | The computer initial entry date in UTC format. | 
| JAMF.Computer.last_cloud_backup_date_epoch | Number | The computer last cloud backup date in epoch format. | 
| JAMF.Computer.last_cloud_backup_date_utc | String | The computer last cloud backup date in UTC format. | 
| JAMF.Computer.last_enrolled_date_epoch | Date | The computer last enrolled date in epoch format. | 
| JAMF.Computer.last_enrolled_date_utc | Date | The computer last enrolled date in UTC format. | 
| JAMF.Computer.mdm_profile_expiration_epoch | Number | The computer MDM profile expiration in epoch format. | 
| JAMF.Computer.mdm_profile_expiration_utc | String | The computer MDM profile expiration in UTC format. | 
| JAMF.Computer.distribution_point | String | The computer distribution point. | 
| JAMF.Computer.sus | String | The computer software updated service \(SUS\). | 
| JAMF.Computer.netboot_server | String | The computer netbbot server. | 
| JAMF.Computer.site.id | Number | The computer site ID. | 
| JAMF.Computer.site.name | String | The computer site name. | 
| JAMF.Computer.itunes_store_account_is_active | Boolean | The computer iTunes store account. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-by-match
***
Matches computers by specific characteristics and returns general data on each of the computers.


#### Base Command

`jamf-get-computer-by-match`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to be returned on each page. The maximum size is 200. Default is 50. | Optional | 
| page | The number of the requested page. Default is 0. | Optional | 
| match | Match computers by specific characteristics (supports wildcards) such as: name, UDID, serial_number, mac_address, username, realname, email. e.g.: “match=john*”, “match=C52F72FACB9T”. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.Computer.id | Number | The computer ID. | 
| JAMF.Computer.name | String | The computer name. | 
| JAMF.Computer.udid | String | The computer UDID. | 
| JAMF.Computer.serial_number | String | The computer serial number. | 
| JAMF.Computer.mac_address | String | The computer MAC address. | 
| JAMF.Computer.alt_mac_address | String | The computer alt MAC address. | 
| JAMF.Computer.asset_tag | String | The computer asset tag. | 
| JAMF.Computer.bar_code_1 | String | The computer barcode 1. | 
| JAMF.Computer.bar_code_2 | String | The computer barcode 2. | 
| JAMF.Computer.username | String | The computer username. | 
| JAMF.Computer.realname | String | The computer real name. | 
| JAMF.Computer.email | String | The computer email address. | 
| JAMF.Computer.email_address | String | The computer email address. | 
| JAMF.Computer.room | String | The computer room. | 
| JAMF.Computer.position | String | The computer position. | 
| JAMF.Computer.building | String | The computer building. | 
| JAMF.Computer.building_name | String | The computer building name. | 
| JAMF.Computer.department | String | The computer department. | 
| JAMF.Computer.department_name | String | The computer department name. | 
| JAMF.Computer.Paging.total_results | Number | The number of computers returned in this specific search. | 
| JAMF.Computer.Paging.page_size | Number | The number of computers to be returned on each page. | 
| JAMF.Computer.Paging.current_page | Number | The number of the requested page. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-general-subset
***
Returns the general subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-general-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerSubset.general.id | Number | The computer ID. | 
| JAMF.ComputerSubset.general.name | String | The computer name. | 
| JAMF.ComputerSubset.general.network_adapter_type | String | The computer network adapter type. | 
| JAMF.ComputerSubset.general.mac_address | Date | The computer MAC address. | 
| JAMF.ComputerSubset.general.alt_network_adapter_type | String | The computer alt network adapter type. | 
| JAMF.ComputerSubset.general.alt_mac_address | String | The computer alt MAC address. | 
| JAMF.ComputerSubset.general.ip_address | String | The computer IP address. | 
| JAMF.ComputerSubset.general.last_reported_ip | String | The computer last reported IP address. | 
| JAMF.ComputerSubset.general.serial_number | String | The computer serial number. | 
| JAMF.ComputerSubset.general.udid | String | The computer UDID. | 
| JAMF.ComputerSubset.general.jamf_version | String | The computer Jamf version. | 
| JAMF.ComputerSubset.general.platform | String | The computer platform. | 
| JAMF.ComputerSubset.general.barcode_1 | String | The computer barcode 1. | 
| JAMF.ComputerSubset.general.barcode_2 | String | The computer barcode 2. | 
| JAMF.ComputerSubset.general.asset_tag | String | The computer asset tag. | 
| JAMF.ComputerSubset.general.remote_management.managed | Boolean | Whether the computer is remotely managed. | 
| JAMF.ComputerSubset.general.remote_management.management_username | String | The computer managment username. | 
| JAMF.ComputerSubset.general.supervised | Boolean | Whether the computer is supervised. | 
| JAMF.ComputerSubset.general.mdm_capable | Boolean | Whether the computer is MDM capable. | 
| JAMF.Computer.general.mdm_capable_users | Boolean | Whether the computer has MDM capable users. | 
| JAMF.Computer.general.management_status.enrolled_via_dep | Boolean | Whether the computer was enrolled via DEP. | 
| JAMF.Computer.general.management_status.user_approved_enrollment | Boolean | Whether the enrollment is user-approved. | 
| JAMF.Computer.general.management_status.user_approved_mdm | Boolean | Whether the MDM is user-approved. | 
| JAMF.ComputerSubset.general.report_date | Date | The computer report date. | 
| JAMF.ComputerSubset.general.report_date_epoch | Date | The computer report date in epoch format. | 
| JAMF.ComputerSubset.general.report_date_utc | Date | The computer report date in UTC format. | 
| JAMF.ComputerSubset.general.last_contact_time | Date | The computer last contact time. | 
| JAMF.ComputerSubset.general.last_contact_time_epoch | Date | The computer last contact time in epoch format. | 
| JAMF.ComputerSubset.general.last_contact_time_utc | Date | The computer last contact time in UTC format. | 
| JAMF.ComputerSubset.general.initial_entry_date | Date | The computer initial entry date. | 
| JAMF.ComputerSubset.general.initial_entry_date_epoch | Date | The computer initial entry date in epoch format. | 
| JAMF.ComputerSubset.general.initial_entry_date_utc | Date | The computer initial entry date in UTC format. | 
| JAMF.ComputerSubset.general.last_cloud_backup_date_epoch | Number | The computer last cloud backup date in epoch format. | 
| JAMF.ComputerSubset.general.last_cloud_backup_date_utc | String | The computer last cloud backup date in UTC format. | 
| JAMF.ComputerSubset.general.last_enrolled_date_epoch | Date | The computer last enrolled date in epoch format. | 
| JAMF.ComputerSubset.general.last_enrolled_date_utc | Date | The computer last enrolled date in UTC format. | 
| JAMF.ComputerSubset.general.mdm_profile_expiration_epoch | Number | The computer MDM profile expiration in epoch format. | 
| JAMF.ComputerSubset.general.mdm_profile_expiration_utc | String | The computer MDM profile expiration in UTC format. | 
| JAMF.ComputerSubset.general.distribution_point | String | The computer distribution point format. | 
| JAMF.ComputerSubset.general.sus | String | The computer SUS. | 
| JAMF.ComputerSubset.general.netboot_server | String | The computer netbbot server. | 
| JAMF.ComputerSubset.general.site.id | Number | The computer site ID. | 
| JAMF.ComputerSubset.general.site.name | String | The computer site name. | 
| JAMF.ComputerSubset.general.itunes_store_account_is_active | Boolean | The computer iTunes store account. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-location-subset
***
Returns the location subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-location-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
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
| JAMF.ComputerSubset.id | Number | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-purchasing-subset
***
Returns the purchasing subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-purchasing-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerSubset.purchasing.is_purchased | Boolean | If the computer is purchased. | 
| JAMF.ComputerSubset.purchasing.is_leased | Boolean | If the computer is leased. | 
| JAMF.ComputerSubset.purchasing.po_number | String | The computer PO number. | 
| JAMF.ComputerSubset.purchasing.vendor | String | The computer vendor. | 
| JAMF.ComputerSubset.purchasing.applecare_id | String | The computer AppleCare ID. | 
| JAMF.ComputerSubset.purchasing.purchase_price | String | The computer purchase price. | 
| JAMF.ComputerSubset.purchasing.purchasing_account | String | The computer purchase account. | 
| JAMF.ComputerSubset.purchasing.po_date | String | The computer PO date. | 
| JAMF.ComputerSubset.purchasing.po_date_epoch | Number | The computer PO date in epoch format. | 
| JAMF.ComputerSubset.purchasing.po_date_utc | String | The computer PO date in UTC format. | 
| JAMF.ComputerSubset.purchasing.warranty_expires | String | The computer warranty expiration date. | 
| JAMF.ComputerSubset.purchasing.warranty_expires_epoch | Number | The computer warranty expiration date in epoch format. | 
| JAMF.ComputerSubset.purchasing.warranty_expires_utc | String | The computer warranty expiration date in UTC format. | 
| JAMF.ComputerSubset.purchasing.lease_expires | String | The computer warranty lease expiration date. | 
| JAMF.ComputerSubset.purchasing.lease_expires_epoch | Number | The computer warranty lease expiration date in epoch time. | 
| JAMF.ComputerSubset.purchasing.lease_expires_utc | String | The computer warranty lease expiration date in UTC format. | 
| JAMF.ComputerSubset.purchasing.life_expectancy | Number | The computer life expectancy. | 
| JAMF.ComputerSubset.purchasing.purchasing_contact | String | The computer purchasing contact. | 
| JAMF.ComputerSubset.purchasing.os_applecare_id | String | The computer operating system AppleCare ID. | 
| JAMF.ComputerSubset.purchasing.os_maintenance_expires | String | The computer operating system maintenance expiration date. | 
| JAMF.ComputerSubset.id | Number | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-peripherals-subset
***
Returns the peripherals subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-peripherals-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerSubset.peripherals | Number | The computer peripherals. | 
| JAMF.ComputerSubset.id | Number | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-hardware-subset
***
Returns the hardware subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-hardware-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerSubset.hardware.make | String | The computer maker. | 
| JAMF.ComputerSubset.hardware.model | String | The computer model. | 
| JAMF.ComputerSubset.hardware.model_identifier | String | The computer model ID. | 
| JAMF.ComputerSubset.hardware.os_name | String | The computer operating system name. | 
| JAMF.ComputerSubset.hardware.os_version | String | The computer operating system version. | 
| JAMF.ComputerSubset.hardware.os_build | String | The computer operating system build. | 
| JAMF.ComputerSubset.hardware.master_password_set | Boolean | Whether the master password is set for the computer. | 
| JAMF.ComputerSubset.hardware.active_directory_status | String | The computer active directory status. | 
| JAMF.ComputerSubset.hardware.service_pack | String | The computer service pack. | 
| JAMF.ComputerSubset.hardware.processor_type | String | The computer processor type. | 
| JAMF.ComputerSubset.hardware.processor_architecture | String | The computer processor architecture. | 
| JAMF.ComputerSubset.hardware.processor_speed | Number | The computer processor speed. | 
| JAMF.ComputerSubset.hardware.processor_speed_mhz | Number | The computer processor speed in MHz. | 
| JAMF.ComputerSubset.hardware.number_processors | Number | The number of processors in the computer. | 
| JAMF.ComputerSubset.hardware.number_cores | Number | The number of cores in the computer. | 
| JAMF.ComputerSubset.hardware.total_ram | Number | The amount of RAM in the computer. | 
| JAMF.ComputerSubset.hardware.total_ram_mb | Number | The amount of RAM in the computer in MB. | 
| JAMF.ComputerSubset.hardware.boot_rom | String | The computer boot ROM. | 
| JAMF.ComputerSubset.hardware.bus_speed | Number | The computer bus speed. | 
| JAMF.ComputerSubset.hardware.bus_speed_mhz | Number | The computer bus speed in MHz. | 
| JAMF.ComputerSubset.hardware.battery_capacity | Number | The computer battery capacity. | 
| JAMF.ComputerSubset.hardware.cache_size | Number | The computer cache size. | 
| JAMF.ComputerSubset.hardware.cache_size_kb | Number | The computer cache size in KB. | 
| JAMF.ComputerSubset.hardware.available_ram_slots | Number | The number of available RAM slots. | 
| JAMF.ComputerSubset.hardware.optical_drive | String | The computer optical drive. | 
| JAMF.ComputerSubset.hardware.nic_speed | String | The computer NIC speed. | 
| JAMF.ComputerSubset.hardware.smc_version | String | The compute SMC version. | 
| JAMF.ComputerSubset.hardware.ble_capable | Boolean | Whether the computer is BLE capable. | 
| JAMF.ComputerSubset.hardware.supports_ios_app_installs | Boolean | If the computer supports iOS app installations. | 
| JAMF.ComputerSubset.hardware.sip_status | String | The computer SIP status. | 
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
| JAMF.ComputerSubset.hardware.storage.partitions.percentage_full | Number | The percentage of the storage partition that is full. | 
| JAMF.ComputerSubset.hardware.storage.partitions.available_mb | Number | The amount of computer storage partition available in MB. | 
| JAMF.ComputerSubset.hardware.storage.partitions.filevault_status | String | The computer storage partition filevault status. | 
| JAMF.ComputerSubset.hardware.storage.partitions.filevault_percent | Number | The computer storage partition filevault percent. | 
| JAMF.ComputerSubset.hardware.storage.partitions.filevault2_status | String | The computer storage partition second filevault status. | 
| JAMF.ComputerSubset.hardware.storage.partitions.filevault2_percent | Number | The computer storage partition second filevault percent. | 
| JAMF.ComputerSubset.hardware.storage.partitions.boot_drive_available_mb | Number | The available space on the computer storage partition boot drive in MB. | 
| JAMF.ComputerSubset.hardware.storage.partitions.lvgUUID | String | The computer storage partition logical volume group \(lvg\) UUID. | 
| JAMF.ComputerSubset.hardware.storage.partitions.lvUUID | String | The computer storage partition logical volume \(lv\) UUID. | 
| JAMF.ComputerSubset.hardware.storage.partitions.pvUUID | String | The computer storage partition physical volume \(pv\) UUID. | 
| JAMF.ComputerSubset.id | Number | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-certificates-subset
***
Returns the certificates subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-certificates-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerSubset.certificates.common_name | String | The certificat common name. | 
| JAMF.ComputerSubset.certificates.identity | Boolean | The certificat identity. | 
| JAMF.ComputerSubset.certificates.expires_utc | Date | The certificat expiration date in UTC format. | 
| JAMF.ComputerSubset.certificates.expires_epoch | Number | The certificat expiration date in epoch format. | 
| JAMF.ComputerSubset.certificates.name | String | The certificat name. | 
| JAMF.ComputerSubset.id | Number | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-security-subset
***
Returns the security subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-security-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerSubset.security.activation_lock | Boolean | The computer activation lock. | 
| JAMF.ComputerSubset.security.secure_boot_level | String | The computer secure boot level. | 
| JAMF.ComputerSubset.security.external_boot_level | String | The computer external boot level. | 
| JAMF.ComputerSubset.id | Number | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-software-subset
***
Returns the software subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-software-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerSubset.software.unix_executables | String | The computer software's Unix executables. | 
| JAMF.ComputerSubset.software.licensed_software.name | String | The computer software's licensed software name. | 
| JAMF.ComputerSubset.software.installed_by_casper.package | String | The computer software that was installed by Jamf PRO. | 
| JAMF.ComputerSubset.software.installed_by_installer_swu.package | String | The computer software that was installed either by an installer, an app or a software update. | 
| JAMF.ComputerSubset.software.cached_by_casper.package | String | The computer software that was cached by Jamf PRO. | 
| JAMF.ComputerSubset.software.available_software_updates.name | String | The name of the available software updates. | 
| JAMF.ComputerSubset.software.available_updates.name | String | The name of the available updates. | 
| JAMF.ComputerSubset.software.available_updates.package_name | String | The name of the available update package. | 
| JAMF.ComputerSubset.software.available_updates.version | String | The version of the available update. | 
| JAMF.ComputerSubset.software.running_services.name | String | The computer running service name. | 
| JAMF.ComputerSubset.software.applications.name | String | The computer application name. | 
| JAMF.ComputerSubset.software.applications.path | String | The computer application path. | 
| JAMF.ComputerSubset.software.applications.version | String | The computer application version. | 
| JAMF.ComputerSubset.software.applications.bundle_id | String | The computer application bundle ID. | 
| JAMF.ComputerSubset.software.fonts.name | String | The computer font name. | 
| JAMF.ComputerSubset.software.fonts.path | String | The computer font path. | 
| JAMF.ComputerSubset.software.fonts.version | String | The computer font version. | 
| JAMF.ComputerSubset.software.plugins.name | String | The computer plugin name. | 
| JAMF.ComputerSubset.software.plugins.path | String | The computer plugin path. | 
| JAMF.ComputerSubset.software.plugins.version | String | The computer plugin version. | 
| JAMF.ComputerSubset.id | Number | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-extension-attributes-subset
***
Returns the extension attributes subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-extension-attributes-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerSubset.extension_attributes.id | Number | The computer extension attributes ID. | 
| JAMF.ComputerSubset.extension_attributes.name | String | The computer extension attributes name. | 
| JAMF.ComputerSubset.extension_attributes.type | String | The computer extension attributes type. | 
| JAMF.ComputerSubset.extension_attributes.multi_value | Boolean | The computer extension attributes multi value. | 
| JAMF.ComputerSubset.extension_attributes.value | String | The computer extension attributes value. | 
| JAMF.ComputerSubset.id | Number | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-groups-accounts-subset
***
Returns the groups accounts subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-groups-accounts-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerSubset.groups_accounts.computer_group_memberships | String | The computer group memberships. | 
| JAMF.ComputerSubset.groups_accounts.local_accounts.name | String | The computer local account name. | 
| JAMF.ComputerSubset.groups_accounts.local_accounts.realname | String | The computer local account real name. | 
| JAMF.ComputerSubset.groups_accounts.local_accounts.uid | String | The computer local account UID. | 
| JAMF.ComputerSubset.groups_accounts.local_accounts.home | String | The computer local account home. | 
| JAMF.ComputerSubset.groups_accounts.local_accounts.home_size | String | The computer local account name size. | 
| JAMF.ComputerSubset.groups_accounts.local_accounts.home_size_mb | Number | The computer local account size in MB. | 
| JAMF.ComputerSubset.groups_accounts.local_accounts.administrator | Boolean | Whether the computer is the local account administrator. | 
| JAMF.ComputerSubset.groups_accounts.local_accounts.filevault_enabled | Boolean | Whether the computer filevault is enabled. | 
| JAMF.ComputerSubset.groups_accounts.user_inventories.disable_automatic_login | Boolean | Whether automatic login is disabled. | 
| JAMF.ComputerSubset.groups_accounts.user_inventories.user.username | String | The computer user inventories user's username. | 
| JAMF.ComputerSubset.groups_accounts.user_inventories.user.password_history_depth | String | Number of unique passcodes before reuse. | 
| JAMF.ComputerSubset.groups_accounts.user_inventories.user.password_min_length | String | Smallest number of passcode characters allowed. | 
| JAMF.ComputerSubset.groups_accounts.user_inventories.user.password_max_age | String | Number of days until the passcode must be changed. | 
| JAMF.ComputerSubset.groups_accounts.user_inventories.user.password_min_complex_characters | String | Smallest number of non-alphanumeric characters allowed. | 
| JAMF.ComputerSubset.groups_accounts.user_inventories.user.password_require_alphanumeric | String | Passcode rule \(must contain at least one letter and one number\). | 
| JAMF.ComputerSubset.id | Number | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-iphones-subset
***
Returns the iPhones subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-iphones-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerSubset.iphones | String | The commputer related iPhones. | 
| JAMF.ComputerSubset.id | Number | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computer-configuration-profiles-subset
***
Returns the configuration profiles subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-configuration-profiles-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerSubset.configuration_profiles.id | Number | The configuration profile ID. | 
| JAMF.ComputerSubset.configuration_profiles.name | String | The configuration profile name. | 
| JAMF.ComputerSubset.configuration_profiles.uuid | String | The configuration profile UUID. | 
| JAMF.ComputerSubset.configuration_profiles.is_removable | Boolean | If the configuration profile is removable. | 
| JAMF.ComputerSubset.id | Number | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-computer-lock
***
Sends the "DeviceLock" command to a computer. This command logs the user out of the computer, restarts the computer, and then locks the computer. Optional: Displays a message on the computer when it locks.


#### Base Command

`jamf-computer-lock`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| passcode | A 6-digit passcode to be used to unlock the computer after it was locked. | Required | 
| id | The ID of the computer that you want to lock. | Required | 
| lock_message | A message to display on the locked screen. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerCommand.name | String | The command name. | 
| JAMF.ComputerCommand.command_uuid | String | The command UDID. | 
| JAMF.ComputerCommand.computer_id | String | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-computer-erase
***
Sends the “EraseDevice'' command to a computer. Permanently erases all the data on the computer and sets a passcode when required by the computer hardware type.


#### Base Command

`jamf-computer-erase`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| passcode | A 6-digit passcode that locks the computer after being erased. | Required | 
| id | The ID of the computer that you want to erase. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputerCommand.name | String | The command name. | 
| JAMF.ComputerCommand.command_uuid | String | The command UDID. | 
| JAMF.ComputerCommand.computer_id | String | The computer ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-users
***
Returns a list of users with their IDs and names. By default, returns the first 50 users to the context (ID + name).


#### Base Command

`jamf-get-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of users to retrieve. The maximal value is 200. Default is 50. | Optional | 
| page | The number of the requested page. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.User.id | Number | The user ID. | 
| JAMF.User.name | String | The user name. | 
| JAMF.User.Paging.total_results | Number | The number of users returned in this specific search. | 
| JAMF.User.Paging.page_size | Number | The number of users to be returned on each page. | 
| JAMF.User.Paging.current_page | Number | The number of requested page. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-user-by-id
***
Returns a specific user with general data about the user according to the given ID.


#### Base Command

`jamf-get-user-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user ID.<br/>To get the user ID, run the `jamf-get-users` command to get all user names and IDs. | Required | 


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
| JAMF.User.managed_apple_id | String | The user managed Apple ID. | 
| JAMF.User.enable_custom_photo_url | Boolean | Whether the user custom photo URL is enabled. | 
| JAMF.User.custom_photo_url | String | The user custom photo URL. | 
| JAMF.User.ldap_server.id | Number | The user LDAP server ID. | 
| JAMF.User.ldap_server.name | String | The user LDAP server name. | 
| JAMF.User.extension_attributes.id | Number | The user extension attributes ID. | 
| JAMF.User.extension_attributes.name | String | The user extension attributes name. | 
| JAMF.User.extension_attributes.type | String | The user extension attributes type. | 
| JAMF.User.extension_attributes.value | String | The user extension attributes value. | 
| JAMF.User.sites.id | Number | The user's site ID. | 
| JAMF.User.sites.name | String | The user's site name. | 
| JAMF.User.links.total_vpp_code_count | Number | The user total VPP code acount. | 
| JAMF.User.links.vpp_assignments.id | Number | The VPP assignment ID that is linked to the user. | 
| JAMF.User.links.vpp_assignments.name | String | The VPP assignment name that is linked to the user. | 
| JAMF.User.links.computers.id | Number | The computer ID that is linked to the user. | 
| JAMF.User.links.computers.name | String | The computer name that is linked to the user. | 
| JAMF.User.links.peripherals.id | Number | The peripherals ID that is linked to the user. | 
| JAMF.User.links.peripherals.name | String | The peripherals name that is linked to the user. | 
| JAMF.User.links.mobile_devices.id | String | The mobile device ID that is linked to the user. | 
| JAMF.User.links.mobile_devices.name | String | The mobile device name that is linked to the user. | 
| JAMF.User.user_groups.size | Number | The user group size. | 
| JAMF.User.user_groups.user_group.id | Number | The user group ID. | 
| JAMF.User.user_groups.user_group.name | String | The user group name. | 
| JAMF.User.user_groups.user_group.is_smart | Boolean | Whether the user group is smart. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-user-by-name
***
Returns a specific user with general data about the user according to the given name.


#### Base Command

`jamf-get-user-by-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The user name. | Required | 


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
| JAMF.User.managed_apple_id | String | The user managed Apple ID. | 
| JAMF.User.enable_custom_photo_url | Boolean | Whether the user custom photo URL is enabled. | 
| JAMF.User.custom_photo_url | String | The user custom photo URL. | 
| JAMF.User.ldap_server.id | Number | The user LDAP server ID. | 
| JAMF.User.ldap_server.name | String | The user LDAP server name. | 
| JAMF.User.extension_attributes.id | Number | The user extension attributes ID. | 
| JAMF.User.extension_attributes.name | String | The user extension attributes name. | 
| JAMF.User.extension_attributes.type | String | The user extension attributes type. | 
| JAMF.User.extension_attributes.value | String | The user extension attributes value. | 
| JAMF.User.sites.site.id | Number | The user's site ID. | 
| JAMF.User.sites.site.name | String | The user's site name. | 
| JAMF.User.links.total_vpp_code_count | Number | The user total VPP code acount. | 
| JAMF.User.links.vpp_assignments.id | Number | The VPP assignment ID that is linked to the user. | 
| JAMF.User.links.vpp_assignments.name | String | The VPP assignment name that is linked to the user. | 
| JAMF.User.links.computers.id | Number | The computer ID that is linked to the user. | 
| JAMF.User.links.computers.name | String | The computer name that is linked to the user. | 
| JAMF.User.links.peripherals.id | Number | The peripherals ID that is linked to the user. | 
| JAMF.User.links.peripherals.name | String | The peripherals name that is linked to the user. | 
| JAMF.User.links.mobile_devices.id | String | The mobile device ID that is linked to the user. | 
| JAMF.User.links.mobile_devices.name | String | The mobile device name that is linked to the user. | 
| JAMF.User.user_groups.size | Number | The user groups size. | 
| JAMF.User.user_groups.user_group.id | Number | The user group ID. | 
| JAMF.User.user_groups.user_group.name | String | The user group name. | 
| JAMF.User.user_groups.user_group.is_smart | Boolean | Whether the user group is smart. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-user-by-email
***
Returns a specific user with general data about the user according to the given email.


#### Base Command

`jamf-get-user-by-email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The user email. | Required | 


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
| JAMF.User.managed_apple_id | String | The user managed Apple ID. | 
| JAMF.User.enable_custom_photo_url | Boolean | Whether the user custom photo URL is enabled. | 
| JAMF.User.custom_photo_url | String | The user custom photo URL. | 
| JAMF.User.ldap_server.id | Number | The user LDAP server ID. | 
| JAMF.User.ldap_server.name | String | The user LDAP server name. | 
| JAMF.User.extension_attributes.id | Number | The user extension attributes ID. | 
| JAMF.User.extension_attributes.name | String | The user extension attributes name. | 
| JAMF.User.extension_attributes.type | String | The user extension attributes type. | 
| JAMF.User.extension_attributes.value | String | The user extension attributes value. | 
| JAMF.User.sites.site.id | Number | The user's site ID. | 
| JAMF.User.sites.site.name | String | The user's site name. | 
| JAMF.User.links.total_vpp_code_count | Number | The user total VPP code acount. | 
| JAMF.User.links.vpp_assignments.id | Number | The VPP assignment ID that is linked to the user. | 
| JAMF.User.links.vpp_assignments.name | String | The VPP assignment name that is linked to the user. | 
| JAMF.User.links.computers.id | Number | The computer ID that is linked to the user. | 
| JAMF.User.links.computers.name | String | The computer name that is linked to the user. | 
| JAMF.User.links.peripherals.id | Number | The peripherals ID that is linked to the user. | 
| JAMF.User.links.peripherals.name | String | The peripherals name that is linked to the user. | 
| JAMF.User.links.mobile_devices.id | String | The mobile device ID that is linked to the user. | 
| JAMF.User.links.mobile_devices.name | String | The mobile device name that is linked to the user. | 
| JAMF.User.user_groups.size | Number | The user groups size. | 
| JAMF.User.user_groups.user_group.id | Number | The user group ID. | 
| JAMF.User.user_groups.user_group.name | String | The user group name. | 
| JAMF.User.user_groups.user_group.is_smart | Boolean | If the user group is smart. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-devices
***
Returns a list of devices with  basic data on each. By default, returns the first 50 devices to the context (ID + name).


#### Base Command

`jamf-get-mobile-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of devices to retrieve. Maximal value is 200. Default is 50. | Optional | 
| page | Number of requested page. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDevice.id | Number | The mobile device ID. | 
| JAMF.MobileDevice.name | String | The mobile device name. | 
| JAMF.MobileDevice.device_name | String | The mobile device name. | 
| JAMF.MobileDevice.udid | String | The mobile device UDID. | 
| JAMF.MobileDevice.serial_number | String | The mobile device serial number. | 
| JAMF.MobileDevice.phone_number | String | The mobile device phone number. | 
| JAMF.MobileDevice.wifi_mac_address | String | The mobile device WIFI MAC address. | 
| JAMF.MobileDevice.managed | Boolean | Whether the mobile device is managed. | 
| JAMF.MobileDevice.supervised | Boolean | Whether the mobile device is supervised. | 
| JAMF.MobileDevice.model | String | The mobile device model. | 
| JAMF.MobileDevice.model_identifier | String | The mobile device model ID. | 
| JAMF.MobileDevice.modelDisplay | String | The mobile device model display. | 
| JAMF.MobileDevice.model_display | String | The mobile device model display. | 
| JAMF.MobileDevice.username | String | The mobile device username. | 
| JAMF.MobileDevice.Paging.total_results | Number | The number of mobile devices returned in this specific search. | 
| JAMF.MobileDevice.Paging.page_size | Number | The number of mobile devices to be returned on each page. | 
| JAMF.MobileDevice.Paging.current_page | Number | The number of the requested page. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-by-id
***
Returns the "general" subset of a specific mobile device, e.g.: name, MAC address, IP, serial number, UDID. etc.


#### Base Command

`jamf-get-mobile-device-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Gets the “general” subset of a specific device.<br/>To get the mobile device ID, run the `jamf-get-mobile-devices` command to get all mobile devices names and IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDevice.id | Number | The mobile device ID. | 
| JAMF.MobileDevice.display_name | String | The mobile device display name. | 
| JAMF.MobileDevice.device_name | String | The mobile device name. | 
| JAMF.MobileDevice.name | String | The mobile device name. | 
| JAMF.MobileDevice.asset_tag | String | The mobile device asset ID. | 
| JAMF.MobileDevice.last_inventory_update | String | The date of the mobile device last inventory update. | 
| JAMF.MobileDevice.last_inventory_update_epoch | Date | The date of the mobile device last inventory update in epoch format. | 
| JAMF.MobileDevice.last_inventory_update_utc | Date | The date of the mobile device last inventory update in UTC format. | 
| JAMF.MobileDevice.capacity | Number | The mobile device capacity. | 
| JAMF.MobileDevice.capacity_mb | Number | The mobile device capacity in MB. | 
| JAMF.MobileDevice.available | Number | The mobile device available storage. | 
| JAMF.MobileDevice.available_mb | Number | The mobile device available storage in MB. | 
| JAMF.MobileDevice.percentage_used | Number | The percentage of memory used. | 
| JAMF.MobileDevice.os_type | String | The mobile device operating system type. | 
| JAMF.MobileDevice.os_version | String | The mobile device operating system version. | 
| JAMF.MobileDevice.os_build | String | The mobile device operating system build. | 
| JAMF.MobileDevice.serial_number | String | The mobile device serial number. | 
| JAMF.MobileDevice.udid | String | The mobile device UDID. | 
| JAMF.MobileDevice.initial_entry_date_epoch | Date | The mobile device initial entry date in epoch format. | 
| JAMF.MobileDevice.initial_entry_date_utc | Date | The mobile device initial entry date in UTC format. | 
| JAMF.MobileDevice.phone_number | String | The mobile device phone number. | 
| JAMF.MobileDevice.ip_address | String | The mobile device IP address. | 
| JAMF.MobileDevice.wifi_mac_address | String | The mobile device WIFI MAC address. | 
| JAMF.MobileDevice.bluetooth_mac_address | String | The mobile device bluetooth MAC address. | 
| JAMF.MobileDevice.modem_firmware | String | The mobile device modem fireware. | 
| JAMF.MobileDevice.model | String | The mobile device model. | 
| JAMF.MobileDevice.model_identifier | String | The mobile device model ID. | 
| JAMF.MobileDevice.model_number | String | The mobile device model number. | 
| JAMF.MobileDevice.modelDisplay | String | The mobile device model display. | 
| JAMF.MobileDevice.model_display | String | The mobile device model display. | 
| JAMF.MobileDevice.device_ownership_level | String | The mobile device ownership level. | 
| JAMF.MobileDevice.enrollment_method | String | The mobile device enrollment method. | 
| JAMF.MobileDevice.last_enrollment_epoch | Number | The mobile device last enrollment in epoch. | 
| JAMF.MobileDevice.last_enrollment_utc | String | The mobile device last enrollment in UTC format. | 
| JAMF.MobileDevice.mdm_profile_expiration_epoch | Number | The mobile device MDM profile expiration in epoch format. | 
| JAMF.MobileDevice.mdm_profile_expiration_utc | String | The mobile device MDM profile expiration in UTC format. | 
| JAMF.MobileDevice.managed | Boolean | Whether the mobile device is managed. | 
| JAMF.MobileDevice.supervised | Boolean | Whether the mobile device is supervised. | 
| JAMF.MobileDevice.exchange_activesync_device_identifier | String | The mobile device exchange active sync device ID. | 
| JAMF.MobileDevice.shared | String | Whether the device is shared. | 
| JAMF.MobileDevice.diagnostic_submission | String | The mobile device diagnostic submission. | 
| JAMF.MobileDevice.app_analytics | String | The mobile device app analytics. | 
| JAMF.MobileDevice.tethered | String | The mobile device tethered status. | 
| JAMF.MobileDevice.battery_level | Number | The mobile device battery level. | 
| JAMF.MobileDevice.ble_capable | Boolean | Whether the mobile device is BLE capable. | 
| JAMF.MobileDevice.device_locator_service_enabled | Boolean | Whether the mobile device locator service is enabled. | 
| JAMF.MobileDevice.do_not_disturb_enabled | Boolean | Whether the mobile device do not disturb is enabled. | 
| JAMF.MobileDevice.cloud_backup_enabled | Boolean | Whether the mobile device cloud backup is enabled. | 
| JAMF.MobileDevice.last_cloud_backup_date_epoch | Date | The mobile device last cloud update backup date in epoch format. | 
| JAMF.MobileDevice.last_cloud_backup_date_utc | Date | The mobile device last cloud update backup date in UTC format. | 
| JAMF.MobileDevice.location_services_enabled | Boolean | Whether the mobile device location services is enabled. | 
| JAMF.MobileDevice.itunes_store_account_is_active | Boolean | Whether the mobile device iTunes store account is enabled. | 
| JAMF.MobileDevice.last_backup_time_epoch | Number | The mobile device last backup time in epoch format. | 
| JAMF.MobileDevice.last_backup_time_utc | String | The mobile device last backup time in UTC format. | 
| JAMF.MobileDevice.site.id | Number | The mobile device site ID. | 
| JAMF.MobileDevice.site.name | String | The mobile device site name. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-by-match
***
Matches mobile devices by specific characteristics and returns general data on each one of the mobile devices.


#### Base Command

`jamf-get-mobile-device-by-match`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| match | The specific characteristics by which to match devices such as: name, udid, serial_number, mac_address, username, email. e.g: “match=john*”, “match=C52F72FACB9T”. (Supports wildcards). Possible values are: . | Required | 
| limit | Maximum number of devices to retrieve. (Maximal value is 200). Default is 50. | Optional | 
| page | The number of the requested page. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDevice.id | Number | The mobile device ID. | 
| JAMF.MobileDevice.name | String | The mobile device name. | 
| JAMF.MobileDevice.udid | String | The mobile device UDID. | 
| JAMF.MobileDevice.serial_number | String | The mobile device serial number. | 
| JAMF.MobileDevice.mac_address | String | The mobile device MAC address. | 
| JAMF.MobileDevice.wifi_mac_address | String | The mobile device WIFI MAC address. | 
| JAMF.MobileDevice.username | String | The mobile device username. | 
| JAMF.MobileDevice.realname | String | The mobile device real name. | 
| JAMF.MobileDevice.email | String | The mobile device user email address. | 
| JAMF.MobileDevice.email_address | String | The mobile device user email address. | 
| JAMF.MobileDevice.room | String | The mobile device room. | 
| JAMF.MobileDevice.position | String | The mobile device position. | 
| JAMF.MobileDevice.building | String | The mobile device building. | 
| JAMF.MobileDevice.building_name | String | The mobile device building name. | 
| JAMF.MobileDevice.department | String | The mobile device department. | 
| JAMF.MobileDevice.department_name | String | The mobile device department name. | 
| JAMF.MobileDevice.Paging.total_results | Number | The number of mobile devices returned in this specific search. | 
| JAMF.MobileDevice.Paging.page_size | Number | The number of mobile devices to be returned on each page. | 
| JAMF.MobileDevice.Paging.current_page | Number | The number of the requested page. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-general-subset
***
Returns the general subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-general-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceSubset.id | String | The mobile device ID. | 
| JAMF.MobileDeviceSubset.general.id | Number | The mobile device ID. | 
| JAMF.MobileDeviceSubset.general.display_name | String | The mobile device display name. | 
| JAMF.MobileDeviceSubset.general.device_name | String | The mobile device name. | 
| JAMF.MobileDeviceSubset.general.name | String | The mobile device name. | 
| JAMF.MobileDeviceSubset.general.asset_tag | String | The mobile device asset ID. | 
| JAMF.MobileDeviceSubset.general.last_inventory_update | String | The date of the mobile device last inventory update. | 
| JAMF.MobileDeviceSubset.general.last_inventory_update_epoch | Date | The date of the mobile device last inventory update in epoch format. | 
| JAMF.MobileDeviceSubset.general.last_inventory_update_utc | Date | The date of the mobile device last inventory update in UTC format. | 
| JAMF.MobileDeviceSubset.general.capacity | Number | The mobile device capacity. | 
| JAMF.MobileDeviceSubset.general.capacity_mb | Number | The mobile device capacity in MB. | 
| JAMF.MobileDeviceSubset.general.available | Number | The available memory in the mobile device. | 
| JAMF.MobileDeviceSubset.general.available_mb | Number | The available memory in the mobile device in MB. | 
| JAMF.MobileDeviceSubset.general.percentage_used | Number | The percentage of memory used in the mobile device. | 
| JAMF.MobileDeviceSubset.general.os_type | String | The mobile device operating system type. | 
| JAMF.MobileDeviceSubset.general.os_version | String | The mobile device operating system version. | 
| JAMF.MobileDeviceSubset.general.os_build | String | The mobile device operating system build. | 
| JAMF.MobileDeviceSubset.general.serial_number | String | The mobile device serial number. | 
| JAMF.MobileDeviceSubset.general.udid | String | The mobile device UDID. | 
| JAMF.MobileDeviceSubset.general.initial_entry_date_epoch | Date | The mobile device initial entry date in epoch format. | 
| JAMF.MobileDeviceSubset.general.initial_entry_date_utc | Date | The mobile device initial entry date in UTC format. | 
| JAMF.MobileDeviceSubset.general.phone_number | String | The mobile device phone number. | 
| JAMF.MobileDeviceSubset.general.ip_address | String | The mobile device IP address. | 
| JAMF.MobileDeviceSubset.general.wifi_mac_address | String | The mobile device WIFI MAC address. | 
| JAMF.MobileDeviceSubset.general.bluetooth_mac_address | String | The mobile device bluetooth MAC address. | 
| JAMF.MobileDeviceSubset.general.modem_firmware | String | The mobile device modem fireware. | 
| JAMF.MobileDeviceSubset.general.model | String | The mobile device model. | 
| JAMF.MobileDeviceSubset.general.model_identifier | String | The mobile device model ID. | 
| JAMF.MobileDeviceSubset.general.model_number | String | The mobile device model number. | 
| JAMF.MobileDeviceSubset.general.modelDisplay | String | The mobile device model display. | 
| JAMF.MobileDeviceSubset.general.model_display | String | The mobile device model display. | 
| JAMF.MobileDeviceSubset.general.device_ownership_level | String | The mobile device ownership level. | 
| JAMF.MobileDeviceSubset.general.enrollment_method | String | The mobile device enrollment method. | 
| JAMF.MobileDeviceSubset.general.last_enrollment_epoch | Number | The mobile device last enrollment in epoch format. | 
| JAMF.MobileDeviceSubset.general.last_enrollment_utc | String | The mobile device last enrollment in UTC format. | 
| JAMF.MobileDeviceSubset.general.mdm_profile_expiration_epoch | Number | The mobile device MDM profile expiration in epoch format. | 
| JAMF.MobileDeviceSubset.general.mdm_profile_expiration_utc | String | The mobile device MDM profile expiration in UTC format. | 
| JAMF.MobileDeviceSubset.general.managed | Boolean | Whether the mobile device is managed. | 
| JAMF.MobileDeviceSubset.general.supervised | Boolean | Whether the mobile device is supervised. | 
| JAMF.MobileDeviceSubset.general.exchange_activesync_device_identifier | String | The mobile device exchange active sync device ID. | 
| JAMF.MobileDeviceSubset.general.shared | String | Whether the device is shared. | 
| JAMF.MobileDeviceSubset.general.diagnostic_submission | String | The mobile device diagnostic submission. | 
| JAMF.MobileDeviceSubset.general.app_analytics | String | The mobile device app analytics. | 
| JAMF.MobileDeviceSubset.general.tethered | String | The mobile device tethered status. | 
| JAMF.MobileDeviceSubset.general.battery_level | Number | The mobile device battery level. | 
| JAMF.MobileDeviceSubset.general.ble_capable | Boolean | Whether the mobile device is BLE capable. | 
| JAMF.MobileDeviceSubset.general.device_locator_service_enabled | Boolean | Whether the mobile device locator service is enabled. | 
| JAMF.MobileDeviceSubset.general.do_not_disturb_enabled | Boolean | Whether the mobile device do not disturb is enabled. | 
| JAMF.MobileDeviceSubset.general.cloud_backup_enabled | Boolean | Whether the mobile device cloud backup is enabled. | 
| JAMF.MobileDeviceSubset.general.last_cloud_backup_date_epoch | Date | The mobie device last cloud update backup date in epoch format. | 
| JAMF.MobileDeviceSubset.general.last_cloud_backup_date_utc | Date | The mobie device last cloud update backup date in UTC format. | 
| JAMF.MobileDeviceSubset.general.location_services_enabled | Boolean | Whether the mobile device location services is enabled. | 
| JAMF.MobileDeviceSubset.general.itunes_store_account_is_active | Boolean | Whether the mobile device iTunes store account is enabled. | 
| JAMF.MobileDeviceSubset.general.last_backup_time_epoch | Number | The mobile device last backup time in epoch format. | 
| JAMF.MobileDeviceSubset.general.last_backup_time_utc | String | The mobile device last backup time in UTC format. | 
| JAMF.MobileDeviceSubset.general.site.id | Number | The mobile device site ID. | 
| JAMF.MobileDeviceSubset.general.site.name | String | The mobile device site name. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-location-subset
***
Returns the location subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-location-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceSubset.id | String | The mobile device ID. | 
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


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-purchasing-subset
***
Returns the purchasing subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-purchasing-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceSubset.id | String | The mobile device ID. | 
| JAMF.MobileDeviceSubset.purchasing.is_purchased | Boolean | Whether the mobile device is purchased. | 
| JAMF.MobileDeviceSubset.purchasing.is_leased | Boolean | Whether the mobile device is leased. | 
| JAMF.MobileDeviceSubset.purchasing.po_number | String | The mobile device PO number. | 
| JAMF.MobileDeviceSubset.purchasing.vendor | String | The mobile device vendor. | 
| JAMF.MobileDeviceSubset.purchasing.applecare_id | String | The mobile device AppleCare ID. | 
| JAMF.MobileDeviceSubset.purchasing.purchase_price | String | The mobile device purchase price. | 
| JAMF.MobileDeviceSubset.purchasing.purchasing_account | String | The mobile device purchase account. | 
| JAMF.MobileDeviceSubset.purchasing.po_date | String | The mobile device purchase PO date. | 
| JAMF.MobileDeviceSubset.purchasing.po_date_epoch | Number | The mobile device purchase PO date in epoch format. | 
| JAMF.MobileDeviceSubset.purchasing.po_date_utc | String | The mobile device purchase PO date in UTC format. | 
| JAMF.MobileDeviceSubset.purchasing.warranty_expires | String | The mobile device warranty expiration date. | 
| JAMF.MobileDeviceSubset.purchasing.warranty_expires_epoch | Number | The mobile device warranty expiration date in epoch format. | 
| JAMF.MobileDeviceSubset.purchasing.warranty_expires_utc | String | The mobile device warranty expiration date in UTC format. | 
| JAMF.MobileDeviceSubset.purchasing.lease_expires | String | The mobile device lease expiration date. | 
| JAMF.MobileDeviceSubset.purchasing.lease_expires_epoch | Number | The mobile device lease expiration date in epoch format. | 
| JAMF.MobileDeviceSubset.purchasing.lease_expires_utc | String | The mobile device lease expiration date in UTC format. | 
| JAMF.MobileDeviceSubset.purchasing.life_expectancy | Number | The mobile device life expectancy. | 
| JAMF.MobileDeviceSubset.purchasing.purchasing_contact | String | The mobile device purchasing contact. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-applications-subset
***
Returns the applications subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-applications-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceSubset.id | String | The mobile device ID. | 
| JAMF.MobileDeviceSubset.applications.application_name | String | The mobile device application name. | 
| JAMF.MobileDeviceSubset.applications.application_version | String | The mobile device application version. | 
| JAMF.MobileDeviceSubset.applications.application_short_version | String | The mobile device application short version. | 
| JAMF.MobileDeviceSubset.applications.identifier | String | The mobile device application ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-security-subset
***
Returns the security subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-security-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceSubset.id | String | The mobile device ID. | 
| JAMF.MobileDeviceSubset.security.data_protection | Boolean | If the mobile device has data protection. | 
| JAMF.MobileDeviceSubset.security.block_level_encryption_capable | Boolean | If the mobile device is block level encryption capable. | 
| JAMF.MobileDeviceSubset.security.file_level_encryption_capable | Boolean | If the mobile device is file level encryption capable. | 
| JAMF.MobileDeviceSubset.security.passcode_present | Boolean | Whether the mobile device has a passcode present. | 
| JAMF.MobileDeviceSubset.security.passcode_compliant | Boolean | Whether the mobile device is passcode compliant. | 
| JAMF.MobileDeviceSubset.security.passcode_compliant_with_profile | Boolean | Whether the mobile device is passcode compliant with profile. | 
| JAMF.MobileDeviceSubset.security.passcode_lock_grace_period_enforced | String | The mobile device passcode lock grace period enforced. | 
| JAMF.MobileDeviceSubset.security.hardware_encryption | Number | The mobile device hardware encryption. | 
| JAMF.MobileDeviceSubset.security.activation_lock_enabled | Boolean | Whether the mobile device has activation lock enabled. | 
| JAMF.MobileDeviceSubset.security.jailbreak_detected | String | The mobile device security jailbreak detected. | 
| JAMF.MobileDeviceSubset.security.lost_mode_enabled | String | The mobile device lost mode. | 
| JAMF.MobileDeviceSubset.security.lost_mode_enforced | Boolean | Whether the mobile device has lost mode enforced. | 
| JAMF.MobileDeviceSubset.security.lost_mode_enable_issued_epoch | Date | The mobile device lost mode enable issued date in epoch. | 
| JAMF.MobileDeviceSubset.security.lost_mode_enable_issued_utc | Date | The mobile device lost mode enable issued date in UTC format. | 
| JAMF.MobileDeviceSubset.security.lost_mode_message | String | The mobile device lost mode message. | 
| JAMF.MobileDeviceSubset.security.lost_mode_phone | String | The mobile device lost mode phone. | 
| JAMF.MobileDeviceSubset.security.lost_mode_footnote | String | The mobile device lost mode footnote. | 
| JAMF.MobileDeviceSubset.security.lost_location_epoch | Date | The mobile device lost location date in epoch format. | 
| JAMF.MobileDeviceSubset.security.lost_location_utc | Date | The mobile device lost location date in UTC format. | 
| JAMF.MobileDeviceSubset.security.lost_location_latitude | Number | The mobile device security lost location latitude. | 
| JAMF.MobileDeviceSubset.security.lost_location_longitude | Number | The mobile device security lost location longitude. | 
| JAMF.MobileDeviceSubset.security.lost_location_altitude | Number | The mobile device security lost location altitude. | 
| JAMF.MobileDeviceSubset.security.lost_location_speed | Number | The mobile device security lost location speed. | 
| JAMF.MobileDeviceSubset.security.lost_location_course | Number | The mobile device security lost location course. | 
| JAMF.MobileDeviceSubset.security.lost_location_horizontal_accuracy | Number | The mobile device security lost location horizontal accuracy. | 
| JAMF.MobileDeviceSubset.security.lost_location_vertical_accuracy | Number | The mobile device security lost location vertical accuracy. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-network-subset
***
Returns the network subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-network-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceSubset.id | String | The mobile device ID. | 
| JAMF.MobileDeviceSubset.network.home_carrier_network | String | The mobile device home carrier network. | 
| JAMF.MobileDeviceSubset.network.cellular_technology | String | The mobile device cellular technology. | 
| JAMF.MobileDeviceSubset.network.voice_roaming_enabled | String | The mobile device voice roaming enabled. | 
| JAMF.MobileDeviceSubset.network.imei | String | The mobile device network IMEI. | 
| JAMF.MobileDeviceSubset.network.iccid | String | The mobile device network ICCID. | 
| JAMF.MobileDeviceSubset.network.meid | String | The mobile device network MEID. | 
| JAMF.MobileDeviceSubset.network.current_carrier_network | String | The mobile device current carrier network. | 
| JAMF.MobileDeviceSubset.network.carrier_settings_version | String | The mobile device network carrier settings version. | 
| JAMF.MobileDeviceSubset.network.current_mobile_country_code | String | The mobile device current mobile country code. | 
| JAMF.MobileDeviceSubset.network.current_mobile_network_code | String | The mobile device current mobile network code. | 
| JAMF.MobileDeviceSubset.network.home_mobile_country_code | String | The mobile device home mobile country code. | 
| JAMF.MobileDeviceSubset.network.home_mobile_network_code | String | The mobile device home mobile network code. | 
| JAMF.MobileDeviceSubset.network.data_roaming_enabled | Boolean | Whether the mobile device has data roaming enabled. | 
| JAMF.MobileDeviceSubset.network.roaming | Boolean | Whether the mobile device has network roaming. | 
| JAMF.MobileDeviceSubset.network.phone_number | String | The mobile device network phone number. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-certificates-subset
***
Returns the certificates subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-certificates-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceSubset.id | String | The mobile device ID. | 
| JAMF.MobileDeviceSubset.certificates.size | String | The mobile device certificates size. | 
| JAMF.MobileDeviceSubset.certificates.certificate.common_name | String | The mobile device certificate common name. | 
| JAMF.MobileDeviceSubset.certificates.certificate.identity | Boolean | Whether this is an identity certificate. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-provisioning-profiles-subset
***
Returns the provisioning profiles subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-provisioning-profiles-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceSubset.id | String | The mobile device ID. | 
| JAMF.MobileDeviceSubset.provisioning_profiles.size | Number | The mobile device provisioning profiles size. | 
| JAMF.MobileDeviceSubset.provisioning_profiles.mobile_device_provisioning_profile.display_name | String | The mobile device provisioning profiles display name. | 
| JAMF.MobileDeviceSubset.provisioning_profiles.mobile_device_provisioning_profile.expiration_date | String | The mobile device provisioning profiles expiration date. | 
| JAMF.MobileDeviceSubset.provisioning_profiles.mobile_device_provisioning_profile.expiration_date_epoch | Number | The mobile device provisioning profiles expiration date in epoch format. | 
| JAMF.MobileDeviceSubset.provisioning_profiles.mobile_device_provisioning_profile.expiration_date_utc | String | The mobile device provisioning profiles expiration date in UTC format. | 
| JAMF.MobileDeviceSubset.provisioning_profiles.mobile_device_provisioning_profile.uuid | String | The mobile device provisioning profiles UUID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-configuration-profiles-subset
***
Returns the configuration profiles subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-configuration-profiles-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceSubset.id | String | The mobile device ID. | 
| JAMF.MobileDeviceSubset.configuration_profiles.size | Number | The mobile device configuration profiles size. | 
| JAMF.MobileDeviceSubset.configuration_profiles.configuration_profile.display_name | String | The mobile device configuration profiles display name. | 
| JAMF.MobileDeviceSubset.configuration_profiles.configuration_profile.version | String | The mobile device configuration profiles version. | 
| JAMF.MobileDeviceSubset.configuration_profiles.configuration_profile.identifier | Number | The mobile device configuration profiles identifier. | 
| JAMF.MobileDeviceSubset.configuration_profiles.configuration_profile.uuid | String | The mobile device configuration profiles UUID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-groups-subset
***
Returns the mobile device groups subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-groups-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceSubset.id | String | The mobile device ID. | 
| JAMF.MobileDeviceSubset.mobile_device_groups.id | Number | The mobile device group ID. | 
| JAMF.MobileDeviceSubset.mobile_device_groups.name | String | The mobile device group name. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-mobile-device-extension-attributes-subset
***
Returns the extension attributes subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-extension-attributes-subset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The identifier used to determine which computer is requested. Possible values: "id", "name", "udid", "serialnumber", and "macaddress". Possible values are: id, name, udid, serialnumber, macaddress. | Required | 
| identifier_value | The value of the "identifier". For example, if you choose the "id" identifier, a computer ID should be passed. If you choose "macaddress" as the identifier, a computer’s MAC address should be passed, etc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceSubset.id | String | The mobile device ID. | 
| JAMF.MobileDeviceSubset.extension_attributes.id | Number | The mobile device extension attribute ID. | 
| JAMF.MobileDeviceSubset.extension_attributes.name | String | The mobile device extension attribute name. | 
| JAMF.MobileDeviceSubset.extension_attributes.type | String | The mobile device extension attribute type. | 
| JAMF.MobileDeviceSubset.extension_attributes.multi_value | Boolean | The mobile device extension attribute multi value. | 
| JAMF.MobileDeviceSubset.extension_attributes.value | String | The mobile device extension attribute value. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-get-computers-by-application
***
Returns a list of computers with basic information on each.


#### Base Command

`jamf-get-computers-by-application`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application | The application’s name (supports wildcards). | Required | 
| version | The application’s version (supports wildcards). Applicable only when “application” parameter value is set. | Optional | 
| limit | Maximum number of devices to retrieve. (Maximal value is 200). Default is 50. | Optional | 
| page | The number of the requested page. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.ComputersByApp.Computer.id | Number | The computer ID. | 
| JAMF.ComputersByApp.Computer.name | String | The computer name. | 
| JAMF.ComputersByApp.Computer.udid | String | The computer UDID. | 
| JAMF.ComputersByApp.Computer.serial_number | String | The computer serial number. | 
| JAMF.ComputersByApp.Computer.mac_address | String | The computer MAC address. | 
| JAMF.ComputersByApp.Application | String | The application the user serched for. | 
| JAMF.ComputersByApp.Paging.total_results | Number | The number of computers returned in this specific search. | 
| JAMF.ComputersByApp.Paging.page_size | Number | The number of computers to be returned on each page. | 
| JAMF.ComputersByApp.Paging.current_page | Number | The number of the requested page. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-mobile-device-lost-mode
***
This is a beta command - couldn't be tested due to technical limitations.
Enables “lost mode” on a specific device. Lost Mode is a feature that allows you to lock a mobile device and track the device's location. The device reports the GPS coordinates of the point where the device received the command. This feature adds additional protection to mobile devices and their data in the event that a device is lost or stolen.


#### Base Command

`jamf-mobile-device-lost-mode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The mobile device’s ID. | Required | 
| lost_mode_message | A message that is displayed on the device’s lock screen. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceCommands.name | String | The mobile device command name. | 
| JAMF.MobileDeviceCommands.status | String | The mobile device command status. | 
| JAMF.MobileDeviceCommands.management_id | String | The mobile device command management ID. | 
| JAMF.MobileDeviceCommands.id | String | The mobile device command ID. | 


#### Command Example
``` ```

#### Human Readable Output



### jamf-mobile-device-erase
***
This is a beta command - couldn't be tested due to technical limitations.
Permanently erases all data on the device and deactivates the device.


#### Base Command

`jamf-mobile-device-erase`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The device’s ID. | Required | 
| preserve_data_plan | Whether to retain cellular data plans (iOS 11 or later). Possible values are: True, False. Default is False. | Optional | 
| clear_activation_code | Whether to clear activation lock on the device. Possible values are: True, False. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.MobileDeviceCommands.name | String | The mobile device command name. | 
| JAMF.MobileDeviceCommands.status | String | The mobile device command status. | 
| JAMF.MobileDeviceCommands.management_id | String | The mobile device command managment ID. | 
| JAMF.MobileDeviceCommands.id | String | The mobile device command ID. | 


#### Command Example
``` ```

#### Human Readable Output



### endpoint
***
Returns information about an endpoint.


#### Base Command

`endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The endpoint ID. | Optional | 
| ip | The endpoint IP address. | Optional | 
| hostname | The endpoint hostname. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The endpoint's hostname. | 
| Endpoint.OS | String | The endpoint's operating system. | 
| Endpoint.IPAddress | String | The endpoint's IP address. | 
| Endpoint.ID | String | The endpoint's ID. | 
| Endpoint.Status | String | The endpoint's status. | 
| Endpoint.IsIsolated | String | The endpoint's isolation status. | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 


#### Command Example
``` ```

#### Human Readable Output


