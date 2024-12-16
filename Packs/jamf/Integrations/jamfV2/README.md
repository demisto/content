Enterprise Mobility Management (EMM) for Apple devices (Mac, iPhone, Apple TV, iPad). Can be used to control various configurations via different policies, install and uninstall applications, lock devices, smart groups searches, and more.
This integration was integrated and tested with version 10.28.0 of jamf v2
JAMF classic API: https://www.jamf.com/developers/apis/classic/reference/#/

## Configure jamf v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for JAMF v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Username | False |
    | Password | False |
    | Client ID | False |
    | Client Secret | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.


### Required Permissions
In order to run JAMF V2 commands, the user should have a set of minimum permissions on the Jamf Pro server. Changing permissions on Jamf Pro server can be done using the following steps inside the Jamf Pro management GUI:

1.Go to “Management Settings → All Settings → Jamf Pro User Accounts & Group”

2.Click on the relevant user which is going to be used inside the integration.

3.Click the “Edit” button.

4.Under the “Account” tab, set the “Privilege Set” to “Custom” (or create a new user with “Privilege Set” as “Custom” if you don’t want to change the existing user’s permissions)

5.Under the “Privileges” tab, tick the relevant checkboxes based on the detailed permissions list below.

6.Click the “Save” button.

| Combined permissions for all of the commands: |
| --- |
| Jamf Pro Server Objects → Computers → Read |
| Jamf Pro Server Objects → Computers → Create |
| Jamf Pro Server Objects → Users → Read |
| Jamf Pro Server Objects → Mobile Devices → Read |
| Jamf Pro Server Objects → Mobile Devices → Create |
| Jamf Pro Server Objects → Advanced Computer Searches → Read |
| Jamf Pro Server Settings → Apple Education Support → Read |
| Jamf Pro Server Actions → Send Computer Remote Lock Command |
| Jamf Pro Server Actions → Send Computer Remote Wipe Command |
| Jamf Pro Server Actions → Send Mobile Device Lost Mode Command |
| Jamf Pro Server Actions → Send Mobile Device Remote Wipe Command |
| Jamf Pro Server Actions → View Mobile Device Lost Mode Location |


## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### jamf-get-computers
***
Returns a list of all computers with their associated IDs. By default, returns the first 50 computers to the context (ID + name).
This command is a replacement for ``jamf-get-computers`` in jamf v1 integration.

#### Base Command

`jamf-get-computers`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computers limit=3```

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
                "Paging": {
                    "current_page": 0,
                    "page_size": 3,
                    "total_results": 137
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Paging for get computers
>|Current Page|Page Size|Total Results|
>|---|---|---|
>| 0 | 3 | 137 |

>### Jamf get computers result
>|ID|Name|
>|---|---|
>| 1 | Computer 95 |
>| 2 | Computer 104 |
>| 3 | Computer 124 |
### jamf-get-computers-basic-subset
***
Returns the “basic” subset for all of the computers. The “basic” subset includes: MAC address, model, UDID, name, department, building, serial number, username, ID.


#### Base Command

`jamf-get-computers-basic-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computers-basic-subset limit=3```

#### Context Example
```json
{
    "JAMF": {
        "Computer": [
            {
                "building": "",
                "department": "",
                "id": 1,
                "mac_address": "18:5B:35:CA:12:56",
                "managed": false,
                "model": "MacBookPro9,2",
                "name": "Computer 95",
                "report_date_epoch": 1617021852595,
                "report_date_utc": "2021-03-29T12:44:12.595+0000",
                "serial_number": "BA40F81C60A2",
                "udid": "BA40F812-60A3-11E4-90B8-12DF261F2C7E",
                "username": "user91"
            },
            {
                "building": "",
                "department": "",
                "id": 2,
                "mac_address": "",
                "managed": false,
                "model": "",
                "name": "Computer 104",
                "report_date_epoch": 1617021852853,
                "report_date_utc": "2021-03-29T12:44:12.853+0000",
                "serial_number": "",
                "udid": "18F1FDEE-1730-4840-BA15-42744EA7A1EF",
                "username": ""
            },
            {
                "building": "",
                "department": "",
                "id": 3,
                "mac_address": "",
                "managed": false,
                "model": "",
                "name": "Computer 124",
                "report_date_epoch": 1617021853383,
                "report_date_utc": "2021-03-29T12:44:13.383+0000",
                "serial_number": "",
                "udid": "10BA9E1B-8992-4664-A34F-423154CB9B0E",
                "username": ""
            },
            {
                "Paging": {
                    "current_page": 0,
                    "page_size": 3,
                    "total_results": 137
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Paging for get computers
>|Current Page|Page Size|Total Results|
>|---|---|---|
>| 0 | 3 | 137 |

>### Jamf get computers result 
>|ID|Mac Address|Name|Serial Number|UDID|Username|
>|---|---|---|---|---|---|
>| 1 | 18:5B:35:CA:12:56 | Computer 95 | BA40F81C60A2 | CA40F812-60A3-11E4-90B8-12DF261F2C7E | user91 |
>| 2 |  | Computer 104 |  | 18F1FDEE-1730-4840-BA15-42744EA7A1EF |  |
>| 3 |  | Computer 124 |  | 10BA9E1B-8992-4664-A34F-423154CB9B0E |  |


### jamf-get-computer-by-id
***
Returns the "general" subset of a specific computer, e.g.: name, MAC address, IP, serial number, UDID, etc.


#### Base Command

`jamf-get-computer-by-id`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-by-id id=1```

#### Context Example
```json
{
    "JAMF": {
        "Computer": {
            "alt_mac_address": "B0:34:95:EC:97:C4",
            "alt_network_adapter_type": "",
            "asset_tag": "",
            "barcode_1": "",
            "barcode_2": "",
            "distribution_point": "",
            "id": 1,
            "initial_entry_date": "2021-03-29",
            "initial_entry_date_epoch": 1617021852322,
            "initial_entry_date_utc": "2021-03-29T12:44:12.322+0000",
            "ip_address": "123.243.192.21",
            "itunes_store_account_is_active": false,
            "jamf_version": "9.6.29507.c",
            "last_cloud_backup_date_epoch": 0,
            "last_cloud_backup_date_utc": "",
            "last_contact_time": "2014-10-24 10:26:55",
            "last_contact_time_epoch": 1414146415335,
            "last_contact_time_utc": "2014-10-24T10:26:55.335+0000",
            "last_enrolled_date_epoch": 1414146339607,
            "last_enrolled_date_utc": "2014-10-24T10:25:39.607+0000",
            "last_reported_ip": "192.168.1.15",
            "mac_address": "18:5B:35:CA:12:56",
            "mdm_capable": false,
            "mdm_capable_users": {},
            "mdm_profile_expiration_epoch": 0,
            "mdm_profile_expiration_utc": "",
            "name": "Computer 95",
            "netboot_server": "",
            "network_adapter_type": "",
            "platform": "Mac",
            "remote_management": {
                "managed": false,
                "management_password_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b812",
                "management_username": ""
            },
            "report_date": "2021-03-29 12:44:12",
            "report_date_epoch": 1617021852595,
            "report_date_utc": "2021-03-29T12:44:12.595+0000",
            "serial_number": "BA40F81C60A2",
            "site": {
                "id": -1,
                "name": "None"
            },
            "supervised": false,
            "sus": "",
            "udid": "CA40F812-60A3-11E4-90B8-12DF261F2C7E"
        }
    }
}
```

#### Human Readable Output

>### Jamf get computers result for computer ID: 1
>|ID|IP Address|Jamf Version|MAC Address|Name|Platform|Serial Number|UDID|
>|---|---|---|---|---|---|---|---|
>| 1 | 123.243.192.21 | 9.6.29507.c | 18:5B:35:CA:12:56 | Computer 95 | Mac | BA40F81C60A2 | CA40F812-60A3-11E4-90B8-12DF261F2C7E |


### jamf-get-computer-by-match
***
Matches computers by specific characteristics and returns general data on each of the computers.


#### Base Command

`jamf-get-computer-by-match`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-by-match match="Computer 9*" limit=3```

#### Context Example
```json
{
    "JAMF": {
        "Computer": [
            {
                "alt_mac_address": "B0:34:95:EC:97:C4",
                "asset_tag": "",
                "bar_code_1": "",
                "bar_code_2": "",
                "building": "",
                "building_name": "",
                "department": "",
                "department_name": "",
                "email": "User91@email.com",
                "email_address": "User91@email.com",
                "id": 1,
                "mac_address": "18:5B:35:CA:12:56",
                "name": "Computer 95",
                "position": "",
                "realname": "User 91",
                "room": "100 Walker Street\t \r\nLevel 14, Suite 3",
                "serial_number": "BA40F81C60A2",
                "udid": "CA40F812-60A3-11E4-90B8-12DF261F2C7E",
                "username": "user91"
            },
            {
                "alt_mac_address": "72:00:04:22:5F:10",
                "asset_tag": "JS002221",
                "bar_code_1": "",
                "bar_code_2": "",
                "building": "",
                "building_name": "",
                "department": "",
                "department_name": "",
                "email": "User81@email.com",
                "email_address": "User81@email.com",
                "id": 49,
                "mac_address": "3C:15:C2:DC:7D:22",
                "name": "Computer 9",
                "position": "",
                "realname": "User 81",
                "room": "1011 Washington Avenue S\r\nSuite 350",
                "serial_number": "CA41077660A3",
                "udid": "CA41076C-60A3-11E4-90B8-12DF261F2C7E",
                "username": "user81"
            },
            {
                "alt_mac_address": "B8:8D:12:40:ED:6A",
                "asset_tag": "JS000531",
                "bar_code_1": "",
                "bar_code_2": "",
                "building": "",
                "building_name": "",
                "department": "",
                "department_name": "",
                "email": "User72@email.com",
                "email_address": "User72@email.com",
                "id": 56,
                "mac_address": "3C:07:54:58:A4:E2",
                "name": "Computer 92",
                "position": "",
                "realname": "User 72",
                "room": "81 Freedom Hills Dr",
                "serial_number": "CA40F73660A3",
                "udid": "CA40F72C-60A3-11E4-90B8-12DF261F2C7E",
                "username": "user72"
            },
            {
                "Paging": {
                    "current_page": 0,
                    "page_size": 3,
                    "total_results": 10
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Paging for get computers
>|Current Page|Page Size|Total Results|
>|---|---|---|
>| 0 | 3 | 10 |

>### Jamf get computers result 
>|ID|Mac Address|Name|Serial Number|UDID|Username|
>|---|---|---|---|---|---|
>| 1 | 18:5B:35:CA:12:56 | Computer 95 | BA40F81C60A2 | CA40F812-60A3-11E4-90B8-12DF261F2C7E | user91 |
>| 49 | 3C:15:C2:DC:7D:22 | Computer 9 | CA41077660A3 | CA41076C-60A3-11E4-90B8-12DF261F2C7E | user81 |
>| 56 | 3C:07:54:58:A4:E2 | Computer 92 | CA40F73660A3 | CA40F72C-60A3-11E4-90B8-12DF261F2C7E | user72 |


### jamf-get-computer-general-subset
***
Returns the general subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-general-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-general-subset identifier=name identifier_value="Computer 95"```

#### Context Example
```json
{
    "JAMF": {
        "ComputerSubset": {
            "computer": {
                "general": {
                    "alt_mac_address": "B0:34:95:EC:97:C4",
                    "alt_network_adapter_type": "",
                    "asset_tag": "",
                    "barcode_1": "",
                    "barcode_2": "",
                    "distribution_point": "",
                    "id": 1,
                    "initial_entry_date": "2021-03-29",
                    "initial_entry_date_epoch": 1617021852322,
                    "initial_entry_date_utc": "2021-03-29T12:44:12.322+0000",
                    "ip_address": "123.243.192.21",
                    "itunes_store_account_is_active": false,
                    "jamf_version": "9.6.29507.c",
                    "last_cloud_backup_date_epoch": 0,
                    "last_cloud_backup_date_utc": "",
                    "last_contact_time": "2014-10-24 10:26:55",
                    "last_contact_time_epoch": 1414146415335,
                    "last_contact_time_utc": "2014-10-24T10:26:55.335+0000",
                    "last_enrolled_date_epoch": 1414146339607,
                    "last_enrolled_date_utc": "2014-10-24T10:25:39.607+0000",
                    "last_reported_ip": "192.168.1.15",
                    "mac_address": "18:5B:35:CA:12:56",
                    "mdm_capable": false,
                    "mdm_capable_users": {},
                    "mdm_profile_expiration_epoch": 0,
                    "mdm_profile_expiration_utc": "",
                    "name": "Computer 95",
                    "netboot_server": "",
                    "network_adapter_type": "",
                    "platform": "Mac",
                    "remote_management": {
                        "managed": false,
                        "management_password_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b812",
                        "management_username": ""
                    },
                    "report_date": "2021-03-29 12:44:12",
                    "report_date_epoch": 1617021852595,
                    "report_date_utc": "2021-03-29T12:44:12.595+0000",
                    "serial_number": "BA40F81C60A2",
                    "site": {
                        "id": -1,
                        "name": "None"
                    },
                    "supervised": false,
                    "sus": "",
                    "udid": "CA40F812-60A3-11E4-90B8-12DF261F2C7E"
                },
                "id": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf computer General subset result
>|Alternate MAC address|ID|IP address|MAC address|Managed|Name|Platform|Serial Number|UDID|
>|---|---|---|---|---|---|---|---|---|
>| B0:34:95:EC:97:C4 | 1 | 123.243.192.21 | 18:5B:35:CA:12:56 | false | Computer 95 | Mac | BA40F81C60A2 | CA40F812-60A3-11E4-90B8-12DF261F2C7E |


### jamf-get-computer-location-subset
***
Returns the location subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-location-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-location-subset identifier=name identifier_value="Computer 95"```

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
                    "phone": "612-605-6625",
                    "phone_number": "612-605-6625",
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

>### Jamf computer Location subset result
>|Email Address|Phone|Real Name|Room|Username|
>|---|---|---|---|---|
>| User91@email.com | 612-605-6625 | User 91 | 100 Walker Street	 <br/>Level 14, Suite 3 | user91 |


### jamf-get-computer-purchasing-subset
***
Returns the purchasing subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-purchasing-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-purchasing-subset identifier=name identifier_value="Computer 95"```

#### Context Example
```json
{
    "JAMF": {
        "ComputerSubset": {
            "computer": {
                "id": 1,
                "purchasing": {
                    "applecare_id": "",
                    "attachments": [],
                    "is_leased": false,
                    "is_purchased": true,
                    "lease_expires": "",
                    "lease_expires_epoch": 0,
                    "lease_expires_utc": "",
                    "life_expectancy": 0,
                    "os_applecare_id": "",
                    "os_maintenance_expires": "",
                    "po_date": "",
                    "po_date_epoch": 0,
                    "po_date_utc": "",
                    "po_number": "",
                    "purchase_price": "",
                    "purchasing_account": "",
                    "purchasing_contact": "",
                    "vendor": "",
                    "warranty_expires": "",
                    "warranty_expires_epoch": 0,
                    "warranty_expires_utc": ""
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf computer Purchasing subset result
>|Is Leased|Is Purchased|
>|---|---|
>| false | true |


### jamf-get-computer-peripherals-subset
***
Returns the peripherals subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-peripherals-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-peripherals-subset identifier=name identifier_value="Computer 95"```

#### Context Example
```json
{
    "JAMF": {
        "ComputerSubset": {
            "computer": {
                "id": 1,
                "peripherals": []
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf computer Peripherals subset result
>**No entries.**


### jamf-get-computer-hardware-subset
***
Returns the hardware subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-hardware-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-hardware-subset identifier=id identifier_value="138"```

#### Context Example
```json
{
    "JAMF": {
        "ComputerSubset": {
            "computer": {
                "hardware": {
                    "active_directory_status": "Not Bound",
                    "available_ram_slots": 0,
                    "battery_capacity": 83,
                    "ble_capable": true,
                    "boot_rom": "1554.80.3.0.0 (iBridge: 18.16.14347.0.0,0)",
                    "bus_speed": 0,
                    "bus_speed_mhz": 0,
                    "cache_size": 8192,
                    "cache_size_kb": 8192,
                    "disk_encryption_configuration": "",
                    "filevault2_users": [
                        "itadmin",
                        "user",
                        "test"
                    ],
                    "gatekeeper_status": "App Store and identified developers",
                    "institutional_recovery_key": "Not Present",
                    "make": "Apple",
                    "mapped_printers": [],
                    "model": "MacBook Pro (13-inch, 2018)",
                    "model_identifier": "MacBookPro15,2",
                    "nic_speed": "10/100",
                    "number_cores": 4,
                    "number_processors": 1,
                    "optical_drive": "",
                    "os_build": "20D91",
                    "os_name": "macOS",
                    "os_version": "11.2.3",
                    "processor_architecture": "x86_64",
                    "processor_speed": 2700,
                    "processor_speed_mhz": 2700,
                    "processor_type": "Quad-Core Intel Core i7",
                    "service_pack": "",
                    "sip_status": "Enabled",
                    "smc_version": "",
                    "storage": [
                        {
                            "connection_type": "NO",
                            "disk": "disk0",
                            "drive_capacity_mb": 500277,
                            "model": "APPLE SSD AP0512M",
                            "partitions": [
                                {
                                    "available_mb": 480067,
                                    "boot_drive_available_mb": 480067,
                                    "filevault2_percent": 0,
                                    "filevault2_status": "Not Encrypted",
                                    "filevault_percent": 0,
                                    "filevault_status": "Not Encrypted",
                                    "lvUUID": "",
                                    "lvgUUID": "",
                                    "name": "HD (Boot Partition)",
                                    "partition_capacity_mb": 499963,
                                    "percentage_full": 4,
                                    "pvUUID": "",
                                    "size": 499963,
                                    "type": "boot"
                                },
                                {
                                    "available_mb": 480067,
                                    "filevault2_percent": 0,
                                    "filevault2_status": "Not Encrypted",
                                    "filevault_percent": 0,
                                    "filevault_status": "Not Encrypted",
                                    "name": "VM",
                                    "partition_capacity_mb": 499963,
                                    "percentage_full": 1,
                                    "size": 499963,
                                    "type": "other"
                                },
                                {
                                    "available_mb": 480067,
                                    "filevault2_percent": 0,
                                    "filevault2_status": "Not Encrypted",
                                    "filevault_percent": 0,
                                    "filevault_status": "Not Encrypted",
                                    "name": "Preboot",
                                    "partition_capacity_mb": 499963,
                                    "percentage_full": 1,
                                    "size": 499963,
                                    "type": "other"
                                },
                                {
                                    "available_mb": 480067,
                                    "filevault2_percent": 0,
                                    "filevault2_status": "Not Encrypted",
                                    "filevault_percent": 0,
                                    "filevault_status": "Not Encrypted",
                                    "name": "Update",
                                    "partition_capacity_mb": 499963,
                                    "percentage_full": 1,
                                    "size": 499963,
                                    "type": "other"
                                },
                                {
                                    "available_mb": 480067,
                                    "filevault2_percent": 0,
                                    "filevault2_status": "Not Encrypted",
                                    "filevault_percent": 0,
                                    "filevault_status": "Not Encrypted",
                                    "name": "Data",
                                    "partition_capacity_mb": 499963,
                                    "percentage_full": 1,
                                    "size": 499963,
                                    "type": "other"
                                },
                                {
                                    "available_mb": 480067,
                                    "filevault2_percent": 0,
                                    "filevault2_status": "Not Encrypted",
                                    "filevault_percent": 0,
                                    "filevault_status": "Not Encrypted",
                                    "name": "HD - Data",
                                    "partition_capacity_mb": 499963,
                                    "percentage_full": 1,
                                    "size": 499963,
                                    "type": "other"
                                }
                            ],
                            "revision": "1161.80.",
                            "serial_number": "C02834600HKJN1N15",
                            "size": 500277,
                            "smart_status": "Verified"
                        }
                    ],
                    "supports_ios_app_installs": false,
                    "total_ram": 16384,
                    "total_ram_mb": 16384,
                    "xprotect_version": "2144"
                },
                "id": 138
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf computer Hardware subset result
>|storage|
>|---|
>| {'disk0': 500277} |


### jamf-get-computer-certificates-subset
***
Returns the certificates subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-certificates-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-certificates-subset identifier=id identifier_value="138"```

#### Context Example
```json
{
    "JAMF": {
        "ComputerSubset": {
            "computer": {
                "certificates": [
                    {
                        "common_name": "com.apple.systemdefault",
                        "expires_epoch": 2249728390000,
                        "expires_utc": "2041-04-16T12:33:10.000+0000",
                        "identity": true,
                        "name": ""
                    },
                    {
                        "common_name": "Palo Alto Networks JSS Built-in Certificate Authority",
                        "expires_epoch": 1930290855000,
                        "expires_utc": "2031-03-03T07:54:15.000+0000",
                        "identity": false,
                        "name": ""
                    },
                    {
                        "common_name": "com.apple.kerberos.kdc",
                        "expires_epoch": 2249728390000,
                        "expires_utc": "2041-04-16T12:33:10.000+0000",
                        "identity": true,
                        "name": ""
                    },
                    {
                        "common_name": "221D61D2-B794-4128-8FFF-8C4A618A9056",
                        "expires_epoch": 1682082455000,
                        "expires_utc": "2023-04-21T13:07:35.000+0000",
                        "identity": true,
                        "name": ""
                    }
                ],
                "id": 138
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf computer Certificates subset result
>|Common Name|Expires Epoch|Expires UTC|Identity|
>|---|---|---|---|
>| com.apple.systemdefault | 2249728390000 | 2041-04-16T12:33:10.000+0000 | true |
>| Palo Alto Networks JSS Built-in Certificate Authority | 1930290855000 | 2031-03-03T07:54:15.000+0000 | false |
>| com.apple.kerberos.kdc | 2249728390000 | 2041-04-16T12:33:10.000+0000 | true |
>| 221D61D2-B794-4128-8FFF-8C4A618A9056 | 1682082455000 | 2023-04-21T13:07:35.000+0000 | true |


### jamf-get-computer-security-subset
***
Returns the security subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-security-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-security-subset identifier=name identifier_value="Computer 95"```

#### Context Example
```json
{
    "JAMF": {
        "ComputerSubset": {
            "computer": {
                "id": 1,
                "security": {
                    "activation_lock": false,
                    "external_boot_level": "unknown",
                    "secure_boot_level": "unknown"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf computer Security subset result
>|Common Name|Expires UTC|Identity|
>|---|---|---|
>| false | unknown | unknown |


### jamf-get-computer-software-subset
***
Returns the software subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-software-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-software-subset identifier=name identifier_value="Computer 95"```

#### Context Example
```json
{
    "JAMF": {
        "ComputerSubset": {
            "computer": {
                "id": 1,
                "software": {
                    "applications": [
                        {
                            "bundle_id": "",
                            "name": "Activity Monitor.app",
                            "path": "/Applications/Utilities/Activity Monitor.app",
                            "version": "10.10.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "AirPort Utility.app",
                            "path": "/Applications/Utilities/AirPort Utility.app",
                            "version": "6.3.4"
                        },
                        {
                            "bundle_id": "",
                            "name": "App Store.app",
                            "path": "/Applications/App Store.app",
                            "version": "2.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Audio MIDI Setup.app",
                            "path": "/Applications/Utilities/Audio MIDI Setup.app",
                            "version": "3.0.6"
                        },
                        {
                            "bundle_id": "",
                            "name": "Automator.app",
                            "path": "/Applications/Automator.app",
                            "version": "2.5"
                        },
                        {
                            "bundle_id": "",
                            "name": "Bluetooth File Exchange.app",
                            "path": "/Applications/Utilities/Bluetooth File Exchange.app",
                            "version": "4.3.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Boot Camp Assistant.app",
                            "path": "/Applications/Utilities/Boot Camp Assistant.app",
                            "version": "5.1.2"
                        },
                        {
                            "bundle_id": "",
                            "name": "Calculator.app",
                            "path": "/Applications/Calculator.app",
                            "version": "10.8"
                        },
                        {
                            "bundle_id": "",
                            "name": "Calendar.app",
                            "path": "/Applications/Calendar.app",
                            "version": "8.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Chess.app",
                            "path": "/Applications/Chess.app",
                            "version": "3.10"
                        },
                        {
                            "bundle_id": "",
                            "name": "ColorSync Utility.app",
                            "path": "/Applications/Utilities/ColorSync Utility.app",
                            "version": "4.10.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Console.app",
                            "path": "/Applications/Utilities/Console.app",
                            "version": "10.10"
                        },
                        {
                            "bundle_id": "",
                            "name": "Contacts.app",
                            "path": "/Applications/Contacts.app",
                            "version": "9.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Dashboard.app",
                            "path": "/Applications/Dashboard.app",
                            "version": "1.8"
                        },
                        {
                            "bundle_id": "",
                            "name": "Dictionary.app",
                            "path": "/Applications/Dictionary.app",
                            "version": "2.2.1"
                        },
                        {
                            "bundle_id": "",
                            "name": "Digital Color Meter.app",
                            "path": "/Applications/Utilities/Digital Color Meter.app",
                            "version": "5.10"
                        },
                        {
                            "bundle_id": "",
                            "name": "Disk Utility.app",
                            "path": "/Applications/Utilities/Disk Utility.app",
                            "version": "13"
                        },
                        {
                            "bundle_id": "",
                            "name": "DVD Player.app",
                            "path": "/Applications/DVD Player.app",
                            "version": "5.7"
                        },
                        {
                            "bundle_id": "",
                            "name": "FaceTime.app",
                            "path": "/Applications/FaceTime.app",
                            "version": "3.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Font Book.app",
                            "path": "/Applications/Font Book.app",
                            "version": "5.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Game Center.app",
                            "path": "/Applications/Game Center.app",
                            "version": "2.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Grab.app",
                            "path": "/Applications/Utilities/Grab.app",
                            "version": "1.8"
                        },
                        {
                            "bundle_id": "",
                            "name": "Grapher.app",
                            "path": "/Applications/Utilities/Grapher.app",
                            "version": "2.5"
                        },
                        {
                            "bundle_id": "",
                            "name": "iBooks.app",
                            "path": "/Applications/iBooks.app",
                            "version": "1.1"
                        },
                        {
                            "bundle_id": "",
                            "name": "Image Capture.app",
                            "path": "/Applications/Image Capture.app",
                            "version": "6.6"
                        },
                        {
                            "bundle_id": "",
                            "name": "iTunes.app",
                            "path": "/Applications/iTunes.app",
                            "version": "12.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Keychain Access.app",
                            "path": "/Applications/Utilities/Keychain Access.app",
                            "version": "9.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Launchpad.app",
                            "path": "/Applications/Launchpad.app",
                            "version": "1.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Mail.app",
                            "path": "/Applications/Mail.app",
                            "version": "8.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Maps.app",
                            "path": "/Applications/Maps.app",
                            "version": "2.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Messages.app",
                            "path": "/Applications/Messages.app",
                            "version": "8.0"
                        },
                        {
                            "bundle_id": "",
                            "name": "Migration Assistant.app",
                            "path": "/Applications/Utilities/Migration Assistant.app",
                            "version": "5"
                        },
                        {
                            "bundle_id": "",
                            "name": "Mission Control.app",
                            "path": "/Applications/Mission Control.app",
                            "version": "1.2"
                        },
                        {
                            "bundle_id": "",
                            "name": "Notes.app",
                            "path": "/Applications/Notes.app",
                            "version": "3.0"
                        }
                    ],
                    "available_software_updates": [],
                    "available_updates": {},
                    "cached_by_casper": [],
                    "fonts": [],
                    "installed_by_casper": [],
                    "installed_by_installer_swu": [],
                    "licensed_software": [],
                    "plugins": [],
                    "running_services": [],
                    "unix_executables": []
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf computer Software subset result
>|Number of installed applications|Number of running services |
>|---|---|
>| 48 | 0 |


### jamf-get-computer-extension-attributes-subset
***
Returns the extension attributes subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-extension-attributes-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-extension-attributes-subset identifier=name identifier_value="Computer 95"```

#### Context Example
```json
{
    "JAMF": {
        "ComputerSubset": {
            "computer": {
                "extension_attributes": [
                    {
                        "id": 5,
                        "multi_value": false,
                        "name": "Battery Cycle Count",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 4,
                        "multi_value": false,
                        "name": "JNUC-2019-LabUser",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 1,
                        "multi_value": false,
                        "name": "Local Password",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 2,
                        "multi_value": false,
                        "name": "Test",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 6,
                        "multi_value": false,
                        "name": "Tomer test",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 7,
                        "multi_value": false,
                        "name": "tomer test 2",
                        "type": "Number",
                        "value": ""
                    },
                    {
                        "id": 3,
                        "multi_value": false,
                        "name": "Usage Policy Violation",
                        "type": "String",
                        "value": ""
                    }
                ],
                "id": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf computer ExtensionAttributes subset result
>|ID|Name|Type|Value|
>|---|---|---|---|
>| 5 | Battery Cycle Count | String | false |
>| 4 | JNUC-2019-LabUser | String | false |
>| 1 | Local Password | String | false |
>| 2 | Test | String | false |
>| 6 | Tomer test | String | false |
>| 7 | tomer test 2 | Number | false |
>| 3 | Usage Policy Violation | String | false |


### jamf-get-computer-groups-accounts-subset
***
Returns the groups accounts subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-groups-accounts-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-groups-accounts-subset identifier=id identifier_value="138"```

#### Context Example
```json
{
    "JAMF": {
        "ComputerSubset": {
            "computer": {
                "groups_accounts": {
                    "computer_group_memberships": [
                        "All Managed Clients",
                        "Security: POODLE, All Clients at Risk",
                        "All Clients: OS X 10.10",
                        "Compliance: No Inventory Report for 14 Days",
                        "All Clients: Last Enrollment More Than 5 Days Ago",
                        "All Clients: Invalid Apple Software Update Catalog URL",
                        "All Clients: FDERecovery Agent is Present/Running and has Valid Individual Key",
                        "FileVault 2: Invalid Individual Key, Mgmt Account is NOT FV2 User",
                        "App: IntelliJ IDEA 13",
                        "Printers: Does not have Riverfront Building",
                        "FileVault 2: Invalid Individual Key, Mgmt Account is FV2 User",
                        "All Clients: Mavericks, Not Running 10.9.5",
                        "Printers: Does not have Minneapolis Office",
                        "FileVault 2: Invalid Individual Key, Mgmt Account is FV2 User, Has JAMF Institutional Key",
                        "Group Name",
                        "App: Genymotion Installed",
                        "Security: POODLE, Firefox Update Required (2014-10-15)",
                        "App: Microsoft Outlook 2011",
                        "Compliance: All Clients Not in Compliance",
                        "All Clients: Mountain Lion, Not Running 10.8.5",
                        "FileVault 2: Valid Individual Key, Needs Mgmt Account as FV2 User",
                        "Security: POODLE, Safari Updates Required (2014-10-15)",
                        "Security: POODLE, OS Updates Required",
                        "App: VMware Fusion Installed",
                        "Security: Shellshock, Patch Ineligible",
                        "Staff: Online Services",
                        "All Clients: No Assigned User (Not in Inventory)",
                        "FileVault 2: Valid Individual Key, Mgmt Account is FV2 User, has JAMF Institutional Key",
                        "Security: POODLE, Chrome Update Required (2014-10-15)",
                        "Security: Shellshock, Patch Required",
                        "FileVault 2: Has JAMF Institutional Key",
                        "App: TextExpander Installed",
                        "FileVault 2: Valid Individual Key, Needs JAMF Institutional Key",
                        "Security: Shellshock, Patch Applied",
                        "FileVault 2: Currently Encrypting",
                        "FileVault 2: Invalid Individual Key, Mgmt Account is FV2 User, Needs JAMF Institutional Key",
                        "App: Parallels Desktop Installed",
                        "FileVault 2: Invalid Individual Key, Mgmt Account is NOT FV2 User, Needs JAMF Institutional Key",
                        "App: RubyMine 6",
                        "Test Test",
                        "Compliance: FileVault 2 Not Enabled",
                        "Test Smart Group",
                        "Tomer2"
                    ],
                    "local_accounts": [
                        {
                            "administrator": true,
                            "filevault_enabled": true,
                            "home": "/Users/test",
                            "home_size": "-1MB",
                            "home_size_mb": -1,
                            "name": "test",
                            "realname": "test",
                            "uid": "504"
                        },
                        {
                            "administrator": true,
                            "filevault_enabled": true,
                            "home": "/Users/user",
                            "home_size": "-1MB",
                            "home_size_mb": -1,
                            "name": "user",
                            "realname": "user",
                            "uid": "502"
                        }
                    ],
                    "user_inventories": {
                        "disable_automatic_login": true,
                        "user": {
                            "password_history_depth": "",
                            "password_max_age": "",
                            "password_min_complex_characters": "",
                            "password_min_length": "4",
                            "password_require_alphanumeric": "false",
                            "username": "test"
                        }
                    }
                },
                "id": 138
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf computer GroupsAccounts subset result
>|Number of groups|Number of local accounts|
>|---|---|
>| 43 | 4 |


### jamf-get-computer-iphones-subset
***
Returns the iPhones subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-iphones-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-iphones-subset identifier=id identifier_value="138"```

#### Context Example
```json
{
    "JAMF": {
        "ComputerSubset": {
            "computer": {
                "id": 138,
                "iphones": []
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf computer iphones subset result
>**No entries.**


### jamf-get-computer-configuration-profiles-subset
***
Returns the configuration profiles subset for a specific computer according to the given arguments.


#### Base Command

`jamf-get-computer-configuration-profiles-subset`

#### Required Permissions
Jamf Pro Server Objects → Computers → Read

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
```!jamf-get-computer-configuration-profiles-subset identifier=id identifier_value="138"```

#### Context Example
```json
{
    "JAMF": {
        "ComputerSubset": {
            "computer": {
                "configuration_profiles": [
                    {
                        "id": -1,
                        "is_removable": false,
                        "name": "",
                        "uuid": ""
                    },
                    {
                        "id": -1,
                        "is_removable": false,
                        "name": "",
                        "uuid": ""
                    },
                    {
                        "id": -2,
                        "is_removable": false,
                        "name": "",
                        "uuid": ""
                    }
                ],
                "id": 138
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf computer ConfigurationProfiles subset result
>|Configuration profile ID|Is Removable|
>|---|---|
>| -1 | false |
>| -1 | false |
>| -2 | false |


### jamf-computer-lock
***
Sends the "DeviceLock" command to a computer. This command logs the user out of the computer, restarts the computer, and then locks the computer. Optional: Displays a message on the computer when it locks.


#### Base Command

`jamf-computer-lock`

#### Required Permissions
Jamf Pro Server Actions → Send Computer Remote Lock Command

Jamf Pro Server Objects → Computers → Create


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
```!jamf-computer-lock id=138 passcode=123456```

#### Context Example
```json
{
    "JAMF": {
        "ComputerCommand": {
            "command_uuid": "2f410832-c87e-4b4c-aab7-8edaa22b2e08",
            "computer_id": "138",
            "name": "DeviceLock"
        }
    }
}
```

#### Human Readable Output

>### Computer 138 locked successfully
>|Command UUID|Computer ID|Name|
>|---|---|---|
>| 2f410832-c87e-4b4c-aab7-8edaa22b2e08 | 138 | DeviceLock |


### jamf-computer-erase
***
Sends the “EraseDevice'' command to a computer. Permanently erases all the data on the computer and sets a passcode when required by the computer hardware type.


#### Base Command

`jamf-computer-erase`

#### Required Permissions
Jamf Pro Server Actions → Send Computer Remote Wipe Command

Jamf Pro Server Objects → Computers → Create

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
```!jamf-computer-erase id=138 passcode=123456```

#### Context Example
```json
{
    "JAMF": {
        "ComputerCommand": {
            "command_uuid": "91cfac41-7826-4d73-b8b7-9ab34848f2f2",
            "computer_id": "138",
            "name": "EraseDevice"
        }
    }
}
```

#### Human Readable Output

>### Computer 138 erased successfully
>|Command UUID|Computer ID|Name|
>|---|---|---|
>| 91cfac41-7826-4d73-b8b7-9ab34848f2f2 | 138 | EraseDevice |


### jamf-get-users
***
Returns a list of users with their IDs and names. By default, returns the first 50 users to the context (ID + name).


#### Base Command

`jamf-get-users`

#### Required Permissions
Jamf Pro Server Objects → Users → Read

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
```!jamf-get-users limit=3```

#### Context Example
```json
{
    "JAMF": {
        "User": [
            {
                "id": 81,
                "name": "AHarrison"
            },
            {
                "id": 80,
                "name": "David.Aspir"
            },
            {
                "id": 76,
                "name": "dummy00001"
            },
            {
                "Paging": {
                    "current_page": 0,
                    "page_size": 3,
                    "total_results": 98
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Paging for get users
>|Current Page|Page Size|Total Results|
>|---|---|---|
>| 0 | 3 | 98 |

>### Jamf get users result 
> Total results:98
>Results per page: 3
>Page: 0
>|ID|Name|
>|---|---|
>| 81 | AHarrison |
>| 80 | David.Aspir |
>| 76 | dummy00001 |


### jamf-get-user-by-id
***
Returns a specific user with general data about the user according to the given ID.


#### Base Command

`jamf-get-user-by-id`

#### Required Permissions
Jamf Pro Server Objects → Users → Read

Jamf Pro Server Settings → Apple Education Support → Read (in order to view these fields: “enable_custom_photo_url” and “custom_photo_url”)

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
```!jamf-get-user-by-id id=1```

#### Context Example
```json
{
    "JAMF": {
        "User": {
            "custom_photo_url": "",
            "email": "User28@email.com",
            "email_address": "User28@email.com",
            "enable_custom_photo_url": false,
            "extension_attributes": [
                {
                    "id": 1,
                    "name": "vip",
                    "type": "String",
                    "value": ""
                },
                {
                    "id": 2,
                    "name": "test user attribute",
                    "type": "String",
                    "value": ""
                }
            ],
            "full_name": "User 28",
            "id": 1,
            "ldap_server": {
                "id": -1,
                "name": "None"
            },
            "links": {
                "computers": [
                    {
                        "id": 16,
                        "name": "Computer 3"
                    },
                    {
                        "id": 42,
                        "name": "Computer 36"
                    },
                    {
                        "id": 85,
                        "name": "Computer 96"
                    }
                ],
                "mobile_devices": [
                    {
                        "id": 1,
                        "name": "Device 71"
                    },
                    {
                        "id": 28,
                        "name": "Device 70"
                    },
                    {
                        "id": 31,
                        "name": "Device 114"
                    }
                ],
                "peripherals": [],
                "total_vpp_code_count": 0,
                "vpp_assignments": []
            },
            "managed_apple_id": "",
            "name": "user28",
            "phone_number": "612-605-6625",
            "position": "",
            "sites": [],
            "user_groups": {
                "size": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf get user result
>|Email|ID|Name|Phone|
>|---|---|---|---|
>| User28@email.com | 1 | user28 | 612-605-6625 |


### jamf-get-user-by-name
***
Returns a specific user with general data about the user according to the given name.


#### Base Command

`jamf-get-user-by-name`

#### Required Permissions
Jamf Pro Server Objects → Users → Read

Jamf Pro Server Settings → Apple Education Support → Read (in order to view these fields: “enable_custom_photo_url” and “custom_photo_url”)

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
```!jamf-get-user-by-name name=tomertest```

#### Context Example
```json
{
    "JAMF": {
        "User": {
            "custom_photo_url": "",
            "email": "tomertest@test.com",
            "email_address": "tomertest@test.com",
            "enable_custom_photo_url": false,
            "extension_attributes": [
                {
                    "id": 1,
                    "name": "vip",
                    "type": "String",
                    "value": ""
                },
                {
                    "id": 2,
                    "name": "test user attribute",
                    "type": "String",
                    "value": ""
                }
            ],
            "full_name": "tomer test",
            "id": 97,
            "ldap_server": {
                "id": 2,
                "name": "AD XSOAR Ninja"
            },
            "links": {
                "computers": [
                    {
                        "id": 138,
                        "name": "itadmin MacBook Pro"
                    },
                    {
                        "id": 139,
                        "name": "Tomer Mac"
                    }
                ],
                "mobile_devices": [
                    {
                        "id": 114,
                        "name": "test iPhone"
                    }
                ],
                "peripherals": [],
                "total_vpp_code_count": 0,
                "vpp_assignments": []
            },
            "managed_apple_id": "",
            "name": "tomertest",
            "phone_number": "",
            "position": "",
            "sites": [
                {
                    "id": 1,
                    "name": "Mainz"
                },
                {
                    "id": 2,
                    "name": "Test4"
                },
                {
                    "id": 7,
                    "name": "Alpha"
                }
            ],
            "user_groups": {
                "size": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf get user result
>|Email|ID|Name|
>|---|---|---|
>| tomertest@test.com | 97 | tomertest |


### jamf-get-user-by-email
***
Returns a specific user with general data about the user according to the given email.


#### Base Command

`jamf-get-user-by-email`

#### Required Permissions
Jamf Pro Server Objects → Users → Read

Jamf Pro Server Settings → Apple Education Support → Read (in order to view these fields: “enable_custom_photo_url” and “custom_photo_url”)

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
```!jamf-get-user-by-email email=user28@email.com```

#### Context Example
```json
{
    "JAMF": {
        "User": {
            "custom_photo_url": "",
            "email": "User28@email.com",
            "email_address": "User28@email.com",
            "enable_custom_photo_url": false,
            "extension_attributes": [
                {
                    "id": 1,
                    "name": "vip",
                    "type": "String",
                    "value": ""
                },
                {
                    "id": 2,
                    "name": "test user attribute",
                    "type": "String",
                    "value": ""
                }
            ],
            "full_name": "User 28",
            "id": 1,
            "ldap_server": [
                {
                    "id": -1
                },
                {
                    "name": "None"
                }
            ],
            "links": [
                {
                    "computer": [
                        {
                            "id": 85
                        },
                        {
                            "name": "Computer 96"
                        }
                    ]
                },
                {},
                {
                    "mobile_device": [
                        {
                            "id": 31
                        },
                        {
                            "name": "Device 114"
                        }
                    ]
                },
                {},
                {
                    "total_vpp_code_count": 0
                }
            ],
            "managed_apple_id": "",
            "name": "user28",
            "phone_number": "612-605-6625",
            "position": "",
            "sites": [],
            "user_groups": []
        }
    }
}
```

#### Human Readable Output

>### Jamf get user result
>|Email|ID|Name|Phone|
>|---|---|---|---|
>| User28@email.com | 1 | user28 | 612-605-6625 |


### jamf-get-mobile-devices
***
Returns a list of devices with  basic data on each. By default, returns the first 50 devices to the context (ID + name).


#### Base Command

`jamf-get-mobile-devices`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

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
                "phone_number": "612-605-6625",
                "serial_number": "CA44F4D060A3",
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
                "phone_number": "612-605-6625",
                "serial_number": "CA44CA9660A3",
                "supervised": false,
                "udid": "ca44ca8c60a311e490b812df261f2c7e",
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
                "phone_number": "612-605-6625",
                "serial_number": "CA44F34060A3",
                "supervised": true,
                "udid": "ca44f33660a311e490b812df261f2c7e",
                "username": "user60",
                "wifi_mac_address": "1C:E6:2B:A5:62:51"
            },
            {
                "Paging": {
                    "current_page": 0,
                    "page_size": 3,
                    "total_results": 114
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Paging for get mobile devices
>|Current Page|Page Size|Total Results|
>|---|---|---|
>| 0 | 3 | 114 |

>### Jamf get mobile devices result 
>|ID|Name|Serial Number|UDID|
>|---|---|---|---|
>| 1 | Device 71 | CA44F4D060A3 | ca44f4c660a311e490b812df261f2c7e |
>| 2 | Device 4 | CA44CA9660A3 | ca44ca8c60a311e490b812df261f2c7e |
>| 3 | Device 68 | CA44F34060A3 | ca44f33660a311e490b812df261f2c7e |


### jamf-get-mobile-device-by-id
***
Returns the "general" subset of a specific mobile device, e.g.: name, MAC address, IP, serial number, UDID. etc.


#### Base Command

`jamf-get-mobile-device-by-id`

#### Required Permissions
Jamf-get-mobile-device-by-id

Jamf Pro Server Objects → Mobile Devices → Read

*Jamf Pro Server Actions → Send Mobile Device Lost Mode Command 

**Jamf Pro Server Actions → View Mobile Device Lost Mode Location

*In order to view these fields: |
| --- |
| lost_mode_enabled |  
| lost_mode_enforced |  
| lost_mode_enable_issued_epoch |  
| lost_mode_enable_issued_utc |  
| lost_mode_message |  
| lost_mode_phone |  
| lost_mode_footnote |  

** In order to view these fields (has to be combined with “Send Mobile Device Lost Mode Command” permission) |
| --- |
| lost_location_epoch |  
| lost_location_utc |  
| lost_location_latitude |  
| lost_location_longitude |  
| lost_location_altitude |  
| lost_location_speed |  
| lost_location_course |  
| lost_location_horizontal_accuracy |  
| lost_location_vertical_accuracy |  


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
```!jamf-get-mobile-device-by-id id=114```

#### Context Example
```json
{
    "JAMF": {
        "MobileDevice": {
            "app_analytics": "Not Enabled",
            "asset_tag": "",
            "available": 250989,
            "available_mb": 250989,
            "battery_level": 65,
            "ble_capable": false,
            "bluetooth_mac_address": "F8:E9:4E:8C:34:F5",
            "capacity": 262144,
            "capacity_mb": 262144,
            "cloud_backup_enabled": true,
            "device_locator_service_enabled": true,
            "device_name": "\u05d6\u05d4\u05d1\u05d9\u05ea\u2019s iPhone",
            "device_ownership_level": "Institutional",
            "diagnostic_submission": "Not Enabled",
            "display_name": "\u05d6\u05d4\u05d1\u05d9\u05ea\u2019s iPhone",
            "do_not_disturb_enabled": false,
            "enrollment_method": "User-initiated - no invitation",
            "exchange_activesync_device_identifier": "U9J58M08ST4KHBH3FH15VD6KG1",
            "id": 114,
            "initial_entry_date_epoch": 1620740433498,
            "initial_entry_date_utc": "2021-05-11T13:40:33.498+0000",
            "ip_address": "123.243.192.22",
            "itunes_store_account_is_active": true,
            "last_backup_time_epoch": 0,
            "last_backup_time_utc": "",
            "last_cloud_backup_date_epoch": 0,
            "last_cloud_backup_date_utc": "",
            "last_enrollment_epoch": 1620741624868,
            "last_enrollment_utc": "2021-05-11T14:00:24.868+0000",
            "last_inventory_update": "Tuesday, May 11 2021 at 2:00 PM",
            "last_inventory_update_epoch": 1620741638658,
            "last_inventory_update_utc": "2021-05-11T14:00:38.658+0000",
            "location_services_enabled": false,
            "managed": false,
            "mdm_profile_expiration_epoch": 1683813623000,
            "mdm_profile_expiration_utc": "2023-05-11T14:00:23.000+0000",
            "model": "iPhone XS Max",
            "modelDisplay": "iPhone XS Max",
            "model_display": "iPhone XS Max",
            "model_identifier": "iPhone11,6",
            "model_number": "NT6J2LL",
            "modem_firmware": "3.03.05",
            "name": "test iPhone",
            "os_build": "18E212",
            "os_type": "iOS",
            "os_version": "14.5.1",
            "percentage_used": 4,
            "phone_number": "",
            "serial_number": "F2LXX5ZKKPHG",
            "shared": "No",
            "site": {
                "id": -1,
                "name": "None"
            },
            "supervised": false,
            "tethered": "",
            "udid": "00008020-001C285E3EE1002E",
            "wifi_mac_address": "F8:E9:4E:96:21:FB"
        }
    }
}
```

#### Human Readable Output

>### Jamf get mobile devices result on mobile ID:114
>|Bluetooth MAC address|ID|IP address|Managed|Model|Model Number|Name|Serial Number|Supervised|UDID|WIFI MAC address|
>|---|---|---|---|---|---|---|---|---|---|---|
>| F8:E9:4E:8C:34:F5 | 114 | 123.243.192.22 | false | iPhone XS Max | NT6J2LL | test iPhone | F2LXX5ZKKPHG | false | 00008020-001C285E3EE1002E | F8:E9:4E:96:21:FB |


### jamf-get-mobile-device-by-match
***
Matches mobile devices by specific characteristics and returns general data on each one of the mobile devices.


#### Base Command

`jamf-get-mobile-device-by-match`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

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
```!jamf-get-mobile-device-by-match match="B0:65:BD:4E:50:5D"```

#### Context Example
```json
{
    "JAMF": {
        "MobileDevice": {
            "Paging": {
                "current_page": 0,
                "page_size": 50,
                "total_results": 1
            },
            "building": "",
            "building_name": "",
            "department": "",
            "department_name": "",
            "email": "User28@email.com",
            "email_address": "User28@email.com",
            "id": 1,
            "mac_address": "B0:65:BD:4E:50:5D",
            "name": "Device 71",
            "position": "",
            "realname": "User 28",
            "room": "315 Graham Ave",
            "serial_number": "CA44F4D060A3",
            "udid": "ca44f4c660a311e490b812df261f2c7e",
            "username": "user28",
            "wifi_mac_address": "B0:65:BD:4E:50:5D"
        }
    }
}
```

#### Human Readable Output

>### Paging for get mobile devices
>|Current Page|Page Size|Total Results|
>|---|---|---|
>| 0 | 50 | 1 |

>### Jamf get mobile devices result 
>|ID|Name|Serial Number|UDID|
>|---|---|---|---|
>| 1 | Device 71 | CA44F4D060A3 | ca44f4c660a311e490b812df261f2c7e |


### jamf-get-mobile-device-general-subset
***
Returns the general subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-general-subset`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

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
```!jamf-get-mobile-device-general-subset identifier=id identifier_value=1```

#### Context Example
```json
{
    "JAMF": {
        "MobileDeviceSubset": {
            "mobiledevice": {
                "general": {
                    "app_analytics": "Not Enabled",
                    "asset_tag": "",
                    "available": 9341,
                    "available_mb": 9341,
                    "battery_level": 72,
                    "ble_capable": true,
                    "bluetooth_mac_address": "B0:65:BD:4E:50:2A",
                    "capacity": 12495,
                    "capacity_mb": 12495,
                    "cloud_backup_enabled": true,
                    "device_locator_service_enabled": false,
                    "device_name": "Device 71",
                    "device_ownership_level": "Institutional",
                    "diagnostic_submission": "Not Enabled",
                    "display_name": "Device 71",
                    "do_not_disturb_enabled": false,
                    "enrollment_method": "",
                    "exchange_activesync_device_identifier": "",
                    "id": 1,
                    "initial_entry_date_epoch": 1617021510106,
                    "initial_entry_date_utc": "2021-03-29T12:38:30.106+0000",
                    "ip_address": "71.13.172.131",
                    "itunes_store_account_is_active": true,
                    "last_backup_time_epoch": 0,
                    "last_backup_time_utc": "",
                    "last_cloud_backup_date_epoch": 1412270303000,
                    "last_cloud_backup_date_utc": "2014-10-02T17:18:23.000+0000",
                    "last_enrollment_epoch": 0,
                    "last_enrollment_utc": "",
                    "last_inventory_update": "Monday, March 29 2021 at 12:38 PM",
                    "last_inventory_update_epoch": 1617021510710,
                    "last_inventory_update_utc": "2021-03-29T12:38:30.710+0000",
                    "location_services_enabled": false,
                    "managed": true,
                    "mdm_profile_expiration_epoch": 0,
                    "mdm_profile_expiration_utc": "",
                    "model": "iPad 3rd Generation (Wi-Fi)",
                    "modelDisplay": "iPad 3rd Generation (Wi-Fi)",
                    "model_display": "iPad 3rd Generation (Wi-Fi)",
                    "model_identifier": "iPad3,1",
                    "model_number": "MD333LL",
                    "modem_firmware": "",
                    "name": "Device 71",
                    "os_build": "12A405",
                    "os_type": "iOS",
                    "os_version": "8.0.2",
                    "percentage_used": 25,
                    "phone_number": "",
                    "serial_number": "CA44F4D060A3",
                    "shared": "No",
                    "site": {
                        "id": -1,
                        "name": "None"
                    },
                    "supervised": false,
                    "tethered": "",
                    "udid": "ca44f4c660a311e490b812df261f2c7e",
                    "wifi_mac_address": "B0:65:BD:4E:50:5D"
                },
                "id": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf mobile device General subset result
>|Bluetooth MAC address|ID|IP address|Managed|Model|Model Number|Name|Serial Number|Supervised|UDID|WIFI MAC address|
>|---|---|---|---|---|---|---|---|---|---|---|
>| B0:65:BD:4E:50:2A | 1 | 71.13.172.131 | true | iPad 3rd Generation (Wi-Fi) | MD333LL | Device 71 | CA44F4D060A3 | false | ca44f4c660a311e490b812df261f2c7e | B0:65:BD:4E:50:5D |


### jamf-get-mobile-device-location-subset
***
Returns the location subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-location-subset`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

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
```!jamf-get-mobile-device-location-subset identifier=id identifier_value=1```

#### Context Example
```json
{
    "JAMF": {
        "MobileDeviceSubset": {
            "mobiledevice": {
                "id": 1,
                "location": {
                    "building": "",
                    "department": "",
                    "email_address": "User28@email.com",
                    "phone": "612-605-6625",
                    "phone_number": "612-605-6625",
                    "position": "",
                    "real_name": "User 28",
                    "realname": "User 28",
                    "room": "315 Graham Ave",
                    "username": "user28"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf mobile device Location subset result
>|Email Address|Phone|Real Name|Room|Username|
>|---|---|---|---|---|
>| User28@email.com | 612-605-6625 | User 28 | 315 Graham Ave | user28 |


### jamf-get-mobile-device-purchasing-subset
***
Returns the purchasing subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-purchasing-subset`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

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
```!jamf-get-mobile-device-purchasing-subset identifier=id identifier_value=114```

#### Context Example
```json
{
    "JAMF": {
        "MobileDeviceSubset": {
            "mobiledevice": {
                "id": 114,
                "purchasing": {
                    "applecare_id": "",
                    "attachments": [],
                    "is_leased": false,
                    "is_purchased": true,
                    "lease_expires": "",
                    "lease_expires_epoch": 0,
                    "lease_expires_utc": "",
                    "life_expectancy": 0,
                    "po_date": "",
                    "po_date_epoch": 0,
                    "po_date_utc": "",
                    "po_number": "",
                    "purchase_price": "",
                    "purchasing_account": "",
                    "purchasing_contact": "",
                    "vendor": "",
                    "warranty_expires": "",
                    "warranty_expires_epoch": 0,
                    "warranty_expires_utc": ""
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf mobile device Purchasing subset result
>|Is Leased|Is Purchased|
>|---|---|
>| false | true |


### jamf-get-mobile-device-applications-subset
***
Returns the applications subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-applications-subset`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

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
```!jamf-get-mobile-device-applications-subset identifier=id identifier_value=114```

#### Context Example
```json
{
    "JAMF": {
        "MobileDeviceSubset": {
            "mobiledevice": {
                "applications": [],
                "id": 114
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf mobile device Applications subset result
>|Number of applications|
>|---|
>| 0 |


### jamf-get-mobile-device-security-subset
***
Returns the security subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-security-subset`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

*Jamf Pro Server Actions → Send Mobile Device Lost Mode Command 

**Jamf Pro Server Actions → View Mobile Device Lost Mode Location

*In order to view these fields: |
| --- |
| lost_mode_enabled |  
| lost_mode_enforced |  
| lost_mode_enable_issued_epoch |  
| lost_mode_enable_issued_utc |  
| lost_mode_message |  
| lost_mode_phone |  
| lost_mode_footnote |  

** In order to view these fields (has to be combined with “Send Mobile Device Lost Mode Command” permission) |
| --- |
| lost_location_epoch |  
| lost_location_utc |  
| lost_location_latitude |  
| lost_location_longitude |  
| lost_location_altitude |  
| lost_location_speed |  
| lost_location_course |  
| lost_location_horizontal_accuracy |  
| lost_location_vertical_accuracy |  


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
```!jamf-get-mobile-device-security-subset identifier=id identifier_value=114```

#### Context Example
```json
{
    "JAMF": {
        "MobileDeviceSubset": {
            "mobiledevice": {
                "id": 114,
                "security": {
                    "activation_lock_enabled": true,
                    "block_level_encryption_capable": true,
                    "data_protection": true,
                    "file_level_encryption_capable": true,
                    "hardware_encryption": 3,
                    "jailbreak_detected": "Unknown",
                    "lost_location_altitude": -1,
                    "lost_location_course": -1,
                    "lost_location_epoch": 1624265477602,
                    "lost_location_horizontal_accuracy": -1,
                    "lost_location_latitude": 0,
                    "lost_location_longitude": 0,
                    "lost_location_speed": -1,
                    "lost_location_utc": "2021-06-21T08:51:17.602+0000",
                    "lost_location_vertical_accuracy": -1,
                    "lost_mode_enable_issued_epoch": 1620740433498,
                    "lost_mode_enable_issued_utc": "2021-05-11T13:40:33.498+0000",
                    "lost_mode_enabled": "Unsupervised Device",
                    "lost_mode_enforced": false,
                    "lost_mode_footnote": "",
                    "lost_mode_message": "",
                    "lost_mode_phone": "",
                    "passcode_compliant": true,
                    "passcode_compliant_with_profile": true,
                    "passcode_lock_grace_period_enforced": "Immediate",
                    "passcode_present": true
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf mobile device Security subset result
>|Activation Lock Enabled|Block Level Encryption Capable|Data Protection|File Level Encryption Capable|Hardware Encryption|Jailbreak Detected|Lost Mode Enable Issued UTC|Lost Mode Enabled|Lost Mode Enforced|Passcode Compliant|Passcode Lock Grace Period Enforced|Passcode Present|Phone|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | true | true | true | 3 | Unknown | 2021-05-11T13:40:33.498+0000 | Unsupervised Device | false | true | Immediate | true | true |


### jamf-get-mobile-device-network-subset
***
Returns the network subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-network-subset`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

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
```!jamf-get-mobile-device-network-subset identifier=id identifier_value=114```

#### Context Example
```json
{
    "JAMF": {
        "MobileDeviceSubset": {
            "mobiledevice": {
                "id": 114,
                "network": {
                    "carrier_settings_version": "",
                    "cellular_technology": "Both",
                    "current_carrier_network": "",
                    "current_mobile_country_code": "",
                    "current_mobile_network_code": "",
                    "data_roaming_enabled": false,
                    "home_carrier_network": "",
                    "home_mobile_country_code": "",
                    "home_mobile_network_code": "",
                    "iccid": "",
                    "imei": "35 727309 398808 9",
                    "meid": "35727309398808",
                    "phone_number": "",
                    "roaming": false,
                    "voice_roaming_enabled": "No"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf mobile device Network subset result
>|Cellular Technology|Data Roaming Enabled|Imei|Meid|Voice_roaming_enabled|
>|---|---|---|---|---|
>| Both | false | 35 727309 398808 9 | 35727309398808 | No |


### jamf-get-mobile-device-certificates-subset
***
Returns the certificates subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-certificates-subset`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

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
```!jamf-get-mobile-device-certificates-subset identifier=id identifier_value=114```

#### Context Example
```json
{
    "JAMF": {
        "MobileDeviceSubset": {
            "mobiledevice": {
                "certificates": [
                    {
                        "common_name": "F53DA0E7-9CEC-436E-90A4-0128769F5A2A",
                        "expires_epoch": "1683813623000",
                        "expires_utc": "2023-05-11T14:00:23.000+0000",
                        "identity": true
                    },
                    {
                        "common_name": "Palo Alto Networks JSS Built-in Certificate Authority",
                        "expires_epoch": "1930290855000",
                        "expires_utc": "2031-03-03T07:54:15.000+0000",
                        "identity": false
                    }
                ],
                "id": 114
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf mobile device Certificates subset result
>|Common Name|Expires Epoch|Expires UTC|Identity|
>|---|---|---|---|
>| F53DA0E7-9CEC-436E-90A4-0128769F5A2A | 1683813623000 | 2023-05-11T14:00:23.000+0000 | true |
>| Palo Alto Networks JSS Built-in Certificate Authority | 1930290855000 | 2031-03-03T07:54:15.000+0000 | false |


### jamf-get-mobile-device-provisioning-profiles-subset
***
Returns the provisioning profiles subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-provisioning-profiles-subset`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

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
```!jamf-get-mobile-device-provisioning-profiles-subset identifier=id identifier_value=114```

#### Context Example
```json
{
    "JAMF": {
        "MobileDeviceSubset": {
            "mobiledevice": {
                "id": 114,
                "provisioning_profiles": []
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf mobile device ProvisioningProfiles subset result
>**No entries.**


### jamf-get-mobile-device-configuration-profiles-subset
***
Returns the configuration profiles subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-configuration-profiles-subset`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

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
```!jamf-get-mobile-device-configuration-profiles-subset identifier=id identifier_value=114```

#### Context Example
```json
{
    "JAMF": {
        "MobileDeviceSubset": {
            "mobiledevice": {
                "configuration_profiles": [
                    {
                        "display_name": "MDM Profile",
                        "identifier": "00000000-0000-0000-A000-4A414D460003",
                        "uuid": "00000000-0000-0000-A000-4A414D460003",
                        "version": "1"
                    }
                ],
                "id": 114
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf mobile device ConfigurationProfiles subset result
>|Display Name|identifier|uuid|version|
>|---|---|---|---|
>| MDM Profile | 00000000-0000-0000-A000-4A414D460003 | 00000000-0000-0000-A000-4A414D460003 | 1 |


### jamf-get-mobile-device-groups-subset
***
Returns the mobile device groups subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-groups-subset`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

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
```!jamf-get-mobile-device-groups-subset identifier=id identifier_value=114```

#### Context Example
```json
{
    "JAMF": {
        "MobileDeviceSubset": {
            "mobiledevice": {
                "id": 114,
                "mobile_device_groups": []
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf mobile device MobileDeviceGroups subset result
>|Number of groups|
>|---|
>| 0 |


### jamf-get-mobile-device-extension-attributes-subset
***
Returns the extension attributes subset for a specific mobile device according to the given arguments.


#### Base Command

`jamf-get-mobile-device-extension-attributes-subset`

#### Required Permissions
Jamf Pro Server Objects → Mobile Devices → Read

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
```!jamf-get-mobile-device-extension-attributes-subset identifier=id identifier_value=114```

#### Context Example
```json
{
    "JAMF": {
        "MobileDeviceSubset": {
            "mobiledevice": {
                "extension_attributes": [
                    {
                        "id": 9,
                        "multi_value": false,
                        "name": "Asset Selector",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 4,
                        "multi_value": false,
                        "name": "rang",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 6,
                        "multi_value": false,
                        "name": "rangal",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 1,
                        "multi_value": false,
                        "name": "risk_test",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 2,
                        "multi_value": false,
                        "name": "Sample",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 5,
                        "multi_value": false,
                        "name": "Sample2",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 3,
                        "multi_value": false,
                        "name": "Sample4",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 7,
                        "multi_value": false,
                        "name": "Yuval Shapria",
                        "type": "String",
                        "value": ""
                    },
                    {
                        "id": 8,
                        "multi_value": false,
                        "name": "Yuval Shapria",
                        "type": "String",
                        "value": ""
                    }
                ],
                "id": 114
            }
        }
    }
}
```

#### Human Readable Output

>### Jamf mobile device ExtensionAttributes subset result
>|ID|Name|Type|Value|
>|---|---|---|---|
>| 9 | Asset Selector | String | false |
>| 4 | rang | String | false |
>| 6 | rangal | String | false |
>| 1 | risk_test | String | false |
>| 2 | Sample | String | false |
>| 5 | Sample2 | String | false |
>| 3 | Sample4 | String | false |
>| 7 | Yuval Shapria | String | false |
>| 8 | Yuval Shapria | String | false |


### jamf-get-computers-by-application
***
Returns a list of computers with basic information on each.


#### Base Command

`jamf-get-computers-by-application`

#### Required Permissions
Jamf Pro Server Objects → Advanced Computer Searches → Read

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
```!jamf-get-computers-by-application application=safar* limit=3```

#### Context Example
```json
{
    "JAMF": {
        "ComputersByApp": {
            "Paging": {
                "current_page": 0,
                "page_size": 3,
                "total_results": 96
            },
            "application": "safar*",
            "computers": [
                {
                    "id": 69,
                    "mac_address": "B8:E8:56:22:12:3E",
                    "name": "Computer 54",
                    "serial_number": "CA41014A60A3",
                    "udid": "CA410140-60A3-11E4-90B8-12DF261F2C7E"
                },
                {
                    "id": 25,
                    "mac_address": "40:6C:8F:1A:4B:10",
                    "name": "Computer 67",
                    "serial_number": "CA40EE4460A3",
                    "udid": "CA40EE3A-60A3-11E4-90B8-12DF261F2C7E"
                },
                {
                    "id": 24,
                    "mac_address": "00:88:65:41:14:B0",
                    "name": "Computer 31",
                    "serial_number": "CA40E50C60A3",
                    "udid": "CA40E502-60A3-11E4-90B8-12DF261F2C7E"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Paging for get mobile devices
>|Current Page|Page Size|Total Results|
>|---|---|---|
>| 0 | 3 | 96 |

>### Jamf computers by application result
>|Sum of computers|version|
>|---|---|
>| 2 | 14.0.3 |
>| 1 | 7.0 |
>| 1 | 7.0.1 |


### jamf-mobile-device-lost-mode
***
#### This is a beta command
This is a beta command - couldn't be tested due to technical limitations. Enables “lost mode” on a specific device. Lost Mode is a feature that allows you to lock a mobile device and track the device's location. The device reports the GPS coordinates of the point where the device received the command. This feature adds additional protection to mobile devices and their data in the event that a device is lost or stolen.


#### Base Command

`jamf-mobile-device-lost-mode`

#### Required Permissions
Jamf Pro Server Actions → Send Mobile Device Lost Mode Command

Jamf Pro Server Objects → Mobile Devices → Create

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
```jamf-mobile-device-lost-mode id=114 ```

#### Human Readable Output
>### Computer 114 locked successfully


### jamf-mobile-device-erase
***
#### This is a beta command
This is a beta command - couldn't be tested due to technical limitations. Permanently erases all data on the device and deactivates the device.


#### Base Command

`jamf-mobile-device-erase`

#### Required Permissions
Jamf Pro Server Actions → Send Mobile Device Remote Wipe Command

Jamf Pro Server Objects → Mobile Devices → Create

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
```jamf-mobile-device-erase id=114```

#### Human Readable Output

>### Computer 114 erased successfully

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
```!endpoint id=138```

#### Context Example
```json
{
    "Endpoint": {
        "Hostname": "test MacBook Pro",
        "ID": 138,
        "MACAddress": "F0:18:98:3F:DB:8E",
        "OS": "Mac",
        "Vendor": "JAMF v2"
    }
}
```

#### Human Readable Output

>### Cortex XDR Endpoint
>|Hostname|ID|MACAddress|OS|Vendor|
>|---|---|---|---|---|
>| test MacBook Pro | 138 | F0:18:98:3F:DB:8E | Mac | JAMF v2 |


### jamf-get-mobile-configuration-profiles-by-id

***
Returns the configuration profiles subset for a specific mobile device according to the given arguments.

#### Base Command

`jamf-get-mobile-configuration-profiles-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the mobile device. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.Mobile.ProfileConfiguration.general.id | Number | The ID of the configuration profile. | 
| JAMF.Mobile.ProfileConfiguration.general.name | String | The name of the configuration profile. | 
| JAMF.Mobile.ProfileConfiguration.general.description | String | The mobile device configuration description. | 
| JAMF.Mobile.ProfileConfiguration.general.level | String | Level of the configuration profile \(System or User\). | 
| JAMF.Mobile.ProfileConfiguration.general.site | String | Site of the configuration profile. | 
| JAMF.Mobile.ProfileConfiguration.general.category | String | Category of the configuration profile. | 
| JAMF.Mobile.ProfileConfiguration.general.uuid | String | Unique identifier of the mobile profile configuration. | 
| JAMF.Mobile.ProfileConfiguration.general.deployment_method | String | Install Automatically or Make Available in Self Service. | 
| JAMF.Mobile.ProfileConfiguration.general.payloads | String | Payloads of the configuration profile for Mobile device. | 
| JAMF.Mobile.ProfileConfiguration.scope | String | Scope object of the configuration profile. | 
| JAMF.Mobile.ProfileConfiguration.self_service | String | Self-service object of the configuration profile. | 

### jamf-get-computer-configuration-profiles-by-id

***
Returns the configuration profiles subset for a specific mobile device according to the given arguments.

#### Base Command

`jamf-get-computer-configuration-profiles-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the mobile device. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JAMF.OSX.ProfileConfiguration.general.id | Number | The ID of the configuration profile. | 
| JAMF.OSX.ProfileConfiguration.general.name | String | The name of the configuration profile. | 
| JAMF.OSX.ProfileConfiguration.general.description | unknown | The mobile device configuration description. | 
| JAMF.OSX.ProfileConfiguration.general.level | String | Level of the configuration profile \(System or User\). | 
| JAMF.OSX.ProfileConfiguration.general.site | String | Site of the configuration profile. | 
| JAMF.OSX.ProfileConfiguration.general.category | String | Category of the configuration profile. | 
| JAMF.OSX.ProfileConfiguration.general.uuid | String | Unique identifier of the mobile profile configuration. | 
| JAMF.OSX.ProfileConfiguration.general.distribution_method | String | Install Automatically or Make Available in Self Service. | 
| JAMF.OSX.ProfileConfiguration.general.payloads | String | Payloads of the configuration profile for OSX device. | 
| JAMF.OSX.ProfileConfiguration.scope | String | Scope object of the configuration profile. | 
| JAMF.OSX.ProfileConfiguration.self_service | String | Self-service object of the configuration profile. | 

