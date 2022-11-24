Google Workspace Mobile Management includes Android, Google Sync, iOS devices, and Google Chrome devices that run on ChromeOS.
This integration was integrated and tested with version xx of GoogleWorkspaceAdmin

## Configure Google Workspace Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Google Workspace Admin.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Customer ID | True |
    | User's Service Account JSON | True |
    | Use system proxy | False |
    | Trust any certificate | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### google-mobiledevice-action
***
Takes an action that affects a mobile device. For example, remotely wiping a device.


#### Base Command

`google-mobiledevice-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | The unique ID the API service uses to identify the mobile device. | Required | 
| action | The action to be performed on the device. Possible values are: admin_remote_wipe, admin_account_wipe, approve, block, cancel_remote_wipe_then_activate, cancel_remote_wipe_then_block. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Google.mobileAction.Response | String | Whether the action was successful or failure. | 
| Google.mobileAction.Reason | String | The reason the command failed. | 

### google-mobiledevice-list
***
Retrieves a paginated list that includes company-owned devices.


#### Base Command

`google-mobiledevice-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| projection | Whether to show all metadata fields, or only the basic metadata fields (e.g., deviceId, model, type, and status). Possible values are: BASIC, FULL. | Optional | 
| query | Search string in the format given at https://developers.google.com/admin-sdk/directory/v1/search-operators. | Optional | 
| order_by | Device property to use for sorting results. Possible values are: DEVICE_ID, EMAIL, LAST_SYNC, MODEL, NAME, OS, STATUS, TYPE. | Optional | 
| sort_order | Whether to return results in ascending or descending order. Must be used with the order_by parameter. Possible values are: ASCENDING, DESCENDING. | Optional | 
| limit | The maximum number of records to return from the collection. The default value is 50. | Optional | 
| page | The page number. | Optional | 
| page_size | The number of requested results per page. The default value is 50. Max allowed value is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Google.mobileEvent.resourceKind | String | Kind of resource this is. | 
| Google.mobileEvent.mobileListObjects | List | TA list of Mobile Device objects. | 
| Google.mobileEvent.mobileListObjects.kind | String | The type of the API resource. | 
| Google.mobileEvent.mobileListObjects.etag | String | ETag of the resource. | 
| Google.mobileEvent.mobileListObjects.resourceId | String | The unique ID the API service uses to identify the mobile device. | 
| Google.mobileEvent.mobileListObjects.deviceId | String | The serial number for a Google Sync mobile device. For Android and iOS devices, this is a software-generated unique identifier. | 
| Google.mobileEvent.mobileListObjects.name | List | A list of the owner's usernames. | 
| Google.mobileEvent.mobileListObjects.email | List | A list of the owner's email addresses. | 
| Google.mobileEvent.mobileListObjects.model | String | The mobile device's model name. | 
| Google.mobileEvent.mobileListObjects.os | String | The mobile device's operating system. | 
| Google.mobileEvent.mobileListObjects.type | String | The type of mobile device. | 
| Google.mobileEvent.mobileListObjects.status | String | The device's status. | 
| Google.mobileEvent.mobileListObjects.hardwareId | String | The IMEI/MEID unique identifier for Android hardware. | 
| Google.mobileEvent.mobileListObjects.firstSync | Date | The date and time the device was initially synchronized with the policy settings in the Admin console. | 
| Google.mobileEvent.mobileListObjects.lastSync | Date | The date and time the device was last synchronized with the policy settings in the Admin console. | 
| Google.mobileEvent.mobileListObjects.userAgent | String | Gives information about the device such as os version. | 
| Google.mobileEvent.mobileListObjects.serialNumber | String | The device's serial number. | 
| Google.mobileEvent.mobileListObjects.imei | String | The device's IMEI number. | 
| Google.mobileEvent.mobileListObjects.meid | String | The device's MEID number. | 
| Google.mobileEvent.mobileListObjects.wifiMacAddress | String | The device's MAC address on Wi-Fi networks. | 
| Google.mobileEvent.mobileListObjects.networkOperator | String | Mobile Device mobile or network operator. | 
| Google.mobileEvent.mobileListObjects.defaultLanguage | String | The default locale used on the device. | 
| Google.mobileEvent.mobileListObjects.managedAccountIsOnOwnerProfile | Boolean | Boolean indicating if this account is on owner/primary profile or not. | 
| Google.mobileEvent.mobileListObjects.deviceCompromisedStatus | String | The compromised device status. | 
| Google.mobileEvent.mobileListObjects.buildNumber | String | The device's operating system build number. | 
| Google.mobileEvent.mobileListObjects.kernelVersion | String | The device's kernel version. | 
| Google.mobileEvent.mobileListObjects.basebandVersion | String | The device's baseband version. | 
| Google.mobileEvent.mobileListObjects.unknownSourcesStatus | Boolean | Unknown sources enabled or disabled on device | 
| Google.mobileEvent.mobileListObjects.adbStatus | Boolean | Adb \(USB debugging\) enabled or disabled on device. | 
| Google.mobileEvent.mobileListObjects.developerOptionsStatus | Boolean | Developer options enabled or disabled on device. | 
| Google.mobileEvent.mobileListObjects.otherAccountsInfo | List | A list of accounts added on device. | 
| Google.mobileEvent.mobileListObjects.supportsWorkProfile | Boolean | Work profile supported on device. | 
| Google.mobileEvent.mobileListObjects.manufacturer | String | Mobile Device manufacturer. | 
| Google.mobileEvent.mobileListObjects.releaseVersion | String | Mobile Device release version version. | 
| Google.mobileEvent.mobileListObjects.securityPatchLevel | Date | Mobile Device Security patch level. | 
| Google.mobileEvent.mobileListObjects.brand | String | Mobile Device Brand. | 
| Google.mobileEvent.mobileListObjects.bootloaderVersion | String | Mobile Device Bootloader version. | 
| Google.mobileEvent.mobileListObjects.hardware | String | Mobile Device Hardware. | 
| Google.mobileEvent.mobileListObjects.encryptionStatus | String | Mobile Device Encryption Status. | 
| Google.mobileEvent.mobileListObjects.devicePasswordStatus | String | Device Password Status | 
| Google.mobileEvent.mobileListObjects.privilege | String | DM Agent Permission. | 
| Google.mobileEvent.mobileListObjects.applications.packageName | String | The application's package name. | 
| Google.mobileEvent.mobileListObjects.applications.displayName | String | The application's display name. | 
| Google.mobileEvent.mobileListObjects.applications.versionName | String | The application's version name. | 
| Google.mobileEvent.mobileListObjects.applications.versionCode | String | The application's version code. | 
| Google.mobileEvent.mobileListObjects.applications.permission | List | The list of permissions of this application. | 

#### Command example
```!google-mobiledevice-list projection=full order_by=NAME sort_order=descending page=2 page_size=3```
#### Context Example
```json
{
    "Google": {
        "mobileEvent": {
            "mobileListObjects": [
                {
                    "adbStatus": false,
                    "basebandVersion": "G960FXXU2BRJ1",
                    "bootloaderVersion": "G960FXXU2BRJ3",
                    "brand": "samsung",
                    "buildNumber": "R16NW.G960FXXU2BRJ3",
                    "defaultLanguage": "English",
                    "developerOptionsStatus": false,
                    "deviceCompromisedStatus": "No compromise detected",
                    "deviceId": "3c404c2af5fd57b7",
                    "devicePasswordStatus": "On",
                    "email": [
                        "yonah@demistodev.com",
                        "yonah@demistodev.com.test-google-a.com"
                    ],
                    "encryptionStatus": "Encrypted",
                    "etag": "\"eObIY8zBQ9kCV09ggrTpjfr4rItHeAuwxsjvkJMw5GI/F_tarXeKufZbbkRVoYbD3fEhjfY\"",
                    "firstSync": "2019-06-05T20:39:47.195Z",
                    "hardware": "samsungexynos9810",
                    "hardwareId": "357164099163035",
                    "imei": "357164099163035",
                    "kernelVersion": "4.9.59-14479316-QB20051937",
                    "kind": "admin#directory#mobiledevice",
                    "lastSync": "2019-06-06T04:53:44.556Z",
                    "managedAccountIsOnOwnerProfile": true,
                    "manufacturer": "samsung",
                    "meid": "",
                    "model": "SM-G960F",
                    "name": [
                        "Yonah Zucker"
                    ],
                    "networkOperator": "",
                    "os": "Android 8.0.0",
                    "privilege": "Device administrator",
                    "releaseVersion": "8.0.0",
                    "resourceId": "AFiQxQ8peh3r_xrCKZlbQAfc3AnFYsyQqjariFM-O3u7GMRyDACqTF4LyTji3vNWJbToIAdsiw-oXWmMIFZr3qkKh17iXYgdaAzqQrvOFPiRmqFpTgWcMTY",
                    "securityPatchLevel": "1538377200000",
                    "serialNumber": "22caa250a70d7ece",
                    "status": "APPROVED",
                    "supportsWorkProfile": true,
                    "type": "ANDROID",
                    "unknownSourcesStatus": true,
                    "userAgent": "Google Apps Device Policy 12.14.01",
                    "wifiMacAddress": ""
                },
                {
                    "adbStatus": false,
                    "basebandVersion": "",
                    "bootloaderVersion": "",
                    "brand": "",
                    "buildNumber": "",
                    "defaultLanguage": "",
                    "developerOptionsStatus": false,
                    "deviceCompromisedStatus": "Undetected",
                    "deviceId": "1A269559-EC7F-44C5-816F-414DF3410482",
                    "devicePasswordStatus": "On",
                    "email": [
                        "admin@demistodev.com",
                        "admin@demistodev.com.test-google-a.com"
                    ],
                    "encryptionStatus": "",
                    "etag": "\"eObIY8zBQ9kCV09ggrTpjfr4rItHeAuwxsjvkJMw5GI/KkFzEqc-FX2_ufEwkUTwRrGqm-M\"",
                    "firstSync": "2018-11-17T16:43:09.118Z",
                    "hardware": "",
                    "hardwareId": "",
                    "imei": "",
                    "kernelVersion": "",
                    "kind": "admin#directory#mobiledevice",
                    "lastSync": "2018-11-18T13:58:09.109Z",
                    "managedAccountIsOnOwnerProfile": false,
                    "manufacturer": "",
                    "meid": "",
                    "model": "iPhone10,6",
                    "name": [
                        "Tomer Malache"
                    ],
                    "networkOperator": "",
                    "os": "",
                    "privilege": "Undetected",
                    "releaseVersion": "",
                    "resourceId": "AFiQxQ8ZbgKGsO-3ts-8_2rW0BXjBduEb2NvgwFwNOsBRqWlG_vJMuE0fN1C6l1ncLu6e_SWWfkl3fwciVaXHDJF1XP5irsvY0JVaJ-NTyeBFGpZJYeg52GdY0hYj6Tc7_czaOiU4iAt",
                    "securityPatchLevel": "0",
                    "serialNumber": "",
                    "status": "APPROVED",
                    "supportsWorkProfile": false,
                    "type": "IOS_SYNC",
                    "unknownSourcesStatus": false,
                    "userAgent": "",
                    "wifiMacAddress": ""
                },
                {
                    "adbStatus": false,
                    "basebandVersion": "M8994F-2.6.37.2.21",
                    "bootloaderVersion": "BHZ11l",
                    "brand": "google",
                    "buildNumber": "N2G47F",
                    "defaultLanguage": "English",
                    "developerOptionsStatus": false,
                    "deviceCompromisedStatus": "No compromise detected",
                    "deviceId": "311fc9cb34adecd6",
                    "devicePasswordStatus": "Off",
                    "email": [
                        "admin@demistodev.com",
                        "admin@demistodev.com.test-google-a.com"
                    ],
                    "encryptionStatus": "Encrypted",
                    "etag": "\"eObIY8zBQ9kCV09ggrTpjfr4rItHeAuwxsjvkJMw5GI/58hhSOIVYHZK0giymcZRWGA_GhA\"",
                    "firstSync": "2017-07-24T10:06:19.002Z",
                    "hardware": "bullhead",
                    "hardwareId": "0261924438872213",
                    "imei": "",
                    "kernelVersion": "3.10.73-ge570678",
                    "kind": "admin#directory#mobiledevice",
                    "lastSync": "2017-11-12T08:36:36.049Z",
                    "managedAccountIsOnOwnerProfile": true,
                    "manufacturer": "LGE",
                    "meid": "",
                    "model": "Nexus 5X",
                    "name": [
                        "Tomer Malache"
                    ],
                    "networkOperator": "",
                    "os": "Android 7.1.2",
                    "privilege": "Device administrator",
                    "releaseVersion": "7.1.2",
                    "resourceId": "AFiQxQ86htIA8RbY0ayqfHl2NOPVfZCnClZd1Iw7KhGBrwi92qKlwe6_GdtNea6jBBGJb_bLuaWAEbwPBEr_eAQ_AVMnXS_1Lxq3e6qppvMDta7GSTlEvoY",
                    "securityPatchLevel": "1491375600000",
                    "serialNumber": "0261924438872213",
                    "status": "APPROVED",
                    "supportsWorkProfile": true,
                    "type": "ANDROID",
                    "unknownSourcesStatus": false,
                    "userAgent": "Google Apps Device Policy 7.74",
                    "wifiMacAddress": ""
                }
            ],
            "resourceKind": "admin#directory#mobiledevices"
        }
    }
}
```

#### Human Readable Output

>### Google Workspace Admin - Mobile Devices List
>|Serial Number|User Names|Model Name|OS|Type|Status|
>|---|---|---|---|---|---|
>| 3c404c2af5fd57b7 | Yonah Zucker | SM-G960F | Android 8.0.0 | ANDROID | APPROVED |
>| 1A269559-EC7F-44C5-816F-414DF3410482 | Tomer Malache | iPhone10,6 |  | IOS_SYNC | APPROVED |
>| 311fc9cb34adecd6 | Tomer Malache | Nexus 5X | Android 7.1.2 | ANDROID | APPROVED |


#### Command example
```!google-mobiledevice-list projection=full order_by=NAME sort_order=descending limit=3```
#### Context Example
```json
{
    "Google": {
        "mobileEvent": {
            "mobileListObjects": [
                {
                    "adbStatus": true,
                    "basebandVersion": "G960FXXU2BRJ1",
                    "bootloaderVersion": "G960FXXU2BRJ3",
                    "brand": "samsung",
                    "buildNumber": "R16NW.G960FXXU2BRJ3",
                    "defaultLanguage": "English",
                    "developerOptionsStatus": true,
                    "deviceCompromisedStatus": "No compromise detected",
                    "deviceId": "33ab1f067ccf2ce4",
                    "devicePasswordStatus": "On",
                    "email": [
                        "yonah-admin@demistodev.com",
                        "yonah-admin@demistodev.com.test-google-a.com"
                    ],
                    "encryptionStatus": "Encrypted",
                    "etag": "\"eObIY8zBQ9kCV09ggrTpjfr4rItHeAuwxsjvkJMw5GI/e4DJG5lu8Z6OZuxU_DT9RPZ0uCw\"",
                    "firstSync": "2020-01-23T14:30:23.686Z",
                    "hardware": "samsungexynos9810",
                    "hardwareId": "357164099163035",
                    "imei": "357164099163035",
                    "kernelVersion": "4.9.59-14479316-QB20051937",
                    "kind": "admin#directory#mobiledevice",
                    "lastSync": "2020-01-23T14:30:40.406Z",
                    "managedAccountIsOnOwnerProfile": true,
                    "manufacturer": "samsung",
                    "meid": "",
                    "model": "SM-G960F",
                    "name": [
                        "yonah-admin Zucker"
                    ],
                    "networkOperator": "Cellcom",
                    "os": "Android 8.0.0",
                    "privilege": "Undetected",
                    "releaseVersion": "8.0.0",
                    "resourceId": "AFiQxQ9mGdZgqQVoA2jLVVOXkv7ZaD_SDog2U2eoqsn_yvHiADwh61egLnlWSt05zCEzmhWCGj86OfsoyLEEWfRnZrPuUeOL5qDw4U6jFeTz_r9RnueikQ4",
                    "securityPatchLevel": "1538377200000",
                    "serialNumber": "22caa250a70d7ece",
                    "status": "WIPING",
                    "supportsWorkProfile": true,
                    "type": "ANDROID",
                    "unknownSourcesStatus": true,
                    "userAgent": "Google Apps Device Policy 14.20.00",
                    "wifiMacAddress": ""
                },
                {
                    "adbStatus": true,
                    "basebandVersion": "G960FXXU2CSB3",
                    "bootloaderVersion": "G960FXXU2CSB9",
                    "brand": "samsung",
                    "buildNumber": "PPR1.180610.011.G960FXXU2CSB9",
                    "defaultLanguage": "English",
                    "developerOptionsStatus": true,
                    "deviceCompromisedStatus": "No compromise detected",
                    "deviceId": "33ab1f067ccf2ce4",
                    "devicePasswordStatus": "On",
                    "email": [
                        "yonah@demistodev.com",
                        "yonah@demistodev.com.test-google-a.com"
                    ],
                    "encryptionStatus": "Encrypted",
                    "etag": "\"eObIY8zBQ9kCV09ggrTpjfr4rItHeAuwxsjvkJMw5GI/4Ulaae77oYUNI1Hs7bL9u2by89Q\"",
                    "firstSync": "2020-01-23T14:34:34.623Z",
                    "hardware": "samsungexynos9810",
                    "hardwareId": "357164099163035",
                    "imei": "357164099163035",
                    "kernelVersion": "4.9.59-15367606",
                    "kind": "admin#directory#mobiledevice",
                    "lastSync": "2021-12-10T10:50:06.711Z",
                    "managedAccountIsOnOwnerProfile": true,
                    "manufacturer": "samsung",
                    "meid": "",
                    "model": "SM-G960F",
                    "name": [
                        "Yonah Zucker"
                    ],
                    "networkOperator": "Cellcom",
                    "os": "Android 9",
                    "privilege": "Device administrator",
                    "releaseVersion": "9",
                    "resourceId": "AFiQxQ8peh3r_xrCKZlbQAfc3AnFW8X8ExOZ3FsdN8Sc2Q1R1uV5zCjoWoQUVGEHoXjcQWi2ehCtH0xVkrxSrInRi9DKTxtwicIB6DWiARj_tgF16TiyzWM",
                    "securityPatchLevel": "1549008000000",
                    "serialNumber": "22caa250a70d7ece",
                    "status": "APPROVED",
                    "supportsWorkProfile": true,
                    "type": "ANDROID",
                    "unknownSourcesStatus": true,
                    "userAgent": "Google Apps Device Policy 17.87.03",
                    "wifiMacAddress": ""
                },
                {
                    "adbStatus": false,
                    "basebandVersion": "",
                    "bootloaderVersion": "",
                    "brand": "",
                    "buildNumber": "",
                    "defaultLanguage": "",
                    "developerOptionsStatus": false,
                    "deviceCompromisedStatus": "Undetected",
                    "deviceId": "1755B888-B091-4465-954D-0B0EFA8FA113",
                    "devicePasswordStatus": "On",
                    "email": [
                        "yonah@demistodev.com",
                        "yonah@demistodev.com.test-google-a.com"
                    ],
                    "encryptionStatus": "",
                    "etag": "\"eObIY8zBQ9kCV09ggrTpjfr4rItHeAuwxsjvkJMw5GI/55kcC_h5kbF3AqPrrkpwl93ThzQ\"",
                    "firstSync": "2019-06-17T08:08:53.683Z",
                    "hardware": "",
                    "hardwareId": "",
                    "imei": "",
                    "kernelVersion": "",
                    "kind": "admin#directory#mobiledevice",
                    "lastSync": "2019-12-02T06:17:34.853Z",
                    "managedAccountIsOnOwnerProfile": false,
                    "manufacturer": "",
                    "meid": "",
                    "model": "iPhone8,1",
                    "name": [
                        "Yonah Zucker"
                    ],
                    "networkOperator": "",
                    "os": "iOS 13.1.2",
                    "privilege": "Undetected",
                    "releaseVersion": "",
                    "resourceId": "AFiQxQ9uIWvIyVTiCNujXIEvkwz_w4DCL97pOpA0DpQSpXkgYHL23PlZQ3h456yh2YgZiuw6qZaFcBItEKzcg3B3MXG6RZWcgMVcddEJthwHskvHEp48tr5sASyDCaToUAe9oWP4EL9g",
                    "securityPatchLevel": "0",
                    "serialNumber": "",
                    "status": "APPROVED",
                    "supportsWorkProfile": false,
                    "type": "IOS_SYNC",
                    "unknownSourcesStatus": false,
                    "userAgent": "",
                    "wifiMacAddress": ""
                }
            ],
            "resourceKind": "admin#directory#mobiledevices"
        }
    }
}
```

#### Human Readable Output

>### Google Workspace Admin - Mobile Devices List
>3 results were found
>|Serial Number|User Names|Model Name|OS|Type|Status|
>|---|---|---|---|---|---|
>| 33ab1f067ccf2ce4 | yonah-admin Zucker | SM-G960F | Android 8.0.0 | ANDROID | WIPING |
>| 33ab1f067ccf2ce4 | Yonah Zucker | SM-G960F | Android 9 | ANDROID | APPROVED |
>| 1755B888-B091-4465-954D-0B0EFA8FA113 | Yonah Zucker | iPhone8,1 | iOS 13.1.2 | IOS_SYNC | APPROVED |


### google-chromeosdevice-list
***
Retrieves a paginated list of company-owned ChromeOS devices.


#### Base Command

`google-chromeosdevice-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| projection | Whether to show all metadata fields, or only the basic metadata fields (e.g., deviceId, serialNumber, status, and user). Possible values are: BASIC, FULL. | Optional | 
| query | Search string in the format given at https://developers.google.com/admin-sdk/directory/v1/list-query-operators. | Optional | 
| order_by | Device property to use for sorting results. Possible values are: ANNOTATED_LOCATION, ANNOTATED_USER, LAST_SYNC, NOTES, SERIAL_NUMBER, STATUS. | Optional | 
| sort_order | Whether to return results in ascending or descending order. Must be used with the order_by parameter. Possible values are: ASCENDING, DESCENDING. | Optional | 
| org_unit_path | The full path of the organizational unit (minus the leading /) or its unique ID. | Optional | 
| include_child_org_units | Whether to return devices from all child orgunits. Possible values are: yes, no. | Optional | 
| limit | The maximum number of records to return from the collection. The default value is 50. | Optional | 
| page | The page number. | Optional | 
| page_size | The number of requested results per page. The default value is 50. Max allowed value is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Google.chromeosEvent.resourceKind | String | Kind of resource this is. | 
| Google.chromeosEvent.chromeosListObjects | List | A list of Chrome OS Device objects. | 
| Google.chromeosEvent.chromeosListObjects.deviceId | String | The unique ID of the Chrome device. | 
| Google.chromeosEvent.chromeosListObjects.serialNumber | String | The Chrome device serial number entered when the device was enabled. | 
| Google.chromeosEvent.chromeosListObjects.status | String | Status of the device. | 
| Google.chromeosEvent.chromeosListObjects.lastSync | String | The date and time the device was last synchronized with the policy settings in the Admin console. | 
| Google.chromeosEvent.chromeosListObjects.supportEndDate | String | The final date the device will be supported. | 
| Google.chromeosEvent.chromeosListObjects.annotatedUser | String | The user of the device as noted by the administrator. | 
| Google.chromeosEvent.chromeosListObjects.annotatedLocation | String | The address or location of the device as noted by the administrator. | 
| Google.chromeosEvent.chromeosListObjects.notes | String | Notes about this device added by the administrator. | 
| Google.chromeosEvent.chromeosListObjects.model | String | The device's model information. | 
| Google.chromeosEvent.chromeosListObjects.meid | String | The Mobile Equipment Identifier \(MEID\) or the International Mobile Equipment Identity \(IMEI\) for the 3G mobile card in a mobile device. | 
| Google.chromeosEvent.chromeosListObjects.orderNumber | String | The device's order number. | 
| Google.chromeosEvent.chromeosListObjects.willAutoRenew | Boolean | Determines if the device will auto renew its support after the support end date. | 
| Google.chromeosEvent.chromeosListObjects.osVersion | String | The Chrome device's operating system version. | 
| Google.chromeosEvent.chromeosListObjects.platformVersion | String | The Chrome device's platform version. | 
| Google.chromeosEvent.chromeosListObjects.firmwareVersion | String | The Chrome device's firmware version. | 
| Google.chromeosEvent.chromeosListObjects.macAddress | String | The device's wireless MAC address. | 
| Google.chromeosEvent.chromeosListObjects.bootMode | String | The boot mode for the device. | 
| Google.chromeosEvent.chromeosListObjects.lastEnrollmentTime | String | The date and time the device was last enrolled. | 
| Google.chromeosEvent.chromeosListObjects.kind | String | The type of resource. | 
| Google.chromeosEvent.chromeosListObjects.recentUsers | List | A list of recent device users, in descending order, by last login time. | 
| Google.chromeosEvent.chromeosListObjects.recentUsers.type | String | The type of the user. | 
| Google.chromeosEvent.chromeosListObjects.recentUsers.email | String | The user's email address. | 
| Google.chromeosEvent.chromeosListObjects.activeTimeRanges | List | A list of active time ranges. | 
| Google.chromeosEvent.chromeosListObjects.activeTimeRanges.activeTime | Integer | Duration of usage in milliseconds. | 
| Google.chromeosEvent.chromeosListObjects.activeTimeRanges.date | Integer | Date of usage. | 
| Google.chromeosEvent.chromeosListObjects.ethernetMacAddress | String | The device's MAC address on the ethernet network interface. | 
| Google.chromeosEvent.chromeosListObjects.annotatedAssetId | String | The asset identifier as noted by an administrator or specified during enrollment. | 
| Google.chromeosEvent.chromeosListObjects.etag | String | ETag of the resource. | 
| Google.chromeosEvent.chromeosListObjects.diskVolumeReports | List | Reports of disk space and other info about mounted/connected volumes. | 
| Google.chromeosEvent.chromeosListObjects.diskVolumeReports.volumeInfo | List | Disk volumes. | 
| Google.chromeosEvent.chromeosListObjects.diskVolumeReports.volumeInfo.volumeId | String | Volume id. | 
| Google.chromeosEvent.chromeosListObjects.diskVolumeReports.volumeInfo.storageTotal | String | Total disk space \[in bytes\]. | 
| Google.chromeosEvent.chromeosListObjects.diskVolumeReports.volumeInfo.storageFree | String | Free disk space \[in bytes\]. | 
| Google.chromeosEvent.chromeosListObjects.systemRamTotal | String | Total RAM on the device in bytes. | 
| Google.chromeosEvent.chromeosListObjects.cpuStatusReports | List | Reports of CPU utilization and temperature. | 
| Google.chromeosEvent.chromeosListObjects.cpuStatusReports.reportTime | String | Date and time the report was received. | 
| Google.chromeosEvent.chromeosListObjects.cpuStatusReports.cpuUtilizationPercentageInfo | List |  | 
| Google.chromeosEvent.chromeosListObjects.cpuStatusReports.cpuTemperatureInfo | List | A list of CPU temperature samples. | 
| Google.chromeosEvent.chromeosListObjects.cpuStatusReports.cpuTemperatureInfo.temperature | Integer | Temperature in Celsius degrees. | 
| Google.chromeosEvent.chromeosListObjects.cpuStatusReports.cpuTemperatureInfo.label | String | CPU label. | 
| Google.chromeosEvent.chromeosListObjects.cpuInfo | List | Information regarding CPU specs in the device. | 
| Google.chromeosEvent.chromeosListObjects.cpuInfo.model | String | The CPU model name. | 
| Google.chromeosEvent.chromeosListObjects.cpuInfo.architecture | String | The CPU architecture. | 
| Google.chromeosEvent.chromeosListObjects.cpuInfo.maxClockSpeedKhz | Integer | The max CPU clock speed in kHz. | 
| Google.chromeosEvent.chromeosListObjects.cpuInfo.logicalCpus | List | Information for the Logical CPUs. | 
| Google.chromeosEvent.chromeosListObjects.cpuInfo.logicalCpus.maxScalingFrequencyKhz | Integer | Maximum frequency the CPU is allowed to run at, by policy. | 
| Google.chromeosEvent.chromeosListObjects.cpuInfo.logicalCpus.currentScalingFrequencyKhz | Integer | Current frequency the CPU is running at. | 
| Google.chromeosEvent.chromeosListObjects.cpuInfo.logicalCpus.idleDuration | String | Idle time since last boot. | 
| Google.chromeosEvent.chromeosListObjects.cpuInfo.logicalCpus.cStates | List | C-States indicate the power consumption state of the CPU. For more information look at documentation published by the CPU maker. | 
| Google.chromeosEvent.chromeosListObjects.cpuInfo.logicalCpus.cStates.displayName | String | Name of the state. | 
| Google.chromeosEvent.chromeosListObjects.cpuInfo.logicalCpus.cStates.sessionDuration | String | Time spent in the state since the last reboot. | 
| Google.chromeosEvent.chromeosListObjects.deviceFiles | List | A list of device files to download. | 
| Google.chromeosEvent.chromeosListObjects.deviceFiles.name | String | File name. | 
| Google.chromeosEvent.chromeosListObjects.deviceFiles.type | String | File type. | 
| Google.chromeosEvent.chromeosListObjects.deviceFiles.downloadUrl | String | File download URL. | 
| Google.chromeosEvent.chromeosListObjects.deviceFiles.createTime | String | Date and time the file was created. | 
| Google.chromeosEvent.chromeosListObjects.deviceFiles.createTime | String | Date and time the file was created. | 
| Google.chromeosEvent.chromeosListObjects.systemRamFreeReports | List | Reports of amounts of available RAM memory. | 
| Google.chromeosEvent.chromeosListObjects.systemRamFreeReports.reportTime | String | Date and time the report was received. | 
| Google.chromeosEvent.chromeosListObjects.systemRamFreeReports.systemRamFreeInfo | List |  | 
| Google.chromeosEvent.chromeosListObjects.lastKnownNetwork | List | Contains last known network. | 
| Google.chromeosEvent.chromeosListObjects.lastKnownNetwork.ipAddress | String | The IP address. | 
| Google.chromeosEvent.chromeosListObjects.lastKnownNetwork.wanIpAddress | String | The WAN IP address. | 
| Google.chromeosEvent.chromeosListObjects.autoUpdateExpiration | String | The timestamp after which the device will stop receiving Chrome updates or support. | 
| Google.chromeosEvent.chromeosListObjects.ethernetMacAddress0 | String | MAC address used by the Chromebook's internal ethernet port, and for onboard network \(ethernet\) interface. The format is twelve \(12\) hexadecimal digits without any delimiter \(uppercase letters\). This is only relevant for some devices. | 
| Google.chromeosEvent.chromeosListObjects.dockMacAddress | String | Built-in MAC address for the docking station that the device connected to. Factory sets Media access control address \(MAC address\) assigned for use by a dock. It is reserved specifically for MAC pass through device policy. The format is twelve \(12\) hexadecimal digits without any delimiter \(uppercase letters\). This is only relevant for some devices. | 
| Google.chromeosEvent.chromeosListObjects.manufactureDate | String | The date the device was manufactured in yyyy-mm-dd format. | 
| Google.chromeosEvent.chromeosListObjects.orgUnitPath | String | The full parent path with the organizational unit's name associated with the device. Path names are case insensitive. If the parent organizational unit is the top-level organization, it is represented as a forward slash, /. | 
| Google.chromeosEvent.chromeosListObjects.tpmVersionInfo | Object | Trusted Platform Module \(TPM\). | 
| Google.chromeosEvent.chromeosListObjects.tpmVersionInfo.family | String | TPM family, using the TPM 2.0 style encoding. | 
| Google.chromeosEvent.chromeosListObjects.tpmVersionInfo.specLevel | String | TPM specification level. | 
| Google.chromeosEvent.chromeosListObjects.tpmVersionInfo.manufacturer | String | TPM manufacturer code. | 
| Google.chromeosEvent.chromeosListObjects.tpmVersionInfo.tpmModel | String | TPM model number. | 
| Google.chromeosEvent.chromeosListObjects.tpmVersionInfo.firmwareVersion | String | TPM firmware version. | 
| Google.chromeosEvent.chromeosListObjects.tpmVersionInfo.vendorSpecific | String | Vendor-specific information such as Vendor ID. | 
| Google.chromeosEvent.chromeosListObjects.screenshotFiles | List | A list of screenshot files to download. | 
| Google.chromeosEvent.chromeosListObjects.screenshotFiles.name | String | File name. | 
| Google.chromeosEvent.chromeosListObjects.screenshotFiles.type | String | File type. | 
| Google.chromeosEvent.chromeosListObjects.screenshotFiles.downloadUrl | String | File download URL. | 
| Google.chromeosEvent.chromeosListObjects.screenshotFiles.createTime | String | Date and time the file was created. | 
| Google.chromeosEvent.chromeosListObjects.orgUnitId | String | The unique ID of the organizational unit. orgUnitPath is the human readable version of orgUnitId. While orgUnitPath may change by renaming an organizational unit within the path, orgUnitId is unchangeable for one organizational unit. | 
| Google.chromeosEvent.chromeosListObjects.osUpdateStatus | Object | The status of the OS updates for the device. | 
| Google.chromeosEvent.chromeosListObjects.osUpdateStatus.state | String | The update state of an OS update. | 
| Google.chromeosEvent.chromeosListObjects.osUpdateStatus.targetOsVersion | String | New platform version of the OS image being downloaded and applied. | 
| Google.chromeosEvent.chromeosListObjects.osUpdateStatus.targetKioskAppVersion | String | New required platform version from the pending updated kiosk app. | 
| Google.chromeosEvent.chromeosListObjects.osUpdateStatus.updateTime | String | Date and time of the last successful OS update. | 
| Google.chromeosEvent.chromeosListObjects.osUpdateStatus.updateCheckTime | String | Date and time of the last update check. | 
| Google.chromeosEvent.chromeosListObjects.osUpdateStatus.rebootTime | String | Date and time of the last reboot. | 
| Google.chromeosEvent.chromeosListObjects.firstEnrollmentTime | String | Date and time for the first time the device was enrolled. | 

### google-chromeosdevice-action
***
Takes an action that affects a ChromeOS Device. This includes deprovisioning, disabling, and re-enabling devices.


#### Base Command

`google-chromeosdevice-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | The unique ID of the device. | Required | 
| action | The action to be performed on the ChromeOS device. Possible values are: deprovision, disable, reenable, pre_provisioned_disable, pre_provisioned_reenable. | Required | 
| deprovision_reason | Only used when the action is deprovision. With the deprovision action, this field is required. Possible values are: different_model_replacement, retiring_device, same_model_replacement, upgrade_transfer. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Google.mobileAction.Response | String | Whether the action was successful or failure. | 
| Google.mobileAction.Reason | String | The reason the command failed. | 
