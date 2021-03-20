# MobileIron CLOUD Integration

## MobileIron Cloud - Getting Started

1. Log in to the MobileIron Cloud Admin console.
2. Open the users section.
3. Click the create user button and select the option to create a new API user. It is recommended to create a new user for the Cortex XSOAR integration specifically and not reuse
an existing one.  
4. Fill in all the required details (i.e., use demisto-api-user as the username) and make sure you enter a strong password.
5. When setting up the Cortex XSOAR integration, use the auto-generated email address as the username and the password you 
defined as the MobileIron tenant credentials.
6. Click the `Test` button and ensure the connection can be established.

Refer to the API documentation at the MobileIron community for more details on setting up the API user.

### MobileIron Cloud - Spaces

If you are dividing the devices into different spaces, it is important to make sure the integration
points to the correct `Partition ID (Device Space ID)`.
 
You should leave this value blank if you are not using spaces or if you want the integration to automatically resolve the 
default space ID.

### Setting up pre-processing rules

If you are using the fetch incidents option, we recommend to set-up a pre-processing rule in order
to filter out any duplicates that might show up as part of the command. 

- In the Cortex XSOAR admin go to Settings -> Integrations -> Pre-Processing Rules
- In *Step 1* add a rule for *Type* equals *MobileIron Cloud Device Incident*.
- In *Step 2* select *Drop and Update*.
- In *Step 3* select *Link to oldest incident* created within the last *15 days* and check the checkbox next to 
*Search closed incidents* .
- Add an *AND* statement and enter *MobileIron Device ID* of existing incident is identical to the one of the incoming incident.
- Save the rule.

Here is an example image of the rule

![Pre-Processing Rules Example](../../doc_files/preprocess_rules.png) 

## Configure MobileIronCLOUD on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MobileIronCLOUD.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Server URL \(i.e., https://eu1.mobileiron.com \) | True |
    | credentials | User Name | True |
    | incidentType | Incident type | False |
    | partition_id | Partition ID \(leave empty to resolve default\) | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | fetch_interval | Fetch Interval \(in minutes\) | True |
    | max_fetch | Maximum number of incidents per fetch | False |
    | isFetch | Fetch incidents | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### mobileiron-cloud-get-devices-data
***
Gets all the devices based on a particular filter query. The command might execute multiple API calls depending on the amount of devices that would be returned.


#### Base Command

`mobileiron-cloud-get-devices-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Filter query for fetching the device data. Default is registrationState=ACTIVE. | Optional | 
| max_fetch | The maximum number of items returned in the list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCloud.Device.id | Number | ID of the device that is fetched. | 
| MobileIronCloud.Device.guid | String | GUID of the device that is fetched. | 
| MobileIronCloud.Device.deviceModel | String | Model of the device that is fetched. | 
| MobileIronCloud.Device.deviceName | String | Name of the device that is fetched. | 
| MobileIronCloud.Device.platformType | String | Platform type of the device that is fetched. | 
| MobileIronCloud.Device.platformVersion | String | Platform version of the device that is fetched. | 
| MobileIronCloud.Device.osBuildVersion | String | Operating system build version of the device that is fetched. | 
| MobileIronCloud.Device.lastCheckin | Date | Last check in time of the device that is fetched. | 
| MobileIronCloud.Device.registrationState | String | Registration state of the device that is fetched. | 
| MobileIronCloud.Device.displayName | String | Display name of the device that is fetched. | 
| MobileIronCloud.Device.firstName | String | First name of the device that is fetched. | 
| MobileIronCloud.Device.lastName | String | Last name of the device that is fetched. | 
| MobileIronCloud.Device.uid | String | UID of the device that is fetched. | 
| MobileIronCloud.Device.emailAddress | String | Email address of the device that is fetched. | 
| MobileIronCloud.Device.manufacturer | String | Manufacturer of the device that is fetched. | 
| MobileIronCloud.Device.imei | Unknown | International Mobile Equipment Identity (IMEI) of the device that is fetched. | 
| MobileIronCloud.Device.imei2 | Unknown | International Mobile Equipment Identity 2 (IME2) of the device that is fetched. | 
| MobileIronCloud.Device.imsi | String | International Mobile Subscriber Identity (IMSI) of the device that is fetched. | 
| MobileIronCloud.Device.wifiMacAddress | String | WiFi MAC address of the device that is fetched. | 
| MobileIronCloud.Device.serialNumber | Unknown | Serial number of the device that is fetched. | 
| MobileIronCloud.Device.altSerialNumber | Unknown | Alternative serial number of the device that is fetched. | 
| MobileIronCloud.Device.ownershipType | String | Ownership type of the device that is fetched. | 
| MobileIronCloud.Device.complianceState | Boolean | Compliance state of the device that is fetched. | 
| MobileIronCloud.Device.roaming | Boolean | Roaming status of the device that is fetched. | 
| MobileIronCloud.Device.supervised | Unknown | Device supervised. | 
| MobileIronCloud.Device.udid | String | UDID of the device that is fetched. | 
| MobileIronCloud.Device.policyViolationCount | Number | Policy violation count of the device that is fetched. | 
| MobileIronCloud.Device.lastRegistrationTime | Date | Last registration time of the device that is fetched. | 
| MobileIronCloud.Device.quarantined | Boolean | Whether the device is quarantined. | 
| MobileIronCloud.Device.jailbroken | Boolean | Whether the device is jailbroken. | 


#### Command Example
```!mobileiron-cloud-get-devices-data```

#### Context Example
```json
{
  "MobileIronCloud": {
    "Device": [
      {
        "id": 123,
        "guid": "",
        "deviceModel": "VirtualBox",
        "deviceName": "DESKTOP-B76IV6U",
        "platformType": "WINDOWS_PHONE",
        "platformVersion": "10.0",
        "osBuildVersion": "",
        "lastCheckin": 1596026443798,
        "registrationState": "ACTIVE",
        "displayName": "Windows User",
        "firstName": "Windows",
        "lastName": "User",
        "uid": "userid",
        "emailAddress": "email",
        "manufacturer": "GmbH",
        "imei": null,
        "imei2": null,
        "imsi": "Not Present",
        "wifiMacAddress": "",
        "serialNumber": null,
        "altSerialNumber": null,
        "ownershipType": "UNKNOWN",
        "complianceState": false,
        "roaming": false,
        "supervised": null,
        "udid": "UIDVALUE",
        "clientLastCheckin": null,
        "prettyModel": "VirtualBox",
        "policyViolationCount": 1,
        "lastRegistrationTime": 1596022502880,
        "quarantined": false,
        "jailbroken": false,
        "windowsDeviceType": "WINDOWS_DESKTOP",
        "entityName": "DESKTOP-B76IV6U"
      }
    ]
  }
}
```

### mobileiron-cloud-get-device-by-mac
***
Gets a single device matching the provided mac address.


#### Base Command

`mobileiron-cloud-get-device-by-mac`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_mac | THe MAC address of the device to fetch. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCloud.Device.id | Number | The ID of the device that is fetched. | 
| MobileIronCloud.Device.guid | String | GUID of the device that is fetched. | 
| MobileIronCloud.Device.deviceModel | String | Model of the device that is fetched. | 
| MobileIronCloud.Device.deviceName | String | Name of the device that is fetched. | 
| MobileIronCloud.Device.platformType | String | Platform type of the device that is fetched. | 
| MobileIronCloud.Device.platformVersion | String | Platform version of the device that is fetched. | 
| MobileIronCloud.Device.osBuildVersion | String | Operating system build version of the device that is fetched. | 
| MobileIronCloud.Device.lastCheckin | Date | Last check in time of the device that is fetched. | 
| MobileIronCloud.Device.registrationState | String | Registration state of the device that is fetched. | 
| MobileIronCloud.Device.displayName | String | Display name of the device that is fetched. | 
| MobileIronCloud.Device.firstName | String | First name of the device that is fetched. | 
| MobileIronCloud.Device.lastName | String | Last name of the device that is fetched. | 
| MobileIronCloud.Device.uid | String | UID of the device that is fetched. | 
| MobileIronCloud.Device.emailAddress | String | Email address of the device that is fetched. | 
| MobileIronCloud.Device.manufacturer | String | Manufacturer of the device that is fetched. | 
| MobileIronCloud.Device.imei | Unknown | International Mobile Equipment Identity (IMEI) of the device that is fetched. | 
| MobileIronCloud.Device.imei2 | Unknown | International Mobile Equipment Identity 2 (IME2) of the device that is fetched. | 
| MobileIronCloud.Device.imsi | String | International mobile subscriber identity (IMSI) of the device that is fetched. | 
| MobileIronCloud.Device.wifiMacAddress | String | WiFi MAC address of the device that is fetched. | 
| MobileIronCloud.Device.serialNumber | Unknown | Serial number of the device that is fetched. | 
| MobileIronCloud.Device.altSerialNumber | Unknown | Alternative serial number of the device that is fetched. | 
| MobileIronCloud.Device.ownershipType | String | Ownership type of the device that is fetched. | 
| MobileIronCloud.Device.complianceState | Boolean | Compliance state of the device that is fetched. | 
| MobileIronCloud.Device.roaming | Boolean | Roaming status of the device that is fetched. | 
| MobileIronCloud.Device.supervised | Unknown | Device Supervised | 
| MobileIronCloud.Device.udid | String | Device UDID of the device that is fetched. | 
| MobileIronCloud.Device.policyViolationCount | Number | Policy violation count of the device that is fetched. | 
| MobileIronCloud.Device.lastRegistrationTime | Date | Last registration time of the device that is fetched. | 
| MobileIronCloud.Device.quarantined | Boolean | Whether the device is quarantined. | 
| MobileIronCloud.Device.jailbroken | Boolean | Whether the device is jailbroken. | 


#### Command Example
```!mobileiron-cloud-get-device-by-mac device_mac=MAC_HERE```

#### Context Example
```json
{
  "MobileIronCloud": {
    "Device": {
      "id": 123,
      "guid": "",
      "deviceModel": "VirtualBox",
      "deviceName": "DESKTOP-B76IV6U",
      "platformType": "WINDOWS_PHONE",
      "platformVersion": "10.0",
      "osBuildVersion": "",
      "lastCheckin": 1596026443798,
      "registrationState": "ACTIVE",
      "displayName": "Windows User",
      "firstName": "Windows",
      "lastName": "User",
      "uid": "userid",
      "emailAddress": "email",
      "manufacturer": "GmbH",
      "imei": null,
      "imei2": null,
      "imsi": "Not Present",
      "wifiMacAddress": "",
      "serialNumber": null,
      "altSerialNumber": null,
      "ownershipType": "UNKNOWN",
      "complianceState": false,
      "roaming": false,
      "supervised": null,
      "udid": "UIDVALUE",
      "clientLastCheckin": null,
      "prettyModel": "VirtualBox",
      "policyViolationCount": 1,
      "lastRegistrationTime": 1596022502880,
      "quarantined": false,
      "jailbroken": false,
      "windowsDeviceType": "WINDOWS_DESKTOP",
      "entityName": "DESKTOP-B76IV6U"
    }
  }
}
```

### mobileiron-cloud-get-device-by-serial
***
Gets a single device matching the provided value for the device serial number.


#### Base Command

`mobileiron-cloud-get-device-by-serial`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_serial | Serial number of the device to fetch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCloud.Device.id | Number | The ID of the device that is fetched. | 
| MobileIronCloud.Device.guid | String | GUID of the device that is fetched. | 
| MobileIronCloud.Device.deviceModel | String | Model of the device that is fetched. | 
| MobileIronCloud.Device.deviceName | String | Name of the device that is fetched. | 
| MobileIronCloud.Device.platformType | String | Platform type of the device that is fetched. | 
| MobileIronCloud.Device.platformVersion | String | Platform version of the device that is fetched. | 
| MobileIronCloud.Device.osBuildVersion | String | Operating system build version of the device that is fetched. | 
| MobileIronCloud.Device.lastCheckin | Date | Last check in time of the device that is fetched. | 
| MobileIronCloud.Device.registrationState | String | Registration state of the device that is fetched. | 
| MobileIronCloud.Device.displayName | String | Display name of the device that is fetched. | 
| MobileIronCloud.Device.firstName | String | First name of the device that is fetched. | 
| MobileIronCloud.Device.lastName | String | Last name of the device that is fetched. | 
| MobileIronCloud.Device.uid | String | UID of the device that is fetched. | 
| MobileIronCloud.Device.emailAddress | String | Email address of the device that is fetched. | 
| MobileIronCloud.Device.manufacturer | String | Manufacturer of the device that is fetched. | 
| MobileIronCloud.Device.imei | Unknown | International Mobile Equipment Identity (IMEI) of the device that is fetched. | 
| MobileIronCloud.Device.imei2 | Unknown | International Mobile Equipment Identity 2 (IME2) of the device that is fetched. | 
| MobileIronCloud.Device.imsi | String | International mobile subscriber identity (IMSI) of the device that is fetched. | 
| MobileIronCloud.Device.wifiMacAddress | String | WiFi MAC address of the device that is fetched. | 
| MobileIronCloud.Device.serialNumber | Unknown | Serial number of the device that is fetched. | 
| MobileIronCloud.Device.altSerialNumber | Unknown | Alternative serial number of the device that is fetched. | 
| MobileIronCloud.Device.ownershipType | String | Ownership type of the device that is fetched. | 
| MobileIronCloud.Device.complianceState | Boolean | Compliance state of the device that is fetched. | 
| MobileIronCloud.Device.roaming | Boolean | Roaming status of the device that is fetched. | 
| MobileIronCloud.Device.supervised | Unknown | Device Supervised | 
| MobileIronCloud.Device.udid | String | Device UDID of the device that is fetched. | 
| MobileIronCloud.Device.policyViolationCount | Number | Policy violation count of the device that is fetched. | 
| MobileIronCloud.Device.lastRegistrationTime | Date | Last registration time of the device that is fetched. | 
| MobileIronCloud.Device.quarantined | Boolean | Whether the device is quarantined. | 
| MobileIronCloud.Device.jailbroken | Boolean | Whether the device is jailbroken. | 


#### Command Example
```!mobileiron-cloud-get-device-by-serial device_serial=SERIAL_HERE```

#### Context Example
```json
{
  "MobileIronCloud": {
    "Device": {
      "id": 123,
      "guid": "",
      "deviceModel": "VirtualBox",
      "deviceName": "DESKTOP-B76IV6U",
      "platformType": "WINDOWS_PHONE",
      "platformVersion": "10.0",
      "osBuildVersion": "",
      "lastCheckin": 1596026443798,
      "registrationState": "ACTIVE",
      "displayName": "Windows User",
      "firstName": "Windows",
      "lastName": "User",
      "uid": "userid",
      "emailAddress": "email",
      "manufacturer": "GmbH",
      "imei": null,
      "imei2": null,
      "imsi": "Not Present",
      "wifiMacAddress": "",
      "serialNumber": null,
      "altSerialNumber": null,
      "ownershipType": "UNKNOWN",
      "complianceState": false,
      "roaming": false,
      "supervised": null,
      "udid": "UIDVALUE",
      "clientLastCheckin": null,
      "prettyModel": "VirtualBox",
      "policyViolationCount": 1,
      "lastRegistrationTime": 1596022502880,
      "quarantined": false,
      "jailbroken": false,
      "windowsDeviceType": "WINDOWS_DESKTOP",
      "entityName": "DESKTOP-B76IV6U"
    }
  }
}
```

### mobileiron-cloud-unlock-device
***
Sends an unlock action to the device.


#### Base Command

`mobileiron-cloud-unlock-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the MobileIron device to fetch. | Optional | 


#### Command Example
```!mobileiron-cloud-unlock-device device_id=1100646```

#### Human Readable Output

>Action was performed successfully

### mobileiron-cloud-retire-device
***
Sends a retire action to the device.


#### Base Command

`mobileiron-cloud-retire-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the MobileIron device to fetch. | Optional | 


#### Human Readable Output

>Action was performed successfully

### mobileiron-cloud-wipe-device
***
Sends a wipe action to the device. This is a potentially destructive action as it will completely wipe the device.


#### Base Command

`mobileiron-cloud-wipe-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the MobileIron device to fetch. | Optional | 


#### Human Readable Output

>Action was performed successfully


### mobileiron-cloud-force-check-in
***
Forces a check in to the particular device based on the device ID.


#### Base Command

`mobileiron-cloud-force-check-in`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the MobileIron device to fetch. | Optional | 


#### Human Readable Output

>Action was performed successfully


### mobileiron-cloud-send-message
***
Sends a message to the device.


#### Base Command

`mobileiron-cloud-send-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the MobileIron device to fetch. | Optional | 
| message_type | The type of notification to send. Possible values are: email, push. Default is push. | Required | 
| subject | The subject of the email. (Only used if an email should be sent). | Optional | 
| message | The message to be sent. | Required | 


#### Human Readable Output

>Action was performed successfully


### mobileiron-cloud-get-device-by-id
***
Returns the data for a particular device based on the device ID.

#### Base Command

`mobileiron-cloud-get-device-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the MobileIron device to fetch. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCloud.Device.id | Number | The ID of the device that is fetched. | 
| MobileIronCloud.Device.guid | String | GUID of the device that is fetched. | 
| MobileIronCloud.Device.deviceModel | String | Model of the device that is fetched. | 
| MobileIronCloud.Device.deviceName | String | Name of the device that is fetched. | 
| MobileIronCloud.Device.platformType | String | Platform type of the device that is fetched. | 
| MobileIronCloud.Device.platformVersion | String | Platform version of the device that is fetched. | 
| MobileIronCloud.Device.osBuildVersion | String | Operating system build version of the device that is fetched. | 
| MobileIronCloud.Device.lastCheckin | Date | Last check in time of the device that is fetched. | 
| MobileIronCloud.Device.registrationState | String | Registration state of the device that is fetched. | 
| MobileIronCloud.Device.displayName | String | Display name of the device that is fetched. | 
| MobileIronCloud.Device.firstName | String | First name of the device that is fetched. | 
| MobileIronCloud.Device.lastName | String | Last name of the device that is fetched. | 
| MobileIronCloud.Device.uid | String | UID of the device that is fetched. | 
| MobileIronCloud.Device.emailAddress | String | Email address of the device that is fetched. | 
| MobileIronCloud.Device.manufacturer | String | Manufacturer of the device that is fetched. | 
| MobileIronCloud.Device.imei | Unknown | International Mobile Equipment Identity (IMEI) of the device that is fetched. | 
| MobileIronCloud.Device.imei2 | Unknown | International Mobile Equipment Identity 2 (IME2) of the device that is fetched. | 
| MobileIronCloud.Device.imsi | String | International mobile subscriber identity (IMSI) of the device that is fetched. | 
| MobileIronCloud.Device.wifiMacAddress | String | WiFi MAC address of the device that is fetched. | 
| MobileIronCloud.Device.serialNumber | Unknown | Serial number of the device that is fetched. | 
| MobileIronCloud.Device.altSerialNumber | Unknown | Alternative serial number of the device that is fetched. | 
| MobileIronCloud.Device.ownershipType | String | Ownership type of the device that is fetched. | 
| MobileIronCloud.Device.complianceState | Boolean | Compliance state of the device that is fetched. | 
| MobileIronCloud.Device.roaming | Boolean | Roaming status of the device that is fetched. | 
| MobileIronCloud.Device.supervised | Unknown | Device Supervised | 
| MobileIronCloud.Device.udid | String | Device UDID of the device that is fetched. | 
| MobileIronCloud.Device.policyViolationCount | Number | Policy violation count of the device that is fetched. | 
| MobileIronCloud.Device.lastRegistrationTime | Date | Last registration time of the device that is fetched. | 
| MobileIronCloud.Device.quarantined | Boolean | Whether the device is quarantined. | 
| MobileIronCloud.Device.jailbroken | Boolean | Whether the device is jailbroken. | 


#### Command Example
```!mobileiron-cloud-get-device-by-id device_id=1100646```

#### Context Example
```json
{
  "MobileIronCloud": {
    "Device": {
      "id": 123,
      "guid": "",
      "deviceModel": "VirtualBox",
      "deviceName": "DESKTOP-B76IV6U",
      "platformType": "WINDOWS_PHONE",
      "platformVersion": "10.0",
      "osBuildVersion": "",
      "lastCheckin": 1596026443798,
      "registrationState": "ACTIVE",
      "displayName": "Windows User",
      "firstName": "Windows",
      "lastName": "User",
      "uid": "userid",
      "emailAddress": "email",
      "manufacturer": "GmbH",
      "imei": null,
      "imei2": null,
      "imsi": "Not Present",
      "wifiMacAddress": "",
      "serialNumber": null,
      "altSerialNumber": null,
      "ownershipType": "UNKNOWN",
      "complianceState": false,
      "roaming": false,
      "supervised": null,
      "udid": "UIDVALUE",
      "clientLastCheckin": null,
      "prettyModel": "VirtualBox",
      "policyViolationCount": 1,
      "lastRegistrationTime": 1596022502880,
      "quarantined": false,
      "jailbroken": false,
      "windowsDeviceType": "WINDOWS_DESKTOP",
      "entityName": "DESKTOP-B76IV6U"
    }
  }
}
```
