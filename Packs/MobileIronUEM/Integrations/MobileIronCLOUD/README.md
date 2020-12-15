MobileIron CLOUD Integration
This integration was integrated and tested with version xx of MobileIronCLOUD
## Configure MobileIronCLOUD on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MobileIronCLOUD.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Server URL \(ex. https://eu1.mobileiron.com \) | True |
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
This command is used to get all the devices based on a particular filter query. The command might execute multiple API calls depending on the amount of devices that would be returned.


#### Base Command

`mobileiron-cloud-get-devices-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Filter query for fetching the device data. Default is registrationState=ACTIVE. | Optional | 
| max_fetch | Limit the number of items returned in the list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCloud.Device.id | Number | Device Id | 
| MobileIronCloud.Device.guid | String | Device GUID | 
| MobileIronCloud.Device.deviceModel | String | Device Model | 
| MobileIronCloud.Device.deviceName | String | Device Name | 
| MobileIronCloud.Device.platformType | String | Platform Type | 
| MobileIronCloud.Device.platformVersion | String | Platform Version | 
| MobileIronCloud.Device.osBuildVersion | String | OS Build Version | 
| MobileIronCloud.Device.lastCheckin | Date | Last Check In | 
| MobileIronCloud.Device.registrationState | String | Registration State | 
| MobileIronCloud.Device.displayName | String | Display Name | 
| MobileIronCloud.Device.firstName | String | First Name | 
| MobileIronCloud.Device.lastName | String | Last Name | 
| MobileIronCloud.Device.uid | String | Device UID | 
| MobileIronCloud.Device.emailAddress | String | Email Address | 
| MobileIronCloud.Device.manufacturer | String | Manufacturer | 
| MobileIronCloud.Device.imei | Unknown | IMEI | 
| MobileIronCloud.Device.imei2 | Unknown | IMEI2 | 
| MobileIronCloud.Device.imsi | String | IMSI | 
| MobileIronCloud.Device.wifiMacAddress | String | WIFI Mac Address | 
| MobileIronCloud.Device.serialNumber | Unknown | Serial Number | 
| MobileIronCloud.Device.altSerialNumber | Unknown | Alternative Serial Number | 
| MobileIronCloud.Device.ownershipType | String | Ownership Type | 
| MobileIronCloud.Device.complianceState | Boolean | Compliance State | 
| MobileIronCloud.Device.roaming | Boolean | Roaming Status | 
| MobileIronCloud.Device.supervised | Unknown | Device Supervised | 
| MobileIronCloud.Device.udid | String | Device UDID | 
| MobileIronCloud.Device.policyViolationCount | Number | Policy Violation Count | 
| MobileIronCloud.Device.lastRegistrationTime | Date | Last Registration Time | 
| MobileIronCloud.Device.quarantined | Boolean | Quarantined | 
| MobileIronCloud.Device.jailbroken | Boolean | Jailbroken | 


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
Used to get a single device matching the provided mac address


#### Base Command

`mobileiron-cloud-get-device-by-mac`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_mac | Device MAC address. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCloud.Device.id | Number | Device Id | 
| MobileIronCloud.Device.guid | String | Device GUID | 
| MobileIronCloud.Device.deviceModel | String | Device Model | 
| MobileIronCloud.Device.deviceName | String | Device Name | 
| MobileIronCloud.Device.platformType | String | Platform Type | 
| MobileIronCloud.Device.platformVersion | String | Platform Version | 
| MobileIronCloud.Device.osBuildVersion | String | OS Build Version | 
| MobileIronCloud.Device.lastCheckin | Date | Last Check In | 
| MobileIronCloud.Device.registrationState | String | Registration State | 
| MobileIronCloud.Device.displayName | String | Display Name | 
| MobileIronCloud.Device.firstName | String | First Name | 
| MobileIronCloud.Device.lastName | String | Last Name | 
| MobileIronCloud.Device.uid | String | Device UID | 
| MobileIronCloud.Device.emailAddress | String | Email Address | 
| MobileIronCloud.Device.manufacturer | String | Manufacturer | 
| MobileIronCloud.Device.imei | Unknown | IMEI | 
| MobileIronCloud.Device.imei2 | Unknown | IMEI2 | 
| MobileIronCloud.Device.imsi | String | IMSI | 
| MobileIronCloud.Device.wifiMacAddress | String | WIFI Mac Address | 
| MobileIronCloud.Device.serialNumber | Unknown | Serial Number | 
| MobileIronCloud.Device.altSerialNumber | Unknown | Alternative Serial Number | 
| MobileIronCloud.Device.ownershipType | String | Ownership Type | 
| MobileIronCloud.Device.complianceState | Boolean | Compliance State | 
| MobileIronCloud.Device.roaming | Boolean | Roaming Status | 
| MobileIronCloud.Device.supervised | Unknown | Device Supervised | 
| MobileIronCloud.Device.udid | String | Device UDID | 
| MobileIronCloud.Device.policyViolationCount | Number | Policy Violation Count | 
| MobileIronCloud.Device.lastRegistrationTime | Date | Last Registration Time | 
| MobileIronCloud.Device.quarantined | Boolean | Quarantined | 
| MobileIronCloud.Device.jailbroken | Boolean | Jailbroken | 


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
Used to get a single device matching the provided value for the device serial number


#### Base Command

`mobileiron-cloud-get-device-by-serial`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_serial | Device Serial Number. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCloud.Device.id | Number | Device Id | 
| MobileIronCloud.Device.guid | String | Device GUID | 
| MobileIronCloud.Device.deviceModel | String | Device Model | 
| MobileIronCloud.Device.deviceName | String | Device Name | 
| MobileIronCloud.Device.platformType | String | Platform Type | 
| MobileIronCloud.Device.platformVersion | String | Platform Version | 
| MobileIronCloud.Device.osBuildVersion | String | OS Build Version | 
| MobileIronCloud.Device.lastCheckin | Date | Last Check In | 
| MobileIronCloud.Device.registrationState | String | Registration State | 
| MobileIronCloud.Device.displayName | String | Display Name | 
| MobileIronCloud.Device.firstName | String | First Name | 
| MobileIronCloud.Device.lastName | String | Last Name | 
| MobileIronCloud.Device.uid | String | Device UID | 
| MobileIronCloud.Device.emailAddress | String | Email Address | 
| MobileIronCloud.Device.manufacturer | String | Manufacturer | 
| MobileIronCloud.Device.imei | Unknown | IMEI | 
| MobileIronCloud.Device.imei2 | Unknown | IMEI2 | 
| MobileIronCloud.Device.imsi | String | IMSI | 
| MobileIronCloud.Device.wifiMacAddress | String | WIFI Mac Address | 
| MobileIronCloud.Device.serialNumber | Unknown | Serial Number | 
| MobileIronCloud.Device.altSerialNumber | Unknown | Alternative Serial Number | 
| MobileIronCloud.Device.ownershipType | String | Ownership Type | 
| MobileIronCloud.Device.complianceState | Boolean | Compliance State | 
| MobileIronCloud.Device.roaming | Boolean | Roaming Status | 
| MobileIronCloud.Device.supervised | Unknown | Device Supervised | 
| MobileIronCloud.Device.udid | String | Device UDID | 
| MobileIronCloud.Device.policyViolationCount | Number | Policy Violation Count | 
| MobileIronCloud.Device.lastRegistrationTime | Date | Last Registration Time | 
| MobileIronCloud.Device.quarantined | Boolean | Quarantined | 
| MobileIronCloud.Device.jailbroken | Boolean | Jailbroken | 


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
This command is used to send an unlock action to the device


#### Base Command

`mobileiron-cloud-unlock-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The MobileIron Device Id. | Optional | 


#### Command Example
```!mobileiron-cloud-unlock-device device_id=1100646```

#### Human Readable Output

>Action was performed successfully

### mobileiron-cloud-retire-device
***
This command is used to send an retire action to the device


#### Base Command

`mobileiron-cloud-retire-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The MobileIron Device Id. | Optional | 


#### Human Readable Output

>Action was performed successfully

### mobileiron-cloud-wipe-device
***
This command is used to send a wipe action to the device. This is a potentially destructive action as it will completely wipe the device


#### Base Command

`mobileiron-cloud-wipe-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The MobileIron Device Id. | Optional | 


#### Human Readable Output

>Action was performed successfully


### mobileiron-cloud-force-check-in
***
This command is used to force checkin to the particular device based on device id


#### Base Command

`mobileiron-cloud-force-check-in`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The MobileIron Device Id. | Optional | 


#### Human Readable Output

>Action was performed successfully


### mobileiron-cloud-send-message
***
This command is used to send an message to the device


#### Base Command

`mobileiron-cloud-send-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The MobileIron Device Id. | Optional | 
| message_type | If a push notification should be sent. Possible values are: email, push. Default is push. | Required | 
| subject | Provide Subject for email (only used in case email should be sent). | Optional | 
| message | Provide the message to be sent. | Required | 


#### Human Readable Output

>Action was performed successfully


### mobileiron-cloud-get-device-by-id
***
Returns the data for a particular device based on the device id

#### Base Command

`mobileiron-cloud-get-device-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The MobileIron Device Id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCloud.Device.id | Number | Device Id | 
| MobileIronCloud.Device.guid | String | Device GUID | 
| MobileIronCloud.Device.deviceModel | String | Device Model | 
| MobileIronCloud.Device.deviceName | String | Device Name | 
| MobileIronCloud.Device.platformType | String | Platform Type | 
| MobileIronCloud.Device.platformVersion | String | Platform Version | 
| MobileIronCloud.Device.osBuildVersion | String | OS Build Version | 
| MobileIronCloud.Device.lastCheckin | Date | Last Check In | 
| MobileIronCloud.Device.registrationState | String | Registration State | 
| MobileIronCloud.Device.displayName | String | Display Name | 
| MobileIronCloud.Device.firstName | String | First Name | 
| MobileIronCloud.Device.lastName | String | Last Name | 
| MobileIronCloud.Device.uid | String | Device UID | 
| MobileIronCloud.Device.emailAddress | String | Email Address | 
| MobileIronCloud.Device.manufacturer | String | Manufacturer | 
| MobileIronCloud.Device.imei | Unknown | IMEI | 
| MobileIronCloud.Device.imei2 | Unknown | IMEI2 | 
| MobileIronCloud.Device.imsi | String | IMSI | 
| MobileIronCloud.Device.wifiMacAddress | String | WIFI Mac Address | 
| MobileIronCloud.Device.serialNumber | Unknown | Serial Number | 
| MobileIronCloud.Device.altSerialNumber | Unknown | Alternative Serial Number | 
| MobileIronCloud.Device.ownershipType | String | Ownership Type | 
| MobileIronCloud.Device.complianceState | Boolean | Compliance State | 
| MobileIronCloud.Device.roaming | Boolean | Roaming Status | 
| MobileIronCloud.Device.supervised | Unknown | Device Supervised | 
| MobileIronCloud.Device.udid | String | Device UDID | 
| MobileIronCloud.Device.policyViolationCount | Number | Policy Violation Count | 
| MobileIronCloud.Device.lastRegistrationTime | Date | Last Registration Time | 
| MobileIronCloud.Device.quarantined | Boolean | Quarantined | 
| MobileIronCloud.Device.jailbroken | Boolean | Jailbroken | 


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
