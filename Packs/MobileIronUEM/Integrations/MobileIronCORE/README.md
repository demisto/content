MobileIron CORE Integration
This integration was integrated and tested with version 11.0.0 of MobileIronCORE
## Configure MobileIronCORE on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MobileIronCORE.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Server URL \(ex. https://core.mobileiron.com \) | True |
    | admin_space_id | Admin Space ID \(ex. 1 for the global space id\) | True |
    | credentials | API User Credentials | True |
    | max_fetch | Maximum number of incidents per fetch | False |
    | incidentType | Incident type | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | fetch_interval | Fetch Interval \(in minutes\) | True |
    | isFetch | Fetch incidents | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### mobileiron-core-send-message
***
This command is used to send a message to the particular device based on device id


#### Base Command

`mobileiron-core-send-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron send message command. | Required | 
| subject | Provide Subject for email. | Required | 
| message | Provide message for email. | Required | 
| message_type | Send Message Mode. Possible values are: pns, sms, email. | Required | 


### mobileiron-core-update-os
***
This command is used to update OS to the particular device based on device id


#### Base Command

`mobileiron-core-update-os`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron update os command. | Required | 



### mobileiron-core-unlock-device-only
***
This command is used to unlock device to the particular device based on device id


#### Base Command

`mobileiron-core-unlock-device-only`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron unlock device only command. | Required | 


### mobileiron-core-enable-voice-roaming
***
This command is used to enable voice roaming to the particular device based on device id


#### Base Command

`mobileiron-core-enable-voice-roaming`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron enable voice roaming command. | Required | 


### mobileiron-core-disable-voice-roaming
***
This command is used to disable voice roaming to the particular device based on device id


#### Base Command

`mobileiron-core-disable-voice-roaming`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron disable voice roaming command. | Required | 


### mobileiron-core-enable-data-roaming
***
This command is used to enable data roaming to the particular device based on device id


#### Base Command

`mobileiron-core-enable-data-roaming`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron enable data roaming command. | Required | 


### mobileiron-core-disable-data-roaming
***
This command is used to disable data roaming to the particular device based on device id


#### Base Command

`mobileiron-core-disable-data-roaming`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron disable data roaming command. | Required | 


### mobileiron-core-enable-personal-hotspot
***
This command is used to enable personal hotspot to the particular device based on device id


#### Base Command

`mobileiron-core-enable-personal-hotspot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron enable personal hotspot command. | Required | 


### mobileiron-core-disable-personal-hotspot
***
This command is used to disable personal hotspot to the particular device based on device id


#### Base Command

`mobileiron-core-disable-personal-hotspot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron disable personal hotspot command. | Required | 


### mobileiron-core-unlock-app-connect-container
***
This command is used to unlock app connect container to the particular device based on device id


#### Base Command

`mobileiron-core-unlock-app-connect-container`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron unlock app connect container command. | Required | 


### mobileiron-core-retire-device
***
This command is used to retire device to the particular device based on device id


#### Base Command

`mobileiron-core-retire-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron retire device command. | Required | 


### mobileiron-core-wipe-device
***
This command is used to wipe device to the particular device based on device id


#### Base Command

`mobileiron-core-wipe-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | device id pointing to the device to execute the command on. | Required | 


### mobileiron-core-force-checkin
***
This command is used to force checkin to the particular device based on device id


#### Base Command

`mobileiron-core-force-checkin`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | This argument fetch the device id for mobileiron force checkin command. | Required | 


### mobileiron-core-get-devices-data
***
This command is used to get a list of devices matching the provided query

#### Base Command

`mobileiron-core-get-devices-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query which to execute to filter down the list of devices. Default is common.status = "ACTIVE". | Required | 
| additional_fields | comma separated list of fields to query from the API. | Optional | 
| max_fetch | limit the number of items that should be returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCore.Device.common.model | String | Model | 
| MobileIronCore.Device.common.os_version | String | OS Version | 
| MobileIronCore.Device.common.platform | String | Platform Name | 
| MobileIronCore.Device.common.status | String | Status | 
| MobileIronCore.Device.common.imei | String | IMEI | 
| MobileIronCore.Device.common.platform | String | Platform | 
| MobileIronCore.Device.common.security_state | String | Security State | 
| MobileIronCore.Device.user.display_name | String | Display Name | 
| MobileIronCore.Device.common.last_connected_at | Date | Last Connected At | 
| MobileIronCore.Device.common.uuid | String | Device UUID | 
| MobileIronCore.Device.common.quarantined | Boolean | Quarantined | 
| MobileIronCore.Device.common.id | Number | Device ID | 
| MobileIronCore.Device.common.imsi | String | IMSI | 
| MobileIronCore.Device.common.owner | String | Device Owner | 
| MobileIronCore.Device.user.email_address | String | User Email Address | 
| MobileIronCore.Device.common.manufacturer | String | Manufacturer | 
| MobileIronCore.Device.common.compliant | Boolean | Compliant | 
| MobileIronCore.Device.user.user_id | String | User ID | 
| MobileIronCore.Device.common.registration_date | Date | Registration Date | 
| MobileIronCore.Device.common.wifi_mac_address | String | Wifi MAC Address | 
| MobileIronCore.Device.common.noncompliance_reasons | String | Non compliance Reasons | 
| MobileIronCore.Device.ios.iPhone UDID | String | iPhone UDID | 
| MobileIronCore.Device.ios.iPhone MAC_ADDRESS_EN0 | String | IPhone MAC Address EN0 | 
| MobileIronCore.Device.ios.Current MCC | String | Current MCC | 
| MobileIronCore.Device.common.current_country_code | String | Current country code | 
| MobileIronCore.Device.user.sam_account_name | String | SAM account name | 
| MobileIronCore.Device.common.current_country_name | String | Current country name | 
| MobileIronCore.Device.common.home_country_name | String | Home country name | 
| MobileIronCore.Device.common.home_country_code | String | Home country code | 
| MobileIronCore.Device.common.device_is_compromised | Boolean | True if device is compromised | 
| MobileIronCore.Device.common.SerialNumber | String | Device serial number | 
| MobileIronCore.Device.common.mdm_managed | Boolean | Device is MDM managed | 


#### Command Example
```!mobileiron-core-get-devices-data```

#### Context Example
```json
{
    "MobileIronCore": {
        "Device": [
            {
              "common.wifi_mac_address": "",
              "common.noncompliance_reasons": [
                "DEVICE_ADMIN_DEACTIVE"
              ],
              "ios.iPhone UDID": "",
              "common.device_is_compromised": false,
              "common.SerialNumber": "",
              "common.mdm_managed": false,
              "common.model": "Pixel",
              "common.os_version": "10.0",
              "common.status": "ACTIVE",
              "common.imei": "",
              "common.platform": "Android",
              "common.security_state": "Ok",
              "user.display_name": "*****",
              "common.last_connected_at": "2020-11-09T07:38:22.000Z",
              "common.uuid": "",
              "common.quarantined": false,
              "common.id": 3,
              "common.imsi": "*****",
              "common.owner": "COMPANY",
              "user.email_address": "*****",
              "common.manufacturer": "Google",
              "common.compliant": false,
              "user.user_id": "*****",
              "common.registration_date": "2020-10-29T14:11:39.000Z"
            }
        ]
    }
}
```


### mobileiron-core-get-device-by-uuid
***
This command is used to get a single device based on the device uuid


#### Base Command

`mobileiron-core-get-device-by-uuid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_uuid | device uuid. | Required | 
| additional_fields | comma separated list of fields to query from the API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCore.Device.common.model | String | Model | 
| MobileIronCore.Device.common.os_version | String | OS Version | 
| MobileIronCore.Device.common.platform | String | Platform Name | 
| MobileIronCore.Device.common.status | String | Status | 
| MobileIronCore.Device.common.imei | String | IMEI | 
| MobileIronCore.Device.common.platform | String | Platform | 
| MobileIronCore.Device.common.security_state | String | Security State | 
| MobileIronCore.Device.user.display_name | String | Display Name | 
| MobileIronCore.Device.common.last_connected_at | Date | Last Connected At | 
| MobileIronCore.Device.common.uuid | String | Device UUID | 
| MobileIronCore.Device.common.quarantined | Boolean | Quarantined | 
| MobileIronCore.Device.common.id | Number | Device ID | 
| MobileIronCore.Device.common.imsi | String | IMSI | 
| MobileIronCore.Device.common.owner | String | Device Owner | 
| MobileIronCore.Device.user.email_address | String | User Email Address | 
| MobileIronCore.Device.common.manufacturer | String | Manufacturer | 
| MobileIronCore.Device.common.compliant | Boolean | Compliant | 
| MobileIronCore.Device.user.user_id | String | User ID | 
| MobileIronCore.Device.common.registration_date | Date | Registration Date | 
| MobileIronCore.Device.common.wifi_mac_address | String | Wifi MAC Address | 
| MobileIronCore.Device.common.noncompliance_reasons | String | Non compliance Reasons | 
| MobileIronCore.Device.ios.iPhone UDID | String | iPhone UDID | 
| MobileIronCore.Device.ios.iPhone MAC_ADDRESS_EN0 | String | IPhone MAC Address EN0 | 
| MobileIronCore.Device.ios.Current MCC | String | Current MCC | 
| MobileIronCore.Device.common.current_country_code | String | Current country code | 
| MobileIronCore.Device.user.sam_account_name | String | SAM account name | 
| MobileIronCore.Device.common.current_country_name | String | Current country name | 
| MobileIronCore.Device.common.home_country_name | String | Home country name | 
| MobileIronCore.Device.common.home_country_code | String | Home country code | 
| MobileIronCore.Device.common.device_is_compromised | Boolean | True if device is compromised | 
| MobileIronCore.Device.common.SerialNumber | String | Device serial number | 
| MobileIronCore.Device.common.mdm_managed | Boolean | Device is MDM managed | 


#### Command Example
```!mobileiron-core-get-device-by-uuid device_uuid=9b0da853-9f9b-483c-97ef-f4b5457299cf```

#### Context Example
```json
{
    "MobileIronCore": {
        "Device": {
          "common.wifi_mac_address": "",
          "common.noncompliance_reasons": [
            "DEVICE_ADMIN_DEACTIVE"
          ],
          "ios.iPhone UDID": "",
          "common.device_is_compromised": false,
          "common.SerialNumber": "",
          "common.mdm_managed": false,
          "common.model": "Pixel",
          "common.os_version": "10.0",
          "common.status": "ACTIVE",
          "common.imei": "",
          "common.platform": "Android",
          "common.security_state": "Ok",
          "user.display_name": "*****",
          "common.last_connected_at": "2020-11-09T07:38:22.000Z",
          "common.uuid": "",
          "common.quarantined": false,
          "common.id": 3,
          "common.imsi": "*****",
          "common.owner": "COMPANY",
          "user.email_address": "*****",
          "common.manufacturer": "Google",
          "common.compliant": false,
          "user.user_id": "*****",
          "common.registration_date": "2020-10-29T14:11:39.000Z"
        }
    }
}
```

### mobileiron-core-get-device-by-serial
***
This command is used to get a single device based on the device serial number

#### Base Command

`mobileiron-core-get-device-by-serial`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_serial | device serial. | Required | 
| additional_fields | comma separated list of fields to query from the API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCore.Device.common.model | String | Model | 
| MobileIronCore.Device.common.os_version | String | OS Version | 
| MobileIronCore.Device.common.platform | String | Platform Name | 
| MobileIronCore.Device.common.status | String | Status | 
| MobileIronCore.Device.common.imei | String | IMEI | 
| MobileIronCore.Device.common.platform | String | Platform | 
| MobileIronCore.Device.common.security_state | String | Security State | 
| MobileIronCore.Device.user.display_name | String | Display Name | 
| MobileIronCore.Device.common.last_connected_at | Date | Last Connected At | 
| MobileIronCore.Device.common.uuid | String | Device UUID | 
| MobileIronCore.Device.common.quarantined | Boolean | Quarantined | 
| MobileIronCore.Device.common.id | Number | Device ID | 
| MobileIronCore.Device.common.imsi | String | IMSI | 
| MobileIronCore.Device.common.owner | String | Device Owner | 
| MobileIronCore.Device.user.email_address | String | User Email Address | 
| MobileIronCore.Device.common.manufacturer | String | Manufacturer | 
| MobileIronCore.Device.common.compliant | Boolean | Compliant | 
| MobileIronCore.Device.user.user_id | String | User ID | 
| MobileIronCore.Device.common.registration_date | Date | Registration Date | 
| MobileIronCore.Device.common.wifi_mac_address | String | Wifi MAC Address | 
| MobileIronCore.Device.common.noncompliance_reasons | String | Non compliance Reasons | 
| MobileIronCore.Device.ios.iPhone UDID | String | iPhone UDID | 
| MobileIronCore.Device.ios.iPhone MAC_ADDRESS_EN0 | String | IPhone MAC Address EN0 | 
| MobileIronCore.Device.ios.Current MCC | String | Current MCC | 
| MobileIronCore.Device.common.current_country_code | String | Current country code | 
| MobileIronCore.Device.user.sam_account_name | String | SAM account name | 
| MobileIronCore.Device.common.current_country_name | String | Current country name | 
| MobileIronCore.Device.common.home_country_name | String | Home country name | 
| MobileIronCore.Device.common.home_country_code | String | Home country code | 
| MobileIronCore.Device.common.device_is_compromised | Boolean | True if device is compromised | 
| MobileIronCore.Device.common.SerialNumber | String | Device serial number | 
| MobileIronCore.Device.common.mdm_managed | Boolean | Device is MDM managed | 


#### Command Example
```!mobileiron-core-get-device-by-serial device_serial=EXAMPLE```


#### Context Example
```json
{
    "MobileIronCore": {
        "Device": {
          "common.wifi_mac_address": "",
          "common.noncompliance_reasons": [
            "DEVICE_ADMIN_DEACTIVE"
          ],
          "ios.iPhone UDID": "",
          "common.device_is_compromised": false,
          "common.SerialNumber": "",
          "common.mdm_managed": false,
          "common.model": "Pixel",
          "common.os_version": "10.0",
          "common.status": "ACTIVE",
          "common.imei": "",
          "common.platform": "Android",
          "common.security_state": "Ok",
          "user.display_name": "*****",
          "common.last_connected_at": "2020-11-09T07:38:22.000Z",
          "common.uuid": "",
          "common.quarantined": false,
          "common.id": 3,
          "common.imsi": "*****",
          "common.owner": "COMPANY",
          "user.email_address": "*****",
          "common.manufacturer": "Google",
          "common.compliant": false,
          "user.user_id": "*****",
          "common.registration_date": "2020-10-29T14:11:39.000Z"
        }
    }
}
```

### mobileiron-core-get-device-by-mac
***
This command is used to get a single device based on the device wifi mac address


#### Base Command

`mobileiron-core-get-device-by-mac`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_mac | device mac. | Required | 
| additional_fields | comma separated list of fields to query from the API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCore.Device.common.model | String | Model | 
| MobileIronCore.Device.common.os_version | String | OS Version | 
| MobileIronCore.Device.common.platform | String | Platform Name | 
| MobileIronCore.Device.common.status | String | Status | 
| MobileIronCore.Device.common.imei | String | IMEI | 
| MobileIronCore.Device.common.platform | String | Platform | 
| MobileIronCore.Device.common.security_state | String | Security State | 
| MobileIronCore.Device.user.display_name | String | Display Name | 
| MobileIronCore.Device.common.last_connected_at | Date | Last Connected At | 
| MobileIronCore.Device.common.uuid | String | Device UUID | 
| MobileIronCore.Device.common.quarantined | Boolean | Quarantined | 
| MobileIronCore.Device.common.id | Number | Device ID | 
| MobileIronCore.Device.common.imsi | String | IMSI | 
| MobileIronCore.Device.common.owner | String | Device Owner | 
| MobileIronCore.Device.user.email_address | String | User Email Address | 
| MobileIronCore.Device.common.manufacturer | String | Manufacturer | 
| MobileIronCore.Device.common.compliant | Boolean | Compliant | 
| MobileIronCore.Device.user.user_id | String | User ID | 
| MobileIronCore.Device.common.registration_date | Date | Registration Date | 
| MobileIronCore.Device.common.wifi_mac_address | String | Wifi MAC Address | 
| MobileIronCore.Device.common.noncompliance_reasons | String | Non compliance Reasons | 
| MobileIronCore.Device.ios.iPhone UDID | String | iPhone UDID | 
| MobileIronCore.Device.ios.iPhone MAC_ADDRESS_EN0 | String | IPhone MAC Address EN0 | 
| MobileIronCore.Device.ios.Current MCC | String | Current MCC | 
| MobileIronCore.Device.common.current_country_code | String | Current country code | 
| MobileIronCore.Device.user.sam_account_name | String | SAM account name | 
| MobileIronCore.Device.common.current_country_name | String | Current country name | 
| MobileIronCore.Device.common.home_country_name | String | Home country name | 
| MobileIronCore.Device.common.home_country_code | String | Home country code | 
| MobileIronCore.Device.common.device_is_compromised | Boolean | True if device is compromised | 
| MobileIronCore.Device.common.SerialNumber | String | Device serial number | 
| MobileIronCore.Device.common.mdm_managed | Boolean | Device is MDM managed | 


#### Command Example
```!mobileiron-core-get-device-by-mac device_mac=EXAMPLE```


#### Context Example
```json
{
    "MobileIronCore": {
        "Device": {
          "common.wifi_mac_address": "",
          "common.noncompliance_reasons": [
            "DEVICE_ADMIN_DEACTIVE"
          ],
          "ios.iPhone UDID": "",
          "common.device_is_compromised": false,
          "common.SerialNumber": "",
          "common.mdm_managed": false,
          "common.model": "Pixel",
          "common.os_version": "10.0",
          "common.status": "ACTIVE",
          "common.imei": "",
          "common.platform": "Android",
          "common.security_state": "Ok",
          "user.display_name": "*****",
          "common.last_connected_at": "2020-11-09T07:38:22.000Z",
          "common.uuid": "",
          "common.quarantined": false,
          "common.id": 3,
          "common.imsi": "*****",
          "common.owner": "COMPANY",
          "user.email_address": "*****",
          "common.manufacturer": "Google",
          "common.compliant": false,
          "user.user_id": "*****",
          "common.registration_date": "2020-10-29T14:11:39.000Z"
        }
    }
}
```

### mobileiron-core-get-device-by-ip
***
This command is used to get a single device based on the device ip

#### Base Command

`mobileiron-core-get-device-by-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ip | device IP. | Required | 
| additional_fields | comma separated list of fields to query from the API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MobileIronCore.Device.common.model | String | Model | 
| MobileIronCore.Device.common.os_version | String | OS Version | 
| MobileIronCore.Device.common.platform | String | Platform Name | 
| MobileIronCore.Device.common.status | String | Status | 
| MobileIronCore.Device.common.imei | String | IMEI | 
| MobileIronCore.Device.common.platform | String | Platform | 
| MobileIronCore.Device.common.security_state | String | Security State | 
| MobileIronCore.Device.user.display_name | String | Display Name | 
| MobileIronCore.Device.common.last_connected_at | Date | Last Connected At | 
| MobileIronCore.Device.common.uuid | String | Device UUID | 
| MobileIronCore.Device.common.quarantined | Boolean | Quarantined | 
| MobileIronCore.Device.common.id | Number | Device ID | 
| MobileIronCore.Device.common.imsi | String | IMSI | 
| MobileIronCore.Device.common.owner | String | Device Owner | 
| MobileIronCore.Device.user.email_address | String | User Email Address | 
| MobileIronCore.Device.common.manufacturer | String | Manufacturer | 
| MobileIronCore.Device.common.compliant | Boolean | Compliant | 
| MobileIronCore.Device.user.user_id | String | User ID | 
| MobileIronCore.Device.common.registration_date | Date | Registration Date | 
| MobileIronCore.Device.common.wifi_mac_address | String | Wifi MAC Address | 
| MobileIronCore.Device.common.noncompliance_reasons | String | Non compliance Reasons | 
| MobileIronCore.Device.ios.iPhone UDID | String | iPhone UDID | 
| MobileIronCore.Device.ios.iPhone MAC_ADDRESS_EN0 | String | IPhone MAC Address EN0 | 
| MobileIronCore.Device.ios.Current MCC | String | Current MCC | 
| MobileIronCore.Device.common.current_country_code | String | Current country code | 
| MobileIronCore.Device.user.sam_account_name | String | SAM account name | 
| MobileIronCore.Device.common.current_country_name | String | Current country name | 
| MobileIronCore.Device.common.home_country_name | String | Home country name | 
| MobileIronCore.Device.common.home_country_code | String | Home country code | 
| MobileIronCore.Device.common.device_is_compromised | Boolean | True if device is compromised | 
| MobileIronCore.Device.common.SerialNumber | String | Device serial number | 
| MobileIronCore.Device.common.mdm_managed | Boolean | Device is MDM managed | 


#### Command Example
```!mobileiron-core-get-device-by-ip device_id=IP```


#### Context Example
```json
{
    "MobileIronCore": {
        "Device": {
          "common.wifi_mac_address": "",
          "common.noncompliance_reasons": [
            "DEVICE_ADMIN_DEACTIVE"
          ],
          "ios.iPhone UDID": "",
          "common.device_is_compromised": false,
          "common.SerialNumber": "",
          "common.mdm_managed": false,
          "common.model": "Pixel",
          "common.os_version": "10.0",
          "common.status": "ACTIVE",
          "common.imei": "",
          "common.platform": "Android",
          "common.security_state": "Ok",
          "user.display_name": "*****",
          "common.last_connected_at": "2020-11-09T07:38:22.000Z",
          "common.uuid": "",
          "common.quarantined": false,
          "common.id": 3,
          "common.imsi": "*****",
          "common.owner": "COMPANY",
          "user.email_address": "*****",
          "common.manufacturer": "Google",
          "common.compliant": false,
          "user.user_id": "*****",
          "common.registration_date": "2020-10-29T14:11:39.000Z"
        }
    }
}
```


