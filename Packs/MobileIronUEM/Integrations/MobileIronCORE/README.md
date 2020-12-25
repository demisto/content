# MobileIron CORE Integration

This integration was created and tested with version *11.0.0* of MobileIronCORE

## MobileIron Core - Getting Started

1. Log in to the MobileIron Core Admin console
2. Open the `Users` top section
3. Click on the `create local user` button. It is recommended to create a new user for the demisto integration specifically and not reuse
an existing one.
4. Make sure you enter all the details and keep note of the User ID (ex. demisto-api-user) and the password specifically.
5. Click on the `Admins` top section
6. Add the user you just created as an admin to the instance.
6. When setting up the Demisto integration use User ID as the username and the password you defined as the MobileIron tenant credentials
7. Click the `Test` button and ensure the connection can be established

Refer to the API documentation at the MobileIron community for more details on setting up the API user.

### MobileIron Core - Spaces

In case you are dividing the devices into different spaces, it is important to make sure the integration
points to the correct `Device Admin Space ID`.
 
This is in most cases set to the value *1* for the global space id

### Setting up pre-processing rules

In case you are using the fetch incidents option its advisable to set-up a pre-processing rule in order
to filter out any duplicates that might show up as part of the command. 

- Inside the Demisto XSOAR admin go to Settings -> Integrations -> Pre-Processing Rules
- In *Step 1* add a rule for *Type* equals *MobileIron Core Device Incident*
- In *Step 2* select *Drop and Update*
- In *Step 3* select *Link to oldest incident* created within the last *15 days* and check the checkbox next to 
*Search closed incidents* 
- Add an *AND* statement and enter *MobileIron Device ID* of existing incident is identical to the one of the 
incoming incident 
- Save

Here is an example image of the rule

![Pre-Processing Rules Example](Packs/MobileIronUEM/doc_files/preprocess_rules.png) 

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
| MobileIronCore.Device.common_model | String | Model | 
| MobileIronCore.Device.common_os_version | String | OS Version | 
| MobileIronCore.Device.common_platform | String | Platform Name | 
| MobileIronCore.Device.common_status | String | Status | 
| MobileIronCore.Device.common_imei | String | IMEI | 
| MobileIronCore.Device.common_platform | String | Platform | 
| MobileIronCore.Device.common_security_state | String | Security State | 
| MobileIronCore.Device.user_display_name | String | Display Name | 
| MobileIronCore.Device.common_last_connected_at | Date | Last Connected At | 
| MobileIronCore.Device.common_uuid | String | Device UUID | 
| MobileIronCore.Device.common_quarantined | Boolean | Quarantined | 
| MobileIronCore.Device.common_id | Number | Device ID | 
| MobileIronCore.Device.common_imsi | String | IMSI | 
| MobileIronCore.Device.common_owner | String | Device Owner | 
| MobileIronCore.Device.user_email_address | String | User Email Address | 
| MobileIronCore.Device.common_manufacturer | String | Manufacturer | 
| MobileIronCore.Device.common_compliant | Boolean | Compliant | 
| MobileIronCore.Device.user_user_id | String | User ID | 
| MobileIronCore.Device.common_registration_date | Date | Registration Date | 
| MobileIronCore.Device.common_wifi_mac_address | String | Wifi MAC Address | 
| MobileIronCore.Device.common_noncompliance_reasons | String | Non compliance Reasons | 
| MobileIronCore.Device.ios_iPhone_UDID | String | iPhone UDID | 
| MobileIronCore.Device.ios_iPhone_MAC_ADDRESS_EN0 | String | IPhone MAC Address EN0 | 
| MobileIronCore.Device.ios_Current_MCC | String | Current MCC | 
| MobileIronCore.Device.common_current_country_code | String | Current country code | 
| MobileIronCore.Device.user_sam_account_name | String | SAM account name | 
| MobileIronCore.Device.common_current_country_name | String | Current country name | 
| MobileIronCore.Device.common_home_country_name | String | Home country name | 
| MobileIronCore.Device.common_home_country_code | String | Home country code | 
| MobileIronCore.Device.common_device_is_compromised | Boolean | True if device is compromised | 
| MobileIronCore.Device.common_SerialNumber | String | Device serial number | 
| MobileIronCore.Device.common_mdm_managed | Boolean | Device is MDM managed | 


#### Command Example
```!mobileiron-core-get-devices-data```

#### Context Example
```json
{
    "MobileIronCore": {
        "Device": [
            {
              "common_wifi_mac_address": "",
              "common_noncompliance_reasons": [
                "DEVICE_ADMIN_DEACTIVE"
              ],
              "ios_iPhone_UDID": "",
              "common_device_is_compromised": false,
              "common_SerialNumber": "",
              "common_mdm_managed": false,
              "common_model": "Pixel",
              "common_os_version": "10.0",
              "common_status": "ACTIVE",
              "common_imei": "",
              "common_platform": "Android",
              "common_security_state": "Ok",
              "user_display_name": "*****",
              "common_last_connected_at": "2020-11-09T07:38:22.000Z",
              "common_uuid": "",
              "common_quarantined": false,
              "common_id": 3,
              "common_imsi": "*****",
              "common_owner": "COMPANY",
              "user_email_address": "*****",
              "common_manufacturer": "Google",
              "common_compliant": false,
              "user_user_id": "*****",
              "common_registration_date": "2020-10-29T14:11:39.000Z"
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
| MobileIronCore.Device.common_model | String | Model | 
| MobileIronCore.Device.common_os_version | String | OS Version | 
| MobileIronCore.Device.common_platform | String | Platform Name | 
| MobileIronCore.Device.common_status | String | Status | 
| MobileIronCore.Device.common_imei | String | IMEI | 
| MobileIronCore.Device.common_platform | String | Platform | 
| MobileIronCore.Device.common_security_state | String | Security State | 
| MobileIronCore.Device.user_display_name | String | Display Name | 
| MobileIronCore.Device.common_last_connected_at | Date | Last Connected At | 
| MobileIronCore.Device.common_uuid | String | Device UUID | 
| MobileIronCore.Device.common_quarantined | Boolean | Quarantined | 
| MobileIronCore.Device.common_id | Number | Device ID | 
| MobileIronCore.Device.common_imsi | String | IMSI | 
| MobileIronCore.Device.common_owner | String | Device Owner | 
| MobileIronCore.Device.user_email_address | String | User Email Address | 
| MobileIronCore.Device.common_manufacturer | String | Manufacturer | 
| MobileIronCore.Device.common_compliant | Boolean | Compliant | 
| MobileIronCore.Device.user_user_id | String | User ID | 
| MobileIronCore.Device.common_registration_date | Date | Registration Date | 
| MobileIronCore.Device.common_wifi_mac_address | String | Wifi MAC Address | 
| MobileIronCore.Device.common_noncompliance_reasons | String | Non compliance Reasons | 
| MobileIronCore.Device.ios_iPhone_UDID | String | iPhone UDID | 
| MobileIronCore.Device.ios_iPhone_MAC_ADDRESS_EN0 | String | IPhone MAC Address EN0 | 
| MobileIronCore.Device.ios_Current_MCC | String | Current MCC | 
| MobileIronCore.Device.common_current_country_code | String | Current country code | 
| MobileIronCore.Device.user_sam_account_name | String | SAM account name | 
| MobileIronCore.Device.common_current_country_name | String | Current country name | 
| MobileIronCore.Device.common_home_country_name | String | Home country name | 
| MobileIronCore.Device.common_home_country_code | String | Home country code | 
| MobileIronCore.Device.common_device_is_compromised | Boolean | True if device is compromised | 
| MobileIronCore.Device.common_SerialNumber | String | Device serial number | 
| MobileIronCore.Device.common_mdm_managed | Boolean | Device is MDM managed | 


#### Command Example
```!mobileiron-core-get-device-by-uuid device_uuid=9b0da853-9f9b-483c-97ef-f4b5457299cf```

#### Context Example
```json
{
    "MobileIronCore": {
        "Device": {
          "common_wifi_mac_address": "",
          "common_noncompliance_reasons": [
            "DEVICE_ADMIN_DEACTIVE"
          ],
          "ios_iPhone_UDID": "",
          "common_device_is_compromised": false,
          "common_SerialNumber": "",
          "common_mdm_managed": false,
          "common_model": "Pixel",
          "common_os_version": "10.0",
          "common_status": "ACTIVE",
          "common_imei": "",
          "common_platform": "Android",
          "common_security_state": "Ok",
          "user_display_name": "*****",
          "common_last_connected_at": "2020-11-09T07:38:22.000Z",
          "common_uuid": "",
          "common_quarantined": false,
          "common_id": 3,
          "common_imsi": "*****",
          "common_owner": "COMPANY",
          "user_email_address": "*****",
          "common_manufacturer": "Google",
          "common_compliant": false,
          "user_user_id": "*****",
          "common_registration_date": "2020-10-29T14:11:39.000Z"
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
| MobileIronCore.Device.common_model | String | Model | 
| MobileIronCore.Device.common_os_version | String | OS Version | 
| MobileIronCore.Device.common_platform | String | Platform Name | 
| MobileIronCore.Device.common_status | String | Status | 
| MobileIronCore.Device.common_imei | String | IMEI | 
| MobileIronCore.Device.common_platform | String | Platform | 
| MobileIronCore.Device.common_security_state | String | Security State | 
| MobileIronCore.Device.user_display_name | String | Display Name | 
| MobileIronCore.Device.common_last_connected_at | Date | Last Connected At | 
| MobileIronCore.Device.common_uuid | String | Device UUID | 
| MobileIronCore.Device.common_quarantined | Boolean | Quarantined | 
| MobileIronCore.Device.common_id | Number | Device ID | 
| MobileIronCore.Device.common_imsi | String | IMSI | 
| MobileIronCore.Device.common_owner | String | Device Owner | 
| MobileIronCore.Device.user_email_address | String | User Email Address | 
| MobileIronCore.Device.common_manufacturer | String | Manufacturer | 
| MobileIronCore.Device.common_compliant | Boolean | Compliant | 
| MobileIronCore.Device.user_user_id | String | User ID | 
| MobileIronCore.Device.common_registration_date | Date | Registration Date | 
| MobileIronCore.Device.common_wifi_mac_address | String | Wifi MAC Address | 
| MobileIronCore.Device.common_noncompliance_reasons | String | Non compliance Reasons | 
| MobileIronCore.Device.ios_iPhone_UDID | String | iPhone UDID | 
| MobileIronCore.Device.ios_iPhone_MAC_ADDRESS_EN0 | String | IPhone MAC Address EN0 | 
| MobileIronCore.Device.ios_Current_MCC | String | Current MCC | 
| MobileIronCore.Device.common_current_country_code | String | Current country code | 
| MobileIronCore.Device.user_sam_account_name | String | SAM account name | 
| MobileIronCore.Device.common_current_country_name | String | Current country name | 
| MobileIronCore.Device.common_home_country_name | String | Home country name | 
| MobileIronCore.Device.common_home_country_code | String | Home country code | 
| MobileIronCore.Device.common_device_is_compromised | Boolean | True if device is compromised | 
| MobileIronCore.Device.common_SerialNumber | String | Device serial number | 
| MobileIronCore.Device.common_mdm_managed | Boolean | Device is MDM managed | 


#### Command Example
```!mobileiron-core-get-device-by-serial device_serial=EXAMPLE```


#### Context Example
```json
{
    "MobileIronCore": {
        "Device": {
          "common_wifi_mac_address": "",
          "common_noncompliance_reasons": [
            "DEVICE_ADMIN_DEACTIVE"
          ],
          "ios_iPhone_UDID": "",
          "common_device_is_compromised": false,
          "common_SerialNumber": "",
          "common_mdm_managed": false,
          "common_model": "Pixel",
          "common_os_version": "10.0",
          "common_status": "ACTIVE",
          "common_imei": "",
          "common_platform": "Android",
          "common_security_state": "Ok",
          "user_display_name": "*****",
          "common_last_connected_at": "2020-11-09T07:38:22.000Z",
          "common_uuid": "",
          "common_quarantined": false,
          "common_id": 3,
          "common_imsi": "*****",
          "common_owner": "COMPANY",
          "user_email_address": "*****",
          "common_manufacturer": "Google",
          "common_compliant": false,
          "user_user_id": "*****",
          "common_registration_date": "2020-10-29T14:11:39.000Z"
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
| MobileIronCore.Device.common_model | String | Model | 
| MobileIronCore.Device.common_os_version | String | OS Version | 
| MobileIronCore.Device.common_platform | String | Platform Name | 
| MobileIronCore.Device.common_status | String | Status | 
| MobileIronCore.Device.common_imei | String | IMEI | 
| MobileIronCore.Device.common_platform | String | Platform | 
| MobileIronCore.Device.common_security_state | String | Security State | 
| MobileIronCore.Device.user_display_name | String | Display Name | 
| MobileIronCore.Device.common_last_connected_at | Date | Last Connected At | 
| MobileIronCore.Device.common_uuid | String | Device UUID | 
| MobileIronCore.Device.common_quarantined | Boolean | Quarantined | 
| MobileIronCore.Device.common_id | Number | Device ID | 
| MobileIronCore.Device.common_imsi | String | IMSI | 
| MobileIronCore.Device.common_owner | String | Device Owner | 
| MobileIronCore.Device.user_email_address | String | User Email Address | 
| MobileIronCore.Device.common_manufacturer | String | Manufacturer | 
| MobileIronCore.Device.common_compliant | Boolean | Compliant | 
| MobileIronCore.Device.user_user_id | String | User ID | 
| MobileIronCore.Device.common_registration_date | Date | Registration Date | 
| MobileIronCore.Device.common_wifi_mac_address | String | Wifi MAC Address | 
| MobileIronCore.Device.common_noncompliance_reasons | String | Non compliance Reasons | 
| MobileIronCore.Device.ios_iPhone_UDID | String | iPhone UDID | 
| MobileIronCore.Device.ios_iPhone_MAC_ADDRESS_EN0 | String | IPhone MAC Address EN0 | 
| MobileIronCore.Device.ios_Current_MCC | String | Current MCC | 
| MobileIronCore.Device.common_current_country_code | String | Current country code | 
| MobileIronCore.Device.user_sam_account_name | String | SAM account name | 
| MobileIronCore.Device.common_current_country_name | String | Current country name | 
| MobileIronCore.Device.common_home_country_name | String | Home country name | 
| MobileIronCore.Device.common_home_country_code | String | Home country code | 
| MobileIronCore.Device.common_device_is_compromised | Boolean | True if device is compromised | 
| MobileIronCore.Device.common_SerialNumber | String | Device serial number | 
| MobileIronCore.Device.common_mdm_managed | Boolean | Device is MDM managed | 


#### Command Example
```!mobileiron-core-get-device-by-mac device_mac=EXAMPLE```


#### Context Example
```json
{
    "MobileIronCore": {
        "Device": {
          "common_wifi_mac_address": "",
          "common_noncompliance_reasons": [
            "DEVICE_ADMIN_DEACTIVE"
          ],
          "ios_iPhone_UDID": "",
          "common_device_is_compromised": false,
          "common_SerialNumber": "",
          "common_mdm_managed": false,
          "common_model": "Pixel",
          "common_os_version": "10.0",
          "common_status": "ACTIVE",
          "common_imei": "",
          "common_platform": "Android",
          "common_security_state": "Ok",
          "user_display_name": "*****",
          "common_last_connected_at": "2020-11-09T07:38:22.000Z",
          "common_uuid": "",
          "common_quarantined": false,
          "common_id": 3,
          "common_imsi": "*****",
          "common_owner": "COMPANY",
          "user_email_address": "*****",
          "common_manufacturer": "Google",
          "common_compliant": false,
          "user_user_id": "*****",
          "common_registration_date": "2020-10-29T14:11:39.000Z"
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
| MobileIronCore.Device.common_model | String | Model | 
| MobileIronCore.Device.common_os_version | String | OS Version | 
| MobileIronCore.Device.common_platform | String | Platform Name | 
| MobileIronCore.Device.common_status | String | Status | 
| MobileIronCore.Device.common_imei | String | IMEI | 
| MobileIronCore.Device.common_platform | String | Platform | 
| MobileIronCore.Device.common_security_state | String | Security State | 
| MobileIronCore.Device.user_display_name | String | Display Name | 
| MobileIronCore.Device.common_last_connected_at | Date | Last Connected At | 
| MobileIronCore.Device.common_uuid | String | Device UUID | 
| MobileIronCore.Device.common_quarantined | Boolean | Quarantined | 
| MobileIronCore.Device.common_id | Number | Device ID | 
| MobileIronCore.Device.common_imsi | String | IMSI | 
| MobileIronCore.Device.common_owner | String | Device Owner | 
| MobileIronCore.Device.user_email_address | String | User Email Address | 
| MobileIronCore.Device.common_manufacturer | String | Manufacturer | 
| MobileIronCore.Device.common_compliant | Boolean | Compliant | 
| MobileIronCore.Device.user_user_id | String | User ID | 
| MobileIronCore.Device.common_registration_date | Date | Registration Date | 
| MobileIronCore.Device.common_wifi_mac_address | String | Wifi MAC Address | 
| MobileIronCore.Device.common_noncompliance_reasons | String | Non compliance Reasons | 
| MobileIronCore.Device.ios_iPhone_UDID | String | iPhone UDID | 
| MobileIronCore.Device.ios_iPhone_MAC_ADDRESS_EN0 | String | IPhone MAC Address EN0 | 
| MobileIronCore.Device.ios_Current_MCC | String | Current MCC | 
| MobileIronCore.Device.common_current_country_code | String | Current country code | 
| MobileIronCore.Device.user_sam_account_name | String | SAM account name | 
| MobileIronCore.Device.common_current_country_name | String | Current country name | 
| MobileIronCore.Device.common_home_country_name | String | Home country name | 
| MobileIronCore.Device.common_home_country_code | String | Home country code | 
| MobileIronCore.Device.common_device_is_compromised | Boolean | True if device is compromised | 
| MobileIronCore.Device.common_SerialNumber | String | Device serial number | 
| MobileIronCore.Device.common_mdm_managed | Boolean | Device is MDM managed | 


#### Command Example
```!mobileiron-core-get-device-by-ip device_id=IP```


#### Context Example
```json
{
    "MobileIronCore": {
        "Device": {
          "common_wifi_mac_address": "",
          "common_noncompliance_reasons": [
            "DEVICE_ADMIN_DEACTIVE"
          ],
          "ios_iPhone_UDID": "",
          "common_device_is_compromised": false,
          "common_SerialNumber": "",
          "common_mdm_managed": false,
          "common_model": "Pixel",
          "common_os_version": "10.0",
          "common_status": "ACTIVE",
          "common_imei": "",
          "common_platform": "Android",
          "common_security_state": "Ok",
          "user_display_name": "*****",
          "common_last_connected_at": "2020-11-09T07:38:22.000Z",
          "common_uuid": "",
          "common_quarantined": false,
          "common_id": 3,
          "common_imsi": "*****",
          "common_owner": "COMPANY",
          "user_email_address": "*****",
          "common_manufacturer": "Google",
          "common_compliant": false,
          "user_user_id": "*****",
          "common_registration_date": "2020-10-29T14:11:39.000Z"
        }
    }
}
```


