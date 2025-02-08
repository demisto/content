This is the Palo Alto Networks IoT integration (previously Zingbox).
This integration was integrated and tested with the Banff release of Palo Alto Networks IoT.

## Get your Palo Alto Networks IoT Access Keys
This integration requires that API access be configured.
To obtain the **Access Key ID** and **Secret Access Key**, refer to the [Palo Alto Networks IoT API User Guide](https://docs.paloaltonetworks.com/iot/iot-security-api-reference/iot-security-api-overview/get-started-with-the-iot-security-api.html).

## Configure Palo Alto Networks IoT in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Palo Alto Networks IoT Security Portal URL \(e.g. https://example.iot.paloaltonetworks.com\) | True |
| tenant_id | Tenant ID | True |
| access_key_id | Access Key ID | True |
| secret_access_key | Secret Access Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| first_fetch | First fetch time | False |
| max_fetch | Maximum number of incidents per fetch | False |
| fetch_alerts | Fetch IoT Alerts | False |
| fetch_vulns | Fetch IoT Vulnerabilities | False |
| api_timeout | The timeout for querying APIs | False |
| incidentType | Incident type | False |
| isFetch | Fetch incidents | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### iot-security-get-device
***
IoT get device command - get a single device's details.


#### Base Command

`iot-security-get-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The device uid (mac address) | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksIoT.Device | unknown | Device details. |
| PaloAltoNetworksIoT.Device.hostname | String | The hostname of the device. |
| PaloAltoNetworksIoT.Device.ip_address | String | The IP address of the device. |
| PaloAltoNetworksIoT.Device.profile_type | String | The device profile type: Non\_IoT vs IoT. |
| PaloAltoNetworksIoT.Device.profile_vertical | String | The device profile vertical. |
| PaloAltoNetworksIoT.Device.category | String | The device category |
| PaloAltoNetworksIoT.Device.profile | String | The device profile. |
| PaloAltoNetworksIoT.Device.last_activity | Date | The last activity timestamp of the device. |
| PaloAltoNetworksIoT.Device.long_description | String | The long description of the device. |
| PaloAltoNetworksIoT.Device.vlan | Number | The device VLAN ID. |
| PaloAltoNetworksIoT.Device.site_name | String | The site which the device is in. |
| PaloAltoNetworksIoT.Device.risk_score | Number | The device risk score. |
| PaloAltoNetworksIoT.Device.risk_level | String | The device risk level: Low, Medium, High, Critical |
| PaloAltoNetworksIoT.Device.subnet | String | The device subnet. |
| PaloAltoNetworksIoT.Device.first_seen_date | Date | The first seen date of the device. |
| PaloAltoNetworksIoT.Device.confidence_score | Number | The device confidence score. |
| PaloAltoNetworksIoT.Device.deviceid | Date | The device ID. |
| PaloAltoNetworksIoT.Device.location | String | The device location. |
| PaloAltoNetworksIoT.Device.vendor | String | The device vendor. |
| PaloAltoNetworksIoT.Device.model | String | The device model. |
| PaloAltoNetworksIoT.Device.description | String | The device description. |
| PaloAltoNetworksIoT.Device.asset_tag | String | The device asset tag \(e.g. a sticky label at the bottom of the device\). |
| PaloAltoNetworksIoT.Device.os_group | String | The device OS group. |
| PaloAltoNetworksIoT.Device.Serial_Number | String | The device serial number. |
| PaloAltoNetworksIoT.Device.DHCP | String | Whether the device is in DHCP model: Valid values are Yes or No. |
| PaloAltoNetworksIoT.Device.wire_or_wireless | String | Is the device wired or wireless. |
| PaloAltoNetworksIoT.Device.department | String | The device department. |
| PaloAltoNetworksIoT.Device.Switch_Port | Number | The port of the switch this device is connected to. |
| PaloAltoNetworksIoT.Device.Switch_Name | String | The name of the switch this device is connected to. |
| PaloAltoNetworksIoT.Device.Switch_IP | String | The IP of the switch this device is connected to. |
| PaloAltoNetworksIoT.Device.Access_Point_IP | String | The IP of the access point this device is connected to. |
| PaloAltoNetworksIoT.Device.Access_Point_Name | String | The name of the access point this device is connected to. |
| PaloAltoNetworksIoT.Device.SSID | String | The SSID of the wireless network this device is connected to. |
| PaloAltoNetworksIoT.Device.MAC | Date | The device MAC address. |
| PaloAltoNetworksIoT.Device.display_tags | String | The user tags of the device. |
| PaloAltoNetworksIoT.Device.mac_address | String | The device MAC address. |


#### Command Example
```iot-security-get-device id=00:0f:e5:04:14:4c```

#### Human Readable Output
|AD_Domain|AD_Username|AET|Access_Point_IP|Access_Point_Name|Applications|Authentication_Method|CMMS_Category|CMMS_Source|CMMS_State|DHCP|EAP_Method|Encryption_Cipher|External_Inventory_Sync_Field|MAC|NAC_Auth_Info|NAC_Auth_State|NAC_profile|NAC_profile_source|NetworkLocation|SMB|SSID|Serial_Number|Source|Switch_IP|Switch_Name|Switch_Port|Synced_With_Third-Party|Time_Synced_With_Third-Party|WIFI_Auth_Status|WIFI_Auth_Timestamp|asset_tag|category|confidence_score|department|description|deviceid|display_tags|endpoint_protection|endpoint_protection_vendor|first_seen_date|hostname|in_use|ip_address|is_server|last_activity|location|long_description|mac_address|model|number_of_caution_alerts|number_of_critical_alerts|number_of_info_alerts|number_of_warning_alerts|os/firmware_version|os_combined|os_group|parent_mac|profile|profile_type|profile_vertical|risk_level|risk_score|services|site_name|source|subnet|vendor|vlan|wire_or_wireless|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |  |  |  |  |  |  |  | 00:0f:e5:04:14:4c |  |  |  |  |  |  |  |  | Monitored |  |  |  |  |  |  |  |  | Physical Security | 94 |  |  | 00:0f:e5:04:14:4c |  | not_protected |  | 2020-08-13T07:21:02.000Z | 00:0f:e5:04:14:4c |  | 10.70.112.20 |  | 2020-08-18T19:26:05.000Z |  |  | 00:0f:e5:04:14:4c |  | 0 | 0 | 0 | 0 |  |  |  |  | Access Control Device | IoT | Facility | Low | 10 |  | test-katherine-0821 |  | 10.0.0.0/8 | HID Global/Mercury Security |  |  |


### iot-security-list-devices
***
IoT list devices command


#### Base Command

`iot-security-list-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The offset in the pagination. | Optional |
| limit | The maximum size of the list of the devices. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksIoT.DeviceList | unknown | List of devices. |


#### Command Example
```iot-security-list-devices offset=0 limit=2```

#### Human Readable Output
|AD_Domain|AD_Username|AET|Access_Point_IP|Access_Point_Name|Applications|Authentication_Method|CMMS_Category|CMMS_Source|CMMS_State|DHCP|EAP_Method|Encryption_Cipher|External_Inventory_Sync_Field|MAC|NAC_Auth_Info|NAC_Auth_State|NAC_profile|NAC_profile_source|NetworkLocation|SMB|SSID|Serial_Number|Source|Switch_IP|Switch_Name|Switch_Port|Synced_With_Third-Party|Time_Synced_With_Third-Party|WIFI_Auth_Status|WIFI_Auth_Timestamp|asset_tag|category|confidence_score|department|description|deviceid|display_tags|endpoint_protection|endpoint_protection_vendor|first_seen_date|hostname|in_use|ip_address|is_server|last_activity|location|long_description|mac_address|model|number_of_caution_alerts|number_of_critical_alerts|number_of_info_alerts|number_of_warning_alerts|os/firmware_version|os_combined|os_group|parent_mac|profile|profile_type|profile_vertical|risk_level|risk_score|services|site_name|source|subnet|vendor|vlan|wire_or_wireless|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | Monitored |  |  |  |  |  |  |  |  | Smartphone | 90 |  |  | 356582100001420 |  | not_protected |  | 2020-08-11T01:45:31.000Z | 356582100001420 |  | 1.0.2.2 |  | 2020-08-11T00:09:02.000Z |  |  | 356582100001420 | iPhone 11 (A2223) | 0 | 0 | 0 | 0 |  | iOS | iOS |  | Apple iPhone 11 (A2223) | IoT | Traditional IT | Low | 21 |  |  test |  | uknown |  |  |  |
|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | Monitored |  |  |  |  |  |  |  |  | Smartphone | 90 |  |  | 356582100001430 |  | not_protected |  | 2020-08-11T01:48:05.000Z | 356582100001430 |  | 1.0.3.2 |  | 2020-08-11T00:09:02.000Z |  |  | 356582100001430 | iPhone 11 (A2223) | 0 | 0 | 0 | 0 |  | iOS | iOS |  | Apple iPhone 11 (A2223) | IoT | Traditional IT | Low | 21 |  |  test |  | uknown |  |  |  |


### iot-security-list-alerts
***
IoT list alerts.


#### Base Command

`iot-security-list-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start time in the format of ISO 8601 in UTC, e.g. 2018-11-06T08:56:41Z. | Optional |
| offset | The offset in the pagination. | Optional |
| limit | The maximum size of the list of the alerts. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksIoT.Alerts | unknown | List of alerts. |


#### Command Example
```iot-security-list-alerts offset=0 limit=2```

#### Human Readable Output
|category|date|description|deviceid|hostname|id|inspectorid|internal_hostname|msg|name|profile|reason_history|resolved|serviceLevel|severity|severityNumber|siteid|tenantid|type|zb_ticketid|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Network Security Equipment | 2020-08-26T06:11:04.000Z | The usage of an outdated Chrome version has been detected on this device. Using older versions of a web browser can expose your device to security risks. | d4:f4:be:b0:c3:10 |  | 5f463c8703a2260700a99dbf | 012501000732 |  | severity: low&lt;br&gt;taggedBy: PolicyAlert&lt;br&gt;userPolicy: false&lt;br&gt;alertType: security risk&lt;br&gt;localDeviceRole: initiator&lt;br&gt;values: {'label': 'user agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19041'}&lt;br&gt;localProfile: Palo Alto Networks Device&lt;br&gt;description: The usage of an outdated Chrome version has been detected on this device. Using older versions of a web browser can expose your device to security risks.&lt;br&gt;recommendation: {"content": ["Update the browser to the latest version", "If browser usage on the device is authorized and essential, use a URL-filtering tool to block connections to known malicious websites or update firewall policy rules to permit connections only to designated websites.", "Check network traffic coming to and from the device on the device details page and enable trusted behavior by applying an ACL (access control list) to restrict nonessential traffic."]}&lt;br&gt;alertKey: 24072002d4:f4:be:b0:c3:10analytics-outdated-chrome&lt;br&gt;anomalyMap: {"application": 1}&lt;br&gt;generationTimestamp: 1598438532757&lt;br&gt;autoPublish: true&lt;br&gt;name: Outdated Chrome version used by IoT device&lt;br&gt;localip: 192.168.58.56&lt;br&gt;fromip: 192.168.58.56&lt;br&gt;id: ObDMsWG0&lt;br&gt;ruleid: analytics-outdated-chrome&lt;br&gt;status: publish&lt;br&gt;toURL: UNKNOWN URL&lt;br&gt;hostname: unknown | Outdated Chrome version used by IoT device | Palo Alto Networks Device |  | no |  | low | 2 | 0 |  | policy_alert | alert-ObDMsWG0 |
| IT Server | 2020-08-26T02:09:43.000Z | This event indicates a brute force attack through multiple login attempts to an SSH server. | 00:25:90:92:82:2a |  | 5f45c4a52f31500800a47fc7 | 012501003437 |  | taggedBy: PolicyAlert&lt;br&gt;values: {'label': 'device profile', 'value': 'Super Micro Computer'},&lt;br&gt;{'label': 'client port', 'value': 34904},&lt;br&gt;{'label': 'threat ID', 'value': 40015},&lt;br&gt;{'label': 'threat category', 'value': 'brute-force'},&lt;br&gt;{'label': 'threat type', 'value': 'vulnerability'},&lt;br&gt;{'label': 'number of occurrences', 'value': 2},&lt;br&gt;{'label': 'alert source', 'value': 'Firewall'},&lt;br&gt;{'label': 'firewall name', 'value': 'SJC-Eng-5260-fw1'},&lt;br&gt;{'label': 'firewall action', 'value': 'Raised an alert'},&lt;br&gt;{'label': 'firewall inbound interface', 'value': 'vlan'},&lt;br&gt;{'label': 'firewall outbound interface', 'value': 'vlan'}&lt;br&gt;localProfile: Super Micro Computer&lt;br&gt;localDeviceLabels: Attacker&lt;br&gt;description: This event indicates a brute force attack through multiple login attempts to an SSH server.&lt;br&gt;recommendation: {"content": ["Enable brute-force login protection by setting a maximum limit for the number of unsuccessful login attempts the device will accept before refusing further attempts.", "If unauthorized users tried to log in, block the IP addresses from which they made their attempts.", "Avoid using the manufacturer's default credentials or the same text string as both the username and password.", "Strengthen the login username and password for the ssh application."]}&lt;br&gt;anomalyMap: {"payload": 2}&lt;br&gt;generationTimestamp: 1598407836500&lt;br&gt;remoteHostMetadata: {'deviceIds': ['10.0.16.245'], 'ip': '10.0.16.245', 'connections': [{'app': 'ssh', 'port': 22, 'ipProto': 'tcp'}], 'network': 'internal'}&lt;br&gt;toip: 10.0.16.245&lt;br&gt;fromip: 10.0.6.174&lt;br&gt;id: KbYbFjYw&lt;br&gt;severity: medium&lt;br&gt;threatid: 40015&lt;br&gt;userPolicy: false&lt;br&gt;alertType: vulnerability&lt;br&gt;localDeviceRole: initiator&lt;br&gt;appName: ssh&lt;br&gt;alertKey: 2407200200:25:90:92:82:2aanalytics-evt-threat-attacker40015&lt;br&gt;remoteHostLabels: Victim&lt;br&gt;autoPublish: true&lt;br&gt;isAttempt: false&lt;br&gt;forensicData: {"search": {"iotdevid": "00:25:90:92:82:2a", "threatid": 40015, "remoteIPAddr": ["10.0.16.245"], "appName": "ssh", "tenantid": "24072002", "isClient": "Yes", "reverse": true, "timestamp": 1598407783000, "isLocal": true, "direction": "client to server"}, "addFields": {"rxPkts": "packets", "txPkts": "packets"}}&lt;br&gt;name: SSH User Authentication Brute Force Attempt&lt;br&gt;localip: 10.0.6.174&lt;br&gt;threatCategory: brute-force&lt;br&gt;ruleid: analytics-evt-threat-attacker&lt;br&gt;status: publish&lt;br&gt;toURL: UNKNOWN URL&lt;br&gt;hostname: unknown | SSH User Authentication Brute Force Attempt | Super Micro Computer |  | no |  | medium | 3 | 0 |  | policy_alert | alert-KbYbFjYw |


### iot-security-list-vulns
***
IoT list Vulnerabilities.


#### Base Command

`iot-security-list-vulns`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start time in the format of ISO 8601 in UTC, e.g. 2018-11-06T08:56:41Z. | Optional |
| offset | The offset in the pagination. | Optional |
| limit | The maximum size of the list of the vulnerabilities. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksIoT.Vulns | unknown | List of vulnerabilities. |


#### Command Example
```iot-security-list-vulns limit=2 offset=0```

#### Human Readable Output
|asset_tag|date|detected_date|deviceid|display_profile_category|ip|model|name|os|osCombined|profile|profile_vertical|reason_history|remediate_checkbox|remediate_instruction|remediate_workorder|risk_level|risk_score|siteName|siteid|sn|ticketAssignees|ticketState|vendor|vulnerability_name|zb_ticketid|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|  | 2020-07-16T09:18:21.000Z | 2020-08-20T23:59:59.000Z | 64:16:7f:77:45:c9 | Video Audio Conference | 10.72.32.237 | Trio8800 | Polycom_64167f7745c9 | Embedded | Embedded | Polycom Video Conferencing Device | Office |  |  |  |  | Low | 26 |  test | 0 |  |  |  | Polycom | Vulnerability Test - Medium | vuln-65046ad8 |
|  | 2020-07-22T19:18:32.000Z | 2020-08-20T23:59:59.000Z | 64:16:7f:76:64:c6 | Video Audio Conference | 10.72.33.195 | Trio8800 | Polycom_64167f7664c6 | Embedded | Embedded | Polycom Device | Office |  |  |  |  | Low | 26 |  test | 0 |  |  |  | Polycom | Vulnerability Test - Medium | vuln-8cc12cd4 |


### iot-security-resolve-alert
***
Resolving an IoT alert.


#### Base Command

`iot-security-resolve-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The alert ID | Required |
| reason | The alert resolution reason. | Optional |
| reason_type | The alert resolution reason type (No Action Needed, Issue Mitigated). | Optional |


#### Context Output

There is no context output for this command.

#### Command Example
```iot-security-resolve-alert id="5e73ecb3eff46f80a7cdc57a" reason=test reason_type="No Action Needed"```


### iot-security-resolve-vuln
***
Resolving an IoT vulnerability.


#### Base Command

`iot-security-resolve-vuln`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The vulnerability ID. | Required |
| full_name | The vulnerability full name. | Required |
| reason | The vulnerability resolution reason. | Optional |


#### Context Output

There is no context output for this command.

#### Command Example
```iot-security-resolve-vuln full_name=CVE-2019-10960 id=vuln-b12d4f0a reason=test```


### iot-security-get-device-by-ip
***
IoT get device command - get a single device's details.


#### Base Command

`iot-security-get-device-by-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The device ip (ip address). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksIoT.Device | unknown | Device details. | 
| PaloAltoNetworksIoT.Device.hostname | String | The hostname of the device. | 
| PaloAltoNetworksIoT.Device.ip_address | String | The IP address of the device. | 
| PaloAltoNetworksIoT.Device.profile_type | String | The device profile type: Non_IoT vs IoT. | 
| PaloAltoNetworksIoT.Device.profile_vertical | String | The device profile vertical. | 
| PaloAltoNetworksIoT.Device.category | String | The device category | 
| PaloAltoNetworksIoT.Device.profile | String | The device profile. | 
| PaloAltoNetworksIoT.Device.last_activity | Date | The last activity timestamp of the device. | 
| PaloAltoNetworksIoT.Device.long_description | String | The long description of the device. | 
| PaloAltoNetworksIoT.Device.vlan | Number | The device VLAN ID. | 
| PaloAltoNetworksIoT.Device.site_name | String | The site which the device is in. | 
| PaloAltoNetworksIoT.Device.risk_score | Number | The device risk score. | 
| PaloAltoNetworksIoT.Device.risk_level | String | The device risk level: Low, Medium, High, Critical | 
| PaloAltoNetworksIoT.Device.subnet | String | The device subnet. | 
| PaloAltoNetworksIoT.Device.first_seen_date | Date | The first seen date of the device. | 
| PaloAltoNetworksIoT.Device.confidence_score | Number | The device confidence score. | 
| PaloAltoNetworksIoT.Device.deviceid | Date | The device ID. | 
| PaloAltoNetworksIoT.Device.location | String | The device location. | 
| PaloAltoNetworksIoT.Device.vendor | String | The device vendor. | 
| PaloAltoNetworksIoT.Device.model | String | The device model. | 
| PaloAltoNetworksIoT.Device.description | String | The device description. | 
| PaloAltoNetworksIoT.Device.asset_tag | String | The device asset tag \(e.g. a sticky label at the bottom of the device\). | 
| PaloAltoNetworksIoT.Device.os_group | String | The device OS group. | 
| PaloAltoNetworksIoT.Device.Serial_Number | String | The device serial number. | 
| PaloAltoNetworksIoT.Device.DHCP | String | Whether the device is in DHCP model: Valid values are Yes or No. | 
| PaloAltoNetworksIoT.Device.wire_or_wireless | String | Is the device wired or wireless. | 
| PaloAltoNetworksIoT.Device.department | String | The device department. | 
| PaloAltoNetworksIoT.Device.Switch_Port | Number | The port of the switch this device is connected to. | 
| PaloAltoNetworksIoT.Device.Switch_Name | String | The name of the switch this device is connected to. | 
| PaloAltoNetworksIoT.Device.Switch_IP | String | The IP of the switch this device is connected to. | 
| PaloAltoNetworksIoT.Device.Access_Point_IP | String | The IP of the access point this device is connected to. | 
| PaloAltoNetworksIoT.Device.Access_Point_Name | String | The name of the access point this device is connected to. | 
| PaloAltoNetworksIoT.Device.SSID | String | The SSID of the wireless network this device is connected to. | 
| PaloAltoNetworksIoT.Device.MAC | Date | The device MAC address. | 
| PaloAltoNetworksIoT.Device.display_tags | String | The user tags of the device. | 
| PaloAltoNetworksIoT.Device.mac_address | String | The device MAC address. | 