Use the Palo Alto Networks Device Security integration to fetch alerts and vulnerabilities, retrieve device details, and resolve security incidents (previously Zingbox).

## Configure Palo Alto Networks Device Security in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| TSG ID |  | True |
| Client ID |  | True |
| Client Secret |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| First fetch time | The format must be &lt;number&gt; &lt;time unit&gt;, for example, 12 hours, 7 days, or 2 seconds. | False |
| Maximum number of incidents per fetch | The maximum number of events is 100. | False |
| Fetch Device Security Alerts | When selected, the integration fetches Device Security alerts from the Device Security Portal. | False |
| Fetch Device Security Vulnerabilities | When selected, the integration fetches Device Security vulnerabilities from the Device Security Security Portal. | False |
| Fetch incidents |  | False |
| Incidents Fetch Interval |  | False |
| The timeout for querying APIs |  | False |
| Incident type |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### device-security-get-device

***
Retrieves a single device's details using its MAC address.

#### Base Command

`device-security-get-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Retrieves the device UID (mac address). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksDeviceSecurity.Device | Object | The device details. |
| PaloAltoNetworksDeviceSecurity.Device.hostname | String | The hostname of the device. |
| PaloAltoNetworksDeviceSecurity.Device.ip_address | String | The IP address of the device. |
| PaloAltoNetworksDeviceSecurity.Device.profile_type | String | The device profile type: Non_IoT vs IoT. |
| PaloAltoNetworksDeviceSecurity.Device.profile_vertical | String | The device profile vertical. |
| PaloAltoNetworksDeviceSecurity.Device.category | String | The device category. |
| PaloAltoNetworksDeviceSecurity.Device.profile | String | The device profile. |
| PaloAltoNetworksDeviceSecurity.Device.last_activity | Date | The last activity timestamp of the device. |
| PaloAltoNetworksDeviceSecurity.Device.long_description | String | The long description of the device. |
| PaloAltoNetworksDeviceSecurity.Device.vlan | Number | The device VLAN ID. |
| PaloAltoNetworksDeviceSecurity.Device.site_name | String | The name of the site where the device is located. |
| PaloAltoNetworksDeviceSecurity.Device.risk_score | Number | The device risk score. |
| PaloAltoNetworksDeviceSecurity.Device.risk_level | String | The device risk level: Low, Medium, High, Critical. |
| PaloAltoNetworksDeviceSecurity.Device.subnet | String | The device subnet. |
| PaloAltoNetworksDeviceSecurity.Device.first_seen_date | Date | The first seen date of the device. |
| PaloAltoNetworksDeviceSecurity.Device.confidence_score | Number | The device confidence score. |
| PaloAltoNetworksDeviceSecurity.Device.deviceid | String | The device ID. |
| PaloAltoNetworksDeviceSecurity.Device.location | String | The device location. |
| PaloAltoNetworksDeviceSecurity.Device.vendor | String | The device vendor. |
| PaloAltoNetworksDeviceSecurity.Device.model | String | The device model. |
| PaloAltoNetworksDeviceSecurity.Device.description | String | The device description. |
| PaloAltoNetworksDeviceSecurity.Device.asset_tag | String | The device asset tag \(e.g. a sticky label at the bottom of the device\). |
| PaloAltoNetworksDeviceSecurity.Device.os_group | String | The device OS group. |
| PaloAltoNetworksDeviceSecurity.Device.Serial_Number | String | The device serial number. |
| PaloAltoNetworksDeviceSecurity.Device.DHCP | String | Whether the device uses DHCP configuration. Can be "Yes" or "No". |
| PaloAltoNetworksDeviceSecurity.Device.wire_or_wireless | String | Whether the device is wired or wireless. |
| PaloAltoNetworksDeviceSecurity.Device.department | String | The device department. |
| PaloAltoNetworksDeviceSecurity.Device.Switch_Port | Number | The port of the switch this device is connected to. |
| PaloAltoNetworksDeviceSecurity.Device.Switch_Name | String | The name of the switch this device is connected to. |
| PaloAltoNetworksDeviceSecurity.Device.Switch_IP | String | The IP of the switch this device is connected to. |
| PaloAltoNetworksDeviceSecurity.Device.Access_Point_IP | String | The IP of the access point this device is connected to. |
| PaloAltoNetworksDeviceSecurity.Device.Access_Point_Name | String | The name of the access point this device is connected to. |
| PaloAltoNetworksDeviceSecurity.Device.SSID | String | The SSID of the wireless network this device is connected to. |
| PaloAltoNetworksDeviceSecurity.Device.MAC | String | The device MAC address. |
| PaloAltoNetworksDeviceSecurity.Device.display_tags | String | The user tags of the device. |
| PaloAltoNetworksDeviceSecurity.Device.mac_address | String | The device MAC address. |

### device-security-get-device-by-ip

***
Returns a single device's details using its IP address.

#### Base Command

`device-security-get-device-by-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The device IP address. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksDeviceSecurity.Device | Object | The device details. |
| PaloAltoNetworksDeviceSecurity.Device.hostname | String | The hostname of the device. |
| PaloAltoNetworksDeviceSecurity.Device.ip_address | String | The IP address of the device. |
| PaloAltoNetworksDeviceSecurity.Device.profile_type | String | The device profile type: Non_IoT vs IoT. |
| PaloAltoNetworksDeviceSecurity.Device.profile_vertical | String | The device profile vertical. |
| PaloAltoNetworksDeviceSecurity.Device.category | String | The device category. |
| PaloAltoNetworksDeviceSecurity.Device.profile | String | The device profile. |
| PaloAltoNetworksDeviceSecurity.Device.last_activity | Date | The last activity timestamp of the device. |
| PaloAltoNetworksDeviceSecurity.Device.long_description | String | The long description of the device. |
| PaloAltoNetworksDeviceSecurity.Device.vlan | Number | The device VLAN ID. |
| PaloAltoNetworksDeviceSecurity.Device.site_name | String | The name of the site where the device is located. |
| PaloAltoNetworksDeviceSecurity.Device.risk_score | Number | The device risk score. |
| PaloAltoNetworksDeviceSecurity.Device.risk_level | String | The device risk level: Low, Medium, High, Critical. |
| PaloAltoNetworksDeviceSecurity.Device.subnet | String | The device subnet. |
| PaloAltoNetworksDeviceSecurity.Device.first_seen_date | Date | The first seen date of the device. |
| PaloAltoNetworksDeviceSecurity.Device.confidence_score | Number | The device confidence score. |
| PaloAltoNetworksDeviceSecurity.Device.deviceid | String | The device ID. |
| PaloAltoNetworksDeviceSecurity.Device.location | String | The device location. |
| PaloAltoNetworksDeviceSecurity.Device.vendor | String | The device vendor. |
| PaloAltoNetworksDeviceSecurity.Device.model | String | The device model. |
| PaloAltoNetworksDeviceSecurity.Device.description | String | The device description. |
| PaloAltoNetworksDeviceSecurity.Device.asset_tag | String | The device asset tag \(e.g. a sticky label at the bottom of the device\). |
| PaloAltoNetworksDeviceSecurity.Device.os_group | String | The device OS group. |
| PaloAltoNetworksDeviceSecurity.Device.Serial_Number | String | The device serial number. |
| PaloAltoNetworksDeviceSecurity.Device.DHCP | String | Whether the device uses DHCP configuration. Can be "Yes" or "No". |
| PaloAltoNetworksDeviceSecurity.Device.wire_or_wireless | String | Whether the device is wired or wireless. |
| PaloAltoNetworksDeviceSecurity.Device.department | String | The device department. |
| PaloAltoNetworksDeviceSecurity.Device.Switch_Port | Number | The port of the switch this device is connected to. |
| PaloAltoNetworksDeviceSecurity.Device.Switch_Name | String | The name of the switch this device is connected to. |
| PaloAltoNetworksDeviceSecurity.Device.Switch_IP | String | The IP of the switch this device is connected to. |
| PaloAltoNetworksDeviceSecurity.Device.Access_Point_IP | String | The IP of the access point this device is connected to. |
| PaloAltoNetworksDeviceSecurity.Device.Access_Point_Name | String | The name of the access point this device is connected to. |
| PaloAltoNetworksDeviceSecurity.Device.SSID | String | The SSID of the wireless network this device is connected to. |
| PaloAltoNetworksDeviceSecurity.Device.MAC | String | The device MAC address. |
| PaloAltoNetworksDeviceSecurity.Device.display_tags | String | The user tags of the device. |
| PaloAltoNetworksDeviceSecurity.Device.mac_address | String | The device MAC address. |

### device-security-list-devices

***
Retrieves a list of devices.

#### Base Command

`device-security-list-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The offset in the pagination. | Optional |
| limit | The maximum size of the list of the devices. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksDeviceSecurity.DeviceList | List | The list of devices. |

### device-security-list-alerts

***
Device security list alerts command.

#### Base Command

`device-security-list-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start time in the format of ISO 8601 in UTC, e.g. 2018-11-06T08:56:41Z. | Optional |
| offset | The offset in the pagination. | Optional |
| limit | The maximum size of the list of the alerts. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksDeviceSecurity.Alerts | List | The list of alerts. |

### device-security-list-vulns

***
Retrieves a list of device security vulnerabilities.

#### Base Command

`device-security-list-vulns`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start time in ISO 8601 UTC format, for example 2018-11-06T08:56:41Z. | Optional |
| offset | The offset in the pagination. | Optional |
| limit | The maximum size of the list of the vulnerabilities. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksDeviceSecurity.Vulns | List | The list of vulnerabilities. |

### device-security-resolve-alert

***
Resolves a device security alert.

#### Base Command

`device-security-resolve-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The alert ID. | Required |
| reason | The alert resolution reason. | Optional |
| reason_type | The alert resolution reason type (No Action Needed, Issue Mitigated). Possible values are: No Action Needed, Issue Mitigated. | Optional |

#### Context Output

There is no context output for this command.

### device-security-resolve-vuln

***
Resolves a device security vulnerability.

#### Base Command

`device-security-resolve-vuln`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The vulnerability ID. | Required |
| full_name | The vulnerability full name. | Required |
| reason | The vulnerability resolution reason. | Optional |

#### Context Output

There is no context output for this command.
