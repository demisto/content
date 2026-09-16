Use the Palo Alto Networks Device Security integration to fetch alerts and vulnerabilities, retrieve device details, and resolve security incidents (previously Zingbox).

## Prerequisites

Before configuring the integration, ensure that you have:

- Access to a Strata Cloud Manager (SCM) tenant.
- A valid Tenant Service Group (TSG) ID.
- An OAuth **Client ID** and **Client Secret** for a service account with the required permissions.
- A custom role assigned to the service account with the following permissions:
  - **Devices:** Read
  - **Alerts:** Read, Write
  - **Vulnerabilities:** Read, Write

## Configure Palo Alto Networks Device Security in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| TSG ID |  | True |
| Client ID |  | True |
| Client Secret |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| First fetch time | The format must be &lt;number&gt; &lt;time unit&gt;, for example, 12 hours, 7 days, or 2 seconds. | False |
| Maximum number of incidents per fetch | The maximum number of incidents is 100. | False |
| Fetch Device Security Alerts | When selected, the integration fetches Device Security alerts from the Device Security Portal. | False |
| Fetch Device Security Vulnerabilities | When selected, the integration fetches Device Security vulnerabilities from the Device Security Portal. | False |
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

#### Command Example

```!device-security-get-device id="00:50:56:bf:32:95"```

#### Context Example

```json
{
    "PaloAltoNetworksDeviceSecurity.Device": {
        "AD_Domain": null,
        "wire_or_wireless": null,
        "NAC_profile_source": null,
        "cmms_end_of_service": null,
        "cmms_mission_critical": null,
        "Windows_Installed_Software_Version": null,
        "internet_access": "Yes",
        "mdm_lost_mode_capable": null,
        "risk_score": 30,
        "cmms_warranty_date": null,
        "CMMS_State": null,
        "confidence_score_factors": {
            "0": {
                "name": "Network Behaviors",
                "ts": "2026.07.09"
            },
            "1": {
                "name": "Application Behaviors",
                "ts": "2026.07.09"
            },
            "2": {
                "name": "Device Attributes",
                "ts": "2026.07.09"
            }
        },
        "first_seen_date": "2026-07-02T19:50:02.000Z",
        "site_name": "Test Google Map",
        "Applications": "",
        "vlan": "1",
        "childrenDeviceids": null,
        "endpoint_protection": "not_protected",
        "NetworkLocation": null,
        "os_group": null,
        "SCCM_Model": null,
        "endpoint_protection_vendor": null,
        "iccid": null,
        "Has_Children": "No",
        "number_of_critical_alerts": 0,
        "cmms_device_purchase_price": null,
        "Windows_GUID": null,
        "Windows_Installed_Patches_Source": null,
        "os_end_of_support": null,
        "Encryption_Cipher": null,
        "dnac_location": null,
        "Authentication_Method": null,
        "SMB": null,
        "vendor": "VMware, Inc.",
        "os_ver": null,
        "mdm_model_identifier": null,
        "customAttributes": [
            {
                "test_jnolan": "testing-adding-device-id"
            }
        ],
        "firmwareVer": null,
        "profile": "VMware",
        "WIFI_Auth_Timestamp": null,
        "NAC_Auth_State": null,
        "SCCM_Domain": null,
        "model": null,
        "cmms_equipment_number": null,
        "cmms_id": null,
        "CMMS_Source": null,
        "Total_Scan_Time(min)": "",
        "asset_tag": null,
        "EAP_Method": null,
        "number_of_warning_alerts": 0,
        "profile_vertical": "Traditional IT",
        "SCCM_Site": null,
        "Synced_With_Third-Party": null,
        "Disk_Encryption_Status": null,
        "Switch_Port": null,
        "mdm_supervised": null,
        "CMMS_Category": null,
        "External_Inventory_Sync_Field": null,
        "SCCM_Vendor": null,
        "in_use": "",
        "Disk_Encryption_Status_Source": null,
        "MAC": "00:50:56:bf:32:95",
        "SCCM_Serial_Number": null,
        "profile_type": "Non_IoT",
        "AET": null,
        "display_meid": null,
        "PHI": "No",
        "deviceid": "00:50:56:bf:32:95",
        "Access_Point_IP": null,
        "cmms_end_of_life": null,
        "Network_Segments": "28",
        "mdm_vendor": null,
        "DHCP": null,
        "Status": "Offline",
        "AD_Username": null,
        "Switch_IP": null,
        "department": null,
        "hostname": "apt1",
        "cmms_device_replacement_cost": null,
        "confidence_score_status": "existing",
        "risk_level": "Low",
        "Serial_Number": null,
        "Windows_Installed_Patches": null,
        "Access_Point_Name": null,
        "Windows_GUID_Source": null,
        "location": null,
        "NAC_Auth_Info": null,
        "number_of_info_alerts": 0,
        "Switch_Name": null,
        "display_tags": null,
        "cmms_owner_id": null,
        "mdm_managed": null,
        "display_ssid": null,
        "cmms_next_service": null,
        "Case_Studies": "",
        "last_activity": "2026-07-08T23:35:04.707Z",
        "Images": "",
        "config_source": null,
        "is_server": null,
        "Tags": "",
        "long_description": "",
        "parent_mac": null,
        "allTags": [],
        "NAC_profile": null,
        "Time_Synced_With_Third-Party": null,
        "Tag": [],
        "source": "",
        "Source": "Monitored",
        "mdm_device_id": null,
        "cmms_last_service": null,
        "ip_address": "10.0.2.184",
        "cmms_secondary_mac_and_ip_addresses": null,
        "description": null,
        "mdm_lock_status": null,
        "confidence_score": 70,
        "mdm_firmware_version": null,
        "number_of_caution_alerts": 0,
        "subnet": "10.0.0.0/12",
        "services": null,
        "category": "Virtual Machine",
        "WIFI_Auth_Status": null,
        "os/firmware_version": null
    }
}
```

#### Human Readable Output

>### Device Security Device
>
>| AD_Domain | AD_Username | AET | Access_Point_IP | Access_Point_Name | Applications | Authentication_Method | CMMS_Category | CMMS_Source | CMMS_State | DHCP | EAP_Method | Encryption_Cipher | External_Inventory_Sync_Field | MAC | NAC_Auth_Info | NAC_Auth_State | NAC_profile | NAC_profile_source | NetworkLocation | SMB | SSID | Serial_Number | Source | Switch_IP | Switch_Name | Switch_Port | Synced_With_Third-Party | Time_Synced_With_Third-Party | WIFI_Auth_Status | WIFI_Auth_Timestamp | asset_tag | category | confidence_score | department | description | deviceid | display_tags | endpoint_protection | endpoint_protection_vendor | first_seen_date | hostname | in_use | ip_address | is_server | last_activity | location | long_description | mac_address | model | number_of_caution_alerts | number_of_critical_alerts | number_of_info_alerts | number_of_warning_alerts | os/firmware_version | os_combined | os_group | parent_mac | profile | profile_type | profile_vertical | risk_level | risk_score | services | site_name | source | subnet | vendor | vlan | wire_or_wireless |
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
>|  |  |  |  |  |  |  |  |  |  |  |  |  |  | 00:50:56:bf:32:95 |  |  |  |  |  |  |  |  | Monitored |  |  |  |  |  |  |  |  | Virtual Machine | 70 |  |  | 00:50:56:bf:32:95 |  | not_protected |  | 2026-07-02T19:50:02.000Z | apt1 |  | 10.0.2.184 |  | 2026-07-08T23:35:04.707Z |  |  | 00:50:56:bf:32:95 |  | 0 | 0 | 0 | 0 |  |  |  |  | VMware | Non_IoT | Traditional IT | Low | 30 |  | Test Google Map |  | 10.0.0.0/12 | VMware, Inc. | 1 |  |

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

#### Command Example

```!device-security-get-device-by-ip ip="10.0.2.184"```

#### Context Example

```json
{
    "PaloAltoNetworksDeviceSecurity.Device": [
        {
            "risk_score": 30,
            "first_seen_date": "2026-07-02T19:50:02.000Z",
            "site_name": "Test Google Map",
            "Applications": "",
            "vlan": "1",
            "endpoint_protection": "not_protected",
            "mac_address": "00:50:56:bf:32:95",
            "number_of_critical_alerts": 1,
            "vendor": "VMware, Inc.",
            "profile": "VMware",
            "number_of_warning_alerts": 2,
            "profile_vertical": "Traditional IT",
            "zone": null,
            "in_use": "",
            "segmentId": "28",
            "MAC": "00:50:56:bf:32:95",
            "profile_type": "Non_IoT",
            "attr": {
                "panwIoTFname_39Cd0UDM8": "",
                "panwIoTFname_f_nfikiK3T_source": "ruleBased",
                "panwIoTFname_1001": "unknown",
                "panwIoTFname_1002": "2",
                "panwIoTFname_6_G_6PYPEg_source": "config",
                "panwIoTFname_1003": "",
                "panwIoTFname_pVeqQm9URJ": "defaultValueEdit7",
                "panwIoTFname_vLo9iTCUkB_source": "config",
                "panwIoTFname_1004": "testbbbb",
                "panwIoTFname_1005": "Unmanaged",
                "panwIoTFname_VhpPXcTuF": "mohamed-test-value",
                "panwIoTFname_jUXXLtTC7_source": "config",
                "panwIoTFname_J-gAZNlwze": "test",
                "panwIoTFname_J-gAZNlwze_source": "config",
                "panwIoTFname_jUXXLtTC7": "katherine-test-value",
                "panwIoTFname_VhpPXcTuF_source": "config",
                "panwIoTFname_1005_source": "config",
                "panwIoTFname_1004_source": "config",
                "panwIoTFname_6_G_6PYPEg": "ff",
                "panwIoTFname_vLo9iTCUkB": "abc",
                "panwIoTFname_pVeqQm9URJ_source": "config",
                "panwIoTFname_1003_source": "config",
                "panwIoTFname_1002_source": "config",
                "panwIoTFname_1001_source": "config",
                "panwIoTFname_f_nfikiK3T": "testing-adding-device-id",
                "panwIoTFname_39Cd0UDM8_source": "config"
            },
            "deviceid": "00:50:56:bf:32:95",
            "hostname": "apt1",
            "risk_level": "Low",
            "number_of_info_alerts": 1,
            "last_activity": "2026-07-08T23:35:04.707Z",
            "allTags": [],
            "source": "",
            "ip_address": "10.0.2.184",
            "ext_network_date": "2026-07-05T02:22:12.000Z",
            "confidence_score": 70,
            "number_of_caution_alerts": 0,
            "subnet": "10.0.0.0/12",
            "category": "Virtual Machine"
        }
    ]    
}
```

#### Human Readable Output

>### Device Security Devices
>
>| AD_Domain | AD_Username | AET | Access_Point_IP | Access_Point_Name | Applications | Authentication_Method | CMMS_Category | CMMS_Source | CMMS_State | DHCP | EAP_Method | Encryption_Cipher | External_Inventory_Sync_Field | MAC | NAC_Auth_Info | NAC_Auth_State | NAC_profile | NAC_profile_source | NetworkLocation | SMB | SSID | Serial_Number | Source | Switch_IP | Switch_Name | Switch_Port | Synced_With_Third-Party | Time_Synced_With_Third-Party | WIFI_Auth_Status | WIFI_Auth_Timestamp | asset_tag | category | confidence_score | department | description | deviceid | display_tags | endpoint_protection | endpoint_protection_vendor | first_seen_date | hostname | in_use | ip_address | is_server | last_activity | location | long_description | mac_address | model | number_of_caution_alerts | number_of_critical_alerts | number_of_info_alerts | number_of_warning_alerts | os/firmware_version | os_combined | os_group | parent_mac | profile | profile_type | profile_vertical | risk_level | risk_score | services | site_name | source | subnet | vendor | vlan | wire_or_wireless |
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
>|  |  |  |  |  |  |  |  |  |  |  |  |  |  | 00:50:56:bf:32:95 |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | Virtual Machine | 70 |  |  | 00:50:56:bf:32:95 |  | not_protected |  | 2026-07-02T19:50:02.000Z | apt1 |  | 10.0.2.184 |  | 2026-07-08T23:35:04.707Z |  |  | 00:50:56:bf:32:95 |  | 0 | 1 | 1 | 2 |  |  |  |  | VMware | Non_IoT | Traditional IT | Low | 30 |  | Test Google Map |  | 10.0.0.0/12 | VMware, Inc. | 1 |  |

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

#### Command Example

```!device-security-list-devices offset=0 limit=2```

#### Context Example

```json
{
    "PaloAltoNetworksDeviceSecurity.DeviceList": 
    [{
  "firewall": [
   {
    "applianceid": "012501003437",
    "date": "2026-07-03T06:43:01.523Z"
   }
  ],
  "display_vlan": null,
  "carm_sources_seen_array": [
   "iot.bg_connect",
   "iot.bg_profiler",
   "iot.auto_tag",
   "iot.offline_profile",
   "iot.ai_confidence_score_breakdown",
   "data_quality_metrics"
  ],
  "display_profile_confidence_level": "70_Medium",
  "siteid": "43",
  "ml_risk_score": 0,
  "WireWireless": "wireless",
  "ip": "10.47.115.129",
  "vendor": "Apple Inc.",
  "display_protos": "ssh,ssl,web-browsing",
  "last_network_activity": "2026-07-03T06:43:01.523Z",
  "profile": "Apple Device",
  "firstseen": "2026-07-02T19:46:29.000Z",
  "ouiVendor": "Apple, Inc.",
  "name": "88:66:5a:1e:a0:3c",
  "profile_vertical": "Traditional IT",
  "epp_safety": "not_protected",
  "MAC_sources_seen_array": [
   "iot.hipmatch"
  ],
  "zone": null,
  "segmentId": "28",
  "MAC": "88:66:5a:1e:a0:3c",
  "display_apps": "",
  "profile_type": "Non_IoT",
  "carm_first_source": "iot.bg_connect",
  "attr": {
   "panwIoTFname_39Cd0UDM8": "",
   "panwIoTFname_f_nfikiK3T_source": "ruleBased",
   "panwIoTFname_1001": "Level 4",
   "panwIoTFname_1002": "2",
   "panwIoTFname_6_G_6PYPEg_source": "config",
   "panwIoTFname_1003": "",
   "panwIoTFname_pVeqQm9URJ": "defaultValueEdit7",
   "panwIoTFname_vLo9iTCUkB_source": "config",
   "panwIoTFname_1004": "testbbbb",
   "panwIoTFname_1005": "Unmanaged",
   "panwIoTFname_VhpPXcTuF": "mohamed-test-value",
   "panwIoTFname_jUXXLtTC7_source": "config",
   "panwIoTFname_J-gAZNlwze": "test",
   "panwIoTFname_J-gAZNlwze_source": "config",
   "panwIoTFname_jUXXLtTC7": "katherine-test-value",
   "panwIoTFname_VhpPXcTuF_source": "config",
   "panwIoTFname_1005_source": "config",
   "panwIoTFname_1004_source": "config",
   "panwIoTFname_6_G_6PYPEg": "ff",
   "panwIoTFname_vLo9iTCUkB": "abc",
   "panwIoTFname_pVeqQm9URJ_source": "config",
   "panwIoTFname_1003_source": "config",
   "panwIoTFname_1002_source": "config",
   "panwIoTFname_1001_source": "ruleBased",
   "panwIoTFname_f_nfikiK3T": "testing-adding-device-id",
   "panwIoTFname_39Cd0UDM8_source": "config"
  },
  "ml_risk_level": "Low",
  "countries": "No",
  "subnets": "10.0.0.0/10",
  "adv_name": {
   "734f1597-dc3a-4be6-bc43-820861090bbf": "Documentation-demo",
   "fce32059-a030-4cbe-912b-0e67b39a03af": "Onboarding Device"
  },
  "foreignAccess": "",
  "tags": {
   "panwIoTTname_1": "In Scope",
   "panwIoTTname_1_source": "ruleBased",
   "panwIoTTname_xvLLFTDKR": "test",
   "panwIoTTname_xvLLFTDKR_source": "ruleBased"
  },
  "_id": "6a46c0152dd53a90ec54b3c8",
  "source": "",
  "id": "88:66:5a:1e:a0:3c",
  "ext_network_date": "",
  "display_vlan_description": null,
  "display_profile_confidence": 70,
  "category": "generic",
  "latest_device_time": "2026-07-08T07:40:03.462Z"
 }]
}
```

#### Human Readable Output

>### Device Security Devices
>
>| AD_Domain | AD_Username | AET | Access_Point_IP | Access_Point_Name | Applications | Authentication_Method | CMMS_Category | CMMS_Source | CMMS_State | DHCP | EAP_Method | Encryption_Cipher | External_Inventory_Sync_Field | MAC | NAC_Auth_Info | NAC_Auth_State | NAC_profile | NAC_profile_source | NetworkLocation | SMB | SSID | Serial_Number | Source | Switch_IP | Switch_Name | Switch_Port | Synced_With_Third-Party | Time_Synced_With_Third-Party | WIFI_Auth_Status | WIFI_Auth_Timestamp | asset_tag | category | confidence_score | department | description | deviceid | display_tags | endpoint_protection | endpoint_protection_vendor | first_seen_date | hostname | in_use | ip_address | is_server | last_activity | location | long_description | mac_address | model | number_of_caution_alerts | number_of_critical_alerts | number_of_info_alerts | number_of_warning_alerts | os/firmware_version | os_combined | os_group | parent_mac | profile | profile_type | profile_vertical | risk_level | risk_score | services | site_name | source | subnet | vendor | vlan | wire_or_wireless |
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
>|  |  |  |  |  |  |  |  |  |  |  |  |  |  | 88:66:5a:1e:a0:3c |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | generic | 70 |  |  | 88:66:5a:1e:a0:3c |  | not_protected |  | 2026-07-02T19:46:29.000Z | 88:66:5a:1e:a0:3c |  | 10.47.115.129 |  | 2026-07-08T07:40:03.462Z |  |  | 88:66:5a:1e:a0:3c |  |  |  |  |  |  |  |  |  | Apple Device | Non_IoT | Traditional IT | Low | 0 |  |  |  | 10.0.0.0/10 | Apple Inc. |  | wireless |

### device-security-list-alerts

***
Retrieves a list of device security alerts.

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

#### Command Example

```!device-security-list-alerts offset=0 limit=2```

#### Context Example

```json
{
    "PaloAltoNetworksDeviceSecurity.Alerts": [
        {
            "msg": {
                "alertType": "action_center",
                "id": "JL6JM9RIa",
                "status": "publish"
            },
            "display_profile_confidence_level": "90_High",
            "siteid": "43",
            "tenantid": "",
            "severityNumber": 3,
            "profile": "Super Micro Computer",
            "name": "Action Center Alert",
            "date": "2026-07-09T06:30:03.843Z",
            "url": "https://iot45-64662843-csp-sls-09.iot.paloaltonetworks.com/guardian/alert/alert?id=JL6JM9RIa",
            "serviceLevel": "",
            "deviceid": "3c:ec:ef:fa:e6:3e",
            "siteName": "Test Google Map",
            "hostname": "ubuntu-server",
            "internal_hostname": "ubuntu-server",
            "trafficRestricted": true,
            "primaryDevice": null,
            "resolved": "no",
            "reason_history": [],
            "display_severity": "high",
            "type": "policy_alert",
            "id": "6a4f3feb7bb95b150609ad41",
            "description": "aaaa",
            "severity": "medium",
            "zb_ticketid": "alert-JL6JM9RIa",
            "category": "IT Server"
        }
    ]
}
```

#### Human Readable Output

>### Device Security Alerts
>
>| category | date | description | deviceid | hostname | id | inspectorid | internal_hostname | msg | name | profile | reason_history | resolved | serviceLevel | severity | severityNumber | siteid | tenantid | type | zb_ticketid |
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
>| IT Server | 2026-07-09T06:30:03.843Z | aaaa | 3c:ec:ef:fa:e6:3e | ubuntu-server | 6a4f3feb7bb95b150609ad41 |  | ubuntu-server | alertType: action_center; id: JL6JM9RIa; status: publish | Action Center Alert | Super Micro Computer | [] | no |  | medium | 3 | 43 |  | policy_alert | alert-JL6JM9RIa |

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

#### Command Example

```!device-security-list-vulns offset=0 limit=2```

#### Context Example

```json
{
  "PaloAltoNetworksDeviceSecurity.Vulns": [
    {
      "deviceid": "00:15:5d:94:1c:01",
      "cvss_score": 7.8,
      "detected_date": [
        "2023-10-11T19:15:09.000Z"
      ],
      "device_last_activity": "2026-06-15T05:50:44.677Z",
      "ics_cert": null,
      "is_sbom": false,
      "severity": "Medium",
      "source": "trend_micro_vision_one",
      "status": "Confirmed",
      "zb_ticketid": "vuln-3e396a5f",
      "ticketState": "new",
      "ticketAssignees": null,
      "reason_history": [
        {
          "evidence_type": "last_detected",
          "timestamp": "2023-10-11T19:15:09.000Z",
          "evidence": {}
        },
        {
          "evidence_type": "first_detected",
          "timestamp": "2023-10-11T19:15:09.000Z",
          "evidence": {}
        }
      ],
      "remediate_workorder": null,
      "remediate_checkbox": null,
      "remediate_instruction": null,
      "last_detected_date": "2023-10-11T19:15:09.000Z",
      "vulnerability_name": "CVE-2023-31096",
      "asset_criticality": "Medium",
      "name": "DESKTOP-A51IU1U",
      "ip": "172.30.72.200",
      "profile": "PC-Windows",
      "profile_vertical": "Traditional IT",
      "display_profile_category": "Personal Computer",
      "vendor": "Microsoft Corporation",
      "model": null,
      "os": "Windows",
      "osCombined": "Windows",
      "siteid": "43",
      "asset_tag": null,
      "sn": "4758-5248-5193-6935-8922-7043-79",
      "date": "2026-06-15T05:50:44.677Z",
      "risk_score": 0,
      "risk_level": "Low",
      "trafficRestricted": null,
      "subnets": "172.16.0.0/12",
      "display_profile_confidence_level": "70_Medium",
      "display_profile_confidence": 75,
      "siteName": "Test Google Map",
      "allTags": []
    }
  ]
}
```

#### Human Readable Output

>### Device Security Vulnerabilities
>
>| asset_tag | date | detected_date | deviceid | display_profile_category | ip | model | name | os | osCombined | profile | profile_vertical | reason_history | remediate_checkbox | remediate_instruction | remediate_workorder | risk_level | risk_score | siteName | siteid | sn | ticketAssignees | ticketState | vendor | vulnerability_name | zb_ticketid |
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
>|  | 2026-06-15T05:50:44.677Z | 2023-10-11T19:15:09.000Z | 00:15:5d:94:1c:01 | Personal Computer | 172.30.72.200 |  | DESKTOP-A51IU1U | Windows | Windows | PC-Windows | Traditional IT | evidence_type: last_detected; timestamp: 2023-10-11T19:15:09.000Z; evidence: {}; evidence_type: first_detected; timestamp: 2023-10-11T19:15:09.000Z; evidence: {} |  |  |  | Low | 0 | Test Google Map | 43 | 4758-5248-5193-6935-8922-7043-79 |  | new | Microsoft Corporation | CVE-2023-31096 | vuln-3e396a5f |

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

#### Command Example

```!device-security-resolve-alert id="5e73ecb3eff46f80a7cdc57a" reason="test" reason_type="No Action Needed"```

#### Context Example

There is no context example for this command because it does not return context output.

#### Human Readable Output

Alert 5e73ecb3eff46f80a7cdc57a was resolved successfully

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

#### Command Example

```!device-security-resolve-vuln id="vuln-b12d4f0a" full_name="CVE-2019-10960" reason="test"```

#### Context Example

There is no context example for this command because it does not return context output.

#### Human Readable Output

Vulnerability vuln-b12d4f0a was resolved successfully
