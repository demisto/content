VMware Workspace ONE UEM integration allows users to search enrolled corporate or employee-owned devices, provides detailed information about each device such as its serial number, installed OS's, pending OS updates, network details, and much more leveraging Workspace ONE UEM's (formerly AirWatch MDM) API.
This integration was integrated and tested with version 21.5.0.4 of VMware Workspace ONE UEM (AirWatch MDM)
## Configure VMware Workspace ONE UEM (AirWatch MDM) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Server URL to connect to VMware Workspace ONE UEM. | True |
| API Key | API key required for additional authorization. | True |
| Username | Username of administrative account with read access. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## API Limitations
- The [OS update](https://as1687.awmdm.com/api/help/#!/apis/10003?!%2FDevicesV2%2FDevicesV2_GetOSUpdatesByUUIDAsync) API returns an empty response for Windows devices even if updates can be seen in the UI.
- As per the [devices search](https://as1687.awmdm.com/api/help/#!/apis/10003?!%2FDevicesV2%2FDevicesV2_SearchAsync) API, the model parameter doesn't work with values like iPhone 6s (32 GB Silver).
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### vmwuem-devices-search
***
Searches device(s) using the query information provided.


#### Base Command

`vmwuem-devices-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | Filters devices based on enrolled username. | Optional | 
| model | Filters devices based on the model. For example: iPhone. | Optional | 
| platform | Filter devices based on device's platform type. For example: Apple, Android, WindowsPC, etc. | Optional | 
| last_seen | Filters devices based on the date when the devices were last seen.<br/><br/>Format accepted:<br/>(&lt;number&gt; &lt;time unit&gt;, e.g., "12 hours ago", "7 days ago", "1 week", "1 month") or (&lt;date&gt; &lt;time&gt;, e.g. "yyyy-mm-ddTHH-MM-SS") or ( "YYYY-MM-ddTHH:mm:ss.sssZ", e.g. 2020-07-22T07:10:02.782Z) or (&lt;date&gt;, e.g. "2020-07-22"). | Optional | 
| ownership | Filters devices based on ownership type. Possible values are: Corporate owned, Employee owned, Shared, or Undefined. | Optional | 
| lgid | Limits the search to a given Organization Group, defaults to the user's Organization Group. | Optional | 
| page | Filters search results to return results based on the page number. Starts from 0. Default is 0. | Optional | 
| page_size | Maximum records per page. Default is 10. | Optional | 
| order_by | Sorts results based on the provided field. Possible values are: model, lastseen, ownership, platform, deviceid, etc. Default is deviceid. | Optional | 
| sort_order | Sorts results based on the given sorting order. Possible values are: ASC or DESC. Default is ASC. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMwareWorkspaceONEUEM.Device.Uuid | String | The UUID of the device. | 
| VMwareWorkspaceONEUEM.Device.Id.Value | Number | The ID value of the device. | 
| VMwareWorkspaceONEUEM.Device.EasIds.EasId | Unknown | The unique identifiers for the device's mail client. | 
| VMwareWorkspaceONEUEM.Device.TimeZone | String | The time zone of the device. | 
| VMwareWorkspaceONEUEM.Device.Udid | String | The unique identifier of the device. | 
| VMwareWorkspaceONEUEM.Device.SerialNumber | String | The serial number reported by the device. | 
| VMwareWorkspaceONEUEM.Device.MacAddress | String | The MAC address of the device. | 
| VMwareWorkspaceONEUEM.Device.Imei | String | The IMEI hardware identifier of the device. | 
| VMwareWorkspaceONEUEM.Device.EasId | String | The EAS ID of the device. | 
| VMwareWorkspaceONEUEM.Device.AssetNumber | String | The asset number of the device. | 
| VMwareWorkspaceONEUEM.Device.DeviceFriendlyName | String | The friendly name of the device. | 
| VMwareWorkspaceONEUEM.Device.DeviceReportedName | String | The reported name of the device. | 
| VMwareWorkspaceONEUEM.Device.LocationGroupId.Id.Value | Number | The unique identifier of the location group the device belongs to. | 
| VMwareWorkspaceONEUEM.Device.LocationGroupId.Name | String | The name of the location group the device belongs to. | 
| VMwareWorkspaceONEUEM.Device.LocationGroupId.Uuid | String | The UUID of the location group the device belongs to. | 
| VMwareWorkspaceONEUEM.Device.LocationGroupName | String | The name of the location group the device belongs to. | 
| VMwareWorkspaceONEUEM.Device.UserId.Id.Value | Number | The unique identifier of the user the device is assigned to. | 
| VMwareWorkspaceONEUEM.Device.UserId.Name | String | The name of the user the device is assigned to. | 
| VMwareWorkspaceONEUEM.Device.UserId.Uuid | String | The UUID of the user the device is assigned to. | 
| VMwareWorkspaceONEUEM.Device.UserName | String | The username to which the device is assigned to. | 
| VMwareWorkspaceONEUEM.Device.DataProtectionStatus | Number | The data protection status of the user to which the device belongs to. | 
| VMwareWorkspaceONEUEM.Device.UserEmailAddress | String | The email address of the user. | 
| VMwareWorkspaceONEUEM.Device.Ownership | String | The device ownership status. I.e. Corporate, Employee, Shared, or Undefined. | 
| VMwareWorkspaceONEUEM.Device.PlatformId.Id.Value | Number | The platform ID of the device. | 
| VMwareWorkspaceONEUEM.Device.PlatformId.Name | String | The platform name of the device. | 
| VMwareWorkspaceONEUEM.Device.PlatformId.Uuid | String | The platform UUID of the device. | 
| VMwareWorkspaceONEUEM.Device.Platform | String | The platform of the device. Example: iOS, BlackBerry, Android, etc. | 
| VMwareWorkspaceONEUEM.Device.ModelId.Id.Value | Number | The model unique identifier of the device. | 
| VMwareWorkspaceONEUEM.Device.ModelId.Name | String | The model name of the device. | 
| VMwareWorkspaceONEUEM.Device.ModelId.Uuid | String | The model UUID of the device. | 
| VMwareWorkspaceONEUEM.Device.Model | String | The model of the device. | 
| VMwareWorkspaceONEUEM.Device.OperatingSystem | String | The operating system including version. | 
| VMwareWorkspaceONEUEM.Device.PhoneNumber | String | The user's phone number, if available. | 
| VMwareWorkspaceONEUEM.Device.LastSeen | Date | The time when the device last reported any status with AirWatch. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentStatus | String | The enrollment status of the device. | 
| VMwareWorkspaceONEUEM.Device.ComplianceStatus | String | The compliance status of the device. | 
| VMwareWorkspaceONEUEM.Device.CompromisedStatus | Boolean | Value indicating the compromised status of the device. True if the device is compromised, otherwise false. | 
| VMwareWorkspaceONEUEM.Device.LastEnrolledOn | Date | The date-time of the last enrollment. | 
| VMwareWorkspaceONEUEM.Device.LastComplianceCheckOn | Date | The date-time of when the last compliance check was performed. | 
| VMwareWorkspaceONEUEM.Device.LastCompromisedCheckOn | Date | The date-time of when the last compromised data was received. | 
| VMwareWorkspaceONEUEM.Device.ComplianceSummary.DeviceCompliance.CompliantStatus | Boolean | The compliant status of the device. | 
| VMwareWorkspaceONEUEM.Device.ComplianceSummary.DeviceCompliance.PolicyName | String | The policy name of the device. | 
| VMwareWorkspaceONEUEM.Device.ComplianceSummary.DeviceCompliance.PolicyDetail | String | Policy details of the device. | 
| VMwareWorkspaceONEUEM.Device.ComplianceSummary.DeviceCompliance.LastComplianceCheck | Date | The date-time of the last compliance check. | 
| VMwareWorkspaceONEUEM.Device.ComplianceSummary.DeviceCompliance.NextComplianceCheck | Date | The date-time of the next compliance check. | 
| VMwareWorkspaceONEUEM.Device.ComplianceSummary.DeviceCompliance.ActionTaken.ActionType | Number | The type of action taken on compliance violations. | 
| VMwareWorkspaceONEUEM.Device.ComplianceSummary.DeviceCompliance.Id.Value | Number | The compliance policy ID of the device. | 
| VMwareWorkspaceONEUEM.Device.ComplianceSummary.DeviceCompliance.Uuid | String | The compliance UUID of the device. | 
| VMwareWorkspaceONEUEM.Device.IsSupervised | Boolean | A value indicating whether the device is supervised or not. | 
| VMwareWorkspaceONEUEM.Device.DeviceMCC.SIMMCC | String | Information about device SIM Mobile Country Code. | 
| VMwareWorkspaceONEUEM.Device.DeviceMCC.CurrentMCC | String | Information about device Current Mobile Country Code. | 
| VMwareWorkspaceONEUEM.Device.IsRemoteManagementEnabled | String | Flag which indicates whether remote management \[MotoRC\] is enabled on the device or not. | 
| VMwareWorkspaceONEUEM.Device.DataEncryptionYN | String | Whether there is data protection enabled or not. | 
| VMwareWorkspaceONEUEM.Device.AcLineStatus | Number | The power status of the device. 0 indicates battery. 1 indicates AC Power. | 
| VMwareWorkspaceONEUEM.Device.VirtualMemory | Number | The size of the virtual memory. | 
| VMwareWorkspaceONEUEM.Device.OEMInfo | String | The OEM information of the device. | 
| VMwareWorkspaceONEUEM.Device.DeviceCapacity | Number | The total capacity of the device. | 
| VMwareWorkspaceONEUEM.Device.AvailableDeviceCapacity | Number | The available capacity of the device. | 
| VMwareWorkspaceONEUEM.Device.LastSystemSampleTime | Date | The last system sample time of the device. | 
| VMwareWorkspaceONEUEM.Device.IsDeviceDNDEnabled | Boolean | Value indicating whether the device is in do not disturb mode or not. | 
| VMwareWorkspaceONEUEM.Device.IsDeviceLocatorEnabled | Boolean | Value indicating whether the device's locator is enabled or not. | 
| VMwareWorkspaceONEUEM.Device.IsCloudBackupEnabled | Boolean | Value indicating whether the device's cloud backup is enabled or not. | 
| VMwareWorkspaceONEUEM.Device.IsActivationLockEnabled | Boolean | Value indicating whether the device's activation lock is enabled or not. | 
| VMwareWorkspaceONEUEM.Device.IsNetworkTethered | Boolean | Value indicating whether the iOS device is network tethered or not. | 
| VMwareWorkspaceONEUEM.Device.BatteryLevel | String | Gives information about the battery level of the iOS device. | 
| VMwareWorkspaceONEUEM.Device.IsRoaming | Boolean | Value indicating whether this gives information about the roaming status of the device. | 
| VMwareWorkspaceONEUEM.Device.LastNetworkLANSampleTime | Date | The last network LAN sample time of the device. | 
| VMwareWorkspaceONEUEM.Device.LastBluetoothSampleTime | Date | The last bluetooth sample time of the device. | 
| VMwareWorkspaceONEUEM.Device.SystemIntegrityProtectionEnabled | Boolean | Value indicating whether system integrity protection is enabled on a macOS device. | 
| VMwareWorkspaceONEUEM.Device.ProcessorArchitecture | Number | The processor architecture reported by the device. | 
| VMwareWorkspaceONEUEM.Device.UserApprovedEnrollment | Boolean | Flag to check if the user has approved installation of the MDM profile. | 
| VMwareWorkspaceONEUEM.Device.EnrolledViaDEP | Boolean | Informs if the device is enrolled via DEP. | 
| VMwareWorkspaceONEUEM.Device.TotalPhysicalMemory | Number | The total physical memory of the device. | 
| VMwareWorkspaceONEUEM.Device.AvailablePhysicalMemory | Number | The available physical memory of the device. | 
| VMwareWorkspaceONEUEM.Device.OSBuildVersion | String | The build version of the operating system. | 
| VMwareWorkspaceONEUEM.Device.HostName | String | The host name of the macOS device. | 
| VMwareWorkspaceONEUEM.Device.LocalHostName | String | The local host name of the macOS device as reported by Bonjour. | 
| VMwareWorkspaceONEUEM.Device.SecurityPatchDate | Date | The security patch date received from the agent. | 
| VMwareWorkspaceONEUEM.Device.SystemUpdateReceivedTime | Date | The pending system update received time. | 
| VMwareWorkspaceONEUEM.Device.IsSecurityPatchUpdate | Boolean | The value is true when there is a security patch update available. | 
| VMwareWorkspaceONEUEM.Device.DeviceManufacturerId | Number | The manufacturer ID of the device. | 
| VMwareWorkspaceONEUEM.Device.DeviceNetworkInfo.ConnectionType | String | The network connection type of the device. | 
| VMwareWorkspaceONEUEM.Device.DeviceNetworkInfo.IPAddress | String | The IP address of the device. | 
| VMwareWorkspaceONEUEM.Device.DeviceNetworkInfo.MACAddress | String | The MAC address of the device. | 
| VMwareWorkspaceONEUEM.Device.DeviceNetworkInfo.Name | String | The network interface name of the device. | 
| VMwareWorkspaceONEUEM.Device.DeviceNetworkInfo.Vendor | String | The vendor of the network interface. | 
| VMwareWorkspaceONEUEM.Device.DeviceCellularNetworkInfo.CarrierName | String | The carrier provider name of the device. | 
| VMwareWorkspaceONEUEM.Device.DeviceCellularNetworkInfo.CardId | String | The SIM card ID of the device. | 
| VMwareWorkspaceONEUEM.Device.DeviceCellularNetworkInfo.PhoneNumber | String | The phone number associated with the SIM. | 
| VMwareWorkspaceONEUEM.Device.DeviceCellularNetworkInfo.DeviceMCC.SIMMCC | String | Information about device SIM Mobile Country Code. | 
| VMwareWorkspaceONEUEM.Device.DeviceCellularNetworkInfo.DeviceMCC.CurrentMCC | String | Information about device Current Mobile Country Code. | 
| VMwareWorkspaceONEUEM.Device.DeviceCellularNetworkInfo.IsRoaming | Boolean | Whether roaming is enabled. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentUserUuid | String | The enrolled user UUID. | 
| VMwareWorkspaceONEUEM.Device.ManagedBy | Number | The device is managed by. = \['0', '1', '2', '3', '4', '5', '6', '998', '999'\] | 
| VMwareWorkspaceONEUEM.Device.WifiSsid | String | The Wifi SSID, if available. | 
| VMwareWorkspaceONEUEM.Device.DepTokenSource | Number | The value of the DEP token source. | 


#### Command Example
```!vmwuem-devices-search page_size=2```

#### Context Example
```json
{
    "VMwareWorkspaceONEUEM": {
        "Device": [
            {
                "AvailablePhysicalMemory": 0,
                "ComplianceStatus": "Compliant",
                "CompromisedStatus": false,
                "DataProtectionStatus": 0,
                "DepTokenSource": 0,
                "DeviceFriendlyName": "user123 Inspiron 5567 Windows Desktop 10.0.18363 CYL2",
                "DeviceReportedName": "user123 laptop",
                "EnrollmentStatus": "Enrolled",
                "EnrollmentUserUuid": "00000000-0000-0000-0000-000000000000",
                "Id": {
                    "Value": 5614
                },
                "IsActivationLockEnabled": false,
                "IsCloudBackupEnabled": false,
                "IsDeviceDNDEnabled": false,
                "IsDeviceLocatorEnabled": false,
                "IsNetworkTethered": false,
                "IsRoaming": false,
                "IsSupervised": false,
                "LastComplianceCheckOn": "0001-01-01T00:00:00.000",
                "LastCompromisedCheckOn": "2021-06-23T12:54:53.210",
                "LastEnrolledOn": "2021-06-23T12:44:21.720",
                "LastSeen": "2021-06-28T04:35:20.150",
                "LocationGroupId": {
                    "Id": {
                        "Value": 1210
                    },
                    "Name": "M123456789",
                    "Uuid": "12345678-1234-1234-1234-123456789ABC"
                },
                "LocationGroupName": "M123456789",
                "MacAddress": "ABABABABABAB",
                "ManagedBy": 1,
                "Model": "Inspiron 5567",
                "ModelId": {
                    "Id": {
                        "Value": 83
                    },
                    "Name": "Inspiron 5567"
                },
                "OEMInfo": "Dell Inc.",
                "OSBuildVersion": "1379",
                "OperatingSystem": "10.0.18363",
                "Ownership": "Undefined",
                "Platform": "WinRT",
                "PlatformId": {
                    "Id": {
                        "Value": 12
                    },
                    "Name": "WinRT"
                },
                "ProcessorArchitecture": 9,
                "SerialNumber": "ABC1234",
                "SystemIntegrityProtectionEnabled": false,
                "TotalPhysicalMemory": 0,
                "Udid": "7D584CC5A511D94CAD8713BA2A266CC7",
                "UserEmailAddress": "dummy-email",
                "UserId": {
                    "Id": {
                        "Value": 11572
                    },
                    "Name": "user user user",
                    "Uuid": "12345678-1234-1234-1234-123456789ABC"
                },
                "UserName": "user123",
                "Uuid": "12345678-1234-1234-1234-123456789ABC",
                "VirtualMemory": 0
            },
            {
                "AvailablePhysicalMemory": 0,
                "ComplianceStatus": "NonCompliant",
                "ComplianceSummary": {
                    "DeviceCompliance": [
                        {
                            "ActionTaken": [
                                {
                                    "ActionType": 1
                                }
                            ],
                            "CompliantStatus": false,
                            "Id": {
                                "Value": 93
                            },
                            "LastComplianceCheck": "2021-07-12T07:27:40.487",
                            "NextComplianceCheck": "0001-01-01T00:00:00.000",
                            "PolicyDetail": "Compromised Status",
                            "PolicyName": "Compromised Status",
                            "Uuid": "12345678-1234-1234-1234-123456789ABC"
                        }
                    ]
                },
                "CompromisedStatus": true,
                "DataProtectionStatus": 0,
                "DepTokenSource": 0,
                "DeviceFriendlyName": "user123-laptop2 Inspiron 15 7000 Gaming Windows Desktop 10.0.19042 DYL2",
                "DeviceReportedName": "user123's DESKTOP",
                "EnrollmentStatus": "Enrolled",
                "EnrollmentUserUuid": "00000000-0000-0000-0000-000000000000",
                "Id": {
                    "Value": 5711
                },
                "IsActivationLockEnabled": false,
                "IsCloudBackupEnabled": false,
                "IsDeviceDNDEnabled": false,
                "IsDeviceLocatorEnabled": false,
                "IsNetworkTethered": false,
                "IsRoaming": false,
                "IsSupervised": false,
                "LastComplianceCheckOn": "2021-07-12T07:27:40.487",
                "LastCompromisedCheckOn": "2021-06-28T02:59:52.557",
                "LastEnrolledOn": "2021-06-28T02:59:29.077",
                "LastSeen": "2021-07-12T08:28:57.557",
                "LocationGroupId": {
                    "Id": {
                        "Value": 1210
                    },
                    "Name": "M123456789",
                    "Uuid": "12345678-1234-1234-1234-123456789CBA"
                },
                "LocationGroupName": "M123456789",
                "MacAddress": "ABABABABABAB",
                "ManagedBy": 1,
                "Model": "Inspiron 15 7000 Gaming",
                "ModelId": {
                    "Id": {
                        "Value": 83
                    },
                    "Name": "Inspiron 15 7000 Gaming"
                },
                "OEMInfo": "Dell Inc.",
                "OSBuildVersion": "1083",
                "OperatingSystem": "10.0.19042",
                "Ownership": "E",
                "Platform": "WinRT",
                "PlatformId": {
                    "Id": {
                        "Value": 12
                    },
                    "Name": "WinRT"
                },
                "ProcessorArchitecture": 9,
                "SerialNumber": "ABC1234",
                "SystemIntegrityProtectionEnabled": false,
                "TotalPhysicalMemory": 0,
                "Udid": "6D8875FB9197E042842E27E6EC2CF1CA",
                "UserEmailAddress": "dummy-email",
                "UserId": {
                    "Id": {
                        "Value": 11866
                    },
                    "Name": "user  user",
                    "Uuid": "12345678-1234-1234-1234-123456789CBA"
                },
                "UserName": "user123-laptop2",
                "Uuid": "12345678-1234-1234-1234-123456789CBA",
                "VirtualMemory": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Device(s)
>|Device Friendly Name|UUID|Platform|Model|Ownership|Serial Number|MAC Address|Compliance Status|Compromised Status|User Email Address|Last Seen (In UTC)|
>|---|---|---|---|---|---|---|---|---|---|---|
>| user123 Inspiron 5567 Windows Desktop 10.0.18363 CYL2 | 12345678-1234-1234-1234-123456789ABC | WinRT | Inspiron 5567 | Undefined | ABC1234 | ABABABABABAB | Compliant | Not Compromised | dummy-email | June 28, 2021 at 04:35:20 AM |
>| user123-laptop2 Inspiron 15 7000 Gaming Windows Desktop 10.0.19042 DYL2 | 12345678-1234-1234-1234-123456789CBA | WinRT | Inspiron 15 7000 Gaming | Employee owned | ABC1234 | ABABABABABAB | NonCompliant | Compromised | dummy-email | July 12, 2021 at 08:28:57 AM |


### vmwuem-device-get
***
Get basic information about the device.


#### Base Command

`vmwuem-device-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The unique identifier of the device. Example: 153B4D9D-24DC-416B-91F9-94253D623611.<br/>Note: To get the uuid, use the command 'vmwuem-devices-search'. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMwareWorkspaceONEUEM.Device.Uuid | String | The UUID of the device. | 
| VMwareWorkspaceONEUEM.Device.Udid | String | The UDID of the device. | 
| VMwareWorkspaceONEUEM.Device.SerialNumber | String | The serial number of the device. | 
| VMwareWorkspaceONEUEM.Device.MacAddress | String | The MAC address of the device. | 
| VMwareWorkspaceONEUEM.Device.Imei | String | The IMEI hardware identifier of the device. | 
| VMwareWorkspaceONEUEM.Device.FriendlyName | String | The friendly name of the device. | 
| VMwareWorkspaceONEUEM.Device.OrganizationGroupName | String | The organization group name of the device. | 
| VMwareWorkspaceONEUEM.Device.TotalStorageBytes | String | Total storage capacity in bytes. | 
| VMwareWorkspaceONEUEM.Device.AvailableStorageBytes | String | Available storage capacity in bytes. | 
| VMwareWorkspaceONEUEM.Device.BatteryLevelPercentage | String | Battery level of the iOS device in percentage. | 
| VMwareWorkspaceONEUEM.Device.ComputerName | String | Desktop name of the device. | 
| VMwareWorkspaceONEUEM.Device.Supervised | Boolean | Supervised status of the device. | 
| VMwareWorkspaceONEUEM.Device.DataEncrypted | Boolean | Data encryption status. | 
| VMwareWorkspaceONEUEM.Device.PlatformInfo.DeviceType | String | Type of the device. | 
| VMwareWorkspaceONEUEM.Device.PlatformInfo.PlatformName | String | Name of the platform. | 
| VMwareWorkspaceONEUEM.Device.PlatformInfo.ModelName | String | Model of the device. | 
| VMwareWorkspaceONEUEM.Device.PlatformInfo.OsVersion | String | Version of the operating system installed on the device. | 
| VMwareWorkspaceONEUEM.Device.CarrierInfo.PhoneNumber | String | Phone number of the device. | 
| VMwareWorkspaceONEUEM.Device.CarrierInfo.RoamingEnabled | Boolean | Roaming status of the device. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentInfo.EnrollmentStatus | String | Enrollment status of the device. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentInfo.Compliant | Boolean | Compliance status of the device. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentInfo.EnrollmentTimestamp | Date | Date-time of last enrollment date. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentInfo.LastSeenTimestamp | Date | Time the device last reported any status. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentInfo.Ownership | String | Ownership type of the device. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentInfo.OrganizationGroupId | String | Id of the organization group. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentInfo.OrganizationGroupName | String | Organization group name where the device is enrolled. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentInfo.UserName | String | User name of the device. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentInfo.UserEmailAddress | String | User's email address of the device. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentInfo.EnrollmentUserUuid | String | Enrollment user uuid of device. | 
| VMwareWorkspaceONEUEM.Device.EnrollmentInfo.ManagedBy | String | Device managed by = \['0', '1', '2', '3', '4', '5', '6', '998', '999'\]. | 
| VMwareWorkspaceONEUEM.Device.OSBuildVersion | String | OS build version of the device. | 
| VMwareWorkspaceONEUEM.Device.WifiSsid | String | WiFi SSID device is connected to. | 
| VMwareWorkspaceONEUEM.Device.Links.Rel | String | Relational links. | 
| VMwareWorkspaceONEUEM.Device.Links.Href | String | Hyper text reference. | 
| VMwareWorkspaceONEUEM.Device.Links.Title | String | Title of the link. | 


#### Command Example
```!vmwuem-device-get uuid=12345678-1234-1234-1234-123456789ABC```

#### Context Example
```json
{
    "VMwareWorkspaceONEUEM": {
        "Device": {
            "AvailableStorageBytes": "17704955904",
            "CarrierInfo": {
                "RoamingEnabled": false
            },
            "DataEncrypted": true,
            "EnrollmentInfo": {
                "Compliant": true,
                "EnrollmentStatus": "ENROLLED",
                "EnrollmentTimestamp": "2021-06-29T10:16:00.677Z",
                "EnrollmentUserUuid": "12345678-1234-1234-1234-123456789ABC",
                "LastSeenTimestamp": "2021-06-29T16:08:37.087Z",
                "ManagedBy": "MDM",
                "OrganizationGroupId": "12345678-1234-1234-1234-123456789ABC",
                "OrganizationGroupName": "M123456789",
                "Ownership": "CORPORATE",
                "UserEmailAddress": "dummy-email",
                "UserName": "user user"
            },
            "FriendlyName": "iPhone iOS 14.4.2 HFLN",
            "Imei": "12345678912345",
            "Links": [
                {
                    "Href": "http://as1687.awmdm.com/API/mdm/devices/12345678-1234-1234-1234-123456789ABC",
                    "Rel": "self"
                }
            ],
            "MacAddress": "ABABABABABAB",
            "OSBuildVersion": "18D70",
            "OrganizationGroupName": "M123456789",
            "PlatformInfo": {
                "DeviceType": "Apple",
                "ModelName": "iPhone 6s (32 GB Silver)",
                "OsVersion": "14.4.2",
                "PlatformName": "Apple"
            },
            "SerialNumber": "ABCD12345678",
            "Supervised": false,
            "TotalStorageBytes": "34359738368",
            "Udid": "2749273b99b86bf87c68fca650b4006f73060056",
            "Uuid": "12345678-1234-1234-1234-123456789ABC"
        }
    }
}
```

#### Human Readable Output

>### Device(s)
>|Device Friendly Name|UUID|Platform|Model|Ownership|Serial Number|MAC Address|Compliance Status|User Email Address|Last Seen (In UTC)|
>|---|---|---|---|---|---|---|---|---|---|
>| iPhone iOS 14.4.2 HFLN | 12345678-1234-1234-1234-123456789ABC | Apple | iPhone 6s (32 GB Silver) | CORPORATE | ABCD12345678 | ABABABABABAB | Compliant | dummy-email | June 29, 2021 at 04:08:37 PM |


### vmwuem-device-os-updates-list
***
Retrieves a list of all available OS and software updates for the specified device.


#### Base Command

`vmwuem-device-os-updates-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The unique identifier of the device. Example: 153B4D9D-24DC-416B-91F9-94253D623611. <br/>Note: To get the uuid, use the command 'vmwuem-devices-search'. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMwareWorkspaceONEUEM.OSUpdate.Uuid | String | The UUID of the device. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.ProductKey | String | The unique product key of the update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.HumanReadableName | String | The common name of the update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.ProductName | String | The product name of the update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.Version | String | The version of the update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.Build | String | The build number of the update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.IsPreview | Boolean | Preview or beta version of the update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.DownloadSize | Number | Storage size needed to download the software update. Floating point number of bytes. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.InstallSize | Number | Storage size needed to install the software update. Floating point number of bytes. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.IsCritical | Boolean | Set to true if the update is considered critical. Defaults to false. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.IsConfigurationDataUpdate | Boolean | Set to true if it is an update to a configuration file. Defaults to false \(macOS only\). | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.IsFirmwareUpdate | Boolean | Set to true if it is an update to the firmware. Defaults to false \(macOS only\). | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.RestartRequired | Boolean | Set to true if the device restarts after the update is installed. Defaults to false. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.AllowsInstallLater | Boolean | Set to true if the update is eligible for later Install. Defaults to true. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.AppIdentifiersToClose | Unknown | Each entry represents an app identifier that is closed to install the update \(macOS only\). | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.DeviceUpdateName | String | The name of the device update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.ReleaseDate | String | Indicates the release date of the corresponding device update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.ExpiationDate | Date | Indicates the expiration date of the corresponding device update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.DownloadPercentComplete | Number | Indicates the percentage of downloads that is complete. Floating point number \(0.0 to 1.0\). | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.Status | String | Indicates the status of the update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.SampleTime | Date | Indicates the sampling time of the device update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.StatusTime | Date | Indicates the status time of the device update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.DeviceUpdateVersion | String | Indicates the version for iOS device update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.DeviceUpdateUuid | String | Indicates update UUID for the corresponding iOS device update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.Id | Number | The unique identifier of the OS update. | 
| VMwareWorkspaceONEUEM.OSUpdate.OSUpdateList.Uuid | String | The universally unique identifier of the OS update. | 


#### Command Example
```!vmwuem-device-os-updates-list uuid=12345678-1234-1234-1234-123456789ABC```

#### Context Example
```json
{
    "VMwareWorkspaceONEUEM": {
        "OSUpdate": {
            "OSUpdateList": [
                {
                    "AllowsInstallLater": false,
                    "DeviceUpdateName": "iOS",
                    "DeviceUpdateUuid": "12345678-1234-1234-1234-123456789ABC",
                    "DeviceUpdateVersion": "14.6",
                    "DownloadPercentComplete": 0,
                    "DownloadSize": 0,
                    "ExpiationDate": "2021-10-09T00:00:00",
                    "InstallSize": 0,
                    "IsConfigurationDataUpdate": false,
                    "IsCritical": false,
                    "IsFirmwareUpdate": false,
                    "IsPreview": false,
                    "ReleaseDate": "2021-05-24T00:00:00",
                    "RestartRequired": false,
                    "SampleTime": "0001-01-01T00:00:00",
                    "StatusTime": "0001-01-01T00:00:00"
                },
                {
                    "AllowsInstallLater": false,
                    "DeviceUpdateName": "iOS",
                    "DeviceUpdateUuid": "12345678-1234-1234-1234-123456789ABC",
                    "DeviceUpdateVersion": "14.5.1",
                    "DownloadPercentComplete": 0,
                    "DownloadSize": 0,
                    "ExpiationDate": "2021-08-22T00:00:00",
                    "InstallSize": 0,
                    "IsConfigurationDataUpdate": false,
                    "IsCritical": false,
                    "IsFirmwareUpdate": false,
                    "IsPreview": false,
                    "ReleaseDate": "2021-05-03T00:00:00",
                    "RestartRequired": false,
                    "SampleTime": "0001-01-01T00:00:00",
                    "StatusTime": "0001-01-01T00:00:00"
                },
                {
                    "AllowsInstallLater": false,
                    "DeviceUpdateName": "iOS",
                    "DeviceUpdateUuid": "12345678-1234-1234-1234-123456789ABC",
                    "DeviceUpdateVersion": "14.5",
                    "DownloadPercentComplete": 0,
                    "DownloadSize": 0,
                    "ExpiationDate": "2021-08-01T00:00:00",
                    "InstallSize": 0,
                    "IsConfigurationDataUpdate": false,
                    "IsCritical": false,
                    "IsFirmwareUpdate": false,
                    "IsPreview": false,
                    "ReleaseDate": "2021-04-26T00:00:00",
                    "RestartRequired": false,
                    "SampleTime": "0001-01-01T00:00:00",
                    "StatusTime": "0001-01-01T00:00:00"
                }
            ],
            "Uuid": "12345678-1234-1234-1234-123456789ABC"
        }
    }
}
```

#### Human Readable Output

>### OSUpdate(s)
>|Device UUID|Update Name|Update Version|Critical Update|Restart Required|Release Date|Expiration Date|
>|---|---|---|---|---|---|---|
>| 12345678-1234-1234-1234-123456789ABC | iOS | 14.6 | No | No | May 24, 2021 at 12:00:00 AM | October 09, 2021 at 12:00:00 AM |
>| 12345678-1234-1234-1234-123456789ABC | iOS | 14.5.1 | No | No | May 03, 2021 at 12:00:00 AM | August 22, 2021 at 12:00:00 AM |
>| 12345678-1234-1234-1234-123456789ABC | iOS | 14.5 | No | No | April 26, 2021 at 12:00:00 AM | August 01, 2021 at 12:00:00 AM |
