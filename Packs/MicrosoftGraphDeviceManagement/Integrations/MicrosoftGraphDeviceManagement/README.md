Microsoft Intune is a Microsoft cloud-based management solution that provides for mobile device and operating system management

## Authentication
For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication).

### Required Permissions
* DeviceManagementApps.ReadWrite.All - Application
* DeviceManagementConfiguration.ReadWrite.All - Application
* DeviceManagementManagedDevices.PrivilegedOperations.All - Application
* DeviceManagementManagedDevices.ReadWrite.All - Application
* DeviceManagementRBAC.ReadWrite.All - Application
* DeviceManagementServiceConfig.ReadWrite.All - Application

## Configure Microsoft Graph Device Management on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Graph Device Management.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL | True |
| auth_id | ID \(received from the admin consent \- see Detailed Instructions \(?\) | True |
| tenant_id | Token \(received from the admin consent \- see Detailed Instructions \(?\) section\) | True |
| enc_key | Key \(received from the admin consent \- see Detailed Instructions \(?\) | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| self_deployed | Use a self deployed Azure Application | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### msgraph-get-managed-device-by-id
***
Get managed devices


#### Base Command

`msgraph-get-managed-device-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphDeviceManagement.Device.ID | String | The ID of the managed device | 
| MSGraphDeviceManagement.Device.UserID | String | Unique Identifier for the user associated with the device | 
| MSGraphDeviceManagement.Device.Name | String | Name of the device | 
| MSGraphDeviceManagement.Device.ManagedDeviceOwnerType | String | Ownership of the device. Possible values are unknown, company, personal. | 
| MSGraphDeviceManagement.Device.ActionResults.actionName | String | Action name | 
| MSGraphDeviceManagement.Device.ActionResults.ActionState | String | State of the action. Possible values are none, pending, canceled, active, done, failed, notSupported | 
| MSGraphDeviceManagement.Device.ActionResults.StartDateTime | Date | Time the action was initiated | 
| MSGraphDeviceManagement.Device.ActionResults.lastUpdatedDateTime | Date | Time the action state was last updated | 
| MSGraphDeviceManagement.Device.EnrolledDateTime | Date | Enrollment time of the device | 
| MSGraphDeviceManagement.Device.LastSyncDateTime | Date | The date and time that the device last completed a successful sync with Intune. | 
| MSGraphDeviceManagement.Device.OperatingSystem | String | Operating system of the device. Windows, iOS, etc. | 
| MSGraphDeviceManagement.Device.ComplianceState | String | Compliance state of the device. Possible values are unknown, compliant, noncompliant, conflict, error, inGracePeriod, configManager | 
| MSGraphDeviceManagement.Device.JailBroken | String | whether the device is jail broken or rooted. | 
| MSGraphDeviceManagement.Device.ManagementAgent | String | Management channel of the device. Possible values are eas, mdm, easMdm, intuneClient, easIntuneClient, configurationManagerClient, configurationManagerClientMdm, configurationManagerClientMdmEas, unknown, jamf, googleCloudDevicePolicyController. | 
| MSGraphDeviceManagement.Device.OSVersion | String | Operating system version of the device. | 
| MSGraphDeviceManagement.Device.EASDeviceId | String | Exchange ActiveSync Id of the device. | 
| MSGraphDeviceManagement.Device.EASActivationDateTime | Date | Exchange ActivationSync activation time of the device. | 
| MSGraphDeviceManagement.Device.ActivationLockBypassCode | String | Code that allows the Activation Lock on a device to be bypassed. | 
| MSGraphDeviceManagement.Device.EmailAddress | String | Email\(s\) for the user associated with the device | 
| MSGraphDeviceManagement.Device.AzureADDeviceId | String | The unique identifier for the Azure Active Directory device. Read only. | 
| MSGraphDeviceManagement.Device.CategoryDisplayName | String | Device category display name | 
| MSGraphDeviceManagement.Device.ExchangeAccessState | String | The Access State of the device in Exchange. Possible values are none, unknown, allowed, blocked, quarantined. | 
| MSGraphDeviceManagement.Device.exchangeAccessStateReason | String | The reason for the device's access state in Exchange. Possible values are none, unknown, exchangeGlobalRule, exchangeIndividualRule, exchangeDeviceRule, exchangeUpgrade, exchangeMailboxPolicy, other, compliant, notCompliant, notEnrolled, unknownLocation, mfaRequired, azureADBlockDueToAccessPolicy, compromisedPassword, deviceNotKnownWithManagedApp. | 
| MSGraphDeviceManagement.Device.IsSupervised | Boolean | Device supervised status | 
| MSGraphDeviceManagement.Device.IsEncrypted | Boolean | Device encryption status | 
| MSGraphDeviceManagement.Device.UserPrincipalName | String | Device user principal name | 
| MSGraphDeviceManagement.Device.Model | String | Model of the device | 
| MSGraphDeviceManagement.Device.Manufacturer | String | Manufacturer of the device | 
| MSGraphDeviceManagement.Device.IMEI | String | IMEI of the device | 
| MSGraphDeviceManagement.Device.SerialNumber | String | Serial number of the device | 
| MSGraphDeviceManagement.Device.PhoneNumber | String | Phone number of the device | 
| MSGraphDeviceManagement.Device.AndroidSecurityPatchLevel | String | Android security patch level of the device | 
| MSGraphDeviceManagement.Device.ConfigurationManagerClientEnabledFeatures.inventory | Boolean | Whether inventory is managed by Intune | 
| MSGraphDeviceManagement.Device.ConfigurationManagerClientEnabledFeatures.modernApps | Boolean | Whether modern application is managed by Intune | 
| MSGraphDeviceManagement.Device.ConfigurationManagerClientEnabledFeatures.resourceAccess | Boolean | Whether resource access is managed by Intune | 
| MSGraphDeviceManagement.Device.ConfigurationManagerClientEnabledFeatures.deviceConfiguration | Boolean | Whether device configuration is managed by Intune | 
| MSGraphDeviceManagement.Device.ConfigurationManagerClientEnabledFeatures.compliancePolicy | Boolean | Whether compliance policy is managed by Intune | 
| MSGraphDeviceManagement.Device.ConfigurationManagerClientEnabledFeatures.windowsUpdateForBusiness | Boolean | Whether Windows Update for Business is managed by Intune | 
| MSGraphDeviceManagement.Device.WiFiMacAddress | String | Wi\-Fi MAC | 
| MSGraphDeviceManagement.Device.HealthAttestationState.lastUpdateDateTime | String | The Timestamp of the last update. | 
| MSGraphDeviceManagement.Device.HealthAttestationState.issuedDateTime | Date | The DateTime when device was evaluated or issued to MDM | 
| MSGraphDeviceManagement.Device.HealthAttestationState.resetCount | Number | The number of times a PC device has hibernated or resumed | 
| MSGraphDeviceManagement.Device.HealthAttestationState.restartCount | Number | The number of times a PC device has rebooted | 
| MSGraphDeviceManagement.Device.HealthAttestationState.bitLockerStatus | String | On or Off of BitLocker Drive Encryption | 
| MSGraphDeviceManagement.Device.HealthAttestationState.bootManagerVersion | String | The version of the Boot Manager | 
| MSGraphDeviceManagement.Device.HealthAttestationState.secureBoot | String | When Secure Boot is enabled, the core components must have the correct cryptographic signatures | 
| MSGraphDeviceManagement.Device.HealthAttestationState.bootDebugging | String | When bootDebugging is enabled, the device is used in development and testing | 
| MSGraphDeviceManagement.Device.HealthAttestationState.operatingSystemKernelDebugging | String | When operatingSystemKernelDebugging is enabled, the device is used in development and testing | 
| MSGraphDeviceManagement.Device.HealthAttestationState.codeIntegrity | String | When code integrity is enabled, code execution is restricted to integrity verified code | 
| MSGraphDeviceManagement.Device.HealthAttestationState.testSigning | String | When test signing is allowed, the device does not enforce signature validation during boot | 
| MSGraphDeviceManagement.Device.HealthAttestationState.safeMode, | String | Safe mode is a troubleshooting option for Windows that starts your computer in a limited state | 
| MSGraphDeviceManagement.Device.HealthAttestationState.windowsPE | String | Operating system running with limited services that is used to prepare a computer for Windows | 
| MSGraphDeviceManagement.Device.HealthAttestationState.earlyLaunchAntiMalwareDriverProtection | String | ELAM provides protection for the computers in your network when they start up | 
| MSGraphDeviceManagement.Device.HealthAttestationState.virtualSecureMode | String | VSM is a container that protects high value assets from a compromised kernel | 
| MSGraphDeviceManagement.Device.HealthAttestationState.pcrHashAlgorithm | String | Informational attribute that identifies the HASH algorithm that was used by TPM | 
| MSGraphDeviceManagement.Device.HealthAttestationState.bootAppSecurityVersion | String | The security version number of the Boot Application | 
| MSGraphDeviceManagement.Device.HealthAttestationState.bootManagerSecurityVersion | String | The security version number of the Boot Application | 
| MSGraphDeviceManagement.Device.HealthAttestationState.tpmVersion | String | The security version number of the Boot Application | 
| MSGraphDeviceManagement.Device.HealthAttestationState.pcr0 | String | The measurement that is captured in PCR\[0\] | 
| MSGraphDeviceManagement.Device.HealthAttestationState.secureBootConfigurationPolicyFingerPrint | String | Fingerprint of the Custom Secure Boot Configuration Policy | 
| MSGraphDeviceManagement.Device.HealthAttestationState.codeIntegrityPolicy | String | The Code Integrity policy that is controlling the security of the boot environment | 
| MSGraphDeviceManagement.Device.HealthAttestationState.bootRevisionListInfo | String | The Boot Revision List that was loaded during initial boot on the attested device | 
| MSGraphDeviceManagement.Device.HealthAttestationState.operatingSystemRevListInfo | String | The Operating System Revision List that was loaded during initial boot on the attested device | 
| MSGraphDeviceManagement.Device.HealthAttestationState.healthStatusMismatchInfo | String | This attribute appears if DHA\-Service detects an integrity issue | 
| MSGraphDeviceManagement.Device.HealthAttestationState.healthAttestationSupportedStatus | String | This attribute indicates if DHA is supported for the device | 
| MSGraphDeviceManagement.Device.SubscriberCarrier | String | Subscriber Carrier | 
| MSGraphDeviceManagement.Device.MEID | String | MEID | 
| MSGraphDeviceManagement.Device.TotalStorageSpaceInBytes | Number | Total Storage in Bytes | 
| MSGraphDeviceManagement.Device.FreeStorageSpaceInBytes | Number | Free Storage in Bytes | 
| MSGraphDeviceManagement.Device.ManagedDeviceName | String | Automatically generated name to identify a device. Can be overwritten to a user friendly name. | 
| MSGraphDeviceManagement.Device.PartnerReportedThreatState | String | Indicates the threat state of a device when a Mobile Threat Defense partner is in use by the account and device. Read Only. Possible values are unknown, activated, deactivated, secured, lowSeverity, mediumSeverity, highSeverity, unresponsive, compromised, misconfigured. | 


#### Command Example
```!msgraph-get-managed-device-by-id device_id=DEVICE_ID_VALUE```

#### Context Example
```
{
    "MSGraphDeviceManagement": {
        "Device": {
            "AzureADDeviceID": "AZURE_AD_DEVICE_ID",
            "ComplianceState": "compliant",
            "EASActivationDateTime": "0001-01-01T00:00:00Z",
            "EmailAddress": "EMAIL_ADDRESS",
            "EnrolledDateTime": "2020-03-03T11:32:54.6467627Z",
            "ExchangeAccessState": "none",
            "ExchangeAccessStateReason": "none",
            "FreeStorageSpaceInBytes": -1247805440,
            "ID": "ID_VALUE",
            "IsEncrypted": false,
            "IsSupervised": false,
            "JailBroken": "Unknown",
            "LastSyncDateTime": "2020-05-05T10:34:20.9574056Z",
            "ManagedDeviceName": "MANAGED_DEVICE_NAME",
            "ManagedDeviceOwnerType": "company",
            "ManagementAgent": "MANAGEMENT_AGENT",
            "Manufacturer": "MANUFACTURER_VALUE",
            "Model": "MODEL_VALUE",
            "Name": "NAME_VALUE",
            "OSVersion": "10.0.18363.778",
            "OperatingSystem": "Windows",
            "PartnerReportedThreatState": "highSeverity",
            "SerialNumber": "SERIAL_NUMBER_VALUE",
            "TotalStorageSpaceInBytes": -2097152,
            "UserID": "USER_ID_VALUE",
            "UserPrincipalName": "USER_PRINCIPAL_VALUE_NAME"
        }
    }
}
```

#### Human Readable Output

>### Managed device DESKTOP-S2455R8
>|ID|User ID|Device Name|Operating System|OS Version|Email Address|Manufacturer|Model|
>|---|---|---|---|---|---|---|---|
>| DEVICE_ID_VALUE | 2827c1e7-edb6-4529-b50d-25984e968637 | DESKTOP-S2455R8 | Windows | 10.0.18363.778 | dev@demistodev.onmicrosoft.com | VMware, Inc. | VMware7,1 |


### msgraph-sync-device
***
Check the device with Intune, immediately receive pending actions and policies


#### Base Command

`msgraph-sync-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 

#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-sync-device device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Sync device action activated successfully.



### msgraph-device-disable-lost-mode
***
Disable the lost mode of the device


#### Base Command

`msgraph-device-disable-lost-mode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-windows-device-defender-scan device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Windows device defender scan action activated successfully.



### msgraph-locate-device
***
Gets the GPS location of a device (iOS only)


#### Base Command

`msgraph-locate-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-locate-device device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Locate device action activated successfully.



### msgraph-device-reboot-now
***
Immediately reboots the device


#### Base Command

`msgraph-device-reboot-now`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-device-reboot-now device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Device reboot now action activated successfully..



### msgraph-device-shutdown
***
Immideately shuts down the device


#### Base Command

`msgraph-device-shutdown`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-device-shutdown device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Device shutdown action activated successfully.



### msgraph-device-bypass-activation-lock
***
Removes the activation lock (iOS devices only)


#### Base Command

`msgraph-device-bypass-activation-lock`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-device-bypass-activation-lock device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Device bypass activation lock action activated successfully.



### msgraph-device-retire
***
Remove the device from intune management


#### Base Command

`msgraph-device-retire`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-device-retire device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Retire device action activated successfully.



### msgraph-device-reset-passcode
***
Resets the passcode for the device


#### Base Command

`msgraph-device-reset-passcode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-device-reset-passcode device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Device reset passcode action activated successfully.



### msgraph-device-remote-lock
***
Lock the device, to unlock the user will have to use the passcode


#### Base Command

`msgraph-device-remote-lock`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-device-remote-lock device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Device remote lock action activated successfully.



### msgraph-device-request-remote-assistance
***
Request a remote access via TeamViewer


#### Base Command

`msgraph-device-request-remote-assistance`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-device-request-remote-assistance device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Device request remote assistance action activated successfully.



### msgraph-device-recover-passcode
***
Recovers the passcode from the device


#### Base Command

`msgraph-device-recover-passcode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-device-recover-passcode device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Device recover passcode action activated successfully.



### msgraph-logout-shared-apple-device-active-user
***
logs out the current user on a shared iPad device


#### Base Command

`msgraph-logout-shared-apple-device-active-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-logout-shared-apple-device-active-user device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Logout shard apple device active user action activated successfully.



### msgraph-delete-user-from-shared-apple-device
***
deletes a user that you select from the local cache on a shared iPad device


#### Base Command

`msgraph-delete-user-from-shared-apple-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_principal_name | The principal name of the user to be deleted. | Required | 
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-delete-user-from-shared-apple-device device_id=DEVICE_ID_VALUE user_principal_name=USER_PRINCIPAL_NAME_VALUE```


#### Human Readable Output

>Delete user from shared apple device action activated successfully.


### msgraph-windows-device-defender-update-signatures
***
Forece update windows defender signatures


#### Base Command

`msgraph-windows-device-defender-update-signatures`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-windows-device-defender-update-signatures device_id=DEVICE_ID_VALUE```


#### Human Readable Output

>Windows device defender update signatures action activated successfully.



### msgraph-clean-windows-device
***
removes any apps that are installed on a PC running Windows 10. it helps remove pre-installed (OEM) apps that are typically installed with a new PC


#### Base Command

`msgraph-clean-windows-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| keep_user_data | Whether to keep the user's data or not. (Default is set to true) | Optional | 
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-clean-windows-device device_id=DEVICE_ID_VALUE keep_user_data=false```


#### Human Readable Output

>Clean windows device action activated successfully.



### msgraph-windows-device-defender-scan
***
Scans the device with windows defender (windows devices only)


#### Base Command

`msgraph-windows-device-defender-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| quick_scan | Whether to peformn quick scan or not. (Default is set to true) | Optional | 
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-windows-device-defender-scan device_id=DEVICE_ID_VALUE quick_scan=false```


#### Human Readable Output

>Windows device defender scan action activated successfully.

### msgraph-wipe-device
***
restores a device to its factory default settings


#### Base Command

`msgraph-wipe-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| keep_enrollment_data | Whether to keep enrollment data or not. (Default is set to true) | Optional | 
| keep_user_data | Whether to keep the user's data or not. (Default is set to true) | Optional | 
| mac_os_unlock_code | The MacOS unlock code. | Optional | 
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-wipe-device device_id=DEVICE_ID_VALUE keep_enrollment_data=false keep_user_data=true```


#### Human Readable Output

>Wipe device action activated successfully.



### msgraph-update-windows-device-account
***
Updates the windows account of the device


#### Base Command

`msgraph-update-windows-device-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_initiation_protocal_address | SIP address | Required | 
| exchange_server | Exchenge servier adddress | Required | 
| calendar_sync_enabled | Whether to enable calendar sync or not. (Default is set to false) | Optional | 
| password_rotation_enabled | Whether to enable password rotation or not. (Default is set to false) | Optional | 
| device_account_password | The device account password. | Required | 
| device_account_email | The device account email. | Required | 
| device_id | The ID of the managed device to be fetched (Can be retreived using the msgraph-list-managed-devices command) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-update-windows-device-account device_id=DEVICE_ID_VALUE session_initiation_protocal_address=PA_VALUE device_account_password=PW_VALUE device_account_email=MAIL_VALUE```


#### Human Readable Output

>Update windows device account action activated successfully.



### msgraph-list-managed-devices
***
List of managed devices


#### Base Command

`msgraph-list-managed-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of managed devices to fetch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphDeviceManagement.Device.ID | String | The ID of the managed device | 
| MSGraphDeviceManagement.Device.UserID | String | Unique Identifier for the user associated with the device | 
| MSGraphDeviceManagement.Device.Name | String | Name of the device | 
| MSGraphDeviceManagement.Device.ManagedDeviceOwnerType | String | Ownership of the device. Possible values are unknown, company, personal. | 
| MSGraphDeviceManagement.Device.ActionResults.actionName | String | Action name | 
| MSGraphDeviceManagement.Device.ActionResults.ActionState | String | State of the action. Possible values are none, pending, canceled, active, done, failed, notSupported | 
| MSGraphDeviceManagement.Device.ActionResults.StartDateTime | Date | Time the action was initiated | 
| MSGraphDeviceManagement.Device.ActionResults.lastUpdatedDateTime | Date | Time the action state was last updated | 
| MSGraphDeviceManagement.Device.EnrolledDateTime | Date | Enrollment time of the device | 
| MSGraphDeviceManagement.Device.LastSyncDateTime | Date | The date and time that the device last completed a successful sync with Intune. | 
| MSGraphDeviceManagement.Device.OperatingSystem | String | Operating system of the device. Windows, iOS, etc. | 
| MSGraphDeviceManagement.Device.ComplianceState | String | Compliance state of the device. Possible values are unknown, compliant, noncompliant, conflict, error, inGracePeriod, configManager | 
| MSGraphDeviceManagement.Device.JailBroken | String | whether the device is jail broken or rooted. | 
| MSGraphDeviceManagement.Device.ManagementAgent | String | Management channel of the device. Possible values are eas, mdm, easMdm, intuneClient, easIntuneClient, configurationManagerClient, configurationManagerClientMdm, configurationManagerClientMdmEas, unknown, jamf, googleCloudDevicePolicyController. | 
| MSGraphDeviceManagement.Device.OSVersion | String | Operating system version of the device. | 
| MSGraphDeviceManagement.Device.EASDeviceId | String | Exchange ActiveSync Id of the device. | 
| MSGraphDeviceManagement.Device.EASActivationDateTime | Date | Exchange ActivationSync activation time of the device. | 
| MSGraphDeviceManagement.Device.ActivationLockBypassCode | String | Code that allows the Activation Lock on a device to be bypassed. | 
| MSGraphDeviceManagement.Device.EmailAddress | String | Email\(s\) for the user associated with the device | 
| MSGraphDeviceManagement.Device.AzureADDeviceId | String | The unique identifier for the Azure Active Directory device. Read only. | 
| MSGraphDeviceManagement.Device.CategoryDisplayName | String | Device category display name | 
| MSGraphDeviceManagement.Device.ExchangeAccessState | String | The Access State of the device in Exchange. Possible values are none, unknown, allowed, blocked, quarantined. | 
| MSGraphDeviceManagement.Device.exchangeAccessStateReason | String | The reason for the device's access state in Exchange. Possible values are none, unknown, exchangeGlobalRule, exchangeIndividualRule, exchangeDeviceRule, exchangeUpgrade, exchangeMailboxPolicy, other, compliant, notCompliant, notEnrolled, unknownLocation, mfaRequired, azureADBlockDueToAccessPolicy, compromisedPassword, deviceNotKnownWithManagedApp. | 
| MSGraphDeviceManagement.Device.IsSupervised | Boolean | Device supervised status | 
| MSGraphDeviceManagement.Device.IsEncrypted | Boolean | Device encryption status | 
| MSGraphDeviceManagement.Device.UserPrincipalName | String | Device user principal name | 
| MSGraphDeviceManagement.Device.Model | String | Model of the device | 
| MSGraphDeviceManagement.Device.Manufacturer | String | Manufacturer of the device | 
| MSGraphDeviceManagement.Device.IMEI | String | IMEI of the device | 
| MSGraphDeviceManagement.Device.SerialNumber | String | Serial number of the device | 
| MSGraphDeviceManagement.Device.PhoneNumber | String | Phone number of the device | 
| MSGraphDeviceManagement.Device.AndroidSecurityPatchLevel | String | Android security patch level of the device | 
| MSGraphDeviceManagement.Device.ConfigurationManagerClientEnabledFeatures.inventory | Boolean | Whether inventory is managed by Intune | 
| MSGraphDeviceManagement.Device.ConfigurationManagerClientEnabledFeatures.modernApps | Boolean | Whether modern application is managed by Intune | 
| MSGraphDeviceManagement.Device.ConfigurationManagerClientEnabledFeatures.resourceAccess | Boolean | Whether resource access is managed by Intune | 
| MSGraphDeviceManagement.Device.ConfigurationManagerClientEnabledFeatures.deviceConfiguration | Boolean | Whether device configuration is managed by Intune | 
| MSGraphDeviceManagement.Device.ConfigurationManagerClientEnabledFeatures.compliancePolicy | Boolean | Whether compliance policy is managed by Intune | 
| MSGraphDeviceManagement.Device.ConfigurationManagerClientEnabledFeatures.windowsUpdateForBusiness | Boolean | Whether Windows Update for Business is managed by Intune | 
| MSGraphDeviceManagement.Device.WiFiMacAddress | String | Wi\-Fi MAC | 
| MSGraphDeviceManagement.Device.HealthAttestationState.lastUpdateDateTime | String | The Timestamp of the last update. | 
| MSGraphDeviceManagement.Device.HealthAttestationState.issuedDateTime | Date | The DateTime when device was evaluated or issued to MDM | 
| MSGraphDeviceManagement.Device.HealthAttestationState.resetCount | Number | The number of times a PC device has hibernated or resumed | 
| MSGraphDeviceManagement.Device.HealthAttestationState.restartCount | Number | The number of times a PC device has rebooted | 
| MSGraphDeviceManagement.Device.HealthAttestationState.bitLockerStatus | String | On or Off of BitLocker Drive Encryption | 
| MSGraphDeviceManagement.Device.HealthAttestationState.bootManagerVersion | String | The version of the Boot Manager | 
| MSGraphDeviceManagement.Device.HealthAttestationState.secureBoot | String | When Secure Boot is enabled, the core components must have the correct cryptographic signatures | 
| MSGraphDeviceManagement.Device.HealthAttestationState.bootDebugging | String | When bootDebugging is enabled, the device is used in development and testing | 
| MSGraphDeviceManagement.Device.HealthAttestationState.operatingSystemKernelDebugging | String | When operatingSystemKernelDebugging is enabled, the device is used in development and testing | 
| MSGraphDeviceManagement.Device.HealthAttestationState.codeIntegrity | String | When code integrity is enabled, code execution is restricted to integrity verified code | 
| MSGraphDeviceManagement.Device.HealthAttestationState.testSigning | String | When test signing is allowed, the device does not enforce signature validation during boot | 
| MSGraphDeviceManagement.Device.HealthAttestationState.safeMode, | String | Safe mode is a troubleshooting option for Windows that starts your computer in a limited state | 
| MSGraphDeviceManagement.Device.HealthAttestationState.windowsPE | String | Operating system running with limited services that is used to prepare a computer for Windows | 
| MSGraphDeviceManagement.Device.HealthAttestationState.earlyLaunchAntiMalwareDriverProtection | String | ELAM provides protection for the computers in your network when they start up | 
| MSGraphDeviceManagement.Device.HealthAttestationState.virtualSecureMode | String | VSM is a container that protects high value assets from a compromised kernel | 
| MSGraphDeviceManagement.Device.HealthAttestationState.pcrHashAlgorithm | String | Informational attribute that identifies the HASH algorithm that was used by TPM | 
| MSGraphDeviceManagement.Device.HealthAttestationState.bootAppSecurityVersion | String | The security version number of the Boot Application | 
| MSGraphDeviceManagement.Device.HealthAttestationState.bootManagerSecurityVersion | String | The security version number of the Boot Application | 
| MSGraphDeviceManagement.Device.HealthAttestationState.tpmVersion | String | The security version number of the Boot Application | 
| MSGraphDeviceManagement.Device.HealthAttestationState.pcr0 | String | The measurement that is captured in PCR\[0\] | 
| MSGraphDeviceManagement.Device.HealthAttestationState.secureBootConfigurationPolicyFingerPrint | String | Fingerprint of the Custom Secure Boot Configuration Policy | 
| MSGraphDeviceManagement.Device.HealthAttestationState.codeIntegrityPolicy | String | The Code Integrity policy that is controlling the security of the boot environment | 
| MSGraphDeviceManagement.Device.HealthAttestationState.bootRevisionListInfo | String | The Boot Revision List that was loaded during initial boot on the attested device | 
| MSGraphDeviceManagement.Device.HealthAttestationState.operatingSystemRevListInfo | String | The Operating System Revision List that was loaded during initial boot on the attested device | 
| MSGraphDeviceManagement.Device.HealthAttestationState.healthStatusMismatchInfo | String | This attribute appears if DHA\-Service detects an integrity issue | 
| MSGraphDeviceManagement.Device.HealthAttestationState.healthAttestationSupportedStatus | String | This attribute indicates if DHA is supported for the device | 
| MSGraphDeviceManagement.Device.SubscriberCarrier | String | Subscriber Carrier | 
| MSGraphDeviceManagement.Device.MEID | String | MEID | 
| MSGraphDeviceManagement.Device.TotalStorageSpaceInBytes | Number | Total Storage in Bytes | 
| MSGraphDeviceManagement.Device.FreeStorageSpaceInBytes | Number | Free Storage in Bytes | 
| MSGraphDeviceManagement.Device.ManagedDeviceName | String | Automatically generated name to identify a device. Can be overwritten to a user friendly name. | 
| MSGraphDeviceManagement.Device.PartnerReportedThreatState | String | Indicates the threat state of a device when a Mobile Threat Defense partner is in use by the account and device. Read Only. Possible values are unknown, activated, deactivated, secured, lowSeverity, mediumSeverity, highSeverity, unresponsive, compromised, misconfigured. | 


#### Command Example
```!msgraph-list-managed-devices```

#### Context Example
```
{
    "MSGraphDeviceManagement": {
        "Device": {
            "AzureADDeviceID": "AZURE_AD_DEVICE_ID",
            "ComplianceState": "compliant",
            "EASActivationDateTime": "0001-01-01T00:00:00Z",
            "EmailAddress": "EMAIL_ADDRESS",
            "EnrolledDateTime": "2020-03-03T11:32:54.6467627Z",
            "ExchangeAccessState": "none",
            "ExchangeAccessStateReason": "none",
            "FreeStorageSpaceInBytes": -1247805440,
            "ID": "ID_VALUE",
            "IsEncrypted": false,
            "IsSupervised": false,
            "JailBroken": "Unknown",
            "LastSyncDateTime": "2020-05-05T10:34:20.9574056Z",
            "ManagedDeviceName": "MANAGED_DEVICE_NAME",
            "ManagedDeviceOwnerType": "company",
            "ManagementAgent": "MANAGEMENT_AGENT",
            "Manufacturer": "MANUFACTURER_VALUE",
            "Model": "MODEL_VALUE",
            "Name": "NAME_VALUE",
            "OSVersion": "10.0.18363.778",
            "OperatingSystem": "Windows",
            "PartnerReportedThreatState": "highSeverity",
            "SerialNumber": "SERIAL_NUMBER_VALUE",
            "TotalStorageSpaceInBytes": -2097152,
            "UserID": "USER_ID_VALUE",
            "UserPrincipalName": "USER_PRINCIPAL_VALUE_NAME"
        }
    }
}
```

#### Human Readable Output

>### Managed device DESKTOP-S2455R8
>|ID|User ID|Device Name|Operating System|OS Version|Email Address|Manufacturer|Model|
>|---|---|---|---|---|---|---|---|
>| DEVICE_ID_VALUE | 2827c1e7-edb6-4529-b50d-25984e968637 | DESKTOP-S2455R8 | Windows | 10.0.18363.778 | dev@demistodev.onmicrosoft.com | VMware, Inc. | VMware7,1 |

