This command uses the Registry Parse automation to extract critical forensics data from a registry file. The essential values are specified by the argument. 


## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 6.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Registry Parse Data Analysis

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | This entry ID for the reg file. |
| registryData | This argument allows the user to specify which of the following objects in the registry to parse. Default is "All". |
| customRegistryPaths | A comma-separated list of registry paths to parse. Try to keep your searches as exact as possible, for example registry_path=\`HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList\`. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RegistryForensicDataRaw.Type | The registry data type. "Custom" for custom registry path. | Unknown |
| RegistryForensicDataRaw.RegistryPath | The registry key path. | Unknown |
| RegistryForensicDataRaw.RegistryKey | The registry key. | Unknown |
| RegistryForensicDataRaw.RegistryValue | The registry value. | Unknown |
| RegistryForensicData.Users.Sid | User SID. | Unknown |
| RegistryForensicData.Users.Guid | User GUID. | Unknown |
| RegistryForensicData.LastLoggedOnUser | Last user to be logged in. | Unknown |
| RegistryForensicData.TimeZone | Registry ime zone. | Unknown |
| RegistryForensicData.Services.DisplayName | Registry service name. | Unknown |
