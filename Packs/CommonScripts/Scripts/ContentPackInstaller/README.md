Install Content packs from marketplace.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | configuration, Content Management |
| Cortex XSOAR Version | 6.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Configuration Setup
* Content Update Manager

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| packs_data | Information about the packs to install including pack ID and version. |
| pack_id_key | The key in which the pack ID is stored. |
| pack_version_key | The key in which the pack version is stored. Enter "latest" to update all packs to the latest version. |
| install_dependencies | Whether to install the pack dependencies. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ContentPackInstaller.packname | The name of the pack. | Unknown |
| ContentPackInstaller.packversion | The version of the pack. | Unknown |
| ContentPackInstaller.installationstatus | The installation status of the pack. | Unknown |

### Command Examples
#### Without escape chars
!ContentPackInstaller packs_data=`[{"id":"GoogleCloudCompute","itemVersion":"latest"},{"id":"GoogleKubernetesEngine","itemVersion":"latest"},{"id":"GoogleSafeBrowsing","itemVersion":"latest"}]` pack_id_key=id pack_version_key=itemVersion

#### With escape chars
`!ContentPackInstaller packs_data="[{\"packid\": \"GoogleCloudCompute\",\"packversion\": \"latest\"}]" pack_id_key=packid pack_version_key=packversion`

### Troubleshooting
#### Mulit-tenant environments 
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.

#### General Failures
1. Make sure the Core REST API integration is configured correctly, and the pressing the test button returns success.
2. Make sure you have a connection to the marketplace, you can check that by going to the marketplace page in the XSOAR UI and refreshing. 
3. Make sure the *packs_data* parameter value is in the correct format:
   1. A list `[]` containing dictionaries `{}`. For each pack you want to install, add a dictionary with pack_id_key as the pack id key and pack_version_key as the pack version key as demonstrated in the command examples above.
   2. The escape characters are in the right order and none are missing.
