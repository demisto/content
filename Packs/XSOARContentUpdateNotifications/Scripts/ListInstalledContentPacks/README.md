This script will show all installed content packs and whether they have an update.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |

## Dependencies
---
This script uses the following commands and scripts.
* demisto-api-get

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| updates | Whether to only show packs that have updates available. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| InstalledPacks.Name | Pack Name | string |
| InstalledPacks.Version | Pack Version | string |
| InstalledPacks.Update | Is there an update available | boolean |

### Troubleshooting
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.