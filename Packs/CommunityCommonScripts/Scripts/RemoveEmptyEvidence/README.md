The automation removes evidence based on a query performed on the evidence content,
if the provided string is found within the evidence- it will be removed.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| removeIfContains | String that if found in the entry of an evidence- the evidence will be removed. The default value is "No entries" |

## Outputs
---
There are no outputs for this script.

### Troubleshooting
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.