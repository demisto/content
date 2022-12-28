Identify custom and detached system incidents type  
Checking if 'Auto Extraction' is turned on for:
Extract from all
Extract from specific indicators doesn't have any settings

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* HealthCheck

## Inputs
---
There are no inputs for this script.

## Outputs
---
There are no outputs for this script.

### Troubleshooting
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.