Finds which integrations implement a specific Demisto command.  The results will be returned as comma-separated values (CSV).  The "Demisto REST API" integration must first be enabled.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | general |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* demisto-api-post
* demisto-api-get

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| command | The integration command to find |
| enabled | Filters results to integrations that are enabled or disabled.  'true' or 'false'.  Will return both types by default.  False means that an integration instance is either not defined or not enabled.  True means that an integration instance is both defined and enabled. |

## Outputs
---
There are no outputs for this script.

### Troubleshooting
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.