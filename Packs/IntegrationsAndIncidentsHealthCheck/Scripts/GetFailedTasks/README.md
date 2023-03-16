Gets failed tasks details for incidents based on a query. Limited to 1000 incidents

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations)

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
* Integrations and Playbooks Health Check - Running Scripts
    
## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | The query by which to retrieve failed tasks. Optional. The default value is "-status:closed" |
| rest_api_instance | The Rest API instance to use. |
| max_incidents | Maximum number of incidents to query. Maximum is 1000. |

## Outputs
---
There are no outputs for this script.

### Troubleshooting
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.
