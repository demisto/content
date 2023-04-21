Retrieves all Playbook (and Sub-Playbook) names and Integrations for a provided Playbook name

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| playbook_name | Name of Playbook |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RetrievePlaybooksAndIntegrations.Playbooks | Names of all Playbooks and Sub-Playbooks used | Unknown |
| RetrievePlaybooksAndIntegrations.Integrations | Names of all Integrations used | Unknown |

### Troubleshooting
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.