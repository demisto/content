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
Multi tenant environments should be configured with Cortex Rest API instance when using this automation and 
make sure *Use tenant* parameter (in Cortex Rest API integration) is checked to make sure that API calls are made to the current tenant
instead of the master tenant.