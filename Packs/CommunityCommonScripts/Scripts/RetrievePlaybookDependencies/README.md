Retrieves all Playbook (and Sub-Playbook) names, Integrations, Automation Scripts, Commands and Lists for a provided Playbook name.

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
| RetrievePlaybookDependencies.Parent Playbook | Name of parent playbook provided. | Unknown |
| RetrievePlaybookDependencies.Playbooks | Names of all Playbooks and Sub-Playbooks used. | Unknown |
| RetrievePlaybookDependencies.Integrations | Names of all Integrations used. | Unknown |
| RetrievePlaybookDependencies.Automations | Names of all Automation Scripts used. | Unknown |
| RetrievePlaybookDependencies.Commands | Names of all brandless Commands used. | Unknown |
| RetrievePlaybookDependencies.Lists | Names of all Lists used. | Unknown |
| RetrievePlaybookDependencies.MarkdownString | Markdown formatted string data of playbook dependencies. | Unknown |

### Troubleshooting

Multi-tenant environments should be configured with the Cortex Rest API instance when using this
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked
to ensure that API calls are made to the current tenant instead of the master tenant.
