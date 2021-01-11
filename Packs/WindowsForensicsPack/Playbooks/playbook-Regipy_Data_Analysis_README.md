This playbook leverages the Regipy tool to perform registry analysis and extract forensic artifacts.  The Automation includes common registry objects to extract which are useful for analyzing registry or a user provides registry path to parse.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RegistryFileEntryID | The entry id for the registry file to parse. |  | Optional |
| RegistryData | This specifies which data to parse out of the registry and output to context, including<br/>Users<br/>LastLoggedOnUser<br/>MachineRunOnce<br/>MachineStartup<br/>Timezone<br/>USB<br/>And all which selects all the options and the default option |  | Optional |
| CustomRegistryPaths | Custom registry path to parse. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RegistryForensicData | The data parsed from registry. | string |

## Playbook Image
---
![Regipy Data Analysis](Insert the link to your image here)