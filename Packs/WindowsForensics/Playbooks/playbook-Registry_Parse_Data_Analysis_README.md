This playbook leverages the RegistryParse automation to perform registry analysis and extract forensic artifacts.  The automation includes common registry objects to extract which are useful for analyzing registry, or a user provided registry path to parse.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* RegistryParse

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RegistryFileEntryID | The entry ID for the registry file to parse. |  | Optional |
| RegistryData | The data to parse out of the registry and output to context, including<br/>Users<br/>LastLoggedOnUser<br/>MachineRunOnce<br/>MachineStartup<br/>Timezone<br/>USB<br/>"All" selects all the options and any default options |  | Optional |
| CustomRegistryPaths | Custom registry path to parse. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RegistryForensicData | The data parsed from registry. | string |

## Playbook Image
---
![Registry Data Analysis](../doc_files/Registry_Parse_Data_Analysis.png)
