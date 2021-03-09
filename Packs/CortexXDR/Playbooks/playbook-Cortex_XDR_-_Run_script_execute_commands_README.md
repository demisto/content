Use to Initiate a new script execution of shell commands. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex XDR - Check Action Status

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* xdr-run-script-execute-commands
* xdr-get-script-execution-results

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| endpoint_ids | A comma-separated list of endpoint IDs. |  | Optional |
| commands | A comma-separated list of shell commands to execute. |  | Optional |
| timeout | The timeout in seconds for this execution.<br/>\(Default is: '600'\) |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR - Run script execute commands](https://github.com/demisto/content/blob/58ee96b17cf8578c61781f67063742116544dfff/Packs/CortexXDR/doc_files/Cortex_XDR_-_Run_script_execute_commands.png?raw=true)