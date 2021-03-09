Use to Initiates a new endpoint script execution kill process and retrieve the results.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex XDR - Check Action Status

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* xdr-run-script-kill-process
* xdr-get-script-execution-results

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| endpoint_id | A comma-separated list of endpoint IDs.  |  | Optional |
| process_name | Name of the process to kill. |  | Optional |
| timeout | The timeout in seconds for this execution.<br/>\(Default is: '600'\) |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR - Run script kill process](https://github.com/demisto/content/blob/58ee96b17cf8578c61781f67063742116544dfff/Packs/CortexXDR/doc_files/Cortex_XDR_-_Run_script_kill_process.png?raw=true)