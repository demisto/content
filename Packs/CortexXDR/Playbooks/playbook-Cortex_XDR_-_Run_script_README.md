Initiates a new endpoint script execution action using a provided script unique id from Cortex XDR script library.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex XDR - Check Action Status

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* xdr-get-script-execution-results
* xdr-run-script

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| endpoint_ids | A comma-separated list of endpoint IDs.  |  | Optional |
| script_uid | Unique identifier of the script. Can be retrieved by running the xdr-get-scripts command. |  | Optional |
| parameters | Dictionary contains the parameter name as key and its value for this execution as the value. For example, \{"param1":"param1_value","param2":"param2_value"\} |  | Optional |
| timeout | The timeout in seconds for this execution.<br/>\(Default is: '600'\) |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR - Run script](https://raw.githubusercontent.com/demisto/content/58ee96b17cf8578c61781f67063742116544dfff/Packs/CortexXDR/doc_files/Cortex_XDR_-_Run_script.png)