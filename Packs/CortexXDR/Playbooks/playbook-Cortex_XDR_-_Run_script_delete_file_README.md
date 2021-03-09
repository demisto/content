Use to Initiates a new endpoint script execution to delete the specified file and retrieve the results.

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
* xdr-run-script-delete-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| endpoint_id | A comma-separated list of endpoint IDs.  |  | Optional |
| file_path | Path of the file to delete. |  | Optional |
| timeout | The timeout in seconds for this execution.<br/>\(Default is: '600'\) |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR - Run script delete file](https://github.com/demisto/content/blob/58ee96b17cf8578c61781f67063742116544dfff/Packs/CortexXDR/doc_files/Cortex_XDR_-_Run_script_delete_file.png?raw=true)