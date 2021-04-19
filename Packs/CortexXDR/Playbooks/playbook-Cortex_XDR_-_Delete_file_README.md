Initiates a new endpoint script execution to delete the specified file and retrieve the results.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
Cortex XDR - Check Action Status

### Integrations
CortexXDRIR

### Scripts
This playbook does not use any scripts.

### Commands
* xdr-run-script-delete-file
* xdr-get-script-execution-results

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| endpoint_id | A comma-separated list of endpoint IDs.  |  | Optional |
| file_path | Path of the file to delete. |  | Optional |
| timeout | The timeout in seconds for this execution.<br/>\(Default is: '600'\) |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptResult.results._return_value | Value returned by the script in case the type is not a dictionary. | unknown |

## Playbook Image
---
![Cortex XDR - Delete file](Insert the link to your image here)
