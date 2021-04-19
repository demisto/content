Initiates a new endpoint script execution kill process and retrieves the results.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
Cortex XDR - Check Action Status

### Integrations
CortexXDRIR

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

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptResult.results._return_value | Value returned by the script in case the type is not a dictionary. | unknown |
| PaloAltoNetworksXDR.ScriptResult.results.standard_output | The STDOUT and the STDERR logged by the script during the execution. | unknown |

## Playbook Image
---
![Cortex XDR - kill process](Insert the link to your image here)
