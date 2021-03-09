Use to Initiates a new endpoint script execution action using the provided snippet code and retrieve the file results.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex XDR - Check Action Status

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* xdr-run-snippet-code-script
* xdr-get-script-execution-results

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| endpoint_id | A comma-separated list of endpoint IDs.  |  | Optional |
| snippet_code | Section of a script you want to initiate on an endpoint \(e.g., print\("7"\)\). |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR - Run snippet code script](hhttps://raw.githubusercontent.com/demisto/content/4440f08a9f57f4cd349267a18d94e189e3315ae9/Packs/CortexXDR/doc_files/Cortex_XDR_-_Run_snippet_code_script.png)