Deprecated. Use the `xdr-file-delete-script-execute` command instead. Initiates a new endpoint script execution to delete the specified file and retrieve the results.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cortex XDR - Check Action Status

### Integrations

* CortexXDRIR

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
| file_path | A comma-separated list of file paths to delete.<br/>Files will be deleted on all provided endpoint ids |  | Optional |
| script_timeout | The timeout in seconds for this execution.<br/>\(Default is: '600'\) |  | Optional |
| polling_timeout | Amount of time to poll action status before declaring a timeout and resuming the playbook \(in minutes\). | 10 | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptResult.results._return_value | Value returned by the script in case the type is not a dictionary. | unknown |

## Playbook Image

---

![Cortex XDR - delete file](../doc_files/Cortex_XDR_-_Delete_file.png)
