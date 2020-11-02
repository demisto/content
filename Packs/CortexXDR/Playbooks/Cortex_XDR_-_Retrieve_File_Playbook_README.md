Retrieve files from selected endpoints. You can retrieve up to 20 files, from no more than 10 endpoints.
Please enter - endpoint ids, comma separated and at least one file path:
windows_file_paths - comma separated,
linux_file_paths - comma separated,
mac_file_paths - comma separated

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Cortex XDR - IR

### Scripts
* PrintErrorEntry

### Commands
* xdr-retrieve-files
* xdr-retrieve-file-details

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| endpoint_ids | Please enter comma separated list of endpoint ids. |  | Required |
| windows_file_paths | Comma separated list, of paths.<br/>Please enter at least one path \( windows, linux or mac\) |  | Optional |
| linux_file_paths | Comma separated list, of paths.<br/>Please enter at least one path \( windows, linux or mac\) |  | Optional |
| mac_file_paths | Comma separated list, of paths.<br/>Please enter at least one path \( windows, linux or mac\) |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXDR.RetrievedFileDetails | Retrieve file details command results. | unknown |
| PaloAltoNetworksXDR.RetrievedFileDetails.endpoint_id | Endpoint ID. | string |
| PaloAltoNetworksXDR.RetrievedFileDetails.file_link | Link to the file retrieved by Retrieve File request. | string |
| PaloAltoNetworksXDR.RetrievedFileDetails.action_id | Action ID of the Retrieve File request | string |

## Playbook Image
---
![Cortex XDR - Retrieve File Playbook](https://raw.githubusercontent.com/demisto/content/cortex-xdr-enhancement/Packs/CortexXDR/doc_files/Cortex%20XDR%20-%20Retrieve%20File%20Playbook.png)