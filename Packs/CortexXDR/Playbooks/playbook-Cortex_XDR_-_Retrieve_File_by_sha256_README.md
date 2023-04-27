This playbook is part of the 'Malware Investigation And Response' pack. For more information, refer to https://xsoar.pan.dev/docs/reference/packs/malware-investigation-and-response.
This playbook is a sub-playbook for the Cortex XDR malware investigation flow. In this playbook, we retrieve multiple files from the investigated device (using the Device ID incident field), based on their SHA256 hash.
To run the playbook always remember to make it shared with the global context and set the Sha256 input to run in a loop ( in case there are multiple SHA256s that needs to be retrieved).

How does this playbook works:
The playbook sets all SHA256 paths from the alert to be retreived from the endpoint. Once the playbook checked the relevent paths (Actor,Action and Cusallity paths) it will run all the mathced pats agains all the endpoints ids that are
associated with the incident.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cortex XDR - Get File Path from alerts by hash

### Integrations

* CortexXDRIR

### Scripts

* isError
* UnzipFile
* PrintErrorEntry

### Commands

* xdr-file-retrieve

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Sha256 | SHA256 for the file to be retrieved. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | Retrieve the file details command results. | unknown |
| File.Name | The full file name \(including the file extension\). | String |
| File.EntryID | The ID for locating the file in the War Room. | String |
| File.Size | The size of the file in bytes. | Number |
| File.MD5 | The MD5 hash of the file. | String |
| File.SHA1 | The SHA1 hash of the file. | String |
| File.SHA256 | The SHA256 hash of the file. | String |
| File.SHA512 | The SHA512 hash of the file. | String |
| File.Extension | The file extension. For example, 'xls'. | String |
| File.Type | The file type, as determined by libmagic \(same as displayed in the file entries\). | String |

## Playbook Image

---

![Cortex XDR - Retrieve File by sha256](../doc_files/Cortex_XDR_-_Retrieve_File_by_sha256.png)
