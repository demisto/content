Uses the Upload API to have a client application request that Check Point Threat Prevention modules scan and analyze a file. When a file is to the service, the file will be encrypted. The file is un-encrypted during analysis, and then deleted.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | sandblast |


## Dependencies

---
This script uses the following commands and scripts.

* sb-upload

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| file_name | The name of the file. The service calculates the file name from the part name. |
| md5 | The MD5 hash of the file to upload. |
| sha1 | The SHA1 hash of the file to upload. |
| sha256 | The SHA256 hash of the file to upload. |
| file_type | The extension of the file. The service identifies the type of the file. |
| features | The available features. The default is "te" and "av". |
| images | The array of the objects with ID and revision of available OS images. |
| reports | The array of supported report formats. Can be, "pdf", "xml", or "tar". |
| benign_reports | By default, reports are returned only for malicious files. Mark this as true and get benign reports. |
| file_id | The ID of the file. |

## Outputs

---
There are no outputs for this script.
