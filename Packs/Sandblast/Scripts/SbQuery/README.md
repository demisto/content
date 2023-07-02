Uses the Query API to have a client application look for either the analysis report of a specific file on the Check Point Threat Prevention service databases or the status of a file, uploaded for analysis.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | sandblast |


## Dependencies

---
This script uses the following commands and scripts.

* sb-query

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| md5 | The MD5 hash of the file to query. |
| sha1 | The SHA1 hash of the file to query. |
| sha256 | The SHA256 hash of the file to query. |
| file_type | The extension of the file. The service identifies the type. |
| features | The available features. The default is "te" and "av". |
| images | The array of the objects with ID and revision of the available OS images. |
| reports | The array of supported report formats. Can be, "pdf", "xml", or "tar". |
| benign_reports | By default, reports are returned only for malicious files. Mark this as true to get benign reports. |
| quota | Whether the response delivers the quota data (for cloud services only). |
| file_name | The name of the file. The service calculates the file name from the part name. |

## Outputs

---
There are no outputs for this script.
