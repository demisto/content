Retrieves a file's reputation and upload the file if required for analysis.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | server, threat-intel, cylance, file |


## Dependencies
---
This script uses the following commands and scripts.
* file
* cy-upload

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entry | The ID of a file entry to upload. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.MD5 | The bad MD5 file hash. | Unknown |
| File.SHA1 | The bad SHA1 file hash. | Unknown |
| File.SHA256 | The bad SHA256 file hash. | Unknown |
| File.Malicious.Vendor | The vendor that made the decision that the file is malicious. | Unknown |
| File.Malicious.Description | The reason that the vendor made the decision that the file is malcious.| Unknown |
| DBotScore.Indicator | The indicator that was tested. | Unknown |
| DBotScore.Type | The type of the indicator. | Unknown |
| DBotScore.Vendor | The vendor used to calculate the score. | Unknown |
| DBotScore.Score | The actual score. | Unknown |
