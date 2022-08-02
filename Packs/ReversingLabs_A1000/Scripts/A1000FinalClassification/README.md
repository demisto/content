Calculates A1000 final classification based on A1000 classification and A1000 full reports.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| a1000_classification_report | A1000 classification report |
| a1000_full_report | A1000 full report |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.SHA256 | The SHA256 hash of the file. | String |
| File.SHA1 | The SHA1 hash of the file. | String |
| File.SHA512 | The SHA512 hash of the file. | String |
| File.Name | The name of the file. | String |
| File.EntryID | The Entry ID. | String |
| File.Info | Information about the file. | String |
| File.Type | The type of the file. | String |
| File.MD5 | MD5 hash of the file. | String |
| DBotScore.Score | The actual score. | Number |
| DBotScore.Type | The indicator type. | String |
| DBotScore.Indicator | The indicator that was tested. | String |
| DBotScore.Vendor | The vendor used to calculate the score. | String |
