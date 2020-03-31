Detonates a file through McAfee ATD. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
* McAfee Advanced Threat Defense

## Scripts
* Exists

## Commands
* detonate-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| EntryID | The EntryID of the file to detonate. | EntryID | File | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision. | string |
| File.Type | The file type e.g. "PE" (only in case of report type=json). | string |
| File.Size | The file size (only in case of report type=json). | number |
| File.MD5 | The MD5 hash of the file (only in case of report type=json). | string |
| File.Name | The filename (only in case of report type=json). | string |
| File.SHA1 | The SHA1 hash of the file (only in case of report type=json). | string |
| File | The file object. | unknown |
| File.Malicious.Description | For malicious files, the reason for the vendor to make the decision. | string |
| File.SHA256 | The SHA256 hash of the file (only in case of report type=json). | string |
| DBotScore | The DBotScore object. | unknown |
| DBotScore.Indicator | The indicator we tested (only in case of report type=json). | string |
| DBotScore.Type | The type of the indicator (only in case of report type=json). | string |
| DBotScore.Vendor | The vendor used to calculate the score (only in case of report type=json). | string |
| DBotScore.Score | The actual score (only in case of report type=json). | number |
| IP.Address | The IP's address relevant to the sample. | string |

![ATD_Detonate_File](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/ATD_Detonate_File.png)
