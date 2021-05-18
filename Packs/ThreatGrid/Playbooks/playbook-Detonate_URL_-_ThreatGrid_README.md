Detonates one or more URLs using the ThreatGrid integration. This playbook returns relevant reports to the War Room and URL reputations to the context data.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Threat Grid

### Scripts
This playbook does not use any scripts.

### Commands
* threat-grid-url-to-file
* threat-grid-get-samples-state
* threat-grid-upload-sample

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| URL | The URL of the sites to detonate. | Data | URL | Optional |
| FileName | The name of the file to detonate. | file-detonated-via-demisto | - | Optional |
| VM | The VM to use (string). | - | - | Optional |
| Playbook | The name of the Threat Grid playbook to apply to this sample run. | default | - | Optional |
| Private | The sample is marked private if this is present. If it is set to any other value then it will not be private. | - | - | Optional |
| Source | The string used for identifying the source of the detonation (user defined). | - | - | Optional |
| Tags | A comma-separated list of tags applied to the sample. | - | - | Optional |
| Interval | The polling frequency. How often the polling command should run (in minutes). | 1 | - | Optional |
| Timeout | How much time to wait before a timeout occurs (in minutes). | 15 | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.SHA256 | The SHA256 hash of the file. | string |
| File.Malicious | The File malicious description | unknown |
| File.Type | The file type. For example, "PE". | string |
| File.Size | THe file size. | number |
| File.MD5 | The MD5 hash of the file. | string |
| File.Name | The filename. | string |
| File.SHA1 | The SHA1 hash of the file. | string |
| File | The file object. | unknown |
| File.Malicious.Vendor | The vendor that made the decision that the file is malicious. | string |
| DBotScore | The DBotScore object. | unknown |
| DBotScore.Indicator | The indicator that was tested. | string |
| DBotScore.Type | The type of the indicator. | string |
| DBotScore.Vendor | The vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| Sample.State | The sample state. | unknown |
| Sample.ID | The sample ID. | unknown |

## Playbook Image
---
![Detonate_URL_ThreatGrid](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Detonate_URL_ThreatGrid.png)
