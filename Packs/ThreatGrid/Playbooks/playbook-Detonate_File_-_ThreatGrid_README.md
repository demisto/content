Detonates one or more files using the ThreatGrid integration. This playbook returns relevant reports to the War Room and file reputations to the context data. 

The detonation supports the following file types: EXE, DLL, JAR, JS, PDF, DOC, DOCX, RTF, XLS, PPT, PPTX, XML, ZIP, VBN, SEP, XZ, GZ, BZ2, TAR, MHTML, SWF, LNK, URL, MSI, JTD, JTT, JTDC, JTTC, HWP, HWT, HWPX, BAT, HTA, PS1, VBS, WSF, JSE, VBE, CHM.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
* threat-grid-get-samples-state
* threat-grid-upload-sample

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| File | The file object of the file to detonate. | None | File | Optional |
| FileName | The name of the file to detonate. | file-detonated-via-demisto | - | Optional |
| VM | The VM to use (string). | - | - | Optional |
| playbook | The name of the Threat Grid playbook to apply to this sample run. | Default | - | Optional |
| Private | The sample is marked private if this is present, and set to any value other than false. | - | - | Optional |
| Source | The string used for identifying the source of the detonation (user defined). | - | - | Optional |
| Tags | The comma-separated list of tags applied to this sample. | - | - | Optional |
| Interval | The polling frequency. How often the polling command should run (in minutes). | 1 | - | Optional |
| Timeout | How much time to wait before a timeout occurs (in minutes). | 15 | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Malicious | The file malicious description. | unknown |
| File.Malicious.Vendor | The vendor that made the decision that the file is malicious. | string |
| File.Type | The file type. For example "PE". | string |
| File.Size | The file size. | number |
| File.MD5 | The MD5 hash of the file. | string |
| File.Name | The filename. | string |
| File.SHA1 | The SHA1 hash of the file. | string |
| File | The file object. | unknown |
| File.SHA256 | The SHA256 hash of the file. | string |
| DBotScore | The DBotScore object. | unknown |
| DBotScore.Indicator | The indicator we tested. | string |
| DBotScore.Type | The type of the indicator. | string |
| DBotScore.Vendor | The vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| Sample.State | The sample state. | unknown |
| Sample.ID | The sample ID. | unknown |

## Playbook Image
---
![Detonate_File_ThreatGrid](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Detonate_File_ThreatGrid.png)
