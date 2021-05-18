Detonates a file using the SNDBOX.

Advanced Threat Defense supports the following File Types:

Microsoft (2003 and earlier): doc, dot, xls, csv, xlt, xlm, ppt, pot, pps.

Microsoft (2007 and later): docx, docm, dotx, dotm, dotm, xlsx, xlsm, xltx, xltm, xlsb, xla, xlam, iqy, pptx, pptm, potx, ppsx, xml.

Other: pe32, rtf, pdf, vbs, vbe, ps1, js, lnk, html, bat.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
* sndbox-download-report
* sndbox-analysis-submit-sample
* sndbox-analysis-info

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| File | The file to detonate. The file is taken from the context. | None | File | Optional |
| Interval | How often the polling command should run (in minutes). | 1 | - | Optional |
| Timeout | How much time to wait before a timeout occurs (in minutes). | 15 | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SNDBOX.Analysis.ID | The analysis ID. | string |
| SNDBOX.Analysis.SampleName | The sample data. Can be, "filename" or "URL". | string |
| SNDBOX.Analysis.Status | The analysis status. | string |
| SNDBOX.Analysis.Time | The submitted time. | date |
| SNDBOX.Analysis.Result | The analysis results. | string |
| SNDBOX.Analysis.Errors | The errors raised during sampling. | unknown |
| SNDBOX.Analysis.Link | The analysis link. | string |
| SNDBOX.Analysis.MD5 | The MD5 hash of the analysis sample. | string |
| SNDBOX.Analysis.SHA1 | The SHA1 hash of the analysis sample. | string |
| SNDBOX.Analysis.SHA256 | The SHA256 hash of the analysis sample. | string |
| DBotScore.Vendor | The name of the vendor: SNDBOX. | string |
| DBotScore.Indicator | The name of the sample file or URL. | unknown |
| DBotScore.Type |The file. | string |
| DBotScore.Score | The actual score. | number |
| DBotScore.Malicious.Vendor | The name of the vendor: SNDBOX. | string |
| DBotScore.Malicious.Detections | The sub analysis detection statuses. | string |
| DBotScore.Malicious.SHA1 | The SHA1 hash of the file. | string |
| InfoFile.Name | The filename. | string |
| InfoFile.EntryID | The EntryID of the report. | string |
| InfoFile.Size | The file size. | number |
| InfoFile.Type | The file type. For example, "PE". | string |
| InfoFile.Info | The basic information of the file. | string |
| InfoFile.Extension | The file extension. | string |
| File.Size | The file size. | number |
| File.SHA1 | The SHA1 hash of the file. | string |
| File.SHA256 | The SHA256 hash of the file. | string |
| File.Name | The sample name. | string |
| File.SSDeep | The SSDeep hash of the file. | string |
| File.EntryID | The War Room entry ID of the file. | string |
| File.Info | The basic information of the file. | string |
| File.Type | The file type. For example, "PE". | string |
| File MD5 | The MD5 hash of the file. | string |
| File.Extension | The file extension. | string |

## Playbook Image
---
![Detonate_File_SNDBOX](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Detonate_File_SNDBOX.png)
