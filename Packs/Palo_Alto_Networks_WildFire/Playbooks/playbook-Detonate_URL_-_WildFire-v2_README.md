Detonates a webpage or a remote file using the WildFire integration. This playbook returns relevant reports to the War Room and file reputations to the context data.

The detonation supports the following file types:
APK, JAR, DOC, DOCX, RTF, OOXLS, XLSX, PPT, PPTX, XML, PE32, PDF, DMG, PKG, RAR, 7Z.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* WildFire-v2

### Scripts
This playbook does not use any scripts.

### Commands
* wildfire-report
* wildfire-upload-file-url
* wildfire-upload-url

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| URL | The URL of the webpage or the file URL to detonate. The URL is taken from the context. | Data | URL | Optional |
| Interval | The duration for executing the pooling (in minutes). | 1 | - | Optional |
| Timeout | The duration after which to stop pooling and to resume the playbook (in minutes). | 15 | - | Optional |
| ReportFileType | The resource type to download. The default is pdf. XML is also possible. | - | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore | The DBotScore object. | unknown |
| DBotScore.Score | The actual score. | number |
| File.Size | The file size. | number |
| File.MD5 | The MD5 hash of the file. | string |
| File.SHA1 | The SHA1 hash of the file. | string |
| File.Type | The file type. For example, "PE". | string |
| File.SHA256 | Thas SHA256 hash of the file. | string |
| File.EntryID | The entry ID of the sample. | string |
| File.Malicious.Vendor | The vendor that made the decision that the file is malicious. | string |
| File.Name | The filename | string |
| File.Malicious.Description | The reason for the vendor to make the decision that the file is malicious. | string |
| DBotScore.Indicator | The indicator that was tested. | string |
| DBotScore.Type | The type of the indicator. | string |
| DBotScore.Vendor | The vendor used to calculate the score. | string |
| IP.Address | The IP addresses's relevant to the sample. | string |
| File | The file object. | unknown |
| InfoFile | The report file object. | unknown |
| InfoFile.EntryID | The EntryID of the report file. | string |
| InfoFile.Extension | The extension of the report file. | string |
| InfoFile.Name | The name of the report file. | string |
| InfoFile.Info | The info of the report file. | string |
| InfoFile.Size | The size of the report file. | number |
| InfoFile.Type | The type of the report file. | string |
| File.Malicious | The malicious object. | unknown |
| WildFire.Report | The submission object. | unknown |
| WildFire.Report.MD5 | The MD5 hash of the submission. | string |
| WildFire.Report.SHA256 | The SHA256  hash of the submission. | string |
| WildFire.Report.FileType | The type of the submission. | string |
| WildFire.Report.Status | The status of the submission. | string |
| WildFire.Report.Size | The size of the submission. | number |
| WildFire.Report.detection_reasons | The detection reasons object. | unknown |
| WildFire.Report.detection_reasons.description | Reason for the detection verdict. | string |
| WildFire.Report.detection_reasons.name | Name of the detection. | string |
| WildFire.Report.detection_reasons.type | Type of the detection. | string |
| WildFire.Report.detection_reasons.verdict | Verdict of the detection. | string |
| WildFire.Report.detection_reasons.artifacts | Artifacts for the detection. | string |
| WildFire.Report.iocs | Associated IOCs. | string |

## Playbook Image
---
![Detonate_URL_WildFire-v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Detonate_URL_WildFire-v2.png)
