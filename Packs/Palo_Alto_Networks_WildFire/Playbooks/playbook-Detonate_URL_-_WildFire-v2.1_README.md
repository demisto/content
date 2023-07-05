Detonate a webpage or remote file using the WildFire integration. This playbook returns relevant reports to the War Room and file reputations to the context data.
The detonation supports the following file types:
APK, JAR, DOC, DOCX, RTF, OOXLS, XLSX, PPT, PPTX, XML, PE32, PDF, DMG, PKG, RAR, 7Z, JS.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

GenericPolling

### Integrations

Palo_Alto_Networks_WildFire_v2

### Scripts

This playbook does not use any scripts.

### Commands

* wildfire-upload-file-url
* wildfire-report
* wildfire-upload-url

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | URL of the webpage or file URL to detonate. The URL is taken from the context. | URL.Data | Optional |
| Interval | Duration for executing the polling \(in minutes\). | 1 | Optional |
| Timeout | The duration after which to stop polling and to resume the playbook \(in minutes\). | 60 | Optional |
| ReportFileType | The resource type to download. Default is PDF. XML is also possible. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore | The DBotScore object. | unknown |
| DBotScore.Score | The actual score. | number |
| File.Size | File size. | number |
| File.MD5 | MD5 hash. | string |
| File.SHA1 | SHA1 hash. | string |
| File.Type | File type, e.g., "PE". | string |
| File.SHA256 | SHA256 hash. | string |
| File.EntryID | The entry ID of the sample. | string |
| File.Malicious.Vendor | For malicious files, the vendor that determined that the file is malicious. | string |
| File.Name | File.name. | string |
| File.Malicious.Description | For malicious files, the reason the vendor determined that the file is malicious. | string |
| DBotScore.Indicator | The indicator we tested. | string |
| DBotScore.Type | The type of indicator. | string |
| DBotScore.Vendor | Vendor used to calculate the score. | string |
| IP.Address | IPs relevant to the sample. | string |
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
| WildFire.Report.MD5 | MD5 of the submission. | string |
| WildFire.Report.SHA256 | SHA256 of the submission. | string |
| WildFire.Report.FileType | The type of the submission. | string |
| WildFire.Report.Status | The status of the submission. | string |
| WildFire.Report.Size | The size of the submission. | number |
| WildFire.Report.URL | URL of the submission. | string |
| WildFire.Report.detection_reasons | The detection reasons object. | unknown |
| WildFire.Report.detection_reasons.description | Reason for the detection verdict. | string |
| WildFire.Report.detection_reasons.name | Name of the detection. | string |
| WildFire.Report.detection_reasons.type | Type of the detection. | string |
| WildFire.Report.detection_reasons.verdict | Verdict of the detection. | string |
| WildFire.Report.detection_reasons.artifacts | Artifacts for the detection reasons. | string |
| WildFire.Report.iocs | Associated IOCs. | string |

## Playbook Image
---
![Detonate_URL_WildFire-v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Detonate_URL_WildFire-v2.png)
