Detonates one or more remote files using the Joe Security sandbox integration.
Returns relevant reports to the War Room and file reputations to the context data.
This type of analysis is available for Windows only and works only for direct download links.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Joe Security

### Scripts
This playbook does not use any scripts.

### Commands
* joe-analysis-submit-sample
* joe-download-report

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileURL | The URL of the web file to detonate. The `FileUrl` is taken from the context. | - | Optional |
| Interval | The duration for executing the pooling (in minutes). | 1 | Optional |
| Timeout | The duration after which to stop pooling and to resume the playbook (in minutes). | 15 | Optional |
| Systems | The operating system to run the analysis on (comma-separated). Supported values are: w7, w7x64, w7_1, w7_2, w7native, android2, android3, mac1, w7l, w7x64l, w10, android4, w7x64native, w7_3, w10native, android5native_1, w7_4, w7_5, w10x64, w7x64_hvm, android6, iphone1, w7_sec, macvm, w7_lang_packs, w7x64native_hvm, lnxubuntu1, lnxcentos1, android7_nougat. | - | Optional |
| Comments | The comments for the analysis. | - | Optional |
| InternetAccess | Whether internet access is enabled (boolean). The default is "True". "True" means there is internet access. False means there is no internet access. | True | Optional |
| ReportFileType | The resource type to download. The default is "html". The spported values are, "html", "lighthtml", "executive", "pdf", "classhtml", "xml", "lightxml", "classxml", "clusterxml", "irxml", "json", "jsonfixed", "lightjson", "lightjsonfixed", "irjson", "irjsonfixed", "shoots" (screenshots), "openioc", "maec", "misp", "graphreports", "memstrings", "binstrings", "sample", "cookbook", "bins" (dropped files), 'unpackpe" (unpacked PE files), "unpack", "ida", "pcap", "pcapslim", "memdumps", or "yara". | html | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Malicious.Vendor | The vendor that made the decision that the file is malicious. | string |
| File.Name | The filename (only in case of report type=json). | string |
| File.Size | The file size (only in case of report type=json). | number |
| File.MD5 | The MD5 hash of the file (only in case of report type=json). | string |
| File.SHA1 | The SHA1 hash of the file (only in case of report type=json). | string |
| File.Type | The file type. For example, "PE" (only in case of report type=json). | string |
| File.SHA256 | The SHA256 hash of the file (only in case of report type=json). | string |
| File.EntryID | The Entry ID of the sample. | string |
| File.Malicious.Description | The reason for the vendor to make the decision that the file is malicious. | string |
| DBotScore.Indicator | The indicator that was tested (only in case of report type=json). | string |
| DBotScore.Type | The indicator type (only in case of report type=json). | string |
| DBotScore.Vendor | The vendor used to calculate the score (only in case of report type=json). | string |
| IP.Address | The IP addresses's relevant to the sample. | string |
| DBotScore.Score | The actual score (only in case of report type=json). | number |

## Playbook Image
---
![Detonate_File_From_URL_JoeSecurity](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Detonate_File_From_URL_JoeSecurity.png)
