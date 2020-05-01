Detonates one or more files using the Joe Security - Joe Sandbox integration.
Returns relevant reports to the War Room and file reputations to the context data.
All file types are supported.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Joe Security

### Scripts
* Set

### Commands
* joe-analysis-info
* joe-download-report
* joe-analysis-submit-sample

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| File | The file object of the file to detonate. The file is taken from the context. | None | File | Optional |
| Interval | The duration for executing the pooling (in minutes). | 1 | - | Optional |
| Timeout | The duration after which to stop pooling and to resume the playbook (in minutes). | 15 |-  | Optional |
| Systems | The operating system to run the analysis on (comma-separated). Supported values are: w7, w7x64, w7_1, w7_2, w7native, android2, android3, mac1, w7l, w7x64l, w10, android4, w7x64native, w7_3, w10native, android5native_1, w7_4, w7_5, w10x64, w7x64_hvm, android6, iphone1, w7_sec, macvm, w7_lang_packs, w7x64native_hvm, lnxubuntu1, lnxcentos1, android7_nougat. | - |-  | Optional |
| Comments | The comments for the analysis. | - | - | Optional |
| InternetAccess | Whether to enable internet access (boolean). The default is "True". "True" means there is internet access. "False" means there is no internet access. | True | - | Optional |
| ReportFileType | The resource type to download. The default is "HTML". The supported values are: html, lighthtml, executive, pdf, classhtml, xml, lightxml, classxml, clusterxml, irxml, json, jsonfixed, lightjson, lightjsonfixed, irjson, irjsonfixed, shoots (screenshots), openioc, maec, misp, graphreports, memstrings, binstrings, sample, cookbook, bins (dropped files), unpackpe (unpacked PE files), unpack, ida, pcap, pcapslim, memdumps, yara. |-  | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Vendor | The vendor used to calculate the score. | string |
| Joe.Analysis.ID | The web ID. | string |
| Joe.Analysis.Status | The analysis status. | string |
| Joe.Analysis.Comments | The analysis comments. | string |
| Joe.Analysis.Time | The submitted time. | date |
| Joe.Analysis.Runs | The sub-analysis information. | unknown |
| Joe.Analysis.Result | The analysis results. | string |
| Joe.Analysis.Errors | The raised errors during sampling. | unknown |
| Joe.Analysis.Systems | The analysis OS. | unknown |
| Joe.Analysis.MD5 | The MD5 hash of analysis sample. | string |
| Joe.Analysis.SHA1 | The SHA1 hash of analysis sample. | string |
| Joe.Analysis.SHA256 | The SHA256 hash of analysis sample. | string |
| Joe.Analysis.SampleName | The sample data. Can be, "file name" or "URL". | string |
| DBotScore.Indicator | The indicator that was tested. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Score | The actual score. | number |
| DBotScore.Malicious.Vendor | The vendor used to calculate the score. | string |
| DBotScore.Malicious.Detections | The sub-analysis detection statuses. | string |
| DBotScore.Malicious.SHA1 | The SHA1 hash of the file. | string |
| InfoFile.Name | The filename. | string |
| InfoFile.EntryID | The EntryID of the sample. | string |
| InfoFile.Size | The file size. | number |
| InfoFile.Type | The file type. For example, "PE". | string |
| InfoFile.Info | The basic information of the file. | string |
| File.Extension | The file extension. | string |
| InfoFile | The report file object. | unknown |
| File | The file object. | unknown |
| Joe.Analysis | The Joe analysis object. | unknown |
| DBotScore | The DBotScore object. | unknown |
| DBotScore.Malicious | The DBotScore malicious object. | unknown |

## Playbook Image
---
![Detonate_File_JoeSecurity](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Detonate_File_JoeSecurity.png)
