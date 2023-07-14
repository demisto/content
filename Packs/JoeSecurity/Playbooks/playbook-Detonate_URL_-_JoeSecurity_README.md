Deprecated. Use the joe-submit-url command instead.

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
* joe-analysis-submit-url

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | URL to detonate. | URL.Data | Optional |
| Interval | Duration for executing the pooling \(in minutes\) | 1 | Optional |
| Timeout | The duration after which to stop pooling and to resume the playbook \(in minutes\) | 15 | Optional |
| Systems | Operating system to run the analysis on \(comma-separated\). Supported values are: w7, w7x64, w7_1, w7_2, w7native, android2, android3, mac1, w7l, w7x64l, w10, android4, w7x64native, w7_3, w10native, android5native_1, w7_4, w7_5, w10x64, w7x64_hvm, android6, iphone1, w7_sec, macvm, w7_lang_packs, w7x64native_hvm, lnxubuntu1, lnxcentos1, android7_nougat |  | Optional |
| Comments | Comments for the analysis. |  | Optional |
| InternetAccess | Enable internet access \(boolean\). True= internet access \(default\), False= no internet access. | True | Optional |
| ReportFileType | The resource type to download. Default is html. Supported values are: html, lighthtml, executive, pdf, classhtml, xml, lightxml, classxml, clusterxml, irxml, json, jsonfixed, lightjson, lightjsonfixed, irjson, irjsonfixed, shoots \(screenshots\), openioc, maec, misp, graphreports, memstrings, binstrings, sample, cookbook, bins \(dropped files\), unpackpe \(unpacked PE files\), unpack, ida, pcap, pcapslim, memdumps, yara | html | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Vendor | The vendor used to calculate the score. | string |
| Joe.Analysis.ID | Web ID | string |
| Joe.Analysis.Status | Analysis Status | string |
| Joe.Analysis.Comments | Analysis Comments | string |
| Joe.Analysis.Time | Submitted Time | date |
| Joe.Analysis.Runs | Sub-Analysis Information | unknown |
| Joe.Analysis.Result | Analysis Results | string |
| Joe.Analysis.Errors | Raised errors during sampling | unknown |
| Joe.Analysis.Systems | Analysis OS | unknown |
| Joe.Analysis.MD5 | MD5 of analysis sample | string |
| Joe.Analysis.SHA1 | SHA1 of analysis sample | string |
| Joe.Analysis.SHA256 | SHA256 of analysis sample | string |
| Joe.Analysis.SampleName | Sample Data, could be a file name or URL | string |
| DBotScore.Indicator | The name of the sample file or URL | string |
| DBotScore.Type | 'url' for url samples, otherwise 'file' | string |
| DBotScore.Score | The actual score. | number |
| DBotScore.Malicious.Vendor | The vendor used to calculate the score. | string |
| DBotScore.Malicious.Detections | The sub analysis detection statuses | string |
| DBotScore.Malicious.SHA1 | The SHA1 of the file | string |
| InfoFile.Name | FileName | string |
| InfoFile.EntryID | The EntryID of the sample | string |
| InfoFile.Size | File Size | number |
| InfoFile.Type | File type e.g. "PE" | string |
| InfoFile.Info | Basic information of the file | string |
| File.Extension | File Extension | string |
| InfoFile | Report file object | unknown |
| File | File object | unknown |
| Joe.Analysis | Joe analysis object | unknown |
| DBotScore | DBotScore object | unknown |
| DBotScore.Malicious | DBotScore malicious object | unknown |

## Playbook Image

---

![Detonate URL - JoeSecurity](../doc_files/Detonate_URL_-_JoeSecurity.png)
