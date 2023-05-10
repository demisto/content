Deprecated. Use cs-falcon-sandbox-submit-sample with polling=true instead.

Detonates one or more files using the Hybrid Analysis integration.
Returns relevant reports to the War Room and file reputations to the context data.
All file types are supported.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* hybrid-analysis-submit-sample
* hybrid-analysis-scan

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| File | The file object of the file to detonate. The File is taken from the context. | None | File | Optional |
| Interval | The duration for executing the pooling (in minutes). | 1 | - | Optional |
| Timeout | The duration after which to stop pooling and to resume the playbook (in minutes). | 15 | - | Optional |
| Systems | The operating system to run the analysis on (comma-separated). Supported values are: w7, w7x64, w7_1, w7_2, w7native, android2, android3, mac1, w7l, w7x64l, w10, android4, w7x64native, w7_3, w10native, android5native_1, w7_4, w7_5, w10x64, w7x64_hvm, android6, iphone1, w7_sec, macvm, w7_lang_packs, w7x64native_hvm, lnxubuntu1, lnxcentos1, android7_nougat | - | - | Optional |
| Comments | The comments for the analysis. | - |-  | Optional |
| InternetAccess | Whether to enable internet access (boolean). The default is "true". "True" means there is internet access. False means there is no internet access. | True | - | Optional |
| ReportFileType | The resource type to download. The default is html. The supported values are: html, lighthtml, executive, pdf, classhtml, xml, lightxml, classxml, clusterxml, irxml, json, jsonfixed, lightjson, lightjsonfixed, irjson, irjsonfixed, shoots (screenshots), openioc, maec, misp, graphreports, memstrings, binstrings, sample, cookbook, bins (dropped files), unpackpe (unpacked PE files), unpack, ida, pcap, pcapslim, memdumps, yara. | - | - | Optional |
| EnvironmentID | The hybrid analysis environment ID to submit the file to. | 100 | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.SHA256 | The SHA256 hash of the file. | date |
| File.SHA1 | The SHA1 hash of the file. | unknown |
| File.MD5 | The MD5 hash of the file. | string |
| File.environmentId | The environment ID of the file.  | unknown |
| File.analysis_start_time | The analysis start time of the file. | unknown |
| File.submitname | The submission name of the file. | string |
| File.classification_tags | The list of classification tags of the file. | string |
| File.vxfamily | The family classification of the file. | string |
| File.total_network_connections | The total network connections of the file. | string |
| File.total_processes | The total processes count of the file. | unknown |
| File.total_signatures | The total signatures count of the file. | string |
| File.hosts | The list of the file's hosts. | number |
| File.isinteresting | Whether the server found the file interesting. | string |
| File.domains | The list of the file's related domains. | string |
| File.isurlanalysis | Whether the file was analyzed by URL. | string |
| File.Malicious.Vendor | The vendor that made the decision that the file is malicious. | string |
| File.Malicious.Description | The reason for the vendor to make the decision that the file is malicious. | string |
| HybridAnalysis.Submit.State | The state of the process. | string |
| HybridAnalysis.Submit.SHA256 | The submission SHA256 hash. | unknown |
| HybridAnalysis.Submit.JobID | The JobID of the submission. | unknown |
| HybridAnalysis.Submit.EnvironmentID | The environmentID of the submission. | unknown |

## Playbook Image
---
![Detonate_File_HybridAnalysis](https://raw.githubusercontent.com/demisto/content/bf8a2c7a52660270f2feb78b649076aa204a25e3/Packs/HybridAnalysis/doc_files/Detonate_File_HybridAnalysis.png)
