Deprecated. No available replacement.

Runs a quick-scan command with `Generic-Polling`.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* hybrid-analysis-quick-scan-url-results
* hybrid-analysis-quick-scan-url

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| url | The website URL, or the URL that contains the file to submit. | - | Optional |
| scan_type | The type of scan. Run the `hybrid-analysis-list-scanners` command to view available scanners. | all | Optional |
| min_malicious_scanners | The number of scanners that report the file as malicious to determine whether the file is malicious. The default is "2". | 2 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HybridAnalysis.URL.SubmissionType | The type of the submission. Can be, "file" or "url". | unknown |

## Playbook Image
---
![Hybrid-analysis_quick-scan](https://raw.githubusercontent.com/demisto/content/bf8a2c7a52660270f2feb78b649076aa204a25e3/Packs/HybridAnalysis/doc_files/Hybrid-analysis_quick-scan.png)
