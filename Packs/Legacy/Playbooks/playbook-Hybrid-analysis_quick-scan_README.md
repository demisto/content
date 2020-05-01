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
![Hybrid-analysis_quick-scan](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Hybrid-analysis_quick-scan.png)
