This playbook handles false positive alerts.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* closeInvestigation
* core-add-exclusion
* core-allowlist-files

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ShouldCloseAutomatically | Should we close alerts as false positive automatically? Specify true/false. | alert.initiatormd5 | Optional |
| HostIP | Host IP from the alert. | alert.hostip | Optional |
| username | Username from the alert. | alert.username | Optional |
| alertName | Alert name. | alert.name | Optional |
| FileSHA256 | File SHA256 from the alert. | alert.initiatorsha256 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Handle False Positive Alerts](https://github.com/demisto/content/ffdcb3e5fd7a0d840bd476f458c9afa731cf1f51/Packs/CommonPlaybooks/doc_files/Enrichment_for_Verdict.png)
