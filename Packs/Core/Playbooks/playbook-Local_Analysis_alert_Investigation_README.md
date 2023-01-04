When an unknown executable, DLL, or macro attempts to run on a Windows or Mac endpoint, the Cortex XDR agent uses local analysis to determine if it is likely to be malware. Local analysis uses a static set of pattern-matching rules that inspect multiple file features and attributes, and a statistical model that was developed with machine learning on WildFire threat intelligence.

**Investigative Actions:**

Investigate the executed process image and verify if it is malicious using:

* XDR trusted signers
* VT trusted signers
* VT detection rate
* NSRL DB

**Response Actions**

The playbook's first response action is a containment plan that is based on the initial data provided within the alert. In that phase, the playbook will execute:

* Auto block indicators
* Auto file quarantine
* Manual endpoint isolation

When the playbook executes, it checks for additional activity using the Endpoint Investigation Plan playbook, and another phase, which includes containment and eradication, is executed.

This phase will execute the following containment actions:

* Manual block indicators
* Manual file quarantine
* Auto endpoint isolation

And the following eradication actions:

* Manual process termination
* Manual file deletion
* Manual reset of the user’s password

External resources:

[Malware Protection Flow](https://docs.paloaltonetworks.com/traps/4-2/traps-endpoint-security-manager-admin/malware-protection/malware-protection-flow)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Recovery Plan
* Containment Plan
* Wildfire Detonate and Analyze File
* Enrichment for Verdict
* Handle False Positive Alerts
* Eradication Plan
* Endpoint Investigation Plan

### Integrations
* CortexCoreIR

### Scripts
* UnzipFile
* GetTime

### Commands
* core-report-incorrect-wildfire
* internal-wildfire-get-report
* core-retrieve-files
* core-retrieve-file-details
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| GraywareAsMalware | Whether to treat Grayware verdict as Malware.  | False | Optional |
| AutoContainment | Setting this input will impact both Containment Plan sub-playbooks. Without setting this input, the default values are True for the first occurrence and False for the second.<br/>Whether to execute automatically or manually the containment plan tasks:<br/>\* Isolate endpoint<br/>\* Block indicators<br/>\* Quarantine file<br/>\* Disable user | True | Optional |
| AutoEradication | Whether to execute automatically or manually the eradication plan tasks:<br/>\* Terminate process<br/>\* Delete file<br/>\* Reset the user's password | False | Optional |
| FileRemediation | Should be either 'Quarantine' or 'Delete'. | Quarantine | Optional |
| AutoRecovery | Whether to execute the Recovery playbook. | False | Optional |
| AutoCloseAlert | Whether to close the alert automatically or manually, after an analyst's review. | False | Optional |
| ShouldRescanBenign | Whether to rescan \(Using WildFire detonate file\) benign files. | True | Optional |
| ShouldManualReviewFP | Whether to ask for a manual review before false positive handling. Should be True or False | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Local Analysis alert Investigation](../doc_files/Local_Analysis_alert_Investigation.png)