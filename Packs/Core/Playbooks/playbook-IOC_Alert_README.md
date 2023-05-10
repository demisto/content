IOCs provide the ability to alert on known malicious objects on endpoints across the organization. 

**Analysis Actions:**
The playbook will use several enrichment sources to determine the IOC verdict. Additionally, will use the Analytics module to run a prevalence check for the IOC.

**Response Actions**
The playbook's first response action is a containment plan which is based on the playbook input. In that phase, the playbook will execute endpoint isolation.

**Investigative Actions:**
When the playbook executes, it checks for additional abnormal activity using the Endpoint Investigation Plan playbook that can indicate the endpoint might be compromised.

**Remediation Actions:**
In case results are found within the investigation phase, the playbook will execute remediation actions that include containment and eradication.

This phase will execute the following containment actions:

* File quarantine
* Endpoint isolation

And the following eradication actions:

* Manual process termination
* Manual file deletion

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Eradication Plan
* Enrichment for Verdict
* Handle False Positive Alerts
* Endpoint Investigation Plan
* Recovery Plan
* Containment Plan

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* extractIndicators
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| BlockIndicatorsAutomatically | Whether to block suspicious/malicious indicators automatically. Specify True/False. | False | Optional |
| ShouldCloseAutomatically | Whether to close the alert automatically if it's established verdict is False Positive? | True | Optional |
| PreHostContainment | Whether to isolate the host before the investigation phase in case an IOC is found to be suspicious. | False | Optional |
| ShouldHandleFPautomatically | Whether to automatically handle false positive alerts? Specify true/false. |  | Optional |
| AutoRestoreEndpoint | Whether to execute the Recovery playbook. |  | Optional |
| AutoContainment | Setting this input will impact both Containment Plan sub-playbooks. Without setting this input, the default values are True for the first occurrence and False for the second.<br/>Whether to execute automatically or manually the containment plan tasks:<br/>\* Isolate endpoint<br/>\* Block indicators<br/>\* Quarantine file<br/>\* Disable user |  | Optional |
| FileRemediation | Should be either 'Quarantine' or 'Delete'. | Quarantine | Optional |
| AutoEradication | Whether to execute automatically or manually the eradication plan tasks:<br/>\* Terminate process<br/>\* Delete file<br/>\* Reset the user's password | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![IOC Alert](../doc_files/IOC_Alert.png)
