This playbook handles masquerading alerts based on MITRE T1036 technique.
An attacker might leverage Microsoft Windows well-known image names to run malicious processes without being caught.

**Attacker's Goals:**

An attacker is attempting to masquerade as standard windows images by using a trusted name to execute malicious code.

**Investigative Actions:**

Investigate the executed process image and verify if it is malicious using:

* XDR trusted signers
* VT trusted signers
* VT detection rate
* NSRL DB

**Response Actions**

The playbook's first response action is a containment plan which is based on the initial data provided within the alert. In that phase, the playbook will execute:

* Auto block indicators
* Auto file quarantine
* Manual endpoint isolation

When the playbook proceeds, it checks for additional activity using the Endpoint Investigation Plan playbook, and another phase, which includes containment and eradication, is executed.

This phase will execute the following containment actions:

* Manual block indicators
* Manual file quarantine
* Auto endpoint isolation

And the following eradication actions:

* Manual process termination
* Manual file deletion
* Manual reset of the user’s password

External resources:

[MITRE Technique T1036](https://attack.mitre.org/techniques/T1036/)

[Possible Microsoft process masquerading](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-analytics-alert-reference/cortex-xdr-analytics-alert-reference/possible-microsoft-process-masquerading.html)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Endpoint Investigation Plan
* Containment Plan
* Eradication Plan
* Enrichment for Verdict
* Handle False Positive Alerts
* Recovery Plan

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileRemediation | Should be either 'Quarantine' or 'Delete'. | Quarantine | Required |
| AutoCloseAlert | Whether to close the alert automatically or manually after an analyst's review. | false | Optional |
| AutoRecovery | Whether to execute the Recovery playbook. | false | Optional |
| AutoContainment | Whether to execute automatically or manually the containment plan tasks:<br/>\* Block indicators<br/>\* Quarantine file<br/>\* Disable user |  | Optional |
| HostAutoContainment | Whether to execute endpoint isolation automatically or manually based on the Endpoint Investigation findings. | true | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![T1036 - Masquerading](https://raw.githubusercontent.com/demisto/content/b9b3e36e6893e95be5de09876efce94acec09da8/Packs/Core/doc_files/T1036_-_Masquerading.png)