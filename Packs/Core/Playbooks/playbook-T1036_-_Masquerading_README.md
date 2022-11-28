This playbook handles masquerading alerts based on the MITRE T1036 technique.
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

[MITRE Technique T1036](https://attack.mitre.org/techniques/T1036/)

[Possible Microsoft process masquerading](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-analytics-alert-reference/cortex-xdr-analytics-alert-reference/possible-microsoft-process-masquerading.html)

## How to use this playbook

### Create a new playbook trigger

1. Click on the **Incident Response** icon on the left menu.
2. Under **Automation** click on **Incident Configuration**.
3. Select **Playbook Triggers** on the left panel.
4. Click on **New Trigger**.
5. Choose a trigger name e.g. Masquerading Response.
6. Under **Playbook To Run**, select T1036 - Masquerading playbook.
7. Add trigger description - optional.
8. Create a filter for the playbook trigger.
    1. Click on 'select field'.
    2. Choose 'Mitre ATT&CK Technique'.
    3. Fill the value with 'T1036' and select all.
    4. Click **Create**.
    
* **Note** that the playbook triggers are executed according to its order. Consider changing the trigger position for the execution order as intended. If not, other trigger may override the new trigger.

Click **Save**.

### Playbook inputs

Before executing the playbook, review the inputs and change the default values, if needed.

Important playbook inputs you should pay attention to:

1. *FileRemediation*: Under the second phase of the playbook remediation, there are two sub-playbooks:
    1. Containment Plan
    2. Eradication Plan

One playbook can quarantine a file and the other can delete it. Since both can be executed together, this playbook input allows you to decide which response action the playbook should execute.

2. *AutoContainment*: Whether to execute the following response actions automatically or manually:
    1. Block indicators
    2. Quarantine file
    3. Disable user
    
3. *HostAutoContainment*: Whether to execute Endpoint Isolation automatically or manually.


### Playbook remediation plan

In this playbook the remediation plan happens in two different phases:

1. At an early stage of the playbook execution, the Containment Plan sub-playbook is being used for **File quarantine** and **Block indicators**.
2. At a later stage, the playbook executes the **Endpoint Investigation Plan**, which searches for additional activity on the alerted endpoint. In this phase, based on the results of the Endpoint Investigation Plan playbook, both Containment and Eradication Plan sub-playbooks are being executed.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Enrichment for Verdict
* Endpoint Investigation Plan
* Handle False Positive Alerts
* Eradication Plan
* Containment Plan
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
| AutoCloseAlert | Whether to close the alert automatically or manually, after an analyst's review. | False | Optional |
| AutoRecovery | Whether to execute the Recovery playbook. | False | Optional |
| AutoContainment | Setting this input will impact both Containment Plan sub-playbooks. Without setting this input, the default values are True for the first occurrence and False for the second.<br/>Whether to execute automatically or manually the containment plan tasks:<br/>\* Isolate endpoint<br/>\* Block indicators<br/>\* Quarantine file<br/>\* Disable user |  | Optional |
| AutoEradication | Whether to execute automatically or manually the eradication plan tasks:<br/>\* Terminate process<br/>\* Delete file<br/>\* Reset the user's password | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![T1036 - Masquerading](../doc_files/T1036_-_Masquerading.png)