This playbook handles Command and Scripting Interpreter alerts based on MITRE T1059 technique.
An attacker might abuse command and script interpreters to execute commands, scripts, or binaries.
Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of Unix Shell while Windows installations include the Windows Command Shell and PowerShell.


**Attacker's Goals:**

An attacker can abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in Initial Access payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. attacker may also execute commands through interactive terminals/shells, as well as utilize various Remote Services in order to achieve remote Execution.

**Analysis**

Due to the nature of this technique and the usage of built-in command-line interfaces, the first step of the playbook is to analyze the command-line. 
The command-line analysis will:
- Checks and decode base64
- Extracts and enrich indicators from the command line
- Checks specific arguments for malicious usage 

**Investigative Actions:**
The playbook checks for additional activity using the 'Endpoint Investigation Plan' playbook and utilizes the power of the insight alerts.

**Response Actions**

The playbook's first response actions is to contain the threat based on the initial data provided within the alert and after analyzing the data. In that phase, the playbook will execute:

* Isolate the endpoint based on playbook inputs.

When the playbook proceeds, it checks for additional activity using the 'Endpoint Investigation Plan' playbook, and another phase, which includes containment and eradication, is executed.

This phase will execute the following containment actions:

* Automatically isolate the endpoint

And the following eradication actions:

* process termination

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Endpoint Investigation Plan
* Command-Line Analysis
* Handle False Positive Alerts
* Containment Plan
* Recovery Plan
* Eradication Plan

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
| CloseAlertAfterEradication | Whether to automatically close the alert after investigation and remediation are finished. True/False. | False | Optional |
| AutoRestoreEndpoint | Whether to execute the Recovery playbook. | False | Optional |
| AutoContainment | Whether to execute automatically or manually the containment plan tasks:<br/>\* Block indicators<br/>\* Quarantine file<br/>\* Disable user  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![T1059 - Command and Scripting Interpreter](Insert the link to your image here)