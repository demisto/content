This playbook handles command and scripting interpreter alerts based on the MITRE T1059 technique.
An attacker might abuse command and script interpreters to execute commands, scripts, or binaries.
Most systems come with some kind of built-in command line interface and scripting capabilities. For example, macOS and Linux distributions include some form of Unix Shell while Windows installations include the Windows Command Shell and PowerShell.


**Attacker's Goals:**

An attacker can abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in initial access payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. An attacker may also execute commands through interactive terminals/shells, as well as utilize various remote services to achieve remote execution.

**Analysis**

Due to the nature of this technique and the usage of built-in command line interfaces, the first step of the playbook is to analyze the command line. 
The command line analysis does the following:
- Checks and decodes base64
- Extracts and enriches indicators from the command line
- Checks specific arguments for malicious usage 

**Investigative Actions:**
The playbook checks for additional activity using the 'Endpoint Investigation Plan' playbook and utilizes the power of insight alerts.

**Response Actions**

After analyzing the data, the playbook's first response action is to contain the threat based on the initial data provided within the alert. In this phase, the playbook will:

* Isolate the endpoint based on playbook inputs.

When the playbook proceeds, it checks for additional activity using the 'Endpoint Investigation Plan' playbook. It then continues with the next stage, which includes, containment and eradication.

This phase executes the following containment actions:

* Automatically isolates the endpoint

It then continues with the following eradication actions:

* process termination

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Containment Plan
* Endpoint Investigation Plan
* Eradication Plan
* Recovery Plan
* Command-Line Analysis
* Handle False Positive Alerts

### Integrations
* CortexCoreIR

### Scripts
This playbook does not use any scripts.

### Commands
* core-get-dynamic-analysis
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ShouldCloseAutomatically | Whether to close the alert automatically or manually, after an analyst's review. | False | Optional |
| AutoRestoreEndpoint | Whether to execute the Recovery playbook. | False | Optional |
| AutoContainment | Whether to execute automatically or manually the containment plan tasks:<br/>\* Block indicators<br/>\* Quarantine file<br/>\* Disable user  |  | Optional |
| PreHostContainment | Isolate the host after the Analysis phase \(command-line analysis\) | True | Optional |
| FileRemediation | Can be 'Quarantine' or 'Delete'. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![T1059 - Command and Scripting Interpreter](https://raw.githubusercontent.com/demisto/content/260a4d094a4db588e37a3763d511b5248cd7049b/Packs/Core/doc_files/T1059_-_Command_and_Scripting_Interpreter.png)