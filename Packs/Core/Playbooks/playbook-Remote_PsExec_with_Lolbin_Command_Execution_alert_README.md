The "Remote PsExec-like LOLBIN Command Execution" playbook is designed to address and respond to alerts indicating suspicious activities related to remote PsExec-like LOLBIN command execution from an unsigned non-standard source. 
The playbook aims to efficiently:

- Check if the execution is blocked. If not will terminate the process (Manually by default).
- Enrich any entities and indicators from the alert and find any related campaigns.
- Perform command analysis to provide insights and verdict for the executed command.
- Perform further endpoint investigation using XDR.
- Checks for any malicious verdict found to raise the severity of the alert.
- Perform Automatic/Manual remediation response by blocking any malicious indicators found.

The playbook is designed to run as a sub-playbook in ‘Cortex XDR Incident Handling - v3 & Cortex XDR Alerts Handling’.
It depends on the data from the parent playbooks and can not be used as a standalone version.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Threat Hunting - Generic
* Block Indicators - Generic v3
* Command-Line Analysis
* Get entity alerts by MITRE tactics
* Enrichment for Verdict

### Integrations

* CortexCoreIR

### Scripts

This playbook does not use any scripts.

### Commands

* extractIndicators
* core-get-endpoints
* core-run-script-execute-commands
* setAlert
* setIncident

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| alerts_ids | The ID's of the relevant alerts | ${alert.id} | Optional |
| AutoRemediation | Whether remediation will be run automatically or manually. If set to "True" - remediation will be automatic. | false | Optional |
| LOLBASFeedLimit | LOLBAS Feed results limit | 100 | Optional |
| EndpointIDs | The IDs of the victim endpoint | ${alert.hostip} | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Remote PsExec with LOLBIN command execution alert](../doc_files/Remote_PsExec_with_LOLBIN_command_execution_alert.png)
