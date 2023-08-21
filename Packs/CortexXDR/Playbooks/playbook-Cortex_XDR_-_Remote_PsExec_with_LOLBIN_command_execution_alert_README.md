The "Remote PsExec-like LOLBIN Command Execution" playbook is designed to address and respond to alerts indicating suspicious activities related to remote PsExec-like LOLBIN command execution from an unsigned non-standard source. 
The playbook aims to efficiently:

- Get the alert data and check if the execution is blocked. If not will terminate the process (Manually by default).
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

* Block Indicators - Generic v3
* Command-Line Analysis
* Entity Enrichment - Generic v4
* TIM - Indicator Relationships Analysis
* Cortex XDR - Endpoint Investigation
* Threat Hunting - Generic

### Integrations

* Cortex XDR - IR
* CortexXDRIR

### Scripts

* IncreaseIncidentSeverity

### Commands

* xdr-get-alerts
* xdr-script-commands-execute

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IPAddress | The remote IP address which executed the process | incident.xdralerts.actionremoteip | Optional |
| alerts_ids | The ID's of the relevant alerts | incident.xdralerts.alert_id | Optional |
| AutoRemediation | Whether remediation will be run automatically or manually. If set to "True" - remediation will be automatic. | false | Optional |
| rule_id | The ID of the \`Remote PsExec-like LOLBIN command execution from an unsigned non-standard\` XDR analytics alert | f2282012-53aa-44f0-bda2-e45cd6b8b61a | Optional |
| LOLBASFeedLimit | LOLBAS Feed results limit | 100 | Optional |
| EndpointIDs | The IDs of the victim endpoint | incident.xdralerts.endpoint_id | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Remote PsExec with LOLBIN command execution alert](../doc_files/Cortext_XDR_-_Remote_PsExec_with_LOLBIN_command_execution_alert.png)
