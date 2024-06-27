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

When the playbook executes, it checks for additional activity, and if a malicious behavior is found, the playbook proceeds with containment and eradication, is executed.

This phase will execute the following containment actions:

* Manual block indicators
* Manual file quarantine
* Auto endpoint isolation
* Auto process termination

External resources:

[MITRE Technique T1036](https://attack.mitre.org/techniques/T1036/)

[Possible Microsoft process masquerading](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Analytics-Alert-Reference/Possible-Microsoft-process-masquerading).

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Detonate File - Generic
* Command-Line Analysis
* Entity Enrichment - Generic v3
* Cortex XDR - Quarantine File v2
* Cortex XDR - Endpoint Investigation

### Integrations

* CortexXDRIR

### Scripts

* GetErrorsFromEntry
* HttpV2
* ParseJSON

### Commands

xdr-snippet-code-script-execute

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoContainment | Setting this input to True will quarantine the file automatically in case of malicious file. | True | Optional |
| FileSHA256 | The file SHA256 to investigate. | PaloAltoNetworksXDR.Incident.alerts.actor_process_image_sha256 | Optional |
| FilePath | The file path to investigate. | PaloAltoNetworksXDR.Incident.alerts.actor_process_image_path | Optional |
| Username | The alert's username. | PaloAltoNetworksXDR.Incident.alerts.user_name | Optional |
| EndpointID | The IP, Hostname or ID of the Endpoint | PaloAltoNetworksXDR.Incident.alerts.endpoint_id | Optional |
| AlertID | The ID of the alert | PaloAltoNetworksXDR.Incident.alerts.aler_id | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex XDR - T1036 - Masquerading](../doc_files/Cortex_XDR_-_T1036_-_Masquerading.png)
