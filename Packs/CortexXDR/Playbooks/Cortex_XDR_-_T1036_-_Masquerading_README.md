This playbook handles masquerading alerts based on the MITRE T1036 technique.
An attacker might leverage Microsoft Windows well-known image names to run malicious processes without being caught.

**Attacker's Goals:**

An attacker is attempting to masquerade as standard windows images by using a trusted name to execute malicious code.

**Investigative Actions:**

Investigate the executed process image and verify if it is malicious using:

* File Reputation
* NSRL DB
* CommandLine Analysis
* Related Alerts


**Response Actions**

The playbook's first response action is a containment plan which is based on the initial data provided within the alert. In that phase, the playbook will execute:

* Auto Process termination
* Auto file quarantine
* Manual containment

External resources:

[MITRE Technique T1036](https://attack.mitre.org/techniques/T1036/)

[Possible Microsoft process masquerading](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Analytics-Alert-Reference/Possible-Microsoft-process-masquerading).

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cortex XDR - Endpoint Investigation
* Command-Line Analysis
* Cortex XDR - Quarantine File v2
* Entity Enrichment - Generic v3

### Integrations

* CortexXDRIR

### Scripts

* GetErrorsFromEntry
* HttpV2
* ParseJSON

### Commands

* xdr-snippet-code-script-execute

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoContainment | Setting this input to True will quarantine the file automatically in case of malicious file. | False | Optional |
| FileSHA256 | The file SHA256 to investigate. | PaloAltoNetworksXDR.Incident.alerts.actor_process_image_sha256 | Optional |
| FilePath | The file path to investigate. | PaloAltoNetworksXDR.Incident.alerts.actor_process_image_path | Optional |
| EndpointID | The IP, Hostname or ID of the Endpoint | PaloAltoNetworksXDR.Incident.alerts.endpoint_id | Optional |
| AlertID | The ID of the alert | PaloAltoNetworksXDR.Incident.alerts.alert_id | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex XDR - T1036 - Masquerading](../doc_files/Cortex_XDR_-_T1036_-_Masquerading.png)
