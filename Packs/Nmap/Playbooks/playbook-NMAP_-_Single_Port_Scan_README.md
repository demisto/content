Subplaybook that conducts a single port NMAP scan and returns results to the parent playbook.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
* nmap-scan

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RemoteIP | Remote IP address in incident/alert |  | Required |
| RemotePort | Remote port number in incident/alert |  | Required |
| NMAPOptions | options to be used for nmap scan \(we do "-p&amp;lt;RemotePort&amp;gt;" by default and recommend using "-Pn" to skip ping check\) |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ScanResult | What was the result of the scan \(if done\) | unknown |
| ScanDone | Was a scan actually performed \(based on subtypes\) | unknown |
| NMAP | NMAP scan data | unknown |

## Playbook Image
---
![NMAP - Single Port Scan](../doc_files/NMAP_-_Single_Port_Scan.png)