Subplaybook the performs and NMAP scan and compares against regular expression for match.  This could be used to look for OpenSSH versions or other OS information found from the banner.

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
| Regex | regular expression to compare against banner for match |  | Required |
| NMAPOptions | options to be used for nmap scan \(we do "--script=banner -p&amp;lt;RemotePort&amp;gt;" by default and recommend using "-Pn" to skip ping check\) |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ScanResult | What was the result of the scan \(if done\) | unknown |
| ScanDone | Was a scan actually performed \(based on subtypes\) | unknown |
| NMAP.Scan | NMAP scan data | unknown |

## Playbook Image
---
![NMAP - Banner Check](../doc_files/NMAP_-_Banner_Check.png)