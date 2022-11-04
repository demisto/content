Sub-playbook that performs an Nmap scan and compares the results against a regular expression for a match.  This could be used to look for OpenSSH versions or other OS information found in the banner.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
NMAP

### Scripts
Set

### Commands
nmap-scan

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RemoteIP | Remote IP address in an incident/alert. |  | Required |
| RemotePort | Remote port number in incident/alert |  | Required |
| Regex | Regular expression to compare against the banner for a match. |  | Required |
| NMAPOptions | Options to be used for the Nmap scan. \(We do "--script=banner -p\<RemotePort\>" by default and recommend using "-Pn" to skip the ping check\.) |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ScanResult | The results of the scan \(if done\) | unknown |
| ScanDone | Whether a scan was actually performed \(based on subtypes\). | unknown |
| NMAP.Scan | Nmap scan data. | unknown |

## Playbook Image
---
![NMAP - Banner Check](../doc_files/NMAP_-_Banner_Check.png)
