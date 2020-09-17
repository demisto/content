Investigates a Cortex XDR incident containing internal port scan alerts. The playbook:
- Syncs data with Cortex XDR.
- Notifies management about a compromised host.
- Escalates the incident in case of lateral movement alert detection.

The playbook is used as a sub- playbook in 'Cortex XDR Incident Handling - v2'

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* IP Enrichment - Internal - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
* IsIPInRanges
* SetAndHandleEmpty
* AssignAnalystToIncident

### Commands
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| WhitelistedPorts | A list of comma\-separated ports that should not be blocked even if used in an attack. |  | Optional |
| BlockAttackerIP | Determines whether attacking IPs should be automatically blocked using firewalls. | False | Optional |
| EmailAddressesToNotify | A list of comma\-separated values of email addresses that should receive a notification about compromised hosts. |  | Optional |
| InternalIPRanges | A list of IP ranges to check the IP against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). If a list is not provided, will use default list provided in the IsIPInRanges script \(the known IPv4 private address ranges\). |  | Optional |
| RoleForEscalation | The name of the Cortex XSOAR role of the users that the incident can be escalated to in case of developments like lateral movement. If this input is left empty, no escalation will take place. |  | Optional |
| OnCall | Set to true to assign only the users that are currently on shift. | false | Optional |
| xdr_alert_id | Unique ID for the XDR alert. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PortScan.BlockPorts | Indicates whether there's a need to block the ports used for exploitation on the scanned host. | unknown |
| PortScan.AttackerIPs | Attacker IPs from the port scan alert. | unknown |
| PortScan.AttackerHostnames | Attacker hostnames from the port scan alert. | unknown |
| PortScan.AttackerUsername | Attacker username from the port scan alert. | unknown |
| PortScan.FileArtifacts | File artifacts from the port scan alert. | unknown |
| PortScan.LateralMovementFirstDatetime | Lateral Movement First Date time from the port scan alert. | unknown |
| PortScan.PortScanFirstDatetime | Port Scan First Date time | unknown |

## Playbook Image
---
![Cortex XDR - Port Scan - Adjusted](https://github.com/demisto/content/raw/3fadebe9e16eb7c9fc28ce3bb600319ec875e3b5/Packs/CortexXDR/doc_files/Cortex_XDR_-_Port_Scan_-_Adjusted.png)