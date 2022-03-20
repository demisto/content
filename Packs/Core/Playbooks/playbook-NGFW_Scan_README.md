This playbook handles external and internal scanning alerts.

**Attacker's Goals:**

Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system.

**Investigative Actions:**

Investigate the scanner IP address using:

* IP enrichment:
* NGFW Internal Scan playbook
* Endpoint Investigation Plan playbook
* Entity enrichment

**Response Actions:**

* Block IP - Generic v3
* Report IP to AbuseIPDB
* Endpoint isolation

**External resources:**

[Mitre technique T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)

[Port Scan](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-analytics-alert-reference/cortex-xdr-analytics-alert-reference/port-scan.html)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Containment Plan
* Block IP - Generic v3
* Recovery Plan
* Handle False Positive Alerts
* Endpoint Investigation Plan
* NGFW Internal Scan

### Integrations
* CortexCoreIR
* CoreIOCs

### Scripts
* SearchIncidentsV2

### Commands
* abuseipdb-report-ip
* ip
* send-mail
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| scannerIP | The scanner IP address. | alert.hostip | Optional |
| blockKnownScanner | Whether to block the IP address based on previously seen scanning alerts. | true | Optional |
| AutoCloseAlert | Whether to close the alert automatically or manually after an analyst's review. | false | Optional |
| AutoRecovery | Whether to execute the Recovery playbook. | false | Optional |
| SOCEmailAddress | The SOC email address. |  | Optional |
| reportIPAddress | Whether to report the IP address to AbuseIPDB or not. | false | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![NGFW Scan](Insert the link to your image here)