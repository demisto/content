This playbook handles external and internal scanning alerts.

**Attacker's Goals:**

Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system.

**Investigative Actions:**

Investigate the scanner IP address using:

* IP enrichment:
* NGFW Internal Scan playbook
* Endpoint Investigation Plan playbook
* Entity enrichment

**Response Actions**

The playbook's response actions are based on the initial data provided within the alert. In that phase, the playbook will execute:

* Automatically block IP address
* Report IP address to AbuseIPDB (If configured as true in the playbook inputs)

When the playbook proceeds, it checks for additional activity using the Endpoint Investigation Plan playbook, and another phase, which includes the Containment Plan playbook, is executed.
This phase will execute the following containment actions:

* Auto endpoint isolation
* Manual block indicators
* Manual file quarantine
* Manual disable user

**External resources:**

[Mitre technique T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)

[Port Scan](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-analytics-alert-reference/cortex-xdr-analytics-alert-reference/port-scan.html)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Handle False Positive Alerts
* NGFW Internal Scan
* Containment Plan
* Recovery Plan
* Block IP - Generic v3
* Endpoint Investigation Plan

### Integrations
* CortexCoreIR
* CoreIOCs

### Scripts
* SearchIncidentsV2

### Commands
* send-mail
* ip
* abuseipdb-report-ip
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
| AutoContainment | Whether to execute automatically or manually the containment plan tasks:<br/>\* Block indicators<br/>\* Quarantine file<br/>\* Disable user | false | Optional |
| HostAutoContainment | Whether to execute endpoint isolation automatically or manually. | false | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![NGFW Scan](https://raw.githubusercontent.com/demisto/content/b9b3e36e6893e95be5de09876efce94acec09da8/Packs/Core/doc_files/NGFW_Scan.png)