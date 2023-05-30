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

When the playbook executes, it checks for additional activity using the Endpoint Investigation Plan playbook, and another phase, which includes the Containment Plan playbook, is executed.
This phase will execute the following containment actions:

* Auto endpoint isolation
* Manual block indicators
* Manual file quarantine
* Manual disable user

**External resources:**

[Mitre technique T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)

[Port Scan](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Analytics-Alert-Reference/Port-Scan)

## How to use this playbook

### Create a new playbook trigger

1. Click on the **Incident Response** icon on the left menu.
2. Under **Automation** click on **Incident Configuration**.
3. Select **Playbook Triggers** on the left panel.
4. Click on **New Trigger**.
5. Choose a trigger name e.g. Scanner Response.
6. Under **Playbook To Run**, select NGFW Scan.
7. Add trigger description - optional.
8. Create a filter for the playbook trigger.
    1. Click on 'select field'.
    2. Choose 'Alert name'.
    3. Fill the value with 'Scan' and keep the 'contains' condition.
    4. Click **Create**

* **Note** that the playbook triggers are executed according to its order. Consider changing the trigger position for the execution order as intended. If not, other trigger may override the new trigger.

Click **Save**.

### Playbook inputs

Before executing the playbook, please review the inputs and change them default values if needed.

Important playbook inputs you should pay attention to:

1. *blockKnownScanner*: Whether a benign IP address that has been previously seen in more than 5 alerts should be blocked.

2. *reportIPAddress*: (Relevant for an enabled AbuseIPDB integration) Whether to report the IP address to AbuseIPDB.

3. *AutoContainment*: Whether to execute the following response actions automatically or manually:
    1. Block indicators
    2. Quarantine file
    3. Disable user

4. *HostAutoContainment*: Whether to execute Endpoint Isolation automatically or manually.

### Playbook remediation plan

In this playbook the remediation plan happens in two different phases:

1. At an early stage of the playbook execution, if the IP address verdict is malicious, the IP is blocked using the Block IP - Generic v3 playbook.
2. At a later stage, the playbook executes the **Endpoint Investigation Plan**, which searches for additional activity involving the scanner IP address. In this phase, based on the results of the Endpoint Investigation Plan playbook, the SOC is notified, and the Containment Plan playbook will be executed.

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
| scannerIP | The IP address of the scanner. | alert.localip | Optional |
| blockKnownScanner | Whether to block the IP address based on previously seen scanning alerts. | true | Optional |
| AutoCloseAlert | Whether to close the alert automatically or manually, after an analyst's review. | false | Optional |
| AutoRecovery | Whether to execute the Recovery playbook. | false | Optional |
| SOCEmailAddress | The email address of the SOC. |  | Optional |
| reportIPAddress | Whether to report the IP address to AbuseIPDB. | false | Optional |
| AutoContainment | Whether to execute automatically or manually the containment plan tasks:<br/>\* Block indicators<br/>\* Quarantine file<br/>\* Disable user | false | Optional |
| HostAutoContainment | Whether to execute endpoint isolation automatically or manually. | false | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![NGFW Scan](https://raw.githubusercontent.com/demisto/content/b9b3e36e6893e95be5de09876efce94acec09da8/Packs/Core/doc_files/NGFW_Scan.png)
