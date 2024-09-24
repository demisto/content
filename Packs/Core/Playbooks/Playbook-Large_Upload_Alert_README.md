The playbook investigates Cortex XDR alerts involving large upload alerts. 
The playbook consists of the following procedures:
- Searches for similar previous alerts that were closed as false positives.
- Enrichment and investigation of the initiator and destination hostname and IP address.
- Enrichment and investigation of the initiator user, process, file, or command if it exists.
- Detection of related indicators and analysis of the relationship between the detected indicators.
- Utilize the detected indicators to conduct threat hunting.
- Blocks detected malicious indicators.
- Endpoint isolation.
This playbook supports the following Cortex XDR alert names:
- Large Upload (Generic)
- Large Upload (SMTP)
- Large Upload (FTP)
- Large Upload (HTTPS)

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Block Indicators - Generic v3
* User Investigation - Generic
* TIM - Indicator Relationships Analysis
* Command-Line Analysis
* Threat Hunting - Generic
* Entity Enrichment - Generic v3
* Endpoint Investigation Plan
* Search and Compare Process Executions - Generic

### Integrations

* CortexCoreIR

### Scripts

* DBotFindSimilarIncidents
* SetAndHandleEmpty
* Set

### Commands

* setAlertStatus
* core-isolate-endpoint
* setAlert
* core-get-cloud-original-alerts

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| InternalIPRanges | A list of IP ranges to check the IP against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). If a list is not provided, will use default list provided in the IsIPInRanges script \(the known IPv4 private address ranges\). | ${lists.PrivateIPs} | Optional |
| FurtherInvestigation | Determines whether an alert should be further investigated if similar previous false positive alerts were found.<br/>Possible values:True/False. Default: False. | False | Required |
| AutoBlockIndicators | Determine whether the given indicators be automatically blocked, or if the user should be given the option to choose.<br/>Possible values:True/False. Default: True.<br/>If set to False - no prompt will appear, and all provided indicators will be blocked automatically.<br/>If set to True - the user will be prompted to select which indicators to block. | True | Required |
| BlockIndicators_UserVerification | Determine whether the blocking of any indicator requires the verification of the user.<br/>Possible values:True/False. Default: False. | False | Required |
| EarlyContainment | Whether early containment should be allowed when the IP address is known to be malicious.<br/>Possible values:True/False. Default: True. | True | Required |
| AutoIsolateEndpoint | Whether to isolate the initiating endpoint automatically if the investigation verdict is malicious.<br/>Possible values:True/False. Default: False. | False | Required |
| Transferred_Data _Threshold | Specify the uploaded data threshold volume \(in MB\) from which large upload alerts should be investigated.<br/>By setting a threshold, you will be able to determine which large upload alerts require investigation.<br/>Default value: 150 \(MB\). | 150 | Required |
| FWApps_Processes_Whitlist | A list of known and authorized FW application IDs and processes used in the organization. | ip,tcp,udp,ssl,syslog,quic,Chrome.exe,Firefox.exe,Opera.exe,Safari.exe,iexplore.exe,msedge.exe,brave.exe | Optional |
| Alert_ID | The Cortex XDR alert ID. | ${alert.id} | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Large Upload Alert](../doc_files/Large_Upload_Alert.png)
