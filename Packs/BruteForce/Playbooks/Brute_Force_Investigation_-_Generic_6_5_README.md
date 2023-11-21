This playbook investigates a "Brute Force" incident by gathering user and IP information, calculating the incident severity based on the gathered information and information received from the user, and performs remediation.

The playbook handles the following use-cases:

* Brute Force IP Detected - A detection of source IPs that are exceeding a high threshold of rejected and/or invalid logins. 
* Brute Force Increase Percentage - A detection of large increase percentages in various brute force statistics over different periods of time.
* Brute Force Potentially Compromised Accounts - A detection of accounts that have shown high amount of failed logins with one successful login.

Used Sub-playbooks:
- IP Enrichment - Generic v2
- Account Enrichment - Generic v2.1
- Calculate Severity - Critical Assets v2
- Isolate Endpoint - Generic v2
- Block Indicators - Generic v3


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Block Indicators - Generic v3
* Account Enrichment - Generic v2.1
* Calculate Severity - Critical Assets v2
* IP Enrichment - Generic v2
* Isolate Endpoint - Generic V2

### Integrations

This playbook does not use any integrations.

### Scripts

* GenerateInvestigationSummaryReport

### Commands

* ad-disable-account
* send-mail
* setIncident
* closeInvestigation
* ad-enable-account
* ad-expire-password

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| username | Username of the user who is suspected of the activity. | incident.username | Required |
| src | Source endpoint that triggered the incident. | incident.src | Required |
| traps_endpoint_id | Traps endpoint ID, used for endpoint isolation. | incident.agentid | Optional |
| logins_count_threshold | The threshold for number of logins, from which the investigation and remediation will start automatically without waiting for the user"s reply. Default is 10. | 10 | Optional |
| severity_threshold | The threshold for the severity value from which an automatic remediation takes place. Specify the severity number \(default is Critical\): 0 - Unknown, 0.5 - Informational. 1 - Low, 2 - Medium, 3 - High, 4 - Critical | 4 | Optional |
| internal_range | A list of internal IP ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: '172.16.0.0/12,10.0.0.0/8,192.168.0.0/16' \(without quotes\). If a list is not provided, will use default list provided in the IsIPInRanges script \(the known IPv4 private address ranges\). |  | Optional |
| critical_users | Critical users, separated by comma. |  | Optional |
| critical_endpoints | Critical endpoints, separated by comma. |  | Optional |
| critical_groups | Critical groups, separated by comma. |  | Optional |
| CustomBlockRule | This input determines whether Palo Alto Networks Panorama or Firewall Custom Block Rules are used.<br/>Specify True to use Custom Block Rules. | True | Optional |
| AutoCommit | This input determines whether Palo Alto Networks Panorama or Firewall Static Address Groups are used.<br/>Specify the Static Address Group name for IP handling. | No | Optional |
| DAG | This input determines whether Palo Alto Networks Panorama or Firewall Dynamic Address Groups are used.<br/>Specify the Dynamic Address Group tag name for IP handling. |  | Optional |
| StaticAddressGroup | This input determines whether Palo Alto Networks Panorama or Firewall Static Address Groups are used.<br/>Specify the Static Address Group name for IP handling. |  | Optional |
| CustomURLCategory | Custom URL Category name. | XSOAR Remediation - Malicious URLs | Optional |
| type | Custom URL category type. Insert "URL List"/ "Category Match". |  | Optional |
| device-group | Device group for the Custom URL Category \(Panorama instances\). |  | Optional |
| categories | The list of categories. Relevant from PAN-OS v9.x. |  | Optional |
| EDLServerIP | This input determines whether Palo Alto Networks Panorama or Firewall External Dynamic Lists are used:<br/>\* The IP address of the web server on which the files are stored.<br/>\* The web server IP address is configured in the integration instance. |  | Optional |
| UserVerification | Possible values: True/False. <br/>Whether to provide user verification for blocking IPs. <br/><br/>False - No prompt will be displayed to the user.<br/>True - The server will ask the user for blocking verification and will display the blocking list. | False | Optional |
| AutoBlockIndicators | Possible values: True/False.  Default: True.<br/>Should the given indicators be automatically blocked, or should the user be given the option to choose?<br/><br/>If set to False - no prompt will appear, and all provided indicators will be blocked automatically.<br/>If set to True - the user will be prompted to select which indicators to block. | True | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Brute Force Investigation - Generic](../doc_files/Brute_Force_Investigation_-_Generic_6_5.png)
