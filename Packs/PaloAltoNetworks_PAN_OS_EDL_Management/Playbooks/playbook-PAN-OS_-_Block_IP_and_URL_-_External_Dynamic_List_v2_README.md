This playbook blocks IP addresses and URLs using Palo Alto Networks Panorama or Firewall External Dynamic Lists.
It checks if the EDL configuration is in place with the 'PAN-OS EDL Setup' sub-playbook (otherwise the list will be configured), and adds the inputted IPs and URLs to the relevant lists.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS EDL Setup v3

### Integrations
* Palo Alto Networks PAN-OS
* Palo Alto Networks PAN-OS EDL Management

### Scripts
This playbook does not use any scripts.

### Commands
* panorama-refresh-edl
* pan-os-edl-update
* panorama

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| IPListName | IP address list from the instance context with which to override the remote file. Cannot contain spaces |  |  | Optional |
| IP | IP address to block | Address | IP | Optional |
| URL | URL to block. | Data | URL | Optional |
| URLListName | URL list from the instance context with which to override the remote file. Cannot contain spaces |  |  | Optional |
| LogForwarding | Log Forwarding object name. |  |  | Optional |
| EDLManagementServerURL  | The EDL Management server full URL address.

\* http://hostname/pathtolist/
\* https://hostname/pathtolist/ |  |  | Optional |
| AutoCommit | This input establishes whether to commit the configuration automatically.
Yes \- Commit automatically.
No \- Commit manually. | False |  | Optional |
| url-pre-post-rulebase | Either pre\-rulebase or post\-rulebase,  according to the rule structure. | pre-rulebase |  | Optional |
| ip-pre-post-rulebase | Either pre\-rulebase or post\-rulebase,  according to the rule structure. | pre-rulebase |  | Optional |
| url-rule-position | The position of the rule in the ruleset. Valid values are:
  \* top
  \* bottom
  \* before
  \* after | top |  | Optional |
| ip-rule-position | The position of the rule in the ruleset. Valid values are:
  \* top
  \* bottom
  \* before
  \* after | top |  | Optional |
| inbound-or-outbound-rule | Determines if the rule is inbound or outbound. | outbound |  | Optional |
| device-group | The device group to work on. Exists only in panorama\! |  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
## Playbook Image
---
![PAN-OS_Block_IP_and_URL_External_Dynamic_List_v2](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/PAN-OS_-_Block_IP_and_URL_-_External_Dynamic_List_v2.png)
