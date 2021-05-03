Deprecated. Use "PAN-OS - Block IP and URL - External Dynamic List v2" playbook instead. This playbook blocks IP addresses and URLs using Palo Alto Networks Panorama or Firewall External Dynamic Lists.
It checks if the EDL configuration is in place with the 'PAN-OS EDL Setup' sub-playbook (otherwise the list will be configured), and adds the input IPs and URLs to the relevant lists.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS EDL Setup v2

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* pan-os-edl-update
* panorama
* panorama-refresh-edl

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IPListName | IP address list from the instance context with which to override the remote file. | Demisto Remediation - IP EDL | Optional |
| IP | IP address to block | IP.Address | Optional |
| URL | URL to block. | URL.Data | Optional |
| URLListName | URL list from the instance context with which to override the remote file. | Demisto Remediation - URL EDL | Optional |
| LogForwarding | Log Forwarding object name. |  | Optional |
| EDLServerIP | EDL server IP address. |  | Optional |
| AutoCommit | This input establishes whether to commit the configuration automatically.<br/>Yes - Commit automatically.<br/>No - Commit manually. | No | Optional |
| url-pre-post-rulebase | Either pre-rulebase or post-rulebase,  according to the rule structure. | pre-rulebase | Optional |
| ip-pre-post-rulebase | Either pre-rulebase or post-rulebase,  according to the rule structure. | pre-rulebase | Optional |
| url-rule-position | The position of the rule in the ruleset. Valid values are:<br/>  \* top<br/>  \* bottom<br/>  \* before<br/>  \* after | top | Optional |
| ip-rule-position | The position of the rule in the ruleset. Valid values are:<br/>  \* top<br/>  \* bottom<br/>  \* before<br/>  \* after | top | Optional |
| inbound-or-outbound-rule | Determines if the rule is inbound or outbound. | outbound | Optional |
| device-group | The device group to work on. Exists only in panorama\! |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS - Block IP and URL - External Dynamic List](Insert the link to your image here)