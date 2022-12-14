This playbook blocks malicious URLs using all integrations that are enabled.

Supported integrations for this playbook:
* Palo Alto Networks PAN-OS
* Zscaler
* Sophos
* Forcepoint
* Checkpoint
* Netcraft

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS - Block URL - Custom URL Category
* Sophos Firewall - Block URL
* Checkpoint - Block URL

### Integrations
* Netcraft
* Forcepoint
* Zscaler

### Scripts
* IsIntegrationAvailable
* SetAndHandleEmpty

### Commands
* fp-add-address-to-category
* zscaler-blacklist-url
* setIndicator
* netcraft-report-attack

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | Array of malicious URLs to block. |  | Optional |
| LogForwarding | Log Forwarding object name. |  | Optional |
| AutoCommit | This input establishes whether to commit the configuration automatically.<br/>Yes - Commit automatically.<br/>No - Commit manually. | No | Optional |
| CustomURLCategory | Custom URL Category name. | XSOAR Remediation - Malicious URLs | Optional |
| type | Custom URL category type. Insert "URL List"/ "Category Match". |  | Optional |
| categories | The list of categories. Relevant from PAN-OS v9.x. |  | Optional |
| UserVerification | Possible values:True/False. Default:True.<br/>Specify if User Verification is Requrired | True | Optional |
| EDLServerIP | EDL Server IP Address |  | Optional |
| device-group | Device group for the Custom URL Category \(Panorama instances\). |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Block URL - Generic v2](../doc_files/Block_URL_-_Generic_v2.png)