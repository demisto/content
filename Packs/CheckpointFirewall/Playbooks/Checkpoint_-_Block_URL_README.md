This playbook blocks URLs using Check Point Firewall through Custom URL Categories.
The playbook checks whether the input URL category already exists, and if the URLs are a part of this category. If not, it creates the category, blocks the URLs, and publishes the configuration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Checkpoint - Publish&Install configuration

### Integrations
* CheckPointFirewallV2

### Scripts
* Print

### Commands
* checkpoint-application-site-category-get
* checkpoint-application-site-update
* checkpoint-logout
* checkpoint-login-and-get-session-id
* checkpoint-application-site-category-add
* checkpoint-application-site-add

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| install_policy | Whether the playbook should continue install policy process for Check Point Firewall. | True | Required |
| URL | An array of URLs to block.<br/>Example: example.com,example.org |  | Required |
| policy_package | The name of the policy package to be installed. | Standard | Required |
| URL_application_site_category | URL category object name.  The category to add URL to. | Suspicious | Required |
| checkpoint_error_handling | If one of the actions for the Block IP playbook fails due to issues on the Check Point Firewall, this input determines whether the playbook continues or stops for manual review. If the playbook continues, the session ID logs out and all Check Point changes are discarded.<br/>Values are "Continue" or "Stop".<br/>The default value is "Stop". | Stop | Required |
| block_URL_error_handling | If one of the actions for Block URL playbook fails due to issues on the Check Point Firewall, this input determines whether the playbook continues or stops for manual review. If the playbook continues, session ID logs out and all Check Point changes are discarded.<br/>Values can be "Continue" or "Stop".<br/>The default value will be "Stop". | Stop | Required |
| application_site_name | Define the Application Site Name. Default: Bad_URLs. | Bad_URLs | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Checkpoint - Block URL](../doc_files/Checkpoint_-_Block_URL.png)
