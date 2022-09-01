Blocks URLs using Palo Alto Networks Panorama or Firewall through Custom URL Categories.
The playbook checks whether the input URL category already exists, and if the URLs are a part of this category. Otherwise, it will create the category, block the URLs, and commit the configuration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Commit Configuration

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* pan-os-edit-custom-url-category
* pan-os-custom-block-rule
* pan-os-get-custom-url-category
* pan-os-create-custom-url-category

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| URL | The URL to block. | Data | URL | Optional |
| CustomURLCategory | The custom URL category name. | Demisto Remediation - Malicious URLs | - | Optional |
| LogForwarding | The panorama log forwarding object name. | - | - | Optional |
| AutoCommit | Whether to commit the configuration automatically. "Yes" will commit automatically. "No" will commit manually. | No | - | Optional |
| type | The custom URL category type. Insert "URL List"/ "Category Match". | - | - | Optional |
| device-group | The device group for the custom URL category (Panorama instances). | - | - | Optional |
| categories | The list of categories. Relevant from PAN-OS v9.x. | - | - | Optional |
| pre-post | Specify pre-rulebase or post-rulebase. (Panorama instances). | pre-rulebase | - | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS_Block_URL_Custom_URL_Category](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PAN-OS_Block_URL_Custom_URL_Category.png)
