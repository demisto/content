Deprecated. Use the Hunt Extracted Hashes V2 playbook instead. This playbook extracts IOCs from the incident details and attached\ \ files using regular expressions and then hunts for hashes on endpoints in the organization\ \ using available tools.\nThe playbook supports multiple types of attachments. For\ \ the full supported attachments list, refer to \"Extract Indicators From\ \ File - Generic v2\".

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Search Endpoints By Hash - Generic
* Extract Indicators From File - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* extractIndicators

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | The file from which to extract indicators. | File.None | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Hunt Extracted Hashes](Insert the link to your image here)