Deprecated. We recommend using extractIndicators command instead.
Extract indicators from input data.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* ExtractURL
* ExtractHash
* ExtractEmail
* ExtractIP
* ExtractDomain

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incident |  | ${incident} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.MD5 | Extracted MD5 | string |
| File.SHA1 | Extracted SHA1 | string |
| File.SHA256 | Extracted SHA256 | string |
| URL.Data | Extracted URLs | string |
| IP.Address | Extracted IPs | string |
| Domain.Name | Extracted domains | string |
| Account.Email.Address | Extracted emails | string |

## Playbook Image
---
![Extract Indicators - Generic](Insert the link to your image here)