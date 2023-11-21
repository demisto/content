Extract indicators from a text-based file.
Indicators that can be extracted:
* IP
* Domain
* URL
* File Hash
* Email Address

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Extract Indicators From File - Generic
* Extract Indicators From File - Generic v2

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | The War-Room entryID of the file to read. |
| maxFileSize | Maximal file size to load, in bytes. Default is 1000000 \(1MB\). |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain.Name | Extracted domains | string |
| Account.Email.Address | Extracted emails | string |
| File.MD5 | Extracted MD5 | string |
| File.SHA1 | Extracted SHA1 | string |
| File.SHA256 | Extracted SHA256 | string |
| IP.Address | Extracted IPs | string |
| URL.Data | Extracted URLs | string |
