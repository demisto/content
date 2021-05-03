Deprecated. Use "Get File Sample By Hash - Generic v2" playbook instead. Returns to the war-room a file sample correlating from a hash using one or more products

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get File Sample By Hash - Carbon Black Enterprise Response
* Get File Sample By Hash - Cylance Protect

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | Get file sample from MD5 input | File.MD5 | Optional |
| SHA256 | Get file sample from SHA256 input | File.SHA256 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | File sample object | unknown |

## Playbook Image
---
![Get File Sample By Hash - Generic](Insert the link to your image here)