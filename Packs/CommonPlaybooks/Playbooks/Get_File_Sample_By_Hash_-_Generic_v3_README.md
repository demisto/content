This playbook returns a file sample correlating to a hash in the war-room using the following sub-playbooks:
- Get binary file by MD5 hash from Carbon Black telemetry data. - VMware Carbon Black EDR v2.
- Get the threat (file) attached to a specific SHA256 hash- Cylance Protect v2.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get binary file from Carbon Black by MD5 hash
* Get File Sample By Hash - Cylance Protect v2

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
| MD5 | Get file sample from MD5 input |  | Optional |
| SHA256 | Get file sample from SHA256 input |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | File sample object | unknown |

## Playbook Image
---
![Get File Sample By Hash - Generic v3](Insert the link to your image here)