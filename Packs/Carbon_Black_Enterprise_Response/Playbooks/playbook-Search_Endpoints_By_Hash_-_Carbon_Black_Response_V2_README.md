Hunt for malicious indicators using Carbon Black

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* integration-Carbon_Black_Enterprise_Response

### Scripts
This playbook does not use any scripts.

### Commands
* cb-get-processes

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hash | MD5 Hash | File.MD5 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint.Hostname | The device hostname | string |
| Endpoint | The endpoint | unknown |

