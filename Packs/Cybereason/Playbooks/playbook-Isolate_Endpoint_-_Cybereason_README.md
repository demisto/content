This playbook isolates a machine based on the hostname provided.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
Cybereason

### Scripts
This playbook does not use any scripts.

### Commands
* cybereason-is-probe-connected
* cybereason-isolate-machine

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | The hostname of the endpoint to isolate using Cybereason. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Cybereason.Machine | Machine name. | unknown |
| Cybereason.IsIsolated | Is the machine isolated. | unknown |
| Endpoint.Hostname | Machine name. | unknown |

## Playbook Image
---
![Isolate Endpoint - Cybereason](../doc_files/Isolate_Endpoint_-_Cybereason.png)
