Uses Demisto D2 agent to scan a host using Intezer scanner.

Input:
* Hostname (default: ${Endpoint.Hostname})
* OS (default: windows)
* Credentials (default: Admin)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Intezer v2

### Scripts
* IntezerScanHost
* AreValuesEqual
* IncidentAddSystem
* Exists

### Commands
* intezer-get-analysis-result

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| Host | Deploys Demist D2 agent on the target Host. | 10.254.7.24 | Required |
| OS | The default OS type of target host. | windows | Optional |
| INTEZER_API_KEY | The Intezer api-key | - | Required |
| Credentials | The name of the credential set. Credentials are located in Demisto: Settings > Integrations > Credentials. | Admin | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
![Intezer_scan_host](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Intezer_scan_host.png)
