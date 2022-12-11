This playbook get as an input all of the involved IP addresses and identities from the Impossible Traveler playbook alert, and enriches them based on the following:
* Geo location
* Active Directory
* IP enrichment e.g. VirusTotal, AbuseIPDB, etc.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Account Enrichment - Generic v2.1

### Integrations
* CoreIOCs
* CortexCoreIR

### Scripts
* DeleteContext
* Set
* http
* ParseJSON

### Commands
* ip

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| sourceip | The source IP to iterate over. |  | Optional |
| username | The username to iterate over. |  | Optional |
| domain | The organization domain. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ActiveDirectory.Users.manager | The manager of the user. | unknown |

## Playbook Image
---
![Impossible Traveler - Enrichment](../doc_files/Impossible_Traveler_-_Enrichment.png)