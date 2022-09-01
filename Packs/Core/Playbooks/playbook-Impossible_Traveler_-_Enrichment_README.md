This playbook get as an input all of the involved IP addresses and identities from the Impossible Traveler playbook alert and enriches them based on the following:
* Geo location
* Active Directory
* Verdict enrichment e.g. VirusTotal, AbuseIPDB, etc.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Active Directory - Get User Manager Details

### Integrations
* CoreIOCs
* CortexCoreIR

### Scripts
* http
* Set
* DeleteContext
* ParseJSON

### Commands
* ip
* ad-get-user

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| sourceip | The source IP to iterate over |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Impossible Traveler - Enrichment](https://raw.githubusercontent.com/demisto/content/b391822313ec453de36439890a0137d4dd126e8e/Packs/Core/doc_files/Impossible_Traveler_-_Enrichment.png)
