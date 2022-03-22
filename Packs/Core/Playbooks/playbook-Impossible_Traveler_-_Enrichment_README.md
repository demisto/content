This playbook get as an input all of the involved IP addresses and identities from the Impossible Traveler main playbook alert and enrich them based on:
* Geo location
* AD

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Active Directory - Get User Manager Details

### Integrations
This playbook does not use any integrations.

### Scripts
* DeleteContext
* Set
* http
* ParseJSON

### Commands
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
![Impossible Traveler - Enrichment](https://raw.githubusercontent.com/demisto/content/f731e1a3ca654aca1ebe5ff29df935f2390c9099/Packs/Core/doc_files/Impossible_Traveler_-_Enrichment.png)