This Playbook is used to handle a Shadow IT incident. A Shadow IT incident occurs when a resource attributed to the organization that is not sanctioned by IT nor protected by the InfoSec team is found.

This playbook handles the incident by helping the analyst to find the owner of the resource based on existing evidence. The playbook also marks the service indicators (IP or FQDN) with a Shadow IT tag. The possible owner and their manager are notified and onboarding of the asset on Prisma Cloud is triggered through a manual process.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Active Directory - Get User Manager Details

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* findIndicators
* appendIndicatorField
* send-mail
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Notify Manager | Notify user's manager | Yes | Optional |
| ShadowITIndicatorTags | Tags to add to indicators to identify potential Shadow IT assets | ShadowIT | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Handle Shadow IT Incident](https://github.com/demisto/content/raw/5bc55ad72806e9b442b10f1cc75c41aee13760d9/Packs/ShadowIT/doc_files/Handle_Shadow_IT_Incident.png)
