Provides a basic response to phishing incidents. Playbook features:
- Calculates reputation for all indicators
- Extracts indicators from email attachments
- Calculates severity for the incident based on indicator reputation
- Updates reporting user about investigation status
- Allows manual remediation of the incident

The differences between this playbook and the older version are:
  1) This playbook uses incident fields instead of labels
  2) This playbook uses the "Process Email - Core v2" playbook 
## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Process Email - Core v2
* Extract Indicators From File - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* setIncident
* send-mail
* rasterize
* closeInvestigation
* rasterize-email

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| GetURLScreenshots | Whether the user wants the Rasterize integration to produce images of URLs that are involved in the incident. If "True", screenshots will be taken. | True | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Phishing - Core v2](../doc_files/Phishing_-_Core_v2.png)