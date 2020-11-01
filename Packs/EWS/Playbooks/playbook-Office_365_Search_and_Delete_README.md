Runs a compliance search on Office 365 and deletes the results.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* ews-o365-purge-compliance-search-results
* ews-o365-get-compliance-search
* ews-o365-start-compliance-search
* ews-o365-remove-compliance-search

## Playbook Inputs
---

| **Name** | **Description** |  **Required** |
| --- | --- | --- | 
| Query | The compliance search query. |  Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Office_365_Search_and_Delete](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Office_365_Search_and_Delete.png)
