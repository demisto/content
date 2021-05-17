This will query `Frontline.Cloud`'s active view for any critical level vulnerabilities found to be older than 90 days.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Digital Defense FrontlineVM

### Scripts
* Print

### Commands
* frontline-get-vulns

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- | 
| Days Older Than | The inputed number of days from now in which to search if vulnerabilities exist. |Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Digital_Defense_FrontlineVM_Old_Vulnerabilities_Found](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Digital_Defense_FrontlineVM_Old_Vulnerabilities_Found.png)
