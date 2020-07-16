Pulls IP addresses from the detail value of an incident and check if that asset has been scanned within the past 60 days. If not then it will then prompt the user to perform a scan on the asset.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Print

### Commands
* frontline-scan-asset
* frontline-get-assets

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Digital_Defense_FrontlineVM_Scan_Asset_Not_Recently_Scanned](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Digital_Defense_FrontlineVM_Scan_Asset_Not_Recently_Scanned.png)
