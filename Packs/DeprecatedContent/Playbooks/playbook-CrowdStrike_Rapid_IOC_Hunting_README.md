DEPRECATED. Use "CrowdStrike Rapid IOC Hunting v2" playbook instead. Hunts for endpoint activity involving hash and domain IOCs, using Crowdstrike Falcon Host.This playbook also use `AnalystEmail` label to determine where to send an email alert if something is found.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
* FalconHost

## Scripts
* Exists
* SendEmail

## Commands
* cs-device-search
* cs-device-ran-on

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![CrowdStrike_Rapid_IOC_Hunting](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/CrowdStrike_Rapid_IOC_Hunting.png)
