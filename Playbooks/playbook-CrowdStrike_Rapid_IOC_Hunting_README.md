Hunts for endpoint activity involving hash and domain IOCs, using Crowdstrike Falcon Host.This playbook also use `AnalystEmail` label to determine where to send an email alert if something is found.

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

![CrowdStrike_Rapid_IOC_Hunting](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/CrowdStrike_Rapid_IOC_Hunting.png)
