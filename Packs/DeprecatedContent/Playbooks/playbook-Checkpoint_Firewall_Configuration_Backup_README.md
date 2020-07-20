DEPRECATED. Triggers a backup task on each firewall appliance and pulls the resulting file into the War Room via SCP.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
This playbook does not use any integrations.

## Scripts
* CPShowBackupStatus
* CPCreateBackup
* SCPPullFiles
* SendEmail
* CloseInvestigation
* UtilAnyResults
* SNOpenTicket

## Commands
This playbook does not use any commands.

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Checkpoint_Firewall_Configuration_Backup](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Checkpoint_Firewall_Configuration_Backup.png)
