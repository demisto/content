Triggers a backup task on each firewall appliance and pulls the resulting file into the War Room via SCP.

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

![Checkpoint_Firewall_Configuration_Backup](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Checkpoint_Firewall_Configuration_Backup.png)
