Troubleshoot a problem with either an integration's configuration or with running a command.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* PrintErrorEntry
* Print
* TroubleshootTestInstance
* TroubleshootGetInstanceParameters
* TroubleshootAggregateResults
* ZipFile
* TroubleshootIsDockerImageExists
* ReadFile
* TroubleshootExecuteCommand
* TroubleshootGetCommandandArgs

### Commands

* core-api-download
* core-api-get

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| instancename | The name of the instance to check. | incident.instancename | Required |
| troubleshoottype | The troubleshoot type. | incident.troubleshoottype | Required |
| commandline | The full command to run, for example, "\!vt-comments-get resource=www.example.com" | incident.commandline | Optional |
| insecure | Whether to run with changing the insecure flag. | incident.runwithinsecure | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.