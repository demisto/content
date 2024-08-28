This playbook terminates user SSO sessions so that upon the next login attempt following the unlocking of the account, authentication is required.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SafeNetTrustedAccess

### Scripts
* IsIntegrationAvailable
* Sleep
* PrintErrorEntry

### Commands
* setIncident
* sta-delete-user-sessions
* sta-get-user-sessions
* closeInvestigation
* sta-validate-tenant
* sta-get-user-info

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| UserName | Username of the user. | ${incident.safenettrustedaccessusername} | Required |
| InstanceName | Name of the SafeNet Trusted Access integration instance. | ${incident.safenettrustedaccessinstancename} | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![SafeNet Trusted Access - Terminate User SSO Sessions](../doc_files/SafeNet_Trusted_Access_-_Terminate_User_SSO_Sessions.png)