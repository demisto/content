This playbook is one of the sub-playbooks in the containment plan. 
This playbook handles the clearing of users' sessions as a crucial step in the containment action. (currently, the playbook supports only Okta)


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* CompareLists
* Set
* IsIntegrationAvailable

### Commands

* setParentIncidentContext
* okta-get-user
* okta-clear-user-sessions

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ClearUserSessions | Set to 'True' to clear the user active Okta sessions. | True | Optional |
| Username | The username to disable. |  | Optional |
| IAMUserDomain | The Okta IAM users domain. The domain will be appended to the username. e.g. username@IAMUserDomain. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Containment Plan - Clear User Sessions](../doc_files/Containment_Plan_-_Clear_User_Sessions.png)
