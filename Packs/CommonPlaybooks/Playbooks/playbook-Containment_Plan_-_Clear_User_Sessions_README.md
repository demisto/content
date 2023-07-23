This playbook is one of the sub-playbooks in the containment plan. 
The playbook executes actions to clear the users' sessions, which is a crucial step in the containment process. (currently, the playbook supports only Okta)


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* IsIntegrationAvailable
* Set

### Commands

* setParentIncidentContext
* okta-clear-user-sessions
* okta-get-user

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ClearUserSessions | Set to 'True' to clear the user active Okta sessions. | True | Optional |
| Username | The username to disable. |  | Optional |
| IAMUserDomain | The Okta IAM users domain. The domain will be appended to the username. E.g., username@IAMUserDomain. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Containment Plan - Clear User Sessions](../doc_files/Containment_Plan_-_Clear_User_Sessions.png)
