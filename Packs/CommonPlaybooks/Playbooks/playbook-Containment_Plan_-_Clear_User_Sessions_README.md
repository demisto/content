## Containment Plan - Clear User Sessions

This playbook is a sub-playbook within the containment plan playbook.
The playbook clears the users' sessions using Okta integration. (currently, the playbook supports only Okta)

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* Set
* IsIntegrationAvailable

### Commands

* okta-get-user
* okta-clear-user-sessions
* setParentIncidentContext

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
