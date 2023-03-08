This is a sub-playbook that simulates an AD Password Reset process, which can be used as a sub-playbook across a number of different playbooks simply by adding it in, and passing the proper inputs in. 

This sub-playbook will output the new password, so it can be provided to the User, or maybe the users manager. 

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* XSOAR Engineer Training

### Scripts

* GeneratePassword

### Commands

* ad-expire-password
* ad-set-new-password

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| username | The samAccountName of the user to reset the password for. |  | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NEW_PASSWORD | The new password generated for the user. | unknown |

## Playbook Image

---

![XSOAR Engineer Training - AD Password Reset  (Sub-Playbook)](../doc_files/XSOAR_Engineer_Training_-_AD_Password_Reset__(Sub-Playbook).png)
