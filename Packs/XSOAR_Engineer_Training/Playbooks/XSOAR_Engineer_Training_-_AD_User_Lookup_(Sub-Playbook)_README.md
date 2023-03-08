This sub-playbook will check to see if the user exists in AD based on the inputed email address.

If the user exists, it will add the user to a key called Exists, if not add them to NotExists.  

These keys are outputs of this sub-playbook which will be returned to the parent.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* XSOAR Engineer Training

### Scripts

* DeleteContext
* Set

### Commands

* ad-get-user

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Users | Array of users email addresses to lookup |  | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Exists | List of users who exist | unknown |
| NotExisted | List of users who don't exist | unknown |

## Playbook Image

---

![XSOAR Engineer Training - AD User Lookup (Sub-Playbook)](../doc_files/XSOAR_Engineer_Training_-_AD_User_Lookup_(Sub-Playbook).png)
