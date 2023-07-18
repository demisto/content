This playbook is used to add an Anti-Spyware security profile to a security rule in PAN-OS in a safe manner: it provides granular control over the behavior for cases where a rule already has an Anti-Spyware profile attached, or has a security profile group configured to it with/without an Anti-Spyware profile.
The playbook outputs the Anti-Spyware profile configured for the rule at the time the playbook finished. This could be the previous profile if it was not overwritten, or it could be a new one that it was overwritten with or has just been added.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Panorama

### Scripts

* SetAndHandleEmpty

### Commands

* pan-os-create-anti-spyware-best-practice-profile
* pan-os-list-rules
* pan-os-get-security-profiles
* pan-os-apply-security-profile

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RuleName | The name of the rule to which the Security Profile should be added. |  | Required |
| SecurityProfileName | The name of the Security Profile that should be added to the rule. If it doesn't exit, one will be created with the name specified here. |  | Required |
| OverwriteProfileIfExists | Whether to overwrite an existing Anti-Spyware Security Profile.<br/>If an Anti-Spyware Security Profile is configured to the rule through a group of profiles and not a single profile, setting this input's value to True will overwrite the existing profile within the group instead of applying the profile and overwriting the whole group.<br/><br/>Possible values are: True to overwrite, False to keep existing. | False | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AntiSpywareProfileNameApplied | The name of the Anti-Spyware Security Profile that is applied to the rule. The value could be the name of the rule that was added, overwritten with, or left untouched - for the specified rule. | unknown |

## Playbook Image

---

![PAN-OS - Add Anti-Spyware Security Profile To Rule](../doc_files/PAN-OS_-_Add_Anti-Spyware_Security_Profile_To_Rule.png)
