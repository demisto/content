This playbook enforces the WildFire Best Practices Profile as defined by Palo Alto Networks BPA.
The playbook performs the following tasks:
- Check for WildFire license (If license is not activated, the playbook refers users to their Palo Alto Networks account manager for further instructions).
- Get the existing profile information.
- Get the best practices profile information.
- Check if the best practices profile set by Cortex XSOAR is enforced. (If not, the playbook allows the user to compare the existing profile with the best practices and decide on the action to take).
- Create best practices profile.
- Apply profile to policy rules on PAN-OS firewall or Panorama.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS - Apply Security Profile to Policy Rule
* PAN-OS Commit Configuration
* Palo Alto Networks BPA - Submit Scan

### Integrations
This playbook does not use any integrations.

### Scripts
* SetAndHandleEmpty
* DeleteContext
* ExportToCSV

### Commands
* pan-os-get-wildfire-best-practice
* pan-os-enforce-wildfire-best-practice
* pan-os-create-wildfire-best-practice-profile
* pan-os-get-licenses
* setIncident
* pan-os-get-security-profiles

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| template | Template name to enforce WildFire best practices profile. |  | Optional |
| device-group | The device group to work on. Exists only in panorama\! |  | Optional |
| tag | Tag for which to filter the results. |  | Optional |
| pre-post-rulebase | Determines whether the rule is a pre-rulebase or post-rulebase rule, according to the rule structure. Exists only in panorama\! |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS - Enforce WildFire Best Practices Profile](../doc_files/PAN-OS_-_Enforce_WildFire_Best_Practices_Profile.png)