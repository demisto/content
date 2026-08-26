Blocks a domain via a Netskope Destination Profile: looks up the profile by name and either appends the domain to that existing profile, or - if no profile with that name exists yet - prompts for a match type and creates a new one with the domain as its first value.

Checks the profile's current values before appending, so re-running this playbook for an already-blocked domain is a safe no-op (Netskope's destination profile "append" operation has no server-side dedup). Deploys the profile after appending so the change takes effect immediately.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

Netskope - Direct to Zero Trust

### Scripts

This playbook does not use any scripts.

### Commands

* netskopev2-list-destination-profiles
* netskopev2-update-destination-profile-values
* netskopev2-deploy-destination-profiles
* netskopev2-create-destination-profile

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain | The domain to block. |  | Required |
| ProfileName | Name of the Netskope Destination Profile to add the domain to. If no profile with this name exists, you'll be prompted to pick a match type (sensitive, insensitive, or regex) and one is created with the domain as its first value. |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.
