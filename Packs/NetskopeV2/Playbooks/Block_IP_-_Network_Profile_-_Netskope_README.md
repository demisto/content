Blocks an IP address, IP range, or CIDR netmask via a Netskope Network Profile (shown as "Network Location" in the Netskope UI). Looks up the profile by name and either appends the value to that existing profile, or - if no profile with that name exists yet - creates a new one with the value as its first entry.

Checks the profile's current values before appending, so re-running this playbook for an already-blocked value is a safe no-op (Netskope's network profile "append" operation has no server-side dedup). Deploys the profile after appending so the change takes effect immediately.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

Netskope - Direct to Zero Trust

### Scripts

This playbook does not use any scripts.

### Commands

* netskopev2-list-network-profiles
* netskopev2-update-network-profile-values
* netskopev2-deploy-network-profiles
* netskopev2-create-network-profile

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ProfileName | Name of the Netskope Network Profile to add the value to. If no profile with this name exists, one is created with the value as its first entry. |  | Required |
| Value | IP address, IP range, or CIDR netmask to add (e.g. "4.145.79.224/27"). |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.
