Blocks a domain via a Netskope Destination Profile: looks up the profile by name and either
appends the domain to that existing profile or, if no profile with that name exists yet,
prompts the analyst to pick a match type and creates a new one with the domain as its first
value.

The match type prompt is a single-select with exactly three choices - sensitive (Exact - Case
Sensitive), insensitive (Exact - Case Insensitive), or regex (RegEx), mirroring the "Match Type"
choice in the Netskope UI's destination profile editor - so there's no risk of a typo or wrong
casing (e.g. "Regex" instead of "regex") getting rejected by the create command. It's only asked
when a new profile actually needs to be created - it's skipped entirely when appending to a
profile that already exists (its match type was already fixed at creation).

Profile names are unique in Netskope, so an exact-match lookup (name eq "<ProfileName>") returns
at most one profile - no manual ID lookup needed, just the profile's display name.

IMPORTANT: unlike the URL List and File Hash List "append" behavior, Netskope's destination
profile values "append" operation has no server-side dedup - calling it twice with the same
domain (e.g. re-running this playbook for a domain that's already blocked) adds it twice. This
playbook checks the profile's current values (fetched by the name lookup) first and only
appends when the domain isn't already present, so re-running it for an already-blocked domain
is a safe no-op. Also make sure only one Netskope integration instance is enabled at a time - if
two are enabled, Cortex XSOAR dispatches the command to both, causing the same double-add.

Unlike URL Lists, Destination Profile value changes are staged (pending) until deployed - this
playbook appends the value and then immediately deploys that one profile so the change takes
effect right away. Creating a profile with default settings (interactive=false) applies
immediately - no separate deploy step is needed for that path, unlike the
append-to-existing-profile path.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* NetskopeV2

### Scripts

This playbook does not use any scripts.

### Commands

* netskopev2-create-destination-profile
* netskopev2-deploy-destination-profiles
* netskopev2-list-destination-profiles
* netskopev2-update-destination-profile-values

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain | The domain to block. |  | Required |
| ProfileName | Name of the Netskope Destination Profile to add the domain to. The playbook looks up the profile by this name \(netskopev2-list-destination-profiles, filter name eq "&lt;ProfileName&gt;"\). If no profile with this name exists, you'll be prompted to pick a match type \(single-select - sensitive, insensitive, or regex\) and one is created with the domain as its first value. |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Block Domain - Destination Profile - Netskope](../doc_files/Block_Domain_-_Destination_Profile_-_Netskope.png)
