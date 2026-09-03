Meant to run periodically (attach it to an hourly scheduled Job in XSOAR) to keep a Netskope Destination Profile in sync with indicators already ingested into XSOAR's own Threat Intel Management.

Looks up the destination profile by name, then:
- if the profile exists: searches XSOAR indicators of the selected types (Domain/URL/IP/CIDR), skips any value already present in the profile, appends the rest in batches, and deploys the change.
- if no profile with that name exists yet: searches the same way, and if any values were found, creates a new profile with the chosen match type and those values in one call.

CIDR indicator values are prefixed with `CIDR:` to match the format Netskope's destination profile Definition field expects. Every run only appends values not already present in the profile, so re-running this on a schedule with a mostly-unchanged indicator set is a safe, idempotent no-op. Ends with a Close Investigation task so a recurring Job isn't blocked from firing again.

Make sure only one Netskope integration instance is enabled at a time - if two are enabled, XSOAR dispatches every command to both, silently doubling every append.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

Netskope - Direct to Zero Trust

### Scripts

* NetskopeIndicatorSync
* SetMultipleValues

### Commands

* netskopev2-list-destination-profiles
* netskopev2-create-destination-profile
* closeInvestigation

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ProfileName | Name of the Netskope Destination Profile to sync indicators into. | Test02 | Optional |
| MatchType | Match type to use only if ProfileName doesn't exist yet and a new profile needs to be created. One of "sensitive", "insensitive", or "regex". | regex | Optional |
| IndicatorTypes | Comma-separated list of XSOAR indicator types to pull and sync into the profile. One or more of Domain, URL, IP, CIDR. | Domain,URL,IP,CIDR | Optional |
| Tags | Optional comma-separated indicator tags to further restrict which indicators are pulled. |  | Optional |
| SkipTags | Optional comma-separated indicator tags to exclude. |  | Optional |
| MaxIndicators | Maximum number of indicators to pull from XSOAR per run (default 500 if left empty). |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.
