Synchronizes bounded Cortex XSOAR Threat Intel indicators to a Netskope Destination Profile.
The profile name is required. Match type and indicator types have editable playbook defaults,
and each input is validated independently before any Netskope command runs.

Existing profiles are updated in batches of at most 10 values. New profiles are created as
pending changes. Set Deploy to true to apply pending changes; it defaults to false so scheduled
jobs cannot enforce changes without explicit authorization. The default indicator query selects
active indicators with a Bad reputation and can be further restricted with tags.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* NetskopeV2

### Scripts

* NetskopeIndicatorSync

### Commands

* closeInvestigation
* netskopev2-create-destination-profile
* netskopev2-deploy-destination-profiles
* netskopev2-list-destination-profiles

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ProfileName | Name of the Netskope Destination Profile to sync indicators into. No tenant-specific fallback is used. |  | Required |
| MatchType | Match type to use only when creating a profile. One of sensitive, insensitive, or regex. Defaults to regex. | regex | Optional |
| IndicatorTypes | Comma-separated Cortex XSOAR indicator types to sync. One or more of Domain, URL, IP, and CIDR. | Domain,URL,IP,CIDR | Optional |
| Tags | Optional comma-separated indicator tags to further restrict which indicators are pulled \(e.g. "netskope-block"\). Leave empty to consider all indicators regardless of tag. |  | Optional |
| SkipTags | Optional comma-separated indicator tags to exclude - any indicator carrying one of these tags is skipped even if it matches Tags. Leave empty to not exclude by tag. |  | Optional |
| MaxIndicators | Maximum number of indicators to pull from Cortex XSOAR per run \(default 500 if left empty\). Bounds how much work a single scheduled run does. |  | Optional |
| IndicatorQuery | Additional Cortex XSOAR indicator query. The default limits synchronization to active indicators with a Bad reputation. | reputation:Bad and expirationStatus:active | Optional |
| Deploy | Whether to deploy pending Destination Profile changes. Defaults to false. | false | Optional |
| ChangeNote | Change note recorded when Deploy is true. | Threat Intel synchronization from Cortex XSOAR | Optional |
| CloseReason | Close reason used for the recurring job incident. | Other | Optional |
| CloseNotes | Close notes used for the recurring job incident. | Netskope Threat Intel synchronization completed. | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Sync Threat Intel to Destination Profile - Netskope](../doc_files/Sync_Threat_Intel_to_Destination_Profile_-_Netskope.png)
