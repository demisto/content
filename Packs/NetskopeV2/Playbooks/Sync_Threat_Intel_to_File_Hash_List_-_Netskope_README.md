Synchronizes bounded Cortex XSOAR File indicators to an existing Netskope file hash list.
Netskope's v1 API replaces the full list and does not provide a read endpoint, so the playbook
preserves the running set in a Cortex XSOAR List named NetskopeHashList_<ListName>.

ListName is required and has no tenant-specific fallback. The default indicator query selects
active indicators with a Bad reputation. If the mirror list is empty, the playbook stops unless
AllowEmptyMirrorOverwrite is explicitly enabled, preventing accidental replacement of an
existing Netskope list with incomplete state.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* NetskopeV2

### Scripts

* NetskopeFileHashSync
* NetskopeGetXsoarListContent
* NetskopeSetXsoarListContentWithRetry

### Commands

* closeInvestigation
* netskopev2-update-file-hash-list

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Tags | Optional comma-separated indicator tags to further restrict which File indicators are pulled \(e.g. "malware"\). Leave empty to consider all File-type indicators. |  | Optional |
| ListName | Name of an existing Netskope file hash list. No tenant-specific fallback is used. |  | Required |
| MaxIndicators | Maximum number of File indicators to pull from Cortex XSOAR per run \(default 500 if left empty\). Bounds how much work a single scheduled run does. |  | Optional |
| SkipTags | Optional comma-separated indicator tags to exclude. |  | Optional |
| IndicatorQuery | Additional Cortex XSOAR indicator query. The default limits synchronization to active indicators with a Bad reputation. | reputation:Bad and expirationStatus:active | Optional |
| AllowEmptyMirrorOverwrite | Whether to allow replacing the Netskope list when the Cortex XSOAR mirror is empty. Defaults to false. | false | Optional |
| CloseReason | Close reason used for the recurring job incident. | Other | Optional |
| CloseNotes | Close notes used for the recurring job incident. | Netskope Threat Intel hash synchronization completed. | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Sync Threat Intel to File Hash List - Netskope](../doc_files/Sync_Threat_Intel_to_File_Hash_List_-_Netskope.png)
