Meant to run periodically (attach it to an hourly scheduled Job in XSOAR) to keep a Netskope file hash list in sync with File indicators already ingested into XSOAR's own Threat Intel Management.

Netskope's v1 file hash list API has no endpoint to read the current list content, so this playbook tracks the running hash set in an XSOAR List named `NetskopeHashList_<ListName>`, merges it with newly found hashes from Threat Intel, and sends the full merged set as a replace. If nothing new is found, it skips the update call entirely rather than resending an unchanged list every hour.

Ends with a Close Investigation task so a recurring Job isn't blocked from firing again.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

Netskope - Direct to Zero Trust

### Scripts

* NetskopeGetXsoarListContent
* NetskopeSetXsoarListContentWithRetry
* NetskopeFileHashSync
* SetMultipleValues

### Commands

* netskopev2-update-file-hash-list
* closeInvestigation

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Tags | Optional comma-separated indicator tags to further restrict which File indicators are pulled. |  | Optional |
| ListName | Name of an existing Netskope file hash list to update. Must already exist in the Netskope UI. | CTETest | Optional |
| MaxIndicators | Maximum number of File indicators to pull from XSOAR per run (default 500 if left empty). |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.
