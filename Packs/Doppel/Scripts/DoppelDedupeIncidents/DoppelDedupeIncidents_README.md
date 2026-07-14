Cleans up duplicate Doppel incidents created by the fetch duplication bug.

Incidents are grouped by the Doppel alert ID (dbotMirrorId). Within each group, only OPEN incidents are considered: the survivor kept as canonical is the oldest open incident that has an owner (analyst work in progress), or the oldest open incident if none are owned. The remaining OPEN duplicates are CLOSED as "Duplicate" (default, reversible) or DELETED (explicit opt-in).

Already-closed incidents are NEVER touched, regardless of their close reason (Duplicate, False Positive, Resolved, ...). An analyst's disposition is never overwritten, and incidents already closed as Duplicate are never chosen as the canonical survivor and never re-processed, so re-runs / batched runs are idempotent.

Safety model: defaults to a dry run that only reports what it would do; defaults to close (not delete) so any incident is fully recoverable by reopening it; and the report flags any open duplicate that has an owner for human review before a non-dry run.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | doppel |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| action | The action to take on duplicate incidents (close or delete). Possible values are: close, delete. Default is close. |
| dry_run | Whether to only report the planned actions without changing anything. Possible values are: true, false. Default is true. |
| query | The incident search query used to find candidate Doppel incidents. Leave empty to use the built-in Doppel Alert type query. |
| page_size | The number of incidents to fetch per search page (keep at or below 100). Default is 100. |
| max_pages | The safety ceiling on the number of search pages to scan. Default is 1000. |
| limit | The maximum number of incidents to close/delete in a single run (0 = no limit). Use to process a large backlog in safe batches; re-run until the report shows 0 remaining. Default is 0. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Doppel.Dedupe.scanned | The number of incidents scanned. | Number |
| Doppel.Dedupe.dry_run | Whether the run was a dry run (no changes made). | Boolean |
| Doppel.Dedupe.action | The action applied to duplicates (close or delete). | String |
| Doppel.Dedupe.limit | The per-run cap on the number of incidents actioned (0 = no limit). | Number |
| Doppel.Dedupe.duplicate_groups | The number of Doppel alert groups that had open redundant incidents. | Number |
| Doppel.Dedupe.skipped_closed | The number of already-closed incidents left untouched. | Number |
| Doppel.Dedupe.total_actions | The total number of open duplicate incidents planned for action. | Number |
| Doppel.Dedupe.remaining | The number of planned actions not performed in this run (re-run to continue). | Number |
| Doppel.Dedupe.actions | The full list of planned close/delete actions. | Unknown |
| Doppel.Dedupe.flagged | The open duplicates that have an owner and warrant review. | Unknown |
| Doppel.Dedupe.performed | The actions performed in this run (empty on a dry run). | Unknown |
