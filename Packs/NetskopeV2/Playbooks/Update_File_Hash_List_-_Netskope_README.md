Adds hashes to a Netskope file hash list via ***netskopev2-update-file-hash-list***.

Netskope's file hash list API (v1) has no endpoint to read the current list content - every update REPLACES the full list, it cannot append. Since Netskope itself can't tell us what's already there, this playbook tracks the running hash set on the XSOAR side instead, in an XSOAR List named `NetskopeHashList_<ListName>` (auto-created on first run): it reads that List's current content, merges it with `NewHashes`, sends the full merged set to Netskope, then writes the result back to the same XSOAR List so the next run picks up where this one left off.

Only MD5 (32 hex chars) and SHA256 (64 hex chars) hashes are accepted.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

Netskope - Direct to Zero Trust

### Scripts

* NetskopeGetXsoarListContent
* NetskopeSetXsoarListContentWithRetry

### Commands

* netskopev2-update-file-hash-list

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ListName | Name of an existing Netskope file hash list to update. Must already exist in the Netskope UI. |  | Required |
| NewHashes | Comma-separated MD5 or SHA256 hashes to add to the list this run. |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.
