Deletes indicators ingested from Cyware Intel Exchange (CTIX v3) that are flagged as deprecated, revoked, false positive, or whitelisted.

The script builds a Threat Intel query scoped to indicators from the **CTIX v3** integration (`sourceBrands:"CTIX v3"`) with any of the enabled flag fields set, and runs the built-in `deleteIndicators` command on the matches. All delete flags are disabled by default — the script does nothing until at least one flag is explicitly enabled, so it can never issue an unscoped delete.

It is intended to be run on a schedule via the bundled **CTIX - Delete Flagged Indicators** job (which triggers the playbook of the same name), but can also be run manually from the War Room or Playground.

Note: an indicator flagged in CTIX is only picked up after the feed re-fetches it (the fetch updates the indicator's flag fields in the Threat Intel Module; the next script run then finds and deletes it).

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| delete_deprecated | Whether to delete indicators marked as deprecated in Cyware Intel Exchange \(CTIX\). Default is false. |
| delete_revoked | Whether to delete indicators revoked by their source in Cyware Intel Exchange \(CTIX\). Default is false. |
| delete_false_positive | Whether to delete indicators marked as false positive in Cyware Intel Exchange \(CTIX\). Default is false. |
| delete_whitelisted | Whether to delete indicators allow-listed in Cyware Intel Exchange \(CTIX\). Default is false. |
| exclude | Whether to also add the deleted indicators to the Exclusion List. When false \(default\), indicators are purely deleted and can be re-created if they reappear un-flagged. |
| reason | Reason recorded for the deletion \(and exclusion, if enabled\). |

## Outputs

---
There are no outputs for this script.
