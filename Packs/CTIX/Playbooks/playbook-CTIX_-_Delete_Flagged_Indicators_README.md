Deletes indicators ingested from Cyware Intel Exchange (CTIX v3) that are flagged as deprecated, revoked, false positive, or whitelisted, by running the **CTIXDeleteFlaggedIndicators** script.

All delete flags default to `false`, so the playbook does nothing until at least one flag input is enabled. It is intended to run on a schedule via the bundled **CTIX - Delete Flagged Indicators** job — jobs cannot pass per-run inputs, so enable the desired flags once by editing the playbook input defaults (or the job's playbook input overrides).

Note: an indicator flagged in CTIX is only picked up after the CTIX v3 feed re-fetches it, which updates the indicator's flag fields in the Threat Intel Module; the next run then finds and deletes it.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* CTIXDeleteFlaggedIndicators

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| delete_deprecated | Whether to delete indicators marked as deprecated in Cyware Intel Exchange \(CTIX\). | false | Optional |
| delete_revoked | Whether to delete indicators revoked by their source in Cyware Intel Exchange \(CTIX\). | false | Optional |
| delete_false_positive | Whether to delete indicators marked as false positive in Cyware Intel Exchange \(CTIX\). | false | Optional |
| delete_whitelisted | Whether to delete indicators allow-listed in Cyware Intel Exchange \(CTIX\). | false | Optional |
| exclude | Whether to also add the deleted indicators to the Exclusion List. When false \(default\), indicators are purely deleted and can be re-created if they reappear un-flagged. | false | Optional |
| reason | Reason recorded for the deletion \(and exclusion, if enabled\). | Deleted by CTIXDeleteFlaggedIndicators job | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.
