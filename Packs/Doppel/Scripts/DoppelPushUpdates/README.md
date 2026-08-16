Finds Doppel incidents/issues that were closed since the last sweep and archives the corresponding alerts in Doppel, optionally sending the close notes as the alert comment.

The script is intended to run on a schedule via the bundled **Doppel - Sync Alerts** job on platforms without native mirroring, such as Cortex XSIAM. On Cortex XSOAR, prefer the integration's native outgoing mirroring instead.

Incidents closed with the **Duplicate** close reason are skipped, because duplicate closures come from incident cleanup rather than analyst dispositions. Alerts that are already archived in Doppel are left untouched. The cursor is stored in the **Doppel Push Updates Cursor** list and only advances after a clean, fully-drained sweep, making the script safe to re-run.

## Permissions

The script runs with the DBotRole role, which is required to search incidents/issues across the tenant.

## Script data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| lookback | How far back to look for closed incidents/issues when no push cursor exists yet \(first run\). Accepts durations such as '1 hour' or '2 days', or an ISO 8601 timestamp. |
| max_incidents | Maximum number of closed incidents/issues to process per sweep. When the cap is reached, the cursor is not advanced and the remaining closures are processed by the next sweep. |
| push_close_notes | Whether to send the incident close notes to Doppel as the alert comment when archiving. |
| dry_run | Whether to only report what would be pushed without modifying anything. The push cursor is not advanced. |
| instance_name | The Doppel integration instance to use when more than one instance is configured. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Doppel.PushUpdates.ClosedIncidents | Number of closed incidents/issues found since the last sweep. | Number |
| Doppel.PushUpdates.AlertsArchived | Number of Doppel alerts that were archived. | Number |
| Doppel.PushUpdates.AlreadyArchived | Number of Doppel alerts that were already archived and left untouched. | Number |
| Doppel.PushUpdates.Skipped | Number of closed incidents/issues that were skipped \(no Doppel alert ID, closed as Duplicate, or already pushed in this sweep\). | Number |
| Doppel.PushUpdates.Errors | Number of per-alert push failures during the sweep. | Number |
| Doppel.PushUpdates.CursorAdvanced | Whether the push cursor was advanced after the sweep. | Boolean |
| Doppel.PushUpdates.Cursor | The push cursor after the sweep, in ISO 8601 format. | Date |
| Doppel.PushUpdates.DryRun | Whether the sweep ran in dry-run mode. | Boolean |
