Polls Doppel for alerts whose state changed since the last sweep and applies the changes to the matching Cortex incidents or issues.

The script is intended to run on a schedule via the bundled **Doppel - Sync Alerts** job on platforms without native mirroring, such as Cortex XSIAM. On Cortex XSOAR, prefer the integration's native mirroring instead.

Each sweep retrieves the Doppel alerts whose last activity occurred at or after the sync cursor, matches them to existing incidents/issues by the Doppel alert ID (the **dbotMirrorId** field set by ***fetch-incidents***), and updates the Doppel queue state, entity state, severity, notes, and audit logs. The cursor is stored in the **Doppel Sync Alerts Cursor** list and only advances after a clean, fully-drained sweep, so no update is ever skipped. Every update is idempotent, making the script safe to re-run.

When Doppel revives an alert — Revival Monitoring moves it back into an active queue, for example when a taken-down domain comes back online — the sweep reopens the matching closed incident or issue (controlled by the **reopen_revived** argument, enabled by default). The reopen only fires on a queue transition observed since the last sweep, so unrelated alert activity does not reopen incidents an analyst closed.

## Permissions

The script runs with the DBotRole role, which is required to search and update incidents/issues across the tenant.

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
| lookback | How far back to look for modified Doppel alerts when no sync cursor exists yet \(first run\). Accepts durations such as '1 hour' or '2 days', or an ISO 8601 timestamp. |
| max_pages | Maximum number of pages \(200 alerts each\) to retrieve from the Doppel API per sweep. When the cap is reached, the cursor is not advanced and the remaining updates are processed by the next sweep. |
| close_archived | Whether to close the Cortex incident/issue when the corresponding Doppel alert has been archived in Doppel. Disabled by default, which matches the behavior of native mirroring. |
| reopen_revived | Whether to reopen a closed Cortex incident/issue when Doppel revives the alert \(moves it back into an active queue such as Doppel Review or Actioned\). Enabled by default. |
| dry_run | Whether to only report what would be updated without modifying anything. The sync cursor is not advanced. |
| instance_name | The Doppel integration instance to query when more than one instance is configured. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Doppel.SyncAlerts.ModifiedAlerts | Number of Doppel alerts with activity since the last sweep. | Number |
| Doppel.SyncAlerts.IncidentsUpdated | Number of incidents/issues that were updated. | Number |
| Doppel.SyncAlerts.IncidentsClosed | Number of incidents/issues that were closed because the Doppel alert was archived. | Number |
| Doppel.SyncAlerts.IncidentsReopened | Number of closed incidents/issues that were reopened because the Doppel alert was revived into an active queue. | Number |
| Doppel.SyncAlerts.AlertsWithoutIncident | Number of modified Doppel alerts with no matching incident/issue in the tenant. | Number |
| Doppel.SyncAlerts.Errors | Number of per-incident update failures during the sweep. | Number |
| Doppel.SyncAlerts.CursorAdvanced | Whether the sync cursor was advanced after the sweep. | Boolean |
| Doppel.SyncAlerts.Cursor | The sync cursor after the sweep, in ISO 8601 format. | Date |
| Doppel.SyncAlerts.DryRun | Whether the sweep ran in dry-run mode. | Boolean |
