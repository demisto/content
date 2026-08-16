Keeps Doppel incidents/issues in sync with the Doppel platform on deployments without native mirroring, such as Cortex XSIAM. Runs DoppelSyncAlerts to apply Doppel-side changes (queue state, entity state, severity, notes, and audit logs) to the matching incidents/issues, then runs DoppelPushUpdates to archive Doppel alerts whose incidents/issues were closed by analysts.

Intended to run on a schedule via the bundled **Doppel - Sync Alerts** job. On Cortex XSOAR, prefer the integration's native mirroring and leave the job disabled.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Doppel

### Scripts

* DoppelSyncAlerts
* DoppelPushUpdates

### Commands

This playbook does not use any commands directly.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| lookback | How far back the sync and push sweeps look on their first run, before a cursor exists. Accepts durations such as '1 hour' or '2 days', or an ISO 8601 timestamp. | 1 hour | Optional |
| close_archived | Whether to close the Cortex incident/issue when the corresponding Doppel alert has been archived in Doppel. Disabled by default, which matches the behavior of native mirroring. | false | Optional |
| push_close_notes | Whether to send the incident close notes to Doppel as the alert comment when archiving. | true | Optional |
| instance_name | The Doppel integration instance to use when more than one instance is configured. |  | Optional |

## Playbook Outputs

---

There are no outputs for this playbook.
