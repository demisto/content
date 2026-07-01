# Doppel XSOAR Pack

## Overview

Doppel is a Modern Digital Risk Protection Solution, that detects the phishing and brand cyber attacks on the emerging channels. Doppel scans millions of channels online which includes, social media, domains, paid ads, dark web, emerging channels, etc. Doppel can identify the malicious content and cyber threats, and enables their customers to take down the digital risks proactively.

## Features supported by the Doppel XSOAR pack

1. Mirror Incidents : Alerts from Doppel are mirrored as per the configured schedule.
2. Command: create-alert : Command to create an alert in Doppel.
3. Command: get-alert : Command to fetch alert details from Doppel.
4. Command: get-alerts : Command to fetch list of alerts from Doppel.
5. Command: update-alert : Command to update alert details from Doppel.
6. Command: create-abuse-alert : Command to create abuse alert details from Doppel.
7. Automation: DoppelDedupeIncidents : Consolidates duplicate Doppel incidents.

## Cleaning up duplicate incidents

The **DoppelDedupeIncidents** automation consolidates duplicate Doppel incidents (for example, duplicates created by an earlier fetch issue). It groups incidents by the Doppel alert id and, within each group, keeps a single canonical **open** incident, then closes or optionally deletes the remaining **open** duplicates.

How it works:

- **Survivor selection** is owner-aware: the oldest open incident that has an owner is kept, otherwise the oldest open incident.
- **Already-closed incidents are never touched**, regardless of close reason, so analyst dispositions (for example, False Positive) are preserved and re-runs are idempotent.
- Defaults to a **dry run** that only reports the planned actions, and defaults to **close** (reversible) rather than delete.

### Arguments

| Argument | Description | Default |
| --- | --- | --- |
| `action` | `close` (reversible) or `delete` (permanent). | `close` |
| `dry_run` | When `true`, only report the planned actions. | `true` |
| `query` | Incident search query. Leave empty to use the built-in Doppel Alert type query. | built-in |
| `page_size` | Incidents fetched per search page (keep at or below 100). | `100` |
| `max_pages` | Safety ceiling on search pages to scan. | `1000` |
| `limit` | Maximum incidents to close/delete per run (0 = no limit). | `0` |

### Recommended rollout

1. Run a dry run to review the plan (and the attached CSV of planned actions):

   ```
   !DoppelDedupeIncidents dry_run=true
   ```

2. For a large backlog, drain it in batches with `limit` and re-run until the report shows `Remaining: 0`:

   ```
   !DoppelDedupeIncidents dry_run=false action=close limit=500
   ```

   Tip: if a run approaches the automation timeout, lower `page_size` and/or `limit`.
