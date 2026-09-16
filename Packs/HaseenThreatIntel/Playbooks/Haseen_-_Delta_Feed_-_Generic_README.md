# Haseen - Delta Feed - Generic

> **Short description:** A template playbook to run on Haseen delta-in-feed trigger jobs — stage newly-fetched indicators, hunt, and optionally block selected IOCs.

## Overview

Triggered by the Haseen feed's delta-in-feed job after each fetch. The playbook picks up indicators that arrived from the Haseen Threat Intel integration (`sourceBrands:"Haseen Threat Intel"`) within the last 24 hours, gathers their relationships, associates them to the incident, and walks the analyst through a hunt → manual-block-validation → close flow.

The playbook is a **template requiring customization**: the hunt, blocking, and closure flows are placeholders you must replace with your own standard flows.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts:

- **Haseen Threat Intel** integration (feeds the indicators).
- **SearchIndicator** / **SearchIndicatorRelationships** builtin commands.
- **setIncident** / **associateIndicatorsToIncident** builtin commands.

## Flow

| Stage | Task | Description |
| --- | --- | --- |
| Stage | `Stage the fetched indicators` | `SearchIndicator` for `sourceBrands:"Haseen Threat Intel"` with `sourcetimestamp`/`lastSeen` within the last 24 hours (max 500). Haseen updates its STIX bundle roughly once per day, so a 24-hour window is the default; adjust it to match your environment. |
| Stage | `Search Relationships` | `SearchIndicatorRelationships` for the staged indicator values (max 500). |
| Stage | `Add all indicators to the incident` | `associateIndicatorsToIncident` on `${incident.id}`, appending each relationship's `EntityB` so indicators referenced only via relationships (not as STIX SDO/SCO) are also staged. |
| Stage | `Prepare all indicators for hunt and block` | `SearchIndicator` for `incident.id:${incident.id}` (max 1000 — up to 500 new indicators plus up to 500 relationship objects). |
| Hunt | **Threat Hunting on Security Technologies** | Section header. **Replace the `Replace with your Hunting Flow` task** with your actual hunting automation/flow. The hunt inputs are under the `foundIndicators.value` context path. |
| Hunt | `Check if results are returned from Threat Hunting` | Branches on whether the hunt returned results. |
| Hunt | `Increase incident severity to high if hunt process found matches` | On hunt hits, sets incident severity to `3` (High) via `setIncident`. The value is configurable — High or Critical is recommended, depending on your hunt prioritization process. |
| Block | **Block Indicators** | Section header. |
| Block | `IOCs Analyst Validation for Blocking?` | Manual collection task — the analyst multi-selects Domains, IPs, URLs, and SHA256 hashes to block (from `foundIndicators`). |
| Block | `Check if any IOCs selected for blocking?` | Branches on whether any IOC was selected. |
| Block | `Following IOCs will be Blocked Please confirm…` | Confirmation prompt listing the selected IPs/Domains/URLs/Hashes. |
| Block | `Replace with your Blocking flow` | **Replace this task** with your blocking logic; the selected IOCs are passed via `${Block IOCs Manual Validation.Answers.0..3}`. |
| Close | **Incident Closure** | Section header. |
| Close | `Replace with your Incident Closure logic` | **Replace this task** with your closure logic. Ends at `Done`. |

## Customisation points

The playbook is a template. Replace the three placeholder tasks with your own flows:

* **`Replace with your Hunting Flow`** — consume `foundIndicators.value` and return hunt results.
* **`Replace with your Blocking flow`** — consume `${Block IOCs Manual Validation.Answers.0..3}` (Domains / IPs / URLs / Hashes) and enforce blocks.
* **`Replace with your Incident Closure logic`** — close the incident per your SOC's SOP.

## Notes on scope and limits

* **24-hour window** — tasks stage indicators created or updated in the last 24 hours because Haseen publishes its bundle once per day. Adjust the `sourcetimestamp`/`lastSeen` window if your feed cadence differs.
* **Search limits** — `SearchIndicator` returns 25 results by default and `SearchIndicatorRelationships` returns 20. The playbook raises these to 500/500/1000 because Haseen updates can carry up to ~500 new indicators and ~500 relationship objects; adjust freely if your volumes differ.
* **EntityB association** — the `Add all indicators to the incident` task also appends each relationship's `EntityB` (`Relationships.EntityB`) so indicators that only appear inside Haseen relationship objects (rather than as STIX SDO/SCO entries) are staged for hunt and block.

## Screenshot

![Haseen Delta Feed Job Playbook](doc_files/Haseen-DeltaFeed-Generic.png)
