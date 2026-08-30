# Haseen-delta-in-feed-generic playbook

<!-- TODO: Mohamed — replace this with the official short description you want in the Marketplace. -->
> **Short description (placeholder):** A template playbook to run on Haseen delta-in-feed trigger jobs — stage newly-fetched indicators, hunt, and optionally block selected IOCs. <!-- EDIT ME -->


## Overview

Triggered by the Haseen feed's delta-in-feed job after each fetch. The playbook picks up indicators that arrived from the Haseen Threat Intel instance within the last 24 hours, gathers their relationships, associates them to the incident, and walks the analyst through a hunt → manual-block-validation → close flow.


## Flow

| Stage | Task | Description |
| --- | --- | --- |
| Stage | `Stage the fetched indicators` | `SearchIndicator` for `sourceInstances:"Haseen Threat Intel_instance_1"` with `sourcetimestamp`/`lastSeen` within the last 24 hours (max 300). |
| Stage | `Search Relationships` | `SearchIndicatorRelationships` for the staged indicator values (max 300). |
| Stage | `Add all indicators to the incident` | `associateIndicatorsToIncident` on `${incident.id}`, appending each relationship's `EntityB`. |
| Stage | `Prepare all indicators for hunt and block` | `SearchIndicator` for `incident.id:${incident.id}` (max 500). |
| Hunt | **Threat Hunting on Security Technologies** | Section header. **Replace the `Replace with your Hunting Flow` task** with your actual hunting automation/flow (`StixIndicators.value` and `foundIndicators.value` are the inputs). |
| Hunt | `Check if results are returned from Threat Hunting` | Branches on whether the hunt returned results. |
| Hunt | `Increase incident severity to high` | On hunt hits, sets incident severity to `3` (High) via `setIncident`. |
| Block | **Block Indicators** | Section header. |
| Block | `IOCs Analyst Validation for Blocking?` | Manual collection task — the analyst multi-selects Domains, IPs, URLs, and SHA256 hashes to block (from `foundIndicators`). |
| Block | `Check if any IOCs selected for blocking?` | Branches on whether any IOC was selected. |
| Block | `Following IOCs will be Blocked Please confirm…` | Confirmation prompt listing the selected IPs/Domains/URLs/Hashes. |
| Block | `Replace with your Blocking flow` | **Replace this task** with your blocking logic; the selected IOCs are passed via `${Block IOCs Manual Validation.Answers.0..3}`. |
| Close | **Incident Closure** | Section header. |
| Close | `Replace with your Incident Closure logic` | **Replace this task** with your closure logic. Ends at `Done`. |


## Customisation points

The playbook is a template. Replace the three placeholder tasks with your own flows:

* **`Replace with your Hunting Flow`** — consume `StixIndicators.value` / `foundIndicators.value` and return hunt results.
* **`Replace with your Blocking flow`** — consume `${Block IOCs Manual Validation.Answers.0..3}` (Domains / IPs / URLs / Hashes) and enforce blocks.
* **`Replace with your Incident Closure logic`** — close the incident per your SOC's SOP.

<!-- TODO: Mohamed — add screenshots, expected context paths, or sample outputs here. -->
