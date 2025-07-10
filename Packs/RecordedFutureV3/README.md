# Recorded Future - Pack Documentation

Recorded Future delivers real-time threat intelligence that helps security teams detect, prioritise, and respond to
threats faster.  
The **Recorded Future** pack focuses on alert-handling and brings both **Recorded Future Classic Alerts** and
**Recorded Future Playbook Alerts** straight into Cortex XSOAR so you can triage, investigate, and close alerts without
ever leaving the SOC console.

> **Heads-up:** This pack replaces the alert-centric capabilities that previously lived in the *Recorded Future
Intelligence* pack - namely the *Recorded Future v2* and *Recorded Future - Playbook Alerts* integrations.
>
> See [Guide: Migrating from Recorded Future Intelligence pack](doc_files/migrate_from_recorded_future_intelligence_pack.md) for more details.

---

## What does this pack include?

* **Integration - Recorded Future Alerts** - fetch, search, update, and enrich Classic & Playbook alerts.
* **Pre-built content** - incident types, layouts, classifier & mapper so that alerts arrive in XSOAR with the right
  structure and visuals out of the box.

---

## Key capabilities

* **Ingest alerts as incidents** - continuous fetch of both Classic and Playbook alerts with granular filtering (rule
  names, status, category, priority, etc.).
* **Search alerts on-demand** - list alerts from the CLI, automations, or playbooks using flexible query parameters.
* **Update alerts** - change status, add comments/notes, assign analysts, or control reopen behaviour - all from XSOAR.
* **Fetch screenshots** - automatically download and attach the latest screenshots that accompany an alert.
* **Rich UX** - dedicated layouts surface the most relevant context for each alert subtype (Domain Abuse, Vulnerability,
  Facility Risk, etc.).
* **Accurate classification & mapping** - built-in classifier and mapper keep incident fields synchronised with Recorded
  Future.

---

## Integrations

### Recorded Future Alerts

Fetch & triage Recorded Future Classic and Playbook alerts.

#### Available commands

| Command             | Description                                                                   |
|---------------------|-------------------------------------------------------------------------------|
| **rf-alerts**       | Search / list Classic or Playbook alerts.                                     |
| **rf-alert-update** | Update alert status, assignee, comment/note, or reopen strategy.              |
| **rf-alert-rules**  | Search for alert rule IDs by (partial) rule name.                             |
| **rf-alert-images** | Retrieve the latest screenshots for an alert and attach them to the incident. |

Full parameter, example, and context details are available in
the [integration README](./Integrations/RecordedFutureAlerts/README.md).

---

#### Relevant Classifiers

* **RF - Classifier** - determines the correct incident type for both Classic and Playbook alerts.
* **RF - Incoming Mapper** - maps alert fields from Recorded Future into Cortex XSOAR incident fields.

---

#### Relevant Incident Types

* RF Classic Alert
* RF Playbook Alert
* RF Domain Abuse Playbook Alert
* RF Vulnerability Playbook Alert
* RF Data Leakage on Code Repo Playbook Alert
* RF Facility Risk Playbook Alert
* RF Third-Party Cyber Playbook Alert

---

#### Relevant Layouts

* RF Classic Alert Layout
* RF Playbook Alert Generic Layout
* RF Domain Abuse Playbook Alert Layout
* RF Vulnerability Playbook Alert Layout
* RF Facility Risk Playbook Alert Layout

---

## Example use cases

* **Phishing & Typosquatting** - triage Domain Abuse alerts and pivot to brand-protection takedown workflows.
* **Vulnerability Management** - prioritise vulnerabilities with real-world exploitation evidence using Cyber
  Vulnerability playbook alerts.
* **Third-Party & Facility Risk** - monitor suppliers or physical facilities for emerging geopolitical or security
  issues.

These are only a few examples - the integration supports any Classic or Playbook alert configured in your Recorded
Future workspace.

---

## Additional resources

* Integration command reference and examples - see
  the [Recorded Future Alerts integration README](Integrations/RecordedFutureAlerts/README.md).
* Recorded Future product documentation - <https://support.recordedfuture.com/hc/en-us>
* [Guide: migrating from Recorded Future Intelligence pack](doc_files/migrate_from_recorded_future_intelligence_pack.md)

---

© Recorded Future. All rights reserved.
