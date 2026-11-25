Triage playbook for a tLab Anti-APT Verdict incident.

Pulls the detail the fetch did not carry, then splits on the verdict: benign analyses close themselves, malicious and suspicious ones stay open for an analyst with the evidence already in context.

Runs for incidents created by either delivery half. The tLab Delivery Mode field records which one made the incident, and the playbook does not care.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* TLabAntiAPTSandbox

### Scripts

This playbook does not use any scripts.

### Commands

* closeInvestigation
* tlab-get-report
* tlab-get-threat-indicators

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SampleReportId | Sample report to enrich. Defaults to the incident's own. | incident.tlabsamplereportid | Optional |
| AutoCloseBenign | Whether an OK, CLEAN or WHITELIST verdict closes the incident automatically. Turn it off while tuning the verdict filter, so that what would have been closed stays visible. | true | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TLabAntiAPT.Report | The full sample report. | Unknown |
| TLabAntiAPT.ThreatIndicators | Threat indicators observed during analysis. | Unknown |
