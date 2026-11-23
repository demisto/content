Detonates a URL in the tLab Anti-APT sandbox and waits for the verdict.

Follows the Detonate URL - Generic contract. The sandbox fetches the URL itself, so nothing in Cortex XSOAR ever downloads the target.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* TLabAntiAPTSandbox

### Scripts

This playbook does not use any scripts.

### Commands

* tlab-detonate-url

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | The URL to detonate. Defaults to every URL in the incident. | URL | Optional |
| Interval | How often to poll for the verdict, in seconds. | 60 | Optional |
| Timeout | How long to wait before giving up, in seconds. | 1800 | Optional |
| EnableNetwork | Whether the sandbox may reach the internet during analysis. | true | Optional |
| ResearchTime | Dynamic analysis duration in seconds. Empty uses the preset's own value. |  | Optional |
| EnvPreset | Analysis environment preset. Empty uses the instance default. |  | Optional |
| EarlyVerdict | Return as soon as a verdict is decided, without waiting for every stage. | false | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TLabAntiAPT.Analysis | The analysis result. | Unknown |
| TLabAntiAPT.Analysis.Verdict | Canonical verdict. | String |
| TLabAntiAPT.Analysis.Score | Sandbox score from 0 to 100. | Number |
| TLabAntiAPT.Analysis.SampleReportId | Sample report identifier. | Number |
| TLabAntiAPT.Analysis.ReportUrl | Link to the full report. | String |
| DBotScore | The DBot score object. | Unknown |
| URL | The URL object. | Unknown |
