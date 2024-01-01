Detonate one or more URLs using the ThreatGrid integration.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* ThreatGridv2

### Scripts

This playbook does not use any scripts.

### Commands

* threat-grid-sample-upload

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | URL of the sites to detonate. | URL.Data | Optional |
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | 60 | Optional |
| interval | Indicates the time in seconds to wait between command execution when 'polling' argument is true. Minimum value is 10 seconds. Default is 10. | 10 | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ThreatGrid.Sample.id | The sample id | string |
| ThreatGrid.Sample.filename | The sample filename | string |
| ThreatGrid.Sample.state | The state of the sample, one of a stable set of strings "wait, prep, run, proc, succ, fail" | string |
| ThreatGrid.Sample.status | The sample status | string |
| ThreatGrid.Sample.md5 | The sample md5 | string |
| ThreatGrid.Sample.sha1 | The sample sha1 | string |
| ThreatGrid.Sample.sha256 | The sample sha256 | string |
| ThreatGrid.Sample.os | The sample os | string |
| ThreatGrid.Sample.submitted_at | The sample submission time | string |

## Playbook Image

---

![Detonate URL - ThreatGrid v2](../doc_files/Detonate_URL_-_ThreatGrid_v2.png)
