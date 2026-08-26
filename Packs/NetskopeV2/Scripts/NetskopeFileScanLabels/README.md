Builds the `setIncident` `addLabels` JSON string from a ***netskopev2-get-scan-report*** result (jobid, status, verdict, md5, sha256).

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Netskope |

## Dependencies

---
This script uses the following commands and scripts.

* netskopev2-get-scan-report

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| scan_result | The Netskope.FileScanReport context output from netskopev2-get-scan-report (a dict, or a single-element list if XSOAR wraps it) - bind this directly to ${Netskope.FileScanReport}. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NetskopeFileScanLabels.labels_json | JSON string ready to pass as setIncident's addLabels argument. | String |
| NetskopeFileScanLabels.summary | Human-readable summary of what was recorded. | String |
