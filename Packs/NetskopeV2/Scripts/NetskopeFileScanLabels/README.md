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
| scan_result | The Netskope.FileScanReport context output from netskopev2-get-scan-report (a dict, or a single-element list if Cortex XSOAR wraps it) - bind this directly to ${Netskope.FileScanReport}. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Netskope.FileScanLabels.LabelsJson | The JSON string ready to pass as setIncident's addLabels argument. | String |
| Netskope.FileScanLabels.Summary | The human-readable summary of what was recorded. | String |
