Check coverage given a list of CVEs.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* NetOps Panorama coverage by CVE

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| CVE_List | comma delimited list of CVEs to find |
| Result_file | Entry ID of the output file from the panorama command |
| outputFormat | raw output of panorama command into a file |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Panorama.CVECoverage.CVE | The CVE value.| String |
| Panorama.CVECoverage.Coverage.threat_name | The threat name. | String |
| Panorama.CVECoverage.Coverage.link | Link address to the threat in CVE site. | String |
| Panorama.CVECoverage.Coverage.severity | The threat severity. | String |
| Panorama.CVECoverage.Coverage.threat_id | The threat ID. | Number |
| Panorama.CVECoverage.Coverage.default_action | The threat default action. | String |

