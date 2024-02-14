This script runs the "prisma-cloud-compute-hosts-scan-list" command for a specific hostname and returns details about its compliance issues, if found. If any compliance issues found, it will create a new tab in the layout called "Detailed Compliance Issues" showing the issues details.
Returns the following fields for each compliance ID:
- Compliance ID
- Cause
- Severity
- Title.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* PaloAltoNetworks_PrismaCloudCompute
* prisma-cloud-compute-hosts-scan-list

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| hostname | The hostname to be enriched. |
| compliance_ids | A comma separated list of compliance IDs to be enriched. If no value provided, it will return results for all compliance IDs. |

## Outputs

---
There are no outputs for this script.
