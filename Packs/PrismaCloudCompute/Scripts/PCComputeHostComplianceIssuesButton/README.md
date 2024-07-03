This script runs the "prisma-cloud-compute-hosts-scan-list" command for a specific hostname and returns details about its compliance issues, if found. If any compliance issues found, it will create a new tab in the layout called "Detailed Compliance Issues" showing the issues details.
Returns the following fields for each compliance ID:
- Compliance ID
- Cause
- Severity
- Title
- Description.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* prisma-cloud-compute-hosts-scan-list
* PaloAltoNetworks_PrismaCloudCompute

## Inputs

---

| **Argument Name** | **Description**                                                                                                               |
| --- |-------------------------------------------------------------------------------------------------------------------------------|
| hostname | The hostname to be enriched.                                                                                                  |
| compliance_ids | A comma-separated list of compliance IDs to be enriched. If no value provided, it will return results for all compliance IDs. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaCloudCompute.PCC_HostComplianceIssues.hostname | The hostname. | string |
| PrismaCloudCompute.PCC_HostComplianceIssues.compliance_issues | A list of the host's compliance issues. | string |
| PrismaCloudCompute.PCC_HostComplianceIssues.compliance_issues.Cause | Additional information regarding the root cause for the vulnerability. | string |
| PrismaCloudCompute.PCC_HostComplianceIssues.compliance_issues.ComplianceID | ID of the violation. | Unknown |
| PrismaCloudCompute.PCC_HostComplianceIssues.compliance_issues.Severity | Textual representation of the vulnerability's severity. | string |
| PrismaCloudCompute.PCC_HostComplianceIssues.compliance_issues.Title | Compliance title. | string |
| PrismaCloudCompute.PCC_HostComplianceIssues.compliance_issues.Description | Compliance issue description. | string |
