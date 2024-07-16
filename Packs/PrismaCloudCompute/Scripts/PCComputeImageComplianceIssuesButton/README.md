This script runs the "prisma-cloud-compute-images-scan-list" command for a specific container id and returns details about its compliance issues, if found. If any compliance issues found, it will create a new tab in the layout called "Detailed Compliance Issues" showing the issues details.
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

* PaloAltoNetworks_PrismaCloudCompute
* prisma-cloud-compute-images-scan-list

## Inputs

---

| **Argument Name** | **Description**                                                                                                               |
| --- |-------------------------------------------------------------------------------------------------------------------------------|
| image_id | The image ID to be enriched.                                                                                                  |
| compliance_ids | A comma-separated list of compliance IDs to be enriched. If no value provided, it will return results for all compliance IDs. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaCloudCompute.PCC_ImageComplianceIssues.image_id | The image ID. | string |
| PrismaCloudCompute.PCC_ImageComplianceIssues.compliance_issues | A list of the image's compliance issues. | string |
| PrismaCloudCompute.PCC_ImageComplianceIssues.compliance_issues.Cause | Additional information regarding the root cause for the vulnerability. | string |
| PrismaCloudCompute.PCC_ImageComplianceIssues.compliance_issues.ComplianceID | ID of the violation. | Unknown |
| PrismaCloudCompute.PCC_ImageComplianceIssues.compliance_issues.Severity | Textual representation of the vulnerability's severity. | string |
| PrismaCloudCompute.PCC_ImageComplianceIssues.compliance_issues.Title | Compliance title. | string |
| PrismaCloudCompute.PCC_ImageComplianceIssues.compliance_issues.Description | Compliance issue description. | string |
