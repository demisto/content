This script runs the "prisma-cloud-compute-container-scan-results-list" command for a specific container ID and returns details about its compliance issues, if found. If any compliance issues found, it will create a new tab in the layout called "Detailed Compliance Issues" showing the issues details.
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
* prisma-cloud-compute-container-scan-results-list

## Inputs

---

| **Argument Name** | **Description**                                                                                                               |
| --- |-------------------------------------------------------------------------------------------------------------------------------|
| container_id | The container ID to be enriched.                                                                                              |
| compliance_ids | A comma-separated list of compliance IDs to be enriched. If no value provided, it will return results for all compliance IDs. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaCloudCompute.PCC_ContainerComplianceIssues.container_id | The container ID. | string |
| PrismaCloudCompute.PCC_ContainerComplianceIssues.compliance_issues | A list of the container's compliance issues. | string |
| PrismaCloudCompute.PCC_ContainerComplianceIssues.Cause | Additional information regarding the root cause for the vulnerability. | string |
| PrismaCloudCompute.PCC_ContainerComplianceIssues.ComplianceID | ID of the violation. | string |
| PrismaCloudCompute.PCC_ContainerComplianceIssues.Severity | Textual representation of the vulnerability's severity. | string |
| PrismaCloudCompute.PCC_ContainerComplianceIssues.Title | Compliance issue title. | string |
| PrismaCloudCompute.PCC_ContainerComplianceIssues.Description | Compliance issue description. | string |
