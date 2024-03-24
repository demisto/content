This is a sub playbook of the "Prisma Cloud Compute - Compliance Alert v2" playbook.
It will loop through all of the given compliance issue IDs and will retrieve the following information for each affected image based on the compliance issue ID:
- Image ID
- Compliance Issues
- Compliance Distribution
- Hosts
- Image Instances
- Cloud MetaData

The enriched information will be displayed in the layout in a dedicated table under the "Image Compliance Information" tab.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Prisma Cloud Compute - ServiceNow Compliance Ticket
* Prisma Cloud Compute - Jira Compliance Issue

### Integrations

* PaloAltoNetworks_PrismaCloudCompute

### Scripts

* PrismaCloudComputeComplianceTable
* DeleteContext
* SetAndHandleEmpty

### Commands

* setIncident
* prisma-cloud-compute-images-scan-list

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ComplianceIssue | A compliance issue. This list is used to filter relevant hostnames for enrichment. |  | Optional |
| LastComplianceID | The ID of the last compliance issue fetched in the incidents.<br/>Used to know when to set the output after the loops end. |  | Optional |
| TicketingSystem | Which ticketing system should be used to create an external ticket.<br/>Available options:<br/>- Jira<br/>- ServiceNow<br/><br/>If none of the above selected, no external ticket will get created.<br/>For Jira, please also set the "JiraProjectName" and "JiraIssueTypeName" playbook inputs. |  | Optional |
| JiraIssueTypeName | Issue type name. For example: "Task". |  | Optional |
| JiraProjectName | The project name with which to associate the issue. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ComplianceTableOutput | Compliance issues table. | unknown |

## Playbook Image

---

![Prisma Cloud Compute - Compliance Alert Image Enrichment Loop](../doc_files/Prisma_Cloud_Compute_-_Compliance_Alert_Image_Enrichment_Loop.png)
