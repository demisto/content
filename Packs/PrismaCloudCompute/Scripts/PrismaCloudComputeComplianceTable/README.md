Iterate over EnrichedComplianceIssue information in the context data and add the important keys to a table under PrismaCloudCompute.ComplianceTable or a provided grid id.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| resourceType | Type of resource to add to the table. |
| contextPath | The context path to the enriched compliance issues list. |

## Outputs

---

| **Path**                                                            | **Description** | **Type** |
|---------------------------------------------------------------------| --- | --- |
| PrismaCloudCompute.ComplianceTable.Host.Hostname                    | ID of the host. | String |
| PrismaCloudCompute.ComplianceTable.Host.ComplianceIssues            | Compliance issue records related to the host. Updated in every iteration. | Array |
| PrismaCloudCompute.ComplianceTable.Host.ComplianceDistribution      | Compliance distribution of the host. | Dictionary |
| PrismaCloudCompute.ComplianceTable.Host.CloudMetadata               | Cloud metadata of the host. | Dictionary |
| PrismaCloudCompute.ComplianceTable.Container.ContainerID            | ID of the container. | String |
| PrismaCloudCompute.ComplianceTable.Container.ComplianceIssues       | Compliance issue records related to the container. Updated in every iteration. | Array |
| PrismaCloudCompute.ComplianceTable.Container.ComplianceDistribution | Compliance distribution of the container. | Dictionary |
| PrismaCloudCompute.ComplianceTable.Container.Hostname               | Hostname of the container. | String |
| PrismaCloudCompute.ComplianceTable.Container.ImageName              | Image name of the container. | String |
| PrismaCloudCompute.ComplianceTable.Container.CloudMetadata          | Cloud metadata of the container. | Dictionary |
| PrismaCloudCompute.ComplianceTable.Image.ImageID                    | ID of the image. | String |
| PrismaCloudCompute.ComplianceTable.Image.ComplianceIssues           | Compliance issue records related to the image. Updated in every iteration. | Array |
| PrismaCloudCompute.ComplianceTable.Image.ComplianceDistribution     | Compliance distribution of the image. | Dictionary |
| PrismaCloudCompute.ComplianceTable.Image.Hosts                      | Hosts of the image. | Array |
| PrismaCloudCompute.ComplianceTable.Container.ImageInstances         | Image instances of the image. | Array |
| PrismaCloudCompute.ComplianceTable.Container.CloudMetadata          | Cloud metadata of the image. | Dictionary |
