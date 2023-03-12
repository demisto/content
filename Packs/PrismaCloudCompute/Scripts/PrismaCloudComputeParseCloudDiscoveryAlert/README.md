Parse Cloud Discovery alert raw JSON data

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Prisma Cloud Compute |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Prisma Cloud Compute - Cloud Discovery Alert

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| alert_raw_json | The compliance alert raw JSON |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaCloudCompute.CloudDiscoveryAlert.time | Time represents the alert creation timestamp | Date |
| PrismaCloudCompute.CloudDiscoveryAlert.credentialId | CredentialID is the id reference of the credential used | String |
| PrismaCloudCompute.CloudDiscoveryAlert.provider | Provider is the cloud provider for example: AWS, GCP | String |
| PrismaCloudCompute.CloudDiscoveryAlert.serviceType | ServiceType is the cloud service type for example: ECR, GCR | String |
| PrismaCloudCompute.CloudDiscoveryAlert.region | Region is the region that was scanned, for example: GCP - "us-east-1", Azure - "westus" | String |
| PrismaCloudCompute.CloudDiscoveryAlert.project | Project is the GCP project that was scanned | String |
| PrismaCloudCompute.CloudDiscoveryAlert.registry | Registry is the Azure registry that was scanned, for example: testcloudscanregistry.azurecr.io | String |
| PrismaCloudCompute.CloudDiscoveryAlert.protected | Protected is the number of protected entities \(registries, functions, clusters\) | Number |
| PrismaCloudCompute.CloudDiscoveryAlert.total | Total is total number of entities found in cloud scan | Number |
| PrismaCloudCompute.CloudDiscoveryAlert.err | Err holds any error found during a scan | String |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.name | Name is the name of the entity | String |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.protected | Protected indicates if the entity is protected | Number |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.lastModified | LastModified is the modification time of the function | Date |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.runtime | Runtime is runtime environment for the function, e.g. nodejs | String |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.version | Version is the version of the entity | String |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.arn | The Amazon Resource Name \(ARN\) assigned to the entity | String |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.status | Status is the current status of entity | String |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.runningTasksCount | RunningTasksCount is the number of running tasks in ecs cluster | Number |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.activeServicesCount | ActiveServicesCount is the number of active services in ecs cluster | Number |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.createdAt | CreatedAt is the time when the entity was created | Date |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.nodesCount | NodesCount is the number of nodes in the cluster \(aks, gke\) | Number |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.resourceGroup | ResourceGroup is the the azure resource group containing the entity | String |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.containerGroup | ContainerGroup is the azure aci container group the container belongs to | String |
| PrismaCloudCompute.CloudDiscoveryAlert.entities.image | Image is the image of an aci container | String |
| PrismaCloudCompute.CloudDiscoveryAlert.collections | Collections are the matched result collections | String |
| PrismaCloudCompute.CloudDiscoveryAlert.accountID | AccountID is the cloud account ID | Date |
