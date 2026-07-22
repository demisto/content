Gets the existing "Trusted Images" results from Prisma Cloud Compute and updates the relevant trust group with the images stored in the given internal list.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.9.0 |

## Dependencies

---
This script uses the following commands and scripts.

* PaloAltoNetworks_PrismaCloudCompute
* prisma-cloud-compute-trusted-images-update

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| list_name | The name of the XSOAR internal list we wish to use in order to update the remote trust images list. |
| trusted_group_id | The trusted group which should be updated with the images of the given list. In order to get the trusted groups ID, either use the Prisma Cloud UI \(the ID would be the group name\) or use the "prisma-cloud-compute-trusted-images-list" command. |
| current_trusted_images | The current state of the trusted images in Prisma Cloud. Can be retrieved with the "prisma-cloud-compute-trusted-images-list" command. |

## Outputs

---
There are no outputs for this script.
