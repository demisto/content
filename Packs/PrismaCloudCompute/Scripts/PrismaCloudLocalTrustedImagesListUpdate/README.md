Takes the results of "prisma-cloud-compute-images-scan-list" and "prisma-cloud-ci-scan-results-list" commands and creates or updates a list of trusted images which can be used for updating the "Trusted Images" list in Prisma Cloud, using the PrismaCloudRemoteTrustedImagesListUpdate automation.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.9.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| list_name | The name of the Cortex XSOAR internal list to update or create in case it doesn't exist. |
| deployed_images | The results of the "prisma-cloud-compute-images-scan-list" command. |
| passed_ci_scan_images | The "entityInfo" results of the "prisma-cloud-compute-ci-scan-results-list" command. |
| time_frame | The time passed since the last time an image was updated based on the given deployed_images and passed_ci_scan_images inputs. If an image wasn't updated in this timeframe, it will be deleted from the list. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: '2019-10-21T23:45:00' (ISO date format), '3 days ago' (relative time), 1579039377301 (epoch time). |

## Outputs

---
There are no outputs for this script.
