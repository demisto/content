Executes a test for all integration instances available and returns a detailed table with information about any failed integration instances.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | - |
| Demisto Version | 4.0.0+ |

## Inputs
---
There are no inputs for this script.

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| FailedInstances.instance | The name of the failed integration instance. | string |
| FailedInstances.brand | The brand of the failed integration instance. | string |
| FailedInstances.category | The category of the failed integration instance. | string |
| FailedInstances.information | The error information of the failed integration instance. | string |
| FailedInstances.status | Status of the instance. | string |
| FailedInstances.failureCount | The number of failed instances. | string |
| FailedInstances.successCount | The number of working instances. | string |
| FailedInstances.totalCount | The number of total enabled instances. | string |
