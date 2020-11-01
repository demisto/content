Creates an Amazon EBS-backed AMI from an Amazon EBS-backed instance that is either running or stopped.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Amazon Web Services |


## Dependencies
---
This script uses the following commands and scripts.
* create-image

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| instanceId | The ID of the instance. |
| name | A name for the new image. There are constraints such as, 3-128 alphanumeric characters, parentheses (()), square brackets ([]), spaces ( ), periods (.), slashes (/), dashes (-), single quotes ('), at-signs (@), or underscores(_). |
| noReboot | By default, Amazon EC2 attempts to shut down and reboot the instance before creating the image. If the `No Reboot` option is set (give the value `true`). Amazon EC2 will not shut down the instance before creating the image. When this option is used, the file system integrity of the created image can't be guaranteed. |
| description | The description for the new image. |

## Outputs
---
There are no outputs for this script.
