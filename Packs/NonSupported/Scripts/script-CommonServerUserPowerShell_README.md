Common user-defined code that is merged into each script and integration during execution. You can use this script to define functions that are used by scripts and integrations. For example you can add a common error function for logging which wraps `$demisto.Error` and includes extra environment information. Then you can call this function in custom integrations and scripts.  

**Note:** The code is not merged into system integrations. It is only merged into scripts (custom/system) and custom integrations.  

**Server 6.5 and above**: To disable merging the code into system scripts, set the `content.oob.script.use_common_user` advanced Server parameter to `false`.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | powershell |
| Tags | infra, server |
| Cortex XSOAR Version | 5.5.0+ |

## Inputs
---
There are no inputs for this script.

## Outputs
---
There are no outputs for this script.
