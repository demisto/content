Checks if the Docker container running this script has been hardened according to the recommended settings located [here](https://support.demisto.com/hc/en-us/articles/360040922194)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Demisto Version | 5.0.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| memory | The amount of memory to check. This is specified in bytes or append MB/GB for Mega/Giga bytes. The default is 1 GB. |
| pids | The maximum number of PIDs to check. |
| fds_soft | The soft file descriptor limit to check. |
| fds_hard | The hard file descriptor limit to check. |
| cpus | The number of CPUs limit to check. |

## Outputs
---
There are no outputs for this script.
