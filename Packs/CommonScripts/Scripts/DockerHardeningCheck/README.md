Checks if the Docker container running this script has been hardened according to the recommended settings located [here](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/cortex-xsoar-admin/docker/docker-hardening-guide.html).

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
| memory_check | The memory check type to perform: cgroup - check memory cgroup configuration, allocate - try allocating actual memory and verify that the allocation fails. Note the allocate test on some configurations may cause the container to be killed by the linux memory manager and the whole test will then time out. |
| pids | The maximum number of PIDs to check. |
| fds_soft | The soft file descriptor limit to check. |
| fds_hard | The hard file descriptor limit to check. |
| cpus | The number of CPUs limit to check. |

## Outputs
---
There are no outputs for this script.
