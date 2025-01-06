Checks if the Docker container running this script has been hardened according to the recommended settings located in the [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide).

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0+ |

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
| network_check | The network check to perform. cloud_metadata - check that access is blocked to cloud metadata server, host_machine - check that access is blocked to the host machine on the default gateway IP, all - perform all network tests. |

## Outputs
---
There are no outputs for this script.

## Notes
* **Network Host Check:** The network host check only checks available access on the default gateway's IP using an https request to port 443. There still may be access available to the host network either on a different IP or port and this check will not detect it.