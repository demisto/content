Checks to see if SNMP is enabled on the IP address provided.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.5.0 |

## Used In
---
This script is used in the following playbooks and scripts.
Cortex ASM - SNMP Check

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| ip_address | IP address. |
| time_out | Request timeout value, in seconds. Default value is 3 seconds. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SnmpDetection | Displays if SNMP version is enabled and gets the versions running. | Unknown |
