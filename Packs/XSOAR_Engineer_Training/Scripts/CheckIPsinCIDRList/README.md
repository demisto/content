Determines whether an IPv4 address is contained in one or more comma-delimited CIDR ranges.  You can pass in an array of IPs, and the name of the XSOAR list containing the comma separated list of CIDRs or /32 addresses.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities, training |
| Cortex XSOAR Version | 6.8.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* XSOAR Engineer Training - Loop on Array Data

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| ips | IPv4 addresses to filter, you can pass in a single IP, or an array. |
| listname | XSOAR list name which contains the comma separated CIDR Ranges to check \(e.g. External IP Ranges\) |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| InCIDR.Address | IP Addresses in the CIDR Range | Unknown |
| InCIDR.In | The CIDR Range the IP was found in | Unknown |
