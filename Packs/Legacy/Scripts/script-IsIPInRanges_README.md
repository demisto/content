Returns "yes" if the IP address is within one of the ranges provided. Otherwise it will return "no".

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | ip |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| ip | The IP address to check in ranges. |
| ipRanges | The list of IP address ranges to check the IP addresses in. The list should be provided in CIDR notation, separated by commas. For example, "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" (without quotes). If a list is not provided, it will use a default list provided in the `IsIPInRanges` script (the known IPv4 private address ranges). |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| yes | Whether a given value is within an IP address range. | Unknown |
| no | Whether a given value is not within an IP address range. | Unknown |
| IP.Address | The IP address. | Unknown |
| IP.InRange | Whether the IP address is within the input ranges. Can be, "yes" or "no".) | Unknown |
