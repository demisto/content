Pings an IP address or URL address, to verify it's operational.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| address | The address to ping. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Ping.ret_code | The return code of the ping. | number |
| Ping.destination | The destination address of the ping. | string |
| Ping.max_rtt | The maximum round trip time of the ping. | number |
| Ping.avg_rtt | The average round trip time of the ping. | number |
| Ping.min_rtt | The minimum round trip time of the ping. | number |
| Ping.destination_ip | The destination IP address of the ping. | string |
