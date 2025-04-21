Pings an IP or url address, to verify it's up. Note - On Cortex XSOAR 8 and Cortex XSIAM, the script can run only on a custom engine.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| address | Address to ping |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Ping.ret_code | Ping return code | number |
| Ping.destination | Ping destination address | string |
| Ping.max_rtt | Ping max round trip time | number |
| Ping.avg_rtt | Ping average round trip time | number |
| Ping.min_rtt | Ping minimum round trip time | number |
| Ping.destination_ip | Ping destination IP | string |
