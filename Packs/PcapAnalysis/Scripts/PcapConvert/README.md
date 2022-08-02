Convert packet data to the standard pcap. Currently it only supports CDL(NGFW) pcap from which to convert.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | pcap, Utility, transformer |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The value to be converted from. |
| path | The context path to the pcap (e.g., PcapData.pcap). If you add a comma + a node name after the path, the output will be set to the node (e.g., PcapData.pcap,out). |
| pcap_type | The data type of the pcap data. |
| error_action | The action on error to parsing pcap. Possible values are abort \(default\), ignore, and keep. |

## Outputs
---
There are no outputs for this script.
