Extract payloads of each stream from a pcap.
The payloads will be retrieved with an array of dictionaries of these keys:
- protocol
- client_ip
- client_port
- server_ip
- server_port
- stream_size
- stream_text
- stream_base64
- outgoing_size
- outgoing_text
- outgoing_base64
- incoming_size
- incoming_text
- incoming_base64

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
| value | The data of a pcap in base64 from which to extract streams. |
| path | The context path to the pcap (e.g., PcapData.pcap). If you add a comma plus a node name after the path, the output will be set to the node (e.g., PcapData.pcap,out). |
| pcap_type | The data type of the pcap data. |
| bin2txt_mode | The mode of how to convert the binary to text |
| pcap_filter | Filter to apply on PCAP. Wireshark syntax as can be found here: https://www.wireshark.org/docs/man-pages/wireshark-filter.html |
| rsa_decrypt_key | The RSA decryption key in base64. |
| wpa_password | The WPA password. By providing the password you will be able to decrypt encrypted traffic data. |
| filter_keys | Keys of output items by which to filter them. |
| error_action | The action on error to parsing pcap. Possible values are abort \(default\), ignore, and keep. |
| server_ports | Default server port numbers by which to decide the direction. |

## Outputs
---
There are no outputs for this script.
