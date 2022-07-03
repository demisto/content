Extract payloads of each stream from a pcap file.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | pcap, file, Utility |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | The entry_id of the pcap file from which to extract streams. |
| bin2txt_mode | The mode of how to convert the binary to text. |
| pcap_filter | Filter to apply on pcap. Wireshark syntax as can be found here: https://www.wireshark.org/docs/man-pages/wireshark-filter.html |
| rsa_decrypt_key_entry_id | The entry ID for the RSA decryption key. |
| wpa_password | The WPA password. By providing the password you will be able to decrypt encrypted traffic data. |
| filter_keys | Keys of output items by which to filter them. |
| verbose | Set to true to generate stream entries, otherwise false. |
| server_ports | Default server port numbers by which to decide the direction. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PCAPStream.protocol | Protocol. | string |
| PCAPStream.client_ip | Client IP address. | string |
| PCAPStream.client_port | Client port number. | number |
| PCAPStream.server_ip | Server IP address. | string |
| PCAPStream.server_poprt | Server port nream data in bytes. | number |
| PCAPStream.stream_text | The data stream in text. | string |
| PCAPStream.stream_base64 | The data stream in base64. | string |
| PCAPStream.outgoing_size | Size of the outgoing data in bytes. | number |
| PCAPStream.outgoing_text | The outgoing data stream in text. | string |
| PCAPStream.outgoing_base64 | The outgoing data stream in base64. | string |
| PCAPStream.incoming_size | Size of the incoming data in bytes. | number |
| PCAPStream.incoming_text | The incoming data stream in text. | string |
| PCAPStream.incoming_base64 | The incoming data stream in base64. | string |
