A common use case in incident response and forensics is analyzing network traffic and protocols by using network packet capture files as part of an investigation. PCAP files provide all the critical traffic data such as IP addresses in use, protocols, as well as the actual payload of the traffic itself. 
The PCAP Analysis pack includes the PCAP Miner V2 script, as well as playbooks that automate the process of searching for and summarizing data within PCAP files, extracting indicators, decrypting traffic, and more. Cortex XSOAR can leverage the power of Wireshark to parse, search, and extract data from PCAP files. 
With this content pack, you can significantly reduce the time and effort by automating the process of analyzing PCAP files and not miss out on critical data that can be extracted from them.
The PCAP Analysis playbook is meant to demonstrate the full range of PCAP analysis capabilities, however, the most common use case is to use each of the sub-playbooks separately. Review each playbook README for configuration details. 

##### What does this pack do?

The script and playbooks included in this pack help you automate repetitive tasks associated with PCAP files:
- Search PCAP files for common objects such as IP addresses, ports, protocols, or custom search filters just like in Wireshark.
- Search for specific regex patterns with the payload.
- Parse and extract protocol-specific data for several common protocols such as DNS, HTTP, and many more.
- Display summarized search results.
- Decrypt various encrypted traffic such as SSL and WPA (as long as decryption keys are provided).
- Extract indicators such as IP addresses, URLs, domains, and files from the payload and perform enrichment on those indicators.

_We encourage you to [learn more about the PCAP Analysis playbook](https://xsoar.pan.dev/docs/reference/playbooks/pcap-analysis)_

## Demo Video
[![PCAP Analysis in Cortex XSOAR](https://img.youtube.com/vi/VDUdBmGuVYQ/0.jpg)](https://www.youtube.com/watch?v=VDUdBmGuVYQ "PCAP Analysis in Cortex XSOAR")

