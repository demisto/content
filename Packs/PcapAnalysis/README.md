A common use case in incident response and forensics is analysing network traffic and protocols by using networks packet capture files as part of an investigation. PCAP files provide all the critical traffic data such as IP addresses in use, protocols, as well as the actual payload of the traffic itself. 
The PCAP Analysis pack includes the PCAP Miner V2 script as well as playbooks that automate the process of searching for and summarizing data within PCAP files, extracting indicators, decrypting traffic and more. Cortex XSOAR can leverage the power of Wireshark in order to perform parsing, searching and extraction of data from PCAP files. 
With this content pack, you can significantly reduce the time and effort by automating the process of analysing PCAP files and not miss out on critical data that can be extracted from them.

#####What does this pack do?

The script and playbooks included in this pack help you automate repetitive tasks associated with PCAP files:
Searching PCAP files for common objects such as IP addresses, ports, protocols, or custom search filters just like in Wireshark.

- Searching for specific regex patterns with the payload.
- Parsing and extracting protocol specific data for several common protocols such as DNS, HTTP and many more.
- Displaying summarized search results.
- Decrypting various encrypted traffic such as SSL and WPA (provided decryption keys are provided).
- Extracting indicators such as IP addresses, URLs, domain, files from the payload and performing enrichment on those indicators.

_For more information, visit our [Cortex XSOAR Developer Docs](https://xsoar.pan.dev/docs/reference/playbooks)_