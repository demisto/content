PcapMIner V2 allows to parse PCAP files by displaying the all of the relevant data within including ip addresses, ports, flows, specific protocol breakdown, searching by regex, decrypting encrypted  traffic and more.
This automation takes about a minute to process 20,000 packets (which is approximately 10MB). If you want to mine large files you can either:
a) Use the `pcap_filter` parameter to filter your PCAP file and thus make is smaller.
b) Copy the automation and change the `default timeout` parameter to match your needs.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | pcap, mine, file, Utility |
| Demisto Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | The entry\_id of the PCAP file to mine. |
| protocol_output | A comma\-separated list of protocols to output as context. If empty, will not output any protocols to context. |
| extract_strings | Whether to extract IP, URL, and Email from PCAP file. Can be "True" or "False". |
| pcap_filter | Filter to apply on PCAP. Wireshark syntax as can be found here: https://www.wireshark.org/docs/man\-pages/wireshark\-filter.html |
| custom_regex | Your own regular expression to extract from the PCAP. |
| filtered_file_name | The name of the PCAP file to save to the War Room after applying the \`pcap\_filter\` \(i.e. \`filtered\_file.pcap\`\). |
| rsa_decrypt_key_entry_id | The entry ID for the RSA decryption key. |
| convs_to_display | Number of conversations to display. The default is 15. |
| wpa_password | The WPA password. By providing the password you will be able to decrypt encrypted traffic data. |
| extract_ips | Output to context the source and destination IPs in the PCAP file. Can be "True" or "False". The default is "False". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PcapResults.Bytes | The number of bytes transmitted in the PCAP file. | Number |
| PcapResults.Packets | The number of packets transmitted in the PCAP file. | Number |
| PcapResults.EntryID | The entryID of the PCAP file. | String |
| PcapResults.StreamCount | The number of streams in the PCAP file. | String |
| PcapResults.StartTime | The date and time of the first packet in the PCAP file. | Date |
| PcapResults.EndTime | The date and time of the last packet in the PCAP file. | String |
| PcapResults.UniqueSourceIP | The number of unique IPs from which packets were transmitted. | Number |
| PcapResults.UniqueDestIP | The number of unique IPs from to packets were transmitted. | Number |
| PcapResultsFlow.Bytes | The number of bytes transmitted in the flow. | String |
| PcapResultsFlow.DestIP | The destination IP of the flow. | String |
| PcapResultsFlow.SourceIP | The source IP of the flow. | String |
| PcapResultsFlow.Transport | The transport protocol of the flow. | String|
| PcapResultsFlow.SourcePort | The source port of the flow. | String |
| PcapResultsFlow.DestPort | The destination port of the flow. | String |
| PcapResultsFlow.Duration | The duration of the flow \(in seconds\). | String |
| PcapResultsFlow.EndTime | The date/time the flow ended. | Date |
| PcapResultsFlow.StartTime | The date/time the flow started. | Date |
| PcapResults.URL | The URLs extracted from the file. | String |
| PcapResults.IP | The IPs extracted from the file. | String |
| PcapResults.Email | The emails extracted from the file. | String |
| PcapResults.Regex | The regular expressions specified in \`extract\_regex\` extracted from the file. | String |
| PcapResultsHTTP.ResponseStatusCode | The response code. | String |
| PcapResultsHTTP.RequestVersion | The request version. | String |
| PcapResultsHTTP.RequestCacheControl | The cache control of the request. | String |
| PcapResultsHTTP.ResponseDate | The date/time of the response. | Date |
| PcapResultsHTTP.RequestMethod | The request method. | String |
| PcapResultsHTTP.RequestSourceIP | The source IP of the request. | String |
| PcapResultsHTTP.ResponseContentType | The response content type. | String |
| PcapResultsHTTP.RequestAgent | The request agent. | String |
| PcapResultsHTTP.RequestHost | The request host. | String |
| PcapResultsHTTP.ResponseVersion | The response version. | String |
| PcapResultsHTTP.ID | The ID of the HTTP interaction. | String |
| PcapResultsHTTP.EntryID | The PCAP entry ID. | String |
| PcapResultsHTTP.RequestURI | The request URI. | String |
| PcapResultsHTTP.ResponseContentLength | The length of the response content. | String |
| PcapResultsHTTP.ResponseCodeDesc | The code description of the response. | String |
| PcapResultsDNS.ID | The ID of the DNS request. | String |
| PcapResultsDNS.Request | The DNS request. | String |
| PcapResultsDNS.Response | The DNS response. | String |
| PcapResultsDNS.Type | The type of the DNS request. | String |
| PcapResultsDNS.ID | The DNS packet ID. | String |
| PcapResultsDNS.EntryID | The PCAP entry ID. | String |
| PcapResults.Protocols | List of protocols found in the PCAP. | String |
| PcapResultsSMTP.From | The mail sender. | String |
| PcapResultsSMTP.To | The mail recipients. | String |
| PcapResultsSMTP.Subject | The mail subject. | String |
| PcapResultsSMTP.MimeVersion | The mime version. | String |
| PcapResultsSMTP.ID | The SMTP packet's ID. | String |
| PcapResultsSMTP.EntryID | The PCAP entry ID. | String |
| PcapResultsKERBEROS.EntryID | The PCAP entry ID. | String |
| PcapResultsKERBEROS.Realm | The KERBEROS realm. | String |
| PcapResultsKERBEROS.SName | The KERBEROS SName. | String |
| PcapResultsKERBEROS.CName | The KERBEROS CName. | String |
| PcapResultsTelnet.Data | The telnet data. | String |
| PcapResultsTelnet.Commands | The telnet commands. | String |
| PcapResultsTelnet.EntryID | The PCAP entry ID. | String |
| PcapResultsLLMNR.EntryID | The PCAP entry ID. | String |
| PcapResultsLLMNR.QueryClass | The LLMNR query class. | String |
| PcapResultsLLMNR.QueryName | The LLMNR query name. | String |
| PcapResultsLLMNR.Questions | The LLMNR questions. | String |
| PcapResultsLLMNR.ID | The LLMNR packet ID. | String |
| PcapResultsLLMNR.QueryType | The LLMNR query type. | String |
| PcapResultsSYSLOG.EntryID | The PCAP entry ID. | String |
| PcapResultsSYSLOG.ID | The SYSLOGS packet ID. | String |
| PcapResultsSYSLOG.Message | The SYSLOGS message. | String |
| PcapResultsSYSLOG.Hostname | The SYSLOGS host name. | String |
| PcapResultsSYSLOG.Timestamp | The SYSLOGS time stamp. | String |
| PcapResultsSMB2.EntryID | The PCAP entry ID. | String |
| PcapResultsSMB2.ID | The SMB2 packet ID. | String |
| PcapResultsSMB2.UserName | The SMB2 user name. | String |
| PcapResultsSMB2.Domain | The SMB2 domain. | String |
| PcapResultsSMB2.HostName | The SMB2 host name. | String |
| PcapResultsSMB2.Command | The SMB2 command. | String |
| PcapResultsSMB2.FileName | The SMB2 file name. | String |
| PcapResultsSMB2.Tree | The SMB2 tree. | String |
| PcapResultsNETBIOS.EntryID | The PCAP entry ID. | String |
| PcapResultsNETBIOS.ID | The NETIOS packet ID. | String |
| PcapResultsNETBIOS.Name | The NETIOS name. | String |
| PcapResultsNETBIOS.Type | The NETIOS type. | String |
| PcapResultsNETBIOS.Class | The NETIOS class. | String |
| PcapResultsIRC.EntryID | The PCAP entry ID. | String |
| PcapResultsIRC.ID | The IRC packet ID. | String |
| PcapResultsIRC.RequestCommand | The IRC request command. | String |
| PcapResultsIRC.RequestTrailer | The IRC request trailer. | String |
| PcapResultsIRC.RequestPrefix | The IRC request prefix. | String |
| PcapResultsIRC.RequestParameters | The IRC request parameters. | String |
| PcapResultsIRC.ResponseCommand | The IRC response command. | String |
| PcapResultsIRC.ResponseTrailer | The IRC response trailers. | String |
| PcapResultsIRC.ResponsePrefix | The IRC response prefix. | String |
| PcapResultsIRC.ResponseParameters | The IRC response parameters. | String |
| PcapResultsFTP.EntryID | The PCAP entry ID. | String |
| PcapResultsFTP.ID | The FTP packet ID. | String |
| PcapResultsFTP.RequestCommand | The FTP request command. | String |
| PcapResultsFTP.ResponseArgs | The FTP response arguments. | String |
| PcapResultsFTP.ResponseCode | The FTP response code. | String |
| PcapResultsICMP | ICMP data. | String |
| PcapResultsSSH.EntryID | The PCAP's entry ID. | String |
| PcapResultsSSH.ClientProtocols | The SSH client protocols in the PCAP. | String |
| PcapResultsSSH.ServerProtocols | The SSH server protocols in the PCAP. | String |
| PcapResultsSSH.KeyExchangeMessageCode | The SSH key exchange message codes. | String |
