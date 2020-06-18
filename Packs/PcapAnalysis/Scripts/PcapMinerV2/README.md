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
| PCAPResults.Bytes | The number of bytes transmitted in the PCAP file. | Number |
| PCAPResults.Packets | The number of packets transmitted in the PCAP file. | Number |
| PCAPResults.EntryID | The entryID of the PCAP file. | String |
| PCAPResults.StreamCount | The number of streams in the PCAP file. | String |
| PCAPResults.StartTime | The date and time of the first packet in the PCAP file. | Date |
| PCAPResults.EndTime | The date and time of the last packet in the PCAP file. | String |
| PCAPResults.UniqueSourceIP | The number of unique IPs from which packets were transmitted. | Number |
| PCAPResults.UniqueDestIP | The number of unique IPs from to packets were transmitted. | Number |
| PCAPResultsFlow.Bytes | The number of bytes transmitted in the flow. | String |
| PCAPResultsFlow.DestIP | The destination IP of the flow. | String |
| PCAPResultsFlow.SourceIP | The source IP of the flow. | String |
| PCAPResultsFlow.Transport | The transport protocol of the flow. | String|
| PCAPResultsFlow.SourcePort | The source port of the flow. | String |
| PCAPResultsFlow.DestPort | The destination port of the flow. | String |
| PCAPResultsFlow.Duration | The duration of the flow \(in seconds\). | String |
| PCAPResultsFlow.EndTime | The date/time the flow ended. | Date |
| PCAPResultsFlow.StartTime | The date/time the flow started. | Date |
| PCAPResults.URL | The URLs extracted from the file. | String |
| PCAPResults.IP | The IPs extracted from the file. | String |
| PCAPResults.Email | The emails extracted from the file. | String |
| PCAPResults.Regex | The regular expressions specified in \`extract\_regex\` extracted from the file. | String |
| PCAPResultsHTTP.ResponseStatusCode | The response code. | String |
| PCAPResultsHTTP.RequestVersion | The request version. | String |
| PCAPResultsHTTP.RequestCacheControl | The cache control of the request. | String |
| PCAPResultsHTTP.ResponseDate | The date/time of the response. | Date |
| PCAPResultsHTTP.RequestMethod | The request method. | String |
| PCAPResultsHTTP.RequestSourceIP | The source IP of the request. | String |
| PCAPResultsHTTP.ResponseContentType | The response content type. | String |
| PCAPResultsHTTP.RequestAgent | The request agent. | String |
| PCAPResultsHTTP.RequestHost | The request host. | String |
| PCAPResultsHTTP.ResponseVersion | The response version. | String |
| PCAPResultsHTTP.ID | The ID of the HTTP interaction. | String |
| PCAPResultsHTTP.EntryID | The PCAP entry ID. | String |
| PCAPResultsHTTP.RequestURI | The request URI. | String |
| PCAPResultsHTTP.ResponseContentLength | The length of the response content. | String |
| PCAPResultsHTTP.ResponseCodeDesc | The code description of the response. | String |
| PCAPResultsDNS.ID | The ID of the DNS request. | String |
| PCAPResultsDNS.Request | The DNS request. | String |
| PCAPResultsDNS.Response | The DNS response. | String |
| PCAPResultsDNS.Type | The type of the DNS request. | String |
| PCAPResultsDNS.ID | The DNS packet ID. | String |
| PCAPResultsDNS.EntryID | The PCAP entry ID. | String |
| PCAPResults.Protocols | List of protocols found in the PCAP. | String |
| PCAPResultsSMTP.From | The mail sender. | String |
| PCAPResultsSMTP.To | The mail recipients. | String |
| PCAPResultsSMTP.Subject | The mail subject. | String |
| PCAPResultsSMTP.MimeVersion | The mime version. | String |
| PCAPResultsSMTP.ID | The SMTP packet's ID. | String |
| PCAPResultsSMTP.EntryID | The PCAP entry ID. | String |
| PCAPResultsKERBEROS.EntryID | The PCAP entry ID. | String |
| PCAPResultsKERBEROS.Realm | The KERBEROS realm. | String |
| PCAPResultsKERBEROS.SName | The KERBEROS SName. | String |
| PCAPResultsKERBEROS.CName | The KERBEROS CName. | String |
| PCAPResultsTelnet.Data | The telnet data. | String |
| PCAPResultsTelnet.Commands | The telnet commands. | String |
| PCAPResultsTelnet.EntryID | The PCAP entry ID. | String |
| PCAPResultsLLMNR.EntryID | The PCAP entry ID. | String |
| PCAPResultsLLMNR.QueryClass | The LLMNR query class. | String |
| PCAPResultsLLMNR.QueryName | The LLMNR query name. | String |
| PCAPResultsLLMNR.Questions | The LLMNR questions. | String |
| PCAPResultsLLMNR.ID | The LLMNR packet ID. | String |
| PCAPResultsLLMNR.QueryType | The LLMNR query type. | String |
| PCAPResultsSYSLOG.EntryID | The PCAP entry ID. | String |
| PCAPResultsSYSLOG.ID | The SYSLOGS packet ID. | String |
| PCAPResultsSYSLOG.Message | The SYSLOGS message. | String |
| PCAPResultsSYSLOG.Hostname | The SYSLOGS host name. | String |
| PCAPResultsSYSLOG.Timestamp | The SYSLOGS time stamp. | String |
| PCAPResultsSMB2.EntryID | The PCAP entry ID. | String |
| PCAPResultsSMB2.ID | The SMB2 packet ID. | String |
| PCAPResultsSMB2.UserName | The SMB2 user name. | String |
| PCAPResultsSMB2.Domain | The SMB2 domain. | String |
| PCAPResultsSMB2.HostName | The SMB2 host name. | String |
| PCAPResultsSMB2.Command | The SMB2 command. | String |
| PCAPResultsSMB2.FileName | The SMB2 file name. | String |
| PCAPResultsSMB2.Tree | The SMB2 tree. | String |
| PCAPResultsNETBIOS.EntryID | The PCAP entry ID. | String |
| PCAPResultsNETBIOS.ID | The NETIOS packet ID. | String |
| PCAPResultsNETBIOS.Name | The NETIOS name. | String |
| PCAPResultsNETBIOS.Type | The NETIOS type. | String |
| PCAPResultsNETBIOS.Class | The NETIOS class. | String |
| PCAPResultsIRC.EntryID | The PCAP entry ID. | String |
| PCAPResultsIRC.ID | The IRC packet ID. | String |
| PCAPResultsIRC.RequestCommand | The IRC request command. | String |
| PCAPResultsIRC.RequestTrailer | The IRC request trailer. | String |
| PCAPResultsIRC.RequestPrefix | The IRC request prefix. | String |
| PCAPResultsIRC.RequestParameters | The IRC request parameters. | String |
| PCAPResultsIRC.ResponseCommand | The IRC response command. | String |
| PCAPResultsIRC.ResponseTrailer | The IRC response trailers. | String |
| PCAPResultsIRC.ResponsePrefix | The IRC response prefix. | String |
| PCAPResultsIRC.ResponseParameters | The IRC response parameters. | String |
| PCAPResultsFTP.EntryID | The PCAP entry ID. | String |
| PCAPResultsFTP.ID | The FTP packet ID. | String |
| PCAPResultsFTP.RequestCommand | The FTP request command. | String |
| PCAPResultsFTP.ResponseArgs | The FTP response arguments. | String |
| PCAPResultsFTP.ResponseCode | The FTP response code. | String |
| PCAPResultsICMP | ICMP data. | String |
| PCAPResultsSSH.EntryID | The PCAP's entry ID. | String |
| PCAPResultsSSH.ClientProtocols | The SSH client protocols in the PCAP. | String |
| PCAPResultsSSH.ServerProtocols | The SSH server protocols in the PCAP. | String |
| PCAPResultsSSH.KeyExchangeMessageCode | The SSH key exchange message codes. | String |
