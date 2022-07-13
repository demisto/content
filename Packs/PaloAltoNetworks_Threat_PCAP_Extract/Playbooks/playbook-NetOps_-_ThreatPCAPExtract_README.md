Use the Palo Alto Networks Threat PCAP Extract playbook to automatically export PCAP from firewalls using either direct integration or via Panorama.

The playbook can be used as its own playbook (with incident close) or as a sub-playbook depending on the usecase
## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Panorama

### Scripts
* PcapMinerV2

### Commands
* setIncident
* print
* increaseIncidentSeverity
* pan-os-get-pcap
* closeInvestigation

## Playbook Inputs
---
* inc_details
* inc_severity
* proxy_via_panorama
* pan_os_ngfw_instance
* pan_os_pra_instance
* used_as_sub-playbook
* archive_pcap
* pcap_activity

## Playbook Outputs
---
* PCAPResults.Bytes
* PCAPResults.Packets
* PCAPResults.EntryID
* PCAPResults.StreamCount
* PCAPResults.StartTime
* PCAPResults.EndTime
* PCAPResults.UniqueSourceIP
* PCAPResults.UniqueDestIP
* PCAPResults.URL
* PCAPResults.IP
* PCAPResults.Email
* PCAPResults.Regex
* PCAPResults.Protocols
* PCAPResultsFlow
* PCAPResultsFlow.Bytes
* PCAPResultsFlow.DestIP
* PCAPResultsFlow.Transport
* PCAPResultsFlow.SourceIP
* PCAPResultsFlow.SourcePort
* PCAPResultsFlow.DestPort
* PCAPResultsFlow.Duration
* PCAPResultsFlow.EndTime
* PCAPResultsFlow.StartTime
* PCAPResultsHTTP
* PCAPResultsHTTP.ResponseStatusCode
* PCAPResultsHTTP.RequestVersion
* PCAPResultsHTTP.RequestCacheControl
* PCAPResultsHTTP.ResponseDate
* PCAPResultsHTTP.RequestMethod
* PCAPResultsHTTP.RequestSourceIP
* PCAPResultsHTTP.ResponseContentType
* PCAPResultsHTTP.RequestAgent
* PCAPResultsHTTP.RequestHost
* PCAPResultsHTTP.ResponseVersion
* PCAPResultsHTTP.ID
* PCAPResultsHTTP.EntryID
* PCAPResultsHTTP.RequestURI
* PCAPResultsHTTP.ResponseContentLength
* PCAPResultsHTTP.ResponseCodeDesc
* PCAPResultsDNS
* PCAPResultsDNS.ID
* PCAPResultsDNS.Request
* PCAPResultsDNS.Response
* PCAPResultsDNS.Type
* PCAPResultsDNS.EntryID
* PCAPResultsSMTP
* PCAPResultsSMTP.From
* PCAPResultsSMTP.To
* PCAPResultsSMTP.Subject
* PCAPResultsSMTP.MimeVersion
* PCAPResultsSMTP.ID
* PCAPResultsSMTP.EntryID
* PCAPResultsKERBEROS
* PCAPResultsKERBEROS.EntryID
* PCAPResultsKERBEROS.Realm
* PCAPResultsKERBEROS.SName
* PCAPResultsKERBEROS.CName
* PCAPResultsTelnet
* PCAPResultsTelnet.Data
* PCAPResultsTelnet.Commands
* PCAPResultsTelnet.EntryID
* PCAPResultsLLMNR
* PCAPResultsLLMNR.EntryID
* PCAPResultsLLMNR.QueryClass
* PCAPResultsLLMNR.QueryName
* PCAPResultsLLMNR.Questions
* PCAPResultsLLMNR.ID
* PCAPResultsLLMNR.QueryType
* PCAPResultsSYSLOG
* PCAPResultsSYSLOG.EntryID
* PCAPResultsSYSLOG.ID
* PCAPResultsSYSLOG.Message
* PCAPResultsSYSLOG.Hostname
* PCAPResultsSYSLOG.Timestamp
* PCAPResultsSMB2
* PCAPResultsSMB2.EntryID
* PCAPResultsSMB2.ID
* PCAPResultsSMB2.UserName
* PCAPResultsSMB2.Domain
* PCAPResultsSMB2.HostName
* PCAPResultsSMB2.Command
* PCAPResultsSMB2.FileName
* PCAPResultsSMB2.Tree
* PCAPResultsNETBIOS
* PCAPResultsNETBIOS.EntryID
* PCAPResultsNETBIOS.ID
* PCAPResultsNETBIOS.Name
* PCAPResultsNETBIOS.Type
* PCAPResultsNETBIOS.Class
* PCAPResultsIRC
* PCAPResultsIRC.EntryID
* PCAPResultsIRC.ID
* PCAPResultsIRC.RequestCommand
* PCAPResultsIRC.RequestTrailer
* PCAPResultsIRC.RequestPrefix
* PCAPResultsIRC.RequestParameters
* PCAPResultsIRC.ResponseCommand
* PCAPResultsIRC.ResponseTrailer
* PCAPResultsIRC.ResponsePrefix
* PCAPResultsIRC.ResponseParameters
* PCAPResultsFTP
* PCAPResultsFTP.EntryID
* PCAPResultsFTP.ID
* PCAPResultsFTP.RequestCommand
* PCAPResultsFTP.ResponseArgs
* PCAPResultsFTP.ResponseCode
* PCAPResultsICMP
* PCAPResultsSSH
* PCAPResultsSSH.EntryID
* PCAPResultsSSH.ClientProtocols
* PCAPResultsSSH.ServerProtocols
* PCAPResultsSSH.KeyExchangeMessageCode




## Playbook Image
---
