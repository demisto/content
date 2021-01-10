One of the most common issues when investigating an incident on a windows host is how to acquire the forensic evidence as quickly as possible as the incident is occurring. An analyst may need to login or remotely deploy an agent or applications such as Wireshark or begin copying files from the host. Often the investigation will take place after the malware was already executed and evidence deleted.

##### What does this pack do?
This pack provides an easy, quick and agentless method to acquire forensic data from windows hosts by leveraging builtin capabilities within windows such as Winrm and Powershell as the infrastructure and multiple other windows built in capabilities for creating the evidence.
The common use cases we cover in this pack are acquiring a network capture file from a host, acquiring the MFT (Master File Table) and the hosts registry. Once the objects are created we upload them to XSOAR and analyze accordingly.

The pack includes: 
The Powershell Remoting integration which allows you to interact with windows hosts for actions such as acquiring forensic data and much more.
The ETL2PCAP automation which converts ETL files (Windows native traffic recording format) to PCAP files that can be opened in Wireshark or XSOAR’s PCAP miner tool.
The Regipy Parse Forensic Data which allows you to parse registry hives in order to extract common data or specific data provided by the user.
Multiple playbooks for acquiring, parsing and analyzing data from windows hosts.

As part of this pack, you will also get out-of-the-box forensics incident type, and a layout. All of these are easily customizable to suit the needs of your organization.

_For more information, visit our  [Cortex XSOAR Developer Docs](https://xsoar.pan.XXXX)_

![Acquire And Analyze Host Forensics](https://raw.githubusercontent.com/demisto/content/master/Packs/Whois/doc_files/TIM_-_Process_Domains_With_Whois.png)
