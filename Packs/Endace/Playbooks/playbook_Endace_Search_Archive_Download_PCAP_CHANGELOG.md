## [Unreleased]


## [20.5.0] - 2020-05-12
#### New Playbook
This playbook uses Endace APIs to search, archive and download PCAP file from either a single EndaceProbe or many via the InvestigationManager.      The workflow accepts inputs like “the date and time of the incident or a timeframe”, “source or destination IP address of the incident”,  “source or destination IP port of the incident”,  “protocol of the incident” and name of archive file. 
The Workflow in this playbook : 
1. Finds the packet history related to the search items. Multiple Search Items in an argument field are OR'd. Search Items between multiple arguments are AND'd. 
2.  A successful Search is followed by an auto archival process of matching packets on EndaceProbe which can be accessed from an investigation link on the Evidence Board and/or War Room board that can be used to start forensic analysis of the packets history on EndaceProbe.
3. Finally Download the archived PCAP file to XSOAR system provided the file size is less than a user defined threshold say 10MB. Files greater than 10MB can be accessed or analyzed on EndaceProbe via "Download PCAP link" or "Endace PivotToVision link" displayed on Evidence Board.
