DEPRECATED - This playbook has been deprecated. Use Endace Search Archive Download PCAP v2 instead. This playbook uses Endace APIs to search, archive and download PCAP file from either a single EndaceProbe or many via the InvestigationManager.      The workflow accepts inputs like “the date and time of the incident or a timeframe”, “source or destination IP address of the incident”,  “source or destination IP port of the incident”,  “protocol of the incident” and name of archive file. 
The Workflow in this playbook : 
1. Finds the packet history related to the search items. Multiple Search Items in an argument field are OR'd. Search Items between multiple arguments are AND'd. 
2.  A successful Search is followed by an auto archival process of matching packets on EndaceProbe which can be accessed from an investigation link on the Evidence Board and/or War Room board that can be used to start forensic analysis of the packets history on EndaceProbe.
3. Finally Download the archived PCAP file to XSOAR system provided the file size is less than a user defined threshold say 10MB. Files greater than 10MB can be accessed or analyzed on EndaceProbe via "Download PCAP link" or "Endace PivotToVision link" displayed on Evidence Board.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Endace

### Scripts
* AreValuesEqual
* AddEvidence
* IsGreaterThan

### Commands
* endace-get-archive-status
* endace-delete-archived-file
* endace-create-archive
* endace-create-search
* endace-download-pcap

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| start | Event Start Time in ISO 8601 format as in 2020\-04\-08T15:46:30 |  | Optional |
| end | Event End Time in ISO 8601 format  as in 2020\-04\-08T15:46:30 |  | Optional |
| src_host_list | List of comma delimited Source IP addresses to search with a maximum of 10 IP addresses per search. For valid search either a Src Host or a Dest Host value is required. |  | Optional |
| dest_host_list | List of comma delimited Destination IP addresses to search with a maximum of 10 IP addresses per search. For valid search either a Src Host or a Dest Host value is required. |  | Optional |
| src_port_list | List of comma delimited Source Port addresses to search with a maximum of 10 Port addresses per search. |  | Optional |
| dest_port_list | List of comma delimited Destination Port addresses to search with a maximum of 10 Port addresses per search. |  | Optional |
| protocol | IANA defined IP Protocol Name or Number. For example \- either use TCP or tcp or 6 for tcp protocol |  | Optional |
| timeframe | Event timeframe to search \- in seconds.  Timeframe works as search for last "n" seconds if start and end time is not provided. For example, by specifying 3600 seconds as the timeframe, analyst can schedule a search for last 1 hour. If both start and end time is provided, timeframe value is ignored. If either start or end time is provided along with timeframe, the respective start or end time is calculated accordingly. |  | Optional |
| archive_filename | Name of the archive file. For example, archive\_filename could be an event ID. To keep archive filename unique, value of epoch seconds at the time of execution of the command is appended to this filename argument. For example \- if the event id is 123456789, then archive\_filename is 123456789\-&lt;epochtime&gt;. |  | Optional |
| delete_archive | Delete archived file 0: Don't delete archived file. 1: Delete archived file. By default archived files on EndaceProbe won't be deleted |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Endace Search Archive Download PCAP](https://raw.githubusercontent.com/demisto/content/6076f09ff5093102f383da8c11dfce0b12331d82/Packs/Endace/doc_imgs/playbook_Endace_Search_Archive_Download_PCAP.png)