This playbook uses Endace APIs to search, archive and download PCAP file from either a single EndaceProbe or many via the InvestigationManager.      The workflow accepts inputs like “the date and time of the incident or a timeframe”, “source or destination IP address of the incident”,  “source or destination IP port of the incident”,  “protocol of the incident” and name of archive file. 
Required Inputs -
Either timeframe  or start and timeframe or end and timeframe or start and end fields. 
Either src_host_list or dest_host_list or ip fields. 
Either src_port_list or dest_port_list or port fields. 
archive_filename field is required
delete_archive field  is required
download_threshold field is required

The Workflow in this playbook : 
1. Finds the packet history related to the search items. Multiple Search Items in an argument field are OR'd. Search Items between multiple arguments are AND'd. 
2.  A successful Search is followed by an auto archival process of matching packets on EndaceProbe which can be accessed from an investigation link on the Evidence Board and/or War Room board that can be used to start forensic analysis of the packets history on EndaceProbe.
3. Finally Download the archived PCAP file to XSOAR system provided the file size is less than a user defined threshold say 10MB. Files greater than this threshold can be accessed or analyzed on EndaceProbe via "Download PCAP link" or "Endace PivotToVision link" displayed on Evidence Board.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Endace

### Scripts
* IsGreaterThan
* IsTrue
* Set
* AreValuesEqual
* Print
* AddEvidence

### Commands
* endace-create-archive
* endace-create-search
* endace-delete-archived-file
* endace-get-archive-status
* endace-download-pcap

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| start | UTC StartTime in ISO 8601 format as in 2020\-04\-08T15:46:30 |  | Optional |
| end | UTC EndTime in ISO 8601 format  as in 2020\-04\-08T15:46:30 |  | Optional |
| timeframe | Event timeframe to search. Select one of the values from  30seconds, 1minute, 5minutes, 10minutes, 30minutes, 1hour, 2hours, 5hours, 10hours, 12hours, 1day, 3days, 5days, 1week. Timeframe works as search for last n seconds if start and end time is not provided. For example, by specifying 1h as the timeframe, analyst can schedule a search for last 3600s. If both start and end time is provided, timeframe value is ignored. If either start or end time is provided along with timeframe, the respective start or end time is calculated accordingly. Initial value of timeframe is 1hour. |  | Optional |
| ip | directionless ip address. For valid search either a IP or Src Host or a Dest Host value is required |  | Optional |
| port | directionless port.  |  | Optional |
| src_host_list | List of comma delimited Source IP addresses to search with a maximum of 10 IP addresses per search. For valid search either a Src Host or a Dest Host value is required. |  | Optional |
| dest_host_list | List of comma delimited Destination IP addresses to search with a maximum of 10 IP addresses per search. For valid search either a Src Host or a Dest Host value is required. |  | Optional |
| src_port_list | List of comma delimited Source Port addresses to search with a maximum of 10 Port addresses per search. |  | Optional |
| dest_port_list | List of comma delimited Destination Port addresses to search with a maximum of 10 Port addresses per search. |  | Optional |
| protocol | IANA defined IP Protocol Name or Number. For example \- either use TCP or tcp or 6 for tcp protocol |  | Optional |
| archive_filename | Name of the archive file. For example, archive\_filename could be an event ID. To keep archive filename unique, value of epoch seconds at the time of execution of the command is appended to this filename argument. For example \- if the event id is someid, then archive\_filename is someid\-epochtime. |  | Required |
| delete_archive | false/true. if set to false archived file created by this playbook is retained on EndaceProbe. Value of true deletes the archived file. Once deleted this archived file is not available for future investigation.  |  | Required |
| download_threshold | PCAP file download size limit in MegaBytes. For example for 10MB, value is 10. Minimum value is 1\(MB\). |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endace.Download.PCAP.FileName | Name of the File to download from EndaceProbe | string |
| Endace.Download.PCAP.FileSize | File size in MegaBytes | string |
| Endace.Download.PCAP.FileUser | Username of the person who has permission to download this PCAP from EndaceProbe. | string |

## Playbook Image
---
![Endace Search Archive Download PCAP v2](https://raw.githubusercontent.com/demisto/content/495a2da87de9d6a64d87d48876f2033139431197/Packs/Endace/doc_imgs/playbook_Endace_Search_Archive_Download_PCAP_v2.png)