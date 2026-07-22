DEPRECATED - This playbook has been deprecated. This playbook uses Endace APIs to search, archive and download PCAP file from either a single EndaceProbe or many via the InvestigationManager and enables integration of full historical packet capture into security automation workflows.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Endace

### Scripts
* IsGreaterThan
* AreValuesEqual
* AddEvidence

### Commands
* endace-create-archive
* endace-get-search-status
* endace-download-pcap
* endace-get-archive-status
* endace-delete-search-task
* endace-create-search

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| start | Event Start Time in ISO 8601 format |  | Optional |
| end | Event End Time in ISO 8601 format |  | Optional |
| src_host_list | List of Source IP addresses to search |  | Optional |
| dest_host_list | List of Destination IP addresses to search |  | Optional |
| src_port_list | List of Source Port addresses to search |  | Optional |
| dest_port_list | List of Destination Port addresses to search |  | Optional |
| protocol | TCP or UDP | TCP | Optional |
| timeframe | Event timeframe to search \- in seconds.  Timeframe works as search for last "n" seconds if start and end time is not provided. For example, by specifying 3600 seconds as the timeframe, analyst can schedule a search for last 1 hour. If both start and end time is provided, timeframe value is ignored. If either start or end time is provided along with timeframe, the respective start or end time is calculated accordingly. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endace.Search.Query.JobID | Search Job ID | string |
| Endace.Search.Response.JobID | This is the job ID of search query which we polled to get search status | string |
| Endace.Search.Response.Status | job status  | string |
| Endace.Search.Response.JobProgress | Progress of this search Job  | string |
| Endace.Search.Response.TotalBytes | Total data matching this search across all datasources | string |
| Endace.Search.Delete.JobID | JobID of the task that needs to be deleted | string |
| Endace.Search.Delete.Error | Error message  | string |
| Endace.Search.Delete.Status | delete status, queryNotFound indicates that the search query has already expired before this operation, which is expected as EndaceProbes purges inactive tasks after their timer expires. queryDeleted indicates an active search query is now deleted.  | string |
| Endace.Archive.Query.JobID | JobID of the Archive Task | string |
| Endace.Archive.Query.FileName | Name of the archived File | string |
| Endace.Archive.Query.P2Vurl | Endace Pivot to Vision URL that links to an Investigation Dashboard on EndaceProbe. This enables user to further drill down on packets of interests on EndaceProbe without even downloading a pcap | string |
| Endace.Download.FileName | Name of the File to download from EndaceProbe | string |
| Endace.Download.FileSize | File size in MegaBytes | string |
| Endace.Download.FileType | The file downloaded from EndaceProbes is either a rotationfile or archivefile. | string |
| Endace.Download.FileURL | URL to PCAP file on EndaceProbe.  | string |
| Endace.Download.FileUser | Username of the person associated with the Endace instance who downloads this PCAP | string |
| Endace.Download.Status | Download status of the file.  | string |
| Endace.Download.Error | error occured during downloading of this file | string |

## Playbook Image
---
![Endace Search Archive and Download](https://raw.githubusercontent.com/demisto/content/6076f09ff5093102f383da8c11dfce0b12331d82/Packs/Endace/doc_imgs/playbook_Endace_Search_Archive_and_Download.png)