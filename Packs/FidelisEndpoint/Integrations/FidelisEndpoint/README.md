## Overview
---

Use the Fidelis Endpoint integration for advanced endpoint detection and response (EDR) across Windows, Mac and Linux OSes for faster threat remediation.
This integration was integrated and tested with version 9.2 of Fidelis EDR.

The account must have appropriate permissions to execute API calls. While you could use an administrator account, use an account designated for executing API calls.


To Get the appropriate permissions navigate to __Configuration__ > __Roles__ > __Create a role__ > __Permissions__
## Use Cases
---
* Fetch Alerts
* Get Alert Details
* Download File to Cortex XSOAR
* Execute Script on Endpoint
* query / search the Logs on Fidelis Console

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Fidelis EDR.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g. `https://abcde.fideliscloud.com/` )__
    * __Username__
    * __Incident type__
    * __Fetch incidents__
    * __First fetch timestamp ("number time unit", e.g., 12 hours, 7 days, 3 months, 1 year)__
    * __Fetch limit (minimum 5)__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.


## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. fidelis-endpoint-list-alerts
2. fidelis-endpoint-host-info
3. fidelis-endpoint-file-search
4. fidelis-endpoint-file-search-status
5. fidelis-endpoint-file-search-result-metadata
6. fidelis-endpoint-get-file
7. fidelis-endpoint-delete-file-search-job
8. fidelis-endpoint-list-scripts
9. fidelis-endpoint-get-script-manifest
10. fidelis-endpoint-list-processes
11. fidelis-endpoint-get-script-result
12. fidelis-endpoint-kill-process
13. fidelis-endpoint-delete-file
14. fidelis-endpoint-isolate-network
15. fidelis-endpoint-remove-network-isolation
16. fidelis-endpoint-script-job-status
17. fidelis-endpoint-execute-script
18. fidelis-endpoint-query-file
19. fidelis-endpoint-query-process
20. fidelis-endpoint-query-connection-by-remote-ip
21. fidelis-endpoint-query-by-dns
22. fidelis-endpoint-query-dns-by-server-ip
23. fidelis-endpoint-query-dns-by-source-ip
24. fidelis-endpoint-query-events
### 1. fidelis-endpoint-list-alerts
---
Returns all alerts in the system.
##### Required Permissions
The required permissions: View Alerts
##### Base Command

`fidelis-endpoint-list-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of alerts to return. | Optional | 
| sort | Sorts the result before applying take and skip. Can be any property name of the alert object.<br/>For example: "insertionDate Descending" | Optional | 
| start_date | The start of the time range of returned values in UTC format. For example: 0001-01-01T00:00:00Z | Optional | 
| end_date | The end of the time range of returned values in UTC format. For example: 0001-01-01T00:00:00Z | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Alert.EndpointName | String | Endpoint name. | 
| FidelisEndpoint.Alert.IntelName | String | Intel name. | 
| FidelisEndpoint.Alert.HasJob | Boolean | Whether the alert has an open job. | 
| FidelisEndpoint.Alert.EventTime | Date | Alert event time. | 
| FidelisEndpoint.Alert.ActionsTaken | String | The actions taken for this alert. | 
| FidelisEndpoint.Alert.CreateDate | Date | Alert creation date. | 
| FidelisEndpoint.Alert.ParentEventID | String | Parent event ID. | 
| FidelisEndpoint.Alert.Name | String | Alert name. | 
| FidelisEndpoint.Alert.ReportID | String | Report ID. | 
| FidelisEndpoint.Alert.EndpointID | String | Endpoint ID. | 
| FidelisEndpoint.Alert.IntelID | String | Intel ID. | 
| FidelisEndpoint.Alert.Name | String | Alert Name. | 
| FidelisEndpoint.Alert.EventType | Number | Event Type. | 
| FidelisEndpoint.Alert.EventID | String | Event ID. | 
| FidelisEndpoint.Alert.SourceType | Number | Source type. | 
| FidelisEndpoint.Alert.AgentTag | String | Agent tag. | 
| FidelisEndpoint.Alert.EventIndex | Number | Event index. | 
| FidelisEndpoint.Alert.Telemetry | String | Telemetry data. | 
| FidelisEndpoint.Alert.Source | String | Alert source. | 
| FidelisEndpoint.Alert.ID | Number | Alert ID. | 
| FidelisEndpoint.Alert.ValidatedDate | Date | Validation date. | 
| FidelisEndpoint.Alert.Description | String | Alert description. | 
| FidelisEndpoint.Alert.InsertionDate | Date | Alert insertion date. | 
| FidelisEndpoint.Alert.Severity | Number | Alert severity. | 
| FidelisEndpoint.Alert.ArtifactName | String | Artifact name. | 


##### Command Example
```!fidelis-endpoint-list-alerts limit="5"```
##### Context Example
```
{
    "FidelisEndpoint.Alert": [
        {
            "Severity": 2, 
            "IntelName": null, 
            "Telemetry": null, 
            "Source": "Installed Software CVE", 
            "InsertionDate": "2020-03-21T00:06:38.940Z", 
            "IntelID": null, 
            "HasJob": false, 
            "Description": "2 new vulnerable software installed today:\n\n[[!0::rsyslog:8.24.0:]]\r\nHighest Severity: High\r\nEndpoints: 1\r\n\u2022 [[!0::rsyslog:8.24.0:CVE-2017-12588]] - High\r\nThe zmq3 input and output modules in rsyslog before 8.28.0 interpreted description fields as format strings, possibly allowing a format string attack with unspecified impact.\r\n\u2022 [[!0::rsyslog:8.24.0:CVE-2018-16881]] - Medium\r\nA denial of service vulnerability was found in rsyslog in the imptcp module. An attacker could send a specially crafted message to the imptcp socket, which would cause rsyslog to crash. Versions before 8.27.0 are vulnerable.\r\n\r\n[[!0::binutils:2.27:]]\r\nHighest Severity: Medium\r\nEndpoints: 1\r\n\u2022 [[!0::binutils:2.27:CVE-2017-12448]] - Medium\r\nThe bfd_cache_close function in bfd/cache.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause a heap use after free and possibly achieve code execution via a crafted nested archive file. This issue occurs...\r\n\u2022 [[!0::binutils:2.27:CVE-2017-12449]] - Medium\r\nThe _bfd_vms_save_sized_string function in vms-misc.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of bounds heap read via a crafted vms file.\r\n\u2022 [[!0::binutils:2.27:CVE-2017-12450]] - Medium\r\nThe alpha_vms_object_p function in bfd/vms-alpha.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of bounds heap write and possibly achieve code execution via a crafted vms alpha file.\r\n\u2022 [[!0::binutils:2.27:CVE-2017-12451]] - Medium\r\nThe _bfd_xcoff_read_ar_hdr function in bfd/coff-rs6000.c and bfd/coff64-rs6000.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of bounds stack read via a crafted COFF image file.\r\n\u2022 [[!0::binutils:2.27:CVE-2017-12452]] - Medium\r\nThe bfd_mach_o_i386_canonicalize_one_reloc function in bfd/mach-o-i386.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of bounds heap read via a crafted mach-o file.\r\n\u2022 [[!0::binutils:2.27:CVE-2017-12453]] - Medium\r\nThe _bfd_vms_slurp_eeom function in libbfd.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of bounds heap read via a crafted vms alpha file.\r\n\u2022 [[!0::binutils:2.27:CVE-2017-12454]] - Medium\r\nThe _bfd_vms_slurp_egsd function in bfd/vms-alpha.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an arbitrary memory read via a crafted vms alpha file.\r\n\u2022 [[!0::binutils:2.27:CVE-2017-12455]] - Medium\r\nThe evax_bfd_print_emh function in vms-alpha.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of bounds heap read via a crafted vms alpha file.\r\n\u2022 [[!0::binutils:2.27:CVE-2017-12456]] - Medium\r\nThe read_symbol_stabs_debugging_info function in rddbg.c in GNU Binutils 2.29 and earlier allows remote attackers to cause an out of bounds heap read via a crafted binary file.\r\n\u2022 [[!0::binutils:2.27:CVE-2017-12457]] - Medium\r\nThe bfd_make_section_with_flags function in section.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause a NULL dereference via a crafted file.\r\n\u2022 [[!0::binutils:2.27:CVE-2017-12458]] - Medium\r\nThe nlm_swap_auxiliary_headers_in function in bfd/nlmcode.h in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of bounds heap read via a crafted nlm file.\r\n\u2022 [[!0::binutils:2.27:CVE-2017-12459]] - Medium\r\nThe bfd_mach_o_read_symtab_strtab function in bfd/mach-o.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of bounds heap write and possibly achieve code execution via a crafted mach-o file.\r\n\u2022 [[!0::binutils:2.27:CVE-2018-19931]] - Medium\r\nAn issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils through 2.31. There is a heap-based buffer overflow in bfd_elf32_swap_phdr_in in elfcode.h because the number of program headers is not restricted.\r\n\u2022 [[!0::binutils:2.27:CVE-2018-1000876]] - Medium\r\nbinutils version 2.32 and earlier contains a Integer Overflow vulnerability in objdump, bfd_get_dynamic_reloc_upper_bound,bfd_canonicalize_dynamic_reloc that can result in Integer overflow trigger heap overflow. Successful exploitation allows execution of arbitrary code.. This attack appear to be...\r\n\u2022 [[!0::binutils:2.27:CVE-2018-19932]] - Medium\r\nAn issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils through 2.31. There is an integer overflow and infinite loop caused by the IS_CONTAINED_BY_LMA macro in elf.c.\r\n\u2022 [[!0::binutils:2.27:CVE-2018-20671]] - Medium\r\nload_specific_debug_section in objdump.c in GNU Binutils through 2.31.1 contains an integer overflow vulnerability that can trigger a heap-based buffer overflow via a crafted section size.\r\n\u2022 [[!0::binutils:2.27:CVE-2019-1010204]] - Medium\r\nGNU binutils gold gold v1.11-v1.16 (GNU binutils v2.21-v2.31.1) is affected by: Improper Input Validation, Signed/Unsigned Comparison, Out-of-bounds Read. The impact is: Denial of service. The component is: gold/fileread.cc:497, elfcpp/elfcpp_file.h:644. The attack vector is: An ELF file with an...\r\n\r\n", 
            "EventType": null, 
            "EventIndex": null, 
            "ArtifactName": null, 
            "CreateDate": "2020-03-19T23:59:59.999Z", 
            "EventTime": null, 
            "Name": "Vulnerable Software Installed - 3/19/2020", 
            "ParentEventID": null, 
            "EndpointName": "fidelis-endpoint.windows", 
            "ReportID": null, 
            "ActionsTaken": null, 
            "ID": 437, 
            "EventID": null, 
            "ValidatedDate": null, 
            "SourceType": 19, 
            "AgentTag": null, 
            "EndpointID": "70815600-2b9c-4cbe-971f-ab5601ed1ce1"
        }, 
        {
            "Severity": 3, 
            "IntelName": "CVE-2013-1753", 
            "Telemetry": null, 
            "Source": "Installed Software CVE", 
            "InsertionDate": "2020-03-12T09:21:27.021Z", 
            "IntelID": null, 
            "HasJob": false, 
            "Description": "python - 2.7.5\n\nThe gzip_decode function in the xmlrpc client library in Python 3.4 and earlier allows remote attackers to cause a denial of service (memory consumption) via a crafted HTTP request.", 
            "EventType": null, 
            "EventIndex": null, 
            "ArtifactName": null, 
            "CreateDate": "2020-03-12T09:21:27.021Z", 
            "EventTime": null, 
            "Name": "Vulnerable Software - CVE-2013-1777", 
            "ParentEventID": null, 
            "EndpointName": "fidelis-endpoint.windows", 
            "ReportID": null, 
            "ActionsTaken": null, 
            "ID": 436, 
            "EventID": null, 
            "ValidatedDate": null, 
            "SourceType": 19, 
            "AgentTag": null, 
            "EndpointID": "70815600-2b9c-4cbe-971f-ab5601ed1ce1"
        }, 
        {
            "Severity": 4, 
            "IntelName": "CVE-2020-10029", 
            "Telemetry": null, 
            "Source": "Installed Software CVE", 
            "InsertionDate": "2020-03-07T09:21:24.356Z", 
            "IntelID": null, 
            "HasJob": false, 
            "Description": "glibc - 2.17\n\nThe GNU C Library (aka glibc or libc6) before 2.32 could overflow an on-stack buffer during range reduction if an input to an 80-bit long double function contains a non-canonical bit pattern, a seen when passing a 0x5d414141414141410000 value to sinl on x86 targets. This is related to sysdeps/ieee754/ldbl-96/e_rem_pio2l.c.", 
            "EventType": null, 
            "EventIndex": null, 
            "ArtifactName": null, 
            "CreateDate": "2020-03-07T09:21:24.356Z", 
            "EventTime": null, 
            "Name": "Vulnerable Software - CVE-2020-10029", 
            "ParentEventID": null, 
            "EndpointName": "fidelis-endpoint.windows", 
            "ReportID": null, 
            "ActionsTaken": null, 
            "ID": 435, 
            "EventID": null, 
            "ValidatedDate": null, 
            "SourceType": 19, 
            "AgentTag": null, 
            "EndpointID": "70815600-2b9c-4cbe-971f-ab5601ed1ce1"
        }, 
        {
            "Severity": 2, 
            "IntelName": "CVE-2015-8710", 
            "Telemetry": null, 
            "Source": "Installed Software CVE", 
            "InsertionDate": "2020-02-27T09:21:03.253Z", 
            "IntelID": null, 
            "HasJob": false, 
            "Description": "libxml2 - 2.9.1\n\nThe htmlParseComment function in HTMLparser.c in libxml2 allows attackers to obtain sensitive information, cause a denial of service (out-of-bounds heap memory access and application crash), or possibly have unspecified other impact via an unclosed HTML comment.", 
            "EventType": null, 
            "EventIndex": null, 
            "ArtifactName": null, 
            "CreateDate": "2020-02-27T09:21:03.253Z", 
            "EventTime": null, 
            "Name": "Vulnerable Software - CVE-2015-8710", 
            "ParentEventID": null, 
            "EndpointName": "fidelis-endpoint.windows", 
            "ReportID": null, 
            "ActionsTaken": null, 
            "ID": 434, 
            "EventID": null, 
            "ValidatedDate": null, 
            "SourceType": 19, 
            "AgentTag": null, 
            "EndpointID": "70815600-2b9c-4cbe-971f-ab5601ed1ce1"
        }, 
        {
            "Severity": 2, 
            "IntelName": "CVE-2014-4650", 
            "Telemetry": null, 
            "Source": "Installed Software CVE", 
            "InsertionDate": "2020-02-27T09:21:03.253Z", 
            "IntelID": null, 
            "HasJob": false, 
            "Description": "python - 2.7.5\n\nThe CGIHTTPServer module in Python 2.7.5 and 3.3.4 does not properly handle URLs in which URL encoding is used for path separators, which allows remote attackers to read script source code or conduct directory traversal attacks and execute unintended code via a crafted character sequence, as demonstrated by a %2f separator.", 
            "EventType": null, 
            "EventIndex": null, 
            "ArtifactName": null, 
            "CreateDate": "2020-02-27T09:21:03.253Z", 
            "EventTime": null, 
            "Name": "Vulnerable Software - CVE-2014-4444", 
            "ParentEventID": null, 
            "EndpointName": "fidelis-endpoint.windows", 
            "ReportID": null, 
            "ActionsTaken": null, 
            "ID": 433, 
            "EventID": null, 
            "ValidatedDate": null, 
            "SourceType": 19, 
            "AgentTag": null, 
            "EndpointID": "70815600-2b9c-4cbe-971f-ab5601ed1ce1"
        }
    ]
}
```
##### Human Readable Output
### Fidelis Endpoint Alerts
|ID|Name|EndpointName|EndpointID|Source|IntelName|Severity|CreateDate|
|---|---|---|---|---|---|---|---|
| 437 | Vulnerable Software Installed - 3/19/2020 | fidelis-endpoint.windows | 70815600-2b9c-4cbe-971f-ab5601ed1ce1 | Installed Software CVE |  | 2 | 2020-03-19T23:59:59.999Z |
| 436 | Vulnerable Software - CVE-2013-1777 | fidelis-endpoint.windows | 70815600-2b9c-4cbe-971f-ab5601ed1ce1 | Installed Software CVE | CVE-2013-1753 | 3 | 2020-03-12T09:21:27.021Z |
| 435 | Vulnerable Software - CVE-2020-10029 | fidelis-endpoint.windows | 70815600-2b9c-4cbe-971f-ab5601ed1ce1 | Installed Software CVE | CVE-2020-10029 | 4 | 2020-03-07T09:21:24.356Z |
| 434 | Vulnerable Software - CVE-2015-8710 | fidelis-endpoint.windows | 70815600-2b9c-4cbe-971f-ab5601ed1ce1 | Installed Software CVE | CVE-2015-8710 | 2 | 2020-02-27T09:21:03.253Z |
| 433 | Vulnerable Software - CVE-2014-4444 | fidelis-endpoint.windows | 70815600-2b9c-4cbe-971f-ab5601ed1ce1 | Installed Software CVE | CVE-2014-4650 | 2 | 2020-02-27T09:21:03.253Z |
### 2. fidelis-endpoint-host-info
---
Searches for endpoints based on an IP address or hostname.
##### Base Command
`fidelis-endpoint-host-info`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | The IP address to search for. | Optional | 
| host | The host name to search for. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Host.AgentVersion | String | The agent version. | 
| FidelisEndpoint.Host.MacAddress | String | Host MAC address. | 
| FidelisEndpoint.Host.OS | String | Endpoint OS. | 
| FidelisEndpoint.Host.IPAddress | String | Endpoint IP address. | 
| FidelisEndpoint.Host.Isolated | Boolean | Whether the endpoint is isolated. | 
| FidelisEndpoint.Host.AV_Enabled | Boolean | Whether AV is enabled. | 
| FidelisEndpoint.Host.Hostname | String | Host name. | 
| FidelisEndpoint.Host.AgentInstalled | Boolean | Whether an agent was installed. | 
| FidelisEndpoint.Host.Groups | String | Endpoint groups. | 
| FidelisEndpoint.Host.LastContactDate | Date | Host last contact date. | 
| FidelisEndpoint.Host.ID | String | Host ID. | 
| FidelisEndpoint.Host.ProcessorName | String | Processor name. | 
| FidelisEndpoint.Host.OnNetwork | Boolean | Whether the host is on the network. | 
##### Command Example
```!fidelis-endpoint-host-info ip_address="2.2.2.2"```
##### Context Example
```
{
    "Endpoint": [
        {
            "MACAddress": "23:01:0a:50:00:02", 
            "IPAddress": "2.2.2.2", 
            "Hostname": "fidelis-endpoint.windows", 
            "Processor": "Intel(R) Xeon(R) CPU @ 2.30GHz", 
            "OS": "CentOS Linux 7 (Core) Linux x64", 
            "ID": "70815600-2b9c-4cbe-971f-ab5601ed1ce1"
        }
    ], 
    "FidelisEndpoint.Host": [
        {
            "AV_Enabled": true, 
            "LastContactDate": "2020-03-26T04:35:02.2887847", 
            "OS": "CentOS Linux 7 (Core) Linux x64", 
            "Hostname": "fidelis-endpoint.windows", 
            "Isolated": false, 
            "MacAddress": "23:01:0a:50:00:02", 
            "AgentVersion": "9.2.4.31", 
            "Groups": null, 
            "AgentInstalled": true, 
            "OnNetwork": true, 
            "ProcessorName": "Intel(R) Xeon(R) CPU @ 2.30GHz", 
            "IPAddress": "2.2.2.2", 
            "ID": "70815600-2b9c-4cbe-971f-ab5601ed1ce1"
        }
    ]
}
```
##### Human Readable Output
### Fidelis Endpoint Host Info
|ID|OS|MacAddress|Isolated|LastContactDate|AgentInstalled|AgentVersion|OnNetwork|AV_Enabled|ProcessorName|
|---|---|---|---|---|---|---|---|---|---|
| 70815600-2b9c-4cbe-971f-ab5601ed1ce1 | CentOS Linux 7 (Core) Linux x64 | 23:01:0a:50:00:02 | false | 2020-03-26T04:35:02.2887847 | true | 9.2.4.31 | true | true | Intel(R) Xeon(R) CPU @ 2.30GHz |
### 3. fidelis-endpoint-file-search
---
Searches for files on multiple hosts, using file hash, file extension, file size, and other search criteria.
##### Required Permissions
The required permissions: Scripts, View Executables 
##### Base Command
`fidelis-endpoint-file-search`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | A comma-separated list of hosts in which to search for the specified file. | Optional | 
| md5 | A comma-separated list MD5 hashes to search for. Get the hashes from the queries commands. | Required | 
| file_extension | The file extension. | Optional | 
| file_path | The file path (recommended to lower the search time). | Optional | 
| file_size | The file size greater than. The default is 100. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.FileSearch.JobID | String | The job ID. | 
| FidelisEndpoint.FileSearch.JobResultID | String | The job result ID. | 
##### Command Example
```!fidelis-endpoint-file-search host="2.2.2.2" md5="098f6bcd4621d373cade4e832347b4f6" file_extension=".txt" file_size="0"```
##### Context Example
```
{
    "FidelisEndpoint.FileSearch": {
        "JobResultID": "e93e848a-2462-4933-b442-ab8a02118111", 
        "JobID": "fcb3b94c-7344-4c30-a47b-93f90bd2385e"
    }
}
```
##### Human Readable Output
### Fidelis Endpoint file search
|JobID|JobResultID|
|---|---|
| fcb3b94c-7344-4c30-a47b-93f90bd2385e | e93e848a-2462-4933-b442-ab8a02118111 |
### 4. fidelis-endpoint-file-search-status
---
Gets the file search job status.
##### Required Permissions
The required permissions: View Executables
##### Base Command
`fidelis-endpoint-file-search-status`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID. Get the ID from the file-search command. | Required | 
| job_result_id | The job result ID. Get the ID from the file-search command. | Required | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.FileSearch.JobID | String | The file search job ID. | 
| FidelisEndpoint.FileSearch.JobResultID | String | Job result ID. | 
| FidelisEndpoint.FileSearch.Status | String | Job status. | 
##### Command Example
```!fidelis-endpoint-file-search-status job_id=a345056b-b290-4746-b953-0822dab381ae job_result_id=0b7161ed-ffe9-4b87-b009-ab8a02034e0e```
##### Context Example
```
{
    "FidelisEndpoint.FileSearch": {
        "Status": "Completed", 
        "JobResultID": "0b7161ed-ffe9-4b87-b009-ab8a02034e0e", 
        "JobID": "a345056b-b290-4746-b953-0822dab381ae"
    }
}
```
##### Human Readable Output
Fidelis Endpoint file search status is: Completed
### 5. fidelis-endpoint-file-search-result-metadata
---
Gets the job results metadata. The maximum is 50 results.
##### Required Permissions
The required permissions: View Executables
##### Base Command
`fidelis-endpoint-file-search-result-metadata`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID. Get the job ID from the file-search command. | Required | 
| job_result_id | The job result ID. Get the job result ID from the file-search command. | Required | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.File.AgentID | String | Agent ID. | 
| FidelisEndpoint.File.FileName | String | File name. | 
| FidelisEndpoint.File.FilePath | String | File path. | 
| FidelisEndpoint.File.FileSize | Number | File size. | 
| FidelisEndpoint.File.HostIP | String | Host IP address. | 
| FidelisEndpoint.File.HostName | String | Host name. | 
| FidelisEndpoint.File.ID | String | File ID. | 
| FidelisEndpoint.File.MD5Hash | String | File MD5 hash. | 
| File.Path | String | The file path. | 
| File.Hostname | String | The name of the host where the file was found. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Name | String | The full file name (including file extension). | 
| File.Size | Number | The size of the file in bytes. | 
##### Command Example
```!fidelis-endpoint-file-search-result-metadata job_id=a345056b-b290-4746-b953-0822dab381ae job_result_id=0b7161ed-ffe9-4b87-b009-ab8a02034e0e```
##### Context Example
```
{
    "FidelisEndpoint.File": {
        "MD5Hash": "098f6bcd4621d373cade4e832347b4f6", 
        "FilePath": "Users\\admin\\Documents\\test.txt", 
        "HostName": "fidelis-endpoint-winserver2019", 
        "FileName": "test.txt", 
        "FileSize": 4, 
        "HostIP": "2.2.2.2", 
        "AgentID": "4088e5f0-0d18-4daa-a1a3-e0becc34c803", 
        "ID": "eyJOYW1lIjoidGVzdC50eHQiLCJQYXRoIjoiL3Jlc3VsdHMvMGI3MTYxZWQtZmZlOS00Yjg3LWIwMDktYWI4YTAyMDM0ZTBlL2IyUnZPVFl5YjFSUGNqRnZSRTkwYlU1aWQxQnJUemRUZDJkTUwzUmFNbUZWY21wMlJrRjFhRXRwTUQwPSJ90"
    }, 
    "File": {
        "Size": 4, 
        "Path": "Users\\admin\\Documents\\test.txt", 
        "Hostname": "fidelis-endpoint-winserver2019", 
        "Name": "test.txt", 
        "MD5": "098f6bcd4621d373cade4e832347b4f6"
    }
}
```
##### Human Readable Output
### Fidelis Endpoint file results metadata
|ID|FileName|FilePath|MD5Hash|FileSize|HostName|HostIP|AgentID|
|---|---|---|---|---|---|---|---|
| eyJOYW1lIjoidGVzdC50eHQiLCJQYXRoIjoiL3Jlc3VsdHMvMGI3MTYxZWQtZmZlOS00Yjg3LWIwMDktYWI4YTAyMDM0ZTBlL2IyUnZPVFl5YjFSUGNqRnZSRTkwYlU1aWQxQnJUemRUZDJkTUwzUmFNbUZWY21wMlJrRjFhRXRwTUQwPSJ90 | test.txt | Users\admin\Documents\test.txt | 098f6bcd4621d373cade4e832347b4f6 | 4 | fidelis-endpoint-winserver2019 | 2.2.2.2 | 4088e5f0-0d18-4daa-a1a3-e0becc34c803 |
### 6. fidelis-endpoint-get-file
---
Gets the file stream and download the file.
##### Required Permissions
The required permissions: Scripts, View Executables
##### Base Command
`fidelis-endpoint-get-file`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The file ID. Get the ID from the file-search-result-metadata command. | Required | 
| file_name | The file name to download (including extension). Get the file name from the file-search-result-metadata command. command). | Required | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file in bytes. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The full file name (including file extension). | 
| File.SSDeep | String | The ssdeep hash of the file (same as displayed in file entries). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Info | String | The file information. | 
| File.Type | String | The file type, as determined by libmagic (same as displayed in file entries). | 
| File.MD5 | String | The MD5 hash of the file. | 
##### Command Example
```!fidelis-endpoint-get-file file_id=eyJOYW1lIjoidGVzdC50eHQiLCJQYXRoIjoiL3Jlc3VsdHMvMGI3MTYxZWQtZmZlOS00Yjg3LWIwMDktYWI4YTAyMDM0ZTBlL2IyUnZPVFl5YjFSUGNqRnZSRTkwYlU1aWQxQnJUemRUZDJkTUwzUmFNbUZWY21wMlJrRjFhRXRwTUQwPSJ90 file_name=test.txt```
##### Human Readable Output
Return the file to download
### 7. fidelis-endpoint-delete-file-search-job
---
Removes the job to free up space on the server.
##### Required Permissions
The required permissions: Scripts, View Executables, Delete Executables
##### Base Command
`fidelis-endpoint-delete-file-search-job`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID. Get the job ID from the file-search command. | Required | 
##### Context Output
There is no context output for this command.
##### Command Example
```!fidelis-endpoint-delete-file-search-job job_id=a345056b-b290-4746-b953-0822dab381ae ```
##### Human Readable Output
The job was successfully deleted
### 8. fidelis-endpoint-list-scripts
---
Gets a list of all script packages.
##### Required Permissions
The required permissions: Read groups, View Behaviors
##### Base Command
`fidelis-endpoint-list-scripts`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Script.Description | String | The script description. | 
| FidelisEndpoint.Script.ID | String | Script ID. | 
| FidelisEndpoint.Script.Name | String | Script name. | 
##### Command Example
```!fidelis-endpoint-list-scripts```
##### Context Example
```
{
    "FidelisEndpoint.Script": [
        {
            "Name": "Administrators", 
            "Description": "Lists all users with Administrator rights. Use the optional parameter to filter the results to usernames that contain the supplied text.", 
            "ID": "8d379688-dde1-451d-8fa2-4f29c84baf97"
        }, 
        {
            "Name": "Administrators", 
            "Description": "Lists all users with Administrator rights. Use the optional parameter to filter the results to usernames that contain the supplied text.", 
            "ID": "c533cf90-f015-4616-84fb-8836b32aa74b"
        }, 
        {
            "Name": "Agent Log", 
            "Description": "Returns log entries from the Fidelis Agent.", 
            "ID": "e73ffbba-14c1-4dd4-bb45-60d6906031c9"
        }, 
        {
            "Name": "Agent Log", 
            "Description": "Returns log entries from the Fidelis Agent.", 
            "ID": "f0572f26-4272-4d2c-8f6f-4a8dfa307904"
        }, 
        {
            "Name": "All User Accounts", 
            "Description": "Displays information about any created users on an endpoint. Use the Optional Question box to filter the results by the specified text--results returned include data containing that value in any column.", 
            "ID": "42787aa7-f721-49ad-ab2d-308f905986f3"
        }, 
        {
            "Name": "All User Accounts", 
            "Description": "Displays information about any created users on an endpoint. Use the Optional Question box to filter the results by the specified text--results returned include data containing that value in any column.", 
            "ID": "b44f4b11-2e76-44c8-9484-238fd3063aea"
        }, 
        {
            "Name": "All User Accounts", 
            "Description": "Displays information about any created users on an endpoint. Use the Optional Question box to filter the results by the specified text--results returned include data containing that value in any column.", 
            "ID": "3fe1ec01-b095-4a6a-8fcf-7d9e1df95284"
        },
        {
            "Name": "Services (WMI)", 
            "Description": "Obtain the list of services from the Windows Management Instrumentation (WMI).\r\nThe Service Name or Account Filter limits the results to services that have the matching name or account.", 
            "ID": "9622541e-2bca-46f5-b2a6-ef406babf9cd"
        }, 

    ]
}
```
##### Human Readable Output
### Fidelis Endpoint scripts
|ID|Name|Description|
|---|---|---|
| 8d379688-dde1-451d-8fa2-4f29c84baf97 | Administrators | Lists all users with Administrator rights. Use the optional parameter to filter the results to usernames that contain the supplied text. |
| c533cf90-f015-4616-84fb-8836b32aa74b | Administrators | Lists all users with Administrator rights. Use the optional parameter to filter the results to usernames that contain the supplied text. |
| e73ffbba-14c1-4dd4-bb45-60d6906031c9 | Agent Log | Returns log entries from the Fidelis Agent. |
| f0572f26-4272-4d2c-8f6f-4a8dfa307904 | Agent Log | Returns log entries from the Fidelis Agent. |
| 42787aa7-f721-49ad-ab2d-308f905986f3 | All User Accounts | Displays information about any created users on an endpoint. Use the Optional Question box to filter the results by the specified text--results returned include data containing that value in any column. |
| b44f4b11-2e76-44c8-9484-238fd3063aea | All User Accounts | Displays information about any created users on an endpoint. Use the Optional Question box to filter the results by the specified text--results returned include data containing that value in any column. |
| 3fe1ec01-b095-4a6a-8fcf-7d9e1df95284 | All User Accounts | Displays information about any created users on an endpoint. Use the Optional Question box to filter the results by the specified text--results returned include data containing that value in any column. |
| 1a57a6ad-4dd7-4055-8def-8e423d949f3f | All User Accounts (WMI) | Lists all the user accounts. Use the optional parameter to filter the results to those that have a username that contains the supplied text |
| c8adc3bc-6345-473d-a8cc-c45a76f9d62c | AntiVirus Information | Shows the AntiVirus and AntiSpyware products installed on client computer and whether they are enabled and up-to-date. Provide the optional filter to only return products that contain the filter text.  This script does not work on server class operating systems. |
| c9b37e1e-3ec6-49a3-9426-b90a90b55071 | ARP Cache | Displays information from the Address Resolution Protocol Cache. Use the Optional Question box to filter the results by the specified text--results returned include data containing that value in any column. |
| f3eb6edf-5764-4e11-8833-6da6b067e54e | ARP Cache | Displays information from the Address Resolution Protocol Cache. Use the Optional Question box to filter the results by the specified text--results returned include data containing that value in any column. |
### 9. fidelis-endpoint-get-script-manifest
---
Gets the script manifest.
##### Required Permissions
The required permissions: View Behaviors
##### Base Command
`fidelis-endpoint-get-script-manifest`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | The script ID. Get the script ID from the list-scripts command. | Required | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Script.ResultColumns | String | The script results columns. | 
| FidelisEndpoint.Script.Priority | String | Script priority. | 
| FidelisEndpoint.Script.ImpersonationUser | String | Impersonation user. | 
| FidelisEndpoint.Script.Name | String | Script name. | 
| FidelisEndpoint.Script.Command | String | The script commands. | 
| FidelisEndpoint.Script.Questions | String | Script questions. | 
| FidelisEndpoint.Script.WizardOverridePassword | Boolean | Wizard override password. | 
| FidelisEndpoint.Script.Platform | String | Scripts platforms (only true). | 
| FidelisEndpoint.Script.ImpersonationPassword | String | Impersonation password. | 
| FidelisEndpoint.Script.ID | String | Script ID. | 
| FidelisEndpoint.Script.Description | String | The script description. | 
| FidelisEndpoint.Script.TimeoutSeconds | Number | Script timeout in seconds. | 
##### Command Example
```!fidelis-endpoint-get-script-manifest script_id="2d32a530-0716-4542-afdc-8da3bd47d8bf"```
##### Context Example
```
{
    "FidelisEndpoint.Script": {
        "Description": "Obtain the list of currently running processes.\r\nOptionally, information about open sockets, handles and loaded DLLs can be included.\r\nCerberus Stage One analysis verifies digital signatures of the processes and performs a risk assessment of known system calls assigning an aggregate score.\r\nThe filter field limits the results to processes that match the given text in any column.", 
        "TimeoutSeconds": 0, 
        "WizardOverridePassword": false, 
        "ImpersonationUser": null, 
        "ResultColumns": [
            "__detail", 
            "PID", 
            "Parent PID", 
            "Name", 
            "User", 
            "MD5", 
            "SHA1", 
            "Path", 
            "Start Time", 
            "Working Directory", 
            "Command Line", 
            "Is Hidden"
        ], 
        "Priority": null, 
        "Platform": [
            "windows32", 
            "windows64"
        ], 
        "ImpersonationPassword": null, 
        "Command": "Volatile.bat sockets {[T:B,V:true]Include Sockets} handles {[T:B,V:true]Include Handles} dlls {[T:B,V:true]Include DLLs} injected {[T:B,?]Check for injected DLLs} jam {[T:B,?]Perform Cerberus Stage 1 Analysis (approximately 5 seconds per process)} filter {[T:T,?] Filter}", 
        "Questions": [
            {
                "answer": "true", 
                "question": "Include Sockets", 
                "inputType": "checkbox", 
                "isOptional": false, 
                "paramNumber": 1
            }, 
            {
                "answer": "true", 
                "question": "Include Handles", 
                "inputType": "checkbox", 
                "isOptional": false, 
                "paramNumber": 2
            }, 
            {
                "answer": "true", 
                "question": "Include DLLs", 
                "inputType": "checkbox", 
                "isOptional": false, 
                "paramNumber": 3
            }, 
            {
                "answer": "false", 
                "question": "Check for injected DLLs", 
                "inputType": "checkbox", 
                "isOptional": true, 
                "paramNumber": 4
            }, 
            {
                "answer": "false", 
                "question": "Perform Cerberus Stage 1 Analysis (approximately 5 seconds per process)", 
                "inputType": "checkbox", 
                "isOptional": true, 
                "paramNumber": 5
            }, 
            {
                "answer": null, 
                "question": " Filter", 
                "inputType": "text", 
                "isOptional": true, 
                "paramNumber": 6
            }
        ], 
        "ID": "2d32a530-0716-4542-afdc-8da3bd47d8bf", 
        "Name": "Process List"
    }
}
```
##### Human Readable Output
### Fidelis Endpoint script manifest
|ID|Name|Description|Platform|Command|Questions|TimeoutSeconds|ResultColumns|WizardOverridePassword|
|---|---|---|---|---|---|---|---|---|
| 2d32a530-0716-4542-afdc-8da3bd47d8bf | Process List | Obtain the list of currently running processes.<br/>Optionally, information about open sockets, handles and loaded DLLs can be included. Cerberus Stage One analysis verifies digital signatures of the processes and performs a risk assessment of known system calls assigning an aggregate score.The filter field limits the results to processes that match the given text in any column. | windows32,windows64 | Volatile.bat sockets {[T:B,V:true]Include Sockets} handles {[T:B,V:true]Include Handles} dlls {[T:B,V:true]Include DLLs} injected {[T:B,?]Check for injected DLLs} jam {[T:B,?]Perform Cerberus Stage 1 Analysis (approximately 5 seconds per process)} filter {[T:T,?] Filter} | {'paramNumber': 1, 'question': 'Include Sockets', 'answer': 'true', 'isOptional': False, 'inputType': 'checkbox'},<br/>{'paramNumber': 2, 'question': 'Include Handles', 'answer': 'true', 'isOptional': False, 'inputType': 'checkbox'},<br/>{'paramNumber': 3, 'question': 'Include DLLs', 'answer': 'true', 'isOptional': False, 'inputType': 'checkbox'},<br/>{'paramNumber': 4, 'question': 'Check for injected DLLs', 'answer': 'false', 'isOptional': True, 'inputType': 'checkbox'},<br/>{'paramNumber': 5, 'question': 'Perform Cerberus Stage 1 Analysis (approximately 5 seconds per process)', 'answer': 'false', 'isOptional': True, 'inputType': 'checkbox'},<br/>{'paramNumber': 6, 'question': ' Filter', 'answer': None, 'isOptional': True, 'inputType': 'text'} | 0 | __detail,<br/>PID,<br/>Parent PID,<br/>Name,<br/>User,<br/>MD5,<br/>SHA1,<br/>Path,<br/>Start Time,<br/>Working Directory,<br/>Command Line,<br/>Is Hidden | false |
### 10. fidelis-endpoint-list-processes
---
Gets a list all processes according to the OS system.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results
##### Base Command
`fidelis-endpoint-list-processes`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ip | The endpoint IP. Get the endpoint IP from the host-info command. | Optional | 
| operating_system | Ths system OS. Can be "Windows", "Linux", or "macOS". | Required | 
| time_out | Script time out in seconds. The default is 300. | Optional | 
| endpoint_name | The endpoint name. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Process.JobID | String | Job ID. | 
| FidelisEndpoint.Process.ID | String | Script ID. | 
##### Command Example
```!fidelis-endpoint-list-processes operating_system=Windows endpoint_ip=2.2.2.2```
##### Context Example
```
{
    "FidelisEndpoint.Process": {
        "ID": "2d32a530-0716-4542-afdc-8da3bd47d8bf", 
        "JobID": "71c6be70-fa49-40ba-8d0a-ab8a02118a19"
    }
}
```
##### Human Readable Output
The job has been executed successfully. 
 Job ID: 71c6be70-fa49-40ba-8d0a-ab8a02118a19
### 11. fidelis-endpoint-get-script-result
---
Gets script job results.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results
##### Base Command
`fidelis-endpoint-get-script-result`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The script execution job ID. Get the ID the following commands: script-execution, file-search, list-processes, kill-process-by-pid, delete-file, network-isolation, remove-network-isolation. | Required | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.ScriptResult.EndpointName | String | Endpoint name. | 
| FidelisEndpoint.ScriptResult.ParentPID | String | Parent process ID. | 
| FidelisEndpoint.ScriptResult.Path | String | File path. | 
| FidelisEndpoint.ScriptResult.SHA1 | String | File SHA1 hash. | 
| FidelisEndpoint.ScriptResult.PID | String | Process ID. | 
| FidelisEndpoint.ScriptResult.Name | String | Process name. | 
| FidelisEndpoint.ScriptResult.User | String | Script user. | 
| FidelisEndpoint.ScriptResult.StartTime | Date | Script start time. | 
| FidelisEndpoint.ScriptResult.EndpointID | String | Endpoint ID. | 
| FidelisEndpoint.ScriptResult.Matches | Number | Script matches. | 
| FidelisEndpoint.ScriptResult.IsHidden | String | Whether the endpoint is hidden. | 
| FidelisEndpoint.ScriptResult.GroupID | String | Group ID. | 
| FidelisEndpoint.ScriptResult.Tags | String | Script tags. | 
| FidelisEndpoint.ScriptResult.ID | String | Script result ID. | 
| FidelisEndpoint.ScriptResult.WorkingDirectory | String | Working directory. | 
| FidelisEndpoint.ScriptResult.MD5 | String | File MD5 hash. | 
| FidelisEndpoint.ScriptResult.CommandLine | String | Command line. | 
##### Command Example
```!fidelis-endpoint-get-script-result job_id=fc94568c-9a15-4fa2-af08-ab8a01f5e86c```
##### Context Example
```
{
    "FidelisEndpoint.ScriptResult": [
        {
            "SHA1": "0000000000000000000000000000000000000000", 
            "Name": "System", 
            "ParentPID": "0", 
            "Tags": [], 
            "Matches": 0, 
            "CommandLine": "", 
            "PID": "4", 
            "GroupID": "9F4354C1CEB3B925ADC6A6286FF5A23F7CF9D7B0", 
            "StartTime": "N/A", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "User": "", 
            "EndpointID": "3494cb0f-67ba-41bc-9190-ab5d015dd57c", 
            "WorkingDirectory": "", 
            "Path": "", 
            "IsHidden": "false", 
            "ID": "7086ab52f0725e547095ff779e30153ae6088ccc", 
            "MD5": "00000000000000000000000000000000"
        }, 
        {
            "SHA1": "0000000000000000000000000000000000000000", 
            "Name": "registry.exe", 
            "ParentPID": "4", 
            "Tags": [], 
            "Matches": 0, 
            "CommandLine": "", 
            "PID": "84", 
            "GroupID": "CE47F839D8D87C334A503491A4D60CDA15295071", 
            "StartTime": "N/A", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "User": "", 
            "EndpointID": "3494cb0f-67ba-41bc-9190-ab5d015dd57c", 
            "WorkingDirectory": "", 
            "Path": "", 
            "IsHidden": "false", 
            "ID": "11ea7715d36598d0bc0aaa97ee3e95c26d293f4b", 
            "MD5": "00000000000000000000000000000000"
        }, 
        {
            "SHA1": "0FA1562A56219B1FC005E24AC1D866F6E1AE7902", 
            "Name": "smss.exe", 
            "ParentPID": "4", 
            "Tags": [], 
            "Matches": 0, 
            "CommandLine": "", 
            "PID": "264", 
            "GroupID": "82D6263B1B8CDA7C62591267E414CA9E56BF603A", 
            "StartTime": "N/A", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "User": "", 
            "EndpointID": "3494cb0f-67ba-41bc-9190-ab5d015dd57c", 
            "WorkingDirectory": "", 
            "Path": "C:\\Windows\\System32\\smss.exe", 
            "IsHidden": "false", 
            "ID": "863637a177dee43dfbcb0b479db1e5ec885d70e8", 
            "MD5": "2855A7D96CF37DF1960A6D8828A614CB"
        }, 
        {
            "SHA1": "A04607D0B11D30B0CDB36739077E7F1B6C7D1FAE", 
            "Name": "protect.exe", 
            "ParentPID": "576", 
            "Tags": [], 
            "Matches": 0, 
            "CommandLine": "\"C:\\Program Files\\Fidelis\\Endpoint\\Platform\\services\\protect\\protect.exe\" -s", 
            "PID": "272", 
            "GroupID": "5D5334D2A0405C72C967B4D784E27AD222E7BDD9", 
            "StartTime": "2020-03-26T04:04:22.855396", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "User": "SYSTEM", 
            "EndpointID": "3494cb0f-67ba-41bc-9190-ab5d015dd57c", 
            "WorkingDirectory": "C:\\Windows\\system32\\", 
            "Path": "C:\\Program Files\\Fidelis\\Endpoint\\Platform\\services\\protect\\protect.exe", 
            "IsHidden": "false", 
            "ID": "4a598df8817b12552d3a485e23dac7f911536a5a", 
            "MD5": "40A35E6DC3ADE3F5CAA79A4C15CCF37C"
        }, 
        {
            "SHA1": "A1385CE20AD79F55DF235EFFD9780C31442AA123", 
            "Name": "svchost.exe", 
            "ParentPID": "576", 
            "Tags": [], 
            "Matches": 0, 
            "CommandLine": "C:\\Windows\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService", 
            "PID": "304", 
            "GroupID": "8C6F410CBCE4C937FC8ED920462AD47CA49FCE0C", 
            "StartTime": "2020-03-12T03:58:08.237101", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "User": "SYSTEM", 
            "EndpointID": "3494cb0f-67ba-41bc-9190-ab5d015dd57c", 
            "WorkingDirectory": "C:\\Windows\\system32\\", 
            "Path": "C:\\Windows\\System32\\svchost.exe", 
            "IsHidden": "false", 
            "ID": "1d807600d7deef1f26d16ddc28ae6ca4ca656202", 
            "MD5": "3A0A29438052FAED8A2532DA50455876"
        }
    ]
}
```
##### Human Readable Output
### Fidelis Endpoint script job results
|ID|Name|EndpointID|EndpointName|PID|User|SHA1|MD5|Path|WorkingDirectory|StartTime|
|---|---|---|---|---|---|---|---|---|---|---|
| 7086ab52f0725e547095ff779e30153ae6088ccc | System | 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 4 |  | 0000000000000000000000000000000000000000 | 00000000000000000000000000000000 |  |  | N/A |
| 11ea7715d36598d0bc0aaa97ee3e95c26d293f4b | registry.exe | 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 84 |  | 0000000000000000000000000000000000000000 | 00000000000000000000000000000000 |  |  | N/A |
| 863637a177dee43dfbcb0b479db1e5ec885d70e8 | smss.exe | 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 264 |  | 0FA1562A56219B1FC002E24AC8D866F6E1AE7902 | 2755A7D96CF37DF1960A6D8828A614CB | C:\Windows\System32\smss.exe |  | N/A |
| 4a598df8817b12552d3a485e23dac7f911536a5a | protect.exe | 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 272 | SYSTEM | A04607D0B11D30B0CDB36739088E8F1B6C7D1FAE | 40A35E6DC3ADE3F5CAA79A4C15CCF37C | C:\Program Files\Fidelis\Endpoint\Platform\services\protect\protect.exe | C:\Windows\system32\ | 2020-03-26T04:04:22.855396 |
| 1d807600d7deef1f26d16ddc28ae6ca4ca656202 | svchost.exe | 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 304 | SYSTEM | A1385CE20AD79F55DF235EFFD9780C31442AA234 | 8a0a29438052faed8a2532da50451234 | C:\Windows\System32\svchost.exe | C:\Windows\system32\ | 2020-03-12T03:58:08.237101 |
| b52743f524304f61a076feb040426c2931921adf | svchost.exe | 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 364 | LOCAL SERVICE | A1385CE20AD79F55DF235EFFD9780C31442AA234 | 8a0a29438052faed8a2532da50451234 | C:\Windows\System32\svchost.exe | C:\Windows\system32\ | 2020-03-12T03:58:08.526584 |
| 63cf4746e5a634fdb2ae8c9f4feca6b49377f1af | csrss.exe | 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 372 |  | 779B8AFC3FA2528B090F400EF3D592E0E2775955 | 7D64128BC1EECE41196858897596EBC8 | C:\Windows\System32\csrss.exe |  | N/A |
| 27e4f8301c0ce8d0dbe449561c0aae59a2fece82 | svchost.exe | 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 440 | LOCAL SERVICE | A1385CE20AD79F55DF235EFFD9780C31442AA234 | 8a0a29438052faed8a2532da50451234 | C:\Windows\system32\svchost.exe | C:\Windows\system32\ | 2020-03-12T03:58:08.540947 |
| d81492c785d46ab06e001d5fed4f8d5e491b02b5 | svchost.exe | 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 444 | LOCAL SERVICE | A1385CE20AD79F55DF235EFFD9780C31442AA234 | 8a0a29438052faed8a2532da50451234 | C:\Windows\system32\svchost.exe | C:\Windows\system32\ | 2020-03-12T03:58:08.526589 |
| f211cdabce3ea5a029ad2a63b803a9962e63af96 | wininit.exe | 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 448 |  | 389E257A924EA521E830C31712494D33B38841A8 | 4E20895E641F2C3E68AB3DB91A1A16F1 | C:\Windows\System32\wininit.exe |  | N/A |
| 395b84b288830e96cf91fa20f7c399d8a21f2d8f | csrss.exe | 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 456 |  | 779B8AFC3FA2528B090F400EF3D592E0E2775955 | 7D64128BC1EECE41196858897596EBC8 | C:\Windows\System32\csrss.exe |  | N/A |
### 12. fidelis-endpoint-kill-process
---
Terminates the process that matches the required parameter's process ID.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results
##### Base Command
`fidelis-endpoint-kill-process`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ip | The endpoint IP address. | Optional | 
| time_out | Script time out (in seconds). The default is 300. | Optional | 
| operating_system | System OS. Can be "Windows", "Linux", or "macOS". | Required | 
| pid | Process ID. Get the PID from the script-manifest command. | Required | 
| endpoint_name | The name of the endpoint. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Process.JobID | String | Script job ID. | 
| FidelisEndpoint.Process.ID | String | Script ID. | 
##### Command Example
```!fidelis-endpoint-kill-process operating_system=Windows pid=516 endpoint_ip=2.2.2.2```
##### Context Example
```
{
    "FidelisEndpoint.Process": {
        "ID": "8d379688-dde1-451d-8fa2-4f29c84baf97", 
        "JobID": "25548787-e75c-4c55-96d5-ab8a0211a820"
    }
}
```
##### Human Readable Output
The job has been executed successfully. 
 Job ID: 25548787-e75c-4c55-96d5-ab8a0211a820
### 13. fidelis-endpoint-delete-file
---
Deletes a file at the specified path.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results
##### Base Command
`fidelis-endpoint-delete-file`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ip | Endpoint IP address. | Optional | 
| time_out | Script time out (in seconds). The default is 300. | Optional | 
| operating_system | System OS. Can be "Windows", "Linux", or "macOS". | Required | 
| file_path | The path of the file to delete. | Required | 
| endpoint_name | The name of the endpoint. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Script.ID | String | Script ID. | 
| FidelisEndpoint.Script.JobID | String | Script job ID. | 
##### Command Example
```!fidelis-endpoint-delete-file file_path=c:\\Users\\admin\\Documents\\test.txt operating_system=Windows endpoint_ip=2.2.2.2 ```
##### Human Readable Output
The job has been executed successfully.
Job ID: 4317e979-81df-46d8-8eb1-ab8a023ef4d8
### 14. fidelis-endpoint-isolate-network
---
Quarantines an endpoint. While isolated, the endpoint's network communication is restricted to only the allowed servers.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results
##### Base Command
`fidelis-endpoint-isolate-network`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ip | The endpoint IP address to isolate. | Optional | 
| time_out | Script timeout (in seconds). The default is 300. | Optional | 
| operating_system | The system OS. Can be "Windows", "Linux", or "macOS". | Required | 
| allowed_server | The server IP address that can communicate with the isolated endpoint. For example: 2.2.2.2. | Required | 
| endpoint_name | The name of the endpoint. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Isolation.ID | String | Script ID. | 
| FidelisEndpoint.Isolation.JobID | String | Script job ID. | 
##### Command Example
```!fidelis-endpoint-isolate-network operating_system=Windows allowed_server=10.10.10.10 endpoint_ip=10.10.0.1```
##### Human Readable Output
The job has been executed successfully.
Job ID: f25691bd-ba78-4f40-9a25-ab8a02420abc
### 15. fidelis-endpoint-remove-network-isolation
---
Removes the endpoint from isolation.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results
##### Base Command
`fidelis-endpoint-remove-network-isolation`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ip | The isolated endpoint IP address. | Optional | 
| time_out | Script timeout (in seconds). The default is 300. | Optional | 
| operating_system | System OS. Can be "Windows", "Linux", or "macOS". | Required | 
| endpoint_name | The name of the endpoint. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Isolation.ID | String | Script ID. | 
| FidelisEndpoint.Isolation.JobID | String | Script job ID. | 
##### Command Example
```!fidelis-endpoint-remove-network-isolation operating_system=Windows endpoint_ip=10.128.0.1 ```
##### Human Readable Output
The job has been executed successfully.
Job ID: 7a0a3179-3bce-43d1-80c0-ab8a0242d147
### 16. fidelis-endpoint-script-job-status
---
Gets the script execution status.
##### Required Permissions
The required permissions: Scripts, View Executables, View Task Results
##### Base Command
`fidelis-endpoint-script-job-status`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_result_id | The script execution job result ID. Get the ID from the following commands: script-execution, file-search, list-processes, kill-process-by-pid, delete-file, network-isolation, remove-network-isolation. | Required | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.ScriptResult.JobName | String | The job name. | 
| FidelisEndpoint.ScriptResult.JobResultID | String | Job result ID. | 
| FidelisEndpoint.ScriptResult.Name | String | Target name. | 
| FidelisEndpoint.ScriptResult.Status | String | Script execution status. | 
##### Command Example
```!fidelis-endpoint-script-job-status job_result_id=fc94568c-9a15-4fa2-af08-ab8a01f5e86c```
##### Context Example
```
{
    "FidelisEndpoint.ScriptResult": [
        {
            "Status": "Completed", 
            "Name": "fidelis-endpoint-winserver2019", 
            "JobResultID": "fc94568c-9a15-4fa2-af08-ab8a01f5e86c", 
            "JobName": "Process List-03-26-2020 9.08.12"
        }
    ]
}
```
##### Human Readable Output
### Fidelis Endpoint script job status
|JobName|JobResultID|Name|Status|
|---|---|---|---|
| Process List-03-26-2020 9.08.12 | fc94568c-9a15-4fa2-af08-ab8a01f5e86c | fidelis-endpoint-winserver2019 | Completed |
### 17. fidelis-endpoint-execute-script
---
Executes a script package from Fidelis endpoint packages.
##### Required Permissions
The required permissions: Scripts, View Executables
##### Base Command
`fidelis-endpoint-execute-script`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | Script ID. Get the script ID from the list-scripts command. | Required | 
| time_out | Script time out (in seconds). The default is 300. | Optional | 
| endpoint_ip | Endpoint IP address on which to run the script. | Optional | 
| answer | The script to run. Get the answer from the script-manifest command. | Required | 
| endpoint_name | The name of the endpoint. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Script.ID | String | Script ID. | 
| FidelisEndpoint.Script.JobID | String | Script job ID. | 
##### Command Example
```!fidelis-endpoint-execute-script script_id="2d32a530-0716-4542-afdc-8da3bd47d8bf" time_out="300" endpoint_ip="2.2.2.2" answer="true"```
##### Context Example
```
{
    "FidelisEndpoint.Script": {
        "ID": "2d32a530-0716-4542-afdc-8da3bd47d8bf", 
        "JobID": "8ac08ab1-e6f4-4aa1-9784-ab8a02115483"
    }
}
```
##### Human Readable Output
The job has been executed successfully. 
 Job ID: 8ac08ab1-e6f4-4aa1-9784-ab8a02115483
### 18. fidelis-endpoint-query-file
---
Queries a file by file hash.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results.
##### Base Command
`fidelis-endpoint-query-file`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start time of the event in the system in UTC format.<br/>Supported values: "2019-10-21T23:45:00" (date). | Optional | 
| end_time | The end time of the event in the system in UTC format.<br/>Supported values:"2019-10-21T23:45:00" (date). | Optional | 
| logic | The logic of the query. Can be "and" or "or". | Required | 
| file_hash | The MD5 file hash to search for. | Required | 
| limit | The maximum number of results to return. The default is 50. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Query.ProcessStartTime | Date | The process start time. | 
| FidelisEndpoint.Query.EndpointName | String | Endpoint name. | 
| FidelisEndpoint.Query.CertificateSubjectName | String | Certificate subject name. | 
| FidelisEndpoint.Query.Size | Number | File size. | 
| FidelisEndpoint.Query.FileExtension | String | File extension. | 
| FidelisEndpoint.Query.Path | String | File path. | 
| FidelisEndpoint.Query.CertificatePublisher | String | Certificate publisher. | 
| FidelisEndpoint.Query.ParentID | String | Process parent ID. | 
| FidelisEndpoint.Query.EventTime | Date | Event time. | 
| FidelisEndpoint.Query.SignedTime | Date | Signed time. | 
| FidelisEndpoint.Query.Name | String | File name. | 
| FidelisEndpoint.Query.TargetID | String | Target ID. | 
| FidelisEndpoint.Query.Hash | String | File hash. | 
| FidelisEndpoint.Query.StartTime | Date | Event start time. | 
| FidelisEndpoint.Query.HashSHA1 | String | File SHA1 hash. | 
| FidelisEndpoint.Query.EventType | Number | Event type. | 
| FidelisEndpoint.Query.HashSHA256 | String | File SHA256 hash. | 
| FidelisEndpoint.Query.ParentName | String | Process parent name. | 
| FidelisEndpoint.Query.FileType | Number | File type. | 
| FidelisEndpoint.Query.Signature | Number | File signature. | 
| FidelisEndpoint.Query.EventIndex | Number | Event index. | 
| FidelisEndpoint.Query.FileCategory | Number | File category. | 
| FidelisEndpoint.Query.CertificateIssuerName | String | Certificate issuer name. | 
| FidelisEndpoint.Query.FileVersion | String | File version. | 
| FidelisEndpoint.Query.IndexingTime | Date | Indexing time. | 
| FidelisEndpoint.Query.EntityType | Number | Entity type. | 
| File.Name | String | The full file name (including file extension). | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension, for example: "txt". | 
| File.Type | Number | The file type, as determined by libmagic (same as displayed in file entries). | 
| File.Path | String | The path where the file is located. | 
| File.Hostname | String | The name of the host where the file was found. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.FileVersion | String | The file version. | 
##### Command Example
```!fidelis-endpoint-query-file logic="and" file_hash="8a0a29438052faed8a2532da50451234"```
##### Context Example
```
{
    "FidelisEndpoint.Query": [
        {
            "EntityType": 1, 
            "TargetID": "aW9qfAMZ5a3", 
            "StartTime": "2020-03-26T09:02:26.511Z", 
            "FileExtension": "exe", 
            "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)", 
            "ProcessStartTime": "2020-03-26T09:02:26.511Z", 
            "IndexingTime": "2020-03-26T09:06:31.958Z", 
            "CertificateSubjectName": "Microsoft Windows Publisher", 
            "EventType": 2, 
            "ParentName": "svchost.exe", 
            "HashSHA1": "a1385ce20ad79f55df235effd9780c31442aa456", 
            "SignedTime": "1:29 9/15/2018", 
            "EventIndex": 1, 
            "Path": "C:\\Windows\\System32\\svchost.exe", 
            "EventTime": "2020-03-26T09:02:26.511Z", 
            "Name": "svchost.exe", 
            "CertificatePublisher": "Microsoft Corporation", 
            "FileType": "8", 
            "HashSHA256": "7fd065bac18c5278777ae44908101cdfed72d26fa741367f0ad4d02020565ab6", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "Signature": "16", 
            "Hash": "8a0a29438052faed8a2532da50455456", 
            "FileCategory": "776", 
            "ParentID": "rSdnlXD7OX6", 
            "CertificateIssuerName": "Microsoft Windows Production PCA 2011", 
            "Size": 51696
        }, 
        {
            "EntityType": 1, 
            "TargetID": "aW9qfAMZ5a3", 
            "StartTime": "2020-03-26T08:02:26.197Z", 
            "FileExtension": "exe", 
            "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)", 
            "ProcessStartTime": "2020-03-26T08:02:26.197Z", 
            "IndexingTime": "2020-03-26T08:05:00.035Z", 
            "CertificateSubjectName": "Microsoft Windows Publisher", 
            "EventType": 2, 
            "ParentName": "svchost.exe", 
            "HashSHA1": "a1385ce20ad79f55df235effd9780c31442aa456", 
            "SignedTime": "1:29 9/15/2018", 
            "EventIndex": 1, 
            "Path": "C:\\Windows\\System32\\svchost.exe", 
            "EventTime": "2020-03-26T08:02:26.197Z", 
            "Name": "svchost.exe", 
            "CertificatePublisher": "Microsoft Corporation", 
            "FileType": "8", 
            "HashSHA256": "7fd065bac18c1234777ae44908101cdfed72d26fa741367f0ad4d02020787ab6", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "Signature": "16", 
            "Hash": "8a0a29438052faed8a2532da12355756", 
            "FileCategory": "776", 
            "ParentID": "m31v1MqQ6", 
            "CertificateIssuerName": "Microsoft Windows Production PCA 2011", 
            "Size": 51696
        }, 
        {
            "EntityType": 1, 
            "TargetID": "aW9qfAMZ5a3", 
            "StartTime": "2020-03-26T07:02:25.887Z", 
            "FileExtension": "exe", 
            "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)", 
            "ProcessStartTime": "2020-03-26T07:02:25.887Z", 
            "IndexingTime": "2020-03-26T07:08:28.331Z", 
            "CertificateSubjectName": "Microsoft Windows Publisher", 
            "EventType": 2, 
            "ParentName": "svchost.exe", 
            "HashSHA1": "a1385ce20ad79f55df235effd9780c31442aa456", 
            "SignedTime": "1:29 9/15/2018", 
            "EventIndex": 1, 
            "Path": "C:\\Windows\\System32\\svchost.exe", 
            "EventTime": "2020-03-26T07:02:25.887Z", 
            "Name": "svchost.exe", 
            "CertificatePublisher": "Microsoft Corporation", 
            "FileType": "8", 
            "HashSHA256": "7fd065bac18c5123777ae44908101cdfed72d26fa741367f0ad4d02020787ab6", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "Signature": "16", 
            "Hash": "8a0a29438052faed8a2532da50455123", 
            "FileCategory": "776", 
            "ParentID": "fmz4un6Qzfd", 
            "CertificateIssuerName": "Microsoft Windows Production PCA 2011", 
            "Size": 51696
        }, 
        {
            "EntityType": 1, 
            "TargetID": "aW9qfAMZ5a3", 
            "StartTime": "2020-03-26T06:15:07.125Z", 
            "FileExtension": "exe", 
            "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)", 
            "ProcessStartTime": "2020-03-26T06:15:07.125Z", 
            "IndexingTime": "2020-03-26T06:20:26.814Z", 
            "CertificateSubjectName": "Microsoft Windows Publisher", 
            "EventType": 2, 
            "ParentName": "svchost.exe", 
            "HashSHA1": "a1385ce20ad79f55df235effd9780c31442aa456", 
            "SignedTime": "1:29 9/15/2018", 
            "EventIndex": 1, 
            "Path": "C:\\Windows\\System32\\svchost.exe", 
            "EventTime": "2020-03-26T06:15:07.125Z", 
            "Name": "svchost.exe", 
            "CertificatePublisher": "Microsoft Corporation", 
            "FileType": "8", 
            "HashSHA256": "7fd065bac18c5278777ae44908101cdfed72d26fa741367f0ad4d02020787ab6", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "Signature": "16", 
            "Hash": "8a0a29438052faed8a2532da50455123", 
            "FileCategory": "776", 
            "ParentID": "fS3SPnQU5Xe", 
            "CertificateIssuerName": "Microsoft Windows Production PCA 2011", 
            "Size": 51696
        }, 
        {
            "EntityType": 1, 
            "TargetID": "aW9qfAMZ5a3", 
            "StartTime": "2020-03-26T06:02:25.581Z", 
            "FileExtension": "exe", 
            "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)", 
            "ProcessStartTime": "2020-03-26T06:02:25.581Z", 
            "IndexingTime": "2020-03-26T06:05:26.740Z", 
            "CertificateSubjectName": "Microsoft Windows Publisher", 
            "EventType": 2, 
            "ParentName": "svchost.exe", 
            "HashSHA1": "a1385ce20ad79f55df235effd9780c31442aa456", 
            "SignedTime": "1:29 9/15/2018", 
            "EventIndex": 1, 
            "Path": "C:\\Windows\\System32\\svchost.exe", 
            "EventTime": "2020-03-26T06:02:25.581Z", 
            "Name": "svchost.exe", 
            "CertificatePublisher": "Microsoft Corporation", 
            "FileType": "8", 
            "HashSHA256": "7fd065bac18c5278777ae44908101cdfed72d26fa741367f0ad4d02020232cb6", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "Signature": "16", 
            "Hash": "8a0a29438052faed8a2532da50455123", 
            "FileCategory": "776", 
            "ParentID": "s8Iu12ulYKh", 
            "CertificateIssuerName": "Microsoft Windows Production PCA 2011", 
            "Size": 51696
        }
     ], 
    "File": [
        {
            "SHA1": "a1385ce20ad79f55df235effd9780c31442aa456", 
            "SHA256": "7fd065bac18c5278777ae44908101cdfed72d26fa741367f0ad4d02020232cb6", 
            "Name": "svchost.exe", 
            "Extension": "exe", 
            "Hostname": "fidelis-endpoint-winserver2019", 
            "Size": 51696, 
            "Path": "C:\\Windows\\System32\\svchost.exe", 
            "MD5": "8a0a29438052faed8a2532da50451234", 
            "Type": "8", 
            "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)"
        }, 
        {
            "SHA1": "a1385ce20ad79f55df235effd9780c31442aa234", 
            "SHA256": "7fd065bac18c5278777ae44908101cdfed72d26fa741367f0ad4d02020787ab6", 
            "Name": "svchost.exe", 
            "Extension": "exe", 
            "Hostname": "fidelis-endpoint-winserver2019", 
            "Size": 51696, 
            "Path": "C:\\Windows\\System32\\svchost.exe", 
            "MD5": "8a0a23438052faed8a2532da50455756", 
            "Type": "8", 
            "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)"
        }, 
        {
            "SHA1": "a1385ce20ad79f55df235effd9780c31442aa234", 
            "SHA256": "7fd065bac18c5278777ae44908101cdfed72d26fa741367f0ad4d02020787ab6", 
            "Name": "svchost.exe", 
            "Extension": "exe", 
            "Hostname": "fidelis-endpoint-winserver2019", 
            "Size": 51696, 
            "Path": "C:\\Windows\\System32\\svchost.exe", 
            "MD5": "8a0a29438052faed8a2532da50451234", 
            "Type": "8", 
            "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)"
        }, 
        {
            "SHA1": "a1385ce20ad79f55df235effd9780c31442aa234", 
            "SHA256": "7fd065bac18c5278777ae44908101cdfed72d26fa741367f0ad4d02020787ab6", 
            "Name": "svchost.exe", 
            "Extension": "exe", 
            "Hostname": "fidelis-endpoint-winserver2019", 
            "Size": 51696, 
            "Path": "C:\\Windows\\System32\\svchost.exe", 
            "MD5": "8a0a29438052faed8a2532da50451234", 
            "Type": "8", 
            "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)"
        }, 
        {
            "SHA1": "a1385ce20ad79f55df235effd9780c31442aa234", 
            "SHA256": "7fd065bac18c5278777ae44908101cdfed72d26fa741367f0ad4d02020787ab6", 
            "Name": "svchost.exe", 
            "Extension": "exe", 
            "Hostname": "fidelis-endpoint-winserver2019", 
            "Size": 51696, 
            "Path": "C:\\Windows\\System32\\svchost.exe", 
            "MD5": "8a0a29438052faed8a2532da50451234", 
            "Type": "8", 
            "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)"
        }, 
    ]
}
```
##### Human Readable Output
### Fidelis Endpoint file hash query results
|EndpointName|Name|Path|Hash|ProcessStartTime|ParentName|EventType|
|---|---|---|---|---|---|---|
| fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | 8a0a29438052faed8a2532da50451234 | 2020-03-26T09:02:26.511Z | svchost.exe | 2 |
| fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | 8a0a29438052faed8a2532da50451234 | 2020-03-26T08:02:26.197Z | svchost.exe | 2 |
| fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | 8a0a29438052faed8a2532da50451234 | 2020-03-26T07:02:25.887Z | svchost.exe | 2 |
| fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | 8a0a29438052faed8a2532da50451234 | 2020-03-26T06:15:07.125Z | svchost.exe | 2 |
| fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | 8a0a29438052faed8a2532da50451234 | 2020-03-26T06:02:25.581Z | svchost.exe | 2 |
| fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | 8a0a29438052faed8a2532da50451234 | 2020-03-26T05:02:25.266Z | svchost.exe | 2 |
| fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | 8a0a29438052faed8a2532da50451234 | 2020-03-26T04:54:08.244Z | svchost.exe | 2 |
### 19. fidelis-endpoint-query-process
---
Query process.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results
##### Base Command
`fidelis-endpoint-query-process`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start time of the event in the system in UTC format.<br/>Supported values: "2019-10-21T23:45:00" (date). | Optional | 
| end_time | The end time of the event in the system in UTC format.<br/>Supported values:"2019-10-21T23:45:00" (date). | Optional | 
| logic | The logic of the query. Can be "and" or "or". | Required | 
| process_name | The process name to query. | Required | 
| limit | The maximum number of results to return. The default is 50. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Query.ProcessStartTime | String | Process start time. | 
| FidelisEndpoint.Query.EndpointName | String | Endpoint name. | 
| FidelisEndpoint.Query.Path | String | The path of the process. | 
| FidelisEndpoint.Query.ParentID | String | Process parent ID. | 
| FidelisEndpoint.Query.EventTime | Date | Event time. | 
| FidelisEndpoint.Query.PID | String | Process ID. | 
| FidelisEndpoint.Query.Name | String | Process name. | 
| FidelisEndpoint.Query.User | String | The user of the system. | 
| FidelisEndpoint.Query.TargetID | String | Process target ID. | 
| FidelisEndpoint.Query.Hash | String | File hash. | 
| FidelisEndpoint.Query.StartTime | Date | Process start time. | 
| FidelisEndpoint.Query.EventType | Number | Event type. | 
| FidelisEndpoint.Query.ParentName | String | Process parent name. | 
| FidelisEndpoint.Query.IndexingTime | Date | Indexing time. | 
| FidelisEndpoint.Query.EntityType | Number | Entity type. | 
##### Command Example
```!fidelis-endpoint-query-process logic="and" process_name="svchost.exe"```
##### Context Example
```
{
    "FidelisEndpoint.Query": [
        {
            "EsDocumentType": "processlog", 
            "EventTime": "2020-03-26T09:02:26.511Z", 
            "IndexingTime": "2020-03-26T09:06:31.958Z", 
            "Hash": "8a0a29438052faed8a2532da50451234", 
            "Name": "svchost.exe", 
            "ParentName": "services.exe", 
            "EsIndex": "eh_20200326_1585180800000_0", 
            "EventType": 0, 
            "TargetID": "rSdnlXD7OX6", 
            "EntityType": 0, 
            "PID": 4432, 
            "ProcessStartTime": "2020-03-26T09:02:26.511Z", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "User": "NT AUTHORITY\\SYSTEM", 
            "StartTime": "2020-03-26T09:02:26.511Z", 
            "ParentID": "TG9An342Ym8", 
            "Path": "C:\\Windows\\System32\\svchost.exe"
        }, 
        {
            "EsDocumentType": "processlog", 
            "EventTime": "2020-03-26T08:02:26.197Z", 
            "IndexingTime": "2020-03-26T08:05:00.035Z", 
            "Hash": "8a0a29438052faed8a2532da50451234", 
            "Name": "svchost.exe", 
            "ParentName": "services.exe", 
            "EsIndex": "eh_20200326_1585180800000_0", 
            "EventType": 0, 
            "TargetID": "m31v1MqQ6", 
            "EntityType": 0, 
            "PID": 2084, 
            "ProcessStartTime": "2020-03-26T08:02:26.197Z", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "User": "NT AUTHORITY\\SYSTEM", 
            "StartTime": "2020-03-26T08:02:26.197Z", 
            "ParentID": "TG9An342Ym8", 
            "Path": "C:\\Windows\\System32\\svchost.exe"
        }, 
        {
            "EsDocumentType": "processlog", 
            "EventTime": "2020-03-26T07:02:25.887Z", 
            "IndexingTime": "2020-03-26T07:08:28.331Z", 
            "Hash": "8a0a29438052faed8a2532da50451234", 
            "Name": "svchost.exe", 
            "ParentName": "services.exe", 
            "EsIndex": "eh_20200326_1585180800000_0", 
            "EventType": 0, 
            "TargetID": "fmz4un6Qzfd", 
            "EntityType": 0, 
            "PID": 1972, 
            "ProcessStartTime": "2020-03-26T07:02:25.887Z", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "User": "NT AUTHORITY\\SYSTEM", 
            "StartTime": "2020-03-26T07:02:25.887Z", 
            "ParentID": "TG9An342Ym8", 
            "Path": "C:\\Windows\\System32\\svchost.exe"
        }, 
        {
            "EsDocumentType": "processlog", 
            "EventTime": "2020-03-26T06:15:07.125Z", 
            "IndexingTime": "2020-03-26T06:20:26.814Z", 
            "Hash": "8a0a29438052faed8a2532da50451234", 
            "Name": "svchost.exe", 
            "ParentName": "services.exe", 
            "EsIndex": "eh_20200326_1585180800000_0", 
            "EventType": 0, 
            "TargetID": "fS3SPnQU5Xe", 
            "EntityType": 0, 
            "PID": 656, 
            "ProcessStartTime": "2020-03-26T06:15:07.125Z", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "User": "NT AUTHORITY\\NETWORK SERVICE", 
            "StartTime": "2020-03-26T06:15:07.125Z", 
            "ParentID": "TG9An342Ym8", 
            "Path": "C:\\Windows\\System32\\svchost.exe"
        }, 
        {
            "EsDocumentType": "processlog", 
            "EventTime": "2020-03-25T19:02:22.160Z", 
            "IndexingTime": "2020-03-25T19:06:37.610Z", 
            "Hash": "8a0a29438052faed8a2532da50451234", 
            "Name": "svchost.exe", 
            "ParentName": "services.exe", 
            "EsIndex": "eh_20200325_1585094400000_0", 
            "EventType": 0, 
            "TargetID": "byvPk5D9Mdd", 
            "EntityType": 0, 
            "PID": 2692, 
            "ProcessStartTime": "2020-03-25T19:02:22.160Z", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "User": "NT AUTHORITY\\SYSTEM", 
            "StartTime": "2020-03-25T19:02:22.160Z", 
            "ParentID": "TG9An342Ym8", 
            "Path": "C:\\Windows\\System32\\svchost.exe"
        }
    ]
}
```
##### Human Readable Output
### Fidelis Endpoint process results
|PID|EndpointName|Name|Path|User|Hash|ProcessStartTime|Parameters|ParentName|EventType|
|---|---|---|---|---|---|---|---|---|---|
| 4432 | fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | NT AUTHORITY\SYSTEM | 8a0a29438052faed8a2532da50451234 | 2020-03-26T09:02:26.511Z | C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc | services.exe | 0 |
| 2084 | fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | NT AUTHORITY\SYSTEM | 8a0a29438052faed8a2532da50451234 | 2020-03-26T08:02:26.197Z | C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc | services.exe | 0 |
| 1972 | fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | NT AUTHORITY\SYSTEM | 8a0a29438052faed8a2532da50451234 | 2020-03-26T07:02:25.887Z | C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc | services.exe | 0 |
| 656 | fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | 8a0a29438052faed8a2532da50451234 | 2020-03-26T06:15:07.125Z | C:\Windows\System32\svchost.exe -k NetworkService -p -s DoSvc | services.exe | 0 |
| 1400 | fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | NT AUTHORITY\SYSTEM | 8a0a29438052faed8a2532da50451234 | 2020-03-26T06:02:25.581Z | C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc | services.exe | 0 |
| 2800 | fidelis-endpoint-winserver2019 | svchost.exe | C:\Windows\System32\svchost.exe | NT AUTHORITY\SYSTEM | 8a0a29438052faed8a2532da50451234 | 2020-03-26T05:02:25.266Z | C:\Windows\System32\svchost.exe -k netsvcs -p -s NetSetupSvc | services.exe | 0 |
### 20. fidelis-endpoint-query-connection-by-remote-ip
---
Queries a connection by remote IP address.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results
##### Base Command
`fidelis-endpoint-query-connection-by-remote-ip`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start time of the event in the system in UTC format.<br/>Supported values: "2019-10-21T23:45:00" (date). | Optional | 
| end_time | The end time of the event in the system in UTC format.<br/>Supported values:"2019-10-21T23:45:00" (date). | Optional | 
| logic | The logic of the query. Can be "and" or "or". | Required | 
| remote_ip | The remote IP address on which to query. | Required | 
| limit | The maximum number of results to return. The default is 50. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Query.ProcessStartTime | Date | Process start time. | 
| FidelisEndpoint.Query.EndpointName | String | Endpoint name. | 
| FidelisEndpoint.Query.ParentID | String | Process parent ID. | 
| FidelisEndpoint.Query.EventTime | Date | Event time. | 
| FidelisEndpoint.Query.RemotePort | Number | Remote port. | 
| FidelisEndpoint.Query.LocalPort | Number | Local port. | 
| FidelisEndpoint.Query.TargetID | String | Target ID. | 
| FidelisEndpoint.Query.RemoteIP | String | Remote IP address. | 
| FidelisEndpoint.Query.StartTime | Date | Event start time. | 
| FidelisEndpoint.Query.EndpointID | String | Endpoint ID. | 
| FidelisEndpoint.Query.NetworkDirection | Number | Network direction. | 
| FidelisEndpoint.Query.LastEventTime | Date | Last event time. | 
| FidelisEndpoint.Query.LocalIP | String | Local IP address. | 
| FidelisEndpoint.Query.EventType | Number | Event type. | 
| FidelisEndpoint.Query.ParentName | String | Parent name. | 
| FidelisEndpoint.Query.FirstEventTime | Date | First event time. | 
| FidelisEndpoint.Query.EventIndex | Number | Event Index. | 
| FidelisEndpoint.Query.Protocol | String | Protocol. | 
| FidelisEndpoint.Query.PPID | Number | Process parent ID. | 
| FidelisEndpoint.Query.EntityType | Number | Entity type. | 
| FidelisEndpoint.Query.ParentHashSHA1 | String | Parent SHA1 hash. | 
##### Command Example
```!fidelis-endpoint-query-connection-by-remote-ip logic=and remote_ip=10.10.0.1 limit=5```
##### Context Example
```
{
    "FidelisEndpoint.Query": [
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-26T09:32:31.172Z", 
            "ParentName": "svchost.exe", 
            "Protocol": "UDP", 
            "EndpointID": "3494cb0f-67ba-41bc-9190-ab5d015dd57c", 
            "LastEventTime": "2020-03-26T09:32:31.172Z", 
            "FirstEventTime": "2020-03-26T09:28:31.148Z", 
            "EventType": 3, 
            "EntityType": 3, 
            "TargetID": "O6ZdOEYU2z8", 
            "ProcessStartTime": "2020-03-12T03:58:09.962Z", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-03-12T03:58:09.962Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 10, 
            "ParentID": "jE4aX1xPk1i", 
            "NetworkDirection": "0", 
            "PPID": 1196, 
            "parentHashSHA1": "a1385ce20ad79f55df235effd9780c31442aa234", 
            "LocalPort": "64669"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-26T09:32:31.169Z", 
            "ParentName": "svchost.exe", 
            "Protocol": "UDP", 
            "EndpointID": "3494cb0f-67ba-41bc-9190-ab5d015dd57c", 
            "LastEventTime": "2020-03-26T09:32:31.172Z", 
            "FirstEventTime": "2020-03-26T09:28:31.148Z", 
            "EventType": 3, 
            "EntityType": 3, 
            "TargetID": "Do8ec6zGCEi", 
            "ProcessStartTime": "2020-03-12T03:58:09.962Z", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-03-12T03:58:09.962Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 9, 
            "ParentID": "jE4aX1xPk1i", 
            "NetworkDirection": "2", 
            "PPID": 1196, 
            "parentHashSHA1": "a1385ce20ad79f55df235effd9780c31442aa234", 
            "LocalPort": "64669"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-26T09:32:14.522Z", 
            "ParentName": "svchost.exe", 
            "Protocol": "UDP", 
            "EndpointID": "3494cb0f-67ba-41bc-9190-ab5d015dd57c", 
            "LastEventTime": "2020-03-26T09:32:31.172Z", 
            "FirstEventTime": "2020-03-26T09:28:31.148Z", 
            "EventType": 3, 
            "EntityType": 3, 
            "TargetID": "8825LGOTGzf", 
            "ProcessStartTime": "2020-03-12T03:58:09.962Z", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-03-12T03:58:09.962Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 8, 
            "ParentID": "jE4aX1xPk1i", 
            "NetworkDirection": "0", 
            "PPID": 1196, 
            "parentHashSHA1": "a1385ce20ad79f55df235effd9780c31442aa234", 
            "LocalPort": "53557"
        }
    ]
}
```
##### Human Readable Output
### Fidelis Endpoint query results for connection by remote IP
|EndpointID|EndpointName|PPID|LocalIP|LocalPort|RemoteIP|RemotePort|ProcessStartTime|FirstEventTime|LastEventTime|Protocol|ParentHashSHA1|ParentName|EventType|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 1196 | 2.2.2.2 | 64669 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | 2020-03-26T09:28:31.148Z | 2020-03-26T09:32:31.172Z | UDP | a1385ce20ad79f55df235effd9780c31442aa234 | svchost.exe | 3 |
| 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 1196 | 2.2.2.2 | 64669 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | 2020-03-26T09:28:31.148Z | 2020-03-26T09:32:31.172Z | UDP | a1385ce20ad79f55df235effd9780c31442aa234 | svchost.exe | 3 |
| 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 1196 | 2.2.2.2 | 53557 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | 2020-03-26T09:28:31.148Z | 2020-03-26T09:32:31.172Z | UDP | a1385ce20ad79f55df235effd9780c31442aa234 | svchost.exe | 3 |
| 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 1196 | 2.2.2.2 | 53557 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | 2020-03-26T09:28:31.148Z | 2020-03-26T09:32:31.172Z | UDP | a1385ce20ad79f55df235effd9780c31442aa234 | svchost.exe | 3 |
| 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 1196 | 2.2.2.2 | 60427 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | 2020-03-26T09:28:31.148Z | 2020-03-26T09:32:31.172Z | UDP | a1385ce20ad79f55df235effd9780c31442aa234 | svchost.exe | 3 |
| 3494cb0f-67ba-41bc-9190-ab5d015dd57c | fidelis-endpoint-winserver2019 | 1196 | 2.2.2.2 | 60427 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | 2020-03-26T09:28:31.148Z | 2020-03-26T09:32:31.172Z | UDP | a1385ce20ad79f55df235effd9780c31442aa234 | svchost.exe | 3 |
### 21. fidelis-endpoint-query-by-dns
---
Queries by DNS request.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results
##### Base Command
`fidelis-endpoint-query-by-dns`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start time of the event in the system in UTC format.<br/>Supported values: "2019-10-21T23:45:00" (date). | Optional | 
| end_time | The end time of the event in the system in UTC format.<br/>Supported values:"2019-10-21T23:45:00" (date). | Optional | 
| logic | The logic of the query. Can be "and" or "or". | Required | 
| url | URL or domain on which to query. | Required | 
| limit | The maximum number of results to return. The default is 50. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Query.ProcessStartTime | Date | Process start time. | 
| FidelisEndpoint.Query.EndpointName | String | Endpoint name. | 
| FidelisEndpoint.Query.ParentID | String | Parent ID. | 
| FidelisEndpoint.Query.EventTime | Date | Event time. | 
| FidelisEndpoint.Query.RemotePort | Number | Remote port. | 
| FidelisEndpoint.Query.DnsAnswer | String | The DNS answer. | 
| FidelisEndpoint.Query.LocalPort | Number | Local port. | 
| FidelisEndpoint.Query.TargetID | String | The target ID. | 
| FidelisEndpoint.Query.RemoteIP | String | Remote IP address. | 
| FidelisEndpoint.Query.DnsQuestion | String | The DNS question. | 
| FidelisEndpoint.Query.StartTime | Date | Event start time. | 
| FidelisEndpoint.Query.NetworkDirection | Number | Network direction. | 
| FidelisEndpoint.Query.LocalIP | String | Local IP address. | 
| FidelisEndpoint.Query.EventType | Number | Event type. | 
| FidelisEndpoint.Query.EventIndex | Number | Event index. | 
| FidelisEndpoint.Query.IndexingTime | Date | Indexing time. | 
| FidelisEndpoint.Query.EntityType | Number | Entity type. | 
##### Command Example
```!fidelis-endpoint-query-by-dns start_time="2019-10-02T00:00:00.842Z" end_time="2020-03-08T15:50:05.552Z" logic="and" url="login.live.com"```
##### Context Example
```
{
    "FidelisEndpoint.Query": [
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-08T06:13:14.009Z", 
            "IndexingTime": "2020-03-08T06:21:15.635Z", 
            "LocalPort": "49862", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "UmDG80sJNc6", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"login.live.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-02-13T03:50:45.515Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 6, 
            "ParentID": "VuFd4n1aut7", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"login.live.com\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"login.msa.msidentity.com\",\"IP\":\"\",\"TTL\":\"299\"},{\"name\":\"login.msa.msidentity.com\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"login.msa.akadns6.net\",\"IP\":\"\",\"TTL\":\"299\"},{\"name\":\"login.msa.akadns6.net\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"ipv4.login.msa.akadns6.net\",\"IP\":\"\",\"TTL\":\"299\"},{\"name\":\"ipv4.login.msa.akadns6.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"3.3.3.3\",\"TTL\":\"299\"}]}", 
            "ProcessStartTime": "2020-02-13T03:50:45.515Z"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-08T03:55:54.514Z", 
            "IndexingTime": "2020-03-08T04:03:12.475Z", 
            "LocalPort": "53712", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "UmDG80sJNc6", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"login.live.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-02-13T03:50:45.515Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 2, 
            "ParentID": "VuFd4n1aut7", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"login.live.com\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"login.msa.msidentity.com\",\"IP\":\"\",\"TTL\":\"51\"},{\"name\":\"login.msa.msidentity.com\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"lgin.msa.trafficmanager.net\",\"IP\":\"\",\"TTL\":\"51\"},{\"name\":\"lgin.msa.trafficmanager.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"2.2.2.2\",\"TTL\":\"59\"},{\"name\":\"lgin.msa.trafficmanager.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"3.3.3.3\",\"TTL\":\"59\"},{\"name\":\"lgin.msa.trafficmanager.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"4.4.4.4\",\"TTL\":\"59\"}]}", 
            "ProcessStartTime": "2020-02-13T03:50:45.515Z"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-08T03:11:13.833Z", 
            "IndexingTime": "2020-03-08T03:17:38.628Z", 
            "LocalPort": "61574", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "UmDG80sJNc6", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"login.live.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-02-13T03:50:45.515Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 5, 
            "ParentID": "VuFd4n1aut7", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"login.live.com\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"login.msa.msidentity.com\",\"IP\":\"\",\"TTL\":\"230\"},{\"name\":\"login.msa.msidentity.com\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"lgin.msa.trafficmanager.net\",\"IP\":\"\",\"TTL\":\"235\"},{\"name\":\"lgin.msa.trafficmanager.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"3.3.3.3\",\"TTL\":\"56\"},{\"name\":\"lgin.msa.trafficmanager.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"2.2.2.2\",\"TTL\":\"56\"},{\"name\":\"lgin.msa.trafficmanager.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"7.7.7.7\",\"TTL\":\"56\"}]}", 
            "ProcessStartTime": "2020-02-13T03:50:45.515Z"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-07T21:53:12.298Z", 
            "IndexingTime": "2020-03-07T21:57:29.402Z", 
            "LocalPort": "57803", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "UmDG80sJNc6", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"login.live.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-02-13T03:50:45.515Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 4, 
            "ParentID": "VuFd4n1aut7", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"login.live.com\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"login.msa.msidentity.com\",\"IP\":\"\",\"TTL\":\"16\"},{\"name\":\"login.msa.msidentity.com\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"lgin.msa.trafficmanager.net\",\"IP\":\"\",\"TTL\":\"197\"},{\"name\":\"lgin.msa.trafficmanager.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"3.3.3.3\",\"TTL\":\"59\"},{\"name\":\"lgin.msa.trafficmanager.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"2.2.2.2\",\"TTL\":\"59\"},{\"name\":\"lgin.msa.trafficmanager.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"7.7.7.7\",\"TTL\":\"59\"}]}", 
            "ProcessStartTime": "2020-02-13T03:50:45.515Z"
        }
    ]
}
```
##### Human Readable Output
### Fidelis Endpoint query results for the DNS request
|EndpointName|LocalIP|LocalPort|RemoteIP|RemotePort|ProcessStartTime|DnsAnswer|EventType|
|---|---|---|---|---|---|---|---|
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 49862 | 10.10.0.1 | 53 | 2020-02-13T03:50:45.515Z | {"dns_answers":[{"name":"login.live.com","class":"IN","type":"CNAME","alias":"login.msa.msidentity.com","IP":"","TTL":"299"},{"name":"login.msa.msidentity.com","class":"IN","type":"CNAME","alias":"login.msa.akadns6.net","IP":"","TTL":"299"},{"name":"login.msa.akadns6.net","class":"IN","type":"CNAME","alias":"ipv4.login.msa.akadns6.net","IP":"","TTL":"299"},{"name":"ipv4.login.msa.akadns6.net","class":"IN","type":"A","alias":"","IP":"3.3.3.3","TTL":"299"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 53712 | 10.10.0.1 | 53 | 2020-02-13T03:50:45.515Z | {"dns_answers":[{"name":"login.live.com","class":"IN","type":"CNAME","alias":"login.msa.msidentity.com","IP":"","TTL":"51"},{"name":"login.msa.msidentity.com","class":"IN","type":"CNAME","alias":"lgin.msa.trafficmanager.net","IP":"","TTL":"51"},{"name":"lgin.msa.trafficmanager.net","class":"IN","type":"A","alias":"","IP":"2.2.2.2","TTL":"59"},{"name":"lgin.msa.trafficmanager.net","class":"IN","type":"A","alias":"","IP":"3.3.3.3","TTL":"59"},{"name":"lgin.msa.trafficmanager.net","class":"IN","type":"A","alias":"","IP":"4.4.4.4","TTL":"59"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 61574 | 10.10.0.1 | 53 | 2020-02-13T03:50:45.515Z | {"dns_answers":[{"name":"login.live.com","class":"IN","type":"CNAME","alias":"login.msa.msidentity.com","IP":"","TTL":"230"},{"name":"login.msa.msidentity.com","class":"IN","type":"CNAME","alias":"lgin.msa.trafficmanager.net","IP":"","TTL":"235"},{"name":"lgin.msa.trafficmanager.net","class":"IN","type":"A","alias":"","IP":"3.3.3.3","TTL":"56"},{"name":"lgin.msa.trafficmanager.net","class":"IN","type":"A","alias":"","IP":"2.2.2.2","TTL":"56"},{"name":"lgin.msa.trafficmanager.net","class":"IN","type":"A","alias":"","IP":"7.7.7.7","TTL":"56"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 57803 | 10.10.0.1 | 53 | 2020-02-13T03:50:45.515Z | {"dns_answers":[{"name":"login.live.com","class":"IN","type":"CNAME","alias":"login.msa.msidentity.com","IP":"","TTL":"16"},{"name":"login.msa.msidentity.com","class":"IN","type":"CNAME","alias":"lgin.msa.trafficmanager.net","IP":"","TTL":"197"},{"name":"lgin.msa.trafficmanager.net","class":"IN","type":"A","alias":"","IP":"3.3.3.3","TTL":"59"},{"name":"lgin.msa.trafficmanager.net","class":"IN","type":"A","alias":"","IP":"3.3.3.3","TTL":"59"},{"name":"lgin.msa.trafficmanager.net","class":"IN","type":"A","alias":"","IP":"7.7.7.7","TTL":"59"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 58656 | 10.10.0.1 | 53 | 2020-02-13T03:50:45.515Z | {"dns_answers":[{"name":"login.live.com","class":"IN","type":"CNAME","alias":"login.msa.msidentity.com","IP":"","TTL":"288"},{"name":"login.msa.msidentity.com","class":"IN","type":"CNAME","alias":"login.msa.akadns6.net","IP":"","TTL":"288"},{"name":"login.msa.akadns6.net","class":"IN","type":"CNAME","alias":"ipv4.login.msa.akadns6.net","IP":"","TTL":"288"},{"name":"ipv4.login.msa.akadns6.net","class":"IN","type":"A","alias":"","IP":"2.2.2.20","TTL":"123"},{"name":"ipv4.login.msa.akadns6.net","class":"IN","type":"A","alias":"","IP":"7.7.7.7","TTL":"123"},{"name":"ipv4.login.msa.akadns6.net","class":"IN","type":"A","alias":"","IP":"10.10.10.10","TTL":"123"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 59564 | 10.10.0.1 | 53 | 2020-02-13T03:50:45.515Z | {"dns_answers":[{"name":"login.live.com","class":"IN","type":"CNAME","alias":"login.msa.msidentity.com","IP":"","TTL":"238"},{"name":"login.msa.msidentity.com","class":"IN","type":"CNAME","alias":"login.msa.akadns6.net","IP":"","TTL":"238"},{"name":"login.msa.akadns6.net","class":"IN","type":"CNAME","alias":"ipv4.login.msa.akadns6.net","IP":"","TTL":"238"},{"name":"ipv4.login.msa.akadns6.net","class":"IN","type":"A","alias":"","IP":"3.3.3.3","TTL":"238"},{"name":"ipv4.login.msa.akadns6.net","class":"IN","type":"A","alias":"","IP":"7.7.7.7","TTL":"238"},{"name":"ipv4.login.msa.akadns6.net","class":"IN","type":"A","alias":"","IP":"10.10.10.10","TTL":"238"}]} | 17 |
### 22. fidelis-endpoint-query-dns-by-server-ip
---
Queries DNS by server IP address.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results
##### Base Command
`fidelis-endpoint-query-dns-by-server-ip`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start time of the event in the system in UTC format.<br/>Supported values: "2019-10-21T23:45:00" (date). | Optional | 
| end_time | The end time of the event in the system in UTC format.<br/>Supported values:"2019-10-21T23:45:00" (date). | Optional | 
| logic | The logic of the query. Can be "and" or "or". | Required | 
| remote_ip | The remote IP on which to query. | Required | 
| limit | The maximum number of results to return. The default is 50. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Query.ProcessStartTime | Date | Process start time. | 
| FidelisEndpoint.Query.EndpointName | String | Endpoint name. | 
| FidelisEndpoint.Query.ParentID | String | Parent ID. | 
| FidelisEndpoint.Query.EventTime | Date | Event time. | 
| FidelisEndpoint.Query.RemotePort | Number | Remote port. | 
| FidelisEndpoint.Query.DnsAnswer | String | The DNS answer. | 
| FidelisEndpoint.Query.LocalPort | Number | Local port. | 
| FidelisEndpoint.Query.TargetID | String | The target ID. | 
| FidelisEndpoint.Query.RemoteIP | String | Remote IP address. | 
| FidelisEndpoint.Query.DnsQuestion | String | The DNS question. | 
| FidelisEndpoint.Query.StartTime | Date | Event start time. | 
| FidelisEndpoint.Query.NetworkDirection | Number | Network direction. | 
| FidelisEndpoint.Query.LocalIP | String | Local IP address. | 
| FidelisEndpoint.Query.EventType | Number | Event type. | 
| FidelisEndpoint.Query.EventIndex | Number | Event index. | 
| FidelisEndpoint.Query.IndexingTime | Date | Indexing time. | 
| FidelisEndpoint.Query.EntityType | Number | Entity type. | 
##### Command Example
```!fidelis-endpoint-query-dns-by-server-ip logic="or" remote_ip="10.10.0.1"```
##### Context Example
```
{
    "FidelisEndpoint.Query": [
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-26T09:29:07.671Z", 
            "IndexingTime": "2020-03-26T09:36:32.819Z", 
            "LocalPort": "61597", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "9anFqxCrJ3h", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"v10.events.data.microsoft.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-03-12T03:58:09.962Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 4, 
            "ParentID": "jE4aX1xPk1i", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"v10.events.data.microsoft.com\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"global.events.data.trafficmanager.net\",\"IP\":\"\",\"TTL\":\"1425\"},{\"name\":\"global.events.data.trafficmanager.net\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"skypedataprdcoleus06.cloudapp.net\",\"IP\":\"\",\"TTL\":\"45\"},{\"name\":\"skypedataprdcoleus06.cloudapp.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"10.10.10.10\",\"TTL\":\"5\"}]}", 
            "ProcessStartTime": "2020-03-12T03:58:09.962Z"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-26T09:14:07.314Z", 
            "IndexingTime": "2020-03-26T09:18:31.967Z", 
            "LocalPort": "55911", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "9anFqxCrJ3h", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"v10.events.data.microsoft.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-03-12T03:58:09.962Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 2, 
            "ParentID": "jE4aX1xPk1i", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"v10.events.data.microsoft.com\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"global.events.data.trafficmanager.net\",\"IP\":\"\",\"TTL\":\"1390\"},{\"name\":\"global.events.data.trafficmanager.net\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"skypedataprdcolcus00.cloudapp.net\",\"IP\":\"\",\"TTL\":\"25\"},{\"name\":\"skypedataprdcolcus00.cloudapp.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"2.2.2.2\",\"TTL\":\"9\"}]}", 
            "ProcessStartTime": "2020-03-12T03:58:09.962Z"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-26T09:01:55.586Z", 
            "IndexingTime": "2020-03-26T09:06:31.755Z", 
            "LocalPort": "56095", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "VqzBXZZVzjd", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-03-12T03:58:09.962Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 4, 
            "ParentID": "jE4aX1xPk1i", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"6.6.6.6\",\"TTL\":\"144\"}]}", 
            "ProcessStartTime": "2020-03-12T03:58:09.962Z"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-26T08:59:06.523Z", 
            "IndexingTime": "2020-03-26T09:02:31.650Z", 
            "LocalPort": "61769", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "9anFqxCrJ3h", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"v10.events.data.microsoft.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-03-12T03:58:09.962Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 2, 
            "ParentID": "jE4aX1xPk1i", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"v10.events.data.microsoft.com\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"global.events.data.trafficmanager.net\",\"IP\":\"\",\"TTL\":\"862\"},{\"name\":\"global.events.data.trafficmanager.net\",\"class\":\"IN\",\"type\":\"CNAME\",\"alias\":\"skypedataprdc.cloudapp.net\",\"IP\":\"\",\"TTL\":\"19\"},{\"name\":\"skypedataprdcolase00.cloudapp.net\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"3.3.3.3\",\"TTL\":\"9\"}]}", 
            "ProcessStartTime": "2020-03-12T03:58:09.962Z"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-26T08:44:30.882Z", 
            "IndexingTime": "2020-03-26T08:50:31.264Z", 
            "LocalPort": "53940", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "VqzBXZZVzjd", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-03-12T03:58:09.962Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 5, 
            "ParentID": "jE4aX1xPk1i", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"6.6.6.6\",\"TTL\":\"274\"}]}", 
            "ProcessStartTime": "2020-03-12T03:58:09.962Z"
        }
    ]
}
```
##### Human Readable Output
### Fidelis Endpoint query results for the DNS request by server IP
|EndpointName|LocalIP|LocalPort|RemoteIP|RemotePort|ProcessStartTime|DnsAnswer|EventType|
|---|---|---|---|---|---|---|---|
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 61597 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | {"dns_answers":[{"name":"v10.events.data.microsoft.com","class":"IN","type":"CNAME","alias":"global.events.data.trafficmanager.net","IP":"","TTL":"1425"},{"name":"global.events.data.trafficmanager.net","class":"IN","type":"CNAME","alias":"skypedataprdcoleus06.cloudapp.net","IP":"","TTL":"45"},{"name":"skypedataprdcoleus06.cloudapp.net","class":"IN","type":"A","alias":"","IP":"2.2.2.2","TTL":"5"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 55911 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | {"dns_answers":[{"name":"v10.events.data.microsoft.com","class":"IN","type":"CNAME","alias":"global.events.data.trafficmanager.net","IP":"","TTL":"1390"},{"name":"global.events.data.trafficmanager.net","class":"IN","type":"CNAME","alias":"skypedataprdcolcus00.cloudapp.net","IP":"","TTL":"25"},{"name":"skypedataprdcolcus00.cloudapp.net","class":"IN","type":"A","alias":"","IP":"3.3.3.3","TTL":"9"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 56095 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | {"dns_answers":[{"name":"logging.googleapis.com","class":"IN","type":"A","alias":"","IP":"3.3.3.3","TTL":"144"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 61769 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | {"dns_answers":[{"name":"v10.events.data.microsoft.com","class":"IN","type":"CNAME","alias":"global.events.data.trafficmanager.net","IP":"","TTL":"862"},{"name":"global.events.data.trafficmanager.net","class":"IN","type":"CNAME","alias":"skypedataprdcolase00.cloudapp.net","IP":"","TTL":"19"},{"name":"skypedataprdcolase00.cloudapp.net","class":"IN","type":"A","alias":"","IP":"4.4.4.4","TTL":"9"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 53940 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | {"dns_answers":[{"name":"logging.googleapis.com","class":"IN","type":"A","alias":"","IP":"3.3.3.3","TTL":"274"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 57260 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | {"dns_answers":[{"name":"v10.events.data.microsoft.com","class":"IN","type":"CNAME","alias":"global.events.data.trafficmanager.net","IP":"","TTL":"1698"},{"name":"global.events.data.trafficmanager.net","class":"IN","type":"CNAME","alias":"skypedataprdcolneu00.cloudapp.net","IP":"","TTL":"21"},{"name":"skypedataprdcolneu00.cloudapp.net","class":"IN","type":"A","alias":"","IP":"7.7.7.7","TTL":"9"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 58832 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | {"dns_answers":[{"name":"logging.googleapis.com","class":"IN","type":"A","alias":"","IP":"3.3.3.3","TTL":"206"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 60472 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | {"dns_answers":[{"name":"v10.events.data.microsoft.com","class":"IN","type":"CNAME","alias":"global.events.data.trafficmanager.net","IP":"","TTL":"3334"},{"name":"global.events.data.trafficmanager.net","class":"IN","type":"CNAME","alias":"skypedataprdcolweu05.cloudapp.net","IP":"","TTL":"58"},{"name":"skypedataprdcolweu05.cloudapp.net","class":"IN","type":"A","alias":"","IP":"10.10.0.1","TTL":"8"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 54309 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | {"dns_answers":[{"name":"v10.events.data.microsoft.com","class":"IN","type":"CNAME","alias":"global.events.data.trafficmanager.net","IP":"","TTL":"2327"},{"name":"global.events.data.trafficmanager.net","class":"IN","type":"CNAME","alias":"skypedataprdcoluks05.cloudapp.net","IP":"","TTL":"44"},{"name":"skypedataprdcoluks05.cloudapp.net","class":"IN","type":"A","alias":"","IP":"10.10.0.1","TTL":"7"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 61757 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | {"dns_answers":[{"name":"logging.googleapis.com","class":"IN","type":"A","alias":"","IP":"3.3.3.3","TTL":"273"}]} | 17 |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 49681 | 10.10.0.1 | 53 | 2020-03-12T03:58:09.962Z | {"dns_answers":[{"name":"v10.events.data.microsoft.com","class":"IN","type":"CNAME","alias":"global.events.data.trafficmanager.net","IP":"","TTL":"798"},{"name":"global.events.data.trafficmanager.net","class":"IN","type":"CNAME","alias":"skypedataprdcolwus08.cloudapp.net","IP":"","TTL":"40"},{"name":"fe2.update.microsoft.com.nsatc.net","class":"IN","type":"A","alias":"","IP":"10.10.0.1","TTL":"175"}]} | 17 |
### 23. fidelis-endpoint-query-dns-by-source-ip
---
Queries DNS by source IP address.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results
##### Base Command
`fidelis-endpoint-query-dns-by-source-ip`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start time of the event in the system in UTC format.<br/>Supported values: "2019-10-21T23:45:00" (date). | Optional | 
| end_time | The end time of the event in the system in UTC format.<br/>Supported values: "2019-10-21T23:45:00" (date). | Optional | 
| logic | The logic of the query. Can be "and" or "or". | Required | 
| source_ip | The source IP address to query. | Required | 
| domain | The domain to query. | Optional | 
| limit | The maximum number of results to return. The default is 50. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Query.ProcessStartTime | Date | Process start time. | 
| FidelisEndpoint.Query.EndpointName | String | Endpoint name. | 
| FidelisEndpoint.Query.ParentID | String | Parent ID. | 
| FidelisEndpoint.Query.EventTime | Date | Event time. | 
| FidelisEndpoint.Query.RemotePort | Number | Remote port. | 
| FidelisEndpoint.Query.DnsAnswer | String | The DNS answer. | 
| FidelisEndpoint.Query.LocalPort | Number | Local port. | 
| FidelisEndpoint.Query.TargetID | String | The target ID. | 
| FidelisEndpoint.Query.RemoteIP | String | Remote IP address. | 
| FidelisEndpoint.Query.DnsQuestion | String | The DNS question. | 
| FidelisEndpoint.Query.StartTime | Date | Event start time. | 
| FidelisEndpoint.Query.NetworkDirection | Number | Network direction. | 
| FidelisEndpoint.Query.LocalIP | String | Local IP address. | 
| FidelisEndpoint.Query.EventType | Number | Event type. | 
| FidelisEndpoint.Query.EventIndex | Number | Event index. | 
| FidelisEndpoint.Query.IndexingTime | Date | Indexing time. | 
| FidelisEndpoint.Query.EntityType | Number | Entity type. | 
##### Command Example
```!fidelis-endpoint-query-dns-by-source-ip start_time="2020-01-01T00:00:00.842Z" end_time="2020-03-08T15:50:05.552Z" logic="or" source_ip="10.128.0.4" domain="logging.googleapis.com" limit=5```
##### Context Example
```
{
    "FidelisEndpoint.Query": [
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-08T12:21:34.260Z", 
            "IndexingTime": "2020-03-08T12:26:25.293Z", 
            "LocalPort": "51663", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "VqzBXZZVzjd", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-02-13T03:50:45.515Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 2, 
            "ParentID": "VuFd4n1aut7", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"6.6.6.6\",\"TTL\":\"87\"}]}", 
            "ProcessStartTime": "2020-02-13T03:50:45.515Z"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-08T12:18:33.199Z", 
            "IndexingTime": "2020-03-08T12:23:25.135Z", 
            "LocalPort": "65002", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "VqzBXZZVzjd", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-02-13T03:50:45.515Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 2, 
            "ParentID": "VuFd4n1aut7", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"6.6.6.6\",\"TTL\":\"105\"}]}", 
            "ProcessStartTime": "2020-02-13T03:50:45.515Z"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-08T11:17:33.908Z", 
            "IndexingTime": "2020-03-08T11:25:23.700Z", 
            "LocalPort": "49412", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "VqzBXZZVzjd", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-02-13T03:50:45.515Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 2, 
            "ParentID": "VuFd4n1aut7", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"6.6.6.6\",\"TTL\":\"253\"}]}", 
            "ProcessStartTime": "2020-02-13T03:50:45.515Z"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-08T11:05:33.831Z", 
            "IndexingTime": "2020-03-08T11:11:23.189Z", 
            "LocalPort": "63755", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "VqzBXZZVzjd", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-02-13T03:50:45.515Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 2, 
            "ParentID": "VuFd4n1aut7", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"6.6.6.6\",\"TTL\":\"282\"}]}", 
            "ProcessStartTime": "2020-02-13T03:50:45.515Z"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-08T09:54:32.087Z", 
            "IndexingTime": "2020-03-08T09:59:21.585Z", 
            "LocalPort": "60331", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "VqzBXZZVzjd", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-02-13T03:50:45.515Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 5, 
            "ParentID": "VuFd4n1aut7", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"6.6.6.6\",\"TTL\":\"61\"}]}", 
            "ProcessStartTime": "2020-02-13T03:50:45.515Z"
        }, 
        {
            "RemotePort": "53", 
            "EventTime": "2020-03-08T09:53:33.246Z", 
            "IndexingTime": "2020-03-08T09:59:21.585Z", 
            "LocalPort": "58452", 
            "EventType": 17, 
            "EntityType": 6, 
            "TargetID": "VqzBXZZVzjd", 
            "DnsQuestion": "{\"dns_questions\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\"}]}", 
            "LocalIP": "2.2.2.2", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-02-13T03:50:45.515Z", 
            "RemoteIP": "10.10.0.1", 
            "EventIndex": 2, 
            "ParentID": "VuFd4n1aut7", 
            "NetworkDirection": "0", 
            "DnsAnswer": "{\"dns_answers\":[{\"name\":\"logging.googleapis.com\",\"class\":\"IN\",\"type\":\"A\",\"alias\":\"\",\"IP\":\"6.6.6.6\",\"TTL\":\"12\"}]}", 
            "ProcessStartTime": "2020-02-13T03:50:45.515Z"
        }
    ]
}
```
##### Human Readable Output
### Fidelis Endpoint query results for the DNS request by source IP
|EndpointName|LocalIP|LocalPort|RemoteIP|RemotePort|ProcessStartTime|DnsQuestion|DnsAnswer|
|---|---|---|---|---|---|---|---|
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 51663 | 10.10.0.1 | 53 | 2020-02-13T03:50:45.515Z | {"dns_questions":[{"name":"logging.googleapis.com","class":"IN","type":"A"}]} | {"dns_answers":[{"name":"logging.googleapis.com","class":"IN","type":"A","alias":"","IP":"6.6.6.6","TTL":"87"}]} |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 65002 | 10.10.0.1 | 53 | 2020-02-13T03:50:45.515Z | {"dns_questions":[{"name":"logging.googleapis.com","class":"IN","type":"A"}]} | {"dns_answers":[{"name":"logging.googleapis.com","class":"IN","type":"A","alias":"","IP":"6.6.6.6","TTL":"105"}]} |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 49412 | 10.10.0.1 | 53 | 2020-02-13T03:50:45.515Z | {"dns_questions":[{"name":"logging.googleapis.com","class":"IN","type":"A"}]} | {"dns_answers":[{"name":"logging.googleapis.com","class":"IN","type":"A","alias":"","IP":"6.6.6.6","TTL":"253"}]} |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 63755 | 10.10.0.1 | 53 | 2020-02-13T03:50:45.515Z | {"dns_questions":[{"name":"logging.googleapis.com","class":"IN","type":"A"}]} | {"dns_answers":[{"name":"logging.googleapis.com","class":"IN","type":"A","alias":"","IP":"6.6.6.6","TTL":"282"}]} |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 60331 | 10.10.0.1 | 53 | 2020-02-13T03:50:45.515Z | {"dns_questions":[{"name":"logging.googleapis.com","class":"IN","type":"A"}]} | {"dns_answers":[{"name":"logging.googleapis.com","class":"IN","type":"A","alias":"","IP":"6.6.6.6","TTL":"61"}]} |
| fidelis-endpoint-winserver2019 | 2.2.2.2 | 58452 | 10.10.0.1 | 53 | 2020-02-13T03:50:45.515Z | {"dns_questions":[{"name":"logging.googleapis.com","class":"IN","type":"A"}]} | {"dns_answers":[{"name":"logging.googleapis.com","class":"IN","type":"A","alias":"","IP":"6.6.6.6","TTL":"12"}]} |
### 24. fidelis-endpoint-query-events
---
Queries events.
##### Required Permissions
The required permissions: Read groups, View Behaviors, View Task Results
##### Base Command
`fidelis-endpoint-query-events`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start time of the event in the system in UTC format.<br/>Supported values: "2019-10-21T23:45:00" (date). | Optional | 
| end_time | The end time of the event in the system in UTC format.<br/>Supported values:"2019-10-21T23:45:00" (date). | Optional | 
| logic | The logic of the query. Can be "and" or "or". | Required | 
| entity_type | Query entity type. Can be "antiMalware", "dns", "file", "network", "process", "registry", "remoteThread", "script", "usb", or "windowsevent". | Required | 
| column | Column to query. For example: hash, name, remoteIP, dnsQuestion, localIP. | Required | 
| value | The value to query. Can be an IP address, file hash, file path, and so on. | Required | 
| operator | The operator, which describes how the "value" relates to the "field" (for example: "=", "!=", ">", "<"). | Required | 
| limit | The maximum number of results to return. The default is 50. | Optional | 
| additional_filter | An additional filter to use in the query. For example: pid = 1234, pid > 1233. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FidelisEndpoint.Query.ProcessStartTime | Date | Process start time. | 
| FidelisEndpoint.Query.EndpointName | String | Endpoint name. | 
| FidelisEndpoint.Query.Path | String | File path. | 
| FidelisEndpoint.Query.ParentID | String | Parent ID. | 
| FidelisEndpoint.Query.EventTime | Date | Event time. | 
| FidelisEndpoint.Query..RemotePort | Number | Remote port. | 
| FidelisEndpoint.Query.DnsAnswer | String | DNS answer. | 
| FidelisEndpoint.Query.PID | Number | Process ID. | 
| FidelisEndpoint.Query.Name | String | Process name. | 
| FidelisEndpoint.Query.User | String | Endpoint user. | 
| FidelisEndpoint.Query.LocalPort | Number | Local port. | 
| FidelisEndpoint.Query.TargetID | String | Target ID. | 
| FidelisEndpoint.Query.RemoteIP | String | Remote IP address. | 
| FidelisEndpoint.Query.Hash | String | File hash. | 
| FidelisEndpoint.Query.DnsQuestion | String | DNS question. | 
| FidelisEndpoint.Query.StartTime | Date | Start time of the event. | 
| FidelisEndpoint.Query.Entropy | Number | Entropy. | 
| FidelisEndpoint.Query.LocalIP | String | Local IP address. | 
| FidelisEndpoint.Query.EventType | Number | Event type. | 
| FidelisEndpoint.Query.ParentName | String | Parent name. | 
| FidelisEndpoint.Query.EventIndex | Number | Event index. | 
| FidelisEndpoint.Query.IndexingTime | Date | Indexing time. | 
| FidelisEndpoint.Query.EntityType | Number | Entity type. | 
##### Command Example
```!fidelis-endpoint-query-events column=name entity_type=process logic=or value=cmd.exe additional_filter="pid = 3276" operator="="```
##### Context Example
```
{
    "FidelisEndpoint.Query": [
        {
            "EntityType": 0, 
            "TargetID": "qgOl6OBq7v8", 
            "LocalIP": null, 
            "RemotePort": null, 
            "ProcessStartTime": "2020-03-26T09:25:53.122Z", 
            "IndexingTime": "2020-03-26T09:30:32.434Z", 
            "Hash": "975b45b669930b0cc773eaf2b412345f", 
            "LocalPort": null, 
            "EventType": 0, 
            "ParentName": "endpoint.exe", 
            "PID": 908, 
            "DnsQuestion": null, 
            "User": "NT AUTHORITY\\SYSTEM", 
            "EventIndex": null, 
            "Path": "C:\\Windows\\System32\\cmd.exe", 
            "DnsAnswer": null, 
            "RemoteIP": null, 
            "EventTime": "2020-03-26T09:25:53.122Z", 
            "Name": "cmd.exe", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-03-26T09:25:53.122Z", 
            "ParentID": "MKH6hK7yr75"
        }, 
        {
            "EntityType": 0, 
            "TargetID": "w8qh7ogIf8l", 
            "LocalIP": null, 
            "RemotePort": null, 
            "ProcessStartTime": "2020-03-26T09:25:39.883Z", 
            "IndexingTime": "2020-03-26T09:30:32.878Z", 
            "Hash": "975b45b669930b0cc773eaf2b412345f", 
            "LocalPort": null, 
            "EventType": 0, 
            "ParentName": "endpoint.exe", 
            "PID": 3376, 
            "DnsQuestion": null, 
            "User": "NT AUTHORITY\\SYSTEM", 
            "EventIndex": null, 
            "Path": "C:\\Windows\\System32\\cmd.exe", 
            "DnsAnswer": null, 
            "RemoteIP": null, 
            "EventTime": "2020-03-26T09:25:39.883Z", 
            "Name": "cmd.exe", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-03-26T09:25:39.883Z", 
            "ParentID": "MKH6hK7yr75"
        }, 
        {
            "EntityType": 0, 
            "TargetID": "SSDiQFEHvNg", 
            "LocalIP": null, 
            "RemotePort": null, 
            "ProcessStartTime": "2020-03-26T09:08:23.233Z", 
            "IndexingTime": "2020-03-26T09:12:32.225Z", 
            "Hash": "975b45b669930b0cc773eaf2b412345f", 
            "LocalPort": null, 
            "EventType": 0, 
            "ParentName": "endpoint.exe", 
            "PID": 2804, 
            "DnsQuestion": null, 
            "User": "NT AUTHORITY\\SYSTEM", 
            "EventIndex": null, 
            "Path": "C:\\Windows\\System32\\cmd.exe", 
            "DnsAnswer": null, 
            "RemoteIP": null, 
            "EventTime": "2020-03-26T09:08:23.233Z", 
            "Name": "cmd.exe", 
            "EndpointName": "fidelis-endpoint-winserver2019", 
            "StartTime": "2020-03-26T09:08:23.233Z", 
            "ParentID": "MKH6hK7yr75"
        }
    ]
}
```
##### Human Readable Output
### Fidelis Endpoint query events result
|PID|EndpointName|User|ProcessStartTime|ParentID|EventType|
|---|---|---|---|---|---|
| 908 | fidelis-endpoint-winserver2019 | NT AUTHORITY\SYSTEM | 2020-03-26T09:25:53.122Z | MKH6hK7yr75 | 0 |
| 3376 | fidelis-endpoint-winserver2019 | NT AUTHORITY\SYSTEM | 2020-03-26T09:25:39.883Z | MKH6hK7yr75 | 0 |
| 2804 | fidelis-endpoint-winserver2019 | NT AUTHORITY\SYSTEM | 2020-03-26T09:08:23.233Z | MKH6hK7yr75 | 0 |
 24  Packs/FidelisEndpoint/pack_metadata.json 
