This playbook leverages the windows builtin Powershell and WinRM capabilities to connect to a Windows host and then the Netsh tool to create an ETL file which is the equivalent of a Wireshark PCAP file by using PS-Remote integration. After receiving the resultant ETL,  XSOAR will be able to convert the ETL to a PCAP file to be parsed and enriched later on.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* PowerShell Remoting

### Scripts
* Sleep
* UnzipFile
* Set
* Etl2Pcap

### Commands
* ps-remote-etl-create-start
* ps-remote-download-file
* ps-remote-etl-create-stop

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Host | The host name for which to create the ETL file. For example testpc01 |  | Optional |
| EtlSizeLimit | The maximum file size for the ETL. Once the file has reached this size the capute will stop. For example 10MB. The default size is 10MB | 10 | Optional |
| EtlPath | The path on the hostname on which to create the etl file. The default path will be c:\\&amp;lt;The host name&amp;gt;.etl | inputs.Host.None | Optional |
| EtlFilter | The filter to apply when creating the ETL file. For example IPv4.Address=1.1.1.1 to capture traffic just from the 1.1.1.1 IP address. If no filter is specified all traffic will be recorded. More example can be found here, https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj129382\(v=ws.11\)\#using-filters-to-limit-etl-trace-file-details |  | Optional |
| ETlTimeToRecord | The time to record in seconds. | 60 | Optional |
| ZipEtl | Specify true to zip the ETL file before sending it to XSOAR. | true | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PcapDetails | The PCAP file details. | string |

## Playbook Image
---
![PS-Remote Get Network Traffic](Insert the link to your image here)