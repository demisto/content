Allows to parse and extract http flows (requests & responses) from a pcap/pcapng file.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | pcap, http |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| pcapFileName | get file entry from file name |
| entryID | File entry from the WarRoom |
| limit | Limit the output of the capture file output's flows \(starts from 0\). |
| start | Index of where to output flows \(starts from 0\). |
| limitData | Limit the HttpFileData field \(in bytes\)		 |
| allowedContentTypes | The allowed content types to display, separated with comma, uses startswith to find a match \(ie text,image will display text\\html, and image\\png\). |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PcapHTTPFlows | Flows extracted from the pcap file. | String |
| PcapHttpFlows.ResultIndex | The index of the http packet in the pcap file. | String |
| PcapHttpFlows.HttpContentType | Http content type of the response. | String |
| PcapHttpFlows.HttpResponseVersion | Http version used in the response. | String |
| PcapHttpFlows.HttpResponseCode | Http response code from the server | String |
| PcapHttpFlows.HttpDate | Http date returned from the sever | String |
| PcapHttpFlows.HttpRequestMethod | Http request method used. | String |
| PcapHttpFlows.HttpRequestUri | Http request URI \(path\) | String |
| PcapHttpFlows.HttpFileData | Http content of the response | String |
| PcapHttpFlows.HttpServer | The server signature in the response | String |
| PcapHttpFlows.HttpUserAgent | Http user agent sent in the request | String |
| PcapHttpFlows.HttpAccept | Http request accept type | String |
| PcapHttpFlows.MetaSniffTimeStamp | Time the packet was sniffed \(unixtime\). | String |
