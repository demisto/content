# Data Enrichment & Threat Intelligence

Important information for an indicator:

Top Use-Cases:
Enriching information about different IOC types:
- [upload object for scan and get the scan results. (If there’s a possibility to upload private/public, default should be set to private)](#upload-example).
- [search for former scan results about an object (This way you can get information about a sample without uploading it yourself).](#analysis-example)
- enrich information and scoring for the object.
- Add/Search for indicators in the system.
- Add indicators to allow list or block list. 
- Calculate DBot Score for indicators.

**Data Enrichment & Threat Intelligence Integration Example** – Virustotal


## Command Examples
### threatstream-submit-to-sandbox . <a name="upload-example"></a>
---
Submits a file or URL to the ThreatStream-hosted Sandbox for detonation.
##### Base Command
`threatstream-submit-to-sandbox`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_classification | Classification of the Sandbox submission. | Optional | 
| report_platform | Platform on which the submitted URL or file will be run. To obtain a list supported platforms run the threatstream-get-sandbox-platforms command. | Optional | 
| submission_type | The detonation type ("file" or "url". | Required | 
| submission_value | The submission value. Possible values are a valid URL or a file ID that was uploaded to the War Room to detonate. | Required | 
| premium_sandbox | Specifies whether the premium sandbox should be used for detonation. Default is "false". | Optional | 
| detail | A CSV list of additional details for the indicator. This information is displayed in the Tag column of the ThreatStream UI. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Analysis.ReportID | String | The report ID that was submitted to the sandbox. | 
| ThreatStream.Analysis.Status | String | The analysis status. | 
| ThreatStream.Analysis.Platform | String | The platform of the submission submitted to the sanbox. | 
##### Command Example
`threatstream-submit-to-sandbox submission_type=file submission_value=5358@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0 premium_sandbox=false report_platform=WINDOWS7`
##### Context Example
```
{
    "File": {
        "EntryID": "5358@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0",
        "Extension": "png",
        "Info": "image/png",
        "MD5": "a36544c75d1253d8dd32070908adebd0",
        "Name": "input_file.png",
        "SHA1": "15868fbe28e34f601b4e07b0f356ecb1f3a14876",
        "SHA256": "5126eb938b3c2dc53837d4805df01c8522a3bd4e5e77e9bc4f825b9ee178e6ab",
        "SSDeep": "98304:pKOjdLh3d35gcNMjnN+FOLEdhVb2t6lLPP9nuyxJ4iQzxKxOduLT/GzxS3UvtT:pHhhvglN+F+GwUlLPP9PxnQzxKxOdEUR",
        "Size": 4938234,
        "Type": "PNG image data, 2572 x 1309, 8-bit/color RGBA, non-interlaced\n"
    },
    "ThreatStream": {
        "Analysis": {
            "Platform": "WINDOWS7",
            "ReportID": 422662,
            "Status": "processing"
        }
    }
}
```
##### Human Readable Output
### The submission info for 5358@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0
|ReportID|Status|Platform|
|---|---|---|
|422662|processing|WINDOWS7|
### threatstream-get-analysis-status 
---
Returns the current status of the report that was submitted to the sandbox. The report ID is returned from threatstream-submit-to-sandbox command.
##### Base Command
`threatstream-get-analysis-status`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID for which to check the status. | Required | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Analysis.ReportID | String | The report ID of the file or URL that was detonated to sandbox. | 
| ThreatStream.Analysis.Status | String | The report status of the file or URL that was detonated in the sandbox. | 
| ThreatStream.Analysis.Platform | String | The platfrom that was used for detonation. | 
| ThreatStream.Analysis.Verdict | String | The report verdict of the file or URL that was detonated in the sandbox. The verdict will remain "benign" until detonation is complete. | 
##### Command Example
`threatstream-get-analysis-status report_id=422662`
##### Context Example
```
{
    "ThreatStream": {
        "Analysis": {
            "Platform": "WINDOWS7",
            "ReportID": "422662",
            "Status": "processing",
            "Verdict": "Benign"
        }
    }
}
```
##### Human Readable Output
### The analysis status for id 422662
|ReportID|Status|Platform|Verdict|
|---|---|---|---|
|422662|processing|WINDOWS7|Benign|
### threatstream-analysis-report <a name="analysis-example"></a>
---
Returns the report of a file or URL that was submitted to the sandbox.
##### Base Command
`threatstream-analysis-report`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID to return. | Required | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Analysis.ReportID | String | The ID of the report submitted to the sandbox. | 
| ThreatStream.Analysis.Category | String | The report category. | 
| ThreatStream.Analysis.Started | String | Detonation start time. | 
| ThreatStream.Analysis.Completed | String | Detonation completion time. | 
| ThreatStream.Analysis.Duration | Number | Duration of the detonation (in seconds). | 
| ThreatStream.Analysis.VmName | String | The name of the VM. | 
| ThreatStream.Analysis.VmID | String | The ID of the VM. | 
| ThreatStream.Analysis.Network.UdpSource | String | The source of UDP. | 
| ThreatStream.Analysis.Network.UdpDestination | String | The destination of UDP. | 
| ThreatStream.Analysis.Network.UdpPort | String | The port of the UDP. | 
| ThreatStream.Analysis.Network.IcmpSource | String | The ICMP source. | 
| ThreatStream.Analysis.Network.IcmpDestination | String | The destinaton of ICMP. | 
| ThreatStream.Analysis.Network.IcmpPort | String | The port of the ICMP. | 
| ThreatStream.Analysis.Network.TcpSource | String | The source of TCP. | 
| ThreatStream.Analysis.Network.TcpDestination | String | The destination of TCP. | 
| ThreatStream.Analysis.Network.TcpPort | String | The port of TCP. | 
| ThreatStream.Analysis.Network.HttpSource | String | The source of HTTP. | 
| ThreatStream.Analysis.Network.HttpDestinaton | String | The destination of HTTP. | 
| ThreatStream.Analysis.Network.HttpPort | String | The port of HTTP. | 
| ThreatStream.Analysis.Network.HttpsSource | String | The source of HTTPS. | 
| ThreatStream.Analysis.Network.HttpsDestinaton | String | The destination of HTTPS. | 
| ThreatStream.Analysis.Network.HttpsPort | String | The port of HTTPS. | 
| ThreatStream.Analysis.Network.Hosts | String | The hosts of network analysis. | 
| ThreatStream.Analysis.Verdict | String | The verdict of the sandbox detonation. | 
##### Command Example
`threatstream-analysis-report report_id=413336`
##### Context Example
```
{
    "ThreatStream": {
        "Analysis": {
            "Category": "File",
            "Completed": "2019-05-30 14:06:33",
            "Duration": 68,
            "Network": [
                {
                    "UdpDestination": "8.8.8.8",
                    "UdpPort": 53,
                    "UdpSource": "192.168.2.4"
                },
                {
                    "UdpDestination": "192.168.2.4",
                    "UdpPort": 65324,
                    "UdpSource": "8.8.8.8"
                },
                {
                    "UdpDestination": "192.168.2.4",
                    "UdpPort": 54896,
                    "UdpSource": "8.8.8.8"
                }
            ],
            "ReportID": "413336",
            "Started": "2019-05-30 14:05:25",
            "Verdict": "Benign",
            "VmID": "",
            "VmName": ""
        }
    }
}
```
##### Human Readable Output
### Report 413336 analysis results
|Category|Started|Completed|Duration|VmName|VmID|ReportID|Verdict|
|---|---|---|---|---|---|---|---|
|File|2019-05-30 14:05:25|2019-05-30 14:06:33|68|||413336|Benign|
