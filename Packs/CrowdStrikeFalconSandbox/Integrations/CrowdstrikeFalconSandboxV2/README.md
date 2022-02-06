# CrowdStrike Falcon Sandbox v2

Use the CrowdStrike Falcon Sandbox integration to submit and analyze files and URLs.

The maximum file upload size is 100 MB.

<p>Supported File Types:</p>
<ul>
<li>PE (.exe, .scr, .pif, .dll, .com, .cpl, and so on)</li>
<li>Microsoft Word (.doc, .docx, .ppt, .pps, .pptx, .ppsx, .xls, .xlsx, .rtf, .pub)</li>
<li>PDF</li>
<li>APK</li>
<li>JAR executables</li>
<li>Windows Script Component (.sct)</li>
<li>Windows Shortcut (.lnk)</li>
<li>Windows Help (.chm)</li>
<li>HTML Application (.hta)</li>
<li>Windows Script File (*.wsf)</li>
<li>Javascript (.js)</li>
<li>Visual Basic (*.vbs, *.vbe)</li>
<li>Shockwave Flash (.swf)</li>
<li>Perl (.pl)</li>
<li>PowerShell (.ps1, .psd1, .psm1)</li>
<li>Scalable Vector Graphics (.svg)</li>
<li>Python scripts (.py)</li>
<li>Perl scripts (.pl)</li>
<li>Linux ELF executables</li>
<li>MIME RFC 822 (*.eml)</li>
<li>Outlook (*.msg files)</li>
</ul>

## Prerequisites

Make sure you have the API key for CrowdStrike Falcon Sandbox v2.

Each API key has an associated authorization level, which determines the available endpoints. By default, all free, non-vetted accounts can issue restricted keys. You can upgrade to full default keys, enabling file submissions and downloads.

Authorization levels:

- Restricted
- Default
- Elevated
- Super


## Configure CrowdStrike Falcon Sandbox v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CrowdStrike Falcon Sandbox v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.



## Commands
You can execute these commands from the Cortex XSOAR CLI as part of an automation or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cs-falcon-sandbox-scan
***
Gets summary information for a given MD5, SHA1, or SHA256 and all the reports generated for any environment ID.


#### Base Command

`cs-falcon-sandbox-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A comma-separated list of file hashes (MD5, SHA1, or SHA256). | Required | 
| polling | Whether to poll until there is at least one result. Possible values are: true, false. | Optional | 
| JobID | The JobID to check the state of when polling.                                         | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Report.job_id | String | The report job ID. | 
| CrowdStrike.Report.environment_id | Number | The report environment ID. | 
| CrowdStrike.Report.environment_description | String | The environment description. | 
| CrowdStrike.Report.size | Number | The file size. | 
| CrowdStrike.Report.type | String | The file type. | 
| CrowdStrike.Report.type_short | String |  | 
| CrowdStrike.Report.target_url | String |  | 
| CrowdStrike.Report.state | String | The report state. | 
| CrowdStrike.Report.error_type | String |  | 
| CrowdStrike.Report.error_origin | String |  | 
| CrowdStrike.Report.submit_name | String | The name of the file when submitted. | 
| CrowdStrike.Report.md5 | String | The MD5 hash of the file. | 
| CrowdStrike.Report.sha1 | String | The SHA1 hash of the file. | 
| CrowdStrike.Report.sha256 | String | The SHA256 hash of the file. | 
| CrowdStrike.Report.sha512 | String | The SHA512 hash of the file. | 
| CrowdStrike.Report.ssdeep | String | The SSDeep hash of the file. | 
| CrowdStrike.Report.imphash | String | The imphash hash of the file. | 
| CrowdStrike.Report.av_detect | Number | The AV Multiscan range, for example 50-70 \(min 0, max 100\). | 
| CrowdStrike.Report.vx_family | String | The file malware family. | 
| CrowdStrike.Report.url_analysis | Boolean |  | 
| CrowdStrike.Report.analysis_start_time | Date |  | 
| CrowdStrike.Report.threat_score | Number | The file threat score. | 
| CrowdStrike.Report.interesting | Boolean | Whether the file was found to be interesting. | 
| CrowdStrike.Report.threat_level | Number | The file threat level. | 
| CrowdStrike.Report.verdict | String | The file verdict. | 
| CrowdStrike.Report.total_network_connections | Number |  | 
| CrowdStrike.Report.total_processes | Number |  | 
| CrowdStrike.Report.total_signatures | Number |  | 
| CrowdStrike.Report.file_metadata | Object | The file metadata. | 
| CrowdStrike.Report.submissions.submission_id | String | The submission ID. | 
| CrowdStrike.Report.submissions.filename | String |  | 
| CrowdStrike.Report.submissions.url | String |  | 
| CrowdStrike.Report.submissions.created_at | Date |  | 
| CrowdStrike.Report.network_mode | String |  | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.Name | string | The file submission name. | 
| File.MalwareFamily | string | The file family classification. | 
| File.Malicious.Vendor | string | The vendor that decided the file was malicious. | 
| File.Malicious.Description | string | The reason the vendor decided the file was malicious. | 
| DBotScore.Indicator | string | The tested indicator. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 

#### Command example
```!cs-falcon-sandbox-scan file=8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51,9745bd652c50ac081e28981b96f41230c1ed2f84724c1e5b0f0d407a90aefe22```
#### Context Example
```json
{
    "CrowdStrike": {
        "Report": [
            {
                "analysis_start_time": "2020-09-15T16:47:06+00:00",
                "av_detect": 0,
                "certificates": [],
                "classification_tags": [],
                "compromised_hosts": [],
                "domains": [],
                "environment_description": "Static Analysis",
                "environment_id": null,
                "error_origin": null,
                "error_type": null,
                "extracted_files": [],
                "file_metadata": null,
                "hosts": [],
                "imphash": null,
                "interesting": false,
                "job_id": null,
                "machine_learning_models": [],
                "md5": "4b41a3475132bd861b30a878e30aa56a",
                "mitre_attcks": [],
                "network_mode": "default",
                "processes": [],
                "sha1": "bfd009f500c057195ffde66fae64f92fa5f59b72",
                "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
                "sha512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
                "size": 3028,
                "ssdeep": null,
                "state": "SUCCESS",
                "submissions": [
                    {
                        "created_at": "2021-12-30T09:34:22+00:00",
                        "filename": "file",
                        "submission_id": "61cd7d1ec35ca563e343e855",
                        "url": null
                    },
                    {
                        "created_at": "2021-12-18T23:47:33+00:00",
                        "filename": "file",
                        "submission_id": "61be731519ff990144369a85",
                        "url": null
                    },
                    {
                        "created_at": "2021-07-03T21:54:07+00:00",
                        "filename": "test.pdf",
                        "submission_id": "60e0dc7fda855364ee0d1826",
                        "url": null
                    },
                    {
                        "created_at": "2021-07-03T21:46:41+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "60e0dac12daa5049bb51ad72",
                        "url": null
                    },
                    {
                        "created_at": "2021-07-03T21:45:44+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "60e0da887bb12112723c8bea",
                        "url": null
                    },
                    {
                        "created_at": "2021-04-25T05:03:31+00:00",
                        "filename": "file",
                        "submission_id": "6084f823ea742a4783209d12",
                        "url": null
                    },
                    {
                        "created_at": "2021-03-01T14:42:05+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "603cfd3d601d615839160474",
                        "url": "http://www.africau.edu/images/default/sample.pdf"
                    },
                    {
                        "created_at": "2021-01-24T05:00:32+00:00",
                        "filename": "file",
                        "submission_id": "600cfef0f365f820bf2f0b02",
                        "url": null
                    },
                    {
                        "created_at": "2020-12-08T18:15:16+00:00",
                        "filename": "5_Journals_3_Manuscripts_10_Version_1_Revision_0_CoverLetter.pdf",
                        "submission_id": "5fcfc2b4fe643e3bee4bf4f5",
                        "url": null
                    },
                    {
                        "created_at": "2020-09-15T16:47:06+00:00",
                        "filename": "file",
                        "submission_id": "5f60f00abbe4e913f73cfff9",
                        "url": null
                    }
                ],
                "submit_name": "file",
                "tags": [],
                "target_url": null,
                "threat_level": 0,
                "threat_score": null,
                "total_network_connections": 0,
                "total_processes": 0,
                "total_signatures": 0,
                "type": "PDF document, version 1.3",
                "type_short": [
                    "pdf"
                ],
                "url_analysis": false,
                "verdict": "whitelisted",
                "vx_family": null
            },
            {
                "analysis_start_time": "2021-12-06T15:19:23+00:00",
                "av_detect": 0,
                "certificates": [],
                "classification_tags": [],
                "compromised_hosts": [],
                "domains": [],
                "environment_description": "Android Static Analysis",
                "environment_id": 200,
                "error_origin": null,
                "error_type": null,
                "extracted_files": [],
                "file_metadata": null,
                "hosts": [],
                "imphash": "Unknown",
                "interesting": false,
                "job_id": "61ae29f24e69ff77d566ab48",
                "machine_learning_models": [],
                "md5": "4b41a3475132bd861b30a878e30aa56a",
                "mitre_attcks": [],
                "network_mode": "default",
                "processes": [],
                "sha1": "bfd009f500c057195ffde66fae64f92fa5f59b72",
                "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
                "sha512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
                "size": 3506,
                "ssdeep": "24:yPp9AA+I3ZpAIZpAL7xMk2uFVBX02ScAjfW2sX25cfW2SJI2k2y62NOfW2t9HZdF:yrQ+YIYbrXq/jeyjbvzGUsnTd3/i",
                "state": "SUCCESS",
                "submissions": [
                    {
                        "created_at": "2022-01-10T08:40:44+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "61dbf10c213fbc5a3914cdd1",
                        "url": null
                    },
                    {
                        "created_at": "2022-01-10T08:35:47+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "61dbefe33f8cec40d619833c",
                        "url": null
                    },
                    {
                        "created_at": "2021-12-06T15:52:44+00:00",
                        "filename": "samplePdf.pdf",
                        "submission_id": "61ae31cce601bf0d4a332f82",
                        "url": null
                    },
                    {
                        "created_at": "2021-12-06T15:19:14+00:00",
                        "filename": "samplePdf.pdf",
                        "submission_id": "61ae29f24e69ff77d566ab49",
                        "url": null
                    }
                ],
                "submit_name": "samplePdf.pdf",
                "tags": [],
                "target_url": null,
                "threat_level": 0,
                "threat_score": null,
                "total_network_connections": 0,
                "total_processes": 0,
                "total_signatures": 1,
                "type": "PDF document, version 1.3",
                "type_short": [
                    "pdf"
                ],
                "url_analysis": false,
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2020-04-14T13:11:37+00:00",
                "av_detect": 0,
                "certificates": [],
                "classification_tags": [],
                "compromised_hosts": [],
                "domains": [],
                "environment_description": "Windows 7 32 bit (HWP Support)",
                "environment_id": 110,
                "error_origin": null,
                "error_type": null,
                "extracted_files": [],
                "file_metadata": null,
                "hosts": [],
                "imphash": "Unknown",
                "interesting": false,
                "job_id": "5e95b682dd8c5642500399ce",
                "machine_learning_models": [],
                "md5": "4b41a3475132bd861b30a878e30aa56a",
                "mitre_attcks": [],
                "network_mode": "default",
                "processes": [],
                "sha1": "bfd009f500c057195ffde66fae64f92fa5f59b72",
                "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
                "sha512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
                "size": 3506,
                "ssdeep": "24:yPp9AA+I3ZpAIZpAL7xMk2uFVBX02ScAjfW2sX25cfW2SJI2k2y62NOfW2t9HZdt:yrQ+YIYbrXq/jeyjbvzGUsnTd3/C",
                "state": "SUCCESS",
                "submissions": [
                    {
                        "created_at": "2020-04-14T13:11:30+00:00",
                        "filename": "file",
                        "submission_id": "5e95b682dd8c5642500399cf",
                        "url": null
                    }
                ],
                "submit_name": "file",
                "tags": [],
                "target_url": null,
                "threat_level": 0,
                "threat_score": null,
                "total_network_connections": 0,
                "total_processes": 4,
                "total_signatures": 14,
                "type": "PDF document, version 1.3",
                "type_short": [
                    "pdf"
                ],
                "url_analysis": false,
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-09-24T13:39:34+00:00",
                "av_detect": 0,
                "certificates": [],
                "classification_tags": [],
                "compromised_hosts": [],
                "domains": [],
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "error_origin": null,
                "error_type": null,
                "extracted_files": [],
                "file_metadata": null,
                "hosts": [],
                "imphash": "Unknown",
                "interesting": false,
                "job_id": "5d8a1c67038838c50e69e5a8",
                "machine_learning_models": [],
                "md5": "4b41a3475132bd861b30a878e30aa56a",
                "mitre_attcks": [],
                "network_mode": "default",
                "processes": [],
                "sha1": "bfd009f500c057195ffde66fae64f92fa5f59b72",
                "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
                "sha512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
                "size": 3506,
                "ssdeep": "24:yPp9AA+I3ZpAIZpAL7xMk2uFVBX02ScAjfW2sX25cfW2SJI2k2y62NOfW2t9HZdd:yrQ+YIYbrXq/jeyjbvzGUsnTd3/hxoxn",
                "state": "SUCCESS",
                "submissions": [
                    {
                        "created_at": "2020-12-17T11:38:35+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5fdb433be6562860c47942cf",
                        "url": null
                    },
                    {
                        "created_at": "2020-12-09T12:12:29+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5fd0bf2d8623f5298734d606",
                        "url": null
                    },
                    {
                        "created_at": "2020-05-26T07:00:18+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5eccbe8203b9557fac384586",
                        "url": null
                    },
                    {
                        "created_at": "2020-04-29T09:51:17+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5ea94e157d7c876d9c76ced3",
                        "url": null
                    },
                    {
                        "created_at": "2020-04-29T09:15:42+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5ea945be351cb361215586fe",
                        "url": null
                    },
                    {
                        "created_at": "2020-04-29T09:11:43+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5ea944cfe3893c0eb22505a3",
                        "url": null
                    },
                    {
                        "created_at": "2020-01-10T00:04:51+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5e17bfa39f797e0f87507547",
                        "url": null
                    },
                    {
                        "created_at": "2019-09-24T13:38:47+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5d8a1c67038838c50e69e5a7",
                        "url": null
                    }
                ],
                "submit_name": "sample.pdf",
                "tags": [],
                "target_url": null,
                "threat_level": 0,
                "threat_score": null,
                "total_network_connections": 0,
                "total_processes": 4,
                "total_signatures": 12,
                "type": "PDF document, version 1.3",
                "type_short": [
                    "pdf"
                ],
                "url_analysis": false,
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-02-09T01:41:57+00:00",
                "av_detect": 0,
                "certificates": [],
                "classification_tags": [],
                "compromised_hosts": [],
                "domains": [],
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "error_origin": null,
                "error_type": null,
                "extracted_files": [],
                "file_metadata": null,
                "hosts": [],
                "imphash": "Unknown",
                "interesting": false,
                "job_id": "5a6896886e3579ce99a80d4d",
                "machine_learning_models": [],
                "md5": "4b41a3475132bd861b30a878e30aa56a",
                "mitre_attcks": [],
                "network_mode": "tor",
                "processes": [],
                "sha1": "bfd009f500c057195ffde66fae64f92fa5f59b72",
                "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
                "sha512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
                "size": 3506,
                "ssdeep": "24:yPp9AA+I3ZpAIZpAL7xMk2uFVBX02ScAjfW2sX25cfW2SJI2k2y62NOfW2t9HZdV:yrQ+YIYbrXq/jeyjbvzGUsnTd3/S",
                "state": "SUCCESS",
                "submissions": [
                    {
                        "created_at": "2022-01-23T17:49:11+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "61ed9517c284dd61265a0e6d",
                        "url": null
                    },
                    {
                        "created_at": "2022-01-09T16:03:26+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "61db074e8782ed13a058f7a4",
                        "url": null
                    },
                    {
                        "created_at": "2022-01-09T16:03:04+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "61db0738f93ee5253c369e74",
                        "url": null
                    },
                    {
                        "created_at": "2021-12-06T14:31:12+00:00",
                        "filename": "samplePdf.pdf",
                        "submission_id": "61ae1eb03be82d62c3775f70",
                        "url": null
                    },
                    {
                        "created_at": "2021-10-20T13:49:19+00:00",
                        "filename": "k18zpzsrq3om4q1pu18mftdo2caaivqq.pdf",
                        "submission_id": "61701e5f1c027f4e08299b54",
                        "url": null
                    },
                    {
                        "created_at": "2021-07-27T13:27:58+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "610009dec612587a6d572e23",
                        "url": null
                    },
                    {
                        "created_at": "2021-07-15T16:15:50+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "60f05f3660f4fd4ee42d0b6f",
                        "url": null
                    },
                    {
                        "created_at": "2021-07-03T21:50:01+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "60e0db8928bccc0b2e405d30",
                        "url": null
                    },
                    {
                        "created_at": "2021-03-01T14:43:08+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "603cfd7c60343f6d115db9f8",
                        "url": "http://www.africau.edu/images/default/sample.pdf"
                    },
                    {
                        "created_at": "2020-10-29T13:17:49+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f9ac0fdd97ff17aac38bc84",
                        "url": "http://www.africau.edu/images/default/sample.pdf"
                    },
                    {
                        "created_at": "2020-07-14T13:09:08+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f0dae74c122fb57fc3f360b",
                        "url": null
                    },
                    {
                        "created_at": "2020-07-14T10:54:02+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f0d8eca91837459ca5cee1c",
                        "url": null
                    },
                    {
                        "created_at": "2020-07-14T10:48:02+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f0d8d622560cc30d825588b",
                        "url": null
                    },
                    {
                        "created_at": "2020-07-13T17:48:02+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f0c9e52f6150a35a72b8c99",
                        "url": null
                    },
                    {
                        "created_at": "2020-07-13T17:38:12+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f0c9c040030d423b83a9991",
                        "url": null
                    },
                    {
                        "created_at": "2020-07-13T17:35:58+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f0c9b7eac8ef74e754f8724",
                        "url": null
                    },
                    {
                        "created_at": "2019-04-11T15:08:01+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5caf58510388385b8b7b23ca",
                        "url": null
                    },
                    {
                        "created_at": "2019-03-10T11:11:01+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5c84f0c5028838b82ffc1ce3",
                        "url": null
                    },
                    {
                        "created_at": "2019-03-10T08:53:28+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5c84d088028838950cfc1ce4",
                        "url": null
                    },
                    {
                        "created_at": "2019-02-08T18:28:18-06:00",
                        "filename": "sample.pdf",
                        "submission_id": "5c5e1ea27ca3e12cd80ecf07",
                        "url": null
                    }
                ],
                "submit_name": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51_1549672910345_sample.pdf",
                "tags": [],
                "target_url": null,
                "threat_level": 0,
                "threat_score": null,
                "total_network_connections": 0,
                "total_processes": 1,
                "total_signatures": 9,
                "type": "PDF document, version 1.3",
                "type_short": [
                    "pdf"
                ],
                "url_analysis": false,
                "verdict": "whitelisted",
                "vx_family": null
            },
            {
                "analysis_start_time": "2021-12-07T08:48:33+00:00",
                "av_detect": 0,
                "certificates": [],
                "classification_tags": [],
                "compromised_hosts": [],
                "domains": [],
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "error_origin": null,
                "error_type": null,
                "extracted_files": [],
                "file_metadata": null,
                "hosts": [],
                "imphash": "Unknown",
                "interesting": false,
                "job_id": "61af1fdd39388f46497e4660",
                "machine_learning_models": [],
                "md5": "73c6bff424d200b4d305a7d775f9d629",
                "mitre_attcks": [],
                "network_mode": "default",
                "processes": [],
                "sha1": "a87c794a850110d03f39d135fe0533710788c694",
                "sha256": "9745bd652c50ac081e28981b96f41230c1ed2f84724c1e5b0f0d407a90aefe22",
                "sha512": "8676737d20a9f151a0af156cc147c97a459ba31922c4f7b2509cfd89be92a46ba745c80fbe12a15281e06bbb20bd571a7a7cc895075f4838b362e4a8e3fe5907",
                "size": 16252453,
                "ssdeep": "Unknown",
                "state": "SUCCESS",
                "submissions": [
                    {
                        "created_at": "2021-12-07T08:48:29+00:00",
                        "filename": "William Stallings - Effective Cybersecurity_ A Guide to Using Best Practices and Standards-Addison-Wesley Professional (2018).pdf",
                        "submission_id": "61af1fdd39388f46497e4661",
                        "url": null
                    }
                ],
                "submit_name": "William Stallings - Effective Cybersecurity_ A Guide to Using Best Practices and Standards-Addison-Wesley Professional (2018).pdf",
                "tags": [],
                "target_url": null,
                "threat_level": 0,
                "threat_score": null,
                "total_network_connections": 0,
                "total_processes": 12,
                "total_signatures": 22,
                "type": "PDF document, version 1.4",
                "type_short": [
                    "pdf"
                ],
                "url_analysis": false,
                "verdict": "no specific threat",
                "vx_family": null
            }
        ]
    },
    "DBotScore": [
        {
            "Indicator": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
            "Reliability": "A - Completely reliable",
            "Score": 1,
            "Type": "file",
            "Vendor": "CrowdStrike Falcon Sandbox V2"
        },
        {
            "Indicator": "9745bd652c50ac081e28981b96f41230c1ed2f84724c1e5b0f0d407a90aefe22",
            "Reliability": "A - Completely reliable",
            "Score": 1,
            "Type": "file",
            "Vendor": "CrowdStrike Falcon Sandbox V2"
        }
    ],
    "File": [
        {
            "JobID": "5a6896886e3579ce99a80d4d",
            "MD5": "4b41a3475132bd861b30a878e30aa56a",
            "Name": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51_1549672910345_sample.pdf",
            "SHA1": "bfd009f500c057195ffde66fae64f92fa5f59b72",
            "SHA256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
            "SHA512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
            "SSDeep": "24:yPp9AA+I3ZpAIZpAL7xMk2uFVBX02ScAjfW2sX25cfW2SJI2k2y62NOfW2t9HZdV:yrQ+YIYbrXq/jeyjbvzGUsnTd3/S",
            "Size": 3506,
            "Type": "PDF document, version 1.3",
            "analysis_start_time": "2019-02-09T01:41:57+00:00",
            "av_detect": 0,
            "certificates": [],
            "classification_tags": [],
            "compromised_hosts": [],
            "domains": [],
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "error_origin": null,
            "error_type": null,
            "extracted_files": [],
            "family": null,
            "file_metadata": null,
            "hosts": [],
            "imphash": "Unknown",
            "interesting": false,
            "isurlanalysis": false,
            "machine_learning_models": [],
            "mitre_attcks": [],
            "network_mode": "tor",
            "processes": [],
            "sha512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
            "size": 3506,
            "ssdeep": "24:yPp9AA+I3ZpAIZpAL7xMk2uFVBX02ScAjfW2sX25cfW2SJI2k2y62NOfW2t9HZdV:yrQ+YIYbrXq/jeyjbvzGUsnTd3/S",
            "state": "SUCCESS",
            "submissions": [
                {
                    "created_at": "2022-01-23T17:49:11+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "61ed9517c284dd61265a0e6d",
                    "url": null
                },
                {
                    "created_at": "2022-01-09T16:03:26+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "61db074e8782ed13a058f7a4",
                    "url": null
                },
                {
                    "created_at": "2022-01-09T16:03:04+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "61db0738f93ee5253c369e74",
                    "url": null
                },
                {
                    "created_at": "2021-12-06T14:31:12+00:00",
                    "filename": "samplePdf.pdf",
                    "submission_id": "61ae1eb03be82d62c3775f70",
                    "url": null
                },
                {
                    "created_at": "2021-10-20T13:49:19+00:00",
                    "filename": "k18zpzsrq3om4q1pu18mftdo2caaivqq.pdf",
                    "submission_id": "61701e5f1c027f4e08299b54",
                    "url": null
                },
                {
                    "created_at": "2021-07-27T13:27:58+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "610009dec612587a6d572e23",
                    "url": null
                },
                {
                    "created_at": "2021-07-15T16:15:50+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "60f05f3660f4fd4ee42d0b6f",
                    "url": null
                },
                {
                    "created_at": "2021-07-03T21:50:01+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "60e0db8928bccc0b2e405d30",
                    "url": null
                },
                {
                    "created_at": "2021-03-01T14:43:08+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "603cfd7c60343f6d115db9f8",
                    "url": "http://www.africau.edu/images/default/sample.pdf"
                },
                {
                    "created_at": "2020-10-29T13:17:49+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "5f9ac0fdd97ff17aac38bc84",
                    "url": "http://www.africau.edu/images/default/sample.pdf"
                },
                {
                    "created_at": "2020-07-14T13:09:08+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "5f0dae74c122fb57fc3f360b",
                    "url": null
                },
                {
                    "created_at": "2020-07-14T10:54:02+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "5f0d8eca91837459ca5cee1c",
                    "url": null
                },
                {
                    "created_at": "2020-07-14T10:48:02+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "5f0d8d622560cc30d825588b",
                    "url": null
                },
                {
                    "created_at": "2020-07-13T17:48:02+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "5f0c9e52f6150a35a72b8c99",
                    "url": null
                },
                {
                    "created_at": "2020-07-13T17:38:12+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "5f0c9c040030d423b83a9991",
                    "url": null
                },
                {
                    "created_at": "2020-07-13T17:35:58+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "5f0c9b7eac8ef74e754f8724",
                    "url": null
                },
                {
                    "created_at": "2019-04-11T15:08:01+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "5caf58510388385b8b7b23ca",
                    "url": null
                },
                {
                    "created_at": "2019-03-10T11:11:01+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "5c84f0c5028838b82ffc1ce3",
                    "url": null
                },
                {
                    "created_at": "2019-03-10T08:53:28+00:00",
                    "filename": "sample.pdf",
                    "submission_id": "5c84d088028838950cfc1ce4",
                    "url": null
                },
                {
                    "created_at": "2019-02-08T18:28:18-06:00",
                    "filename": "sample.pdf",
                    "submission_id": "5c5e1ea27ca3e12cd80ecf07",
                    "url": null
                }
            ],
            "submitname": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51_1549672910345_sample.pdf",
            "tags": [],
            "target_url": null,
            "threat_level": 0,
            "threatscore": null,
            "total_network_connections": 0,
            "total_processes": 1,
            "total_signatures": 9,
            "type": "PDF document, version 1.3",
            "type_short": [
                "pdf"
            ],
            "verdict": "whitelisted"
        },
        {
            "JobID": "61af1fdd39388f46497e4660",
            "MD5": "73c6bff424d200b4d305a7d775f9d629",
            "Name": "William Stallings - Effective Cybersecurity_ A Guide to Using Best Practices and Standards-Addison-Wesley Professional (2018).pdf",
            "SHA1": "a87c794a850110d03f39d135fe0533710788c694",
            "SHA256": "9745bd652c50ac081e28981b96f41230c1ed2f84724c1e5b0f0d407a90aefe22",
            "SHA512": "8676737d20a9f151a0af156cc147c97a459ba31922c4f7b2509cfd89be92a46ba745c80fbe12a15281e06bbb20bd571a7a7cc895075f4838b362e4a8e3fe5907",
            "SSDeep": "Unknown",
            "Size": 16252453,
            "Type": "PDF document, version 1.4",
            "analysis_start_time": "2021-12-07T08:48:33+00:00",
            "av_detect": 0,
            "certificates": [],
            "classification_tags": [],
            "compromised_hosts": [],
            "domains": [],
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "error_origin": null,
            "error_type": null,
            "extracted_files": [],
            "family": null,
            "file_metadata": null,
            "hosts": [],
            "imphash": "Unknown",
            "interesting": false,
            "isurlanalysis": false,
            "machine_learning_models": [],
            "mitre_attcks": [],
            "network_mode": "default",
            "processes": [],
            "sha512": "8676737d20a9f151a0af156cc147c97a459ba31922c4f7b2509cfd89be92a46ba745c80fbe12a15281e06bbb20bd571a7a7cc895075f4838b362e4a8e3fe5907",
            "size": 16252453,
            "ssdeep": "Unknown",
            "state": "SUCCESS",
            "submissions": [
                {
                    "created_at": "2021-12-07T08:48:29+00:00",
                    "filename": "William Stallings - Effective Cybersecurity_ A Guide to Using Best Practices and Standards-Addison-Wesley Professional (2018).pdf",
                    "submission_id": "61af1fdd39388f46497e4661",
                    "url": null
                }
            ],
            "submitname": "William Stallings - Effective Cybersecurity_ A Guide to Using Best Practices and Standards-Addison-Wesley Professional (2018).pdf",
            "tags": [],
            "target_url": null,
            "threat_level": 0,
            "threatscore": null,
            "total_network_connections": 0,
            "total_processes": 12,
            "total_signatures": 22,
            "type": "PDF document, version 1.4",
            "type_short": [
                "pdf"
            ],
            "verdict": "no specific threat"
        }
    ]
}
```

#### Human Readable Output

>### Scan Results:
>|submit name|threat level|verdict|total network connections|total processes|environment description|interesting|environment id|url analysis|analysis start time|total signatures|type|type short|sha256|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| file | 0 | whitelisted | 0 | 0 | Static Analysis | false |  | false | 2020-09-15T16:47:06+00:00 | 0 | PDF document, version 1.3 | pdf | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 |
>| samplePdf.pdf | 0 | no specific threat | 0 | 0 | Android Static Analysis | false | 200 | false | 2021-12-06T15:19:23+00:00 | 1 | PDF document, version 1.3 | pdf | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 |
>| file | 0 | no specific threat | 0 | 4 | Windows 7 32 bit (HWP Support) | false | 110 | false | 2020-04-14T13:11:37+00:00 | 14 | PDF document, version 1.3 | pdf | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 |
>| sample.pdf | 0 | no specific threat | 0 | 4 | Windows 7 64 bit | false | 120 | false | 2019-09-24T13:39:34+00:00 | 12 | PDF document, version 1.3 | pdf | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 |
>| 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51_1549672910345_sample.pdf | 0 | whitelisted | 0 | 1 | Windows 7 32 bit | false | 100 | false | 2019-02-09T01:41:57+00:00 | 9 | PDF document, version 1.3 | pdf | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 |
>| William Stallings - Effective Cybersecurity_ A Guide to Using Best Practices and Standards-Addison-Wesley Professional (2018).pdf | 0 | no specific threat | 0 | 12 | Windows 7 64 bit | false | 120 | false | 2021-12-07T08:48:33+00:00 | 22 | PDF document, version 1.4 | pdf | 9745bd652c50ac081e28981b96f41230c1ed2f84724c1e5b0f0d407a90aefe22 |


### cs-falcon-sandbox-get-environments
***
Gets a list of all available environments.


#### Base Command

`cs-falcon-sandbox-get-environments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Environment.ID | number | The environment ID. | 
| CrowdStrike.Environment.description | string | The environment description. | 
| CrowdStrike.Environment.architecture | string | The environment architecture. | 
| CrowdStrike.Environment.VMs_total | number | The total number of virtual machines in the environment. | 
| CrowdStrike.Environment.VMs_busy | number | The number of busy virtual machines in the environment. | 
| CrowdStrike.Environment.analysisMode | string | The environment analysis mode. | 
| CrowdStrike.Environment.groupicon | string | The environment icon. | 

#### Command example
```!cs-falcon-sandbox-get-environments```
#### Context Example
```json
{
    "CrowdStrike": {
        "Environment": [
            {
                "ID": 100,
                "VMs_busy": 9223372036854776000,
                "VMs_total": 9223372036854776000,
                "analysisMode": "KERNELMODE",
                "architecture": "WINDOWS",
                "description": "Windows 7 32 bit",
                "groupicon": "windows",
                "id": "100",
                "invalid_virtual_machines": 0,
                "virtual_machines": []
            },
            {
                "ID": 110,
                "VMs_busy": 9223372036854776000,
                "VMs_total": 9223372036854776000,
                "analysisMode": "KERNELMODE",
                "architecture": "WINDOWS",
                "description": "Windows 7 32 bit (HWP Support)",
                "groupicon": "windows",
                "id": "110",
                "invalid_virtual_machines": 0,
                "virtual_machines": []
            },
            {
                "ID": 120,
                "VMs_busy": 9223372036854776000,
                "VMs_total": 9223372036854776000,
                "analysisMode": "KERNELMODE",
                "architecture": "WINDOWS",
                "description": "Windows 7 64 bit",
                "groupicon": "windows",
                "id": "120",
                "invalid_virtual_machines": 0,
                "virtual_machines": []
            },
            {
                "ID": 300,
                "VMs_busy": 9223372036854776000,
                "VMs_total": 9223372036854776000,
                "analysisMode": "USERMODE",
                "architecture": "LINUX",
                "description": "Linux (Ubuntu 16.04, 64 bit)",
                "groupicon": "linux",
                "id": "300",
                "invalid_virtual_machines": 0,
                "virtual_machines": []
            },
            {
                "ID": 200,
                "VMs_busy": 9223372036854776000,
                "VMs_total": 9223372036854776000,
                "analysisMode": "USERMODE",
                "architecture": "ANDROID",
                "description": "Android Static Analysis",
                "groupicon": "android",
                "id": "200",
                "invalid_virtual_machines": 0,
                "virtual_machines": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Execution Environments:
>|_ID|Description|Architecture|Total VMS|Busy VMS|Analysis mode|Group icon|
>|---|---|---|---|---|---|---|
>| 100 | Windows 7 32 bit | WINDOWS | 9223372036854775807 | 9223372036854775807 | KERNELMODE | windows |
>| 110 | Windows 7 32 bit (HWP Support) | WINDOWS | 9223372036854775807 | 9223372036854775807 | KERNELMODE | windows |
>| 120 | Windows 7 64 bit | WINDOWS | 9223372036854775807 | 9223372036854775807 | KERNELMODE | windows |
>| 300 | Linux (Ubuntu 16.04, 64 bit) | LINUX | 9223372036854775807 | 9223372036854775807 | USERMODE | linux |
>| 200 | Android Static Analysis | ANDROID | 9223372036854775807 | 9223372036854775807 | USERMODE | android |


### cs-falcon-sandbox-submit-sample
***
Submits a file from the investigation to the analysis server.


#### Base Command

`cs-falcon-sandbox-submit-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryId | The War Room entry ID. | Required | 
| environmentID | The environment ID. Available environment IDs: 300: "Linux (Ubuntu 16.04, 64 bit)"", 200: "Android Static Analysis", 120: "Windows 7 64 bit", 110: "Windows 7 32 bit (HWP Support)", 100: "Windows 7 32 bit". Possible values are: 100, 110, 120, 200, 300. Default is 100. | Required | 
| polling | Whether the command should poll until the result is ready. Possible values are: true, false. | Optional | 
| no_share_third_party | When set to 'true', the sample is never shared with any third party. Possible values are: true, false. | Optional | 
| no_hash_lookup | When set to 'true', no hash lookup is done on the sample. Possible values are: true, false. | Optional | 
| allow_community_access | When set to 'true', the sample is available for the community. Possible values are: true, false. | Optional | 
| action_script | Optional custom runtime action script. Available runtime scripts: default, default_maxantievasion, default_randomfiles, default_randomtheme, default_openie. Possible values are: default, default_maxantievasion, default_randomfiles, default_randomtheme, default_openie. | Optional | 
| hybrid_analysis | When set to 'false', no memory dump or memory dump analysis is done. Possible values are: true, false. | Optional | 
| experimental_anti_evasion | When set to 'true', sets all Kernelmode Monitor experimental anti-evasion options. Possible values are: true, false. | Optional | 
| script_logging | When set to 'true', sets the Kernelmode Monitor in-depth script logging engine. Possible values are: true, false. | Optional | 
| input_sample_tampering | When set to 'true', allows Kernelmode Monitor experimental anti-evasion options that tamper with the input sample. Possible values are: true, false. | Optional | 
| network_settings | Network settings. Available options: default: 'Fully operating network', tor: 'Route network traffic via TOR', simulated: 'Simulate network traffic'. Possible values are: default, tor, simulated. | Optional | 
| email | Optional email address that may be associated with the submission for notification. | Optional | 
| comment | Optional comment text that may be associated with the submission/sample (Note: you can use #tags). | Optional | 
| custom_cmd_line | Optional command line that should be passed to the analysis file. | Optional | 
| custom_run_time | Optional runtime duration (in seconds). | Optional | 
| submit_name | Optional 'submission name' field that will be used for file type detection and analysis. Ignored unless url contains a file | Optional | 
| priority | Optional priority value between 1 (lowest) and 10 (highest). By default all samples run with highest priority. Possible values are: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10. | Optional | 
| document_password | Optional document password used to fill in Adobe/Office password prompts. | Optional | 
| environment_variable | Optional system environment value. The value is provided in the format name=value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Submit.job_id | String | The submitted report job ID. | 
| CrowdStrike.Submit.submission_id | String | The report submission ID. | 
| CrowdStrike.Submit.environment_id | Number | The report environment ID. | 
| CrowdStrike.Submit.sha256 | String | The SHA256 hash of the file. | 
| CrowdStrike.Report.job_id | String | The report job ID. | 
| CrowdStrike.Report.environment_id | Number | The report environment ID. | 
| CrowdStrike.Report.environment_description | String |  | 
| CrowdStrike.Report.size | Number | The file size. | 
| CrowdStrike.Report.type | String | The file type. | 
| CrowdStrike.Report.type_short | String |  | 
| CrowdStrike.Report.target_url | String |  | 
| CrowdStrike.Report.state | String | The report state. | 
| CrowdStrike.Report.error_type | String |  | 
| CrowdStrike.Report.error_origin | String |  | 
| CrowdStrike.Report.submit_name | String | The name of the file when submitted. | 
| CrowdStrike.Report.md5 | String | The MD5 hash of the file. | 
| CrowdStrike.Report.sha1 | String | The SHA1 hash of the file. | 
| CrowdStrike.Report.sha256 | String | The SHA256 hash of the file. | 
| CrowdStrike.Report.sha512 | String | The SHA512 hash of the file. | 
| CrowdStrike.Report.ssdeep | String | The SSDeep hash of the file. | 
| CrowdStrike.Report.imphash | String | The imphash hash of the file. | 
| CrowdStrike.Report.av_detect | Number | The AV Multiscan range, for example 50-70 \(min 0, max 100\). | 
| CrowdStrike.Report.vx_family | String | The file malware family. | 
| CrowdStrike.Report.url_analysis | Boolean |  | 
| CrowdStrike.Report.analysis_start_time | Date |  | 
| CrowdStrike.Report.threat_score | Number | The file threat score. | 
| CrowdStrike.Report.interesting | Boolean | Whether the file was found to be interesting. | 
| CrowdStrike.Report.threat_level | Number | The file threat level. | 
| CrowdStrike.Report.verdict | String | The file verdict. | 
| CrowdStrike.Report.total_network_connections | Number |  | 
| CrowdStrike.Report.total_processes | Number |  | 
| CrowdStrike.Report.total_signatures | Number |  | 
| CrowdStrike.Report.file_metadata | Object | The file metadata. | 
| CrowdStrike.Report.submissions.submission_id | String | The submission ID | 
| CrowdStrike.Report.submissions.filename | String |  | 
| CrowdStrike.Report.submissions.url | String |  | 
| CrowdStrike.Report.submissions.created_at | Date |  | 
| CrowdStrike.Report.network_mode | String |  | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.Name | string | The file submission name. | 
| File.MalwareFamily | string | The file family classification. | 
| File.Malicious.Vendor | string | The vendor that decided the file was malicious. | 
| File.Malicious.Description | string | The reason the vendor decided the file was malicious. | 
| DBotScore.Indicator | string | The tested indicator. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 

### cs-falcon-sandbox-search
***
Searches the database using the Falcon Sandbox search syntax.


#### Base Command

`cs-falcon-sandbox-search`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                      | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| query             | The Falcon Sandbox query syntax, for example url:google,host:95.181.53.78. This argument integrates all other arguments into one and cannot be given along with the other arguments.                                                                                                                                                                                 | Optional | 
| filename          | The file name, for example invoice.exe.                                                                                                                                                                                                                                                                                                                              | Optional | 
| filetype          | The file type. Available options: 64bits, android, assembly, bat, cmd, com, csv, data, doc, docx, elf, empty, executable, flash, html, hwp, hwpx, img, iqy, java, javascript, library, lnk, macho, mshelp, msi, native, neexe, office, outlook, pdf, pedll, peexe, perl, ppt, pptx, ps, pub, python, rtf, script, sct, sh, svg, text, url, vbe, vbs, wsf, xls, xlsx. | Optional | 
| filetype_desc     | The file type description, for example PE32 executable.                                                                                                                                                                                                                                                                                                              | Optional | 
| env_id            | The environment ID.                                                                                                                                                                                                                                                                                                                                                  | Optional | 
| country           | The country (3 digit ISO), for example swe.                                                                                                                                                                                                                                                                                                                          | Optional | 
| verdict           | The search result verdict. Available options: Whitelisted, NoVerdict, NoSpecificThreat, Suspicious, Malicious. Possible values are: Whitelisted, NoVerdict, NoSpecificThreat, Suspicious, Malicious.                                                                                                                                                                 | Optional | 
| av_detect         | The AV Multiscan range, for example 50-70 (min 0, max 100).                                                                                                                                                                                                                                                                                                          | Optional | 
| vx_family         | The AV Family Substring, for example nemucod.                                                                                                                                                                                                                                                                                                                        | Optional | 
| limit             | The max number of search results to return. Default is 10.                                                                                                                                                                                                                                                                                                           | Optional | 
| tag               | The hashtag, for example ransomware.                                                                                                                                                                                                                                                                                                                                 | Optional | 
| date_from         | The date from in format 'YYYY-MM-DD HH:MM', for example 2018-09-28 15:30.                                                                                                                                                                                                                                                                                            | Optional | 
| date_to           | The date to in format 'YYYY-MM-DD HH:MM', for example 2018-09-28 15:30.                                                                                                                                                                                                                                                                                              | Optional | 
| port              | The port, for example 8080.                                                                                                                                                                                                                                                                                                                                          | Optional | 
| host              | The host, for example 192.168.0.1.                                                                                                                                                                                                                                                                                                                                   | Optional | 
| domain            | The domain, for example checkip.dyndns.org.                                                                                                                                                                                                                                                                                                                          | Optional | 
| url               | The HTTP request substring, for example google.                                                                                                                                                                                                                                                                                                                      | Optional | 
| similar_to        | Similar samples, for example &lt;sha256&gt;.                                                                                                                                                                                                                                                                                                                         | Optional | 
| context           | Sample context, for example &lt;sha256&gt;.                                                                                                                                                                                                                                                                                                                          | Optional | 
| imp_hash          | The import hash.                                                                                                                                                                                                                                                                                                                                                     | Optional | 
| ssdeep            | The SSDeep hash.                                                                                                                                                                                                                                                                                                                                                     | Optional | 
| authentihash      | The file authentihash.                                                                                                                                                                                                                                                                                                                                               | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Name | string | The file submission name. | 
| File.MalwareFamily | string | The file family classification. | 
| File.Extension | string |  | 
| File.MalwareFamily | String | The malware family associated with the file. | 
| CrowdStrike.Search.search_terms.id | String |  | 
| CrowdStrike.Search.search_terms.value | String |  | 
| CrowdStrike.Search.count | Number |  | 
| CrowdStrike.Search.result.verdict | String |  | 
| CrowdStrike.Search.result.av_detect | String |  | 
| CrowdStrike.Search.result.threat_score | Number |  | 
| CrowdStrike.Search.result.vx_family | String |  | 
| CrowdStrike.Search.result.job_id | String |  | 
| CrowdStrike.Search.result.sha256 | String |  | 
| CrowdStrike.Search.result.environment_id | Number |  | 
| CrowdStrike.Search.result.analysis_start_time | Date |  | 
| CrowdStrike.Search.result.submit_name | String |  | 
| CrowdStrike.Search.result.environment_description | String |  | 
| CrowdStrike.Search.result.size | Number |  | 
| CrowdStrike.Search.result.type | String |  | 
| CrowdStrike.Search.result.type_short | String |  | 

#### Command example
```!cs-falcon-sandbox-search filename=sample.pdf```
#### Context Example
```json
{
    "CrowdStrike": {
        "Search": [
            {
                "analysis_start_time": "2020-09-15T16:47:06+00:00",
                "av_detect": "0",
                "environment_description": "Static Analysis",
                "environment_id": null,
                "job_id": "5f60f00aeac13102de2fce70",
                "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
                "size": 3028,
                "submit_name": "file",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "whitelisted",
                "vx_family": null
            },
            {
                "analysis_start_time": "2021-11-30 03:00:10",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "61a593b82d8c3b27e521d683",
                "sha256": "e4c0b73252211528f355e7db301da6369e69e079c6daad9e8fbb0134cc44ce27",
                "size": 160626,
                "submit_name": "Sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2021-11-05 17:02:53",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "618551a497ef941c2b423271",
                "sha256": "2f0de9415b0e746b1189d939d84d0dd15ea93d457bd0a42ebec8b52475c2be63",
                "size": 468452,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2021-08-09 07:15:50",
                "av_detect": "25",
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "6110d6214689581ac34e89ab",
                "sha256": "98983e00b47bcbe9ebbaf5f28ea6cdbf619dd88c91f481b18fec7ffdb68ab741",
                "size": 254635,
                "submit_name": "Sample.pdf",
                "threat_score": 100,
                "type": null,
                "type_short": "pdf",
                "verdict": "malicious",
                "vx_family": "RDN/Generic.cf"
            },
            {
                "analysis_start_time": "2021-07-30 17:31:11",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "61043759e4ae00628e4757d9",
                "sha256": "45d2de1252ebd402728b2cb810d8a9232a99e9887f75146d2e7d1d84d46fd360",
                "size": 561412,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2021-06-24 02:53:57",
                "av_detect": "0",
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "60d3f3bb942da51feb3c77b5",
                "sha256": "b33d6fa9eac776c1ad07c406bacef7c9af8ce052a181a5801a0bffa1f24ebf1d",
                "size": 25138418,
                "submit_name": "Sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2021-06-03 09:49:10",
                "av_detect": "0",
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "60b8a59139899b32c2459c98",
                "sha256": "7207460b6cf6e4965b7ab20bfadca652ab1629240781e49f7e783de8a9c31900",
                "size": 370299,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2020-08-04 18:46:31",
                "av_detect": "2",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "5f29acffc8af093b787e92de",
                "sha256": "4af3aa3c6afd3db86a65f191bd69306650e12475fd5611ccaec5519543276d5a",
                "size": 64532,
                "submit_name": "Sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": "Unavailable"
            },
            {
                "analysis_start_time": "2020-07-08 15:39:36",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "5f05c7c22ada7e11701edcc2",
                "sha256": "02b0fcf5406a4cd1c816ea21bc25f6f0bcb5ae36b8da9526d3af6f5aab89b6de",
                "size": 394003,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2020-06-18 15:15:46",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "5eeb85187ce0e079d35424e7",
                "sha256": "3714ef17995d459f9c81d99b77bdef830b24dbe28d893b2b4f1952279ca91aa6",
                "size": 5639308,
                "submit_name": "sample.pdf",
                "threat_score": 29,
                "type": null,
                "type_short": "pdf",
                "verdict": "suspicious",
                "vx_family": null
            },
            {
                "analysis_start_time": "2020-06-05T07:35:10+00:00",
                "av_detect": "42",
                "environment_description": "Linux (Ubuntu 16.04, 64 bit)",
                "environment_id": 300,
                "job_id": "5ed9f5ae2466ef104967e5bb",
                "sha256": "9d0bfa6a3c99f83bb6d9fb4822855c488dedd3a9a2fe19010e0e176437422b04",
                "size": 5732088,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "64-bit elf",
                "verdict": null,
                "vx_family": "Unavailable"
            },
            {
                "analysis_start_time": "2020-06-04 05:21:19",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "5ed884ca8989f014bf0a2867",
                "sha256": "91f5a577e0df35103c8bf6d5d5ea6690b97ed319570ba61688379d254fe9b1ed",
                "size": 159219,
                "submit_name": "Sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2020-05-10 06:06:38",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "5eb799e4098ed957b177f7f1",
                "sha256": "6822023d6f22b0f08f788c4528eed07c424603b1d68fc4fdb8ef8a9e6dfab3b6",
                "size": 69992,
                "submit_name": "Sample.pdf",
                "threat_score": 56,
                "type": null,
                "type_short": "pdf",
                "verdict": "suspicious",
                "vx_family": null
            },
            {
                "analysis_start_time": "2020-02-14 04:50:05",
                "av_detect": null,
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "5e4626f1428a7c6bd26e42e8",
                "sha256": "a5963f78a27e384421e23ff54974094a34112b8eeec77615cd4235d7b82812c7",
                "size": 35270,
                "submit_name": "sample.pdf",
                "threat_score": 35,
                "type": null,
                "type_short": "html",
                "verdict": "suspicious",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-09-25 07:30:35",
                "av_detect": "0",
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "5d8b17a8028838f13e7f6bf4",
                "sha256": "7856688c84402d991250abf44d8bea30131837f11a69891fb9597816e8902f4e",
                "size": 189630,
                "submit_name": "sample.pdf",
                "threat_score": 45,
                "type": null,
                "type_short": "pdf",
                "verdict": "suspicious",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-09-25 07:04:24",
                "av_detect": "0",
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "5d8b1180028838e40e7f6bc1",
                "sha256": "ed511c548b99fe89836cbd9258e81a9f84df95bb8fc8cccc7958b2b5bd40a6e3",
                "size": 186763,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": "Unavailable"
            },
            {
                "analysis_start_time": "2019-09-09 09:07:09",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "5d7616ef0388386b85511900",
                "sha256": "6d056be8945a60bc2f68c6468bd4f6b68a37f99e69090478e0f8f078b9763176",
                "size": 50790,
                "submit_name": "sample.pdf",
                "threat_score": 29,
                "type": null,
                "type_short": "pdf",
                "verdict": "suspicious",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-09-01T10:31:54+00:00",
                "av_detect": null,
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "5d6b9e1a0288383930c48455",
                "sha256": "8b46920adaa5a4d2d2912f68452dea622fa215d78e923a878647a5febe082a36",
                "size": 58,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "text",
                "verdict": null,
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-09-01T10:00:10+00:00",
                "av_detect": null,
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "5d6b96660388389c397057c2",
                "sha256": "84e0435537ceedd0819188759387f4eeb59c8bc63d243c9b4a3399a90e564715",
                "size": 41,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "text",
                "verdict": null,
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-06-22 12:25:24",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit (HWP Support)",
                "environment_id": 110,
                "job_id": "5d0e1e790288380b0e2af5eb",
                "sha256": "9fcb5ed2265c1aca54a8e4ebc847e0c9c19b7aa7984f3e7ca0794b314057505e",
                "size": 2669339,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-04-22 06:41:37",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "5cbd62160388381a4caf198e",
                "sha256": "6042d499aca0c5700fb416a4970fdd9238272397732beda9b4065a21c0150e8e",
                "size": 440654,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-03-29 04:41:26",
                "av_detect": "0",
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "5c9da41c02883869997acd28",
                "sha256": "c979e4b6a1850794609860fcc68bda58edc0f51989d57a199808d3f1a2564d7a",
                "size": 95318,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-03-20T17:45:03+00:00",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "5c927c1f038838b59636b712",
                "sha256": "b26054c33e5f201a2a4cafb5047c576115c389451e5a74f3f75400e4f0504512",
                "size": 95271,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": null,
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-03-19 06:38:41",
                "av_detect": "0",
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "5c909092028838fe55b4f755",
                "sha256": "f8bf163014405cd4dc8f133fc563886e92a2b98862edd98d5f8656eba67db284",
                "size": 496372,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-03-14 17:06:41",
                "av_detect": null,
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "5c8a8c39038838899a329921",
                "sha256": "65ab8a0fd8920379c37d03ad3b5f7d62d5a8b00b902c5d72229269328aa2221f",
                "size": 1317691,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-03-09 06:40:22",
                "av_detect": "0",
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "5c8361e20388387f5d1006a4",
                "sha256": "e28401b6fa6f8fafc7db5946c30a18ab2d306748b277609caec5ecf970506529",
                "size": 696561,
                "submit_name": "Sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-02-26 18:41:27",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "5c758a5a038838514ca50f27",
                "sha256": "a84b84b85911e68b421172a1d857da81706a7608eae6415e9a52bb9e59801e59",
                "size": 1154729,
                "submit_name": "sample.pdf",
                "threat_score": 20,
                "type": null,
                "type_short": "pdf",
                "verdict": "malicious",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-02-15 09:36:27",
                "av_detect": "0",
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "5c6676c07ca3e17d121f3f11",
                "sha256": "855e15b9e02ff992d81e2cf93fdec286b81e8374b5acad5a9009d1569ca86cf0",
                "size": 324101,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-01-30T18:15:14-06:00",
                "av_detect": "0",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "5c5236d97ca3e107a93e8333",
                "sha256": "33adb4f6630443600d5d1381350ac018f1676d8523084af814b5c01da3e7a609",
                "size": 80468,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "raw data",
                "verdict": null,
                "vx_family": null
            },
            {
                "analysis_start_time": "2018-11-22 20:24:37",
                "av_detect": "0",
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "5bf702607ca3e16165774af7",
                "sha256": "9f49c971051e7026314e979e3e1f06552a52f44bd56fe4eb9cf7867f82c8755f",
                "size": 6782390,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2018-10-17 08:14:46",
                "av_detect": "67",
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "job_id": "5bc6d34b7ca3e104a26ff5c3",
                "sha256": "a927b3f2244e901e23e50f6b7a4929b837f0f0d1d8e0dc0a1957f5208b4e4e51",
                "size": 11961,
                "submit_name": "extract-1424750780.560286-HTTP-FTdiED2cMH3iOTs3c4.raw.pdf",
                "threat_score": 100,
                "type": null,
                "type_short": "pdf",
                "verdict": "malicious",
                "vx_family": "PDF:Exploit.PDF"
            },
            {
                "analysis_start_time": "2016-08-27 06:28:06",
                "av_detect": "75",
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "job_id": "57c116c0aac2edfe59c7c2a0",
                "sha256": "86a96ec03ba8242c1486456d67ee17f919128754846dbb3bdf5e836059091dba",
                "size": 10866,
                "submit_name": "pdf-doc-vba-eicar-dropper.pdf",
                "threat_score": 100,
                "type": null,
                "type_short": "pdf",
                "verdict": "malicious",
                "vx_family": "Trojan.Eicartest"
            },
            {
                "analysis_start_time": "2022-01-11T03:46:07+00:00",
                "av_detect": "0",
                "environment_description": "Static Analysis",
                "environment_id": null,
                "job_id": "61dcfd7f797bea289de8eaff",
                "sha256": "55c3b94ca033edb56010d8cfbbc17c900911e0f5bc938020debdc8d454a15313",
                "size": 254738,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2022-01-05T12:02:39+00:00",
                "av_detect": "0",
                "environment_description": "Static Analysis",
                "environment_id": null,
                "job_id": "61d588df797bea289d371b1d",
                "sha256": "6332a96c88c486d1b396f9346e689d1ad15c06ae733539cd4e66a2bd8dbec9ff",
                "size": 218816,
                "submit_name": "SAMPLE.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2021-07-28T05:48:32+00:00",
                "av_detect": "0",
                "environment_description": "Static Analysis",
                "environment_id": null,
                "job_id": "6100efb09a02dd8ce6bb695a",
                "sha256": "177661da747aebe78fa66313ca239143a226be23d397a5327329c732c4d2670b",
                "size": 727215,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": "Unavailable"
            },
            {
                "analysis_start_time": "2021-03-17T06:15:46+00:00",
                "av_detect": "0",
                "environment_description": "Static Analysis",
                "environment_id": null,
                "job_id": "60519e929a02dd8ce6f4090c",
                "sha256": "111ee199588c1a167be496933b037fefaa69c45404f915054edc8e209a73fa4c",
                "size": 215461,
                "submit_name": "SAMPLE.PDF",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2021-01-11T08:18:07+00:00",
                "av_detect": "0",
                "environment_description": "Static Analysis",
                "environment_id": null,
                "job_id": "5ffc09bf40fe1d5daa5ca658",
                "sha256": "dc13bd74b9e78ea241bbb0736a8e660eb56afc53b2701b75964d89cb47f6edb0",
                "size": 1285713,
                "submit_name": "Sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2021-01-08T05:47:16+00:00",
                "av_detect": "0",
                "environment_description": "Static Analysis",
                "environment_id": null,
                "job_id": "5ff7f1e440fe1d5daa17422b",
                "sha256": "6486ef92ad7b591f6da0eacf04304840e8d293b591ca4e48c2eeca664bf0d120",
                "size": 2037209,
                "submit_name": "Sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2020-12-10T03:33:47+00:00",
                "av_detect": "0",
                "environment_description": "Static Analysis",
                "environment_id": null,
                "job_id": "5fd1971b40fe1d5daa721221",
                "sha256": "d60dee8111b0289e66e5858dd27f29855d1611f3602564f0cdfe06725790c144",
                "size": 268886,
                "submit_name": "sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2020-11-25T13:16:42+00:00",
                "av_detect": "0",
                "environment_description": "Static Analysis",
                "environment_id": null,
                "job_id": "5fbe593a40fe1d5daa57823e",
                "sha256": "5ff12f55a1a8c198ccafff9e1920b9e2a5d5cde0f2f6cfe787264c43cbac808c",
                "size": 381447,
                "submit_name": "Sample.pdf",
                "threat_score": null,
                "type": null,
                "type_short": "pdf",
                "verdict": "no specific threat",
                "vx_family": null
            }
        ]
    },
    "File": [
        {
            "Extension": "pdf",
            "JobID": "5f60f00aeac13102de2fce70",
            "Name": "file",
            "SHA256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
            "Size": 3028,
            "av_detect": "0",
            "environmentDescription": "Static Analysis",
            "environmentId": null,
            "size": 3028,
            "start_time": "2020-09-15T16:47:06+00:00",
            "submitname": "file",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "whitelisted",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "61a593b82d8c3b27e521d683",
            "Name": "Sample.pdf",
            "SHA256": "e4c0b73252211528f355e7db301da6369e69e079c6daad9e8fbb0134cc44ce27",
            "Size": 160626,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 160626,
            "start_time": "2021-11-30 03:00:10",
            "submitname": "Sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "618551a497ef941c2b423271",
            "Name": "sample.pdf",
            "SHA256": "2f0de9415b0e746b1189d939d84d0dd15ea93d457bd0a42ebec8b52475c2be63",
            "Size": 468452,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 468452,
            "start_time": "2021-11-05 17:02:53",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "6110d6214689581ac34e89ab",
            "MalwareFamily": "RDN/Generic.cf",
            "Name": "Sample.pdf",
            "SHA256": "98983e00b47bcbe9ebbaf5f28ea6cdbf619dd88c91f481b18fec7ffdb68ab741",
            "Size": 254635,
            "av_detect": "25",
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 254635,
            "start_time": "2021-08-09 07:15:50",
            "submitname": "Sample.pdf",
            "threatscore": 100,
            "type": null,
            "type_short": "pdf",
            "verdict": "malicious",
            "vx_family": "RDN/Generic.cf"
        },
        {
            "Extension": "pdf",
            "JobID": "61043759e4ae00628e4757d9",
            "Name": "sample.pdf",
            "SHA256": "45d2de1252ebd402728b2cb810d8a9232a99e9887f75146d2e7d1d84d46fd360",
            "Size": 561412,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 561412,
            "start_time": "2021-07-30 17:31:11",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "60d3f3bb942da51feb3c77b5",
            "Name": "Sample.pdf",
            "SHA256": "b33d6fa9eac776c1ad07c406bacef7c9af8ce052a181a5801a0bffa1f24ebf1d",
            "Size": 25138418,
            "av_detect": "0",
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 25138418,
            "start_time": "2021-06-24 02:53:57",
            "submitname": "Sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "60b8a59139899b32c2459c98",
            "Name": "sample.pdf",
            "SHA256": "7207460b6cf6e4965b7ab20bfadca652ab1629240781e49f7e783de8a9c31900",
            "Size": 370299,
            "av_detect": "0",
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 370299,
            "start_time": "2021-06-03 09:49:10",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5f29acffc8af093b787e92de",
            "MalwareFamily": "Unavailable",
            "Name": "Sample.pdf",
            "SHA256": "4af3aa3c6afd3db86a65f191bd69306650e12475fd5611ccaec5519543276d5a",
            "Size": 64532,
            "av_detect": "2",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 64532,
            "start_time": "2020-08-04 18:46:31",
            "submitname": "Sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": "Unavailable"
        },
        {
            "Extension": "pdf",
            "JobID": "5f05c7c22ada7e11701edcc2",
            "Name": "sample.pdf",
            "SHA256": "02b0fcf5406a4cd1c816ea21bc25f6f0bcb5ae36b8da9526d3af6f5aab89b6de",
            "Size": 394003,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 394003,
            "start_time": "2020-07-08 15:39:36",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5eeb85187ce0e079d35424e7",
            "Name": "sample.pdf",
            "SHA256": "3714ef17995d459f9c81d99b77bdef830b24dbe28d893b2b4f1952279ca91aa6",
            "Size": 5639308,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 5639308,
            "start_time": "2020-06-18 15:15:46",
            "submitname": "sample.pdf",
            "threatscore": 29,
            "type": null,
            "type_short": "pdf",
            "verdict": "suspicious",
            "vx_family": null
        },
        {
            "Extension": "64-bit elf",
            "JobID": "5ed9f5ae2466ef104967e5bb",
            "MalwareFamily": "Unavailable",
            "Name": "sample.pdf",
            "SHA256": "9d0bfa6a3c99f83bb6d9fb4822855c488dedd3a9a2fe19010e0e176437422b04",
            "Size": 5732088,
            "av_detect": "42",
            "environmentDescription": "Linux (Ubuntu 16.04, 64 bit)",
            "environmentId": 300,
            "size": 5732088,
            "start_time": "2020-06-05T07:35:10+00:00",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "64-bit elf",
            "verdict": null,
            "vx_family": "Unavailable"
        },
        {
            "Extension": "pdf",
            "JobID": "5ed884ca8989f014bf0a2867",
            "Name": "Sample.pdf",
            "SHA256": "91f5a577e0df35103c8bf6d5d5ea6690b97ed319570ba61688379d254fe9b1ed",
            "Size": 159219,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 159219,
            "start_time": "2020-06-04 05:21:19",
            "submitname": "Sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5eb799e4098ed957b177f7f1",
            "Name": "Sample.pdf",
            "SHA256": "6822023d6f22b0f08f788c4528eed07c424603b1d68fc4fdb8ef8a9e6dfab3b6",
            "Size": 69992,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 69992,
            "start_time": "2020-05-10 06:06:38",
            "submitname": "Sample.pdf",
            "threatscore": 56,
            "type": null,
            "type_short": "pdf",
            "verdict": "suspicious",
            "vx_family": null
        },
        {
            "Extension": "html",
            "JobID": "5e4626f1428a7c6bd26e42e8",
            "Name": "sample.pdf",
            "SHA256": "a5963f78a27e384421e23ff54974094a34112b8eeec77615cd4235d7b82812c7",
            "Size": 35270,
            "av_detect": null,
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 35270,
            "start_time": "2020-02-14 04:50:05",
            "submitname": "sample.pdf",
            "threatscore": 35,
            "type": null,
            "type_short": "html",
            "verdict": "suspicious",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5d8b17a8028838f13e7f6bf4",
            "Name": "sample.pdf",
            "SHA256": "7856688c84402d991250abf44d8bea30131837f11a69891fb9597816e8902f4e",
            "Size": 189630,
            "av_detect": "0",
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 189630,
            "start_time": "2019-09-25 07:30:35",
            "submitname": "sample.pdf",
            "threatscore": 45,
            "type": null,
            "type_short": "pdf",
            "verdict": "suspicious",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5d8b1180028838e40e7f6bc1",
            "MalwareFamily": "Unavailable",
            "Name": "sample.pdf",
            "SHA256": "ed511c548b99fe89836cbd9258e81a9f84df95bb8fc8cccc7958b2b5bd40a6e3",
            "Size": 186763,
            "av_detect": "0",
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 186763,
            "start_time": "2019-09-25 07:04:24",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": "Unavailable"
        },
        {
            "Extension": "pdf",
            "JobID": "5d7616ef0388386b85511900",
            "Name": "sample.pdf",
            "SHA256": "6d056be8945a60bc2f68c6468bd4f6b68a37f99e69090478e0f8f078b9763176",
            "Size": 50790,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 50790,
            "start_time": "2019-09-09 09:07:09",
            "submitname": "sample.pdf",
            "threatscore": 29,
            "type": null,
            "type_short": "pdf",
            "verdict": "suspicious",
            "vx_family": null
        },
        {
            "Extension": "text",
            "JobID": "5d6b9e1a0288383930c48455",
            "Name": "sample.pdf",
            "SHA256": "8b46920adaa5a4d2d2912f68452dea622fa215d78e923a878647a5febe082a36",
            "Size": 58,
            "av_detect": null,
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 58,
            "start_time": "2019-09-01T10:31:54+00:00",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "text",
            "verdict": null,
            "vx_family": null
        },
        {
            "Extension": "text",
            "JobID": "5d6b96660388389c397057c2",
            "Name": "sample.pdf",
            "SHA256": "84e0435537ceedd0819188759387f4eeb59c8bc63d243c9b4a3399a90e564715",
            "Size": 41,
            "av_detect": null,
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 41,
            "start_time": "2019-09-01T10:00:10+00:00",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "text",
            "verdict": null,
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5d0e1e790288380b0e2af5eb",
            "Name": "sample.pdf",
            "SHA256": "9fcb5ed2265c1aca54a8e4ebc847e0c9c19b7aa7984f3e7ca0794b314057505e",
            "Size": 2669339,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit (HWP Support)",
            "environmentId": 110,
            "size": 2669339,
            "start_time": "2019-06-22 12:25:24",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5cbd62160388381a4caf198e",
            "Name": "sample.pdf",
            "SHA256": "6042d499aca0c5700fb416a4970fdd9238272397732beda9b4065a21c0150e8e",
            "Size": 440654,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 440654,
            "start_time": "2019-04-22 06:41:37",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5c9da41c02883869997acd28",
            "Name": "sample.pdf",
            "SHA256": "c979e4b6a1850794609860fcc68bda58edc0f51989d57a199808d3f1a2564d7a",
            "Size": 95318,
            "av_detect": "0",
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 95318,
            "start_time": "2019-03-29 04:41:26",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5c927c1f038838b59636b712",
            "Name": "sample.pdf",
            "SHA256": "b26054c33e5f201a2a4cafb5047c576115c389451e5a74f3f75400e4f0504512",
            "Size": 95271,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 95271,
            "start_time": "2019-03-20T17:45:03+00:00",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": null,
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5c909092028838fe55b4f755",
            "Name": "sample.pdf",
            "SHA256": "f8bf163014405cd4dc8f133fc563886e92a2b98862edd98d5f8656eba67db284",
            "Size": 496372,
            "av_detect": "0",
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 496372,
            "start_time": "2019-03-19 06:38:41",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5c8a8c39038838899a329921",
            "Name": "sample.pdf",
            "SHA256": "65ab8a0fd8920379c37d03ad3b5f7d62d5a8b00b902c5d72229269328aa2221f",
            "Size": 1317691,
            "av_detect": null,
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 1317691,
            "start_time": "2019-03-14 17:06:41",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5c8361e20388387f5d1006a4",
            "Name": "Sample.pdf",
            "SHA256": "e28401b6fa6f8fafc7db5946c30a18ab2d306748b277609caec5ecf970506529",
            "Size": 696561,
            "av_detect": "0",
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 696561,
            "start_time": "2019-03-09 06:40:22",
            "submitname": "Sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5c758a5a038838514ca50f27",
            "Name": "sample.pdf",
            "SHA256": "a84b84b85911e68b421172a1d857da81706a7608eae6415e9a52bb9e59801e59",
            "Size": 1154729,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 1154729,
            "start_time": "2019-02-26 18:41:27",
            "submitname": "sample.pdf",
            "threatscore": 20,
            "type": null,
            "type_short": "pdf",
            "verdict": "malicious",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5c6676c07ca3e17d121f3f11",
            "Name": "sample.pdf",
            "SHA256": "855e15b9e02ff992d81e2cf93fdec286b81e8374b5acad5a9009d1569ca86cf0",
            "Size": 324101,
            "av_detect": "0",
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 324101,
            "start_time": "2019-02-15 09:36:27",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "raw data",
            "JobID": "5c5236d97ca3e107a93e8333",
            "Name": "sample.pdf",
            "SHA256": "33adb4f6630443600d5d1381350ac018f1676d8523084af814b5c01da3e7a609",
            "Size": 80468,
            "av_detect": "0",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 80468,
            "start_time": "2019-01-30T18:15:14-06:00",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "raw data",
            "verdict": null,
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5bf702607ca3e16165774af7",
            "Name": "sample.pdf",
            "SHA256": "9f49c971051e7026314e979e3e1f06552a52f44bd56fe4eb9cf7867f82c8755f",
            "Size": 6782390,
            "av_detect": "0",
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 6782390,
            "start_time": "2018-11-22 20:24:37",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5bc6d34b7ca3e104a26ff5c3",
            "MalwareFamily": "PDF:Exploit.PDF",
            "Name": "extract-1424750780.560286-HTTP-FTdiED2cMH3iOTs3c4.raw.pdf",
            "SHA256": "a927b3f2244e901e23e50f6b7a4929b837f0f0d1d8e0dc0a1957f5208b4e4e51",
            "Size": 11961,
            "av_detect": "67",
            "environmentDescription": "Windows 7 64 bit",
            "environmentId": 120,
            "size": 11961,
            "start_time": "2018-10-17 08:14:46",
            "submitname": "extract-1424750780.560286-HTTP-FTdiED2cMH3iOTs3c4.raw.pdf",
            "threatscore": 100,
            "type": null,
            "type_short": "pdf",
            "verdict": "malicious",
            "vx_family": "PDF:Exploit.PDF"
        },
        {
            "Extension": "pdf",
            "JobID": "57c116c0aac2edfe59c7c2a0",
            "MalwareFamily": "Trojan.Eicartest",
            "Name": "pdf-doc-vba-eicar-dropper.pdf",
            "SHA256": "86a96ec03ba8242c1486456d67ee17f919128754846dbb3bdf5e836059091dba",
            "Size": 10866,
            "av_detect": "75",
            "environmentDescription": "Windows 7 32 bit",
            "environmentId": 100,
            "size": 10866,
            "start_time": "2016-08-27 06:28:06",
            "submitname": "pdf-doc-vba-eicar-dropper.pdf",
            "threatscore": 100,
            "type": null,
            "type_short": "pdf",
            "verdict": "malicious",
            "vx_family": "Trojan.Eicartest"
        },
        {
            "Extension": "pdf",
            "JobID": "61dcfd7f797bea289de8eaff",
            "Name": "sample.pdf",
            "SHA256": "55c3b94ca033edb56010d8cfbbc17c900911e0f5bc938020debdc8d454a15313",
            "Size": 254738,
            "av_detect": "0",
            "environmentDescription": "Static Analysis",
            "environmentId": null,
            "size": 254738,
            "start_time": "2022-01-11T03:46:07+00:00",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "61d588df797bea289d371b1d",
            "Name": "SAMPLE.pdf",
            "SHA256": "6332a96c88c486d1b396f9346e689d1ad15c06ae733539cd4e66a2bd8dbec9ff",
            "Size": 218816,
            "av_detect": "0",
            "environmentDescription": "Static Analysis",
            "environmentId": null,
            "size": 218816,
            "start_time": "2022-01-05T12:02:39+00:00",
            "submitname": "SAMPLE.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "6100efb09a02dd8ce6bb695a",
            "MalwareFamily": "Unavailable",
            "Name": "sample.pdf",
            "SHA256": "177661da747aebe78fa66313ca239143a226be23d397a5327329c732c4d2670b",
            "Size": 727215,
            "av_detect": "0",
            "environmentDescription": "Static Analysis",
            "environmentId": null,
            "size": 727215,
            "start_time": "2021-07-28T05:48:32+00:00",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": "Unavailable"
        },
        {
            "Extension": "pdf",
            "JobID": "60519e929a02dd8ce6f4090c",
            "Name": "SAMPLE.PDF",
            "SHA256": "111ee199588c1a167be496933b037fefaa69c45404f915054edc8e209a73fa4c",
            "Size": 215461,
            "av_detect": "0",
            "environmentDescription": "Static Analysis",
            "environmentId": null,
            "size": 215461,
            "start_time": "2021-03-17T06:15:46+00:00",
            "submitname": "SAMPLE.PDF",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5ffc09bf40fe1d5daa5ca658",
            "Name": "Sample.pdf",
            "SHA256": "dc13bd74b9e78ea241bbb0736a8e660eb56afc53b2701b75964d89cb47f6edb0",
            "Size": 1285713,
            "av_detect": "0",
            "environmentDescription": "Static Analysis",
            "environmentId": null,
            "size": 1285713,
            "start_time": "2021-01-11T08:18:07+00:00",
            "submitname": "Sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5ff7f1e440fe1d5daa17422b",
            "Name": "Sample.pdf",
            "SHA256": "6486ef92ad7b591f6da0eacf04304840e8d293b591ca4e48c2eeca664bf0d120",
            "Size": 2037209,
            "av_detect": "0",
            "environmentDescription": "Static Analysis",
            "environmentId": null,
            "size": 2037209,
            "start_time": "2021-01-08T05:47:16+00:00",
            "submitname": "Sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5fd1971b40fe1d5daa721221",
            "Name": "sample.pdf",
            "SHA256": "d60dee8111b0289e66e5858dd27f29855d1611f3602564f0cdfe06725790c144",
            "Size": 268886,
            "av_detect": "0",
            "environmentDescription": "Static Analysis",
            "environmentId": null,
            "size": 268886,
            "start_time": "2020-12-10T03:33:47+00:00",
            "submitname": "sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        },
        {
            "Extension": "pdf",
            "JobID": "5fbe593a40fe1d5daa57823e",
            "Name": "Sample.pdf",
            "SHA256": "5ff12f55a1a8c198ccafff9e1920b9e2a5d5cde0f2f6cfe787264c43cbac808c",
            "Size": 381447,
            "av_detect": "0",
            "environmentDescription": "Static Analysis",
            "environmentId": null,
            "size": 381447,
            "start_time": "2020-11-25T13:16:42+00:00",
            "submitname": "Sample.pdf",
            "threatscore": null,
            "type": null,
            "type_short": "pdf",
            "verdict": "no specific threat",
            "vx_family": null
        }
    ]
}
```

#### Human Readable Output

>### Search Results:
>|Submit Name|Verdict|Vx Family|Threat Score|Sha 256|Size|Environment Id|Type Short|Analysis Start Time|
>|---|---|---|---|---|---|---|---|---|
>| sample.pdf |  |  |  | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 | 3028 | 300 | pdf | 2022-01-10T08:33:11+00:00 |
>| sample.pdf |  |  |  | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 | 3028 | 300 | pdf | 2022-01-10T07:38:29+00:00 |
>| samplePdf.pdf | no specific threat |  |  | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 | 3506 | 200 | pdf | 2021-12-06 15:19:23 |
>| Sample.pdf | no specific threat |  |  | e4c0b73252211528f355e7db301da6369e69e079c6daad9e8fbb0134cc44ce27 | 160626 | 100 | pdf | 2021-11-30 03:00:10 |
>| sample.pdf | no specific threat |  |  | 2f0de9415b0e746b1189d939d84d0dd15ea93d457bd0a42ebec8b52475c2be63 | 468452 | 100 | pdf | 2021-11-05 17:02:53 |
>| Sample.pdf | malicious | RDN/Generic.cf | 100 | 98983e00b47bcbe9ebbaf5f28ea6cdbf619dd88c91f481b18fec7ffdb68ab741 | 254635 | 120 | pdf | 2021-08-09 07:15:50 |
>| sample.pdf | no specific threat |  |  | 45d2de1252ebd402728b2cb810d8a9232a99e9887f75146d2e7d1d84d46fd360 | 561412 | 100 | pdf | 2021-07-30 17:31:11 |
>| Sample.pdf | no specific threat |  |  | b33d6fa9eac776c1ad07c406bacef7c9af8ce052a181a5801a0bffa1f24ebf1d | 25138418 | 120 | pdf | 2021-06-24 02:53:57 |
>| sample.pdf | no specific threat |  |  | 7207460b6cf6e4965b7ab20bfadca652ab1629240781e49f7e783de8a9c31900 | 370299 | 120 | pdf | 2021-06-03 09:49:10 |
>| Sample.pdf | no specific threat | Unavailable |  | 4af3aa3c6afd3db86a65f191bd69306650e12475fd5611ccaec5519543276d5a | 64532 | 100 | pdf | 2020-08-04 18:46:31 |
>| sample.pdf | no specific threat |  |  | 02b0fcf5406a4cd1c816ea21bc25f6f0bcb5ae36b8da9526d3af6f5aab89b6de | 394003 | 100 | pdf | 2020-07-08 15:39:36 |
>| sample.pdf | suspicious |  | 29 | 3714ef17995d459f9c81d99b77bdef830b24dbe28d893b2b4f1952279ca91aa6 | 5639308 | 100 | pdf | 2020-06-18 15:15:46 |
>| sample.pdf |  | Unavailable |  | 9d0bfa6a3c99f83bb6d9fb4822855c488dedd3a9a2fe19010e0e176437422b04 | 5732088 | 300 | 64-bit elf | 2020-06-05T07:35:10+00:00 |
>| Sample.pdf | no specific threat |  |  | 91f5a577e0df35103c8bf6d5d5ea6690b97ed319570ba61688379d254fe9b1ed | 159219 | 100 | pdf | 2020-06-04 05:21:19 |
>| Sample.pdf | suspicious |  | 56 | 6822023d6f22b0f08f788c4528eed07c424603b1d68fc4fdb8ef8a9e6dfab3b6 | 69992 | 100 | pdf | 2020-05-10 06:06:38 |
>| sample.pdf | suspicious |  | 35 | a5963f78a27e384421e23ff54974094a34112b8eeec77615cd4235d7b82812c7 | 35270 | 100 | html | 2020-02-14 04:50:05 |
>| sample.pdf | suspicious |  | 45 | 7856688c84402d991250abf44d8bea30131837f11a69891fb9597816e8902f4e | 189630 | 120 | pdf | 2019-09-25 07:30:35 |
>| sample.pdf | no specific threat | Unavailable |  | ed511c548b99fe89836cbd9258e81a9f84df95bb8fc8cccc7958b2b5bd40a6e3 | 186763 | 120 | pdf | 2019-09-25 07:04:24 |
>| sample.pdf | no specific threat |  |  | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 | 3506 | 120 | pdf | 2019-09-24 13:39:34 |
>| sample.pdf | suspicious |  | 29 | 6d056be8945a60bc2f68c6468bd4f6b68a37f99e69090478e0f8f078b9763176 | 50790 | 100 | pdf | 2019-09-09 09:07:09 |
>| sample.pdf |  |  |  | 8b46920adaa5a4d2d2912f68452dea622fa215d78e923a878647a5febe082a36 | 58 | 120 | text | 2019-09-01T10:31:54+00:00 |
>| sample.pdf |  |  |  | 84e0435537ceedd0819188759387f4eeb59c8bc63d243c9b4a3399a90e564715 | 41 | 120 | text | 2019-09-01T10:00:10+00:00 |
>| sample.pdf | no specific threat |  |  | 9fcb5ed2265c1aca54a8e4ebc847e0c9c19b7aa7984f3e7ca0794b314057505e | 2669339 | 120 | pdf | 2019-06-22 12:28:03 |
>| sample.pdf | no specific threat |  |  | 9fcb5ed2265c1aca54a8e4ebc847e0c9c19b7aa7984f3e7ca0794b314057505e | 2669339 | 200 | pdf | 2019-06-22 12:28:06 |
>| sample.pdf |  |  |  | 9fcb5ed2265c1aca54a8e4ebc847e0c9c19b7aa7984f3e7ca0794b314057505e | 1250161 | 300 | pdf | 2019-06-22T12:29:15+00:00 |
>| sample.pdf | no specific threat |  |  | 9fcb5ed2265c1aca54a8e4ebc847e0c9c19b7aa7984f3e7ca0794b314057505e | 2669339 | 110 | pdf | 2019-06-22 12:25:24 |
>| sample.pdf | no specific threat |  |  | 6042d499aca0c5700fb416a4970fdd9238272397732beda9b4065a21c0150e8e | 440654 | 100 | pdf | 2019-04-22 06:41:37 |
>| sample.pdf | no specific threat |  |  | c979e4b6a1850794609860fcc68bda58edc0f51989d57a199808d3f1a2564d7a | 95318 | 120 | pdf | 2019-03-29 04:41:26 |
>| sample.pdf |  |  |  | b26054c33e5f201a2a4cafb5047c576115c389451e5a74f3f75400e4f0504512 | 95271 | 100 | pdf | 2019-03-20T17:45:03+00:00 |
>| sample.pdf | no specific threat |  |  | f8bf163014405cd4dc8f133fc563886e92a2b98862edd98d5f8656eba67db284 | 496372 | 120 | pdf | 2019-03-19 06:38:41 |
>| sample.pdf | no specific threat |  |  | 65ab8a0fd8920379c37d03ad3b5f7d62d5a8b00b902c5d72229269328aa2221f | 1317691 | 120 | pdf | 2019-03-14 17:06:41 |
>| Sample.pdf | no specific threat |  |  | e28401b6fa6f8fafc7db5946c30a18ab2d306748b277609caec5ecf970506529 | 696561 | 120 | pdf | 2019-03-09 06:40:22 |
>| sample.pdf | malicious |  | 20 | a84b84b85911e68b421172a1d857da81706a7608eae6415e9a52bb9e59801e59 | 1154729 | 100 | pdf | 2019-02-26 18:41:27 |
>| sample.pdf | no specific threat |  |  | 855e15b9e02ff992d81e2cf93fdec286b81e8374b5acad5a9009d1569ca86cf0 | 324101 | 120 | pdf | 2019-02-15 09:36:27 |
>| sample.pdf |  |  |  | 33adb4f6630443600d5d1381350ac018f1676d8523084af814b5c01da3e7a609 | 80468 | 100 | raw data | 2019-01-30T18:15:14-06:00 |
>| sample.pdf | no specific threat |  |  | 9f49c971051e7026314e979e3e1f06552a52f44bd56fe4eb9cf7867f82c8755f | 6782390 | 120 | pdf | 2018-11-22 20:24:37 |
>| sample.pdf | no specific threat |  |  | 7788dc62ba791614492dfb74a78367a9f69b20e9cb5bee106bea578f2cbc29c3 | 40677967 | 120 | pdf | 2018-11-19 17:30:23 |
>| extract-1424750780.560286-HTTP-FTdiED2cMH3iOTs3c4.raw.pdf | malicious | PDF:Exploit.PDF | 100 | a927b3f2244e901e23e50f6b7a4929b837f0f0d1d8e0dc0a1957f5208b4e4e51 | 11961 | 120 | pdf | 2018-10-17 08:14:46 |
>|  | whitelisted |  |  | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 | 3506 | 100 | pdf | 2019-02-09 01:41:57 |
>| pdf-doc-vba-eicar-dropper.pdf | malicious | Trojan.Eicartest | 100 | 86a96ec03ba8242c1486456d67ee17f919128754846dbb3bdf5e836059091dba | 10866 | 100 | pdf | 2016-08-27 06:28:06 |
>| sample.pdf | no specific threat |  |  | 55c3b94ca033edb56010d8cfbbc17c900911e0f5bc938020debdc8d454a15313 | 254738 |  | pdf | 2022-01-11T03:46:07+00:00 |
>| SAMPLE.pdf | no specific threat |  |  | 6332a96c88c486d1b396f9346e689d1ad15c06ae733539cd4e66a2bd8dbec9ff | 218816 |  | pdf | 2022-01-05T12:02:39+00:00 |
>| sample.pdf | no specific threat | Unavailable |  | 177661da747aebe78fa66313ca239143a226be23d397a5327329c732c4d2670b | 727215 |  | pdf | 2021-07-28T05:48:32+00:00 |
>| SAMPLE.PDF | no specific threat |  |  | 111ee199588c1a167be496933b037fefaa69c45404f915054edc8e209a73fa4c | 215461 |  | pdf | 2021-03-17T06:15:46+00:00 |
>| Sample.pdf | no specific threat |  |  | dc13bd74b9e78ea241bbb0736a8e660eb56afc53b2701b75964d89cb47f6edb0 | 1285713 |  | pdf | 2021-01-11T08:18:07+00:00 |
>| Sample.pdf | no specific threat |  |  | 6486ef92ad7b591f6da0eacf04304840e8d293b591ca4e48c2eeca664bf0d120 | 2037209 |  | pdf | 2021-01-08T05:47:16+00:00 |
>| sample.pdf | no specific threat |  |  | d60dee8111b0289e66e5858dd27f29855d1611f3602564f0cdfe06725790c144 | 268886 |  | pdf | 2020-12-10T03:33:47+00:00 |
>| Sample.pdf | no specific threat |  |  | 5ff12f55a1a8c198ccafff9e1920b9e2a5d5cde0f2f6cfe787264c43cbac808c | 381447 |  | pdf | 2020-11-25T13:16:42+00:00 |
>| file | whitelisted |  |  | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 | 3028 |  | pdf | 2020-09-15T16:47:06+00:00 |


### cs-falcon-sandbox-result
***
Retrieves result data on a file. Note: This command returns a file.


#### Base Command

`cs-falcon-sandbox-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| polling | Whether the command should poll until the result is ready. Possible values are: true, false. Default is True. | Optional | 
| file | The file hash (MD5, SHA1, or SHA256). | Optional | 
| environmentID | The environment ID. Available environment IDs: 300: "Linux (Ubuntu 16.04, 64 bit)"", 200: "Android Static Analysis", 120: "Windows 7 64 bit", 110: "Windows 7 32 bit (HWP Support)", 100: "Windows 7 32 bit". Possible values are: 100, 110, 120, 200, 300. | Optional | 
| JobID | The file job ID to generate a report for. | Optional | 
| file-type | The file type. Possible values are: xml, json, html, pdf, maec, stix, misp, misp-json, openioc. Default is pdf. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Report.job_id | String | The file job ID. | 
| CrowdStrike.Report.environment_id | Number | The report environment ID. | 
| CrowdStrike.Report.environment_description | String |  | 
| CrowdStrike.Report.size | Number | The file size. | 
| CrowdStrike.Report.type | String | The file type. | 
| CrowdStrike.Report.type_short | String |  | 
| CrowdStrike.Report.target_url | String |  | 
| CrowdStrike.Report.state | String | The report state. | 
| CrowdStrike.Report.error_type | String |  | 
| CrowdStrike.Report.error_origin | String |  | 
| CrowdStrike.Report.submit_name | String | The file name when submitted. | 
| CrowdStrike.Report.md5 | String | The MD5 hash of the file. | 
| CrowdStrike.Report.sha1 | String | The SHA1 hash of the file. | 
| CrowdStrike.Report.sha256 | String | The SHA256 hash of the file. | 
| CrowdStrike.Report.sha512 | String | The SHA512 hash of the file. | 
| CrowdStrike.Report.ssdeep | String | The SSDeep hash of the file. | 
| CrowdStrike.Report.imphash | String | The imphash hash of the file. | 
| CrowdStrike.Report.av_detect | Number | The AV Multiscan range, for example 50-70 \(min 0, max 100\). | 
| CrowdStrike.Report.vx_family | String | The file malware family. | 
| CrowdStrike.Report.url_analysis | Boolean |  | 
| CrowdStrike.Report.analysis_start_time | Date |  | 
| CrowdStrike.Report.threat_score | Number | The file threat score. | 
| CrowdStrike.Report.interesting | Boolean | Whether the file was found to be interesting. | 
| CrowdStrike.Report.threat_level | Number | The file threat level. | 
| CrowdStrike.Report.verdict | String | The file verdict. | 
| CrowdStrike.Report.total_network_connections | Number |  | 
| CrowdStrike.Report.total_processes | Number |  | 
| CrowdStrike.Report.total_signatures | Number |  | 
| CrowdStrike.Report.file_metadata | Object | The file metadata. | 
| CrowdStrike.Report.submissions.submission_id | String |  | 
| CrowdStrike.Report.submissions.filename | String |  | 
| CrowdStrike.Report.submissions.url | String |  | 
| CrowdStrike.Report.submissions.created_at | Date |  | 
| CrowdStrike.Report.network_mode | String |  | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.Name | string | The file submission name. | 
| File.MalwareFamily | string | The file family classification. | 
| File.Malicious.Vendor | string | The vendor that decided the file was malicious. | 
| File.Malicious.Description | string | The reason the vendor decided the file was malicious. | 
| DBotScore.Indicator | string | The tested indicator. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| InfoFile.Name | string | The file name. | 
| InfoFile.EntryID | string | The file entry ID. | 
| InfoFile.Size | number | The file size. | 
| InfoFile.Type | string | The file type, for example "PE". | 
| InfoFile.Info | string | Basic information about the file. | 
| InfoFile.Extension | string | The file extension. | 

### cs-falcon-sandbox-submit-url
***
Submits a URL for analysis.


#### Base Command

`cs-falcon-sandbox-submit-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL for analysis or the URL of the file to submit. | Required | 
| environmentID | The environment ID. Available environment IDs: 300: "Linux (Ubuntu 16.04, 64 bit)"", 200: "Android Static Analysis", 120: "Windows 7 64 bit", 110: "Windows 7 32 bit (HWP Support)", 100: "Windows 7 32 bit". Possible values are: 100, 110, 120, 200, 300. Default is 100. | Required | 
| polling | Whether the command should poll until the result is ready. Possible values are: true, false. | Optional | 
| no_share_third_party | When set to 'true', the sample is never shared with any third party. Possible values are: true, false. | Optional | 
| no_hash_lookup | When set to 'true', no hash lookup is done on the sample. Possible values are: true, false. | Optional | 
| allow_community_access | When set to 'true', the sample is available for the community. Possible values are: true, false. | Optional | 
| action_script | Optional custom runtime action script. Available runtime scripts: default, default_maxantievasion, default_randomfiles, default_randomtheme, default_openie. Possible values are: default, default_maxantievasion, default_randomfiles, default_randomtheme, default_openie. | Optional | 
| hybrid_analysis | When set to 'false', no memory dump or memory dump analysis is done. Possible values are: true, false. | Optional | 
| experimental_anti_evasion | When set to 'true', sets all Kernelmode Monitor experimental anti-evasion options. Possible values are: true, false. | Optional | 
| script_logging | When set to 'true', sets the Kernelmode Monitor in-depth script logging engine. Possible values are: true, false. | Optional | 
| input_sample_tampering | When set to 'true', allows Kernelmode Monitor experimental anti-evasion options that tamper with the input sample. Possible values are: true, false. | Optional | 
| network_settings | Network settings. Available options: default: 'Fully operating network', tor: 'Route network traffic via TOR', simulated: 'Simulate network traffic'. Possible values are: default, tor, simulated. | Optional | 
| email | Optional email address that may be associated with the submission for notification. | Optional | 
| comment | Optional comment text that may be associated with the submission/sample (Note: you can use #tags). | Optional | 
| custom_cmd_line | Optional command line that should be passed to the analysis file. | Optional | 
| custom_run_time | Optional runtime duration (in seconds). | Optional | 
| submit_name | Optional 'submission name' field that will be used for file type detection and analysis. Ignored unless url contains a file | Optional | 
| priority | Optional priority value between 1 (lowest) and 10 (highest). By default all samples run with highest priority. Possible values are: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10. | Optional | 
| document_password | Optional document password used to fill in Adobe/Office password prompts. | Optional | 
| environment_variable | Optional system environment value. The value is provided in the format name=value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Submit.job_id | String | The The submitted report job ID. | 
| CrowdStrike.Submit.submission_type | String |  | 
| CrowdStrike.Submit.submission_id | String | The submission ID. | 
| CrowdStrike.Submit.environment_id | Number | The submission environment ID. | 
| CrowdStrike.Submit.sha256 | String | The SHA256 hash of the file. | 
| CrowdStrike.Report.job_id | String | The report job ID. | 
| CrowdStrike.Report.environment_id | Number | The report environment ID. | 
| CrowdStrike.Report.environment_description | String |  | 
| CrowdStrike.Report.size | Number | The file size. | 
| CrowdStrike.Report.type | String | The file type. | 
| CrowdStrike.Report.type_short | String |  | 
| CrowdStrike.Report.target_url | String |  | 
| CrowdStrike.Report.state | String | The report state. | 
| CrowdStrike.Report.error_type | String |  | 
| CrowdStrike.Report.error_origin | String |  | 
| CrowdStrike.Report.submit_name | String | The file name when submitted. | 
| CrowdStrike.Report.md5 | String | The MD5 hash of the file. | 
| CrowdStrike.Report.sha1 | String | The SHA1 hash of the file. | 
| CrowdStrike.Report.sha256 | String | The SHA256 hash of the file. | 
| CrowdStrike.Report.sha512 | String | The SHA512 hash of the file. | 
| CrowdStrike.Report.ssdeep | String | The SSDeep hash of the file. | 
| CrowdStrike.Report.imphash | String | The imphash hash of the file. | 
| CrowdStrike.Report.av_detect | Number | The AV Multiscan range, for example 50-70 \(min 0, max 100\) | 
| CrowdStrike.Report.vx_family | String | The file malware famil. | 
| CrowdStrike.Report.url_analysis | Boolean |  | 
| CrowdStrike.Report.analysis_start_time | Date |  | 
| CrowdStrike.Report.threat_score | Number | The file threat score. | 
| CrowdStrike.Report.interesting | Boolean | Whether the file was found to be interesting. | 
| CrowdStrike.Report.threat_level | Number | The file threat level. | 
| CrowdStrike.Report.verdict | String | The file verdict. | 
| CrowdStrike.Report.total_network_connections | Number |  | 
| CrowdStrike.Report.total_processes | Number |  | 
| CrowdStrike.Report.total_signatures | Number |  | 
| CrowdStrike.Report.file_metadata | Object | The file metadata. | 
| CrowdStrike.Report.submissions.submission_id | String | The submission ID. | 
| CrowdStrike.Report.submissions.filename | String |  | 
| CrowdStrike.Report.submissions.url | String |  | 
| CrowdStrike.Report.submissions.created_at | Date |  | 
| CrowdStrike.Report.network_mode | String |  | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.Name | string | The file submission name. | 
| File.MalwareFamily | string | The file family classification. | 
| File.Malicious.Vendor | string | The vendor that decided the file was malicious. | 
| File.Malicious.Description | string | The reason the vendor decided the file was malicious. | 
| DBotScore.Indicator | string | The tested indicator. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 

#### Command example
```!cs-falcon-sandbox-submit-url url=example.com environmentID=300```
#### Context Example
```json
{
    "CrowdStrike": {
        "EnvironmentID": 300,
        "JobID": "61f7a5f99741de6d6100bbc8",
        "Report": [
            {
                "analysis_start_time": "2020-02-03T08:39:15+00:00",
                "av_detect": 0,
                "certificates": [],
                "classification_tags": [],
                "compromised_hosts": [],
                "domains": [],
                "environment_description": "Static Analysis",
                "environment_id": null,
                "error_origin": null,
                "error_type": null,
                "extracted_files": [],
                "file_metadata": null,
                "hosts": [],
                "imphash": null,
                "interesting": false,
                "job_id": null,
                "machine_learning_models": [],
                "md5": "be69708899323a1c8d5f88d9909d7b7a",
                "mitre_attcks": [],
                "network_mode": "default",
                "processes": [],
                "sha1": "017f143e0d7c33c65e4cb1a325e21c02c052c586",
                "sha256": "0b1d27c7ef8651eac6933608d4cb0a4b9fd74c45b883d5a4da1eeaa540f6cc5c",
                "sha512": "891aa9b7c6db52ce2259d8b1094889d389224b4069eac33f608f1630b6b92bdb0c37f488cf0c4254cd9cbbb052d3eeda2497ba560f3f49f0d32fa0b37753149e",
                "size": null,
                "ssdeep": null,
                "state": "SUCCESS",
                "submissions": [
                    {
                        "created_at": "2022-01-04T03:51:44+00:00",
                        "filename": null,
                        "submission_id": "61d3c45075dd613cd2318de3",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-12-10T10:47:23+00:00",
                        "filename": null,
                        "submission_id": "61b3303bee51fe1f135eb6b7",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-12-09T07:12:15+00:00",
                        "filename": null,
                        "submission_id": "61b1ac4fdf3fac4b3646afaf",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-12-06T06:45:16+00:00",
                        "filename": null,
                        "submission_id": "61adb17ce135f902cc551c48",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-12-06T06:44:27+00:00",
                        "filename": null,
                        "submission_id": "61adb14bc57a140f004524e3",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-12-03T02:13:39+00:00",
                        "filename": null,
                        "submission_id": "61a97d5379045c262d110cdd",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-12-03T02:13:03+00:00",
                        "filename": null,
                        "submission_id": "61a97d2fe02d87331d25e5a0",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-12-03T02:10:31+00:00",
                        "filename": null,
                        "submission_id": "61a97c97342971450f29b089",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-09-06T00:39:25+00:00",
                        "filename": null,
                        "submission_id": "6135633d41965265aa0a8dac",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-09-06T00:39:20+00:00",
                        "filename": null,
                        "submission_id": "613563381330f950b228416a",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-09-06T00:39:01+00:00",
                        "filename": null,
                        "submission_id": "6135632521e8ac3e5b189d17",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-09-06T00:21:47+00:00",
                        "filename": null,
                        "submission_id": "61355f1bcde472428f05416c",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-09-06T00:21:41+00:00",
                        "filename": null,
                        "submission_id": "61355f156c70b32ce5616a9a",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-09-06T00:21:16+00:00",
                        "filename": null,
                        "submission_id": "61355efcd71dbf0d2b05a084",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-09-06T00:21:04+00:00",
                        "filename": null,
                        "submission_id": "61355ef05278276a355a88d1",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-09-05T16:15:26+00:00",
                        "filename": null,
                        "submission_id": "6134ed1e68b3fa69b92a29a6",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-09-05T16:15:21+00:00",
                        "filename": null,
                        "submission_id": "6134ed19e76fc318ca444ce3",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-09-05T16:15:03+00:00",
                        "filename": null,
                        "submission_id": "6134ed07a94fd140c8512fe7",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-09-05T16:14:53+00:00",
                        "filename": null,
                        "submission_id": "6134ecfd6743b00302001a9f",
                        "url": "http://example.com/"
                    },
                    {
                        "created_at": "2021-09-05T08:35:09+00:00",
                        "filename": null,
                        "submission_id": "6134813d0ff3652bfc4886c3",
                        "url": "http://example.com/"
                    }
                ],
                "submit_name": "http://example.com/",
                "tags": [
                    "tag",
                    "tng"
                ],
                "target_url": null,
                "threat_level": 1,
                "threat_score": null,
                "total_network_connections": 0,
                "total_processes": 0,
                "total_signatures": 0,
                "type": null,
                "type_short": [],
                "url_analysis": true,
                "verdict": "suspicious",
                "vx_family": null
            }
        ],
        "Submit": {
            "environment_id": 300,
            "job_id": "61f7a5f99741de6d6100bbc8",
            "sha256": "0b1d27c7ef8651eac6933608d4cb0a4b9fd74c45b883d5a4da1eeaa540f6cc5c",
            "submission_id": "61f7a5f99741de6d6100bbc9",
            "submission_type": "page_url"
        }
    },
    "DBotScore": {
        "Indicator": "0b1d27c7ef8651eac6933608d4cb0a4b9fd74c45b883d5a4da1eeaa540f6cc5c",
        "Reliability": "A - Completely reliable",
        "Score": 2,
        "Type": "file",
        "Vendor": "CrowdStrike Falcon Sandbox V2"
    },
    "File": {
        "JobID": null,
        "MD5": "be69708899323a1c8d5f88d9909d7b7a",
        "Name": "http://example.com/",
        "SHA1": "017f143e0d7c33c65e4cb1a325e21c02c052c586",
        "SHA256": "0b1d27c7ef8651eac6933608d4cb0a4b9fd74c45b883d5a4da1eeaa540f6cc5c",
        "SHA512": "891aa9b7c6db52ce2259d8b1094889d389224b4069eac33f608f1630b6b92bdb0c37f488cf0c4254cd9cbbb052d3eeda2497ba560f3f49f0d32fa0b37753149e",
        "analysis_start_time": "2020-02-03T08:39:15+00:00",
        "av_detect": 0,
        "certificates": [],
        "classification_tags": [],
        "compromised_hosts": [],
        "domains": [],
        "environmentDescription": "Static Analysis",
        "environmentId": null,
        "error_origin": null,
        "error_type": null,
        "extracted_files": [],
        "family": null,
        "file_metadata": null,
        "hosts": [],
        "imphash": null,
        "interesting": false,
        "isurlanalysis": true,
        "machine_learning_models": [],
        "mitre_attcks": [],
        "network_mode": "default",
        "processes": [],
        "sha512": "891aa9b7c6db52ce2259d8b1094889d389224b4069eac33f608f1630b6b92bdb0c37f488cf0c4254cd9cbbb052d3eeda2497ba560f3f49f0d32fa0b37753149e",
        "size": null,
        "ssdeep": null,
        "state": "SUCCESS",
        "submissions": [
            {
                "created_at": "2022-01-04T03:51:44+00:00",
                "filename": null,
                "submission_id": "61d3c45075dd613cd2318de3",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-12-10T10:47:23+00:00",
                "filename": null,
                "submission_id": "61b3303bee51fe1f135eb6b7",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-12-09T07:12:15+00:00",
                "filename": null,
                "submission_id": "61b1ac4fdf3fac4b3646afaf",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-12-06T06:45:16+00:00",
                "filename": null,
                "submission_id": "61adb17ce135f902cc551c48",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-12-06T06:44:27+00:00",
                "filename": null,
                "submission_id": "61adb14bc57a140f004524e3",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-12-03T02:13:39+00:00",
                "filename": null,
                "submission_id": "61a97d5379045c262d110cdd",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-12-03T02:13:03+00:00",
                "filename": null,
                "submission_id": "61a97d2fe02d87331d25e5a0",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-12-03T02:10:31+00:00",
                "filename": null,
                "submission_id": "61a97c97342971450f29b089",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-09-06T00:39:25+00:00",
                "filename": null,
                "submission_id": "6135633d41965265aa0a8dac",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-09-06T00:39:20+00:00",
                "filename": null,
                "submission_id": "613563381330f950b228416a",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-09-06T00:39:01+00:00",
                "filename": null,
                "submission_id": "6135632521e8ac3e5b189d17",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-09-06T00:21:47+00:00",
                "filename": null,
                "submission_id": "61355f1bcde472428f05416c",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-09-06T00:21:41+00:00",
                "filename": null,
                "submission_id": "61355f156c70b32ce5616a9a",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-09-06T00:21:16+00:00",
                "filename": null,
                "submission_id": "61355efcd71dbf0d2b05a084",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-09-06T00:21:04+00:00",
                "filename": null,
                "submission_id": "61355ef05278276a355a88d1",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-09-05T16:15:26+00:00",
                "filename": null,
                "submission_id": "6134ed1e68b3fa69b92a29a6",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-09-05T16:15:21+00:00",
                "filename": null,
                "submission_id": "6134ed19e76fc318ca444ce3",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-09-05T16:15:03+00:00",
                "filename": null,
                "submission_id": "6134ed07a94fd140c8512fe7",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-09-05T16:14:53+00:00",
                "filename": null,
                "submission_id": "6134ecfd6743b00302001a9f",
                "url": "http://example.com/"
            },
            {
                "created_at": "2021-09-05T08:35:09+00:00",
                "filename": null,
                "submission_id": "6134813d0ff3652bfc4886c3",
                "url": "http://example.com/"
            }
        ],
        "submitname": "http://example.com/",
        "tags": [
            "tag",
            "tng"
        ],
        "target_url": null,
        "threat_level": 1,
        "threatscore": null,
        "total_network_connections": 0,
        "total_processes": 0,
        "total_signatures": 0,
        "type": null,
        "type_short": [],
        "verdict": "suspicious"
    }
}
```

#### Human Readable Output

>### Scan Results:
>|submit name|threat level|verdict|total network connections|total processes|environment description|interesting|url analysis|analysis start time|total signatures|sha256|
>|---|---|---|---|---|---|---|---|---|---|---|
>| http:<span>//</span>example.com/ | 1 | suspicious | 0 | 0 | Static Analysis | false | true | 2020-02-03T08:39:15+00:00 | 0 | 0b1d27c7ef8651eac6933608d4cb0a4b9fd74c45b883d5a4da1eeaa540f6cc5c |


### cs-falcon-sandbox-get-screenshots
***
Retrieves screenshots from a report


#### Base Command

`cs-falcon-sandbox-get-screenshots`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The sha256 hash of a file. | Optional | 
| environmentID | The environment ID. Available environment IDs: 300: "Linux (Ubuntu 16.04, 64 bit)"", 200: "Android Static Analysis", 120: "Windows 7 64 bit", 110: "Windows 7 32 bit (HWP Support)", 100: "Windows 7 32 bit". Possible values are: 100, 110, 120, 200, 300. | Optional | 
| JobID | The file job ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | The file name. | 
| InfoFile.EntryID | string | The file entry ID. | 
| InfoFile.Size | number | The file size. | 
| InfoFile.Type | string | The file type, for example "PE". | 
| InfoFile.Info | string | Basic information about the file. | 
| InfoFile.Extension | string | The file extension. | 

### cs-falcon-sandbox-analysis-overview
***
Gets the hash overview.


#### Base Command

`cs-falcon-sandbox-analysis-overview`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The SHA256 hash of the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.AnalysisOverview.sha256 | String | The SHA256 hash of the file. | 
| CrowdStrike.AnalysisOverview.last_file_name | String |  | 
| CrowdStrike.AnalysisOverview.threat_score | Number |  | 
| CrowdStrike.AnalysisOverview.verdict | String |  | 
| CrowdStrike.AnalysisOverview.url_analysis | Boolean |  | 
| CrowdStrike.AnalysisOverview.size | Number |  | 
| CrowdStrike.AnalysisOverview.type | String |  | 
| CrowdStrike.AnalysisOverview.type_short | String |  | 
| CrowdStrike.AnalysisOverview.analysis_start_time | Date |  | 
| CrowdStrike.AnalysisOverview.last_multi_scan | Date |  | 
| CrowdStrike.AnalysisOverview.architecture | String |  | 
| CrowdStrike.AnalysisOverview.multiscan_result | Number |  | 
| CrowdStrike.AnalysisOverview.scanners.name | String |  | 
| CrowdStrike.AnalysisOverview.scanners.status | String |  | 
| CrowdStrike.AnalysisOverview.scanners.error_message | String |  | 
| CrowdStrike.AnalysisOverview.scanners.progress | Number |  | 
| CrowdStrike.AnalysisOverview.scanners.total | Number |  | 
| CrowdStrike.AnalysisOverview.scanners.positives | Number |  | 
| CrowdStrike.AnalysisOverview.scanners.percent | Number |  | 
| CrowdStrike.AnalysisOverview.scanners.anti_virus_results.name | String |  | 
| CrowdStrike.AnalysisOverview.scanners.anti_virus_results.result | Boolean |  | 
| CrowdStrike.AnalysisOverview.scanners.anti_virus_results.threat_found | String |  | 
| CrowdStrike.AnalysisOverview.reports | String |  | 
| CrowdStrike.AnalysisOverview.whitelisted | Boolean |  | 
| CrowdStrike.AnalysisOverview.children_in_queue | Number |  | 
| CrowdStrike.AnalysisOverview.children_in_progress | Number |  | 
| File.Size | number |  | 
| File.SHA256 | string |  | 
| File.Name | string |  | 
| File.Type | string |  | 

#### Command example
```!cs-falcon-sandbox-analysis-overview file=8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51```
#### Context Example
```json
{
    "CrowdStrike": {
        "AnalysisOverview": {
            "analysis_start_time": "2022-01-10T08:33:11+00:00",
            "architecture": "WINDOWS",
            "children_in_progress": 0,
            "children_in_queue": 0,
            "last_file_name": "file",
            "last_multi_scan": "2022-01-25T14:15:07+00:00",
            "multiscan_result": 0,
            "other_file_name": [
                "5_Journals_3_Manuscripts_10_Version_1_Revision_0_CoverLetter.pdf",
                "dyUQ2JAbImyU0WNH7TI1K3UYqUwDMsQBh1RwXWHG.pdf",
                "k18zpzsrq3om4q1pu18mftdo2caaivqq.pdf",
                "kuc86odvmimp0vd0tseubdekn9dg41jrff6lso01_parsed.eml",
                "sample.pdf",
                "samplePdf.pdf",
                "test.pdf"
            ],
            "related_children_hashes": [],
            "related_parent_hashes": [
                "77fbcad0cfe9e67946c0f9366d04df5ecf78c122ccceb78cb59c149911e3457d",
                "30c37bbb86c6937256ae67be4d6311cb1a9d9d041966b282378b83eb213ae5ab",
                "36327ca7afc02b525bc33428ab762419cdf3f93c8892de1df50bdb4b803032fb"
            ],
            "related_reports": [
                {
                    "environment_id": 100,
                    "error_origin": null,
                    "error_type": null,
                    "job_id": "5c5e1ea27ca3e12f285dc6b4",
                    "sha256": "30c37bbb86c6937256ae67be4d6311cb1a9d9d041966b282378b83eb213ae5ab",
                    "state": "SUCCESS",
                    "verdict": "no verdict"
                },
                {
                    "environment_id": 100,
                    "error_origin": null,
                    "error_type": null,
                    "job_id": "5f0c9b7eac8ef74e754f871e",
                    "sha256": "36327ca7afc02b525bc33428ab762419cdf3f93c8892de1df50bdb4b803032fb",
                    "state": "SUCCESS",
                    "verdict": "no verdict"
                },
                {
                    "environment_id": 100,
                    "error_origin": null,
                    "error_type": null,
                    "job_id": "5b881e5e7ca3e169b9340464",
                    "sha256": "77fbcad0cfe9e67946c0f9366d04df5ecf78c122ccceb78cb59c149911e3457d",
                    "state": "SUCCESS",
                    "verdict": "no verdict"
                }
            ],
            "reports": [
                "5e95b682dd8c5642500399ce",
                "5d8a1c67038838c50e69e5a8",
                "5a6896886e3579ce99a80d4d",
                "5f60f00aeac13102de2fce70",
                "61ae29f24e69ff77d566ab48",
                "5beb78777ca3e14af2036b03",
                "61128689373f22669b654e8a",
                "61a79f9a99b51b0fda1c1c4c",
                "61dbe275436d0a13692564b8",
                "61dbef47c143326cec7c2d3d"
            ],
            "scanners": [
                {
                    "anti_virus_results": [
                        {
                            "name": "CrowdStrike",
                            "result": false,
                            "threat_found": null
                        }
                    ],
                    "error_message": null,
                    "name": "CrowdStrike Falcon Static Analysis (ML)",
                    "percent": 0,
                    "positives": null,
                    "progress": 100,
                    "status": "clean",
                    "total": null
                },
                {
                    "anti_virus_results": [
                        {
                            "name": "ByteHero",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "AegisLab",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Trend Micro HouseCall",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Vir.IT eXplorer",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "K7",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Kaspersky",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "AhnLab",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Quick Heal",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "RocketCyber",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Comodo",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "IKARUS",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Symantec",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Huorong",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Bitdefender",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Avira",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Zillya!",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Sophos",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "VirusBlokAda",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "McAfee",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Cyren",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "TACHYON",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Antiy",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Xvirus Anti-Malware",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Trend Micro",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "Emsisoft",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "NANOAV",
                            "result": false,
                            "threat_found": null
                        },
                        {
                            "name": "ESET",
                            "result": false,
                            "threat_found": null
                        }
                    ],
                    "error_message": null,
                    "name": "Metadefender",
                    "percent": 0,
                    "positives": 0,
                    "progress": 100,
                    "status": "clean",
                    "total": 27
                },
                {
                    "anti_virus_results": [],
                    "error_message": null,
                    "name": "VirusTotal",
                    "percent": 0,
                    "positives": 0,
                    "progress": 100,
                    "status": "clean",
                    "total": 59
                }
            ],
            "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
            "size": 3506,
            "submit_context": [],
            "tags": [],
            "threat_score": null,
            "type": "PDF document, version 1.3",
            "type_short": [
                "pdf"
            ],
            "url_analysis": false,
            "verdict": "whitelisted",
            "whitelisted": true
        }
    },
    "File": {
        "Name": "file",
        "SHA256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
        "Size": 3506,
        "Type": "PDF document, version 1.3"
    }
}
```

#### Human Readable Output

>### Analysis Overview:
>|Last File Name|Other File Name|Sha 256|Verdict|Url Analysis|Size|Type|Type Short|
>|---|---|---|---|---|---|---|---|
>| file | 5_Journals_3_Manuscripts_10_Version_1_Revision_0_CoverLetter.pdf,<br/>dyUQ2JAbImyU0WNH7TI1K3UYqUwDMsQBh1RwXWHG.pdf,<br/>k18zpzsrq3om4q1pu18mftdo2caaivqq.pdf,<br/>kuc86odvmimp0vd0tseubdekn9dg41jrff6lso01_parsed.eml,<br/>sample.pdf,<br/>samplePdf.pdf,<br/>test.pdf | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 | whitelisted | false | 3506 | PDF document, version 1.3 | pdf |


### cs-falcon-sandbox-analysis-overview-summary
***
Returns the hash overview.


#### Base Command

`cs-falcon-sandbox-analysis-overview-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The SHA256 hash of the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.AnalysisOverviewSummary.sha256 | String | The SHA256 hash of the file. | 
| CrowdStrike.AnalysisOverviewSummary.threat_score | Number | The file threat score. | 
| CrowdStrike.AnalysisOverviewSummary.verdict | String | The file verdict. | 
| CrowdStrike.AnalysisOverviewSummary.analysis_start_time | Date |  | 
| CrowdStrike.AnalysisOverviewSummary.last_multi_scan | Date |  | 
| CrowdStrike.AnalysisOverviewSummary.multiscan_result | Number |  | 

#### Command example
```!cs-falcon-sandbox-analysis-overview-summary file=8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51```
#### Context Example
```json
{
    "CrowdStrike": {
        "AnalysisOverview": {
            "analysis_start_time": "2022-01-10T08:33:11+00:00",
            "last_multi_scan": "2022-01-25T14:15:07+00:00",
            "multiscan_result": 0,
            "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
            "threat_score": null,
            "verdict": "whitelisted"
        }
    }
}
```

#### Human Readable Output

>### Analysis Overview Summary:
>|Analysis Start Time|Last Multi Scan|Multiscan Result|Sha256|Verdict|
>|---|---|---|---|---|
>| 2022-01-10T08:33:11+00:00 | 2022-01-25T14:15:07+00:00 | 0 | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 | whitelisted |


### cs-falcon-sandbox-analysis-overview-refresh
***
Refreshes the overview and downloads fresh data from external services.


#### Base Command

`cs-falcon-sandbox-analysis-overview-refresh`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The SHA256 hash of the file. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cs-falcon-sandbox-analysis-overview-refresh file=8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51```
#### Human Readable Output

>The request to refresh the analysis overview was sent successfully.

### file
***
Returns file information and reputation.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A comma-separated list of file hashes (MD5, SHA1, or SHA256). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Report.job_id | String | The file job ID. | 
| CrowdStrike.Report.environment_id | Number | The report environment ID. | 
| CrowdStrike.Report.environment_description | String |  | 
| CrowdStrike.Report.size | Number | The file size. | 
| CrowdStrike.Report.type | String | The file type. | 
| CrowdStrike.Report.type_short | String |  | 
| CrowdStrike.Report.target_url | String |  | 
| CrowdStrike.Report.state | String | The report state. | 
| CrowdStrike.Report.error_type | String |  | 
| CrowdStrike.Report.error_origin | String |  | 
| CrowdStrike.Report.submit_name | String | The file name when submitted. | 
| CrowdStrike.Report.md5 | String | The MD5 hash of the file. | 
| CrowdStrike.Report.sha1 | String | The SHA1 hash of the file. | 
| CrowdStrike.Report.sha256 | String | The SHA256 hash of the file. | 
| CrowdStrike.Report.sha512 | String | The SHA512 hash of the file. | 
| CrowdStrike.Report.ssdeep | String | The SSDeep hash of the file. | 
| CrowdStrike.Report.imphash | String | The imphash hash of the file. | 
| CrowdStrike.Report.av_detect | Number | The AV Multiscan range, for example 50-70 \(min 0, max 100\). | 
| CrowdStrike.Report.vx_family | String | The file malware family. | 
| CrowdStrike.Report.url_analysis | Boolean |  | 
| CrowdStrike.Report.analysis_start_time | Date |  | 
| CrowdStrike.Report.threat_score | Number | The file threat score. | 
| CrowdStrike.Report.interesting | Boolean | Whether the file was found to be interesting. | 
| CrowdStrike.Report.threat_level | Number | The file threat level. | 
| CrowdStrike.Report.verdict | String | The file verdict. | 
| CrowdStrike.Report.total_network_connections | Number |  | 
| CrowdStrike.Report.total_processes | Number |  | 
| CrowdStrike.Report.total_signatures | Number |  | 
| CrowdStrike.Report.file_metadata | Object | The file metadata. | 
| CrowdStrike.Report.submissions.submission_id | String | The submission ID. | 
| CrowdStrike.Report.submissions.filename | String |  | 
| CrowdStrike.Report.submissions.url | String |  | 
| CrowdStrike.Report.submissions.created_at | Date |  | 
| CrowdStrike.Report.network_mode | String |  | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.Name | string | The file submission name. | 
| File.MalwareFamily | string | The file family classification. | 
| File.Malicious.Vendor | string | The vendor that decided the file was malicious. | 
| File.Malicious.Description | string | The reason the vendor decided the file was malicious. | 
| DBotScore.Indicator | string | The tested indicator. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 

#### Command example
```!file file=8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51```
#### Context Example
```json
{
    "CrowdStrike": {
        "Report": [
            {
                "analysis_start_time": "2020-09-15T16:47:06+00:00",
                "av_detect": 0,
                "certificates": [],
                "classification_tags": [],
                "compromised_hosts": [],
                "domains": [],
                "environment_description": "Static Analysis",
                "environment_id": null,
                "error_origin": null,
                "error_type": null,
                "extracted_files": [],
                "file_metadata": null,
                "hosts": [],
                "imphash": null,
                "interesting": false,
                "job_id": null,
                "machine_learning_models": [],
                "md5": "4b41a3475132bd861b30a878e30aa56a",
                "mitre_attcks": [],
                "network_mode": "default",
                "processes": [],
                "sha1": "bfd009f500c057195ffde66fae64f92fa5f59b72",
                "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
                "sha512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
                "size": 3028,
                "ssdeep": null,
                "state": "SUCCESS",
                "submissions": [
                    {
                        "created_at": "2021-12-30T09:34:22+00:00",
                        "filename": "file",
                        "submission_id": "61cd7d1ec35ca563e343e855",
                        "url": null
                    },
                    {
                        "created_at": "2021-12-18T23:47:33+00:00",
                        "filename": "file",
                        "submission_id": "61be731519ff990144369a85",
                        "url": null
                    },
                    {
                        "created_at": "2021-07-03T21:54:07+00:00",
                        "filename": "test.pdf",
                        "submission_id": "60e0dc7fda855364ee0d1826",
                        "url": null
                    },
                    {
                        "created_at": "2021-07-03T21:46:41+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "60e0dac12daa5049bb51ad72",
                        "url": null
                    },
                    {
                        "created_at": "2021-07-03T21:45:44+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "60e0da887bb12112723c8bea",
                        "url": null
                    },
                    {
                        "created_at": "2021-04-25T05:03:31+00:00",
                        "filename": "file",
                        "submission_id": "6084f823ea742a4783209d12",
                        "url": null
                    },
                    {
                        "created_at": "2021-03-01T14:42:05+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "603cfd3d601d615839160474",
                        "url": "http://www.africau.edu/images/default/sample.pdf"
                    },
                    {
                        "created_at": "2021-01-24T05:00:32+00:00",
                        "filename": "file",
                        "submission_id": "600cfef0f365f820bf2f0b02",
                        "url": null
                    },
                    {
                        "created_at": "2020-12-08T18:15:16+00:00",
                        "filename": "5_Journals_3_Manuscripts_10_Version_1_Revision_0_CoverLetter.pdf",
                        "submission_id": "5fcfc2b4fe643e3bee4bf4f5",
                        "url": null
                    },
                    {
                        "created_at": "2020-09-15T16:47:06+00:00",
                        "filename": "file",
                        "submission_id": "5f60f00abbe4e913f73cfff9",
                        "url": null
                    }
                ],
                "submit_name": "file",
                "tags": [],
                "target_url": null,
                "threat_level": 0,
                "threat_score": null,
                "total_network_connections": 0,
                "total_processes": 0,
                "total_signatures": 0,
                "type": "PDF document, version 1.3",
                "type_short": [
                    "pdf"
                ],
                "url_analysis": false,
                "verdict": "whitelisted",
                "vx_family": null
            },
            {
                "analysis_start_time": "2021-12-06T15:19:23+00:00",
                "av_detect": 0,
                "certificates": [],
                "classification_tags": [],
                "compromised_hosts": [],
                "domains": [],
                "environment_description": "Android Static Analysis",
                "environment_id": 200,
                "error_origin": null,
                "error_type": null,
                "extracted_files": [],
                "file_metadata": null,
                "hosts": [],
                "imphash": "Unknown",
                "interesting": false,
                "job_id": "61ae29f24e69ff77d566ab48",
                "machine_learning_models": [],
                "md5": "4b41a3475132bd861b30a878e30aa56a",
                "mitre_attcks": [],
                "network_mode": "default",
                "processes": [],
                "sha1": "bfd009f500c057195ffde66fae64f92fa5f59b72",
                "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
                "sha512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
                "size": 3506,
                "ssdeep": "24:yPp9AA+I3ZpAIZpAL7xMk2uFVBX02ScAjfW2sX25cfW2SJI2k2y62NOfW2t9HZdF:yrQ+YIYbrXq/jeyjbvzGUsnTd3/i",
                "state": "SUCCESS",
                "submissions": [
                    {
                        "created_at": "2022-01-10T08:40:44+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "61dbf10c213fbc5a3914cdd1",
                        "url": null
                    },
                    {
                        "created_at": "2022-01-10T08:35:47+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "61dbefe33f8cec40d619833c",
                        "url": null
                    },
                    {
                        "created_at": "2021-12-06T15:52:44+00:00",
                        "filename": "samplePdf.pdf",
                        "submission_id": "61ae31cce601bf0d4a332f82",
                        "url": null
                    },
                    {
                        "created_at": "2021-12-06T15:19:14+00:00",
                        "filename": "samplePdf.pdf",
                        "submission_id": "61ae29f24e69ff77d566ab49",
                        "url": null
                    }
                ],
                "submit_name": "samplePdf.pdf",
                "tags": [],
                "target_url": null,
                "threat_level": 0,
                "threat_score": null,
                "total_network_connections": 0,
                "total_processes": 0,
                "total_signatures": 1,
                "type": "PDF document, version 1.3",
                "type_short": [
                    "pdf"
                ],
                "url_analysis": false,
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2020-04-14T13:11:37+00:00",
                "av_detect": 0,
                "certificates": [],
                "classification_tags": [],
                "compromised_hosts": [],
                "domains": [],
                "environment_description": "Windows 7 32 bit (HWP Support)",
                "environment_id": 110,
                "error_origin": null,
                "error_type": null,
                "extracted_files": [],
                "file_metadata": null,
                "hosts": [],
                "imphash": "Unknown",
                "interesting": false,
                "job_id": "5e95b682dd8c5642500399ce",
                "machine_learning_models": [],
                "md5": "4b41a3475132bd861b30a878e30aa56a",
                "mitre_attcks": [],
                "network_mode": "default",
                "processes": [],
                "sha1": "bfd009f500c057195ffde66fae64f92fa5f59b72",
                "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
                "sha512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
                "size": 3506,
                "ssdeep": "24:yPp9AA+I3ZpAIZpAL7xMk2uFVBX02ScAjfW2sX25cfW2SJI2k2y62NOfW2t9HZdt:yrQ+YIYbrXq/jeyjbvzGUsnTd3/C",
                "state": "SUCCESS",
                "submissions": [
                    {
                        "created_at": "2020-04-14T13:11:30+00:00",
                        "filename": "file",
                        "submission_id": "5e95b682dd8c5642500399cf",
                        "url": null
                    }
                ],
                "submit_name": "file",
                "tags": [],
                "target_url": null,
                "threat_level": 0,
                "threat_score": null,
                "total_network_connections": 0,
                "total_processes": 4,
                "total_signatures": 14,
                "type": "PDF document, version 1.3",
                "type_short": [
                    "pdf"
                ],
                "url_analysis": false,
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-09-24T13:39:34+00:00",
                "av_detect": 0,
                "certificates": [],
                "classification_tags": [],
                "compromised_hosts": [],
                "domains": [],
                "environment_description": "Windows 7 64 bit",
                "environment_id": 120,
                "error_origin": null,
                "error_type": null,
                "extracted_files": [],
                "file_metadata": null,
                "hosts": [],
                "imphash": "Unknown",
                "interesting": false,
                "job_id": "5d8a1c67038838c50e69e5a8",
                "machine_learning_models": [],
                "md5": "4b41a3475132bd861b30a878e30aa56a",
                "mitre_attcks": [],
                "network_mode": "default",
                "processes": [],
                "sha1": "bfd009f500c057195ffde66fae64f92fa5f59b72",
                "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
                "sha512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
                "size": 3506,
                "ssdeep": "24:yPp9AA+I3ZpAIZpAL7xMk2uFVBX02ScAjfW2sX25cfW2SJI2k2y62NOfW2t9HZdd:yrQ+YIYbrXq/jeyjbvzGUsnTd3/hxoxn",
                "state": "SUCCESS",
                "submissions": [
                    {
                        "created_at": "2020-12-17T11:38:35+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5fdb433be6562860c47942cf",
                        "url": null
                    },
                    {
                        "created_at": "2020-12-09T12:12:29+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5fd0bf2d8623f5298734d606",
                        "url": null
                    },
                    {
                        "created_at": "2020-05-26T07:00:18+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5eccbe8203b9557fac384586",
                        "url": null
                    },
                    {
                        "created_at": "2020-04-29T09:51:17+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5ea94e157d7c876d9c76ced3",
                        "url": null
                    },
                    {
                        "created_at": "2020-04-29T09:15:42+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5ea945be351cb361215586fe",
                        "url": null
                    },
                    {
                        "created_at": "2020-04-29T09:11:43+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5ea944cfe3893c0eb22505a3",
                        "url": null
                    },
                    {
                        "created_at": "2020-01-10T00:04:51+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5e17bfa39f797e0f87507547",
                        "url": null
                    },
                    {
                        "created_at": "2019-09-24T13:38:47+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5d8a1c67038838c50e69e5a7",
                        "url": null
                    }
                ],
                "submit_name": "sample.pdf",
                "tags": [],
                "target_url": null,
                "threat_level": 0,
                "threat_score": null,
                "total_network_connections": 0,
                "total_processes": 4,
                "total_signatures": 12,
                "type": "PDF document, version 1.3",
                "type_short": [
                    "pdf"
                ],
                "url_analysis": false,
                "verdict": "no specific threat",
                "vx_family": null
            },
            {
                "analysis_start_time": "2019-02-09T01:41:57+00:00",
                "av_detect": 0,
                "certificates": [],
                "classification_tags": [],
                "compromised_hosts": [],
                "domains": [],
                "environment_description": "Windows 7 32 bit",
                "environment_id": 100,
                "error_origin": null,
                "error_type": null,
                "extracted_files": [],
                "file_metadata": null,
                "hosts": [],
                "imphash": "Unknown",
                "interesting": false,
                "job_id": "5a6896886e3579ce99a80d4d",
                "machine_learning_models": [],
                "md5": "4b41a3475132bd861b30a878e30aa56a",
                "mitre_attcks": [],
                "network_mode": "tor",
                "processes": [],
                "sha1": "bfd009f500c057195ffde66fae64f92fa5f59b72",
                "sha256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
                "sha512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
                "size": 3506,
                "ssdeep": "24:yPp9AA+I3ZpAIZpAL7xMk2uFVBX02ScAjfW2sX25cfW2SJI2k2y62NOfW2t9HZdV:yrQ+YIYbrXq/jeyjbvzGUsnTd3/S",
                "state": "SUCCESS",
                "submissions": [
                    {
                        "created_at": "2022-01-23T17:49:11+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "61ed9517c284dd61265a0e6d",
                        "url": null
                    },
                    {
                        "created_at": "2022-01-09T16:03:26+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "61db074e8782ed13a058f7a4",
                        "url": null
                    },
                    {
                        "created_at": "2022-01-09T16:03:04+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "61db0738f93ee5253c369e74",
                        "url": null
                    },
                    {
                        "created_at": "2021-12-06T14:31:12+00:00",
                        "filename": "samplePdf.pdf",
                        "submission_id": "61ae1eb03be82d62c3775f70",
                        "url": null
                    },
                    {
                        "created_at": "2021-10-20T13:49:19+00:00",
                        "filename": "k18zpzsrq3om4q1pu18mftdo2caaivqq.pdf",
                        "submission_id": "61701e5f1c027f4e08299b54",
                        "url": null
                    },
                    {
                        "created_at": "2021-07-27T13:27:58+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "610009dec612587a6d572e23",
                        "url": null
                    },
                    {
                        "created_at": "2021-07-15T16:15:50+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "60f05f3660f4fd4ee42d0b6f",
                        "url": null
                    },
                    {
                        "created_at": "2021-07-03T21:50:01+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "60e0db8928bccc0b2e405d30",
                        "url": null
                    },
                    {
                        "created_at": "2021-03-01T14:43:08+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "603cfd7c60343f6d115db9f8",
                        "url": "http://www.africau.edu/images/default/sample.pdf"
                    },
                    {
                        "created_at": "2020-10-29T13:17:49+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f9ac0fdd97ff17aac38bc84",
                        "url": "http://www.africau.edu/images/default/sample.pdf"
                    },
                    {
                        "created_at": "2020-07-14T13:09:08+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f0dae74c122fb57fc3f360b",
                        "url": null
                    },
                    {
                        "created_at": "2020-07-14T10:54:02+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f0d8eca91837459ca5cee1c",
                        "url": null
                    },
                    {
                        "created_at": "2020-07-14T10:48:02+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f0d8d622560cc30d825588b",
                        "url": null
                    },
                    {
                        "created_at": "2020-07-13T17:48:02+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f0c9e52f6150a35a72b8c99",
                        "url": null
                    },
                    {
                        "created_at": "2020-07-13T17:38:12+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f0c9c040030d423b83a9991",
                        "url": null
                    },
                    {
                        "created_at": "2020-07-13T17:35:58+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5f0c9b7eac8ef74e754f8724",
                        "url": null
                    },
                    {
                        "created_at": "2019-04-11T15:08:01+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5caf58510388385b8b7b23ca",
                        "url": null
                    },
                    {
                        "created_at": "2019-03-10T11:11:01+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5c84f0c5028838b82ffc1ce3",
                        "url": null
                    },
                    {
                        "created_at": "2019-03-10T08:53:28+00:00",
                        "filename": "sample.pdf",
                        "submission_id": "5c84d088028838950cfc1ce4",
                        "url": null
                    },
                    {
                        "created_at": "2019-02-08T18:28:18-06:00",
                        "filename": "sample.pdf",
                        "submission_id": "5c5e1ea27ca3e12cd80ecf07",
                        "url": null
                    }
                ],
                "submit_name": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51_1549672910345_sample.pdf",
                "tags": [],
                "target_url": null,
                "threat_level": 0,
                "threat_score": null,
                "total_network_connections": 0,
                "total_processes": 1,
                "total_signatures": 9,
                "type": "PDF document, version 1.3",
                "type_short": [
                    "pdf"
                ],
                "url_analysis": false,
                "verdict": "whitelisted",
                "vx_family": null
            }
        ]
    },
    "DBotScore": {
        "Indicator": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
        "Reliability": "A - Completely reliable",
        "Score": 1,
        "Type": "file",
        "Vendor": "CrowdStrike Falcon Sandbox V2"
    },
    "File": {
        "JobID": "5a6896886e3579ce99a80d4d",
        "MD5": "4b41a3475132bd861b30a878e30aa56a",
        "Name": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51_1549672910345_sample.pdf",
        "SHA1": "bfd009f500c057195ffde66fae64f92fa5f59b72",
        "SHA256": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51",
        "SHA512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
        "SSDeep": "24:yPp9AA+I3ZpAIZpAL7xMk2uFVBX02ScAjfW2sX25cfW2SJI2k2y62NOfW2t9HZdV:yrQ+YIYbrXq/jeyjbvzGUsnTd3/S",
        "Size": 3506,
        "Type": "PDF document, version 1.3",
        "analysis_start_time": "2019-02-09T01:41:57+00:00",
        "av_detect": 0,
        "certificates": [],
        "classification_tags": [],
        "compromised_hosts": [],
        "domains": [],
        "environmentDescription": "Windows 7 32 bit",
        "environmentId": 100,
        "error_origin": null,
        "error_type": null,
        "extracted_files": [],
        "family": null,
        "file_metadata": null,
        "hosts": [],
        "imphash": "Unknown",
        "interesting": false,
        "isurlanalysis": false,
        "machine_learning_models": [],
        "mitre_attcks": [],
        "network_mode": "tor",
        "processes": [],
        "sha512": "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
        "size": 3506,
        "ssdeep": "24:yPp9AA+I3ZpAIZpAL7xMk2uFVBX02ScAjfW2sX25cfW2SJI2k2y62NOfW2t9HZdV:yrQ+YIYbrXq/jeyjbvzGUsnTd3/S",
        "state": "SUCCESS",
        "submissions": [
            {
                "created_at": "2022-01-23T17:49:11+00:00",
                "filename": "sample.pdf",
                "submission_id": "61ed9517c284dd61265a0e6d",
                "url": null
            },
            {
                "created_at": "2022-01-09T16:03:26+00:00",
                "filename": "sample.pdf",
                "submission_id": "61db074e8782ed13a058f7a4",
                "url": null
            },
            {
                "created_at": "2022-01-09T16:03:04+00:00",
                "filename": "sample.pdf",
                "submission_id": "61db0738f93ee5253c369e74",
                "url": null
            },
            {
                "created_at": "2021-12-06T14:31:12+00:00",
                "filename": "samplePdf.pdf",
                "submission_id": "61ae1eb03be82d62c3775f70",
                "url": null
            },
            {
                "created_at": "2021-10-20T13:49:19+00:00",
                "filename": "k18zpzsrq3om4q1pu18mftdo2caaivqq.pdf",
                "submission_id": "61701e5f1c027f4e08299b54",
                "url": null
            },
            {
                "created_at": "2021-07-27T13:27:58+00:00",
                "filename": "sample.pdf",
                "submission_id": "610009dec612587a6d572e23",
                "url": null
            },
            {
                "created_at": "2021-07-15T16:15:50+00:00",
                "filename": "sample.pdf",
                "submission_id": "60f05f3660f4fd4ee42d0b6f",
                "url": null
            },
            {
                "created_at": "2021-07-03T21:50:01+00:00",
                "filename": "sample.pdf",
                "submission_id": "60e0db8928bccc0b2e405d30",
                "url": null
            },
            {
                "created_at": "2021-03-01T14:43:08+00:00",
                "filename": "sample.pdf",
                "submission_id": "603cfd7c60343f6d115db9f8",
                "url": "http://www.africau.edu/images/default/sample.pdf"
            },
            {
                "created_at": "2020-10-29T13:17:49+00:00",
                "filename": "sample.pdf",
                "submission_id": "5f9ac0fdd97ff17aac38bc84",
                "url": "http://www.africau.edu/images/default/sample.pdf"
            },
            {
                "created_at": "2020-07-14T13:09:08+00:00",
                "filename": "sample.pdf",
                "submission_id": "5f0dae74c122fb57fc3f360b",
                "url": null
            },
            {
                "created_at": "2020-07-14T10:54:02+00:00",
                "filename": "sample.pdf",
                "submission_id": "5f0d8eca91837459ca5cee1c",
                "url": null
            },
            {
                "created_at": "2020-07-14T10:48:02+00:00",
                "filename": "sample.pdf",
                "submission_id": "5f0d8d622560cc30d825588b",
                "url": null
            },
            {
                "created_at": "2020-07-13T17:48:02+00:00",
                "filename": "sample.pdf",
                "submission_id": "5f0c9e52f6150a35a72b8c99",
                "url": null
            },
            {
                "created_at": "2020-07-13T17:38:12+00:00",
                "filename": "sample.pdf",
                "submission_id": "5f0c9c040030d423b83a9991",
                "url": null
            },
            {
                "created_at": "2020-07-13T17:35:58+00:00",
                "filename": "sample.pdf",
                "submission_id": "5f0c9b7eac8ef74e754f8724",
                "url": null
            },
            {
                "created_at": "2019-04-11T15:08:01+00:00",
                "filename": "sample.pdf",
                "submission_id": "5caf58510388385b8b7b23ca",
                "url": null
            },
            {
                "created_at": "2019-03-10T11:11:01+00:00",
                "filename": "sample.pdf",
                "submission_id": "5c84f0c5028838b82ffc1ce3",
                "url": null
            },
            {
                "created_at": "2019-03-10T08:53:28+00:00",
                "filename": "sample.pdf",
                "submission_id": "5c84d088028838950cfc1ce4",
                "url": null
            },
            {
                "created_at": "2019-02-08T18:28:18-06:00",
                "filename": "sample.pdf",
                "submission_id": "5c5e1ea27ca3e12cd80ecf07",
                "url": null
            }
        ],
        "submitname": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51_1549672910345_sample.pdf",
        "tags": [],
        "target_url": null,
        "threat_level": 0,
        "threatscore": null,
        "total_network_connections": 0,
        "total_processes": 1,
        "total_signatures": 9,
        "type": "PDF document, version 1.3",
        "type_short": [
            "pdf"
        ],
        "verdict": "whitelisted"
    }
}
```

#### Human Readable Output

>### Scan Results:
>|submit name|threat level|verdict|total network connections|total processes|environment description|interesting|environment id|url analysis|analysis start time|total signatures|type|type short|sha256|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| file | 0 | whitelisted | 0 | 0 | Static Analysis | false |  | false | 2020-09-15T16:47:06+00:00 | 0 | PDF document, version 1.3 | pdf | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 |
>| samplePdf.pdf | 0 | no specific threat | 0 | 0 | Android Static Analysis | false | 200 | false | 2021-12-06T15:19:23+00:00 | 1 | PDF document, version 1.3 | pdf | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 |
>| file | 0 | no specific threat | 0 | 4 | Windows 7 32 bit (HWP Support) | false | 110 | false | 2020-04-14T13:11:37+00:00 | 14 | PDF document, version 1.3 | pdf | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 |
>| sample.pdf | 0 | no specific threat | 0 | 4 | Windows 7 64 bit | false | 120 | false | 2019-09-24T13:39:34+00:00 | 12 | PDF document, version 1.3 | pdf | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 |
>| 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51_1549672910345_sample.pdf | 0 | whitelisted | 0 | 1 | Windows 7 32 bit | false | 100 | false | 2019-02-09T01:41:57+00:00 | 9 | PDF document, version 1.3 | pdf | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 |


### cs-falcon-sandbox-sample-download
***
Downloads the sample file.


#### Base Command

`cs-falcon-sandbox-sample-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The SHA256 hash of the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The file entry ID. | 
| File.Info | String | Information about the file. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 

#### Command example
```!cs-falcon-sandbox-sample-download file=8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51```
#### Context Example
```json
{
    "File": {
        "EntryID": "321@f80880ff-f5c9-4e8f-843b-3fcfb6f8c1c6",
        "Extension": "gz",
        "Info": "gz",
        "MD5": "227f491cfca844bc56127216c956c59a",
        "Name": "8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51.bin.sample.gz",
        "SHA1": "cc71f378f875b1daa6c462195301ddb8025d0d2f",
        "SHA256": "1801097bfc747e5fab03e194a79c88e665b14f7510950d6702f27096ca41b85d",
        "SHA512": "22464de2b59147cae9f7289308dd5a0e54686840c0a13032173705a280d1918c2aa40b6406dc756b8145ba2c3cea2abb3f5dca93e2ba3b7f8be2704419d12e9b",
        "SSDeep": "24:Xv2b+nAJehSZ/KNNtZHUXXj1xJq34VWwA2uMQi87JTSvE3gt:Xw+IeYENN3cZxJO4V31HQi87cvE3gt",
        "Size": 945,
        "Type": "gzip compressed data, max compression, from Unix, original size 3028"
    }
}
```

#### Human Readable Output

>Requested sample is available for download under the name 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51.bin.sample.gz

### cs-falcon-sandbox-report-state
***
Gets the report state for the given ID.


#### Base Command

`cs-falcon-sandbox-report-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| JobID | The file job ID. | Optional | 
| environmentID | The environment ID. Available environment IDs: 300: "Linux (Ubuntu 16.04, 64 bit)"", 200: "Android Static Analysis", 120: "Windows 7 64 bit", 110: "Windows 7 32 bit (HWP Support)", 100: "Windows 7 32 bit". Possible values are: 100, 110, 120, 200, 300. | Optional | 
| file | The hash of the file. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.State.state | String |  | 
| CrowdStrike.State.error_type | String |  | 
| CrowdStrike.State.error_origin | String |  | 
| CrowdStrike.State.error | String |  | 

#### Command example
```!cs-falcon-sandbox-report-state file=8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 environmentID=300```
#### Context Example
```json
{
    "CrowdStrike": {
        "State": {
            "error": "The requested environment ID \"300\" and file type \"pdf\" have no available execution environment",
            "error_origin": "CLIENT",
            "error_type": "FILE_TYPE_BAD_ERROR",
            "related_reports": [],
            "state": "ERROR"
        }
    }
}
```

#### Human Readable Output

>### State
>|Error|Error Origin|Error Type|Related Reports|State|
>|---|---|---|---|---|
>| The requested environment ID "300" and file type "pdf" have no available execution environment | CLIENT | FILE_TYPE_BAD_ERROR |  | ERROR |
