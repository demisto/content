Upload files using polling, the service supports Microsoft Office files, as well as PDF, SWF, archives and executables. Active content will be cleaned from any documents that you upload (Microsoft Office and PDF files only). Query on existing IOCs, file status, analysis, reports. Download files from the database. Supports both appliance and cloud. Supported Threat Emulation versions are any R80x.
This integration was integrated and tested with version v1 of check_point_threat_emulation_(sand_blast)

## Configure Check Point Threat Emulation (SandBlast) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Check Point Threat Emulation (SandBlast).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | https://te.checkpoint.com | True |
    | Authorization - API Key |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sandblast-query
***
Use the Query API to have a client application look for either the analysis report of a specific file on the Check Point Threat Prevention service databases or the status of a file, uploaded for analysis. It is recommended to add file_name.


#### Base Command

`sandblast-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_name | Name of the file to query. Recommended to use, without it status will be "PARTIALLY_FOUND". | Optional | 
| file_hash | File hash to query, accepted digests are: md5, sha1 and sha256. Only md5 returns 'FOUND' status. | Required | 
| features | Features to use on the file. Possible values are: Threat Emulation, Anti-Virus, Threat Extraction, All. Default is All. | Optional | 
| reports | Comma separated list of supported report formats.Note - Requesting for PDF and summary reports simultaneously is not supported. Possible values are: pdf, xml, tar, summary. Default is xml, summary. | Optional | 
| method | Threat extraction request method. Possible values are: clean, pdf. Default is pdf. | Optional | 
| extracted_parts | Comma separated list of fields to be cleaned in the file. Only relevant if method = clean. Possible values are: Linked Objects, Macros and Code, Sensitive Hyperlinks, PDF GoToR Actions, PDF Launch Actions, PDF URI Actions, PDF Sound Actions, PDF Movie Actions, PDF JavaScript Actions, PDF Submit Form Actions, Database Queries, Embedded Objects, Fast Save Data, Custom Properties, Statistic Properties, Summary Properties. Default is Linked Objects, Macros and Code, Sensitive Hyperlinks, PDF GoToR Actions, PDF Launch Actions, PDF URI Actions, PDF Sound Actions, PDF Movie Actions, PDF JavaScript Actions, PDF Submit Form Actions, Database Queries, Embedded Objects, Fast Save Data. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SandBlast.Query.Status | String | Status of requested features. | 
| SandBlast.Query.MD5 | String | The file's MD5. | 
| SandBlast.Query.SHA1 | String | The file's SHA1. | 
| SandBlast.Query.SHA256 | String | The file's SHA256. | 
| SandBlast.Query.FileType | String | File type can be different from the one sent in the query request \(according to the type to identify\). | 
| SandBlast.Query.FileName | String | Name of the file saved on Check Point databases. | 
| SandBlast.Query.Features | String | Features used. | 
| SandBlast.Query.AntiVirus.SignatureName | String | If the file is not detected by Anti-Virus, the signature name is empty. | 
| SandBlast.Query.AntiVirus.MalwareFamily | Number | ID for malware family, if available: \{0-\}. | 
| SandBlast.Query.AntiVirus.MalwareType | Number | ID for malware type, if available: \{0-\}. | 
| SandBlast.Query.AntiVirus.Severity | Number | 0 for benign files. Minimum: 0 Maximum: 4 | 
| SandBlast.Query.AntiVirus.Confidence | Number | 0 for benign files. Minimum: 0 Maximum 5 | 
| SandBlast.Query.AntiVirus.Status | String | Status of Anti-Virus on the requested file. | 
| SandBlast.Query.ThreatExtraction.Method | String | Method that was used. | 
| SandBlast.Query.ThreatExtraction.ExtractResult | String | CP_EXTRACT_RESULT_UNKNOWN \(Default - returned if the POD did not receive an answer from the Threat Extraction engine in 60 seconds\). CP_EXTRACT_RESULT_SUCCESS, CP_EXTRACT_RESULT_FAILURE, CP_EXTRACT_RESULT_TIMEOUT, CP_EXTRACT_RESULT_UNSUPPORTED_FILE, CP_EXTRACT_RESULT_NOT_SCRUBBED, CP_EXTRACT_RESULT_INTERNAL_ERROR, CP_EXTRACT_RESULT_DISK_LIMIT_REACHED, CP_EXTRACT_RESULT_ENCRYPTED_FILE, CP_EXTRACT_RESULT_DOCSEC_FILE, CP_EXTRACT_RESULT_OUT_OF_MEMORY | 
| SandBlast.Query.ThreatExtraction.ExtractedFileDownloadId | String | The download id of the extracted file, for download request. Only sent when extract_result = CP_EXTRACT_RESULT_SUCCESS | 
| SandBlast.Query.ThreatExtraction.OutputFileName | String | Clean file name. | 
| SandBlast.Query.ThreatExtraction.Time | String | Time for threat extraction completion. | 
| SandBlast.Query.ThreatExtraction.ExtractContent | String | Content of extracted file. | 
| SandBlast.Query.ThreatExtraction.TexProduct | Boolean | True if the queried file is already a Sandblast-safe copy. | 
| SandBlast.Query.ThreatExtraction.Status | String | Status of Threat Extraction on the requested file. | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.InputExtension | String | Uploaded filename-extension as sent by the client. | 
| SandBlast.Query.ThreatExtraction.ExtractionData.InputRealExtension | String | Extension as resolved by Threat Extraction. | 
| SandBlast.Query.ThreatExtraction.ExtractionData.Message | String | Status message for scrub_result | 
| SandBlast.Query.ThreatExtraction.ExtractionData.ProtectionName | String | Potential malicious content extracted. | 
| SandBlast.Query.ThreatExtraction.ExtractionData.ProtectionType | String | Protection done for scrub_method: Conversion to PDF | Content Removal | 
| SandBlast.Query.ThreatExtraction.ExtractionData.ProtocolVersion | String | Protocol used. | 
| SandBlast.Query.ThreatExtraction.ExtractionData.RealExtension | String | Real extension as resolved by Threat Extraction | 
| SandBlast.Query.ThreatExtraction.ExtractionData.Risk | Number | Represents the risk of the part that was extracted from the document. | 
| SandBlast.Query.ThreatExtraction.ExtractionData.ScrubActivity | String | Readable result from Threat Extraction. | 
| SandBlast.Query.ThreatExtraction.ExtractionData.ScrubMethod | String | Convert to PDF | Clean Document. | 
| SandBlast.Query.ThreatExtraction.ExtractionData.ScrubResult | Number | Code result from Threat Extraction. | 
| SandBlast.Query.ThreatExtraction.ExtractionData.ScrubTime | String | Threat Extraction process time. | 
| SandBlast.Query.ThreatExtraction.ExtractionData.ScrubbedContent | String | Content that was removed | 
| SandBlast.Query.ThreatEmulation.Trust | Number | Rating of the threat data and its relevance to this instance. It is recommended to block threats with confidence medium and above. | 
| SandBlast.Query.ThreatEmulation.Score | Number | Threat Emulation score. | 
| SandBlast.Query.ThreatEmulation.CombinedVerdict | String | Combined verdict of all the images. Benign reports are not supported for local gateways. | 
| SandBlast.Query.ThreatEmulation.Severity | Number | Combined severity of threats found. In case threats are not found, this field is not given. | 
| SandBlast.Query.ThreatEmulation.Images | String | Sand boxes used in Threat Emulation. Information about image types can be found in https://sc1.checkpoint.com/documents/TPAPI/CP_1.0_ThreatPreventionAPI_APIRefGuide/html_frameset.htm under "Query API" -&gt; "Query Response Format" -&gt; "Images Object Format". | 
| SandBlast.Query.ThreatEmulation.Status | String | Status of Threat Emulation on the requested file. | 

#### Command example
```!sandblast-query file_hash=db7ad5b18e684bfbd114a133d446e464 file_name=HelloWorld.pdf```
#### Context Example
```json
{
    "SandBlast": {
        "Query": {
            "AntiVirus": {
                "Confidence": 0,
                "MalwareFamily": 0,
                "MalwareType": 0,
                "Severity": 0,
                "SignatureName": "",
                "Status": {
                    "code": 1001,
                    "label": "FOUND",
                    "message": "The request has been fully answered."
                }
            },
            "Features": [
                "te",
                "av",
                "extraction"
            ],
            "FileName": "HelloWorld.pdf",
            "FileType": "pdf",
            "MD5": "db7ad5b18e684bfbd114a133d446e464",
            "SHA1": "c5cecb9940dd5b796eec8ea2d7ea25841f00d087",
            "SHA256": "c8599c57b8e76d04ebec500de0870729b81240f7a7bba6315e03302e1c0524d4",
            "Status": {
                "code": 1001,
                "label": "FOUND",
                "message": "The request has been fully answered."
            },
            "ThreatEmulation": {
                "CombinedVerdict": "benign",
                "Images": [
                    {
                        "id": "e50e99f3-5963-4573-af9e-e3f4750b55e2",
                        "report": {
                            "verdict": "benign"
                        },
                        "revision": 1,
                        "status": "found"
                    },
                    {
                        "id": "3ff3ddae-e7fd-4969-818c-d5f1a2be336d",
                        "report": {
                            "verdict": "benign"
                        },
                        "revision": 1,
                        "status": "found"
                    }
                ],
                "Score": -2147483648,
                "Status": {
                    "code": 1001,
                    "label": "FOUND",
                    "message": "The request has been fully answered."
                },
                "Trust": 0
            },
            "ThreatExtraction": {
                "ExtractContent": "",
                "ExtractResult": "CP_EXTRACT_RESULT_SUCCESS",
                "ExtractedFileDownloadId": "d2aa35e1-7951-4e6c-a938-a5c78769267c",
                "ExtractionData": {
                    "InputExtension": "pdf",
                    "InputRealExtension": "pdf",
                    "Message": "OK",
                    "ProtectionName": "Extract potentially malicious content",
                    "ProtectionType": "Conversion to PDF",
                    "ProtocolVersion": "",
                    "RealExtension": "pdf",
                    "Risk": 0,
                    "ScrubActivity": "PDF file was converted to PDF",
                    "ScrubMethod": "Convert to PDF",
                    "ScrubResult": 0,
                    "ScrubTime": "0.542",
                    "ScrubbedContent": ""
                },
                "Method": "pdf",
                "OutputFileName": "HelloWorld.cleaned.pdf",
                "Status": {
                    "code": 1001,
                    "label": "FOUND",
                    "message": "The request has been fully answered."
                },
                "TexProduct": false,
                "Time": "0.542"
            }
        }
    }
}
```

#### Human Readable Output

>Query Results
>### File Info
>|Filename|Filetype|Label|Message|Md5|Sha1|Sha256|
>|---|---|---|---|---|---|---|
>| HelloWorld.pdf | pdf | FOUND | The request has been fully answered. | db7ad5b18e684bfbd114a133d446e464 | c5cecb9940dd5b796eec8ea2d7ea25841f00d087 | c8599c57b8e76d04ebec500de0870729b81240f7a7bba6315e03302e1c0524d4 |
>### Threat Emulation
>|Combinedverdict|
>|---|
>| benign |
>### Anti-Virus
>|Malwarefamily|Malwaretype|Confidence|Severity|
>|---|---|---|---|
>| 0 | 0 | 0 | 0 |
>### Threat Extraction
>|Extractresult|Extractedfiledownloadid|Risk|
>|---|---|---|
>| CP_EXTRACT_RESULT_SUCCESS | d2aa35e1-7951-4e6c-a938-a5c78769267c | 0 |


### sandblast-upload
***
Use the Upload API to have a client application request that Check Point Threat Prevention modules scan and analyze a file. When you upload a file to the service, the file is encrypted. It is un-encrypted during analysis, and then deleted. This command uses polling with query. The stages of polling are 'UPLOAD_SUCCESS', 'PENDING' and ends with 'FOUND' or 'PARTIALLY_FOUND'. Once the command is done polling it will return analyzed information about the file.


#### Base Command

`sandblast-upload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 
| timeout_in_seconds | Time out in seconds till polling ends. Default is 600. | Optional | 
| file_id | ID of the file to upload, which will be taken from the uploaded file to XSOAR. | Required | 
| file_name | Rename the file to upload, if empty the uploaded file will keep its original name. | Optional | 
| features | Features to use on the file. Possible values are: Threat Emulation, Anti-Virus, Threat Extraction, All. Default is All. | Optional | 
| image_ids | ID of available OS images. An image is an operating system configuration. Inputs must be of same length as image_revisions and will be paired according to position. Information about image types can be found in https://sc1.checkpoint.com/documents/TPAPI/CP_1.0_ThreatPreventionAPI_APIRefGuide/html_frameset.htm under "Query API" -&gt; "Query Response Format" -&gt; "Images Object Format". Possible values are: e50e99f3-5963-4573-af9e-e3f4750b55e2, 7e6fe36e-889e-4c25-8704-56378f0830df, 8d188031-1010-4466-828b-0cd13d4303ff, 5e5de275-a103-4f67-b55b-47532918fa59, 3ff3ddae-e7fd-4969-818c-d5f1a2be336d, 6c453c9b-20f7-471a-956c-3198a868dc92, 10b4a9c6-e414-425c-ae8b-fe4dd7b25244. | Optional | 
| image_revisions | Revisions of available OS images. An image is an operating system configuration. Inputs must be of same length as image_ids and will be paired according to position. | Optional | 
| reports | Comma separated list of supported report formats.Note - Requesting for PDF and summary reports simultaneously is not supported. Possible values are: pdf, xml, tar, summary. Default is xml, summary. | Optional | 
| method | Threat extraction request method. Possible values are: clean, pdf. Default is pdf. | Optional | 
| extracted_parts | Comma separated list of fields to be cleaned in the file. Only relevant if method = clean. Possible values are: Linked Objects, Macros and Code, Sensitive Hyperlinks, PDF GoToR Actions, PDF Launch Actions, PDF URI Actions, PDF Sound Actions, PDF Movie Actions, PDF JavaScript Actions, PDF Submit Form Actions, Database Queries, Embedded Objects, Fast Save Data, Custom Properties, Statistic Properties, Summary Properties. Default is Linked Objects, Macros and Code, Sensitive Hyperlinks, PDF GoToR Actions, PDF Launch Actions, PDF URI Actions, PDF Sound Actions, PDF Movie Actions, PDF JavaScript Actions, PDF Submit Form Actions, Database Queries, Embedded Objects, Fast Save Data. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SandBlast.Upload.Status | String | Status of requested features. | 
| SandBlast.Upload.MD5 | String | The file's MD5. | 
| SandBlast.Upload.SHA1 | String | The file's SHA1. | 
| SandBlast.Upload.SHA256 | String | The file's SHA256. | 
| SandBlast.Upload.FileType | String | File type can be different from the one sent in the upload request \(according to the type to identify\). | 
| SandBlast.Upload.FileName | String | Name of the file saved on Check Point databases. | 
| SandBlast.Upload.Features | String | Features used. | 
| SandBlast.Upload.AntiVirus.SignatureName | String | If the file is not detected by Anti-Virus, the signature name is empty. | 
| SandBlast.Upload.AntiVirus.MalwareFamily | Number | ID for malware family, if available: \{0-\}. | 
| SandBlast.Upload.AntiVirus.MalwareType | Number | ID for malware type, if available: \{0-\}. | 
| SandBlast.Upload.AntiVirus.Severity | Number | 0 for benign files. Minimum: 0 Maximum: 4 | 
| SandBlast.Upload.AntiVirus.Confidence | Number | 0 for benign files. Minimum: 0 Maximum 5 | 
| SandBlast.Upload.AntiVirus.Status | String | Status of Anti-Virus on the requested file. | 
| SandBlast.Upload.ThreatExtraction.Method | String | Method that was used. | 
| SandBlast.Upload.ThreatExtraction.ExtractResult | String | CP_EXTRACT_RESULT_UNKNOWN \(Default - returned if the POD did not receive an answer from the Threat Extraction engine in 60 seconds\). CP_EXTRACT_RESULT_SUCCESS, CP_EXTRACT_RESULT_FAILURE, CP_EXTRACT_RESULT_TIMEOUT, CP_EXTRACT_RESULT_UNSUPPORTED_FILE, CP_EXTRACT_RESULT_NOT_SCRUBBED, CP_EXTRACT_RESULT_INTERNAL_ERROR, CP_EXTRACT_RESULT_DISK_LIMIT_REACHED, CP_EXTRACT_RESULT_ENCRYPTED_FILE, CP_EXTRACT_RESULT_DOCSEC_FILE, CP_EXTRACT_RESULT_OUT_OF_MEMORY | 
| SandBlast.Upload.ThreatExtraction.ExtractedFileDownloadId | String | The download id of the extracted file, for download request. Only sent when extract_result = CP_EXTRACT_RESULT_SUCCESS | 
| SandBlast.Upload.ThreatExtraction.OutputFileName | String | Clean file name. | 
| SandBlast.Upload.ThreatExtraction.Time | String | Time for threat extraction completion. | 
| SandBlast.Upload.ThreatExtraction.ExtractContent | String | Content of extracted file. | 
| SandBlast.Upload.ThreatExtraction.TexProduct | Boolean | True if the queried file is already a Sandblast-safe copy. | 
| SandBlast.Upload.ThreatExtraction.Status | String | Status of Threat Extraction on the requested file. | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.InputExtension | String | Uploaded filename-extension as sent by the client. | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.InputRealExtension | String | Extension as resolved by Threat Extraction. | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.Message | String | Status message for scrub_result | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.ProtectionName | String | Potential malicious content extracted. | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.ProtectionType | String | Protection done for scrub_method: Conversion to PDF | Content Removal | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.ProtocolVersion | String | Protocol used. | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.RealExtension | String | Real extension as resolved by Threat Extraction | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.Risk | Number | Represents the risk of the part that was extracted from the document. | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.ScrubActivity | String | Readable result from Threat Extraction. | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.ScrubMethod | String | Convert to PDF | Clean Document. | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.ScrubResult | Number | Code result from Threat Extraction. | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.ScrubTime | String | Threat Extraction process time. | 
| SandBlast.Upload.ThreatExtraction.ExtractionData.ScrubbedContent | String | Content that was removed | 
| SandBlast.Upload.ThreatEmulation.Trust | Number | Rating of the threat data and its relevance to this instance. It is recommended to block threats with confidence medium and above. | 
| SandBlast.Upload.ThreatEmulation.Score | Number | Threat Emulation score. | 
| SandBlast.Upload.ThreatEmulation.CombinedVerdict | String | Combined verdict of all the images. Benign reports are not supported for local gateways. | 
| SandBlast.Upload.ThreatEmulation.Severity | Number | Combined severity of threats found. In case threats are not found, this field is not given. | 
| SandBlast.Upload.ThreatEmulation.Images | String | Sand boxes used in Threat Emulation. Information about image types can be found in https://sc1.checkpoint.com/documents/TPAPI/CP_1.0_ThreatPreventionAPI_APIRefGuide/html_frameset.htm under "Query API" -&gt; "Query Response Format" -&gt; "Images Object Format". | 
| SandBlast.Upload.ThreatEmulation.Status | String | Status of Threat Emulation on the requested file. | 

#### Command example
```!sandblast-upload file_id=4439@e2ea7f6b-7ea5-4084-8f97-a709139e4ad6```
#### Context Example
```json
{
    "SandBlast": {
        "Upload": {
            "AntiVirus": {
                "Confidence": 0,
                "MalwareFamily": 0,
                "MalwareType": 0,
                "Severity": 0,
                "SignatureName": "",
                "Status": {
                    "code": 1001,
                    "label": "FOUND",
                    "message": "The request has been fully answered."
                }
            },
            "Features": [
                "te",
                "av",
                "extraction"
            ],
            "FileName": "server_api.pdf",
            "FileType": ".pdf",
            "MD5": "dc62a932b37ef74999321f76555141aa",
            "SHA1": "d458741bcd4fd48467418e95de2d65adc552bf16",
            "SHA256": "023a479d2f7d5e5af8c6666e241ac9bc35e361f0f3cac90743bc57e0bb333264",
            "Status": {
                "code": 1002,
                "label": "UPLOAD_SUCCESS",
                "message": "The file was uploaded successfully."
            },
            "ThreatEmulation": {
                "Images": [
                    {
                        "id": "3ff3ddae-e7fd-4969-818c-d5f1a2be336d",
                        "report": {
                            "verdict": "unknown"
                        },
                        "revision": 1,
                        "status": "not_found"
                    },
                    {
                        "id": "e50e99f3-5963-4573-af9e-e3f4750b55e2",
                        "report": {
                            "verdict": "unknown"
                        },
                        "revision": 1,
                        "status": "not_found"
                    }
                ],
                "Score": -2147483648,
                "Status": {
                    "code": 1002,
                    "label": "UPLOAD_SUCCESS",
                    "message": "The file was uploaded successfully."
                },
                "Trust": 0
            },
            "ThreatExtraction": {
                "Method": "pdf",
                "Status": {
                    "code": 1002,
                    "label": "UPLOAD_SUCCESS",
                    "message": "The file was uploaded successfully."
                },
                "TexProduct": false
            }
        }
    }
}
```

#### Human Readable Output

>Upload Results
>### File Info
>|Filename|Filetype|Label|Message|Md5|Sha1|Sha256|
>|---|---|---|---|---|---|---|
>| server_api.pdf | .pdf | UPLOAD_SUCCESS | The file was uploaded successfully. | dc62a932b37ef74999321f76555141aa | d458741bcd4fd48467418e95de2d65adc552bf16 | 023a479d2f7d5e5af8c6666e241ac9bc35e361f0f3cac90743bc57e0bb333264 |


### sandblast-download
***
Use the Upload API to have a client application request that Check Point Threat Prevention modules scan and analyze a file. When you upload a file to the service, the file is encrypted. It is un-encrypted during analysis, and then deleted.


#### Base Command

`sandblast-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | ID of the file to download, which will be taken from "Extractedfiledownloadid" from "Threat Extraction" results. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 

#### Command example
```!sandblast-download file_id=d2aa35e1-7951-4e6c-a938-a5c78769267c```
#### Context Example
```json
{
    "File": {
        "EntryID": "4458@e2ea7f6b-7ea5-4084-8f97-a709139e4ad6",
        "Info": "application/pdf",
        "MD5": "0448d32b46c007b18cd9e7b20f8f47e9",
        "Name": "d2aa35e1-7951-4e6c-a938-a5c78769267c",
        "SHA1": "0ed9a7f03d98741e2bfbaed1e52a2c1f53daf6e8",
        "SHA256": "c8b5e84b5c3f03f42c2d0a89552ea6ea59077e170051ff1b72d25910869df0de",
        "SHA512": "f930bceca97f2b0c96531dfdaafa7ac42d9485cf49d5fb230007d7a6ffdc02c1534deadb2ddbb53f6b400a66a436d156e0abb4c5c79c20a3677f42230f063fb6",
        "SSDeep": "6144:sz1foLXTD6uKvGeiiJgaDn1beShJSNTVwur4MkAu6a:sJoLjKvXj71KKqVwX/R6a",
        "Size": 286972,
        "Type": "PDF document, version 1.5"
    }
}
```

#### Human Readable Output



### sandblast-quota
***
Use the Quote API to have a client application get the current license and quota status of the API Key that you use in the authorization of the other APIs. For cloud services only.


#### Base Command

`sandblast-quota`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SandBlast.Quota.RemainQuotaHour | Number | Remaining quota hours. | 
| SandBlast.Quota.RemainQuotaMonth | Number | Remaining  quota months. | 
| SandBlast.Quota.AssignedQuotaHour | Number | Assigned  quota hours. | 
| SandBlast.Quota.AssignedQuotaMonth | Number | Assigned  quota months. | 
| SandBlast.Quota.HourlyQuotaNextReset | String | Hourly quota next reset. | 
| SandBlast.Quota.MonthlyQuotaNextReset | String | Monthly quota next reset. | 
| SandBlast.Quota.QuotaId | String | Quota ID. | 
| SandBlast.Quota.CloudMonthlyQuotaPeriodStart | String | Cloud monthly quota period start. | 
| SandBlast.Quota.CloudMonthlyQuotaUsageForThisGw | Number | Cloud monthly quota usage for this GW. | 
| SandBlast.Quota.CloudHourlyQuotaUsageForThisGw | Number | Cloud hourly quota usage for this GW. | 
| SandBlast.Quota.CloudMonthlyQuotaUsageForQuotaId | Number | Cloud monthly quota usage for QuotaID. | 
| SandBlast.Quota.CloudHourlyQuotaUsageForQuotaId | Number | Cloud hourly quota usage for QuotaID. | 
| SandBlast.Quota.MonthlyExceededQuota | Number | Monthly exceeded quota. | 
| SandBlast.Quota.HourlyExceededQuota | Number | Hourly exceeded quota. | 
| SandBlast.Quota.CloudQuotaMaxAllowToExceedPercentage | Number | Cloud quota max allowed to exceed percentage. | 
| SandBlast.Quota.PodTimeGmt | String | Pod time GMT. | 
| SandBlast.Quota.QuotaExpiration | String | Quota expiration. | 
| SandBlast.Quota.Action | String | Quota action. | 

#### Command example
```!sandblast-quota```
#### Context Example
```json
{
    "SandBlast": {
        "Quota": {
            "Action": "ALLOW",
            "AssignedQuotaHour": 500,
            "AssignedQuotaMonth": 10000,
            "CloudHourlyQuotaUsageForQuotaId": 0,
            "CloudHourlyQuotaUsageForThisGw": 0,
            "CloudMonthlyQuotaPeriodStart": "2022-07-01T00:00:00.000Z",
            "CloudMonthlyQuotaUsageForQuotaId": 25,
            "CloudMonthlyQuotaUsageForThisGw": 25,
            "CloudQuotaMaxAllowToExceedPercentage": 1000,
            "HourlyExceededQuota": 0,
            "HourlyQuotaNextReset": "2022-07-06T14:00:00.000Z",
            "MonthlyExceededQuota": 0,
            "MonthlyQuotaNextReset": "2022-08-01T00:00:00.000Z",
            "PodTimeGmt": "2022-07-06T13:31:06.000Z",
            "QuotaExpiration": "2022-07-08T00:00:00.000Z",
            "QuotaId": "H05WER4",
            "RemainQuotaHour": 500,
            "RemainQuotaMonth": 9975
        }
    }
}
```

#### Human Readable Output

>### Quota Information
>|Remainquotahour|Remainquotamonth|Assignedquotahour|Assignedquotamonth|Hourlyquotanextreset|Monthlyquotanextreset|Quotaid|Cloudmonthlyquotaperiodstart|Cloudmonthlyquotausageforthisgw|Cloudhourlyquotausageforthisgw|Cloudmonthlyquotausageforquotaid|Cloudhourlyquotausageforquotaid|Monthlyexceededquota|Hourlyexceededquota|Cloudquotamaxallowtoexceedpercentage|Podtimegmt|Quotaexpiration|Action|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 500 | 9975 | 500 | 10000 | 2022-07-06T14:00:00.000Z | 2022-08-01T00:00:00.000Z | H05WER4 | 2022-07-01T00:00:00.000Z | 25 | 0 | 25 | 0 | 0 | 0 | 1000 | 2022-07-06T13:31:06.000Z | 2022-07-08T00:00:00.000Z | ALLOW |

