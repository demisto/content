Detonate files and URLs in the tLab Anti-APT malware sandbox and retrieve verdicts, reports and artifacts.
This integration was developed against the tLab Anti-APT API of sandbox-core 1.13.0.

## Configure tLab Anti-APT Sandbox in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL of the tLab Anti-APT sandbox API \(tlab-server\). Through the tLab web server use https://&lt;tlab-host&gt;/api; for a direct connection use http://&lt;tlab-host&gt;:8080. | True |
| Auth server URL \(tlab-auth\) | Used by the tLab account mode. Where the integration logs in to tlab-auth. Leave empty to use https://&lt;Server URL host&gt;:8002/api, the omni-center portal, which forwards /api to tlab-auth over TLS; if its certificate is self-signed, enable Trust any certificate. Not https://&lt;host&gt;/api, which is the sandbox API itself. | False |
| Authentication mode | tLab account \(tlab-auth\) is recommended: the integration logs in to tlab-auth like the omni-center portal and sends the token as Bearer. Source key needs the source-key gateway \(balancer\) and covers submissions only. Username and password is the legacy tlab-server sign-in. Internal token works only when XSOAR runs on the tlab-server host itself. | True |
| Credentials | Login and password of a tLab account \(tLab account mode\). Retrieving artifacts needs the admin or developer role. Turn off password expiry for this account: tlab-auth rejects an expired password and every command starts failing. Other modes use only the password field: source key or internal token. | True |
| Password / source key / internal token |  | True |
| Client name | Sent as the X-Client header and stored on every submission as the analysis property "client". | False |
| Source UID | Identifies this XSOAR on the tLab side, at most 45 characters. Defaults to the first 45 characters of the XSOAR license ID (Settings > About). Set it to tell apart several instances of this integration on one XSOAR. | False |
| Analysis types | AV_ANALYSIS is always added by the server. DYN_ANALYSIS is removed on a LITE license or with the mailer preset - check RequestedButNotRun in the command output. | False |
| Analysis priority |  | False |
| Environment preset | Leave empty to let the server pick an environment by file type. Maximum 50 characters. | False |
| Dynamic analysis time (seconds) | Maximum 3600 seconds, enforced by the server. | False |
| Enable network during dynamic analysis |  | False |
| Accept an early verdict | Finalize once static and antivirus analysis complete, without waiting for dynamic analysis. | False |
| Suspicious score threshold | Mirrors the product default. Scores from this value up to the malicious threshold are Suspicious. | False |
| Malicious score threshold | Mirrors the product default \(analysisService.minMaliciousScore\). | False |
| Source reliability | Reliability attached to every DBotScore this integration produces. | False |
| Maximum artifact size (MB) | Downloads larger than this are aborted rather than buffered. | False |
| PDF render timeout (seconds) | The PDF endpoint renders synchronously and has no status endpoint, so a large report can take a while. | False |
| tLab web UI base URL | Used only to build human-readable report links in command output. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tlab-submit-file

***
Submit a war room file to tLab Anti-APT and return immediately with an access code.

#### Base Command

`tlab-submit-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | War room entry ID of the file to submit. | Required | 
| file_name | Override the file name sent to the sandbox. | Optional | 
| additional_files_entry_ids | Comma-separated entry IDs of supporting files submitted alongside the main one. | Optional | 
| analysis_types | Override the configured analysis types. Possible values are: STAT_ANALYSIS, DYN_ANALYSIS, CODE_ANALYSIS, AV_ANALYSIS. | Optional | 
| analysis_priority | Queue priority. Possible values are: LOWEST, LOW, MEDIUM, HIGH, HIGHEST. | Optional | 
| research_time | Dynamic analysis time in seconds. Maximum 3600. | Optional | 
| env_preset | Environment preset name. Maximum 50 characters. | Optional | 
| enable_network | Allow network access during dynamic analysis. Possible values are: true, false. | Optional | 
| archive_password | Password for a protected archive. | Optional | 
| extract_archive | Extract archives before analysis. Possible values are: true, false. | Optional | 
| ignore_whitelist | Analyze the sample even if it is whitelisted. Possible values are: true, false. | Optional | 
| tags | Comma-separated tags to attach to the analysis. Each tag must be 2-150 characters. | Optional | 
| properties | JSON object of extra provenance properties stored with the analysis. | Optional | 
| main_filename | Name of the main file inside an archive submission. | Optional | 
| command_line_args | Command line passed to the sample. Maximum 200 characters. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.Submission.AccessCode | String | Access code used to poll this submission. Polling needs no credentials. | 
| TLabAntiAPT.Submission.AnalysisRequestId | Number | Numeric analysis request ID. | 
| TLabAntiAPT.Submission.AnalysisRequestStatus | String | One of UNKNOWN, WAITING_FOR_PROCESSING, PROCESSING, ACCEPTED, REJECTED. | 
| TLabAntiAPT.Submission.RejectionCode | String | Raw rejection code when the submission was refused. | 
| TLabAntiAPT.Submission.RejectionReason | String | Readable explanation of the rejection code. | 
| TLabAntiAPT.Submission.Whitelisted | Boolean | Whether the sample is whitelisted in tLab Anti-APT. | 

#### Command example
```!tlab-submit-file entry_id=3@a1b2c3 file_name=invoice.exe```
#### Context Example
```json
{
    "TLabAntiAPT.Submission(val.AccessCode && val.AccessCode == obj.AccessCode)": {
        "AnalysisRequestId": 1001,
        "AnalysisRequestStatus": "ACCEPTED",
        "AccessCode": "acc-123",
        "Whitelisted": false,
        "Submitted": "invoice.exe"
    }
}
```
#### Human Readable Output

>### Submitted invoice.exe to tLab Anti-APT
>|AccessCode|AnalysisRequestId|AnalysisRequestStatus|Submitted|Whitelisted|
>|---|---|---|---|---|
>| acc-123 | 1001 | ACCEPTED | invoice.exe | false |

### tlab-submit-url

***
Submit a URL to tLab Anti-APT and return immediately with an access code.

#### Base Command

`tlab-submit-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to analyze. | Required | 
| analysis_types | Override the configured analysis types. Possible values are: STAT_ANALYSIS, DYN_ANALYSIS, CODE_ANALYSIS, AV_ANALYSIS. | Optional | 
| research_time | Dynamic analysis time in seconds. Maximum 3600. | Optional | 
| env_preset | Environment preset name. | Optional | 
| enable_network | Allow network access during dynamic analysis. Possible values are: true, false. | Optional | 
| tags | Comma-separated tags to attach to the analysis. | Optional | 
| properties | JSON object of extra provenance properties. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.Submission.AccessCode | String | Access code used to poll this submission. | 
| TLabAntiAPT.Submission.AnalysisRequestStatus | String | Request status returned by the server. | 

### tlab-get-submission-status

***
Poll a submission until tLab Anti-APT reaches a terminal verdict.

#### Base Command

`tlab-get-submission-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| access_code | Access code returned by a submit command. | Required | 
| early_verdict | Finalize once static and antivirus analysis complete, without waiting for dynamic analysis. Possible values are: true, false. | Optional | 
| extended | Also fetch the full report so sub-report IDs are available. The public status endpoint does not carry them. Possible values are: true, false. | Optional | 
| interval_in_seconds | Seconds between polls. Default is 30. | Optional | 
| timeout_in_seconds | Total seconds to keep polling. Default is 1800. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.Analysis.SampleReportId | Number | Report ID in tLab Anti-APT. | 
| TLabAntiAPT.Analysis.Verdict | String | Canonical verdict - MALWARE, SUSPICIOUS, OK, CLEAN, WHITELIST or UNKNOWN. | 
| TLabAntiAPT.Analysis.ScoreLevel | String | Raw ScoreLevel value as returned by the server, where MALICIOUS means MALWARE. | 
| TLabAntiAPT.Analysis.FileVerdict | String | Verdict set manually in tLab for this file. Absent while nobody has set it; not the analysis result, which is in Verdict. | 
| TLabAntiAPT.Analysis.Score | Number | Sample score. Absent when the sandbox has not computed one. | 
| TLabAntiAPT.Analysis.Completeness | String | EMPTY, PARTIALLY_COMPLETE or COMPLETE. | 
| TLabAntiAPT.Analysis.DBotScore | Number | DBot score derived from the verdict. | 
| TLabAntiAPT.Analysis.RequestedButNotRun | Unknown | Analysis types that were requested but not executed, for example when a LITE license strips dynamic analysis. | 
| TLabAntiAPT.Analysis.DynReportId | Number | Dynamic analysis report ID. Available only with extended=true. | 
| TLabAntiAPT.Analysis.StatReportId | Number | Static analysis report ID. Available only with extended=true. | 
| TLabAntiAPT.Analysis.File.HashSha256 | String | SHA256 of the analyzed sample. | 
| TLabAntiAPT.Analysis.MalwareClassifier.PrimaryType | String | Malware family predicted by the classifier. | 
| TLabAntiAPT.Analysis.ReportUrl | String | Link to the full report in the tLab web UI. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | Vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| File.SHA256 | String | SHA256 of the file. | 
| File.Malicious.Vendor | String | Vendor that decided the file is malicious. | 

#### Command example
```!tlab-get-submission-status access_code=acc-123```
#### Context Example
```json
{
    "File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)": [
        {
            "Hashes": [
                {
                    "type": "MD5",
                    "value": "aaaabbbbccccddddeeeeffff00001111"
                },
                {
                    "type": "SHA1",
                    "value": "aaaabbbbccccddddeeeeffff0000111122223333"
                },
                {
                    "type": "SHA256",
                    "value": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"
                }
            ],
            "Name": "invoice.exe",
            "Size": 2048,
            "MD5": "aaaabbbbccccddddeeeeffff00001111",
            "SHA1": "aaaabbbbccccddddeeeeffff0000111122223333",
            "SHA256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "Extension": "exe",
            "Type": "PE",
            "Malicious": {
                "Vendor": "tLab Anti-APT",
                "Description": "tLab Anti-APT verdict: MALWARE"
            }
        }
    ],
    "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)": [
        {
            "Indicator": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "Type": "file",
            "Vendor": "tLab Anti-APT",
            "Score": 3,
            "Reliability": "B - Usually reliable"
        }
    ],
    "TLabAntiAPT.Analysis(val.SampleReportId && val.SampleReportId == obj.SampleReportId)": {
        "AccessCode": "acc-123",
        "AnalysisRequestStatus": "ACCEPTED",
        "SampleReportId": 412839,
        "SampleReportType": "MAIN",
        "Completeness": "COMPLETE",
        "Score": 91.5,
        "MaxScore": 91.5,
        "ScoreLevel": "MALICIOUS",
        "FileVerdict": "MALWARE",
        "Verdict": "MALWARE",
        "DBotScore": 3,
        "Whitelisted": false,
        "DetectedByAv": true,
        "UploadedFilename": "invoice.exe",
        "CreateTime": "2026-03-26T08:00:00Z",
        "UpdateTime": "2026-03-26T08:10:00Z",
        "File": {
            "HashSha256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "HashSha1": "aaaabbbbccccddddeeeeffff0000111122223333",
            "HashMd5": "aaaabbbbccccddddeeeeffff00001111",
            "Size": 2048,
            "FileType": "PE",
            "MimeType": "application/x-dosexec",
            "InferredExtension": "exe",
            "FileVerdict": "MALWARE"
        },
        "MalwareClassifier": {
            "PrimaryType": "Trojan.Generic",
            "Confidence": 0.91,
            "MultiStage": true
        },
        "Source": {
            "SourceId": 12,
            "Type": "Cortex XSOAR",
            "Uid": "lic-1"
        },
        "AnalyzedReportTypes": [
            "AV_ANALYSIS",
            "DYN_ANALYSIS",
            "STAT_ANALYSIS"
        ]
    }
}
```
#### Human Readable Output

>### tLab Anti-APT analysis
>|Completeness|Detected by AV|File|Malware family|Report ID|SHA256|Score|Verdict|
>|---|---|---|---|---|---|---|---|
>| COMPLETE | true | invoice.exe | Trojan.Generic | 412839 | aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999 | 91.5 | MALWARE |

### tlab-detonate-file

***
Submit a war room file and wait for the tLab Anti-APT verdict.

#### Base Command

`tlab-detonate-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | War room entry ID of the file to detonate. | Required | 
| file_name | Override the file name sent to the sandbox. | Optional | 
| research_time | Dynamic analysis time in seconds. Maximum 3600. | Optional | 
| env_preset | Environment preset name. | Optional | 
| enable_network | Allow network access during dynamic analysis. Possible values are: true, false. | Optional | 
| archive_password | Password for a protected archive. | Optional | 
| early_verdict | Finalize once static and antivirus analysis complete. Possible values are: true, false. | Optional | 
| extended | Also fetch the full report so sub-report IDs are available. Possible values are: true, false. | Optional | 
| tags | Comma-separated tags to attach to the analysis. | Optional | 
| interval_in_seconds | Seconds between polls. Default is 30. | Optional | 
| timeout_in_seconds | Total seconds to keep polling. Default is 1800. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.Analysis.SampleReportId | Number | Report ID in tLab Anti-APT. | 
| TLabAntiAPT.Analysis.Verdict | String | Canonical verdict - MALWARE, SUSPICIOUS, OK, CLEAN, WHITELIST or UNKNOWN. | 
| TLabAntiAPT.Analysis.ScoreLevel | String | Raw ScoreLevel value as returned by the server, where MALICIOUS means MALWARE. | 
| TLabAntiAPT.Analysis.FileVerdict | String | Verdict set manually in tLab for this file. Absent while nobody has set it; not the analysis result, which is in Verdict. | 
| TLabAntiAPT.Analysis.Score | Number | Sample score. Absent when the sandbox has not computed one. | 
| TLabAntiAPT.Analysis.Completeness | String | EMPTY, PARTIALLY_COMPLETE or COMPLETE. | 
| TLabAntiAPT.Analysis.DBotScore | Number | DBot score derived from the verdict. | 
| TLabAntiAPT.Analysis.RequestedButNotRun | Unknown | Analysis types that were requested but not executed, for example when a LITE license strips dynamic analysis. | 
| TLabAntiAPT.Analysis.DynReportId | Number | Dynamic analysis report ID. Available only with extended=true. | 
| TLabAntiAPT.Analysis.StatReportId | Number | Static analysis report ID. Available only with extended=true. | 
| TLabAntiAPT.Analysis.File.HashSha256 | String | SHA256 of the analyzed sample. | 
| TLabAntiAPT.Analysis.MalwareClassifier.PrimaryType | String | Malware family predicted by the classifier. | 
| TLabAntiAPT.Analysis.ReportUrl | String | Link to the full report in the tLab web UI. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | Vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| File.SHA256 | String | SHA256 of the file. | 
| File.Malicious.Vendor | String | Vendor that decided the file is malicious. | 

#### Command example
```!tlab-detonate-file entry_id=3@a1b2c3 file_name=invoice.exe```
#### Context Example
```json
{
    "File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)": [
        {
            "Hashes": [
                {
                    "type": "MD5",
                    "value": "aaaabbbbccccddddeeeeffff00001111"
                },
                {
                    "type": "SHA1",
                    "value": "aaaabbbbccccddddeeeeffff0000111122223333"
                },
                {
                    "type": "SHA256",
                    "value": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"
                }
            ],
            "Name": "invoice.exe",
            "Size": 2048,
            "MD5": "aaaabbbbccccddddeeeeffff00001111",
            "SHA1": "aaaabbbbccccddddeeeeffff0000111122223333",
            "SHA256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "Extension": "exe",
            "Type": "PE",
            "Malicious": {
                "Vendor": "tLab Anti-APT",
                "Description": "tLab Anti-APT verdict: MALWARE"
            }
        }
    ],
    "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)": [
        {
            "Indicator": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "Type": "file",
            "Vendor": "tLab Anti-APT",
            "Score": 3,
            "Reliability": "B - Usually reliable"
        }
    ],
    "TLabAntiAPT.Analysis(val.SampleReportId && val.SampleReportId == obj.SampleReportId)": {
        "AccessCode": "acc-123",
        "AnalysisRequestStatus": "ACCEPTED",
        "SampleReportId": 412839,
        "SampleReportType": "MAIN",
        "Completeness": "COMPLETE",
        "Score": 91.5,
        "MaxScore": 91.5,
        "ScoreLevel": "MALICIOUS",
        "FileVerdict": "MALWARE",
        "Verdict": "MALWARE",
        "DBotScore": 3,
        "Whitelisted": false,
        "DetectedByAv": true,
        "UploadedFilename": "invoice.exe",
        "CreateTime": "2026-03-26T08:00:00Z",
        "UpdateTime": "2026-03-26T08:10:00Z",
        "File": {
            "HashSha256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "HashSha1": "aaaabbbbccccddddeeeeffff0000111122223333",
            "HashMd5": "aaaabbbbccccddddeeeeffff00001111",
            "Size": 2048,
            "FileType": "PE",
            "MimeType": "application/x-dosexec",
            "InferredExtension": "exe",
            "FileVerdict": "MALWARE"
        },
        "MalwareClassifier": {
            "PrimaryType": "Trojan.Generic",
            "Confidence": 0.91,
            "MultiStage": true
        },
        "Source": {
            "SourceId": 12,
            "Type": "Cortex XSOAR",
            "Uid": "lic-1"
        },
        "AnalyzedReportTypes": [
            "AV_ANALYSIS",
            "DYN_ANALYSIS",
            "STAT_ANALYSIS"
        ]
    }
}
```
#### Human Readable Output

>### tLab Anti-APT analysis
>|Completeness|Detected by AV|File|Malware family|Report ID|SHA256|Score|Verdict|
>|---|---|---|---|---|---|---|---|
>| COMPLETE | true | invoice.exe | Trojan.Generic | 412839 | aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999 | 91.5 | MALWARE |

### tlab-detonate-url

***
Submit a URL and wait for the tLab Anti-APT verdict.

#### Base Command

`tlab-detonate-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to detonate. | Required | 
| research_time | Dynamic analysis time in seconds. Maximum 3600. | Optional | 
| env_preset | Environment preset name. | Optional | 
| enable_network | Allow network access during dynamic analysis. Possible values are: true, false. | Optional | 
| early_verdict | Finalize once static and antivirus analysis complete. Possible values are: true, false. | Optional | 
| extended | Also fetch the full report so sub-report IDs are available. Possible values are: true, false. | Optional | 
| interval_in_seconds | Seconds between polls. Default is 30. | Optional | 
| timeout_in_seconds | Total seconds to keep polling. Default is 1800. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.Analysis.SampleReportId | Number | Report ID in tLab Anti-APT. | 
| TLabAntiAPT.Analysis.Verdict | String | Canonical verdict - MALWARE, SUSPICIOUS, OK, CLEAN, WHITELIST or UNKNOWN. | 
| TLabAntiAPT.Analysis.ScoreLevel | String | Raw ScoreLevel value as returned by the server, where MALICIOUS means MALWARE. | 
| TLabAntiAPT.Analysis.FileVerdict | String | Verdict set manually in tLab for this file. Absent while nobody has set it; not the analysis result, which is in Verdict. | 
| TLabAntiAPT.Analysis.Score | Number | Sample score. Absent when the sandbox has not computed one. | 
| TLabAntiAPT.Analysis.Completeness | String | EMPTY, PARTIALLY_COMPLETE or COMPLETE. | 
| TLabAntiAPT.Analysis.DBotScore | Number | DBot score derived from the verdict. | 
| TLabAntiAPT.Analysis.RequestedButNotRun | Unknown | Analysis types that were requested but not executed, for example when a LITE license strips dynamic analysis. | 
| TLabAntiAPT.Analysis.DynReportId | Number | Dynamic analysis report ID. Available only with extended=true. | 
| TLabAntiAPT.Analysis.StatReportId | Number | Static analysis report ID. Available only with extended=true. | 
| TLabAntiAPT.Analysis.File.HashSha256 | String | SHA256 of the analyzed sample. | 
| TLabAntiAPT.Analysis.MalwareClassifier.PrimaryType | String | Malware family predicted by the classifier. | 
| TLabAntiAPT.Analysis.ReportUrl | String | Link to the full report in the tLab web UI. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | Vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| File.SHA256 | String | SHA256 of the file. | 
| File.Malicious.Vendor | String | Vendor that decided the file is malicious. | 

#### Command example
```!tlab-detonate-url url=https://example.com/payload```
#### Context Example
```json
{
    "File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)": [
        {
            "Hashes": [
                {
                    "type": "MD5",
                    "value": "aaaabbbbccccddddeeeeffff00001111"
                },
                {
                    "type": "SHA1",
                    "value": "aaaabbbbccccddddeeeeffff0000111122223333"
                },
                {
                    "type": "SHA256",
                    "value": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"
                }
            ],
            "Name": "invoice.exe",
            "Size": 2048,
            "MD5": "aaaabbbbccccddddeeeeffff00001111",
            "SHA1": "aaaabbbbccccddddeeeeffff0000111122223333",
            "SHA256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "Extension": "exe",
            "Type": "PE",
            "Malicious": {
                "Vendor": "tLab Anti-APT",
                "Description": "tLab Anti-APT verdict: MALWARE"
            }
        }
    ],
    "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)": [
        {
            "Indicator": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "Type": "file",
            "Vendor": "tLab Anti-APT",
            "Score": 3,
            "Reliability": "B - Usually reliable"
        }
    ],
    "TLabAntiAPT.Analysis(val.SampleReportId && val.SampleReportId == obj.SampleReportId)": {
        "AccessCode": "acc-123",
        "AnalysisRequestStatus": "ACCEPTED",
        "SampleReportId": 412839,
        "SampleReportType": "MAIN",
        "Completeness": "COMPLETE",
        "Score": 91.5,
        "MaxScore": 91.5,
        "ScoreLevel": "MALICIOUS",
        "FileVerdict": "MALWARE",
        "Verdict": "MALWARE",
        "DBotScore": 3,
        "Whitelisted": false,
        "DetectedByAv": true,
        "UploadedFilename": "invoice.exe",
        "CreateTime": "2026-03-26T08:00:00Z",
        "UpdateTime": "2026-03-26T08:10:00Z",
        "File": {
            "HashSha256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "HashSha1": "aaaabbbbccccddddeeeeffff0000111122223333",
            "HashMd5": "aaaabbbbccccddddeeeeffff00001111",
            "Size": 2048,
            "FileType": "PE",
            "MimeType": "application/x-dosexec",
            "InferredExtension": "exe",
            "FileVerdict": "MALWARE"
        },
        "MalwareClassifier": {
            "PrimaryType": "Trojan.Generic",
            "Confidence": 0.91,
            "MultiStage": true
        },
        "Source": {
            "SourceId": 12,
            "Type": "Cortex XSOAR",
            "Uid": "lic-1"
        },
        "AnalyzedReportTypes": [
            "AV_ANALYSIS",
            "DYN_ANALYSIS",
            "STAT_ANALYSIS"
        ]
    }
}
```
#### Human Readable Output

>### tLab Anti-APT analysis
>|Completeness|Detected by AV|File|Malware family|Report ID|SHA256|Score|Verdict|
>|---|---|---|---|---|---|---|---|
>| COMPLETE | true | invoice.exe | Trojan.Generic | 412839 | aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999 | 91.5 | MALWARE |

### tlab-get-report

***
Retrieve a full sample report by its ID.

#### Base Command

`tlab-get-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_report_id | Report ID in tLab Anti-APT. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.Report.SampleReportId | Number | Report ID in tLab Anti-APT. | 
| TLabAntiAPT.Report.Verdict | String | Canonical verdict. | 
| TLabAntiAPT.Report.Score | Number | Sample score. | 
| TLabAntiAPT.Report.DynReportId | Number | Dynamic analysis report ID. | 
| TLabAntiAPT.Report.StatReportId | Number | Static analysis report ID. | 

#### Command example
```!tlab-get-report sample_report_id=412839```
#### Context Example
```json
{
    "File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)": [
        {
            "Hashes": [
                {
                    "type": "SHA256",
                    "value": "aa"
                }
            ],
            "Name": "invoice.exe",
            "SHA256": "aa",
            "Type": "PE",
            "Malicious": {
                "Vendor": "tLab Anti-APT",
                "Description": "tLab Anti-APT verdict: MALWARE"
            }
        }
    ],
    "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)": [
        {
            "Indicator": "aa",
            "Type": "file",
            "Vendor": "tLab Anti-APT",
            "Score": 3,
            "Reliability": "B - Usually reliable"
        }
    ],
    "TLabAntiAPT.Report(val.SampleReportId && val.SampleReportId == obj.SampleReportId)": {
        "SampleReportId": 412839,
        "SampleReportType": "MAIN",
        "Completeness": "COMPLETE",
        "Score": 91.5,
        "ScoreLevel": "MALICIOUS",
        "FileVerdict": "MALWARE",
        "Verdict": "MALWARE",
        "DBotScore": 3,
        "Whitelisted": false,
        "DetectedByAv": false,
        "UploadedFilename": "invoice.exe",
        "DynReportId": 777,
        "StatReportId": 888,
        "File": {
            "HashSha256": "aa",
            "FileType": "PE",
            "FileVerdict": "MALWARE"
        },
        "RequestedButNotRun": [
            "DYN_ANALYSIS"
        ],
        "AnalyzedReportTypes": [
            "DYN_ANALYSIS",
            "STAT_ANALYSIS"
        ]
    }
}
```
#### Human Readable Output

>### tLab Anti-APT analysis
>|Completeness|Detected by AV|File|Report ID|SHA256|Score|Verdict|
>|---|---|---|---|---|---|---|
>| COMPLETE | false | invoice.exe | 412839 | aa | 91.5 | MALWARE |
>
>**Note:** the server did not run DYN_ANALYSIS. This happens on a LITE license or with the `mailer` preset, where dynamic analysis is removed from the request.

### tlab-get-threat-indicators

***
Retrieve aggregated threat indicators for a report. This is the richest source of observables tLab Anti-APT produces.

#### Base Command

`tlab-get-threat-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_report_id | Report ID in tLab Anti-APT. | Required | 
| level | Keep only indicators at these threat levels. Possible values are: MALICIOUS, SUSPICIOUS, INFO. | Optional | 
| source | Keep only indicators from these analysis sources. Possible values are: BEHAVIOR, SIGMA, DEEP_SLICER, ANOMALY_INSPECTOR, STATIC, YARA, AV, OTHER. | Optional | 
| limit | Maximum number of indicators to return. Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.ThreatIndicator.SampleReportId | Number | Report the indicators belong to. | 
| TLabAntiAPT.ThreatIndicator.Indicators | Unknown | Threat indicators with their observed objects. | 
| TLabAntiAPT.ThreatIndicator.Totals | Unknown | Indicator counts per threat level. | 

#### Command example
```!tlab-get-threat-indicators sample_report_id=412839```
#### Context Example
```json
{
    "TLabAntiAPT.ThreatIndicator(val.SampleReportId && val.SampleReportId == obj.SampleReportId)": {
        "SampleReportId": 412839,
        "Indicators": [
            {
                "Id": 1,
                "Source": "BEHAVIOR",
                "AnalysisType": "DYN_ANALYSIS",
                "Key": "inet",
                "Level": "MALICIOUS",
                "Title": "Connects to a known bad host",
                "Count": 3,
                "ObjectsTotal": 2,
                "Objects": [
                    {
                        "Kind": "VALUE",
                        "Name": "evil.example.com"
                    },
                    {
                        "Kind": "VALUE",
                        "Name": "203.0.113.5"
                    }
                ],
                "Attack": [
                    "T1071"
                ]
            },
            {
                "Id": 2,
                "Source": "STATIC",
                "AnalysisType": "STAT_ANALYSIS",
                "Key": "packer",
                "Level": "SUSPICIOUS",
                "Title": "Packed executable",
                "Count": 1,
                "ObjectsTotal": 0,
                "Objects": [],
                "Attack": []
            }
        ],
        "Totals": {
            "MALICIOUS": 2,
            "SUSPICIOUS": 1
        }
    }
}
```
#### Human Readable Output

>### tLab Anti-APT threat indicators for report 412839
>|Count|Level|Source|Title|
>|---|---|---|---|
>| 3 | MALICIOUS | BEHAVIOR | Connects to a known bad host |
>| 1 | SUSPICIOUS | STATIC | Packed executable |

### tlab-get-attack-matrix

***
Retrieve the MITRE ATT&CK techniques mapped for a report.

#### Base Command

`tlab-get-attack-matrix`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_report_id | Report ID in tLab Anti-APT. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.AttackMatrix.SampleReportId | Number | Report the matrix belongs to. | 
| TLabAntiAPT.AttackMatrix.Techniques | Unknown | Mapped ATT&amp;CK techniques. | 
| TLabAntiAPT.AttackMatrix.CatalogVersion | String | ATT&amp;CK catalog version used for the mapping. | 

#### Command example
```!tlab-get-attack-matrix sample_report_id=412839```
#### Context Example
```json
{
    "TLabAntiAPT.AttackMatrix(val.SampleReportId && val.SampleReportId == obj.SampleReportId)": {
        "SampleReportId": 412839,
        "CatalogVersion": "14.1",
        "Totals": {
            "techniques": 2,
            "tactics": 2
        },
        "Techniques": [
            {
                "Id": "T1071",
                "Name": "Application Layer Protocol",
                "Url": "https://attack.mitre.org/techniques/T1071/",
                "Level": "MALICIOUS",
                "Tactics": [
                    "TA0011"
                ],
                "PrimarySource": "BEHAVIOR",
                "StaticOnly": false
            },
            {
                "Id": "T1027",
                "Name": "Obfuscated Files or Information",
                "Url": "https://attack.mitre.org/techniques/T1027/",
                "Level": "SUSPICIOUS",
                "Tactics": [
                    "TA0005"
                ],
                "PrimarySource": "STATIC",
                "StaticOnly": true
            }
        ],
        "Tactics": [
            {
                "id": "TA0011",
                "name": "Command and Control"
            }
        ]
    }
}
```
#### Human Readable Output

>### MITRE ATT&CK techniques for report 412839
>|Level|Name|Technique|
>|---|---|---|
>| MALICIOUS | Application Layer Protocol | T1071 |
>| SUSPICIOUS | Obfuscated Files or Information | T1027 |

### tlab-get-pcap

***
Retrieve the network capture of a dynamic analysis, either as a PCAP file or as the analyzer's JSON report.

#### Base Command

`tlab-get-pcap`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dyn_report_id | Dynamic analysis report ID. | Required | 
| format | pcap returns the capture file; json returns the analyzer report. Possible values are: pcap, json. Default is pcap. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.PcapReport.DynReportId | Number | Dynamic report the capture belongs to. | 
| InfoFile.Name | String | Name of the returned file. | 
| InfoFile.EntryID | String | War room entry ID of the returned file. | 

### tlab-get-report-pdf

***
Render and download the PDF report for a sample.

#### Base Command

`tlab-get-report-pdf`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_report_id | Report ID in tLab Anti-APT. | Required | 
| timeout | Seconds to wait for the synchronous render. Default is 180. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | String | Name of the returned PDF. | 
| InfoFile.EntryID | String | War room entry ID of the returned PDF. | 

### tlab-list-env-presets

***
List the dynamic analysis environment presets available on the server.

#### Base Command

`tlab-list-env-presets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | Which preset scope to list. Possible values are: global, user. Default is global. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.EnvPreset.Name | String | Preset name accepted by the env_preset argument. | 

#### Command example
```!tlab-list-env-presets scope=global```
#### Context Example
```json
{
    "TLabAntiAPT.EnvPreset(val.Name && val.Name == obj.Name)": [
        {
            "Name": "win10",
            "Scope": "global"
        },
        {
            "Name": "win7",
            "Scope": "global"
        }
    ]
}
```
#### Human Readable Output

>### tLab Anti-APT global environment presets
>|Name|Scope|
>|---|---|
>| win10 | global |
>| win7 | global |

### tlab-list-sources

***
List submission sources registered on the server, with their IDs.

#### Base Command

`tlab-list-sources`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.Source.SourceId | Number | Numeric source ID, usable in report filters. | 
| TLabAntiAPT.Source.Type | String | Source type display code, for example "Cortex XSOAR". | 

#### Command example
```!tlab-list-sources```
#### Context Example
```json
{
    "TLabAntiAPT.Source(val.SourceId && val.SourceId == obj.SourceId)": [
        {
            "SourceId": 12,
            "Type": "Cortex XSOAR",
            "Uid": "u"
        }
    ]
}
```
#### Human Readable Output

>### tLab Anti-APT submission sources
>|SourceId|Type|Uid|
>|---|---|---|
>| 12 | Cortex XSOAR | u |
