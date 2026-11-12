Look up file reputation and past analyses in tLab Anti-APT without submitting anything.
This integration was developed against the tLab Anti-APT API of sandbox-core 1.13.0.

## Configure tLab Anti-APT Lookup in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL of the tLab Anti-APT sandbox API \(tlab-server\). Through the tLab web server use https://&lt;tlab-host&gt;/api; for a direct connection use http://&lt;tlab-host&gt;:8080. | True |
| Auth server URL (tlab-auth) | Used by the tLab account mode. Where the integration logs in to tlab-auth. Leave empty to use https://&lt;Server URL host&gt;:8002/api, the omni-center portal, which forwards /api to tlab-auth over TLS; if its certificate is self-signed, enable Trust any certificate. Not https://&lt;host&gt;/api, which is the sandbox API itself. | False |
| Authentication mode | tLab account \(tlab-auth\) is recommended: the integration logs in to tlab-auth like the omni-center portal and sends the token as Bearer. Source key needs the source-key gateway \(balancer\) and covers submissions only. Username and password is the legacy tlab-server sign-in. Internal token works only when Cortex XSOAR runs on the tlab-server host itself. | True |
| Credentials | Login and password of a tLab account \(tLab account mode\). This integration only reads, so it can use a restricted account: the user role is sufficient. Turn off password expiry for this account: tlab-auth rejects an expired password and every command starts failing. | True |
| Password / source key / internal token | The password of the tLab account, or the source key or internal token, depending on the authentication mode. | True |
| Use system proxy settings | Whether to use the Cortex XSOAR server's system proxy settings. | False |
| Trust any certificate (not secure) | Whether to skip TLS certificate verification. Needed when the tLab certificate is self-signed. | False |
| Client name | Sent as the X-Client header. | False |
| Source reliability | Reliability attached to every DBotScore this integration produces. | False |
| Report completeness to consider | Only reports with these completeness values are used for reputation. Defaults to COMPLETE so a partial analysis does not produce a verdict. | False |
| Reports per hash | How many past analyses to return per hash. The newest is used for the verdict. | False |
| Treat an unknown verdict as benign | Off by default. "tLab has no record" is not the same statement as "this file is benign", and a Good score would suppress other vendors' findings. | False |
| Suspicious score threshold | Scores from this value up to the malicious threshold are Suspicious. Fractional values are allowed. Default is 50, the product default. | False |
| Malicious score threshold | Scores at or above this value are Malicious. Fractional values are allowed. Default is 85, the product default. | False |

## Search filters and roles

`tlab-search-reports` accepts filters that the server applies only for accounts
with the `admin` or `developer` role: verdict, score level, source, root-only,
minimum report ID, minimum score and file name. With a lower role these are
discarded without an error, so a narrow query silently returns everything. The
command adds a warning to its output whenever one of them is used.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### file

***
Return the tLab Anti-APT reputation of one or more file hashes. Accepts full MD5, SHA1 or SHA256 hashes.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Comma-separated list of full file hashes. Partial hashes are skipped, because the server matches hash filters by prefix and a short value would match unrelated samples. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.File.HashSha256 | String | SHA256 of the file as recorded by tLab Anti-APT. | 
| TLabAntiAPT.File.Verdict | String | Canonical verdict - MALWARE, SUSPICIOUS, OK, CLEAN, WHITELIST or UNKNOWN. | 
| TLabAntiAPT.File.ScoreLevel | String | Raw ScoreLevel value as returned by the server, where MALICIOUS means MALWARE. | 
| TLabAntiAPT.File.FileVerdict | String | Verdict set manually in tLab for this file. Absent while nobody has set it; not the analysis result, which is in Verdict. | 
| TLabAntiAPT.File.Score | Number | Sample score of the analysis used for the verdict. | 
| TLabAntiAPT.File.SampleReportId | Number | Report the verdict was taken from. | 
| TLabAntiAPT.File.AnalyzedAt | Date | The date when the sample was analyzed in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| TLabAntiAPT.File.Found | Boolean | Whether tLab Anti-APT has an analysis for this hash. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | Vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| File.MD5 | String | MD5 of the file. | 
| File.SHA1 | String | SHA1 of the file. | 
| File.SHA256 | String | SHA256 of the file. | 
| File.Name | String | Name the file was analyzed under. | 
| File.Size | Number | Size of the file in bytes. | 
| File.Type | String | File type as detected by tLab Anti-APT. | 
| File.Malicious.Vendor | String | Vendor that decided the file is malicious. | 

#### Command example
```!file file=aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999```
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
    "TLabAntiAPT.File(val.HashSha256 && val.HashSha256 == obj.HashSha256)": {
        "SampleReportId": 412839,
        "HashSha256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
        "HashSha1": "aaaabbbbccccddddeeeeffff0000111122223333",
        "HashMd5": "aaaabbbbccccddddeeeeffff00001111",
        "Size": 2048,
        "FileType": "PE",
        "UploadedFilename": "invoice.exe",
        "Verdict": "MALWARE",
        "ScoreLevel": "MALICIOUS",
        "FileVerdict": "MALWARE",
        "Score": 91.5,
        "Completeness": "COMPLETE",
        "AnalyzedAt": "2026-03-26T08:00:00Z",
        "Found": true
    }
}
```
#### Human Readable Output

>### tLab Anti-APT reputation for aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999
>|Analyzed at|File name|Report ID|Score|Verdict|
>|---|---|---|---|---|
>| 2026-03-26T08:00:00Z | invoice.exe | 412839 | 91.5 | MALWARE |

### tlab-file-scan-result

***
Return past tLab Anti-APT analyses of a hash, with more detail than the reputation command.

#### Base Command

`tlab-file-scan-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | Full MD5, SHA1 or SHA256 hash. | Required | 
| hash_type | Hash type. Detected from the value when omitted. Possible values are: md5, sha1, sha256. | Optional | 
| limit | Maximum number of analyses to return, newest first. Default is 1. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.ScanResult.SampleReportId | Number | Report ID in tLab Anti-APT. | 
| TLabAntiAPT.ScanResult.Verdict | String | Canonical verdict. | 
| TLabAntiAPT.ScanResult.Score | Number | Sample score. | 
| TLabAntiAPT.ScanResult.Found | Boolean | Whether any analysis exists for the hash. | 

#### Command example
```!tlab-file-scan-result hash=aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999```
#### Context Example
```json
{
    "TLabAntiAPT.ScanResult(val.SampleReportId && val.SampleReportId == obj.SampleReportId)": [
        {
            "SampleReportId": 412839,
            "HashSha256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "HashSha1": "aaaabbbbccccddddeeeeffff0000111122223333",
            "HashMd5": "aaaabbbbccccddddeeeeffff00001111",
            "Size": 2048,
            "FileType": "PE",
            "UploadedFilename": "invoice.exe",
            "Verdict": "MALWARE",
            "ScoreLevel": "MALICIOUS",
            "FileVerdict": "MALWARE",
            "Score": 91.5,
            "Completeness": "COMPLETE",
            "AnalyzedAt": "2026-03-26T08:00:00Z",
            "Found": true
        }
    ]
}
```
#### Human Readable Output

>### tLab Anti-APT scan results for aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999
>|AnalyzedAt|Completeness|FileType|FileVerdict|Found|HashMd5|HashSha1|HashSha256|SampleReportId|Score|ScoreLevel|Size|UploadedFilename|Verdict|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2026-03-26T08:00:00Z | COMPLETE | PE | MALWARE | true | aaaabbbbccccddddeeeeffff00001111 | aaaabbbbccccddddeeeeffff0000111122223333 | aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999 | 412839 | 91.5 | MALICIOUS | 2048 | invoice.exe | MALWARE |

### tlab-file-info

***
Return stored metadata and the analyst verdict for a file, without any analysis context.

#### Base Command

`tlab-file-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | Full 64-character SHA256 hash. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.FileInfo.FileVerdict | String | Verdict set manually in tLab for this file. Absent while nobody has set it; not the analysis result, which is in Verdict. | 
| TLabAntiAPT.FileInfo.FileType | String | File type as detected by tLab Anti-APT. | 
| TLabAntiAPT.FileInfo.Signed | Boolean | Whether the file carries a digital signature. | 

#### Command example
```!tlab-file-info sha256=aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999```
#### Context Example
```json
{
    "TLabAntiAPT.FileInfo(val.HashSha256 && val.HashSha256 == obj.HashSha256)": {
        "HashSha256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
        "HashSha1": "aaaabbbbccccddddeeeeffff0000111122223333",
        "HashMd5": "aaaabbbbccccddddeeeeffff00001111",
        "Size": 2048,
        "FileType": "PE",
        "MimeType": "application/x-dosexec",
        "InferredExtension": "exe",
        "FileVerdict": "MALWARE",
        "Signed": false,
        "DigitalSignatureCount": 0
    }
}
```
#### Human Readable Output

>### tLab Anti-APT file aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999
>|DigitalSignatureCount|FileType|FileVerdict|HashMd5|HashSha1|HashSha256|InferredExtension|MimeType|Signed|Size|
>|---|---|---|---|---|---|---|---|---|---|
>| 0 | PE | MALWARE | aaaabbbbccccddddeeeeffff00001111 | aaaabbbbccccddddeeeeffff0000111122223333 | aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999 | exe | application/x-dosexec | false | 2048 |

### tlab-search-reports

***
Search past analyses. Note that verdict, score, source and root filters are applied only for accounts with the admin or developer role; a lower role has them discarded without an error.

#### Base Command

`tlab-search-reports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date_from | Start of the creation-time range, for example 2026-09-01 or 2026-09-01T00:00:00Z. | Optional | 
| date_to | End of the creation-time range. | Optional | 
| completeness | Report completeness values to include. Possible values are: COMPLETE, PARTIALLY_COMPLETE, EMPTY. | Optional | 
| status | Report status values to include. Possible values are: ACTIVE, DELETED. | Optional | 
| file_verdict | Filter by stored file verdict. Requires the admin or developer role. Possible values are: UNKNOWN, SUSPICIOUS, MALWARE, OK, WHITELIST. | Optional | 
| score_level | Filter by score level. Requires the admin or developer role. Possible values are: UNKNOWN, SUSPICIOUS, MALICIOUS, OK, CLEAN, WHITELIST. | Optional | 
| file_type | Filter by file type. | Optional | 
| source_id | Filter by submission source ID. Requires the admin or developer role. | Optional | 
| tags | Filter by analysis tags. | Optional | 
| indicators | Filter by indicator codes. Use tlab-list-indicator-codes to discover them. | Optional | 
| root_only | Whether to return only root reports. Requires the admin or developer role. Possible values are: true, false. | Optional | 
| min_report_id | Return reports with an ID greater than or equal to this value. Requires the admin or developer role. | Optional | 
| min_score | Minimum sample score. Requires the admin or developer role. | Optional | 
| file_name | Filter by uploaded file name. Requires the admin or developer role. | Optional | 
| file_hash_sha256 | Filter by SHA256. Matched by prefix on the server. | Optional | 
| file_hash_sha1 | Filter by SHA1. Matched by prefix on the server. | Optional | 
| sort | Sort key. Allowed fields: reportTime, updateTime, sampleReportId, sampleScore, size. Note that createTime is not valid and is silently ignored by the server, so it is rejected here. Default is sampleReportId,desc. | Optional | 
| page | Zero-based page number. Default is 0. | Optional | 
| limit | Maximum number of reports to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.Report.SampleReportId | Number | Report ID in tLab Anti-APT. | 
| TLabAntiAPT.Report.Verdict | String | Canonical verdict. | 
| TLabAntiAPT.Report.Score | Number | Sample score. | 
| TLabAntiAPT.Report.HashSha256 | String | SHA256 of the analyzed sample. | 

#### Command example
```!tlab-search-reports limit=1 root_only=true```
#### Context Example
```json
{
    "TLabAntiAPT.Report(val.SampleReportId && val.SampleReportId == obj.SampleReportId)": [
        {
            "SampleReportId": 412839,
            "HashSha256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "HashSha1": "aaaabbbbccccddddeeeeffff0000111122223333",
            "HashMd5": "aaaabbbbccccddddeeeeffff00001111",
            "Size": 2048,
            "FileType": "PE",
            "UploadedFilename": "invoice.exe",
            "Verdict": "MALWARE",
            "ScoreLevel": "MALICIOUS",
            "FileVerdict": "MALWARE",
            "Score": 91.5,
            "Completeness": "COMPLETE",
            "AnalyzedAt": "2026-03-26T08:00:00Z",
            "Found": true
        }
    ]
}
```
#### Human Readable Output

>### tLab Anti-APT reports (1 total)
>|AnalyzedAt|Completeness|FileType|FileVerdict|Found|HashMd5|HashSha1|HashSha256|SampleReportId|Score|ScoreLevel|Size|UploadedFilename|Verdict|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2026-03-26T08:00:00Z | COMPLETE | PE | MALWARE | true | aaaabbbbccccddddeeeeffff00001111 | aaaabbbbccccddddeeeeffff0000111122223333 | aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999 | 412839 | 91.5 | MALICIOUS | 2048 | invoice.exe | MALWARE |

### tlab-hash-search

***
Find stored files whose hash starts with the given prefix.

#### Base Command

`tlab-hash-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash_type | Which hash to search. Possible values are: md5, sha1, sha256. | Required | 
| hash_part | Hash prefix, at least 3 characters. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.HashSearch.HashValue | String | Matching hash value. | 
| TLabAntiAPT.HashSearch.FileVerdict | String | Verdict set manually in tLab for this file. Absent while nobody has set it; not the analysis result, which is in Verdict. | 

#### Command example
```!tlab-hash-search hash_type=md5 hash_part=aaaabbbb```
#### Context Example
```json
{
    "TLabAntiAPT.HashSearch(val.HashValue && val.HashValue == obj.HashValue)": [
        {
            "HashValue": "aaaabbbbccccddddeeeeffff00001111",
            "HashType": "md5",
            "FileType": "PE",
            "FileVerdict": "MALWARE"
        }
    ]
}
```
#### Human Readable Output

>### tLab Anti-APT hash search for md5 starting with aaaabbbb
>|FileType|FileVerdict|HashType|HashValue|
>|---|---|---|---|
>| PE | MALWARE | md5 | aaaabbbbccccddddeeeeffff00001111 |

### tlab-list-indicator-codes

***
List the indicator code catalog, usable with the indicators filter of tlab-search-reports.

#### Base Command

`tlab-list-indicator-codes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| analysis_type | Return only codes belonging to this analysis type. Possible values are: STAT_ANALYSIS, DYN_ANALYSIS, AV_ANALYSIS, CODE_ANALYSIS. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TLabAntiAPT.IndicatorCode.Code | Number | Numeric indicator code. | 
| TLabAntiAPT.IndicatorCode.Name | String | Indicator name. | 
| TLabAntiAPT.IndicatorCode.AnalysisType | String | Analysis type the code belongs to. | 

#### Command example
```!tlab-list-indicator-codes```
#### Context Example
```json
{
    "TLabAntiAPT.IndicatorCode(val.Code && val.Code == obj.Code)": [
        {
            "Code": 9,
            "Name": "PUBLIC_SIGNATURES",
            "AnalysisType": "STAT_ANALYSIS"
        },
        {
            "Code": 6,
            "Name": "INET_CONNECT",
            "AnalysisType": "DYN_ANALYSIS"
        }
    ]
}
```
#### Human Readable Output

>### tLab Anti-APT indicator codes
>|AnalysisType|Code|Name|
>|---|---|---|
>| STAT_ANALYSIS | 9 | PUBLIC_SIGNATURES |
>| DYN_ANALYSIS | 6 | INET_CONNECT |
