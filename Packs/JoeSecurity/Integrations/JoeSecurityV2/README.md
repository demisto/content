Access the full set of possibilities the Joe Sandbox Cloud provides via RESTful Web API v2.
This integration was integrated and tested with version 3.18.0 of [jbxapi](https://github.com/joesecurity/jbxapi).

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes).

## Configure Joe Security v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Joe Security v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | API Key |  | True |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Create relationships | Create relationships between indicators as part of Enrichment. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

**Note**: Most of the commands have the *full_display* boolean argument that when set to true, indicators information, including their DBot Scores, will be displayed.   


### joe-is-online
***
Check if the Joe Sandbox analysis server is online or in maintenance mode.


#### Base Command

`joe-is-online`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Joe.ServerStatus.Online | Boolean | The server status. | 

#### Command example
```!joe-is-online```
#### Context Example
```json
{
    "Joe": {
        "ServerStatus": {
            "Online": true
        }
    }
}
```

#### Human Readable Output

>Joe server is online

### joe-analysis-info
***
Get information about an analysis.


#### Base Command

`joe-analysis-info`
#### Input

| **Argument Name** | **Description**  | **Required** |
| --- |-------| --- |
| webid | The analysis web ID.      | Required | 
| full_display | When set to true, indicators information, including their DBot Scores, will be displayed. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| File.Hashes.type | String | The hash type. | 
| File.Hashes.value | String | The hash value. | 
| File.Name | String | The full file name. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| URL.Data | String | The URL. | 
| Joe.Analysis.AnalysisID | String | The analysis ID Joe Security. | 
| Joe.Analysis.Classification | String | The classification of the analysis. | 
| Joe.Analysis.Comments | String | Comments regarding the analysis. | 
| Joe.Analysis.detection | String | The analysis detection. Can be one of unknown, clean, suspicious, malicious. | 
| Joe.Analysis.duration | Number | The duration of the analysis in seconds. | 
| Joe.Analysis.encrypted | Boolean | True if the analysis data is encrypted. | 
| Joe.Analysis.filename | String | The file name of the analysis. | 
| Joe.Analysis.md5 | String | The file MD5. | 
| Joe.Analysis.runs.detection | String | The run detection. Can be one of unknown, clean, suspicious, malicious. | 
| Joe.Analysis.runs.error | Unknown | The run errors. | 
| Joe.Analysis.runs.score | Number | The run score. | 
| Joe.Analysis.runs.sigma | Boolean | The run sigma. | 
| Joe.Analysis.runs.snort | Boolean | The run snort. | 
| Joe.Analysis.runs.system | String | The run operation system. | 
| Joe.Analysis.runs.yara | Boolean | The run YARA. | 
| Joe.Analysis.score | Number | The run score. | 
| Joe.Analysis.scriptname | String | The run script name. | 
| Joe.Analysis.sha1 | String | The file SHA1. | 
| Joe.Analysis.sha256 | String | The file SHA256. | 
| Joe.Analysis.status | String | The status is one of submitted, running, finished. | 
| Joe.Analysis.threatname | String | The analysis threat name. | 
| Joe.Analysis.time | Date | The analysis time. | 
| Joe.Analysis.webid | String | The web ID from Joe Security. | 

#### Command example
```!joe-analysis-info webid=2722073```
#### Context Example
```json
{
    "Joe": {
        "Analysis": [
            {
                "analysisid": "1",
                "classification": "",
                "comments": "(example)",
                "detection": "clean",
                "duration": 558,
                "encrypted": false,
                "filename": "test_file.txt",
                "md5": "11111111111111111111111111111111",
                "runs": [
                    {
                        "detection": "clean",
                        "error": null,
                        "score": 1,
                        "sigma": false,
                        "snort": false,
                        "system": "w10x64_21h1_office",
                        "yara": false
                    },
                    {
                        "detection": "clean",
                        "error": null,
                        "score": 0,
                        "sigma": false,
                        "snort": false,
                        "system": "w7x64_office",
                        "yara": false
                    }
                ],
                "score": 1,
                "scriptname": "example.jbs",
                "sha1": "1111111111111111111111111111111111111111",
                "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                "status": "finished",
                "tags": [],
                "threatname": "Unknown",
                "time": "2022-09-15T10:57:20+02:00",
                "webid": "1111111"
            }
        ]
    }
}
```

#### Human Readable Output

>### Analysis Result:
>|Id|SampleName|Status|Time|MD5|SHA1|SHA256|Systems|Result|Errors|Comments|
>|---|---|---|---|---|---|---|---|---|---|---|
>|1| test_file.txt | finished | 2022-09-15T10:57:20+02:00 | 11111111111111111111111111111111 | 1111111111111111111111111111111111111111 | 1111111111111111111111111111111111111111111111111111111111111111 | w7x64_office,<br/>w10x64_21h1_office | clean | None | (example) |


### joe-list-analysis
***
Lists all analyses.


#### Base Command

`joe-list-analysis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number to display. | Optional | 
| page_size | Determine how many entries to display on each page. | Optional | 
| limit | Limit the number of entries to display. Default is 50. | Optional | 
| full_display | When set to true, indicators information, including their DBot Scores, will be displayed. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| File.Hashes.type | String | The hash type. | 
| File.Hashes.value | String | The hash value. | 
| File.Name | String | The full file name. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| URL.Data | String | The URL. | 
| Joe.Analysis.AnalysisID | String | The analysis ID. | 
| Joe.Analysis.Classification | String | The classification of the analysis. | 
| Joe.Analysis.Comments | String | Comments regarding the analysis. | 
| Joe.Analysis.detection | String | The analysis detection. Can be one of unknown, clean, suspicious, malicious. | 
| Joe.Analysis.duration | Number | The duration of the analysis in seconds. | 
| Joe.Analysis.encrypted | Boolean | True if the analysis data is encrypted. | 
| Joe.Analysis.filename | String | The file name of the analysis. | 
| Joe.Analysis.md5 | String | The file MD5. | 
| Joe.Analysis.runs.detection | String | The run detection. Can be one of unknown, clean, suspicious, malicious. | 
| Joe.Analysis.runs.error | Unknown | The run errors. | 
| Joe.Analysis.runs.score | Number | The run score. | 
| Joe.Analysis.runs.sigma | Boolean | The run sigma. | 
| Joe.Analysis.runs.snort | Boolean | The run snort. | 
| Joe.Analysis.runs.system | String | The run operation system. | 
| Joe.Analysis.runs.yara | Boolean | The run YARA. | 
| Joe.Analysis.score | Number | The run score. | 
| Joe.Analysis.scriptname | String | The run script name. | 
| Joe.Analysis.sha1 | String | The file SHA1. | 
| Joe.Analysis.sha256 | String | The file SHA256. | 
| Joe.Analysis.status | String | The status is one of submitted, running, finished. | 
| Joe.Analysis.threatname | String | The analysis threat name. | 
| Joe.Analysis.time | Date | The analysis time. | 
| Joe.Analysis.webid | String | The web ID from Joe Security. | 

#### Command example
```!joe-list-analysis limit=1```
#### Context Example
```json
{
    "Joe": {
        "Analysis": [
            {
                "analysisid": "1",
                "classification": "",
                "comments": "(example)",
                "detection": "clean",
                "duration": 558,
                "encrypted": false,
                "filename": "test_file.txt",
                "md5": "11111111111111111111111111111111",
                "runs": [
                    {
                        "detection": "clean",
                        "error": null,
                        "score": 1,
                        "sigma": false,
                        "snort": false,
                        "system": "w10x64_21h1_office",
                        "yara": false
                    },
                    {
                        "detection": "clean",
                        "error": null,
                        "score": 0,
                        "sigma": false,
                        "snort": false,
                        "system": "w7x64_office",
                        "yara": false
                    }
                ],
                "score": 1,
                "scriptname": "example.jbs",
                "sha1": "1111111111111111111111111111111111111111",
                "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                "status": "finished",
                "tags": [],
                "threatname": "Unknown",
                "time": "2022-09-15T10:57:20+02:00",
                "webid": "1111111"
            }
        ]
    }
}
```

#### Human Readable Output

>### Analysis Result:
>|Id|SampleName|Status|Time|MD5|SHA1|SHA256|Systems|Result|Errors|Comments|
>|---|---|---|---|---|---|---|---|---|---|---|
>|1| test_file.txt | finished | 2022-09-15T10:57:20+02:00 | 11111111111111111111111111111111 | 1111111111111111111111111111111111111111 | 1111111111111111111111111111111111111111111111111111111111111111 | w7x64_office,<br/>w10x64_21h1_office | clean | None | (example) |


### joe-download-report
***
Download a resource belonging to a report. This can be the full report, dropped binaries, etc. See the integration README for the full list of supported report types.


#### Base Command

`joe-download-report`
#### Input

| **Argument Name** | **Description**     | **Required** |
| --- |----------| --- |
| webid | The Web ID.      | Required | 
| type | The resource type to download. Possible values are: html, json, pcap, pdf, xml, iocjson. Default is html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | Filename. | 
| InfoFile.EntryID | string | The entry ID of the report | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type. e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| File.Extension | string | File extension. | 

#### Command example
```!joe-download-report webid=1```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "111@",
        "Extension": "html",
        "Info": "text/html; charset=utf-8",
        "Name": "1_report.html",
        "Size": 3823558,
        "Type": "HTML document, ASCII text, with very long lines"
    }
}
```

#### Human Readable Output

>Returned file: 1_report.html Download


### joe-download-sample
***
Download a sample.


#### Base Command

`joe-download-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| webid | Web ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | File size. | 
| File.SHA1 | string | SHA1 hash of the file | 
| File.SHA256 | string | SHA256 hash of the file | 
| File.Name | string | The sample name. | 
| File.SSDeep | string | SSDeep hash of the file. | 
| File.EntryID | string | War.Room entry ID of the file. | 
| File.Info | string | Basic information of the file | 
| File.Type | string | File type, e.g., "PE". | 
| File MD5 | string | MD5 hash of the file. | 
| File.Extension | string | File extension. | 

#### Command example
```!joe-download-sample webid=2722073```
#### Context Example
```json
{
    "File": {
        "EntryID": "111@",
        "Extension": "dontrun",
        "Info": "dontrun",
        "MD5": "11111111111111111111111111111111",
        "Name": "1.dontrun",
        "SHA1": "1111111111111111111111111111111111111111",
        "SHA256": "1111111111111111111111111111111111111111111111111111111111111111",
        "SHA512": "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        "SSDeep": "3:PFoESNt/FPl2X1sjO3//lGF/llllBl9SLEZWxIUclll7D8/+l/AltdUshMl//:PgG2s/RIUctM/+l/MusKl//",
        "Size": 276,
        "Type": "AppleDouble encoded Macintosh file"
    }
}
```

#### Human Readable Output

>Uploaded file: 1.dontrun Download


### file
***
Retrieves files information from Joe Security.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A comma-separated list of file names, SHA1, SHA256, or MD5 hashes. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | Name of the file. | 
| File.MD5 | String | MD5 hash of the file. | 
| File.SHA1 | String | SHA1 hash of the file. | 
| File.SHA256 | String | SHA256 hash of the file. | 
| File.Tags | String | Tags of the file. | 
| File.Name | String | Name of the file. | 
| Joe.File.MD5 | String | MD5 hash of the file. | 
| Joe.File.SHA1 | String | SHA1 hash of the file. | 
| Joe.File.SHA256 | String | SHA256 hash of the file. | 
| Joe.File.Tags | String | Tags of the file. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

#### Command example
```!file file=example```
#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "example",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "file",
            "Vendor": "JoeSecurityV2"
        }
    ],
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "11111111111111111111111111111111"
            },
            {
                "type": "SHA1",
                "value": "1111111111111111111111111111111111111111"
            },
            {
                "type": "SHA256",
                "value": "1111111111111111111111111111111111111111111111111111111111111111"
            }
        ],
        "MD5": "11111111111111111111111111111111",
        "Name": "example",
        "SHA1": "1111111111111111111111111111111111111111",
        "SHA256": "1111111111111111111111111111111111111111111111111111111111111111"
    },
    "Joe": {
      "File Name": "example",
      "MD5": "11111111111111111111111111111111",
      "SHA1": "1111111111111111111111111111111111111111",
      "SHA256": "1111111111111111111111111111111111111111111111111111111111111111"
    }
}
```

#### Human Readable Output

>### File Result:
>|File Name| Sha1 |Sha256|Md5|
>|---|---|---|---|
>|example| 1111111111111111111111111111111111111111 | 1111111111111111111111111111111111111111111111111111111111111111 | 11111111111111111111111111111111 |


### url
***
Retrieves URL information from Joe Security.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs. | Required | 


#### Context Output

| **Path** | **Type** | **Description**                                            |
|---| --- |---|
| URL.Data | String | The URL data.                                       | 
| Joe.URL.Name | String | Name of the URL.                                           | 
| DBotScore.Indicator | String | The indicator that was tested.                             | 
| DBotScore.Score | Number | The actual score.                                          | 
| DBotScore.Type | String | The indicator type.                                        | 
| DBotScore.Vendor | String | The vendor used to calculate the score.                    | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

#### Command example
```!url url=http://google.com```
#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "http://google.com",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "url",
            "Vendor": "JoeSecurityV2"
        }
    ],
    "Joe": {
        "URL": "http://google.com"
    },
    "URL": {
        "Data": "http://google.com"
    }
}
```

#### Human Readable Output

>### Url Result:
>|Url|
>|---|
>| http:<span>//</span>google.com |


### joe-list–lia-countries
***
Retrieve a list of localized internet anonymization countries.


#### Base Command

`joe-list–lia-countries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Joe.LIACountry | String | A list of localized internet anonymization countries. | 

#### Command example
```!joe-list–lia-countries```
#### Context Example
```json
{
    "Joe": {
        "LIACountry": [
            "Argentina",
            "Australia",
            "Austria",
            "Belgium",
            "Brazil"
        ]
    }
}
```

#### Human Readable Output

>### Results:
>|Name|
>|---|
>| Argentina |
>| Australia |
>| Austria |
>| Belgium |
>| Brazil |



### joe-list-lang-locales
***
Retrieve a list of available language and locale combinations.


#### Base Command

`joe-list-lang-locales`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Joe.LangLocale | String | A list of available language and locale combinations. | 

#### Command example
```!joe-list-lang-locales```
#### Context Example
```json
{
    "Joe": {
        "LangLocale": [
            "Arabic - Egypt",
            "Arabic - Qatar",
            "Arabic - Saudi Arabia",
            "Chinese - PRC",
            "Chinese - Taiwan",
            "English - Australia"
        ]
    }
}
```

#### Human Readable Output

>### Results:
>|Name|
>|---|
>| Arabic - Egypt |
>| Arabic - Qatar |
>| Arabic - Saudi Arabia |
>| Chinese - PRC |
>| Chinese - Taiwan |
>| English - Australia |


### joe-get-account-quota
***
Retrieve the account quota.


#### Base Command

`joe-get-account-quota`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Joe.AccountQuota | String | The account quota. | 
| Joe.AccountQuota.quota.daily.current | Number | The current daily quota. | 
| Joe.AccountQuota.quota.daily.limit | Number | The daily quota limit. | 
| Joe.AccountQuota.quota.daily.remaining | Number | The remaining daily quota. | 
| Joe.AccountQuota.quota.monthly.current | Number | The current monthly quota. | 
| Joe.AccountQuota.quota.monthly.limit | Number | The monthly quota limit. | 
| Joe.AccountQuota.quota.monthly.remaining | Number | The remaining monthly quota. | 
| Joe.AccountQuota.type | String | The quota type. | 

#### Command example
```!joe-get-account-quota```
#### Context Example
```json
{
    "Joe": {
        "AccountQuota": {
            "quota": {
                "daily": {
                    "current": 0,
                    "limit": 100,
                    "remaining": 100
                },
                "monthly": {
                    "current": 150,
                    "limit": 250,
                    "remaining": 100
                }
            },
            "type": "ultimate"
        }
    }
}
```

#### Human Readable Output

>### Results:
>|Quota Type|Daily Quota Current|Daily Quota Limit|Daily Quote Remaining| Monthly Quota Current |Monthly Quota Limit| Monthly Quota Remaining |
>|---|---|---|---|---|---|---|
>| ultimate | 0 | 100 | 100 | 150 | 250 | 100 |


### joe-submission-info
***
Retrieve the submission info.


#### Base Command

`joe-submission-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_ids | A comma-separated list of submission IDs. | Required | 
| full_display | When set to true, indicators information, including their DBot Scores, will be displayed. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| File.Hashes.type | String | The hash type. | 
| File.Hashes.value | String | The hash value. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Name | String | The full file name. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| URL.Data | String | The URL. | 
| Joe.Analysis.AnalysisID | String | The analysis ID. | 
| Joe.Analysis.Classification | String | The classification. | 
| Joe.Analysis.Comments | String | The comments. | 
| Joe.Analysis.detection | String | The detection. | 
| Joe.Analysis.duration | Number | The duration. | 
| Joe.Analysis.encrypted | Boolean | Whether the analysis is encrypted. | 
| Joe.Analysis.filename | String | The filename. | 
| Joe.Analysis.runs.detection | String | The detection. | 
| Joe.Analysis.runs.error | Unknown | The error. | 
| Joe.Analysis.runs.score | Number | The score. | 
| Joe.Analysis.runs.sigma | Boolean | The sigma. | 
| Joe.Analysis.runs.snort | Boolean | The snort. | 
| Joe.Analysis.runs.system | String | The system. | 
| Joe.Analysis.runs.yara | Boolean | The YARA. | 
| Joe.Analysis.score | Number | The score. | 
| Joe.Analysis.scriptname | String | The script name. | 
| Joe.Analysis.status | String | The status. | 
| Joe.Analysis.threatname | String | The threat name. | 
| Joe.Analysis.time | Date | The time. | 
| Joe.Analysis.webid | String | The web ID. | 
| Joe.Submission.most_relevant_analysis.detection | String | The detection. | 
| Joe.Submission.most_relevant_analysis.score | Number | The score. | 
| Joe.Submission.most_relevant_analysis.webid | String | The web ID. | 
| Joe.Submission.name | String | The name. | 
| Joe.Submission.status | String | The status. | 
| Joe.Submission.submission_id | String | The submission ID. | 
| Joe.Submission.time | Date | The time. | 

#### Command example
```!joe-submission-info submission_ids=1111111```
#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "example.txt",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "file",
            "Vendor": "JoeSecurityV2"
        }
    ],
    "File": [
        {
            "Hashes": [
                {
                    "type": "MD5",
                    "value": "11111111111111111111111111111111"
                },
                {
                    "type": "SHA1",
                    "value": "1111111111111111111111111111111111111111"
                },
                {
                    "type": "SHA256",
                    "value": "1111111111111111111111111111111111111111111111111111111111111111"
                }
            ],
            "MD5": "11111111111111111111111111111111",
            "Name": "example.txt",
            "SHA1": "1111111111111111111111111111111111111111",
            "SHA256": "1111111111111111111111111111111111111111111111111111111111111111"
        }
    ],
    "Joe": {
        "Analysis": [
            {
                "analysisid": "1",
                "classification": "",
                "comments": "example comment",
                "detection": "clean",
                "duration": 500,
                "encrypted": false,
                "filename": "example.txt",
                "md5": "11111111111111111111111111111111",
                "runs": [
                    {
                        "detection": "clean",
                        "error": null,
                        "score": 1,
                        "sigma": false,
                        "snort": false,
                        "system": "w10x64_21h1_office",
                        "yara": false
                    },
                    {
                        "detection": "clean",
                        "error": null,
                        "score": 0,
                        "sigma": false,
                        "snort": false,
                        "system": "w7x64_office",
                        "yara": false
                    }
                ],
                "score": 1,
                "scriptname": "example.jbs",
                "sha1": "1111111111111111111111111111111111111111",
                "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                "status": "finished",
                "tags": [],
                "threatname": "Unknown",
                "time": "2022-09-15T10:57:20+02:00",
                "webid": "1"
            }
        ],
        "Submission": {
            "most_relevant_analysis": {
                "detection": "clean",
                "score": 1,
                "webid": "1"
            },
            "name": "example.zip",
            "status": "finished",
            "submission_id": "1111111",
            "time": "2022-09-15T10:57:14+02:00"
        }
    }
}
```

#### Human Readable Output

>### Submission Results:
>|Submission Id|Sample Name|Time|Status|Web Id|Encrypted|Analysis Id|Classification|Threat Name|Score|Detection|SHA256|MD5|SHA1|File Name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | example.zip | 2022-09-15T10:57:14+02:00 | finished | 1 | false | 1 |  | Unknown | 1 | clean | 1111111111111111111111111111111111111111111111111111111111111111 | 11111111111111111111111111111111 | 1111111111111111111111111111111111111111 | example.txt |


### joe-submit-sample
***
Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.
 


#### Base Command

`joe-submit-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the file to submit. | Required | 
| file_name | The filename of the submitted sample | Optional |
| full_display | When set to true, indicators information, including their DBot Scores, will be displayed. Possible values are: true, false. Default is true. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 1200. | Optional | 
| hide_polling_output | Hide polling output. | Optional | 
| report_type | The report type. Possible values are: html, json, pcap, pdf, xml, iocjson. Default is html. | Optional | 
| cookbook | Uploads a cookbook together with the sample. Needs to be a file-like object or a tuple in the shape (filename, file-like object). | Optional | 
| comments | A comment to be added to the analysis. | Optional | 
| tags | A comma-separated list of tags to be added to the analysis. | Optional | 
| systems | A comma-separated list of operating systems to be used for the analysis. Possible values are: w7, w7x64, w7_1, w7_2, w7_4, w7_5, w7native, android2, android3, mac1, w7l, w7x64l, w10, android4, w7x64native, w7_3, w10native, android5native_1, w10x64, w7x64_hvm, android6, iphone1, w7_sec, macvm, w7_lang_packs, w7x64native_hvm, lnxubuntu1, lnxcentos1, android7_nougat. | Optional | 
| internet_access | Whether to allow internet access for the analysis. Default is true. | Optional | 
| archive_no_unpack | Whether to archive the sample without unpacking it. Default is false. | Optional | 
| ssl_inspection | Whether to enable SSL inspection. Default is false. | Optional | 
| localized_internet_country | The localized internet anonymization country. | Optional | 
| internet_simulation | Whether to enable internet simulation. Default is false. | Optional | 
| hybrid_code_analysis | Whether to enable hybrid code analysis. Default is true. | Optional | 
| hybrid_decompilation | Whether to enable hybrid decompilation. Default is false. | Optional | 
| vba_instrumentation | Whether to enable VBA instrumentation. Default is true. | Optional | 
| js_instrumentation | Whether to enable JS instrumentation. Default is true. | Optional | 
| java_jar_tracing | Whether to enable Java JAR tracing. Default is true. | Optional | 
| dotnet_tracing | Whether to enable .NET tracing. Default is true. | Optional | 
| amsi_unpacking | Whether to enable Microsoft Antimalware Scan Interface unpacking. Default is true. | Optional | 
| fast_mode | Whether to enable fast mode. It focuses on fast analysis and detection versus deep forensic analysis. Default is false. | Optional | 
| secondary_results | Whether to enable secondary results, such as Yara rule generation, classification via Joe Sandbox Class as well as several detail reports. Default is false. | Optional | 
| report_cache | Whether to enable report cache. Default is false. | Optional | 
| command_line_argument | A command line argument to be passed to the sample. | Optional | 
| live_interaction | Whether to enable live interaction. Default is false. | Optional | 
| document_password | The document password. | Optional | 
| archive_password | The archive password. | Optional | 
| start_as_normal_user | Whether to start the analysis as a normal user. Default is false. | Optional | 
| language_and_locale | Changes the language and locale of the analysis machine. | Optional | 
| delete_after_days | The number of days after which the analysis will be deleted. Default is 30. | Optional | 
| encrypt_with_password | The password to encrypt the analysis with. | Optional | 
| export_to_jbxview | Whether to export the analysis to JBXView. Default is false. | Optional | 
| email_notification | Send an email notification once the analysis completes. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| File.Hashes.type | String | The hash type. | 
| File.Hashes.value | String | The hash value. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Name | String | The full file name. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| Joe.Analysis.AnalysisID | String | The analysis ID. | 
| Joe.Analysis.Classification | String | The classification. | 
| Joe.Analysis.Comments | String | The comments. | 
| Joe.Analysis.detection | String | The detection. | 
| Joe.Analysis.duration | Number | The duration. | 
| Joe.Analysis.encrypted | Boolean | Whether the analysis is encrypted. | 
| Joe.Analysis.filename | String | The filename. | 
| Joe.Analysis.runs.detection | String | The detection. | 
| Joe.Analysis.runs.error | Unknown | The error. | 
| Joe.Analysis.runs.score | Number | The score. | 
| Joe.Analysis.runs.sigma | Boolean | The sigma. | 
| Joe.Analysis.runs.snort | Boolean | The snort. | 
| Joe.Analysis.runs.system | String | The system. | 
| Joe.Analysis.runs.yara | Boolean | The YARA. | 
| Joe.Analysis.score | Number | The score. | 
| Joe.Analysis.scriptname | String | The script name. | 
| Joe.Analysis.status | String | The status. | 
| Joe.Analysis.threatname | String | The threat name. | 
| Joe.Analysis.time | Date | The time. | 
| Joe.Analysis.webid | String | The web ID. | 
| Joe.Submission.most_relevant_analysis.detection | String | The detection. | 
| Joe.Submission.most_relevant_analysis.score | Number | The score. | 
| Joe.Submission.most_relevant_analysis.webid | String | The web ID. | 
| Joe.Submission.name | String | The name. | 
| Joe.Submission.status | String | The status. | 
| Joe.Submission.submission_id | String | The submission ID. | 
| Joe.Submission.time | Date | The time. | 


#### Command example
```!joe-submit-sample entry_id=1111@1111111111-1111-1111-1111-1 systems=w10x64```
#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "example.txt",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "file",
            "Vendor": "JoeSecurityV2"
        }
    ],
    "File": [
        {
            "Hashes": [
                {
                    "type": "MD5",
                    "value": "11111111111111111111111111111111"
                },
                {
                    "type": "SHA1",
                    "value": "1111111111111111111111111111111111111111"
                },
                {
                    "type": "SHA256",
                    "value": "1111111111111111111111111111111111111111111111111111111111111111"
                }
            ],
            "MD5": "11111111111111111111111111111111",
            "Name": "example.txt",
            "SHA1": "1111111111111111111111111111111111111111",
            "SHA256": "1111111111111111111111111111111111111111111111111111111111111111"
        }
    ],
    "Joe": {
        "Analysis": [
            {
                "analysisid": "1",
                "classification": "",
                "comments": "example comment",
                "detection": "clean",
                "duration": 500,
                "encrypted": false,
                "filename": "example.txt",
                "md5": "11111111111111111111111111111111",
                "runs": [
                    {
                        "detection": "clean",
                        "error": null,
                        "score": 1,
                        "sigma": false,
                        "snort": false,
                        "system": "w10x64",
                        "yara": false
                    }
                ],
                "score": 1,
                "scriptname": "example.jbs",
                "sha1": "1111111111111111111111111111111111111111",
                "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                "status": "finished",
                "tags": [],
                "threatname": "Unknown",
                "time": "2022-09-15T10:57:20+02:00",
                "webid": "1"
            }
        ],
        "Submission": {
            "most_relevant_analysis": {
                "detection": "clean",
                "score": 1,
                "webid": "1"
            },
            "name": "example.txt",
            "status": "finished",
            "submission_id": "1111111",
            "time": "2022-09-15T10:57:14+02:00"
        }
    }
}
```

#### Human Readable Output

>### Submission Results:
>|Submission Id|Sample Name|Time|Status|Web Id|Encrypted|Analysis Id|Classification|Threat Name|Score|Detection|SHA256|MD5|SHA1|File Name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | example.zip | 2022-09-15T10:57:14+02:00 | finished | 1 | false | 1 |  | Unknown | 1 | clean | 1111111111111111111111111111111111111111111111111111111111111111 | 11111111111111111111111111111111 | 1111111111111111111111111111111111111111 | example.txt |


### joe-submit-url
***
Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`joe-submit-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to submit. | Required | 
| url_reputation | The URL reputation. Possible values are: true, false. Default is false. | Optional | 
| full_display | When set to true, indicators information, including their DBot Scores, will be displayed. Possible values are: true, false. Default is true. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 1200. | Optional | 
| hide_polling_output | Hide polling output. | Optional | 
| report_type | The report type. Possible values are: html, json, pcap, pdf, xml, iocjson. Default is html. | Optional | 
| comments | A comment to be added to the analysis. | Optional | 
| tags | A comma-separated list of tags to be added to the analysis. | Optional | 
| systems | A comma-separated list of operating systems to be used for the analysis. Possible values are: w7, w7x64, w7_1, w7_2, w7_4, w7_5, w7native, android2, android3, mac1, w7l, w7x64l, w10, android4, w7x64native, w7_3, w10native, android5native_1, w10x64, w7x64_hvm, android6, iphone1, w7_sec, macvm, w7_lang_packs, w7x64native_hvm, lnxubuntu1, lnxcentos1, android7_nougat. | Optional | 
| internet_access | Whether to allow internet access for the analysis. Default is true. | Optional | 
| archive_no_unpack | Whether to archive the sample without unpacking it. Default is false. | Optional | 
| ssl_inspection | Whether to enable SSL inspection. Default is false. | Optional | 
| localized_internet_country | The localized internet anonymization country. | Optional | 
| internet_simulation | Whether to enable internet simulation. Default is false. | Optional | 
| hybrid_code_analysis | Whether to enable hybrid code analysis. Default is false. | Optional | 
| hybrid_decompilation | Whether to enable hybrid decompilation. Default is false. | Optional | 
| vba_instrumentation | Whether to enable VBA instrumentation. Default is true. | Optional | 
| js_instrumentation | Whether to enable JS instrumentation. Default is true. | Optional | 
| java_jar_tracing | Whether to enable Java JAR tracing. Default is true. | Optional | 
| dotnet_tracing | Whether to enable .NET tracing. Default is true. | Optional | 
| amsi_unpacking | Whether to enable Microsoft Antimalware Scan Interface unpacking. Default is true. | Optional | 
| fast_mode | Whether to enable fast mode, focuses on fast analysis and detection versus deep forensic analysis. Default is false. | Optional | 
| secondary_results | Whether to enable secondary results, such as Yara rule generation, classification via Joe Sandbox Class as well as several detail reports. Default is false. | Optional | 
| report_cache | Whether to enable report cache. Default is false. | Optional | 
| command_line_argument | A command line argument to be passed to the sample. | Optional | 
| live_interaction | Whether to enable live interaction. Default is false. | Optional | 
| document_password | The document password. | Optional | 
| archive_password | The archive password. | Optional | 
| start_as_normal_user | Whether to start the analysis as a normal user. Default is false. | Optional | 
| language_and_locale | Changes the language and locale of the analysis machine. | Optional | 
| delete_after_days | The number of days after which the analysis will be deleted. Default is 30. | Optional | 
| encrypt_with_password | The password to encrypt the analysis with. | Optional | 
| export_to_jbxview | Whether to export the analysis to JBXView. Default is false. | Optional | 
| email_notification | Send an email notification once the analysis completes. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| URL.Data | String | The URL. | 
| Joe.Analysis.AnalysisID | String | The analysis ID. | 
| Joe.Analysis.Classification | String | The classification. | 
| Joe.Analysis.Comments | String | The comments. | 
| Joe.Analysis.detection | String | The detection. | 
| Joe.Analysis.duration | Number | The duration. | 
| Joe.Analysis.encrypted | Boolean | Whether the analysis is encrypted. | 
| Joe.Analysis.filename | String | The filename. | 
| Joe.Analysis.runs.detection | String | The detection. | 
| Joe.Analysis.runs.error | Unknown | The error. | 
| Joe.Analysis.runs.score | Number | The score. | 
| Joe.Analysis.runs.sigma | Boolean | The sigma. | 
| Joe.Analysis.runs.snort | Boolean | The snort. | 
| Joe.Analysis.runs.system | String | The system. | 
| Joe.Analysis.runs.yara | Boolean | The YARA. | 
| Joe.Analysis.score | Number | The score. | 
| Joe.Analysis.scriptname | String | The script name. | 
| Joe.Analysis.status | String | The status. | 
| Joe.Analysis.threatname | String | The threat name. | 
| Joe.Analysis.time | Date | The time. | 
| Joe.Analysis.webid | String | The web ID. | 
| Joe.Submission.most_relevant_analysis.detection | String | The detection. | 
| Joe.Submission.most_relevant_analysis.score | Number | The score. | 
| Joe.Submission.most_relevant_analysis.webid | String | The web ID. | 
| Joe.Submission.name | String | The name. | 
| Joe.Submission.status | String | The status. | 
| Joe.Submission.submission_id | String | The submission ID. | 
| Joe.Submission.time | Date | The time. | 



#### Command example
```!joe-submit-url url=http://example.com```
#### Context Example

```json
{
  "DBotScore": [
    {
      "Indicator": "example.txt",
      "Reliability": "C - Fairly reliable",
      "Score": 1,
      "Type": "url",
      "Vendor": "JoeSecurityV2"
    }
  ],
  "URL": [
    {
      "Data": "http://example.com"
    }
  ],
  "Joe": {
    "Analysis": [
      {
        "analysisid": "1",
        "classification": "",
        "comments": "example comment",
        "detection": "clean",
        "duration": 500,
        "encrypted": false,
        "filename": "http://example.com",
        "md5": "",
        "runs": [
          {
            "detection": "clean",
            "error": null,
            "score": 0,
            "sigma": false,
            "snort": false,
            "system": "w7",
            "yara": false
          }
        ],
        "score": 1,
        "scriptname": "example.jbs",
        "sha1": "",
        "sha256": "",
        "status": "finished",
        "tags": [],
        "threatname": "Unknown",
        "time": "2022-09-15T10:57:20+02:00",
        "webid": "1"
      }
    ],
    "Submission": {
      "most_relevant_analysis": {
        "detection": "clean",
        "score": 0,
        "webid": "1"
      },
      "name": "http://example.com",
      "status": "finished",
      "submission_id": "1111111",
      "time": "2022-09-15T10:57:14+02:00"
    }
  }
}
```

#### Human Readable Output

>### Submission Results:
>|Submission Id|Sample Name|Time|Status|Web Id|Encrypted|Analysis Id|Classification|Threat Name|Score|Detection|URL|
> |---|---|---|---|---|---|---|---|---|---|---|---|
> | 1 | http://example.com | 2022-09-15T10:57:14+02:00 | finished | 1 | false | 1 | | Unknown | 1 | clean | http://example.com |

## Breaking Changes

### Commands
#### The following commands were removed in this version:
* ***joe-analysis-submit-sample*** - this command was replaced by ***joe-submit-sample***.
* ***joe-analysis-submit-url*** - this command was replaced by ***joe-submit-url***.
* ***joe-search*** command, the *query* argument now supports comma-separated values.


### Playbooks
#### The following playbooks were deprecated:
**Detonate File - JoeSecurity** - Use the ***joe-submit-sample*** command instead.
**Detonate File From URL - JoeSecurity** - Use the ***joe-submit-sample*** command instead.
**Detonate URL - JoeSecurity** - Use the ***joe-submit-url*** command instead.


