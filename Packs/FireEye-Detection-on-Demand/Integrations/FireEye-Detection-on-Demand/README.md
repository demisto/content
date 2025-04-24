FireEye Detection On Demand is a threat detection service delivered as an API for integration into the SOC workflow, SIEM analytics, data repositories, or web applications, etc. It delivers flexible file and content analysis to identify malicious behavior wherever the enterprise needs it.
This integration was integrated and tested with version 1.4.1 of FireEye Detection on Demand
## Configure FireEye Detection on Demand in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | DoD hostname | True |
| apikey | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fireeye-dod-get-hashes
***
Queries FireEye Detection on Demand reports for the provided md5 hashes


#### Base Command

`fireeye-dod-get-hashes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5_hashes | One or more comma separated MD5 hashes to get the reputation of. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
| File.Malicious.Vendor | unknown | N/A | 
| File.MD5 | unknown | The MD5 hash of the file | 
| FireEyeDoD.engine_results.cache_lookup.sha256 | String | The sha256 value of the file | 
| FireEyeDoD.engine_results.cache_lookup.signature_name | String | The name of the virus signature | 
| FireEyeDoD.engine_results.cache_lookup.is_malicious | Number | True/False if the file is malicious | 
| FireEyeDoD.engine_results.cache_lookup.verdict | String | The overall verdict of all analysis engines | 
| FireEyeDoD.engine_results.cache_lookup.file_extension | String | The extension of the file | 
| FireEyeDoD.engine_results.cache_lookup.weight | Number | How important this engine result is to determining malicious activity | 
| FireEyeDoD.engine_results.dynamic_analysis.verdict | String | This particular engine's verdict on whether or not the file is malicious | 
| FireEyeDoD.engine_results.av_lookup.verdict | String | This particular engine's verdict on whether or not the file is malicious | 
| FireEyeDoD.engine_results.avs_lookup.verdict | String | This particular engine's verdict on whether or not the file is malicious | 
| FireEyeDoD.engine_results.dti_lookup.verdict | String | This particular engine's verdict on whether or not the file is malicious | 
| FireEyeDoD.md5 | String | The MD5 hash of the file | 
| FireEyeDoD.is_malicious | Number | True/False if the file is malicious | 


#### Command Example
```!fireeye-dod-get-hashes md5_hashes=47f9fdc617f8c98a6732be534d8dbe9c```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "47f9fdc617f8c98a6732be534d8dbe9c",
        "Score": 0,
        "Type": "file",
        "Vendor": "FireEye DoD"
    },
    "File": {
        "FireEyeDoD": {
            "engine_results": {
                "av_lookup": {
                    "verdict": "not_found"
                },
                "avs_lookup": {
                    "verdict": "not_found"
                },
                "cache_lookup": {
                    "verdict": "not_found"
                },
                "dti_lookup": {
                    "verdict": "not_found"
                },
                "dynamic_analysis": {
                    "verdict": "not_found"
                }
            },
            "is_malicious": false
        },
        "MD5": "47f9fdc617f8c98a6732be534d8dbe9c"
    }
}
```

#### Human Readable Output

>### FireEye DoD Results
>|MD5|SHA256|Malicious|
>|---|---|---|
>| 47f9fdc617f8c98a6732be534d8dbe9c |  |  |


### fireeye-dod-submit-file
***
Submits file to FireEye Detection on Demand for analysis


#### Base Command

`fireeye-dod-submit-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | The file entry ID to submit. | Required | 
| password | Password to be used by the detection engine to decrypt a password protected file. | Optional | 
| param | Command line parameter(s) to be used by detection engine when running the file. Mainly applicable to .exe files. For example, setting param to "start -h localhost -p 5555" will make the detection engine run a file named "malicious.exe" as "malicious.exe start -h localhost -p 5555". | Optional | 
| screenshot | Extract screenshot of screen activity during dynamic analysis if true, which later can be downloaded with artifacts api | Optional | 
| video | Extract video activity during dynamic analysis if true, which later can be downloaded with artifacts api | Optional | 
| fileExtraction | Extract dropped files from vm during dynamic analysis if true, which later can be downloaded with artifacts api | Optional | 
| memoryDump | Extract memory dump files from vm during dynamic analysis if true, which later can be downloaded with artifacts api | Optional | 
| pcap | Extract pcap files from vm during dynamic analysis if true, which later can be downloaded with artifacts api | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeDoD.Scan.report_id | unknown | The report ID can be used to query the status and results of the file submission | 
| FireEyeDoD.Scan.status | unknown | The current status of the file submission | 
| FireEyeDoD.Scan.filename | unknown | The name of the file that was submitted | 


#### Command Example
```!fireeye-dod-submit-file entryID=37@760083ae-625e-4a6c-8e93-87ece7964dd0```

#### Context Example
```json
{
    "FireEyeDoD": {
        "Scan": {
            "filename": "test-infection.exe",
            "md5": "47f9fdc617f8c98a6732be534d8dbe9a",
            "overall_status": "RUNNING",
            "report_id": "c1d32790-5b08-45ab-a3be-3e61f8826e8b"
        }
    }
}
```

#### Human Readable Output

>Started analysis of test-infection.exe with FireEye Detection on Demand. Results will be published to report id: c1d32790-5b08-45ab-a3be-3e61f8826e8b

### fireeye-dod-submit-urls
***
Submits URLs to FireEye Detection on Demand for analysis

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`fireeye-dod-submit-urls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urls | A comma separated list of URLs to scan.  Maximum of 10 per request. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeDoD.Scan.report_id | unknown | The ID of the report | 
| FireEyeDoD.Scan.status | unknown | The status of the file submission.  Will be "DONE" when all engines are finished. | 


#### Command Example
```!fireeye-dod-submit-urls urls="https://www.google.com"```

#### Context Example
```json
{
    "FireEyeDoD": {
        "Scan": {
            "md5": "NA",
            "overall_status": "RUNNING",
            "report_id": "55223a00-6741-41c4-80a9-28d3c133a5db"
        }
    }
}
```

#### Human Readable Output

>Started analysis of ['https://www.google.com'] with FireEye Detection on Demand. Results will be published to report id: 55223a00-6741-41c4-80a9-28d3c133a5db

### fireeye-dod-get-reports
***
Retrieves one or more reports of file scans


#### Base Command

`fireeye-dod-get-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_ids | A comma separated list of one or more report IDs to fetch. | Required | 
| extended_report | If True, additional information will be returned | Optional | 
| get_screenshot | Whether or not to get screenshot artifacts from the report | Optional | 
| get_artifact | Which report artifacts to retrieve (if any) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeDoD.Scan.report_id | String | The ID of the report | 
| FireEyeDoD.Scan.overall_status | String | The overall status of all of the engines | 
| FireEyeDoD.Scan.is_malicious | Number | True/False if the file is malicious | 
| FireEyeDoD.Scan.started_at | Date | The UTC time the scan was started | 
| FireEyeDoD.Scan.completed_at | Date | The UTC time the scan was completed | 
| FireEyeDoD.Scan.duration | Number | How long, in seconds, the scan took to complete. | 
| FireEyeDoD.Scan.file_name | String | The name of the submitted file | 
| FireEyeDoD.Scan.file_size | Number | The size of the file in bytes | 
| FireEyeDoD.Scan.file_extension | String | The extension of the submitted file.  If a URL was submitted, this will be empty. | 
| FireEyeDoD.Scan.md5 | String | The MD5 hash of the submitted file | 
| FireEyeDoD.Scan.sha256 | String | The sha256 hash of the submitted file | 
| FireEyeDoD.Scan.signature_name | String | List of signatures extracted by all engines | 


#### Command Example
```!fireeye-dod-get-reports report_ids=82e71bec-04c7-4f04-945b-4d344a758abe```

#### Context Example
```json
{
    "FireEyeDoD": {
        "Scan": {
            "completed_at": "2020-11-10 14:28:18",
            "duration": 0,
            "file_extension": "urlscan",
            "file_name": "test-infection.exe",
            "file_size": 28672,
            "is_malicious": true,
            "magic": null,
            "md5": "NA",
            "name": "test-infection.exe",
            "overall_status": "DONE",
            "report_id": "82e71bec-04c7-4f04-945b-4d344a758abe",
            "sha1": "NA",
            "sha256": "NA",
            "signature_name": [
                "Phish.LIVE.DTI.URL",
                "Malicious.LIVE.DTI.URL",
                "fe_ml_heuristic",
                "FireEye.Malware.exe",
                "FETestEvent"
            ],
            "size": 28672,
            "started_at": "2020-11-10 14:28:18",
            "type": "urlscan",
            "urls": [
                "http://fedeploycheck.fireeye.com/appliance-test/block.html",
                "http://165.227.14.8/?NDU2MDgz&amp;yOyeu&amp;YPocHQsbD=disagree&amp;lAjd=callous&amp;mvUq=disagree&amp;eSCpt=disagree&amp;mnnYBwlX=abettor&amp;MZMJ=everyone&amp;ipEMqw=professional&amp;xRefGF=callous&amp;tzsdfga4=dJORROwbnhRaGKA1hlIhYVV0W8a2ojkbXzhCf1JaG9RGIZ1hD-sGcELgL6G2xyPNRcw&amp;cvggd54=wnfQMvXcJBXQFYbIKuXDSKxDKU7WFEaVw4-RhMG3YpjNfynz1-zURnL6tASVVFuRrbM&amp;hMdqbI=electrical&amp;qgZufk=disagree&amp;egHdAM=abettor&amp;BUfBH=professional&amp;RGVeFwBNTM2MzY2",
                "http://br430.teste.website/~idbrok92/idb/UI/Login/",
                "http://www.dulys.co.zw/",
                "http://fedeploycheck.fireeye.com/appliance-test/test-infection.exe",
                "http://fedeploycheck.fireeye.com/appliance-test/test-infection.pdf",
                "http://fedeploycheck.fireeye.com/appliance-test/alert.html",
                "https://tinyurl.com/y2qezvol",
                "https://fedeploycheck.fireeye.com/appliance-test/alert.html"
            ],
            "verdict": "MALICIOUS"
        }
    }
}
```

#### Human Readable Output

>### Scan status
>|completed_at|duration|file_extension|file_name|file_size|is_malicious|magic|md5|name|overall_status|report_id|sha1|sha256|signature_name|size|started_at|type|urls|verdict|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-11-10 14:28:18 | 0 | urlscan | test-infection.exe | 28672 | true |  | NA | test-infection.exe | DONE | 82e71bec-04c7-4f04-945b-4d344a758abe | NA | NA | Phish.LIVE.DTI.URL,<br/>Malicious.LIVE.DTI.URL,<br/>fe_ml_heuristic,<br/>FireEye.Malware.exe,<br/>FETestEvent | 28672 | 2020-11-10 14:28:18 | urlscan | http:<span></span>//fedeploycheck.fireeye.com/appliance-test/block.html,<br/>http:<span></span>//165.227.14.8/?NDU2MDgz&amp;yOyeu&amp;YPocHQsbD=disagree&amp;lAjd=callous&amp;mvUq=disagree&amp;eSCpt=disagree&amp;mnnYBwlX=abettor&amp;MZMJ=everyone&amp;ipEMqw=professional&amp;xRefGF=callous&amp;tzsdfga4=dJORROwbnhRaGKA1hlIhYVV0W8a2ojkbXzhCf1JaG9RGIZ1hD-sGcELgL6G2xyPNRcw&amp;cvggd54=wnfQMvXcJBXQFYbIKuXDSKxDKU7WFEaVw4-RhMG3YpjNfynz1-zURnL6tASVVFuRrbM&amp;hMdqbI=electrical&amp;qgZufk=disagree&amp;egHdAM=abettor&amp;BUfBH=professional&amp;RGVeFwBNTM2MzY2,<br/>http:<span></span>//br430.teste.website/~idbrok92/idb/UI/Login/,<br/>http:<span></span>//www<span></span>.dulys.co.zw/,<br/>http:<span></span>//fedeploycheck.fireeye.com/appliance-test/test-infection.exe,<br/>http:<span></span>//fedeploycheck.fireeye.com/appliance-test/test-infection.pdf,<br/>http:<span></span>//fedeploycheck.fireeye.com/appliance-test/alert.html,<br/>https:<span></span>//tinyurl.com/y2qezvol,<br/>https:<span></span>//fedeploycheck.fireeye.com/appliance-test/alert.html | MALICIOUS |


### fireeye-dod-get-report-url
***
Generates a pre-signed URL for a report


#### Base Command

`fireeye-dod-get-report-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report to fetch | Required | 
| expiration | Expiration (in hours) for browser viewable report pre-signed URL link. Default value is 72 hours.  Minimum is 1 hour, and maximum is 8760 hours (365 days). | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fireeye-dod-get-report-url report_id=82e71bec-04c7-4f04-945b-4d344a758abe```

#### Context Example
```json
{}
```

#### Human Readable Output

>Report 82e71bec-04c7-4f04-945b-4d344a758abe is available [here](https://public-feapi.marketplace.apps.fireeye.com/reports/82e71bec-04c7-4f04-945b-4d344a758abe?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyZXBvcnRfaWQiOiI4MmU3MWJlYy0wNGM3LTRmMDQtOTQ1Yi00ZDM0NGE3NThhYmUiLCJleHAiOjE2MDUyNzkxMjh9.xcGa3OKhbDJMbJJpwxCvxOYr36OEd59a-47VJ4Rh05o)