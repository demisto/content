Use the Lastline v2 integration to provide threat analysts and incident response teams with the advanced malware isolation and inspection environment needed to safely execute advanced malware samples, and understand their behavior.


## Configure Lastline v2 on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Lastline v2.
3. Click **Add instance** to create and configure a new integration instance. 
Note that you can configure your instance using an API Key and API Token OR Email address and Password.
    - **Name**: a textual name for the integration instance.
    - **Server URL (e.g. https://analysis.lastline.com)**
    - **API Key for accessing Lastline APIs**
    - **API Token for accessing Lastline APIs**
    - **Email Address for accessing Lastline APIs using account based authentication**
    - **Password for accessing Lastline APIs using account based authentication**
    - **Use system proxy settings**
    - **Trust any certificate (not secure)**
    - **Threshold**
4. Click __Test__ to validate the URLs, token, and connection.


### Check the reputation of a file
---
Checks the file reputation of the specified file hashes. Supports MD5, SHA1, and SHA256 hashes.
##### Base Command

`file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A comma-separated list of file hashes to check. Supports MD5, SHA1, and SHA256 hashes. | Required | 
| threshold | The score threshold that determines if the file is malicious. The default value is "70". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Type | string | The file type. | 
| File.Malicious.Vendor | string | The vendor who determined that the file is malicious. | 
| File.Malicious.Description | string | The reason that the vendor determined that the file is malicious. | 
| File.Malicious.Score | number | The score that the vendor gave the malicious file. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The type of indicator. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| Lastline.Submission.Status | string | The status of the submission. | 
| Lastline.Submission.UUID | string | The task UUID. | 
| Lastline.Submission.SubmissionTime | string | The timestamp in Lastline. | 
| Lastline.Submission.YaraSignatures.name | string | Yara signature's name. | 
| Lastline.Submission.YaraSignatures.score | number | The score according to the Yara signatures (0 to 100). | 
| Lastline.Submission.YaraSignatures.internal | boolean | Whether the signature is for internal use only. | 
| Lastline.Submission.DNSqueries | string | A list of DNS queries executed by the analysis subject. | 
| Lastline.Submission.NetworkConnections | string | A list of network connections executed by the analysis subject. | 
| Lastline.Submission.DownloadedFiles | string | A list of files that were downloaded using the Microsoft Windows file-download API functions. Each element is a tuple of file-origin URL and a File element. | 
| Lastline.Submission.Process | Unknown | Information on the Windows process. | 
| Lastline.Submission.Process.arguments | string | The argument of the process. | 
| Lastline.Submission.Process.executable | Unknown | The executable of the process. | 
| Lastline.Submission.Process.executable.abs_path | string | The absolute path of the executable of the process. | 
| Lastline.Submission.Process.executable.filename | string | The filename of the executable. | 
| Lastline.Submission.Process.executable.yara_signature_hits | string | The Yara signature of the executable of the process. | 
| Lastline.Submission.Process.executable.ext_info | unknown | The executable information of the process. | 
| Lastline.Submission.Process.process_id | string | The process ID. | 


##### Command Example
```!file file=03bc132ee4a10f6d656fc21315fc7a65797be69a```

##### Context Example
```
{
    "DBotScore": [
        {
            "Vendor": "Lastline", 
            "Indicator": "441666007e579b040967e72c13e5133b", 
            "Score": 1, 
            "Type": "File"
        }
    ], 
    "File": [
        {
            "Type": "application/zip", 
            "SHA1": "03bc132ee4a10f6d656fc21315fc7a65797be69a", 
            "SHA256": "fd977f34a9514ece503fa3ff3976ed3f305a101b3c5ff31a1293a9d0b607dfc1", 
            "MD5": "441666007e579b040967e72c13e5133b"
        }
    ], 
    "Lastline": [
        {
            "Submission": {
                "Status": "Completed", 
                "SubmissionTime": "2020-02-25 06:58:19", 
                "UUID": "2b9d578d02540010179339d362664f9b"
            }
        }
    ]
}
```

##### Human Readable Output

##### Lastline analysis for file: 441666007e579b040967e72c13e5133b
**Score: 0**

Task UUID: 2b9d578d02540010179339d362664f9b
Submission Time: 2020-02-25 06:58:19
|MD5|SHA1|SHA256|Type|
|---|---|---|---|
| 441666007e579b040967e72c13e5133b | 03bc132ee4a10f6d656fc21315fc7a65797be69a | fd977f34a9514ece503fa3ff3976ed3f305a101b3c5ff31a1293a9d0b607dfc1 | application/zip |


### Submit a URL for analysis
---
Submits a URL for analysis.
##### Base Command

`lastline-upload-url`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url |  The URL to analyze. For example: https://www.demisto.com.  | Required | 
| threshold | The score threshold that determines if the file is malicious. The default value is "70". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | A list of malicious URLs identified by the Lastline analysis. | 
| URL.Malicious.Vendor | string | The vendor who determined that a URL is malicious. | 
| URL.Malicious.Description | string | The reason that the vendor made the decision. | 
| URL.Malicious.Score | number | The score that the malicious URL received from the vendor. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| Lastline.Submission.Status | string | The status of the submission. | 
| Lastline.Submission.UUID | string | The task UUID. | 
| Lastline.Submission.SubmissionTime | string | The submission timestamp in Lastline. | 
| Lastline.Submission.YaraSignatures.name | string | Yara signatures name. | 
| Lastline.Submission.YaraSignatures.score | number | The score according to the Yara signatures (0 to 100). | 
| Lastline.Submission.YaraSignatures.internal | boolean | Whether the signature is for internal usage only. | 
| Lastline.Submission.DNSqueries | string | A list of DNS queries executed by the analysis subject. | 
| Lastline.Submission.NetworkConnections | string | A list of network connections executed by the analysis subject. | 
| Lastline.Submission.DownloadedFiles | string | A list of files that were downloaded using the Microsoft Windows file-download API functions. Each element is a tuple of file-origin URL and a File element. | 
| Lastline.Submission.Process | Unknown | Information on the Windows process. | 
| Lastline.Submission.Process.arguments | string | The argument of the process. | 
| Lastline.Submission.Process.executable | Unknown | The executable of the process. | 
| Lastline.Submission.Process.executable.abs_path | string | The absolute path of the executable of the process. | 
| Lastline.Submission.Process.executable.yara_signature_hits | string | The Yara signature of the executable of the process. | 
| Lastline.Submission.Process.executable.ext_info | unknown | The executable information of the process. | 
| Lastline.Submission.Process.process_id | string | The process ID. | 


##### Command Example
```!lastline-upload-url url="https://www.demisto.com" threshold=80```

##### Context Example
```
{
    "URL": {
        "Data": "https://www.demisto.com"
    }, 
    "DBotScore": {
        "Vendor": "Lastline", 
        "Indicator": "https://www.demisto.com", 
        "Score": 1, 
        "Type": "URL"
    }, 
    "Lastline": {
        "Submission": {
            "Status": "Completed", 
            "SubmissionTime": "2020-02-24 07:05:33", 
            "UUID": "c62b15a9e3dc00101e9557a0b6a17d3f"
        }
    }
}
```

##### Human Readable Output
##### Lastline analysis for url: https://www.demisto.com
**Score: 0**

Task UUID: c62b15a9e3dc00101e9557a0b6a17d3f
Submission Time: 2020-02-24 07:05:33
|Data|
|---|
| https://www.demisto.com |


### Upload a file for analysis
---
Submits a file for analysis.
##### Base Command

`lastline-upload-file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EntryID | The entry ID of the file to upload. | Required | 
| threshold | The score threshold that determines if the file is malicious. The default value is "70". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Type | string | The file type. | 
| File.Malicious.Vendor | string | The vendor who determined that the file is malicious. | 
| File.Malicious.Description | string | The reason that the vendor determined that the file is malicious. | 
| File.Malicious.Score | number | The score the malicious file received from the vendor. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| Lastline.Submission.Status | string | The status of the submission. | 
| Lastline.Submission.UUID | string | The task UUID. | 
| Lastline.Submission.SubmissionTime | string | The submission timestamp in Lastline. | 
| Lastline.Submission.YaraSignatures.name | string | Yara signatures name. | 
| Lastline.Submission.YaraSignatures.score | number | The score according to the Yara signatures (0 to 100). | 
| Lastline.Submission.YaraSignatures.internal | boolean | Whether the signature is for internal use only. | 
| Lastline.Submission.DNSqueries | string | A list of DNS queries executed by the analysis subject. | 
| Lastline.Submission.NetworkConnections | string | A list of network connections executed by the analysis subject. | 
| Lastline.Submission.DownloadedFiles | string | A list of files that were downloaded using the Microsoft Windows file-download API functions. Each element is a tuple of file-origin URL and a File element. | 
| Lastline.Submission.Process | Unknown | Information on the Windows process. | 
| Lastline.Submission.Process.arguments | string | The argument of the process. | 
| Lastline.Submission.Process.executable | Unknown | The executable of the process. | 
| Lastline.Submission.Process.executable.abs_path | string | The absolute path of the executable of the process. | 
| Lastline.Submission.Process.executable.filename | string | The filename of the executable. | 
| Lastline.Submission.Process.executable.yara_signature_hits | string | The Yara signature of the executable of the process. | 
| Lastline.Submission.Process.executable.ext_info | unknown | The executable information of the process. | 
| Lastline.Submission.Process.process_id | string | The process ID. | 


##### Command Example
```!lastline-upload-file EntryID=152@374 threshold=40```

##### Context Example
```
{
    "DBotScore": {
        "Vendor": "Lastline", 
        "Indicator": "441666007e579b040967e72c13e5133b", 
        "Score": 1, 
        "Type": "File"
    }, 
    "File": {
        "Type": "application/zip", 
        "SHA1": "03bc132ee4a10f6d656fc21315fc7a65797be69a", 
        "SHA256": "fd977f34a9514ece503fa3ff3976ed3f305a101b3c5ff31a1293a9d0b607dfc1", 
        "MD5": "441666007e579b040967e72c13e5133b"
    }, 
    "Lastline": {
        "Submission": {
            "Status": "Completed", 
            "SubmissionTime": "2020-02-25 06:58:19", 
            "UUID": "2b9d578d02540010179339d362664f9b"
        }
    }
}
```

##### Human Readable Output
##### Lastline analysis for file: 441666007e579b040967e72c13e5133b
**Score: 0**

Task UUID: 2b9d578d02540010179339d362664f9b
Submission Time: 2020-02-25 06:58:19
|MD5|SHA1|SHA256|Type|
|---|---|---|---|
| 441666007e579b040967e72c13e5133b | 03bc132ee4a10f6d656fc21315fc7a65797be69a | fd977f34a9514ece503fa3ff3976ed3f305a101b3c5ff31a1293a9d0b607dfc1 | application/zip |


### Get an analysis report
---
Returns an analysis report.
##### Base Command

`lastline-get-report`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The task UUID of the submitted Lastline analysis. | Required | 
| threshold | The score threshold that determines if the file is malicious. The default value is "70". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | A list of malicious URLs identified by the Lastline analysis. | 
| URL.Malicious.Vendor | string | The vendor that determined a URL is malicious. | 
| URL.Malicious.Description | string | The reason that the vendor determined that the URL is malicious. | 
| URL.Malicious.Score | number | The score that the malicious URL received from the vendor. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Type | string | The file type. | 
| File.Malicious.Vendor | string | The vendor that determined a file is malicious. | 
| File.Malicious.Description | string | The reason that the vendor determined that the file is malicious. | 
| File.Malicious.Score | number | The score that the malicious file received from the vendor. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The type of indicator. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| Lastline.Submission.Status | string | Status of the submission. | 
| Lastline.Submission.UUID | string | The task UUID. | 
| Lastline.Submission.SubmissionTime | string | The timestamp in Lastline. | 
| Lastline.Submission.YaraSignatures.name | string | Yara signatures name. | 
| Lastline.Submission.YaraSignatures.score | number | The score according to the Yara signatures (0 to 100). | 
| Lastline.Submission.YaraSignatures.internal | boolean | Whether the signature is for internal use only. | 
| Lastline.Submission.DNSqueries | string | A list of DNS queries executed by the analysis subject. | 
| Lastline.Submission.NetworkConnections | string | A list of network connections executed by the analysis subject. | 
| Lastline.Submission.DownloadedFiles | string | A list of files that were downloaded using the Microsoft Windows file-download API functions. Each element is a tuple of file-origin URL and a File element. | 
| Lastline.Submission.Process | Unknown | Information on the Windows process. | 
| Lastline.Submission.Process.arguments | string | The argument of the process. | 
| Lastline.Submission.Process.executable | Unknown | The executable of the process. | 
| Lastline.Submission.Process.executable.abs_path | string | The absolute path of the executable of the process. | 
| Lastline.Submission.Process.executable.filename | string | The filename of the executable. | 
| Lastline.Submission.Process.executable.yara_signature_hits | string | The Yara signature of the executable of the process. | 
| Lastline.Submission.Process.executable.ext_info | unknown | The executable information of the process. | 
| Lastline.Submission.Process.process_id | string | The process ID. | 


##### Command Example
```!lastline-get-report uuid=b32ed21999be00100eca07d07cb7bf38 threshold=70```

##### Context Example
```
{
    "URL": {
        "Data": "https://google.com"
    }, 
    "DBotScore": {
        "Vendor": "Lastline", 
        "Indicator": "https://google.com", 
        "Score": 1, 
        "Type": "URL"
    }, 
    "Lastline": {
        "Submission": {
            "Status": "Completed", 
            "SubmissionTime": "2019-12-31 02:40:44", 
            "UUID": "b32ed21999be00100eca07d07cb7bf38"
        }
    }
}
```

##### Human Readable Output
##### Lastline analysis for url: https://google.com
**Score: 0**

Task UUID: b32ed21999be00100eca07d07cb7bf38
Submission Time: 2019-12-31 02:40:44
|Data|
|---|
| https://google.com |


### Get a list of tasks
---
Returns a list of tasks.
##### Base Command

`lastline-get-task-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| before | Return tasks before this date (in UTC format %Y-%m-%dT%H:%M:%S). For example, 2018-07-08T12:00:00. | Optional | 
| after | Return tasks after this date (in UTC format %Y-%m-%dT%H:%M:%S). For example, 2018-07-10T12:00:00. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!lastline-get-task-list after=2020-01-01T00:00:00 before=2020-01-02T00:00:00```


##### Human Readable Output
##### tasks
|UUID|Time|Status|
|---|---|---|
| b32ed21999be00100eca07d07cb7bf38 | 2019-12-31T02:40:44 | Completed |
| 6493c3fa395000101e8ee41181d70b02 | 2020-01-01T15:26:35 | Completed |


### Get the status of a submission
---
Checks the status of a submission.
##### Base Command

`lastline-check-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The task UUID of the submitted Lastline analysis. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | A list of malicious URLs identified by the lastline analysis. | 
| URL.Malicious.Vendor | string | The vendor that determined that a URL is malicious. | 
| URL.Malicious.Description | string | The reason that the vendor determined that the URL is malicious. | 
| URL.Malicious.Score | number | The score that the malicious URL received from the vendor. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Type | string | The file type. | 
| File.Malicious.Vendor | string | The vendor that determined that the file is malicious. | 
| File.Malicious.Description | string | The reason that the vendor determined that the file is malicious. | 
| File.Malicious.Score | number | The score that the malicious file received from the vendor. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The type of indicator. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| Lastline.Submission.Status | string | The status of the submission. | 
| Lastline.Submission.UUID | string | The task UUID. | 
| Lastline.Submission.SubmissionTime | string | The timestamp in Lastline. | 
| Lastline.Submission.YaraSignatures.name | string | Yara signatures name. | 
| Lastline.Submission.YaraSignatures.score | number | The score according to the Yara signatures (0 to 100). | 
| Lastline.Submission.YaraSignatures.internal | boolean | Whether the signature is for internal use only. | 
| Lastline.Submission.DNSqueries | string | List of DNS queries executed by the analysis subject. | 
| Lastline.Submission.NetworkConnections | string | A list of network connections executed by the analysis subject. | 
| Lastline.Submission.DownloadedFiles | string | A list of files that were downloaded using the Microsoft Windows file-download API functions. Each element is a tuple of file-origin URL and a File element. | 
| Lastline.Submission.Process | Unknown | Information on athe Windows process. | 
| Lastline.Submission.Process.arguments | string | The argument of the process. | 
| Lastline.Submission.Process.executable | Unknown | The executable of the process. | 
| Lastline.Submission.Process.executable.abs_path | string | The absolute path of the executable of the process. | 
| Lastline.Submission.Process.executable.filename | string | The filename of the executable. | 
| Lastline.Submission.Process.executable.yara_signature_hits | string | The Yara signature of the executable of the process. | 
| Lastline.Submission.Process.executable.ext_info | unknown | The executable information of the process. | 
| Lastline.Submission.Process.process_id | string | The process ID. | 


##### Command Example
```!lastline-check-status uuid=b32ed21999be00100eca07d07cb7bf38```

##### Context Example
```
{
    "URL": {
        "Data": "https://google.com"
    }, 
    "DBotScore": {
        "Vendor": "Lastline", 
        "Indicator": "https://google.com", 
        "Score": 1, 
        "Type": "URL"
    }, 
    "Lastline": {
        "Submission": {
            "Status": "Completed", 
            "SubmissionTime": "2019-12-31 02:40:44", 
            "UUID": "b32ed21999be00100eca07d07cb7bf38"
        }
    }
}
```

##### Human Readable Output
##### Lastline analysis for url: https://google.com
**Score: 0**

Task UUID: b32ed21999be00100eca07d07cb7bf38
Submission Time: 2019-12-31 02:40:44
|Data|
|---|
| https://google.com |
