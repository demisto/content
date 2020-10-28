FireEye Detection On Demand is a threat detection service delivered as an API for integration into the SOC workflow, SIEM analytics, data repositories, or web applications, etc. It delivers flexible file and content analysis to identify malicious behavior wherever the enterprise needs it.
This integration was integrated and tested with version xx of FireEye Detection on Demand
## Configure FireEye Detection on Demand on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FireEye Detection on Demand.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | DoD hostname | True |
| apikey | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



### fireeye-dod-submit-urls
***
Submits URLs to FireEye Detection on Demand for analysis


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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output


