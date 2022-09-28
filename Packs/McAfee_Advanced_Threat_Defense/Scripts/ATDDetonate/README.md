Detonates a file or URL through McAfee ATD.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | file, enhancement, atd |


## Dependencies
---
This script uses the following commands and scripts.
* atd-get-report
* atd-check-status
* atd-file-upload

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| vmProfileList | The analyzer of a profile's ID. The profile ID number can be found in the **UI Policy/Analyzer Profile** page, Or using the command `atd-list-analyzer-profiles`, under `vmProfileid` key result. |
| submitType | This parameter accepts four values. Can be, "0", "1", "2" and "3". "0" - a regular file upload. "1" - a URL submission. The URL link is processed inside analyzer VM. "2" - Will submit a file with a URL. "3" - A URL will download. The file from the URL is first downloaded and then analyzed. |
| url | Any valid web URL. |
| messageId | The maximum number character string which is 128. |
| srcIp |  The IPv4 address of the source system or gateway from where the file is downloaded. |
| dstIp |  The IPv4 address of the target endpoint. |
| skipTaskId | The value "0" indicates corresponding taskID in API response. The value "1" indicates -1 as a taskID in API response. |
| analyzeAgain | The value "0" indicates to skip sample analysis if it was analyzed previously . The value "2" indicates to not skip sample analysis if it was not analyzed previously. |
| xMode | The Value "0" indicates no user interaction is needed during sample analysis. The value "1" indicates user interaction is needed during sample analysis. |
| filePriorityQ |  The priority of the sample analysis. The `run_now` command assigns the highest priority. For example, a sample is analyzed right away. The `add_to_q` command puts the sample in a waiting state if there is a waiting queue of samples. The default is `run_now`. |
| entryID | The entry ID. |
| reportType | The report type can be, "html" - a HTML report, "txt" - a text report, "xml" - a XML report, "zip" - all the files packaged into a single zip file, "json" - the same report as xml but in the JSON format, "ioc" - an Indicators of Compromise format, "stix" - a Structured Threat Information Expression. By default, STIX generation is disabled. Use set `stixreportstatus enable` to enable it. "pdf" - Portable Document Format, "sample" - downloads a sample from McAfee Advanced Threat Defense. |
| timeout | The timeout length (in seconds). The default is 10 minutes. |
| interval | The interval to poll for results. The default is 10 seconds. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Name | The filename (only in the case of report type=json). | Unknown |
| File.Type | The file type. For example, "PE" (only in the case of a report type=json). | Unknown |
| File.Size | The file size(only in the case of a report type=json). | Unknown |
| File.MD5 | The MD5 file hash of the file (only in the case of a report type=json). | Unknown |
| File.SHA1 | The SHA1 file hash of the file (only in the case of a report type=json). | Unknown |
| File.SHA256 | The SHA256 file hash of the file (only in the case of a report type=json). | Unknown |
| File.Malicious.Vendor | The vendor that made the decision that the file is malicious. | Unknown |
| File.Malicious.Description | The reason that the vendor decided that the files are malicious. | Unknown |
| DBotScore.Indicator | The indicator that was tested (only in the case of a report type=json). | Unknown |
| DBotScore.Type | The type of the indicator (only in the case of a report type=json). | Unknown |
| DBotScore.Vendor | The vendor used to calculate the score (only in the case of a report type=json). | Unknown |
| DBotScore.Score | The actual score (only in the case of a report type=json). | Unknown |
