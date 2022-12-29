Query and upload samples to Cisco threat grid.
This integration was integrated and tested with version xx of Threat Grid

## Configure Cisco Threat Grid on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco Threat Grid.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://192.168.0.1) | True |
    | API token | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### threat-grid-get-samples
***
Search samples on the Threat Grid platform. Input parameters are ANDed together. Only finished samples can be searched (that is, the ones that are having a status of succ or fail.)


#### Base Command

`threat-grid-get-samples`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The most results to be returned in the response. | Optional | 
| offset | The number of records to skip. | Optional | 
| sha256 | An SHA256 of the submitted sample, only matches samples, not their artifacts. | Optional | 
| md5 | An MD5 checksum of the submitted sample, only matches samples, not their artifacts. | Optional | 
| sha1 | A sha1 of the submitted sample, only matches samples, not their artifacts. | Optional | 
| id | a sample ID. | Optional | 
| ids | a comma-separated list of sample IDs. | Optional | 
| ioc | an IOC name. | Optional | 
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional | 
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional | 
| org-only | If “true”, will only match against samples submitted by your organization. | Optional | 
| user-only | If “true”, will only match against samples you submitted. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.ID | unknown | The sample id | 
| ThreatGrid.Sample.Filename | unknown | The sample filename | 
| ThreatGrid.Sample.State | unknown | The state of the sample, one of a stable set of strings "wait, prep, run, proc, succ, fail" | 
| ThreatGrid.Sample.Status | unknown | The sample status, one of a stable set of strings "succ, fail" | 
| ThreatGrid.Sample.MD5 | unknown | The sample md5 | 
| ThreatGrid.Sample.SHA1 | unknown | The sample sha1 | 
| ThreatGrid.Sample.SHA256 | unknown | The sample sha256 | 
| ThreatGrid.Sample.OS | unknown | The sample os | 
| ThreatGrid.Sample.SubmittedAt | unknown | The sample submission time | 
| ThreatGrid.Sample.StartedAt | unknown | The sample analysis starting time | 
| ThreatGrid.Sample.CompletedAt | unknown | The sample completion time | 

### threat-grid-get-sample-by-id
***
Get threat grid sample by id


#### Base Command

`threat-grid-get-sample-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sample ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.ID | unknown | The sample id | 
| ThreatGrid.Sample.Filename | unknown | The sample filename | 
| ThreatGrid.Sample.State | unknown | The state of the sample, one of a stable set of strings "wait, prep, run, proc, succ, fail" | 
| ThreatGrid.Sample.Status | unknown | The sample status, one of a stable set of strings "succ, fail" | 
| ThreatGrid.Sample.MD5 | unknown | The sample md5 | 
| ThreatGrid.Sample.SHA1 | unknown | The sample sha1 | 
| ThreatGrid.Sample.SHA256 | unknown | The sample sha256 | 
| ThreatGrid.Sample.OS | unknown | The sample os | 
| ThreatGrid.Sample.SubmittedAt | unknown | The sample submission time | 
| ThreatGrid.Sample.StartedAt | unknown | The sample analysis starting time | 
| ThreatGrid.Sample.CompletedAt | unknown | The sample completion time | 

### threat-grid-get-sample-state-by-id
***
Get threat grid sample state by id


#### Base Command

`threat-grid-get-sample-state-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sample ID. | Optional | 
| ids | A comma-separated list of sample IDs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.ID | unknown | The sample ID, globally unique, and the canonical identifier of this sample analysis | 
| ThreatGrid.Sample.State | unknown | The state of the sample, one of a stable set of strings “wait, prep, run, proc, succ, fail” | 

### threat-grid-upload-sample
***
Submits a sample to threat grid for analysis


#### Base Command

`threat-grid-upload-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file-id | The sample file. Click on the chain like icon after you upload a file in Demisto to find the file-id. . | Required | 
| filename | The original filename of the sample, as a string. | Required | 
| vm | a string identifying a specific VM to use. Options: win7-x64: Windows 7 64bit, win7-x64-2: Windows 7 64bit Profile 2, win7-x64-jp: Windows 7 64bit Japanese (Not available on Threat Grid appliances), win7-x64-kr: Windows 7 64bit Korean (Only available on Threat Grid appliances licensed for this VM), win10: Windows 10 (Not available on Threat Grid appliances). NOTE: The standard (English) VMs default to UTF-8 encoding. To support Korean and Japanese character sets, such as S-JIS, submit to the appropriate VM. Possible values are: win7-x64, win7-x64-2, win7-x64-jp, win7-x64-kr, win10. | Optional | 
| private | if present, and set to any value but “false” the sample will be marked private. | Optional | 
| tags | A comma-separated list of tags applied to this sample. | Optional | 
| playbook | Name of a playbook to apply to this sample run. none: Explicitly disables playbooks, default: Default Playbook, alt_tab_programs: Conduct Active Window Change, open_word_embedded_object: Open Embedded Object in Word Document, press_enter: Dialogue OK, visit_site: Visit Website Using Internet Explorer, close_file: Close Active Window, run_dialog_box_ie: Click Run on Internet Explorer Download Dialog Box, open_attachment_msg: Open Outlook Email Attachment, run_dialog_box_dde: Accept Microsoft Office Dialog Boxes to Open Dynamic Data Exchange Content. The current list of playbooks endpoints can be obtained by querying /api/v3/configuration/playbooks. Possible values are: none, default, alt_tab_programs, open_word_embedded_object, press_enter, visit_site, close_file, run_dialog_box_ie, open_attachment_msg, run_dialog_box_dde. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.ID | unknown | The sample id | 
| ThreatGrid.Sample.Filename | unknown | The sample filename | 
| ThreatGrid.Sample.State | unknown | The state of the sample, one of a stable set of strings "wait, prep, run, proc, succ, fail" | 
| ThreatGrid.Sample.Status | unknown | The sample status | 
| ThreatGrid.Sample.MD5 | unknown | The sample md5 | 
| ThreatGrid.Sample.SHA1 | unknown | The sample sha1 | 
| ThreatGrid.Sample.SHA256 | unknown | The sample sha256 | 
| ThreatGrid.Sample.OS | unknown | The sample os | 
| ThreatGrid.Sample.OSVer | unknown | The sample ov version | 
| ThreatGrid.Sample.SubmittedAt | unknown | The sample submission time | 

### threat-grid-search-submissions
***
Search threat grid submissions


#### Base Command

`threat-grid-search-submissions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Query text. If you wish to work with an elasticsearch query please set 'advanced' argument to 'true'. | Optional | 
| user-only | Only display submissions created by the current user, as determined by the value of api_key. | Optional | 
| org-only | Only display submissions created by the current user's organization, as determined by the value of api_key. | Optional | 
| term | Restrict matches to a subset of submission fields. The value of 'term' is a comma-delimited list of strings which select groups of fields. | Optional | 
| before | Return submissions created before specified time. Value is a timestring, either ISO-8601, or free-form (see documentation for 'chronic,' at https://github.com/mojombo/chronic). | Optional | 
| after | Return submissions created after specified time. Value is a timestring, either ISO-8601, or free-form (see documentation for 'chronic,' at https://github.com/mojombo/chronic). | Optional | 
| state | Restrict match to submissions in specific state or states. Value is a comma-delimited string containing one or more of the values: wait proc succ fail. | Optional | 
| advanced | When set to 'true' interprets 'q' as a Lucene query syntax, allowing matches by specific field, for instance: q=sha256:1b4468 will return items with sha256 equal to 1b4468. q=analysis.threat_score:64 will return analysis whose threat_score value is equal to 64. For reference see: https://lucene.apache.org/core/2_9_4/queryparsersyntax.html. | Optional | 
| sort_by | Sorts by timestamp, submitted_at, analyzed_at, filename, type, state, threat or threat_score, login. | Optional | 
| sort_order | desc or asc. | Optional | 
| limit | Restrict the number of records returned. | Optional | 
| offset | Return matching submissions starting at the given offset. | Optional | 
| highlight | Provide a 'matches' field in results, indicating which fields were matched. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.ID | unknown | The sample ID | 
| ThreatGrid.Sample.Filename | unknown | The name of the sample file | 
| ThreatGrid.Sample.State | unknown | The state of the sample, one of a stable set of strings "wait, prep, run, proc, succ, fail" | 
| ThreatGrid.Sample.Status | unknown | The status of the sample | 
| ThreatGrid.Sample.MD5 | unknown | The MD5 id of the sample | 
| ThreatGrid.Sample.SHA1 | unknown | The SHA1 id of the sample | 
| ThreatGrid.Sample.SHA256 | unknown | The SHA256 id of the sample | 
| ThreatGrid.Sample.SubmittedAt | unknown | Time of submission for the sample | 
| ThreatGrid.Sample.ThreatScore | unknown | The threat score of the sample | 

### threat-grid-get-video-by-id
***
Get the sample analysis video by id


#### Base Command

`threat-grid-get-video-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sample id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.Id | string | The sample Id | 
| Demisto.File | unknown | File containing result | 

### threat-grid-get-analysis-by-id
***
The detailed overview of dynamic and static analysis results for the sample


#### Base Command

`threat-grid-get-analysis-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sample id. | Required | 
| limit | Limits the results to not overpopulate the context. Default value is. 20. If you wish to get results with no limit, set this value to "". Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.ID | unknown | The ID of the sample for which the report was downloaded. | 
| Demisto.File | unknown | File containing unfiltered result. | 
| ThreatGrid.Sample.VM.ID | unknown | The VM ID for the sample. | 
| ThreatGrid.Sample.VM.Name | unknown | The VM Name for the sample. | 
| ThreatGrid.Sample.StartedAt | unknown | Start time of the analysis. | 
| ThreatGrid.Sample.Runtime | unknown | Runtime of the analysis. | 
| ThreatGrid.Sample.FileName | unknown | File name of the sample. | 
| ThreatGrid.Sample.Size | unknown | Size of the sample. | 
| ThreatGrid.Sample.MD5 | unknown | The sample MD5 value. | 
| ThreatGrid.Sample.SHA1 | unknown | The sample's SHA1 value. | 
| ThreatGrid.Sample.SHA256 | unknown | The sample's SHA256 value. | 
| ThreatGrid.Sample.MagicType | unknown | Sample magic type. | 
| ThreatGrid.Sample.Type | unknown | Sample's file type | 
| ThreatGrid.Sample.ThreatScore | unknown | The threat score of the sample. | 
| ThreatGrid.Sample.HeuristicScore | unknown | The sample's hueristic score. | 
| ThreatGrid.Sample.FilesDeleted | unknown | The files that were created during the anaylsis. | 
| ThreatGrid.Sample.FileCreated | unknown | The files that were created during the analysis. | 
| ThreatGrid.Sample.FilesModified | unknown | The files that were modified during the analysis. | 
| ThreatGrid.Sample.Directory | unknown | The directory of the sample. | 
| ThreatGrid.Sample.CMD | unknown | The command line execution of the sample. | 
| ThreatGrid.Sample.ProcessName | unknown | The process name of the sample. | 
| ThreatGrid.Sample.Destination | unknown | The destination IP of the sample. | 
| ThreatGrid.Sample.DestinationPort | unknown | The destination port of the sample. | 
| ThreatGrid.Sample.PacketSize | unknown | Packet size in bytes. | 
| ThreatGrid.Sample.VT.Hits | unknown | Sample malicious hits in virustotal. | 
| ThreatGrid.Sample.VT.Engines | unknown | Number of engines that scanned the Sample on Virustotal. | 
| ThreatGrid.Artifact.Yara | unknown | Artifact ID \(yara signature name\) | 
| ThreatGrid.Artifact.Tags | unknown | Artifact tags. | 
| ThreatGrid.Artifact.FamilyName | unknown | Artifact family name. | 
| ThreatGrid.Artifact.ThreatName | unknown | Artifact threat name. | 

### threat-grid-get-processes-by-id
***
Get a JSON object which contains a timeline of all process activities as determined by the dynamic analysis engine.


#### Base Command

`threat-grid-get-processes-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sample id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.Id | string | The ID of the sample for which the PCAP needs to be downloaded. | 

### threat-grid-get-pcap-by-id
***
Get the tcpdump PCAP file for a specific Sample ID, with all the network activity of the sample


#### Base Command

`threat-grid-get-pcap-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sample id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.Id | string | The ID of the sample for which the PCAP needs to be downloaded. | 
| Demisto.File | unknown | File containing result | 

### threat-grid-get-warnings-by-id
***
Gets a JSON structure describing any warnings that occured during the analysis


#### Base Command

`threat-grid-get-warnings-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sample id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.Id | string | The sample ID | 
| Demisto.File | unknown | File containing result | 

### threat-grid-get-summary-by-id
***
Returns summary analysis information


#### Base Command

`threat-grid-get-summary-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sample id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.ID | string | The sample ID. | 
| ThreatGrid.Sample.AnalysisSummary.RegistryCount | number | The registry count of the sample. | 
| ThreatGrid.Sample.AnalysisSummary.FileName | string | The Filename of the sample. | 
| ThreatGrid.Sample.AnalysisSummary.SHA256 | string | The SHA256 hash of the sample. | 
| ThreatGrid.Sample.AnalysisSummary.SampleType | string | The sample type. | 
| ThreatGrid.Sample.AnalysisSummary.FirstSeen | date | The timestamp when the sample was first seen. | 
| ThreatGrid.Sample.AnalysisSummary.LastSeen | date | The timestamp when the sample was last seen. | 

### threat-grid-get-threat-summary-by-id
***
Returns a summary of the threats detected during analysis


#### Base Command

`threat-grid-get-threat-summary-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sample id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.ID | string | The sample id | 
| ThreatGrid.Sample.MaxSeverity | number | The sample max severity | 
| ThreatGrid.Sample.Score | number | The sample score | 
| ThreatGrid.Sample.Count | number | The sample count | 
| ThreatGrid.Sample.MaxConfidence | number | The sample max confidence | 
| DBotScore.Indicator | string | The indicator value | 
| DBotScore.Score | number | The indicator's score | 
| DBotScore.Vendor | string | The indicator's vendor | 
| DBotScore.Type | string | The indicator's type | 
| ThreatGrid.Sample.ThreatFeeds | unknown | The sample threat feeds | 

### threat-grid-get-html-report-by-id
***
Get the report.html file for a specific Sample ID. This is a stand-alone file with a complete report on the sample run. It is designed to be emailed or printed.


#### Base Command

`threat-grid-get-html-report-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sample id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.Id | string | The ID of the sample for which the report was downloaded. | 
| Demisto.File | unknown | File containing result | 

### threat-grid-download-sample-by-id
***
Download a sample by using its ID. The downloaded file is an archive of the sample itself, in a zip format as a form of quarantine.


#### Base Command

`threat-grid-download-sample-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the sample to be downloaded. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.DownloadedSamples.Id | string | The ID of the downloaded sample | 
| Demisto.File | unknown | File containing result | 

### threat-grid-get-analysis-iocs
***
Returns a JSON list of the Indicators of Compromise identified in this sample run


#### Base Command

`threat-grid-get-analysis-iocs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sample id. | Required | 
| ioc | The IOC name you want to fetch details for. | Optional | 
| limit | Limit the number of indicators you would like to see. The list is sorted by indicator severity in descending order. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.IOCs.Title | unknown | The title of the IOC | 
| ThreatGrid.IOCs.Confidence | unknown | The confidence of the IOC | 
| ThreatGrid.IOCs.Severity | unknown | The severity of the IOC | 
| ThreatGrid.IOCs.IOC | unknown | Threat grid's IOC | 
| ThreatGrid.IOCs.IOCCategory | unknown | The IOC category of the IOC | 
| DBotScore.Indicator | unknown | The indicator value | 
| DBotScore.Vendor | unknown | The indicator vendor | 
| DBotScore.Type | unknown | The indicator type | 
| DBotScore.Score | unknown | The indicator score | 
| ThreatGrid.IOCs.Data.IP | unknown | The IP of the IOC | 
| ThreatGrid.IOCs.Data.URL | unknown | The URL of the IOC | 
| ThreatGrid.IOCs.Data.Domain | unknown | The domain of the IOC | 
| ThreatGrid.IOCs.Data.Path | unknown | The path of the IOC | 
| ThreatGrid.IOCs.Data.SHA256 | unknown | The SHA256 value of the IOC | 
| ThreatGrid.IOCs.Tags | unknown | The tags of the IOC | 

### threat-grid-who-am-i
***
Get logged in user


#### Base Command

`threat-grid-who-am-i`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.User.Email | unknown | The logged in user Email. | 
| ThreatGrid.User.Login | unknown | The logged in user Login ID. | 
| ThreatGrid.User.Name | unknown | The logged in user Name. | 
| ThreatGrid.User.OrganizationId | unknown | The logged in user Organization ID. | 
| ThreatGrid.User.Role | unknown | The logged in user Role | 

### threat-grid-user-get-rate-limit
***
Get rate limit for a specific user name. ThreatGrid employs a simple rate limiting method for sample submissions by specifying the number of samples which can be submitted within some variable time period by a user. Multiple rate limits can be employed to form overlapping submission limits. For example, 20 submissions per hour AND 400 per day.


#### Base Command

`threat-grid-user-get-rate-limit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| login | User login name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.User.RateLimit.Minutes | number | Array of array\(s\) representing submission\(s\) per minute\(s\) or the string"nil" to clear the value. Example: \[\[5, 1440\]\] which represents 5 samples per day. This field represent the minutes. | 
| ThreatGrid.User.RateLimit.Samples | number | Array of array\(s\) representing submission\(s\) per minute\(s\) or the string"nil" to clear the value. Example: \[\[5, 1440\]\] which represents 5 samples per day. This field represent the number of samples allowed. | 
| ThreatGrid.User.RateLimit.SubmissionWaitSeconds | number | The number of seconds to wait for a submission to get uploaded on the platform. | 
| ThreatGrid.User.RateLimit.SubmissionsAvailable | number | The number of submissions available for the specified username | 

### threat-grid-get-specific-feed
***
Gets a specific threat feed


#### Base Command

`threat-grid-get-specific-feed`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed-name | The feed name. For a list of possible feed names and how to use them please see - https://panacea.threatgrid.com/doc/main/feeds.html. | Required | 
| feed-period | Feed daily date (YYYY-MM-DD). Alternatively, you may also write in free text (e.g. '2 days ago'). | Optional | 
| output-type | The output type. Default is json. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Demisto.File | unknown | File containing result | 

### threat-grid-url-to-file
***
Convert a URL into a file for Threat Grid file detonation.


#### Base Command

`threat-grid-url-to-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urls | Comma separated list of URLs to convert. | Required | 


#### Context Output

There is no context output for this command.
### threat-grid-organization-get-rate-limit
***
Get rate limits applied to an organization. ThreatGrid employs a simple rate limiting method for sample submissions by specifying the number of samples which can be submitted within some variable time period by an entire organization and/or per a license basis. Multiple rate limits can be employed to form overlapping submission limits. For example, 20 submissions per hour AND 400 per day.


#### Base Command

`threat-grid-organization-get-rate-limit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adminLogin | The admin user login name to be used for getting the rate limits. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.User.RateLimit.Minutes | number | Array of array\(s\) representing submission\(s\) per minute\(s\) or the string"nil" to clear the value. Example: \[\[5, 1440\]\] which represents 5 samples per day. This field represent the minutes. | 
| ThreatGrid.User.RateLimit.Samples | number | Array of array\(s\) representing submission\(s\) per minute\(s\) or the string"nil" to clear the value. Example: \[\[5, 1440\]\] which represents 5 samples per day. This field represent the number of samples allowed. | 
| ThreatGrid.User.RateLimit.SubmissionWaitSeconds | number | The number of seconds to wait for a submission to get uploaded on the platform. | 
| ThreatGrid.User.RateLimit.SubmissionsAvailable | number | The number of submissions available for the entire organization. | 

### threat-grid-search-ips
***
Search IPs. Please provide a single argument (only one) to use this command, as the API supports 1 filter at a time.


#### Base Command

`threat-grid-search-ips`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_dst | search by destination IP. | Optional | 
| network_src | search by source IP. | Optional | 
| artifact | search by artifact SHA256. | Optional | 
| domain | search by domain name. | Optional | 
| url | search by url. | Optional | 
| asn | search by IP asn. | Optional | 
| geo_location | search by IP geo location information. | Optional | 
| cidr | search by IP/CIDR. | Optional | 
| ioc | search by IOC name. | Optional | 
| tag | search by tag name. | Optional | 


#### Context Output

There is no context output for this command.
### threat-grid-get-analysis-annotations
***
Returns data regarding the annotations of the anlysis


#### Base Command

`threat-grid-get-analysis-annotations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sample ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.AnalysisResults.Sample.Id.Annotations.IP | unknown | Ip address present in the annotation. | 
| ThreatGrid.AnalysisResults.Sample.Id.Annotations.IP.Asn | unknown | Autonomous system number of the IP. | 
| ThreatGrid.AnalysisResults.Sample.Id.Annotations.IP.City | unknown | City of the IP found. | 
| ThreatGrid.AnalysisResults.Sample.Id.Annotations.IP.Country | unknown | Country of the IP found | 
| ThreatGrid.AnalysisResults.Sample.Id.Annotations.IP.Org | unknown | Org of the IP found | 
| ThreatGrid.AnalysisResults.Sample.Id.Annotations.IP.Region | unknown | Region of the IP found. | 
| ThreatGrid.AnalysisResults.Sample.Id.Annotations.IP.Timestamp | unknown | Timestamp of the IP found | 

### threat-grid-search-samples
***
Search Samples. Please provide a single argument (only one) to use this command, as the API supports 1 filter at a time.


#### Base Command

`threat-grid-search-samples`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc | search by IOC name. | Optional | 
| checksum | search by checksum (sha256, md5 or sha1). | Optional | 
| checksum_sample | search by checksum of sample. | Optional | 
| path | search by path name. | Optional | 
| path_sample | search by sample path name. | Optional | 
| path_artifact | search by artifact name. | Optional | 
| path_deleted | search by path names that were deleted. | Optional | 
| url | search by url. | Optional | 
| registry_key | search by registry key accessed. | Optional | 
| domain | search by domain name. | Optional | 
| domain_dns_lookup | search by domain name used for DNS lookups. | Optional | 
| domain_http_request | search by domain name used in HTTP request. | Optional | 
| ip | search by ip address. | Optional | 
| ip_dns_lookup | search by IP address returned in DNS lookup. | Optional | 
| ip_src | search by network stream source IP address. | Optional | 
| ip_dst | search by network stream destination IP address. | Optional | 
| tag | search by sample tag. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.ID | unknown | Result ID | 
| ThreatGrid.Sample.Details | unknown | Detail of sample | 

### threat-grid-search-urls
***
Search urls. Please provide a single argument (only one) to use this command, as the API supports 1 filter at a time.


#### Base Command

`threat-grid-search-urls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | search by URL pattern. | Optional | 
| sibling | search by URL pattern prefix. | Optional | 
| neighbor | search by hostname of URL. | Optional | 
| sha256 | search by SHA56 of URL. | Optional | 
| md5 | search by md5 of URL. | Optional | 
| sha1 | search by sha1 of URL. | Optional | 
| protocol | search by protocol name. | Optional | 
| host | search by hostname. | Optional | 
| port | search by post number. | Optional | 
| path | search by path name. | Optional | 
| query | search by query. | Optional | 
| reference | search by fragment identifier. | Optional | 
| ip | search by IP address of network stream. | Optional | 
| artifact | search by artifact downloaded. | Optional | 
| tag | search by url tag. | Optional | 


#### Context Output

There is no context output for this command.
### threat-grid-get-samples-state
***
Get threat grid samples state


#### Base Command

`threat-grid-get-samples-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Comma separated list of sample ids. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.ID | unknown | The sample ID, globally unique, and the canonical identifier of this sample analysis | 
| ThreatGrid.Sample.State | unknown | The state of the sample, one of a stable set of strings “wait, prep, run, proc, succ, fail” | 

### threat-grid-feeds-artifacts
***
Get artifacts threat feed


#### Base Command

`threat-grid-feeds-artifacts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | Restrict returned records with this sha256. | Optional | 
| sha1 | Restrict returned records with this sha1. | Optional | 
| md5 | Restrict returned records with this md5. | Optional | 
| path | Restrict returned records to this path or path fragment. | Optional | 
| before | A date/time (ISO 8601), restricting results to samples submitted before it. | Optional | 
| after | A date/time (ISO 8601), restricting results to samples submitted after it. | Optional | 
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. | Optional | 
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. | Optional | 
| ioc | Restrict returned records to events of this type. | Optional | 
| org-only | If “true”, will only match against samples submitted by your organization. | Optional | 
| user-only |  If “true”, will only match against samples you submitted. | Optional | 
| sample | A comma-separated list of sample IDs. Restrict results to these samples. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Demisto.File | unknown | File containing result | 

### threat-grid-feeds-domain
***
Get domain threat feed


#### Base Command

`threat-grid-feeds-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Restrict returned records to this domain or hostname. | Optional | 
| before | A date/time (ISO 8601), restricting results to samples submitted before it. | Optional | 
| after | A date/time (ISO 8601), restricting results to samples submitted after it. | Optional | 
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. | Optional | 
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. | Optional | 
| ioc | Restrict returned records to events of this type. | Optional | 
| org-only | If “true”, will only match against samples submitted by your organization. | Optional | 
| user-only |  If “true”, will only match against samples you submitted. | Optional | 
| sample | A comma-separated list of sample IDs. Restrict results to these samples. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Demisto.File | unknown | File containing result | 

### threat-grid-feeds-ip
***
Get ips threat feed


#### Base Command

`threat-grid-feeds-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Restrict returned records to this IP or CIDR block. | Optional | 
| before | A date/time (ISO 8601), restricting results to samples submitted before it. | Optional | 
| after | A date/time (ISO 8601), restricting results to samples submitted after it. | Optional | 
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. | Optional | 
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. | Optional | 
| ioc | Restrict returned records to events of this type. | Optional | 
| org-only | If “true”, will only match against samples submitted by your organization. | Optional | 
| user-only |  If “true”, will only match against samples you submitted. | Optional | 
| sample | A comma-separated list of sample IDs. Restrict results to these samples. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Demisto.File | unknown | File containing result | 

### threat-grid-feeds-network-stream
***
Get network stream threat feed


#### Base Command

`threat-grid-feeds-network-stream`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Restrict returned records to this IP address. | Optional | 
| port | Restrict returned records to this port number. | Optional | 
| before | A date/time (ISO 8601), restricting results to samples submitted before it. | Optional | 
| after | A date/time (ISO 8601), restricting results to samples submitted after it. | Optional | 
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. | Optional | 
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. | Optional | 
| ioc | Restrict returned records to events of this type. | Optional | 
| org-only | If “true”, will only match against samples submitted by your organization. | Optional | 
| user-only |  If “true”, will only match against samples you submitted. | Optional | 
| sample | A comma-separated list of sample IDs. Restrict results to these samples. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Demisto.File | unknown | File containing result | 

### threat-grid-feeds-path
***
Get path threat feed


#### Base Command

`threat-grid-feeds-path`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | Restrict returned records to this path or path fragment. | Optional | 
| before | A date/time (ISO 8601), restricting results to samples submitted before it. | Optional | 
| after | A date/time (ISO 8601), restricting results to samples submitted after it. | Optional | 
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. | Optional | 
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. | Optional | 
| ioc | Restrict returned records to events of this type. | Optional | 
| org-only | If “true”, will only match against samples submitted by your organization. | Optional | 
| user-only |  If “true”, will only match against samples you submitted. | Optional | 
| sample | A comma-separated list of sample IDs. Restrict results to these samples. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Demisto.File | unknown | File containing result | 

### threat-grid-feeds-url
***
Get url threat feed


#### Base Command

`threat-grid-feeds-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Restrict returned records to this URL or URL fragment. | Optional | 
| before | A date/time (ISO 8601), restricting results to samples submitted before it. | Optional | 
| after | A date/time (ISO 8601), restricting results to samples submitted after it. | Optional | 
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. | Optional | 
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. | Optional | 
| ioc | Restrict returned records to events of this type. | Optional | 
| org-only | If “true”, will only match against samples submitted by your organization. | Optional | 
| user-only |  If “true”, will only match against samples you submitted. | Optional | 
| sample | A comma-separated list of sample IDs. Restrict results to these samples. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Demisto.File | unknown | File containing result | 

### threat-grid-get-analysis-artifact
***
Returns the sample id artifact with artifact id


#### Base Command

`threat-grid-get-analysis-artifact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the sample id. | Required | 
| aid | The artificat id requested. | Required | 


#### Context Output

There is no context output for this command.
### threat-grid-get-analysis-artifacts
***
Returns the sample id artifacts


#### Base Command

`threat-grid-get-analysis-artifacts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the sample id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.Analysis | unknown | Analysis datat of the sample | 

### threat-grid-get-analysis-ioc
***
Returns data regarding the specified Indicator of Compromise


#### Base Command

`threat-grid-get-analysis-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the sample id. | Required | 
| ioc | the ioc requested. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.IOCs.Title | unknown | The title of the IOC | 
| ThreatGrid.IOCs.Confidence | unknown | The confidence of the IOC | 
| ThreatGrid.IOCs.Severity | unknown | The severity of the IOC | 
| ThreatGrid.IOCs.IOC | unknown | Threat grid's IOC | 
| ThreatGrid.IOCs.IOCCategory | unknown | The IOC category of the IOC | 
| DBotScore.Indicator | unknown | The indicator value | 
| DBotScore.Vendor | unknown | The indicator vendor | 
| DBotScore.Type | unknown | The indicator type | 
| DBotScore.Score | unknown | The indicator score | 
| ThreatGrid.IOCs.Data.IP | unknown | The IP of the IOC | 
| ThreatGrid.IOCs.Data.URL | unknown | The URL of the IOC | 
| ThreatGrid.IOCs.Data.Domain | unknown | The domain of the IOC | 
| ThreatGrid.IOCs.Data.Path | unknown | The path of the IOC | 
| ThreatGrid.IOCs.Data.SHA256 | unknown | The SHA256 value of the IOC | 
| ThreatGrid.IOCs.Tags | unknown | The tags of the IOC | 

### threat-grid-get-analysis-metadata
***
Returns metadata about the analysis


#### Base Command

`threat-grid-get-analysis-metadata`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the sample id. | Required | 


#### Context Output

There is no context output for this command.
### threat-grid-get-analysis-network-stream
***
Returns data regarding a specific network stream


#### Base Command

`threat-grid-get-analysis-network-stream`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the sample id. | Required | 
| nsid | The network stream id. | Required | 


#### Context Output

There is no context output for this command.
### threat-grid-get-analysis-network-streams
***
Returns the network stream analysis


#### Base Command

`threat-grid-get-analysis-network-streams`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the sample id. | Required | 


#### Context Output

There is no context output for this command.
### threat-grid-get-analysis-process
***
Returns data regarding the specifiic process id in the analysis


#### Base Command

`threat-grid-get-analysis-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the sample id. | Required | 
| pid | the process id requested. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Demisto.File | unknown | File containing result | 

### threat-grid-get-analysis-processes
***
Returns data regarding the analysis processes


#### Base Command

`threat-grid-get-analysis-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the sample id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Demisto.File | unknown | File containing result | 

### threat-grid-submit-urls
***
Submit urls for analysis.


#### Base Command

`threat-grid-submit-urls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Url to be sumbitted. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.URLs | unknown | Results of URL Submission | 
| ThreatGrid.URLs.submission_id | unknown | ID of submitted URL | 
| ThreatGrid.URLs.status | unknown | Status of submitted URL | 
| ThreatGrid.URLs.filename | unknown | Filename of submitted URL | 
| ThreatGrid.URLs.state | unknown | State of submitted URL | 
| ThreatGrid.URLs.analyzing | unknown | True/False if submitted URL is analyzing | 

### threat-grid-advanced-search
***
Advanced search that allows searching URLS, Submissions, Samples etc...


#### Base Command

`threat-grid-advanced-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search query . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Threatgrid.SearchResult | unknown | Result for the searched query | 
