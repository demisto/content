Use the Palo Alto Networks AutoFocus integration to distinguish the most important threats from everyday commodity attacks.
This integration was integrated and tested with version xx of AutoFocus V2 test

## Configure AutoFocus V2 test on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AutoFocus V2 test.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key | TIM customers that upgraded to version 6.2 or above, can have this value pre-configured in their main account so no additional input is needed. To use this feature, upgrade your license so it includes the license key. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Suppress errors for non found indicators |  | False |
    | Additional malicious verdicts |  | False |
    | Create relationships | Create relationships between indicators as part of Enrichment. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### autofocus-search-samples
***
Searches for samples in AutoFocus. To view results, run the autofocus-samples-search-results command with the returned AF Cookie. The AF Cookie expires 120 seconds after the search completes. `Autofocus Query Samples, Sessions and Tags` Playbook is recommended for querying and polling.


#### Base Command

`autofocus-search-samples`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| polling | Use XSOAR built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| query | The query for which to retrieve samples. For additional information on how to build your query using the AF GUI, see the detailed description section. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 
| max_results | The number of results to return. Default is 30. | Optional | 
| sort | The field by which to sort the results. Possible values are: App Name, App Packagename, File type, Size, Finish Date, First Seen (Create Date), Last Updated (Update Date), MD5, SHA1, SHA256, Ssdeep Fuzzy Hash. | Optional | 
| order | The order of the results. Can be "Ascending" or "Descending". Possible values are: Ascending, Descending. | Optional | 
| scope |  The scope of the search. Can be "Private", "Public", or "Global". Possible values are: Private, Public, Global. | Required | 
| file_hash | The MD5, SHA1 or SHA256 hash of the file. | Optional | 
| domain | The domain to search. | Optional | 
| ip | The IP address to search. | Optional | 
| url | The URL to search. | Optional | 
| wildfire_verdict | The Wildfire verdict. Can be "Malware", "Grayware", "Benign", or "Phishing". Possible values are: Malware, Grayware, Benign, Phishing. | Optional | 
| first_seen | The date range of the creation date. Format: YYY Y-MM-DDTHH:MM:SS,YYYY-MM-DDTHH:MM:SS where the first date is the beginning and the second is the end. Example: 2019-09-09T00:00:00,2019-09-09T23:01:59. | Optional | 
| last_updated | The date range of the last updated date. Format: YYY Y-MM-DDTHH:MM:SS,YYYY-MM-DDTHH:MM:SS where the first date is the beginning and the second is the end. Example: 2019-09-09T00:00:00,2019-09-09T23:01:59. | Optional | 
| artifact | Whether to return artifacts of samples. Possible values are: true, false. Default is true. | Optional | 
| af_cookie | The AF Cookie for retrieving results of previous searches. The AF Cookie expires 120 seconds after the search completes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.SamplesSearch.AFCookie | String | The AutoFocus search ID. Use this ID to retrieve search results. The AF Cookie expires 120 seconds after the search completes. | 
| AutoFocus.SamplesSearch.Status | String | The search status. Can be "in progress" or "complete". | 
| AutoFocus.SamplesSearch.SessionStart | Date | The time when the session began. | 
| AutoFocus.SamplesResults.Size | String | The file size in bytes. | 
| AutoFocus.SamplesResults.SHA1 | String | The SHA1 hash of the file. | 
| AutoFocus.SamplesResults.SHA256 | String | The SHA256 hash of the file. | 
| AutoFocus.SamplesResults.Created | Date | The date that the file was created. | 
| AutoFocus.SamplesResults.Finished | Date | Date finished. | 
| AutoFocus.SamplesResults.Region | String | Region of the sample. | 
| AutoFocus.SamplesResults.FileType | String | The file type. | 
| AutoFocus.SamplesResults.Tags | String | The tags attached to the sample. | 
| AutoFocus.SamplesResults.Verdict | Number | The verdict of the sample. | 
| AutoFocus.SamplesResults.TagGroups | String | Groups of relevant tags. | 
| AutoFocus.SamplesSearch.Status | String | The search status. Can be "in progress" or "complete". | 
| File.Size | Number | The size of the file in bytes. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 
| File.Tags | String | Tags of the file. | 
| AutoFocus.SamplesResults.Artifact.b | Number | How many set the artifact as benign. | 
| AutoFocus.SamplesResults.Artifact.g | Number | How many set the artifact as grayware. | 
| AutoFocus.SamplesResults.Artifact.m | Number | How many set the artifact as malicious. | 
| AutoFocus.SamplesResults.Artifact.confidence | String | Confidence in the decision. | 
| AutoFocus.SamplesResults.Artifact.indicator | String | The indicator that was tested. | 
| AutoFocus.SamplesResults.Artifact.indicator_type | String | The indicator type, for example: Mutex, User agent, IPv4, Domain. | 
| AutoFocus.SamplesResults.ID | String | ID of sample search | 


#### Command Example
``` ```

#### Human Readable Output



### autofocus-search-sessions
***
Searches for sessions in AutoFocus. To view results, run the autofocus-sessions-search-results command with the returned AF Cookie. The AF Cookie expires 120 seconds after the search completes. `Autofocus Query Samples, Sessions and Tags` Playbook is recommended for querying and polling.


#### Base Command

`autofocus-search-sessions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| polling | Use XSOAR built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 
| af_cookie | The AF Cookie for retrieving the results of a previous search. The AF Cookie expires 120 seconds after the search completes. | Optional | 
| query | The query for which to retrieve samples. For additional information on how to build your query using the AF GUI, see the detailed description section. | Optional | 
| max_results | The maximum number of results to return. Default is 30. Default is 30. | Optional | 
| sort | The field by which to sort the results. Possible values are: Application, Device Country, Device Country Code, Device Hostname, Device Serial, Device vsys, Destination Country, Destination Country Code, Destination IP, Destination Port, Email Charset, Industry, Source Country, Source Country Code, Source IP, Source Port, SHA256, Time, Upload source. | Optional | 
| order | The order of the results. Can be "Ascending" or "Descending". Possible values are: Ascending, Descending. | Optional | 
| file_hash | The MD5, SHA1 or SHA256 hash of the file. | Optional | 
| domain | The domain to search. | Optional | 
| ip | The IP address to search. | Optional | 
| url | The URL to search. | Optional | 
| time_range | The date range in which to search for sessions. Format: YYYY-MM-DDTHH:MM:SS,YYYY-MM-DDTHH:MM:SS where the first date is the beginning and the second is the end. Example: 2019-09-09T00:00:00,2019-09-09T23:01:59. Possible values are: . | Optional | 
| time_after | The date after which to search for sessions. Format: YYYY-MM-DDTHH:MM:SS Example: 2019-09-09T23:01:59. | Optional | 
| time_before | The date before which to search for sessions. Format: YYYY-MM-DDTHH:MM:SS Example: 2019-09-09T23:01:59. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.SessionsSearch.AFCookie | String | The AutoFocus search ID. Use this ID to get search results. The AF Cookie expires 120 seconds after the search completes. | 
| AutoFocus.SessionsSearch.Status | String | The search status. Can be "in progress" or "complete". | 
| AutoFocus.SessionsSearch.SessionStart | Date | The time when the session began. | 
| AutoFocus.SessionsResults.FileName | String | The name of the file.. | 
| AutoFocus.SessionsResults.ID | String | The session ID. Used to get session details. | 
| AutoFocus.SessionsResults.Industry | String | The related industry. | 
| AutoFocus.SessionsResults.Region | String | The regions of the sessions. | 
| AutoFocus.SessionsResults.SHA256 | String | The SHA256 hash of the file. | 
| AutoFocus.SessionsResults.UploadSource | String | The source of the uploaded sample. | 
| AutoFocus.SessionsResults.FileURL | String | The URL of the file. | 
| AutoFocus.SessionsResults.Tags | String | Relevant tags. | 
| AutoFocus.SessionsSearch.Status | String | The search status. Can be "in progress" or "complete". | 
| File.Name | String | The full file name \(including file extension\). | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.MalwareFamily | String | The malware family associated with the file. | 
| File.Tags | String | Tags of the file. | 
| AutoFocus.SessionsResults.Seen | Date | Session seen. | 


#### Command Example
``` ```

#### Human Readable Output



### autofocus-samples-search-results
***
Returns results of a previous samples search. `Autofocus Query Samples, Sessions and Tags` Playbook is recommended for querying and polling.


#### Base Command

`autofocus-samples-search-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| af_cookie | The AF Cookie for retrieving results of previous searches. The AF Cookie expires 120 seconds after the search completes. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.SamplesResults.Size | String | The file size in bytes. | 
| AutoFocus.SamplesResults.SHA1 | String | The SHA1 hash of the file. | 
| AutoFocus.SamplesResults.SHA256 | String | The SHA256 hash of the file. | 
| AutoFocus.SamplesResults.Created | Date | The date that the file was created. | 
| AutoFocus.SamplesResults.Finished | Date | Date finished. | 
| AutoFocus.SamplesResults.Region | String | Region of the sample. | 
| AutoFocus.SamplesResults.FileType | String | The file type. | 
| AutoFocus.SamplesResults.Tags | String | The tags attached to the sample. | 
| AutoFocus.SamplesResults.Verdict | Number | The verdict of the sample. | 
| AutoFocus.SamplesResults.TagGroups | String | Groups of relevant tags. | 
| AutoFocus.SamplesSearch.Status | String | The search status. Can be "in progress" or "complete". | 
| File.Size | Number | The size of the file in bytes. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 
| File.Tags | String | Tags of the file. | 
| AutoFocus.SamplesResults.Artifact.b | Number | How many set the artifact as benign. | 
| AutoFocus.SamplesResults.Artifact.g | Number | How many set the artifact as grayware. | 
| AutoFocus.SamplesResults.Artifact.m | Number | How many set the artifact as malicious. | 
| AutoFocus.SamplesResults.Artifact.confidence | String | Confidence in the decision. | 
| AutoFocus.SamplesResults.Artifact.indicator | String | The indicator that was tested. | 
| AutoFocus.SamplesResults.Artifact.indicator_type | String | The indicator type, for example: Mutex, User agent, IPv4, Domain. | 
| AutoFocus.SamplesResults.ID | String | ID of sample search | 


#### Command Example
``` ```

#### Human Readable Output



### autofocus-sessions-search-results
***
Returns results of a previous sessions search. `Autofocus Query Samples, Sessions and Tags` Playbook is recommended for querying and polling.


#### Base Command

`autofocus-sessions-search-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| af_cookie | The AF Cookie for retrieving the results of a previous search. The AF Cookie expires 120 seconds after the search completes. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.SessionsResults.FileName | String | The name of the file.. | 
| AutoFocus.SessionsResults.ID | String | The session ID. Used to get session details. | 
| AutoFocus.SessionsResults.Industry | String | The related industry. | 
| AutoFocus.SessionsResults.Region | String | The regions of the sessions. | 
| AutoFocus.SessionsResults.SHA256 | String | The SHA256 hash of the file. | 
| AutoFocus.SessionsResults.UploadSource | String | The source of the uploaded sample. | 
| AutoFocus.SessionsResults.FileURL | String | The URL of the file. | 
| AutoFocus.SessionsResults.Tags | String | Relevant tags. | 
| AutoFocus.SessionsSearch.Status | String | The search status. Can be "in progress" or "complete". | 
| File.Name | String | The full file name \(including file extension\). | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.MalwareFamily | String | The malware family associated with the file. | 
| File.Tags | String | Tags of the file. | 
| AutoFocus.SessionsResults.Seen | Date | Session seen. | 


#### Command Example
``` ```

#### Human Readable Output



### autofocus-get-session-details
***
Get session details by session ID


#### Base Command

`autofocus-get-session-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | The session ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.Sessions.FileName | String | The file name. | 
| AutoFocus.Sessions.ID | String | The session ID. | 
| AutoFocus.Sessions.Industry | String | The related industry. | 
| AutoFocus.Sessions.Region | String | Session regions. | 
| AutoFocus.Sessions.SHA256 | String | TheSHA256 hash of the file. | 
| AutoFocus.Sessions.Seen | Date | Seen date. | 
| AutoFocus.Sessions.UploadSource | String | The source that uploaded the sample. | 
| File.Name | String | The full file name \(including file extension\). | 
| File.SHA256 | String | The SHA256 hash of the file. | 


#### Command Example
``` ```

#### Human Readable Output



### autofocus-sample-analysis
***
Returns properties, behaviors, and activities observed for a sample. Run the command a single time to get the fields and operating systems under HTTP, Coverage, Behavior, Registry, Files, Processes, Connections, and DNS.


#### Base Command

`autofocus-sample-analysis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | The SHA256 hash of the sample to analyze. | Required | 
| os | The analysis environment. Can be "win7", "winxp", "android", "static_analyzer", "mac", or "bare_metal". Possible values are: win7, winxp, android, static_analyzer, mac, bare_metal. | Optional | 
| filter_data | Whether to smartly filter the data. If "False", the data returned will not be smartly filtered, and will significantly reduce integration performance. We recommend setting this to "True". Possible values are: True, False. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.SampleAnalysis.Analysis.Http | Unknown | HTTP requests made when the sample was executed. | 
| AutoFocus.SampleAnalysis.Analysis.Coverage | Unknown | WildFire signatures that matched to the sample. | 
| AutoFocus.SampleAnalysis.Analysis.Behavior | Unknown | Sample behavior: created or modified files, started a process, spawned new processes, modified the registry, or installed browser help objects. | 
| AutoFocus.SampleAnalysis.Analysis.Registry | Unknown | Registry settings and options that showed activity when the sample was executed in the analysis environment. | 
| AutoFocus.SampleAnalysis.Analysis.Files | Unknown | Files that showed activity as a result of the sample being executed. | 
| AutoFocus.SampleAnalysis.Analysis.Processes | Unknown | Processes that showed activity when the sample was executed. | 
| AutoFocus.SampleAnalysis.Analysis.Connections | Unknown | Connections to other hosts on the network when the sample was executed. | 
| AutoFocus.SampleAnalysis.Analysis.Dns | Unknown | DNS activity observed when the sample was executed. | 
| AutoFocus.SampleAnalysis.Analysis.Mutex | Unknown | The mutex created when the programs start is listed with the parent process if the sample generates other program threads when executed in the analysis environment. | 


#### Command Example
``` ```

#### Human Readable Output



### autofocus-tag-details
***
Returns details about the given tag.


#### Base Command

`autofocus-tag-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | The public tag name. Can be retrieved from the top-tags command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.Tag.TagName | String | The simple name of the tag. | 
| AutoFocus.Tag.PublicTagName | String | The public name of the tag. This is used as an ID of the tag. | 
| AutoFocus.Tag.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.Tag.Lasthit | Date | The date that the tag was last encountered. | 
| AutoFocus.Tag.TagDefinitionScope | String | The scope of the tag \("public", "private", or "Unit42"\). | 
| AutoFocus.Tag.CustomerName | String | The organization that created the tag. | 
| AutoFocus.Tag.Source | String | The organization or individual that discovered the threat that is defined in the tag. | 
| AutoFocus.Tag.TagClass | String | The classification of the tag. | 
| AutoFocus.Tag.TagDefinitionStatus | String | The status of the tag definition \("enabled", "disabled", "removing", or "rescoping"\). | 
| AutoFocus.Tag.TagGroup | String | The tag group of the tag. | 
| AutoFocus.Tag.Description | String | Tag description. | 


#### Command Example
``` ```

#### Human Readable Output



### autofocus-top-tags-search
***
Performs a search to identify the most popular tags. `Autofocus Query Samples, Sessions and Tags` Playbook is recommended for querying and polling.


#### Base Command

`autofocus-top-tags-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | Scope of the search. Can be "industry", "organization", "all", or "global". Possible values are: industry, organization, all, global. | Required | 
| polling | Use XSOAR built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| af_cookie | The AF Cookie for retrieving results of previous searches. The AF Cookie expires 120 seconds after the search completes. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 40. | Optional | 
| class | Tag class. - Malware Family: group of malware that have shared properties or common functions. - Campaign:  targeted attack, which might include several incidents or sets of activities. - Actor: individual or group that initiates a campaign using malware families. - Exploit: an attack, which takes advantage of a software or network weakness, bug, or vulnerability to manipulate the behavior of the system. - Malicious Behavior: behavior that is not specific to a malware family or campaign, but indicates that your system has been compromised. Possible values are: Actor, Campaign, Exploit, Malicious Behavior, Malware Family. | Required | 
| private | Whether the tag scope is "private". If "True", the tag scope is private. Default is "False". Possible values are: True, False. Default is False. | Optional | 
| public | Whether the tag scope is "public". If "True", the tag scope is public. Default is "False". Possible values are: True, False. Default is False. | Optional | 
| commodity | Whether the tag scope is "commodity". If "True", the tag scope is commodity. Default is "False". Possible values are: True, False. Default is False. | Optional | 
| unit42 | Whether the tag scope is "Unit42". If "True", the tag scope is unit42. Default is "False". Possible values are: True, False. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.TopTagsSearch.AFCookie | String | AutoFocus search ID. Use this ID to get search results. The AF Cookie expires 120 seconds after the search completes. | 
| AutoFocus.TopTagsSearch.Status | String | The search status. Can be "in progress" or "complete". | 
| AutoFocus.SamplesSearch.SessionStart | Date | The time when the session began. | 
| AutoFocus.TopTagsResults.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.TopTagsResults.PublicTagName | String | The public name of the tag. This is used as an ID of the tag. | 
| AutoFocus.TopTagsResults.TagName | String | The simple name of the tag. | 
| AutoFocus.TopTagsResults.Lasthit | Date | The last encounter date of the tag. | 
| AutoFocus.TopTagsSearch.Status | String | The search status. Can be "in progress" or "complete". | 


#### Command Example
``` ```

#### Human Readable Output



### autofocus-top-tags-results
***
Returns the results of a previous top tags search. `Autofocus Query Samples, Sessions and Tags` Playbook is recommended for querying and polling.


#### Base Command

`autofocus-top-tags-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| af_cookie | The AF Cookie for retrieving results of previous search. Note: The AF Cookie expires 120 seconds after the search completes. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.TopTagsResults.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.TopTagsResults.PublicTagName | String | The public name of the tag. This is used as an ID of the tag. | 
| AutoFocus.TopTagsResults.TagName | String | The simple name of the tag. | 
| AutoFocus.TopTagsResults.Lasthit | Date | The last encounter date of the tag. | 
| AutoFocus.TopTagsSearch.Status | String | The search status. Can be "in progress" or "complete". | 


#### Command Example
``` ```

#### Human Readable Output



### ip
***
Checks the reputation of an IP address in AutoFocus.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| IP.Address | String | The IP address. | 
| IP.Relationships.EntityA | string | The source of the relationship. | 
| IP.Relationships.EntityB | string | The destination of the relationship. | 
| IP.Relationships.Relationship | string | The name of the relationship. | 
| IP.Relationships.EntityAType | string | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | string | The type of the destination of the relationship. | 
| AutoFocus.IP.IndicatorValue | String | The IP address. | 
| AutoFocus.IP.IndicatorType | String | The indicator type. | 
| AutoFocus.IP.LatestPanVerdicts | Unknown | Latest verdicts from Palo Alto Networks products. Can be either PAN_DB or WF_SAMPLE\(WildFire\). | 
| IP.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| IP.MalwareFamily | String | The malware family associated with the IP. | 
| IP.Tags | String | Tags that are associated with the IP. | 
| AutoFocus.IP.Tags.PublicTagName | String | The public name of the tag. This is used as an ID of the tag. | 
| AutoFocus.IP.Tags.TagName | String | The simple name of the tag. | 
| AutoFocus.IP.Tags.CustomerName | String | The organization that created the tag. | 
| AutoFocus.IP.Tags.Source | String | The organization or individual that discovered the threat that is defined in the tag. | 
| AutoFocus.IP.Tags.TagDefinitionScopeID | Number | The scope ID of the tag. | 
| AutoFocus.IP.Tags.TagDefinitionStatusID | Number | The definition status ID of the tag. | 
| AutoFocus.IP.Tags.TagClassID | Number | The classification ID of the tag. | 
| AutoFocus.IP.Tags.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.IP.Tags.Lasthit | Date | The date that the tag was last encountered. | 
| AutoFocus.IP.Tags.Description | String | The tag description. | 


#### Command Example
``` ```

#### Human Readable Output



### url
***
Checks the reputation of a URL in AutoFocus.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| URL.Data | String | The URL address. | 
| URL.Relationships.EntityA | string | The source of the relationship. | 
| URL.Relationships.EntityB | string | The destination of the relationship. | 
| URL.Relationships.Relationship | string | The name of the relationship. | 
| URL.Relationships.EntityAType | string | The type of the source of the relationship. | 
| URL.Relationships.EntityBType | string | The type of the destination of the relationship. | 
| AutoFocus.URL.IndicatorValue | String | The URL value. | 
| AutoFocus.URL.IndicatorType | String | The indicator type. | 
| AutoFocus.URL.LatestPanVerdicts | Unknown | Latest verdicts from Palo Alto Networks products. Can be either PAN_DB or WF_SAMPLE\(WildFire\). | 
| URL.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| URL.MalwareFamily | String | The malware family associated with the url. | 
| URL.Tags | String | Tags that are associated with the url. | 
| AutoFocus.URL.Tags.PublicTagName | String | The public name of the tag. This is used as an ID of the tag. | 
| AutoFocus.URL.Tags.TagName | String | The simple name of the tag. | 
| AutoFocus.URL.Tags.CustomerName | String | The organization that created the tag. | 
| AutoFocus.URL.Tags.Source | String | The organization or individual that discovered the threat that is defined in the tag. | 
| AutoFocus.URL.Tags.TagDefinitionScopeID | Number | The scope ID of the tag. | 
| AutoFocus.URL.Tags.TagDefinitionStatusID | Number | The definition status ID of the tag. | 
| AutoFocus.URL.Tags.TagClassID | Number | The classification ID of the tag. | 
| AutoFocus.URL.Tags.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.URL.Tags.Lasthit | Date | The date that the tag was last encountered. | 
| AutoFocus.URL.Tags.Description | String | The tag description. | 


#### Command Example
``` ```

#### Human Readable Output



### file
***
Checks the reputation of a file in AutoFocus.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The SHA256 hash of the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| File.SHA256 | String | SHA256 hash of the file. | 
| File.Relationships.EntityA | string | The source of the relationship. | 
| File.Relationships.EntityB | string | The destination of the relationship. | 
| File.Relationships.Relationship | string | The name of the relationship. | 
| File.Relationships.EntityAType | string | The type of the source of the relationship. | 
| File.Relationships.EntityBType | string | The type of the destination of the relationship. | 
| File.Tags.TagGroups.TagGroupName | String | The tag's group name. | 
| File.Tags.Aliases | String | Aliases of the tags. | 
| File.Tags.PublicTagName | String | The public name of the tag. This is usually used as the ID of the tag. | 
| File.Tags.TagName | String | The simple name of the tag. | 
| AutoFocus.File.IndicatorValue | String | SHA256 of the file. | 
| AutoFocus.File.IndicatorType | String | The indicator type. | 
| AutoFocus.File.LatestPanVerdicts | Unknown | Latest verdicts from Palo Alto Networks products. Can be either PAN_DB or WF_SAMPLE\(WildFire\). | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| AutoFocus.File.Tags.PublicTagName | String | The public name of the tag. This is used as an ID of the tag. | 
| AutoFocus.File.Tags.TagName | String | The simple name of the tag. | 
| AutoFocus.File.Tags.CustomerName | String | The organization that created the tag. | 
| AutoFocus.File.Tags.Source | String | The organization or individual that discovered the threat that is defined in the tag. | 
| AutoFocus.File.Tags.TagDefinitionScopeID | Number | The scope ID of the tag. | 
| AutoFocus.File.Tags.TagDefinitionStatusID | Number | The definition status ID of the tag. | 
| AutoFocus.File.Tags.TagClassID | Number | The classification ID of the tag. | 
| AutoFocus.File.Tags.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.File.Tags.Lasthit | Date | The date that the tag was last encountered. | 
| AutoFocus.File.Tags.Description | String | The tag description. | 


#### Command Example
``` ```

#### Human Readable Output



### domain
***
Checks the reputation of a domain in AutoFocus.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| AutoFocus.Domain.IndicatorValue | String | The domain. | 
| AutoFocus.Domain.IndicatorType | String | The indicator type. | 
| AutoFocus.Domain.LatestPanVerdicts | Unknown | Latest verdicts from Palo Alto Networks products. Can be either PAN_DB or WF_SAMPLE\(WildFire\). | 
| AutoFocus.Domain.Tags.PublicTagName | String | The public name of the tag. This is used as an ID of the tag. | 
| AutoFocus.Domain.Tags.TagName | String | The simple name of the tag. | 
| AutoFocus.Domain.Tags.CustomerName | String | The organization that created the tag. | 
| AutoFocus.Domain.Tags.Source | String | The organization or individual that discovered the threat that is defined in the tag. | 
| AutoFocus.Domain.Tags.TagDefinitionScopeID | Number | The scope ID of the tag. | 
| AutoFocus.Domain.Tags.TagDefinitionStatusID | Number | The definition status ID of the tag. | 
| AutoFocus.Domain.Tags.TagClassID | Number | The classification ID of the tag. | 
| AutoFocus.Domain.Tags.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.Domain.Tags.Lasthit | Date | The date that the tag was last encountered. | 
| AutoFocus.Domain.Tags.Description | String | The tag description. | 
| AutoFocus.Domain.WhoisAdminCountry | String | The country of the domain administrator. | 
| AutoFocus.Domain.WhoisAdminEmail | String | The email address of the domain administrator. | 
| AutoFocus.Domain.WhoisAdminName | String | The name of the domain administrator. | 
| AutoFocus.Domain.WhoisDomainCreationDate | Date | The date that the domain was created. | 
| AutoFocus.Domain.WhoisDomainExpireDate | Date | The date that the domain expires. | 
| AutoFocus.Domain.WhoisDomainUpdateDate | Date | The date that the domain was last updated. | 
| AutoFocus.Domain.WhoisRegistrar | String | The name of the registrar. | 
| AutoFocus.Domain.WhoisRegistrarUrl | String | The email address of the registrar. | 
| AutoFocus.Domain.WhoisRegistrant | String | The name of the registrant. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| Domain.MalwareFamily | String | The malware family associated with the domain. | 
| Domain.Relationships.EntityA | string | The source of the relationship. | 
| Domain.Relationships.EntityB | string | The destination of the relationship. | 
| Domain.Relationships.Relationship | string | The name of the relationship. | 
| Domain.Relationships.EntityAType | string | The type of the source of the relationship. | 
| Domain.Relationships.EntityBType | string | The type of the destination of the relationship. | 
| Domain.Tags | String | Tags that are associated with the domain. | 
| Domain.CreationDate | Date | The date that the domain was created. | 
| Domain.UpdatedDate | String | The date that the domain was last updated. | 
| Domain.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Admin.Email | String | The email address of the domain administrator. | 
| Domain.Admin.Name | String | The name of the domain administrator. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: "GoDaddy" | 


#### Command Example
``` ```

#### Human Readable Output



### autofocus-get-export-list-indicators
***
Gets export list indicators from AutoFocus.


#### Base Command

`autofocus-get-export-list-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label | The label of the exported list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.ExportListIndicator.Type | String | The indicator type in the export list.  | 
| AutoFocus.ExportListIndicator.Value | String | The value of the indicator in the export list. | 
| IP.Address | String | The IP address. | 
| URL.Data | String | The URL address. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| Domain.Name | String | The domain name. | 


#### Command Example
``` ```

#### Human Readable Output


