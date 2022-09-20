Analyse retro hunts, read live hunt notifications and download files from VirusTotal.
## Configure VirusTotal - Premium (API v3)_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for VirusTotal - Premium (API v3)_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Key (leave empty. Fill in the API key in the password field.) | True |
    | API Key | True |
    | Fetch incidents | False |
    | Incident type | False |
    | Maximum number of incidents per fetch | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) or a date or epoch timestamp. | False |
    | Tag: The ruleset's name or the identifier for the YARA rule matching the file to fetch its notifications. Leave blank to fetch all. | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### vt-private-download-file
***
Downloads file from VirusTotal


#### Base Command

`vt-private-download-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | SHA-256, SHA-1 or MD5 identifying the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File | Unknown | The file details command results. | 
| File.Name | String | The full file name \(including the file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Extension | String | The file extension. For example: "xls". | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 

### vt-private-zip-create
***
Creates a password-protected ZIP file containing files from VirusTotal.


#### Base Command

`vt-private-zip-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A commma separated list of hashes (SHA-256, SHA-1, or MD5) for the files included in the ZIP. | Required | 
| password | A password to protect the zip. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Zip.id | String | ID of the zip | 
| VirusTotal.Zip.type | String | Type of the ID \(zip_file\) | 
| VirusTotal.Zip.links.self | String | Self link to file | 
| VirusTotal.Zip.attributes.files_error | Number | The number of files resulted in error | 
| VirusTotal.Zip.attributes.files_ok | Number | The number of files resulted in success zipped. | 
| VirusTotal.Zip.attributes.progress | Number | Progress of the zipping command in percentage. | 
| VirusTotal.Zip.attributes.status | String | The status of the zip process. "finished" is the state when finished. | 

### vt-private-zip-get
***
Retrieve information about a ZIP file.


#### Base Command

`vt-private-zip-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| zip_id | A zip ID. Can be retrieved from the output of vt-private-zip-create. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Zip.id | String | ID of the zip | 
| VirusTotal.Zip.type | String | Type of the ID \(zip_file\) | 
| VirusTotal.Zip.links.self | String | Self link to file | 
| VirusTotal.Zip.attributes.files_error | Number | The number of files resulted in error | 
| VirusTotal.Zip.attributes.files_ok | Number | The number of files resulted in success zipped. | 
| VirusTotal.Zip.attributes.progress | Number | Progress of the zipping command in percentage. | 
| VirusTotal.Zip.attributes.status | String | The status of the zip process. "finished" is the state when finished. | 

### vt-private-zip-download
***
Download a ZIP file.


#### Base Command

`vt-private-zip-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| zip_id | A zip ID. Can be retrieved from the output of vt-private-zip-create. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File | Unknown | The file details command results. | 
| File.Name | String | The full file name \(including the file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Extension | String | The file extension. For example: "xls". | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 

### vt-private-file-sandbox-pcap
***
Extracted PCAP from a sandbox analysis.


#### Base Command

`vt-private-file-sandbox-pcap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Sandbox report ID. Can be aquired from vt-file-sandbox-report in VirusTotal (API v3) integration. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File | Unknown | The file details command results. | 
| File.Name | String | The full file name \(including the file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Extension | String | The file extension. For example: "xls". | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 

### vt-private-intelligence-search
***
Search for files.


#### Base Command

`vt-private-intelligence-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search query. | Required | 
| limit | Maximum number of results. Default is 10. | Optional | 
| order | The order value can be sorted depends on the query type. See documentation. https://developers.virustotal.com/v3.0/reference#intelligence-search. | Optional | 
| cursor | Continuation cursor. | Optional | 
| descriptors_only | Whether to return full object information or just object descriptors. Possible values are: true, false. Default is false. | Optional | 
| extended_data | Whether to return full data information. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.IntelligenceSearch.attributes.last_analysis_stats.harmless | Number | number of reports saying that is harmless. | 
| VirusTotal.IntelligenceSearch.attributes.last_analysis_stats.malicious | Number | number of reports saying that is malicious | 
| VirusTotal.IntelligenceSearch.attributes.last_analysis_stats.suspicious | Number | number of reports saying that is suspicious. | 
| VirusTotal.IntelligenceSearch.attributes.last_analysis_stats.undetected | Number | number of reports saying that is undetected. | 
| VirusTotal.IntelligenceSearch.attributes.last_analysis_stats.timeout | Number | number of timeouts when analysing this URL/file. | 
| VirusTotal.IntelligenceSearch.attributes.reputation | Number | file's score calculated from all votes posted by the VirusTotal community. | 
| VirusTotal.IntelligenceSearch.attributes.last_modification_date | Number | date when the object itself was last modified. UTC timestamp. | 
| VirusTotal.IntelligenceSearch.attributes.total_votes.harmless | Number | number of positive votes. | 
| VirusTotal.IntelligenceSearch.attributes.total_votes.malicious | Number | number of negative votes. | 
| VirusTotal.IntelligenceSearch.type | String | The type of the indicator \(ip_address, domain, url, file\) | 
| VirusTotal.IntelligenceSearch.id | String | ID of the indicator | 
| VirusTotal.IntelligenceSearch.links.self | String | Link to the response | 

### vt-private-search-file
***
Search for files.


#### Base Command

`vt-private-search-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | File search query. For example, query="type:peexe size:90kb+ positives:5+ behaviour:'taskkill'". | Required | 
| fullResponse | Return all of the results, note that it can be thousands of results. Prefer not to use in playbooks. The default value is "false". Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.SearchFile.SearchResult | string | The hashes of files that fit the query | 
| VirusTotal.SearchFile.Query | string | Original search query | 

### vt-private-livehunt-rules-get-by-id
***
Retrieve VT Hunting livehunt rulesets.


#### Base Command

`vt-private-livehunt-rules-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ruleset identifier. Can be retreived from the vt-private-livehunt-rules-list command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntRule.attributes.name | String | The rule's name | 
| VirusTotal.LiveHuntRule.attributes.modification_date | Number | last modification date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rules | String | rule file contents | 
| VirusTotal.LiveHuntRule.attributes.enabled | Boolean | whether it's enabled or not | 
| VirusTotal.LiveHuntRule.attributes.creation_date | Number | Creation date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rule_names | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntRule.attributes.limit | Number | max number of notifications that will be generated by the ruleset in a 24h period. If a match is found, number of generated hunting notifications in the last 24h is looked up and if it's greater than this limit, that match is ignored. | 
| VirusTotal.LiveHuntRule.attributes.number_of_rules | Number | Number of rules presented in the set | 
| VirusTotal.LiveHuntRule.type | String | The type of the entry \(hunting_ruleset\) | 
| VirusTotal.LiveHuntRule.id | Date | ID of the ruleset | 
| VirusTotal.LiveHuntRule.links.self | String | Link to the ruleset | 

### vt-private-livehunt-rules-list
***
Retrieve VT Hunting livehunt rulesets.


#### Base Command

`vt-private-livehunt-rules-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Return the rulesets matching the given criteria only. | Optional | 
| limit | Maximum number of results. Default is 10. | Optional | 
| order | Sort order. Possible values are: name-, creation_date-, modification_date-, name+, creation_date+, modification_date+. | Optional | 
| cursor | Continuation cursor. | Optional | 
| enabled | Should list only enabled or disabled rules. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntRule.attributes.name | String | The rule's name | 
| VirusTotal.LiveHuntRule.attributes.modification_date | Number | last modification date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rules | String | rule file contents | 
| VirusTotal.LiveHuntRule.attributes.enabled | Boolean | whether it's enabled or not | 
| VirusTotal.LiveHuntRule.attributes.creation_date | Number | creation date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rule_names | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntRule.attributes.limit | Number | max number of notifications that will be generated by the ruleset in a 24h period. If a match is found, number of generated hunting notifications in the last 24h is looked up and if it's greater than this limit, that match is ignored. | 
| VirusTotal.LiveHuntRule.attributes.number_of_rules | Number | Number of rules presented in the set | 
| VirusTotal.LiveHuntRule.type | String | The type of the entry \(hunting_ruleset\) | 
| VirusTotal.LiveHuntRule.id | Date | ID of the ruleset | 
| VirusTotal.LiveHuntRule.links.self | String | Link to the ruleset | 

### vt-private-livehunt-rules-create
***
Create a new VT Hunting Livehunt ruleset.


#### Base Command

`vt-private-livehunt-rules-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the rule. | Required | 
| yara_rule | The rule itself. | Required | 
| enabled | Whatever to enable the rule. Possible values are: true, false. Default is false. | Optional | 
| notification_emails | A comma-separated list of emails to notify. | Optional | 
| limit | max number of notifications that will be generated by the ruleset in a 24h period. If a match is found, number of generated hunting notifications in the last 24h is looked up and if it's greater than this limit, that match is ignored. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntRule.attributes.name | String | The rule's name | 
| VirusTotal.LiveHuntRule.attributes.modification_date | Number | last modification date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rules | String | rule file contents | 
| VirusTotal.LiveHuntRule.attributes.enabled | Boolean | whether it's enabled or not | 
| VirusTotal.LiveHuntRule.attributes.creation_date | Number | creation date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rule_names | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntRule.attributes.limit | Number | max number of notifications that will be generated by the ruleset in a 24h period. If a match is found, number of generated hunting notifications in the last 24h is looked up and if it's greater than this limit, that match is ignored. | 
| VirusTotal.LiveHuntRule.attributes.number_of_rules | Number | Number of rules presented in the set | 
| VirusTotal.LiveHuntRule.type | String | The type of the entry \(hunting_ruleset\) | 
| VirusTotal.LiveHuntRule.id | Date | ID of the ruleset | 
| VirusTotal.LiveHuntRule.links.self | String | Link to the ruleset | 

### vt-private-livehunt-rules-update
***
Update a VT Hunting Livehunt ruleset.


#### Base Command

`vt-private-livehunt-rules-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Rule identifier. Can be retrieved from the vt-private-livehunt-rules-list command. | Required | 
| yara_rule | The rule itself. | Optional | 
| enabled | Whatever to enable the rule. Possible values are: true, false. Default is false. | Optional | 
| notification_emails | A comma-separated list of emails to notify. | Optional | 
| limit | max number of notifications that will be generated by the ruleset in a 24h period. If a match is found, number of generated hunting notifications in the last 24h is looked up and if it's greater than this limit, that match is ignored. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntRule.attributes.name | String | The rule's name | 
| VirusTotal.LiveHuntRule.attributes.modification_date | Number | last modification date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rules | String | rule file contents | 
| VirusTotal.LiveHuntRule.attributes.enabled | Boolean | whether it's enabled or not | 
| VirusTotal.LiveHuntRule.attributes.creation_date | Number | creation date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rule_names | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntRule.attributes.limit | Number | max number of notifications that will be generated by the ruleset in a 24h period. If a match is found, number of generated hunting notifications in the last 24h is looked up and if it's greater than this limit, that match is ignored. | 
| VirusTotal.LiveHuntRule.attributes.number_of_rules | Number | Number of rules presented in the set | 
| VirusTotal.LiveHuntRule.type | String | The type of the entry \(hunting_ruleset\) | 
| VirusTotal.LiveHuntRule.id | Date | ID of the ruleset | 
| VirusTotal.LiveHuntRule.links.self | String | Link to the ruleset | 

### vt-private-livehunt-rules-delete
***
Delete a VT Hunting Livehunt ruleset.


#### Base Command

`vt-private-livehunt-rules-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ruleset identifier. Can be retreived from the vt-private-livehunt-rules-list. | Required | 


#### Context Output

There is no context output for this command.
### vt-private-livehunt-notifications-list
***
Retrieve VT Hunting Livehunt notifications.


#### Base Command

`vt-private-livehunt-notifications-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of notifications to retrieve. Maximum can be up to 40. Default is 10. | Optional | 
| from_time | Fetch notification from given time. Can be epoch time, a date or time range (3 days, 1 year). | Optional | 
| to_time | Fetch notification from given time. Can be epoch time or a date. | Optional | 
| cursor | Continuation cursor. | Optional | 
| tag | Filter notifications by tag. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntNotification.meta.count | Number | Notification count | 
| VirusTotal.LiveHuntNotification.meta.cursor | String | The cursor of the list | 
| VirusTotal.LiveHuntNotification.data.attributes.tags | String | notification tags. | 
| VirusTotal.LiveHuntNotification.data.attributes.source_country | String | Source country of the notification | 
| VirusTotal.LiveHuntNotification.data.attributes.source_key | String | Source key of the notificaton | 
| VirusTotal.LiveHuntNotification.data.attributes.snippet | String | The snippet ID \(if exists\) | 
| VirusTotal.LiveHuntNotification.data.attributes.rule_name | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntNotification.data.attributes.date | Number | The date of the notification in epoch | 
| VirusTotal.LiveHuntNotification.data.attributes.match_in_subfile | Boolean | whether the match was in a subfile or not. | 
| VirusTotal.LiveHuntNotification.data.type | String | Type of the notification \(hunting_notification\) | 
| VirusTotal.LiveHuntNotification.data.id | String | The ID of the notification | 
| VirusTotal.LiveHuntNotification.data.links.self | String | The link to the notificaton | 
| VirusTotal.LiveHuntNotification.links.self | String | The link to the current page | 
| VirusTotal.LiveHuntNotification.links.next | String | The link to the next page | 

### vt-private-livehunt-notifications-files-list
***
Retrieve file objects for VT Hunting Livehunt notifications.


#### Base Command

`vt-private-livehunt-notifications-files-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | String to search within the hunting notification tags. | Optional | 
| cursor | Continuation cursor. | Optional | 
| limit | Maximum number of notifications to retrieve. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntFiles.meta.count | Number | Total file's count. | 
| VirusTotal.LiveHuntFiles.meta.cursor | String | Cursor of the call | 
| VirusTotal.LiveHuntFiles.data.attributes.type_description | String | describes the file type. | 
| VirusTotal.LiveHuntFiles.data.attributes.tlsh | String | Trend Micro's TLSH hash | 
| VirusTotal.LiveHuntFiles.data.attributes.vhash | String | in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | 
| VirusTotal.LiveHuntFiles.data.attributes.exiftool | String | exiftool is a program for extracting Exif metadata from different file formats. Metadata shown may vary depending on the file type, and given the nature of Exif metadata, some fields may appear or not. | 
| VirusTotal.LiveHuntFiles.data.attributes.trid.file_type | String | TrID is a utility designed to identify file types from their binary signatures. | 
| VirusTotal.LiveHuntFiles.data.attributes.trid.probability | Number | probability of file format identification \(given as percentage\). | 
| VirusTotal.LiveHuntFiles.data.attributes.creation_date | Number | extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.reputation | Number | file's score calculated from all votes posted by the VirusTotal community. | 
| VirusTotal.LiveHuntFiles.data.attributes.names | String | all file names associated with the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_modification_date | Number | date when the object itself was last modified. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.type_tag | String | tag representing the file type. Can be used in vt-private-intelligence-search | 
| VirusTotal.LiveHuntFiles.data.attributes.times_submitted | Number | number of times the file has been posted to VirusTotal. | 
| VirusTotal.LiveHuntFiles.data.attributes.total_votes.harmless | Number | number of positive votes. | 
| VirusTotal.LiveHuntFiles.data.attributes.total_votes.malicious | Number | number of negative votes. | 
| VirusTotal.LiveHuntFiles.data.attributes.size | Number | file size in bytes. | 
| VirusTotal.LiveHuntFiles.data.attributes.type_extension | String | specifies file extension. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_submission_date | Number | most recent date the file was posted to VirusTotal. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.downloadable | Boolean | true if the file can be downloaded, false otherwise. \(use vt-private-download-file\) to download the file\) | 
| VirusTotal.LiveHuntFiles.data.attributes.sha256 | String | SHA-256 of the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.tags | String | The file's tags. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_date | Number | most recent scan date. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.unique_sources | Number | indicates from how many different sources the file has been posted from. | 
| VirusTotal.LiveHuntFiles.data.attributes.first_submission_date | Number | date when the file was first seen in VirusTotal. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.ssdeep | String | SSDeep of the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.md5 | String | MD5 of the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.sha1 | String | SHA-1 if the file | 
| VirusTotal.LiveHuntFiles.data.attributes.magic | String | magic identifier of this app in hex format. | 
| VirusTotal.LiveHuntFiles.data.attributes.main_icon.raw_md5 | String | MD5 of the file's icon. | 
| VirusTotal.LiveHuntFiles.data.attributes.main_icon.dhash | Date | The dhash of the file's icon | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.harmless | Number | number of reports saying that is harmless. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.type-unsupported | Number | number of AV engines that don't support that type of file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.suspicious | Number | number of reports saying that is suspicious. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.confirmed-timeout | Number | number of AV engines that reach a timeout when analysing that file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.timeout | Number | number of timeouts when analysing this URL/file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.failure | Number | number of AV engines that fail when analysing that file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.malicious | Number | number of reports saying that is malicious | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.undetected | Number | number of reports saying that is undetected. | 
| VirusTotal.LiveHuntFiles.data.attributes.meaningful_name | String | the most interesting name out of all file's names. | 
| VirusTotal.LiveHuntFiles.data.type | String | Type of the entry \(file\) | 
| VirusTotal.LiveHuntFiles.data.id | String | file ID | 
| VirusTotal.LiveHuntFiles.data.links.self | String | link to the file | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_id | String | The notification ID the file is connected to | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_source_key | String | The notification's source key | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_tags | String | notification tags. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.ruleset_name | String | matched rule's ruleset name. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_source_country | String | The notification's source country of the notification | 
| VirusTotal.LiveHuntFiles.data.context_attributes.rule_name | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_snippet | String | The notification snippet ID | 
| VirusTotal.LiveHuntFiles.data.context_attributes.ruleset_id | Date | VirusTotal's ruleset ID. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_date | Number | The notification date in epch. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.match_in_subfile | Boolean | whether the match was in a subfile or not. | 
| VirusTotal.LiveHuntFiles.links.self | String | Link to the current apge | 
| VirusTotal.LiveHuntFiles.links.next | String | Link to the next page | 

### vt-private-livehunt-notifications-files-get-by-hash
***
Retrieve file objects for VT Hunting Livehunt notifications.


#### Base Command

`vt-private-livehunt-notifications-files-get-by-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | Hashes to search within VirusTotal. Will search only hashes and will ignore any other value. | Required | 
| cursor | Continuation cursor. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntFiles.meta.count | Number | Total file's count. | 
| VirusTotal.LiveHuntFiles.meta.cursor | String | Cursor of the call | 
| VirusTotal.LiveHuntFiles.data.attributes.type_description | String | describes the file type. | 
| VirusTotal.LiveHuntFiles.data.attributes.tlsh | String | Trend Micro's TLSH hash | 
| VirusTotal.LiveHuntFiles.data.attributes.vhash | String | in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | 
| VirusTotal.LiveHuntFiles.data.attributes.exiftool | String | exiftool is a program for extracting Exif metadata from different file formats. Metadata shown may vary depending on the file type, and given the nature of Exif metadata, some fields may appear or not. | 
| VirusTotal.LiveHuntFiles.data.attributes.trid.file_type | String | TrID is a utility designed to identify file types from their binary signatures. | 
| VirusTotal.LiveHuntFiles.data.attributes.trid.probability | Number | probability of file format identification \(given as percentage\). | 
| VirusTotal.LiveHuntFiles.data.attributes.creation_date | Number | extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.reputation | Number | file's score calculated from all votes posted by the VirusTotal community. | 
| VirusTotal.LiveHuntFiles.data.attributes.names | String | all file names associated with the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_modification_date | Number | date when the object itself was last modified. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.type_tag | String | tag representing the file type. Can be used in vt-private-intelligence-search | 
| VirusTotal.LiveHuntFiles.data.attributes.times_submitted | Number | number of times the file has been posted to VirusTotal. | 
| VirusTotal.LiveHuntFiles.data.attributes.total_votes.harmless | Number | number of positive votes. | 
| VirusTotal.LiveHuntFiles.data.attributes.total_votes.malicious | Number | number of negative votes. | 
| VirusTotal.LiveHuntFiles.data.attributes.size | Number | file size in bytes. | 
| VirusTotal.LiveHuntFiles.data.attributes.type_extension | String | specifies file extension. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_submission_date | Number | most recent date the file was posted to VirusTotal. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.downloadable | Boolean | true if the file can be downloaded, false otherwise. \(use vt-private-download-file\) to download the file\) | 
| VirusTotal.LiveHuntFiles.data.attributes.sha256 | String | SHA-256 of the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.tags | String | The file's tags. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_date | Number | most recent scan date. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.unique_sources | Number | indicates from how many different sources the file has been posted from. | 
| VirusTotal.LiveHuntFiles.data.attributes.first_submission_date | Number | date when the file was first seen in VirusTotal. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.ssdeep | String | SSDeep of the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.md5 | String | MD5 of the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.sha1 | String | SHA-1 if the file | 
| VirusTotal.LiveHuntFiles.data.attributes.magic | String | magic identifier of this app in hex format. | 
| VirusTotal.LiveHuntFiles.data.attributes.main_icon.raw_md5 | String | MD5 of the file's icon. | 
| VirusTotal.LiveHuntFiles.data.attributes.main_icon.dhash | Date | The dhash of the file's icon | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.harmless | Number | number of reports saying that is harmless. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.type-unsupported | Number | number of AV engines that don't support that type of file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.suspicious | Number | number of reports saying that is suspicious. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.confirmed-timeout | Number | number of AV engines that reach a timeout when analysing that file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.timeout | Number | number of timeouts when analysing this URL/file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.failure | Number | number of AV engines that fail when analysing that file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.malicious | Number | number of reports saying that is malicious | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.undetected | Number | number of reports saying that is undetected. | 
| VirusTotal.LiveHuntFiles.data.attributes.meaningful_name | String | the most interesting name out of all file's names. | 
| VirusTotal.LiveHuntFiles.data.type | String | Type of the entry \(file\) | 
| VirusTotal.LiveHuntFiles.data.id | String | file ID | 
| VirusTotal.LiveHuntFiles.data.links.self | String | link to the file | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_id | String | The notification ID the file is connected to | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_source_key | String | The notification's source key | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_tags | String | notification tags. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.ruleset_name | String | matched rule's ruleset name. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_source_country | String | The notification's source country of the notification | 
| VirusTotal.LiveHuntFiles.data.context_attributes.rule_name | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_snippet | String | The notification snippet ID | 
| VirusTotal.LiveHuntFiles.data.context_attributes.ruleset_id | Date | VirusTotal's ruleset ID. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_date | Number | The notification date in epch. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.match_in_subfile | Boolean | whether the match was in a subfile or not. | 
| VirusTotal.LiveHuntFiles.links.self | String | Link to the current apge | 
| VirusTotal.LiveHuntFiles.links.next | String | Link to the next page | 

### vt-private-livehunt-rule-list-files
***
Get a VT Hunting Livehunt ruleset by hunting notification files relationship.


#### Base Command

`vt-private-livehunt-rule-list-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Rule identifier. Can be retrieved from the vt-private-livehunt-rules-list command. | Required | 
| cursor | Continuation cursor. | Optional | 
| limit | Maximum number of notifications to retrieve. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntFiles.id | String | ID of the file | 
| VirusTotal.LiveHuntFiles.type | String | Type of the entry \(file\) | 

### vt-private-retrohunt-jobs-list
***
Get a VT Hunting Livehunt ruleset by hunting notification files relationship.


#### Base Command

`vt-private-retrohunt-jobs-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Return the jobs matching the given criteria only. | Optional | 
| cursor | Continuation cursor. | Optional | 
| limit | Maximum number jobs to retrieve. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.RetroHuntJob.attributes.status | String | can be either "starting", "running", "aborting", "aborted" or "finished". | 
| VirusTotal.RetroHuntJob.attributes.finish_date | Number | date when the Retrohunt job finished | 
| VirusTotal.RetroHuntJob.attributes.rules | String | The ruleset in the job | 
| VirusTotal.RetroHuntJob.attributes.num_matches_outside_time_range | Number | Matches outside time range | 
| VirusTotal.RetroHuntJob.attributes.scanned_bytes | Date | Total scanned bytes | 
| VirusTotal.RetroHuntJob.attributes.time_range.start | Number | Start of job's time range | 
| VirusTotal.RetroHuntJob.attributes.time_range.end | Number | End of job's time range | 
| VirusTotal.RetroHuntJob.attributes.num_matches | Number | Number of matches. | 
| VirusTotal.RetroHuntJob.attributes.progress | Number | The progress in percentage | 
| VirusTotal.RetroHuntJob.attributes.corpus | String | Corpus of the job \(main/goodware\) | 
| VirusTotal.RetroHuntJob.attributes.creation_date | Number | Job's creation date as UTC timestamp. | 
| VirusTotal.RetroHuntJob.attributes.start_date | Number | The start date of the job in epch. | 
| VirusTotal.RetroHuntJob.type | String | Type of the entry \(retrohunt_job\) | 
| VirusTotal.RetroHuntJob.id | String | ID of the retro job. | 
| VirusTotal.RetroHuntJob.links.self | String | Link to the entry | 

### vt-private-retrohunt-jobs-get-by-id
***
Retrieve a retrohunt job.


#### Base Command

`vt-private-retrohunt-jobs-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Job identifier. Can be acquired from vt-private-retrohunt-jobs-list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.RetroHuntJob.attributes.status | String | can be either "starting", "running", "aborting", "aborted" or "finished". | 
| VirusTotal.RetroHuntJob.attributes.finish_date | Number | date when the Retrohunt job finished | 
| VirusTotal.RetroHuntJob.attributes.rules | String | The ruleset in the job | 
| VirusTotal.RetroHuntJob.attributes.num_matches_outside_time_range | Number | Matches outside time range | 
| VirusTotal.RetroHuntJob.attributes.scanned_bytes | Date | Total scanned bytes | 
| VirusTotal.RetroHuntJob.attributes.time_range.start | Number | Start of job's time range | 
| VirusTotal.RetroHuntJob.attributes.time_range.end | Number | End of job's time range | 
| VirusTotal.RetroHuntJob.attributes.num_matches | Number | Number of matches. | 
| VirusTotal.RetroHuntJob.attributes.progress | Number | The progress in percentage | 
| VirusTotal.RetroHuntJob.attributes.corpus | String | Corpus of the job \(main/goodware\) | 
| VirusTotal.RetroHuntJob.attributes.creation_date | Number | Job's creation date as UTC timestamp. | 
| VirusTotal.RetroHuntJob.attributes.start_date | Number | The start date of the job in epch. | 
| VirusTotal.RetroHuntJob.type | String | Type of the entry \(retrohunt_job\) | 
| VirusTotal.RetroHuntJob.id | String | ID of the retro job. | 
| VirusTotal.RetroHuntJob.links.self | String | Link to the entry | 

### vt-private-retrohunt-jobs-get-matching-files
***
Retrieve matches for a retrohunt job matching file relationship.


#### Base Command

`vt-private-retrohunt-jobs-get-matching-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Job identifier. Can be acquired from vt-private-retrohunt-jobs-list. | Required | 
| extended_data | Whether to return full data information. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.RetroHuntJobFiles.attributes.type_description | String | describes the file type. | 
| VirusTotal.RetroHuntJobFiles.attributes.tlsh | String | Trend Micro's TLSH hash | 
| VirusTotal.RetroHuntJobFiles.attributes.vhash | String | in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | 
| VirusTotal.RetroHuntJobFiles.attributes.exiftool | String | exiftool is a program for extracting Exif metadata from different file formats. Metadata shown may vary depending on the file type, and given the nature of Exif metadata, some fields may appear or not. | 
| VirusTotal.RetroHuntJobFiles.attributes.trid.file_type | String | TrID is a utility designed to identify file types from their binary signatures. | 
| VirusTotal.RetroHuntJobFiles.attributes.trid.probability | Number | probability of file format identification \(given as percentage\). | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.rule_name | String | contains the names of all rules in the ruleset. | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.description | String | matched rule description. | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.author | String | rule author. | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.ruleset_id | String | VirusTotal's ruleset ID. | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.ruleset_name | String | matched rule's ruleset name. | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.match_in_subfile | Boolean | whether the match was in a subfile or not. | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.source | String | ruleset source. | 
| VirusTotal.RetroHuntJobFiles.attributes.creation_date | Number | extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. UTC timestamp. | 
| VirusTotal.RetroHuntJobFiles.attributes.names | String | all file names associated with the file. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_modification_date | Number | date when the object itself was last modified. UTC timestamp. | 
| VirusTotal.RetroHuntJobFiles.attributes.type_tag | String | tag representing the file type. Can be used in vt-private-intelligence-search | 
| VirusTotal.RetroHuntJobFiles.attributes.capabilities_tags | String | list of representative tags related to the file's capabilities | 
| VirusTotal.RetroHuntJobFiles.attributes.total_votes.harmless | Number | number of positive votes. | 
| VirusTotal.RetroHuntJobFiles.attributes.total_votes.malicious | Number | number of negative votes. | 
| VirusTotal.RetroHuntJobFiles.attributes.size | Number | file size in bytes. | 
| VirusTotal.RetroHuntJobFiles.attributes.authentihash | String | sha256 hash used by Microsoft to verify that the relevant sections of a PE image file have not been altered. This specific type of hash is used by Microsoft AppLocker. | 
| VirusTotal.RetroHuntJobFiles.attributes.times_submitted | Number | number of times the file has been posted to VirusTotal. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_submission_date | Number | most recent date the file was posted to VirusTotal. UTC timestamp. | 
| VirusTotal.RetroHuntJobFiles.attributes.meaningful_name | String | the most interesting name out of all file's names. | 
| VirusTotal.RetroHuntJobFiles.attributes.downloadable | Boolean | true if the file can be downloaded, false otherwise. | 
| VirusTotal.RetroHuntJobFiles.attributes.sha256 | String | SHA-256 of the file | 
| VirusTotal.RetroHuntJobFiles.attributes.type_extension | String | specifies file extension. | 
| VirusTotal.RetroHuntJobFiles.attributes.tags | String | list of representative tags related to the file's capabilities | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_date | Number | Most recent scan date. UTC timestamp. | 
| VirusTotal.RetroHuntJobFiles.attributes.unique_sources | Number | indicates from how many different sources the file has been posted from. | 
| VirusTotal.RetroHuntJobFiles.attributes.first_submission_date | Number | date when the file was first seen in VirusTotal. UTC timestamp. | 
| VirusTotal.RetroHuntJobFiles.attributes.sha1 | String | SHA-1 of the file | 
| VirusTotal.RetroHuntJobFiles.attributes.magic | String | magic identifier of this app in hex format. | 
| VirusTotal.RetroHuntJobFiles.attributes.ssdeep | String | SSDeep of the file | 
| VirusTotal.RetroHuntJobFiles.attributes.md5 | String | MD5 of the file | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.harmless | Number | number of reports saying that is harmless. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.type-unsupported | Number | number of AV engines that don't support that type of file. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.suspicious | Number | number of reports saying that is suspicious. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.confirmed-timeout | Number | number of AV engines that reach a timeout when analysing that file. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.timeout | Number | number of timeouts when analysing this URL/file. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.failure | Number | number of AV engines that fail when analysing that file. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.malicious | Number | number of reports saying that is malicious | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.undetected | Number | number of reports saying that is undetected. | 
| VirusTotal.RetroHuntJobFiles.attributes.reputation | Number | file's score calculated from all votes posted by the VirusTotal community. | 
| VirusTotal.RetroHuntJobFiles.attributes.sigma_analysis_stats.high | Number | number of matched high severity rules. | 
| VirusTotal.RetroHuntJobFiles.attributes.sigma_analysis_stats.medium | Number | number of matched medium severity rules. | 
| VirusTotal.RetroHuntJobFiles.attributes.sigma_analysis_stats.critical | Number | number of matched critical severity rules. | 
| VirusTotal.RetroHuntJobFiles.attributes.sigma_analysis_stats.low | Number | number of matched low severity rules. | 
| VirusTotal.RetroHuntJobFiles.type | String | The type of the entry \(file\) | 
| VirusTotal.RetroHuntJobFiles.id | String | ID of file | 
| VirusTotal.RetroHuntJobFiles.links.self | String | A link to the entry | 
| VirusTotal.RetroHuntJobFiles.context_attributes.rule_name | String | contains the names of all rules in the ruleset. | 
| VirusTotal.RetroHuntJobFiles.context_attributes.match_in_subfile | Boolean | whether the match was in a subfile or not. | 

### vt-private-retrohunt-jobs-create
***
Create a new retrohunt job.


#### Base Command

`vt-private-retrohunt-jobs-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rules | The rules to create. https://yara.readthedocs.io/en/stable/. | Required | 
| corpus | The "main" corpus is a composition of files sent to VirusTotal during the last few months. The "goodware" corpus is a random selection of ~1.000.000 files from the NSRL that are not detected by any antivirus engine. Possible values are: main, goodware. Default is main. | Optional | 
| notification_email | A comma-separated list of emails to notify. | Optional | 
| start_time | Fetch retrohunt jobs from given time. Can be epoch time, a date or time range (3 days, 1 year). | Optional | 
| end_time | Fetch retrohunt jobs to given time. Can be epoch time, a date or time range. If start_time supplied and not end_time, end_time will be the current time. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.RetroHuntJob.attributes.status | String | can be either "starting", "running", "aborting", "aborted" or "finished". | 
| VirusTotal.RetroHuntJob.attributes.finish_date | Number | date when the Retrohunt job finished | 
| VirusTotal.RetroHuntJob.attributes.rules | String | The ruleset in the job | 
| VirusTotal.RetroHuntJob.attributes.num_matches_outside_time_range | Number | Matches outside time range | 
| VirusTotal.RetroHuntJob.attributes.scanned_bytes | Date | Total scanned bytes | 
| VirusTotal.RetroHuntJob.attributes.time_range.start | Number | Start of job's time range | 
| VirusTotal.RetroHuntJob.attributes.time_range.end | Number | End of job's time range | 
| VirusTotal.RetroHuntJob.attributes.num_matches | Number | Number of matches. | 
| VirusTotal.RetroHuntJob.attributes.progress | Number | The progress in percentage | 
| VirusTotal.RetroHuntJob.attributes.corpus | String | Corpus of the job \(main/goodware\) | 
| VirusTotal.RetroHuntJob.attributes.creation_date | Number | Job's creation date as UTC timestamp. | 
| VirusTotal.RetroHuntJob.attributes.start_date | Number | The start date of the job in epch. | 
| VirusTotal.RetroHuntJob.type | String | Type of the entry \(retrohunt_job\) | 
| VirusTotal.RetroHuntJob.id | String | ID of the retro job. | 
| VirusTotal.RetroHuntJob.links.self | String | Link to the entry | 

### vt-private-quota-limits-list
***
Retrieve user's API usage.


#### Base Command

`vt-private-quota-limits-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID or API key. If not supplied, will use the API Key configured in the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.QuotaLimits.cases_creation_monthly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.cases_creation_monthly.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_vtdiff_creation_monthly.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.intelligence_vtdiff_creation_monthly.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_vtdiff_creation_monthly.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_vtdiff_creation_monthly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_vtdiff_creation_monthly.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.monitor_uploaded_files.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.monitor_uploaded_files.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.monitor_uploaded_bytes.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.monitor_uploaded_bytes.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.monitor_storage_files.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.monitor_storage_files.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.api_requests_monthly.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.api_requests_monthly.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.api_requests_monthly.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.api_requests_monthly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.api_requests_monthly.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_downloads_monthly.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.intelligence_downloads_monthly.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_downloads_monthly.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_downloads_monthly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_downloads_monthly.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.api_requests_hourly.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.api_requests_hourly.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.api_requests_hourly.group.allowed | Number | hourly api requests group's quota limit | 
| VirusTotal.QuotaLimits.api_requests_hourly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.api_requests_hourly.user.allowed | Date | hourly api requests user's quota limit | 
| VirusTotal.QuotaLimits.intelligence_hunting_rules.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.intelligence_hunting_rules.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_hunting_rules.group.allowed | Number | intelligence_hunting_rules group's quota limit | 
| VirusTotal.QuotaLimits.intelligence_hunting_rules.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_hunting_rules.user.allowed | Number | intelligence_hunting_rules user's quota limit | 
| VirusTotal.QuotaLimits.intelligence_graphs_private.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.intelligence_graphs_private.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_graphs_private.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_graphs_private.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_graphs_private.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.api_requests_daily.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.api_requests_daily.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.api_requests_daily.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.api_requests_daily.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.api_requests_daily.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.monitor_storage_bytes.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.monitor_storage_bytes.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_retrohunt_jobs_monthly.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.intelligence_retrohunt_jobs_monthly.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_retrohunt_jobs_monthly.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_retrohunt_jobs_monthly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_retrohunt_jobs_monthly.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_searches_monthly.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.intelligence_searches_monthly.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_searches_monthly.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_searches_monthly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_searches_monthly.user.allowed | Number | quota limit. | 
