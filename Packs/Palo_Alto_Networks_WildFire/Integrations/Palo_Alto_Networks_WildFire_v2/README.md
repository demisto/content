Use the Palo Alto Networks Wildfire integration to automatically identify unknown threats and stop attackers in their tracks by performing malware dynamic analysis.

## Palo Alto Networks WildFire v2 Playbooks

1. WildFire - Detonate File
2. Detonate URL - WildFire v2.1

## Use Cases

1. Send a file sample to WildFire.
2. Upload a file hosted on a website to WildFire.
3. Submit a webpage to WildFire.
4. Get a report regarding the sent samples using file hash.
5. Get sample file from WildFire.
6. Get verdict regarding multiple hashes (up to 500) using the wildfire-get-verdicts command.

## Supported File Types
For a list of the supported file types, see [here](https://docs.paloaltonetworks.com/advanced-wildfire/administration/advanced-wildfire-overview/advanced-wildfire-file-type-support/advanced-wildfire-file-type-support-complete#idbfe44505-f816-40db-8b28-4047bb834a8c).
## Configure WildFire v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for WildFire-v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server base URL (e.g., https://192.168.0.1/publicapi) |  | True |
    | API Key |  | True |
    | API Key Type | API Key product name | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Return warning entry for unsupported file types |  | False |
    | Create relationships | Create relationships between indicators as part of Enrichment. | False |
    
4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### file
***
Retrieve results for a file hash using WildFire


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hash to check. | Optional | 
| md5 | MD5 hash to check. | Optional | 
| sha256 | SHA256 hash to check. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | string | Name of the file. | 
| File.Type | string | File type, for example: "PE". | 
| File.Size | string | Size of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.DigitalSignature.Publisher | string |   | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| WildFire.Report.Status | string | The status of the submission. | 
| WildFire.Report.SHA256 | string | SHA256 hash of the submission. | 
| InfoFile.EntryID | Unknown | The EntryID of the report file. | 
| InfoFile.Extension | string | Extension of the report file. | 
| InfoFile.Name | string | Name of the report file. | 
| InfoFile.Info | string | Details of the report file. | 
| InfoFile.Size | number | Size of the report file. | 
| InfoFile.Type | string | The report file type. | 
| File.FeedRelatedIndicators.value | String | Indicators that are associated with the file. | 
| File.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the file. | 
| File.Tags | String | Tags that are associated with the file. | 
| File.Behavior.details | String | File behavior details. | 
| File.Behavior.action | String | File behavior action. | 


#### Command Example
```!file file=735bcfa56930d824f9091188eeaac2a1d68bc64a21f90a49c5ff836ed6ea723f```

#### Human Readable Output

>### WildFire File Report
>|FileType|MD5|SHA256|Size|Status|
>|---|---|---|---|---|
>| JScript | ccdb1053f56a2d297906746bc720ef2a | 735bcfa56930d824f9091188eeaac2a1d68bc64a21f90a49c5ff836ed6ea723f | 12 | Completed |


### wildfire-upload
***
Uploads a file to WildFire for analysis.


#### Base Command

`wildfire-upload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upload | ID of the entry containing the file to upload. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 
| md5 | Used for the inner polling flow. For uploading a file, use the 'upload' argument instead. | Optional | 
| format | The type of structured report (XML or PDF) to request. Only relevant when polling=true. Possible values are: xml, pdf. Default is pdf. | Optional | 
| verbose | Whether to receive extended information from WildFire. Only relevant when polling=true. Possible values are: true, false. Default is false. | Optional | 
| extended_data | If set to “true”, the report will return extended data which includes the additional outputs. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Report.MD5 | string | MD5 hash of the submission. | 
| WildFire.Report.SHA256 | string | SHA256 hash of the submission. | 
| WildFire.Report.FileType | string | The submission type. | 
| WildFire.Report.Size | number | The size of the submission. | 
| WildFire.Report.Status | string | The status of the submission. | 
| File.Name | string | Name of the file. | 
| File.Type | string | File type, for example: "PE". | 
| File.Size | number | Size of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.DigitalSignature.Publisher | string | The entity that signed the file for authenticity purposes. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| InfoFile.EntryID | string | The EntryID of the report file. | 
| InfoFile.Extension | string | The extension of the report file. | 
| InfoFile.Name | string | The name of the report file. | 
| InfoFile.Info | string | Details of the report file. | 
| InfoFile.Size | number | The size of the report file. | 
| InfoFile.Type | string | The report file type. | 
| WildFire.Report.NetworkInfo.URL.Host | string | Submission related hosts | 
| WildFire.Report.NetworkInfo.URL.Method | string | Submission related method | 
| WildFire.Report.NetworkInfo.URL.URI | string | Submission related uri | 
| WildFire.Report.NetworkInfo.URL.UserAgent | string | Submission related user agent | 
| WildFire.Report.NetworkInfo.UDP.IP | string | Submission related IPs, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.Port | string | Submission related ports, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.JA3 | string | Submission related JA3s, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.JA3S | string | Submission related JA3Ss, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.Country | string | Submission related Countries, in UDP protocol. | 
| WildFire.Report.NetworkInfo.TCP.IP | string | Submission related IPs, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.JA3 | string | Submission related JA3s, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.JA3S | string | Submission related JA3Ss, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.Country | string | Submission related Countries, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.Port | string | Submission related ports, in TCP protocol. | 
| WildFire.Report.NetworkInfo.DNS.Query | string | Submission DNS queries. | 
| WildFire.Report.NetworkInfo.DNS.Response | string | Submission DNS responses. | 
| WildFire.Report.NetworkInfo.DNS.Type | string | Submission DNS Types. | 
| WildFire.Report.Evidence.md5 | string | Submission evidence MD5 hash. | 
| WildFire.Report.Evidence.Text | string | Submission evidence text. | 
| WildFire.Report.detection_reasons.description | string | Reason for the detection verdict. | 
| WildFire.Report.detection_reasons.name | string | Name of the detection. | 
| WildFire.Report.detection_reasons.type | string | Type of the detection. | 
| WildFire.Report.detection_reasons.verdict | string | Verdict of the detection. | 
| WildFire.Report.detection_reasons.artifacts | unknown | Artifacts of the detection reasons. | 
| WildFire.Report.iocs | unknown | Associated IOCs. | 
| WildFire.Report.verdict | string | The verdict of the report. | 
| WildFire.Report.Platform | string | The Platform of the report | 
| WildFire.Report.Software | string | The Software of the report | 
| WildFire.Report.ProcessList.Service | string | The process service | 
| WildFire.Report.ProcessList.ProcessCommand | string | The process command | 
| WildFire.Report.ProcessList.ProcessName | string | The process name | 
| WildFire.Report.ProcessList.ProcessPid | string | The process pid | 
| WildFire.Report.ProcessList.ProcessFile | string | Lists files that started a child processes, the process name, and the action the process performed. | 
| WildFire.Report.ProcessTree.ProcessName | string | The process name | 
| WildFire.Report.ProcessTree.ProcessPid | string | The process pid | 
| WildFire.Report.ProcessTree.ProcessText | string | The action the process performed. | 
| WildFire.Report.ProcessTree.Process.ChildName | string | The child process name | 
| WildFire.Report.ProcessTree.Process.ChildPid | string | The child process pid | 
| WildFire.Report.ProcessTree.Process.ChildText | string | The action the child process performed. | 
| WildFire.Report.ExtractedURL.URL | string | The extracted url | 
| WildFire.Report.ExtractedURL.Verdict | string | The extracted verdict | 
| WildFire.Report.Summary.Text | string | The summary of the report | 
| WildFire.Report.Summary.Details | string | The details summary of the report | 
| WildFire.Report.Summary.Behavior | string | The behavior summary of the report | 
| WildFire.Report.ELF.ShellCommands | string | The shell commands | 

#### Command Example
```!wildfire-upload upload=294@675f238c-ed75-4cae-83d2-02b6b820168b```

#### Human Readable Output

>### WildFire Upload File
>|FileType|MD5|SHA256|Size|Status|
>|---|---|---|---|---|
>| Jscript for WSH | ccdb1053f56a2d297906746bc720ef2a | 735bcfa56930d824f9091188eeaac2a1d68bc64a21f90a49c5ff836ed6ea723f | 12 | Pending |


### wildfire-upload-file-url
***
Uploads the URL of a remote file to WildFire for analysis.


#### Base Command

`wildfire-upload-file-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upload | URL of the remote file to upload. | Optional | 
| url | Used for the inner polling flow. For uploading a URL, use the 'upload' argument instead. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 
| format | The type of structured report (XML or PDF) to request. Only relevant when polling=true. Possible values are: xml, pdf. Default is pdf. | Optional | 
| verbose | Whether to receive extended information from WildFire. Only relevant when polling=true. Possible values are: true, false. Default is false. | Optional | 
| extended_data | If set to “true”, the report will return extended data which includes the additional outputs. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Report.MD5 | string | MD5 hash of the submission. | 
| WildFire.Report.SHA256 | string | SHA256 hash of the submission. | 
| WildFire.Report.Status | string | The status of the submission. | 
| WildFire.Report.URL | string | URL of the submission. | 
| File.Name | string | Name of the file. | 
| File.Type | string | File type, for example: "PE". | 
| File.Size | number | Size of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.DigitalSignature.Publisher | string | The entity that signed the file for authenticity purposes. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| InfoFile.EntryID | string | The EntryID of the report file. | 
| InfoFile.Extension | string | The extension of the report file. | 
| InfoFile.Name | string | The name of the report file. | 
| InfoFile.Info | string | Details of the report file. | 
| InfoFile.Size | number | The size of the report file. | 
| InfoFile.Type | string | The report file type. | 
| WildFire.Report.NetworkInfo.URL.Host | string | Submission related hosts | 
| WildFire.Report.NetworkInfo.URL.Method | string | Submission related method | 
| WildFire.Report.NetworkInfo.URL.URI | string | Submission related uri | 
| WildFire.Report.NetworkInfo.URL.UserAgent | string | Submission related user agent | 
| WildFire.Report.NetworkInfo.UDP.IP | string | Submission related IPs, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.Port | string | Submission related ports, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.JA3 | string | Submission related JA3s, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.JA3S | string | Submission related JA3Ss, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.Country | string | Submission related Countries, in UDP protocol. | 
| WildFire.Report.NetworkInfo.TCP.IP | string | Submission related IPs, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.JA3 | string | Submission related JA3s, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.JA3S | string | Submission related JA3Ss, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.Country | string | Submission related Countries, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.Port | string | Submission related ports, in TCP protocol. | 
| WildFire.Report.NetworkInfo.DNS.Query | string | Submission DNS queries. | 
| WildFire.Report.NetworkInfo.DNS.Response | string | Submission DNS responses. | 
| WildFire.Report.NetworkInfo.DNS.Type | string | Submission DNS Types. | 
| WildFire.Report.Evidence.md5 | string | Submission evidence MD5 hash. | 
| WildFire.Report.Evidence.Text | string | Submission evidence text. | 
| WildFire.Report.detection_reasons.description | string | Reason for the detection verdict. | 
| WildFire.Report.detection_reasons.name | string | Name of the detection. | 
| WildFire.Report.detection_reasons.type | string | Type of the detection. | 
| WildFire.Report.detection_reasons.verdict | string | Verdict of the detection. | 
| WildFire.Report.detection_reasons.artifacts | unknown | Artifacts of the detection reasons. | 
| WildFire.Report.iocs | unknown | Associated IOCs. | 
| WildFire.Report.verdict | string | The verdict of the report. | 
| WildFire.Report.Platform | string | The Platform of the report | 
| WildFire.Report.Software | string | The Software of the report | 
| WildFire.Report.ProcessList.Service | string | The process service | 
| WildFire.Report.ProcessList.ProcessCommand | string | The process command | 
| WildFire.Report.ProcessList.ProcessName | string | The process name | 
| WildFire.Report.ProcessList.ProcessPid | string | The process pid | 
| WildFire.Report.ProcessList.ProcessFile | string | Lists files that started a child processes, the process name, and the action the process performed. | 
| WildFire.Report.ProcessTree.ProcessName | string | The process name | 
| WildFire.Report.ProcessTree.ProcessPid | string | The process pid | 
| WildFire.Report.ProcessTree.ProcessText | string | The action the process performed. | 
| WildFire.Report.ProcessTree.Process.ChildName | string | The child process name | 
| WildFire.Report.ProcessTree.Process.ChildPid | string | The child process pid | 
| WildFire.Report.ProcessTree.Process.ChildText | string | The action the child process performed. | 
| WildFire.Report.ExtractedURL.URL | string | The extracted url | 
| WildFire.Report.ExtractedURL.Verdict | string | The extracted verdict | 
| WildFire.Report.Summary.Text | string | The summary of the report | 
| WildFire.Report.Summary.Details | string | The details summary of the report | 
| WildFire.Report.Summary.Behavior | string | The behavior summary of the report | 
| WildFire.Report.ELF.ShellCommands | string | The shell commands | 

#### Command Example
```!wildfire-upload-file-url upload=http://www.software995.net/bin/pdf995s.exe```

#### Human Readable Output

>### WildFire Upload File URL
>|FileType|MD5|SHA256|Size|Status|URL|
>|---|---|---|---|---|---|
>| PE32 executable | 891b77e864c88881ea98be867e74177f | 555092d994b8838b8fa18d59df4fdb26289d146e071e831fcf0c6851b5fb04f8 | 5958304 | Pending | http://www.software995.net/bin/pdf995s.exe |


### wildfire-report
***
Retrieves results for a file hash using WildFire.


#### Base Command

`wildfire-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | MD5 hash to check. | Optional | 
| sha256 | SHA256 hash to check. | Optional | 
| hash | Deprecated. Use the sha256 argument instead. | Optional | 
| format | The type of structured report (MAEC, XML or PDF) to request. Possible values are: maec, xml, pdf. Default is pdf. | Optional | 
| verbose | Receive extended information from WildFire. Possible values are: true, false. Default is false. | Optional | 
| url | Retrieves results for a URL using WildFire. The report format is in JSON. | Optional | 
| extended_data | If set to “true”, the report will return extended data which includes the additional outputs. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | string | Name of the file. | 
| File.Type | string | File type, for example: "PE" | 
| File.Size | number | Size of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.DigitalSignature.Publisher | string | The entity that signed the file for authenticity purposes. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| WildFire.Report.Status | string | The status of the submission. | 
| WildFire.Report.SHA256 | string | SHA256 hash of the submission. | 
| InfoFile.EntryID | string | The EntryID of the report file. | 
| InfoFile.Extension | string | The extension of the report file. | 
| InfoFile.Name | string | The name of the report file. | 
| InfoFile.Info | string | Details of the report file. | 
| InfoFile.Size | number | The size of the report file. | 
| InfoFile.Type | string | The report file type. | 
| WildFire.Report.NetworkInfo.URL.Host | string | Submission related hosts | 
| WildFire.Report.NetworkInfo.URL.Method | string | Submission related method | 
| WildFire.Report.NetworkInfo.URL.URI | string | Submission related uri | 
| WildFire.Report.NetworkInfo.URL.UserAgent | string | Submission related user agent | 
| WildFire.Report.NetworkInfo.UDP.IP | string | Submission related IPs, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.Port | string | Submission related ports, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.JA3 | string | Submission related JA3s, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.JA3S | string | Submission related JA3Ss, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.Country | string | Submission related Countries, in UDP protocol. | 
| WildFire.Report.NetworkInfo.TCP.IP | string | Submission related IPs, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.JA3 | string | Submission related JA3s, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.JA3S | string | Submission related JA3Ss, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.Country | string | Submission related Countries, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.Port | string | Submission related ports, in TCP protocol. | 
| WildFire.Report.NetworkInfo.DNS.Query | string | Submission DNS queries. | 
| WildFire.Report.NetworkInfo.DNS.Response | string | Submission DNS responses. | 
| WildFire.Report.NetworkInfo.DNS.Type | string | Submission DNS Types. | 
| WildFire.Report.Evidence.md5 | string | Submission evidence MD5 hash. | 
| WildFire.Report.Evidence.Text | string | Submission evidence text. | 
| WildFire.Report.detection_reasons.description | string | Reason for the detection verdict. | 
| WildFire.Report.detection_reasons.name | string | Name of the detection. | 
| WildFire.Report.detection_reasons.type | string | Type of the detection. | 
| WildFire.Report.detection_reasons.verdict | string | Verdict of the detection. | 
| WildFire.Report.detection_reasons.artifacts | unknown | Artifacts of the detection reasons. | 
| WildFire.Report.iocs | unknown | Associated IOCs. | 
| WildFire.Report.verdict | string | The verdict of the report. | 
| WildFire.Report.Platform | string | The Platform of the report | 
| WildFire.Report.Software | string | The Software of the report | 
| WildFire.Report.ProcessList.Service | string | The process service | 
| WildFire.Report.ProcessList.ProcessCommand | string | The process command | 
| WildFire.Report.ProcessList.ProcessName | string | The process name | 
| WildFire.Report.ProcessList.ProcessPid | string | The process pid | 
| WildFire.Report.ProcessList.ProcessFile | string | Lists files that started a child processes, the process name, and the action the process performed. | 
| WildFire.Report.ProcessTree.ProcessName | string | The process name | 
| WildFire.Report.ProcessTree.ProcessPid | string | The process pid | 
| WildFire.Report.ProcessTree.ProcessText | string | The action the process performed. | 
| WildFire.Report.ProcessTree.Process.ChildName | string | The child process name | 
| WildFire.Report.ProcessTree.Process.ChildPid | string | The child process pid | 
| WildFire.Report.ProcessTree.Process.ChildText | string | The action the child process performed. | 
| WildFire.Report.ExtractedURL.URL | string | The extracted url | 
| WildFire.Report.ExtractedURL.Verdict | string | The extracted verdict | 
| WildFire.Report.Summary.Text | string | The summary of the report | 
| WildFire.Report.Summary.Details | string | The details summary of the report | 
| WildFire.Report.Summary.Behavior | string | The behavior summary of the report | 
| WildFire.Report.ELF.ShellCommands | string | The shell commands | 
| WildFire.Report.maec_report | string | MAEC report output | 

#### Command Example
```!wildfire-report url=https://www.XSOAR.com```

#### Human Readable Output

>### Wildfire URL report for https://www.XSOAR.com
>|sha256|type|verdict|
>|---|---|---|
>| 288cd35401e334a2defc0b428d709f58d4ea28c8e9c6e47fdba88da2d6bc88a7 | wf-report | benign |


### wildfire-get-verdict
***
Returns a verdict for a hash.


#### Base Command

`wildfire-get-verdict`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | Comma-separated list of hashes to get the verdict for. | Optional | 
| url | The URL to get the verdict for. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Verdicts.MD5 | string | MD5 hash of the file. | 
| WildFire.Verdicts.SHA256 | string | SHA256 hash of the file. | 
| WildFire.Verdicts.Verdict | number | Verdict of the file. | 
| WildFire.Verdicts.VerdictDescription | string | Description of the file verdict. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| WildFire.Verdicts.AnalysisTime | date | Verdict analysis time. | 
| WildFire.Verdicts.URL | string | The URL of the web page. | 
| WildFire.Verdicts.Valid | string | Is the URL valid. | 


#### Command Example
```!wildfire-get-verdict hash=afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc```

#### Human Readable Output

>### WildFire Verdict
>|MD5|SHA256|Verdict|VerdictDescription|
>|---|---|---|---|
>| 0e4e3c2d84a9bc726a50b3c91346fbb1 | afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc | 1 | malware |


### wildfire-get-verdicts
***
Returns a verdict regarding multiple hashes, stored in a TXT file or given as list.


#### Base Command

`wildfire-get-verdicts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EntryID | EntryID of the text file that contains multiple hashes. Limit is 500 hashes. | Optional | 
| hash_list | A comma-separated list of hashes to get verdicts for. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Verdicts.MD5 | string | MD5 hash of the file. | 
| WildFire.Verdicts.SHA256 | string | SHA256 hash of the file. | 
| WildFire.Verdicts.Verdict | number | Verdict of the file. | 
| WildFire.Verdicts.VerdictDescription | string | Description of the file verdict. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 


#### Command Example
``` ```

#### Human Readable Output



### wildfire-upload-url
***
Uploads a URL of a webpage to WildFire for analysis.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`wildfire-upload-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upload | URL to submit to WildFire. | Optional | 
| url | Used for the inner polling flow. For uploading a URL, use the 'upload' argument instead. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 
| format | The type of structured report (XML or PDF) to request. Only relevant when polling=true. Possible values are: xml, pdf. Default is pdf. | Optional | 
| verbose | Whether to receive extended information from WildFire. Only relevant when polling=true. Possible values are: true, false. Default is false. | Optional | 
| extended_data | If set to “true”, the report will return extended data which includes the additional outputs. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Report.MD5 | string | MD5 of the submission. | 
| WildFire.Report.SHA256 | string | SHA256 of the submission. | 
| WildFire.Report.Status | string | The status of the submission. | 
| WildFire.Report.URL | string | URL of the submission. | 
| File.Name | string | Name of the file. | 
| File.Type | string | File type, for example: "PE". | 
| File.Size | number | Size of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.DigitalSignature.Publisher | string | The entity that signed the file for authenticity purposes. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| InfoFile.EntryID | string | The EntryID of the report file. | 
| InfoFile.Extension | string | The extension of the report file. | 
| InfoFile.Name | string | The name of the report file. | 
| InfoFile.Info | string | Details of the report file. | 
| InfoFile.Size | number | The size of the report file. | 
| InfoFile.Type | string | The report file type. | 
| WildFire.Report.NetworkInfo.URL.Host | string | Submission related hosts | 
| WildFire.Report.NetworkInfo.URL.Method | string | Submission related method | 
| WildFire.Report.NetworkInfo.URL.URI | string | Submission related uri | 
| WildFire.Report.NetworkInfo.URL.UserAgent | string | Submission related user agent | 
| WildFire.Report.NetworkInfo.UDP.IP | string | Submission related IPs, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.Port | string | Submission related ports, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.JA3 | string | Submission related JA3s, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.JA3S | string | Submission related JA3Ss, in UDP protocol. | 
| WildFire.Report.NetworkInfo.UDP.Country | string | Submission related Countries, in UDP protocol. | 
| WildFire.Report.NetworkInfo.TCP.IP | string | Submission related IPs, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.JA3 | string | Submission related JA3s, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.JA3S | string | Submission related JA3Ss, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.Country | string | Submission related Countries, in TCP protocol. | 
| WildFire.Report.NetworkInfo.TCP.Port | string | Submission related ports, in TCP protocol. | 
| WildFire.Report.NetworkInfo.DNS.Query | string | Submission DNS queries. | 
| WildFire.Report.NetworkInfo.DNS.Response | string | Submission DNS responses. | 
| WildFire.Report.NetworkInfo.DNS.Type | string | Submission DNS Types. | 
| WildFire.Report.Evidence.md5 | string | Submission evidence MD5 hash. | 
| WildFire.Report.Evidence.Text | string | Submission evidence text. | 
| WildFire.Report.detection_reasons.description | string | Reason for the detection verdict. | 
| WildFire.Report.detection_reasons.name | string | Name of the detection. | 
| WildFire.Report.detection_reasons.type | string | Type of the detection. | 
| WildFire.Report.detection_reasons.verdict | string | Verdict of the detection. | 
| WildFire.Report.detection_reasons.artifacts | unknown | Artifacts of the detection reasons. | 
| WildFire.Report.iocs | unknown | Associated IOCs. | 
| WildFire.Report.verdict | string | The verdict of the report. | 
| WildFire.Report.Platform | string | The Platform of the report | 
| WildFire.Report.Software | string | The Software of the report | 
| WildFire.Report.ProcessList.Service | string | The process service | 
| WildFire.Report.ProcessList.ProcessCommand | string | The process command | 
| WildFire.Report.ProcessList.ProcessName | string | The process name | 
| WildFire.Report.ProcessList.ProcessPid | string | The process pid | 
| WildFire.Report.ProcessList.ProcessFile | string | Lists files that started a child processes, the process name, and the action the process performed. | 
| WildFire.Report.ProcessTree.ProcessName | string | The process name | 
| WildFire.Report.ProcessTree.ProcessPid | string | The process pid | 
| WildFire.Report.ProcessTree.ProcessText | string | The action the process performed. | 
| WildFire.Report.ProcessTree.Process.ChildName | string | The child process name | 
| WildFire.Report.ProcessTree.Process.ChildPid | string | The child process pid | 
| WildFire.Report.ProcessTree.Process.ChildText | string | The action the child process performed. | 
| WildFire.Report.ExtractedURL.URL | string | The extracted url | 
| WildFire.Report.ExtractedURL.Verdict | string | The extracted verdict | 
| WildFire.Report.Summary.Text | string | The summary of the report | 
| WildFire.Report.Summary.Details | string | The details summary of the report | 
| WildFire.Report.Summary.Behavior | string | The behavior summary of the report | 
| WildFire.Report.ELF.ShellCommands | string | The shell commands | 


#### Command Example
```!wildfire-upload-url upload=https://www.XSOAR.com```

#### Human Readable Output

>### WildFire Upload URL
>|MD5|SHA256|Status|URL|
>|---|---|---|---|
>| 67632f32e6af123aa8ffd1fe8765a783 | c51a8231d1be07a2545ac99e86a25c5d68f88380b7ebf7ac91501661e6d678bb | Pending | https://www.XSOAR.com |


### wildfire-get-sample
***
Retrieves a sample.


#### Base Command

`wildfire-get-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | MD5 hash of the sample. | Optional | 
| sha256 | SHA256 hash of the sample. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!wildfire-get-sample sha256=afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc```

#### Human Readable Output

There is no human-readable output for this command.



### wildfire-get-url-webartifacts
***
Get web artifacts for a URL webpage. An empty tgz will be returned, no matter what the verdict, or even if the URL is malformed.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`wildfire-get-url-webartifacts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL of the webpage. | Required | 
| types | Whether to download as screenshots or as downloadable files. If not specified, both will be downloaded. Possible values are: download_files, screenshot. | Optional | 
| screenshot_inline | Whether to extract screenshot image from tgz to warroom. Only applies to types=screenshot. Possible values are: true, false. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | The EntryID of the web artifacts. | 
| InfoFile.Extension | string | Extension of the web artifacts. | 
| InfoFile.Name | string | Name of the web artifacts. | 
| InfoFile.Info | string | Details of the web artifacts. | 
| InfoFile.Size | number | Size of the web artifacts. | 
| InfoFile.Type | string | The web artifacts file type. | 


#### Command Example
```!wildfire-get-url-webartifacts url=http://royalmail-login.com```

#### Human Readable Output

There is no human-readable output for this command.
