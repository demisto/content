Use the Palo Alto Networks Wildfire integration to automatically identify unknown threats and stop attackers in their tracks by performing malware dynamic analysis.

## Palo Alto Networks WildFire v2 Playbooks

1. WildFire - Detonate File
2. Detonate URL - WildFire v2.1

##Use Cases

1. Send a File sample to WildFire.
2. Upload a file hosted on a website to WildFire.
3. Submit a webpage to WildFire.
4. Get a report regarding the sent samples using file hash.
5. Get sample file from WildFire.
6. Get verdict regarding multiple hashes(up to 500) using the wildfire-get-verdicts command.

## Configure WildFire v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for WildFire-v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server base URL (e.g. https://192.168.0.1/publicapi) |  | True |
    | API Key |  | True |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Return warning entry for unsupported file types |  | False |

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
| File.Type | string | File type, for example: "PE" | 
| File.Size | string | Size of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
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
| File.FeedRelatedIndicators.value | String | Indicators that are associated with the File. | 
| File.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the File. | 
| File.Tags | String | Tags that are associated with the File. | 
| File.Behavior.details | String | File behavior details. | 
| File.Behavior.action | String | File behavior action. | 


#### Command Example
``` ```

#### Human Readable Output



### wildfire-upload
***
Uploads a file to WildFire for analysis.


#### Base Command

`wildfire-upload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upload | ID of the entry containing the file to upload. | Optional | 
| polling | Use XSOAR built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 
| md5 | Used for the inner polling flow, for uploading a file use the 'upload' argument instead. | Optional | 
| format | Request a structured report (XML or PDF). Only relevant for when using polling=true. Possible values are: xml, pdf. Default is pdf. | Optional | 
| verbose | Receive extended information from WildFire. Only relevant for when using polling=true. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Report.MD5 | string | MD5 hash of the submission. | 
| WildFire.Report.SHA256 | string | SHA256 hash of the submission. | 
| WildFire.Report.FileType | string | The submission type. | 
| WildFire.Report.Size | number | The size of the submission. | 
| WildFire.Report.Status | string | The status of the submission. | 
| File.Name | string | Name of the file. | 
| File.Type | string | File type, for example: "PE" | 
| File.Size | number | Size of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
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
| WildFire.Report.Network.UDP.IP | string | Submission related IPs, in UDP protocol. | 
| WildFire.Report.Network.UDP.Port | string | Submission related ports, in UDP protocol. | 
| WildFire.Report.Network.TCP.IP | string | Submission related IPs, in TCP protocol. | 
| WildFire.Report.Network.TCP.Port | string | Submission related ports, in TCP protocol. | 
| WildFire.Report.Network.DNS.Query | string | Submission DNS queries. | 
| WildFire.Report.Network.DNS.Response | string | Submission DNS responses. | 
| WildFire.Report.Evidence.md5 | string | Submission evidence MD5 hash. | 
| WildFire.Report.Evidence.Text | string | Submission evidence text. | 
| WildFire.Report.detection_reasons.description | string | Reason for the detection verdict. | 
| WildFire.Report.detection_reasons.name | string | Name of the detection. | 
| WildFire.Report.detection_reasons.type | string | Type of the detection. | 
| WildFire.Report.detection_reasons.verdict | string | Verdict of the detection. | 
| WildFire.Report.detection_reasons.artifacts | unknown | Artifacts of the detection reasons. | 
| WildFire.Report.iocs | unknown | Associated IOCs. | 
| WildFire.Report.verdict | string | The verdict of the report. | 


#### Command Example
``` ```

#### Human Readable Output



### wildfire-upload-file-url
***
Uploads the URL of a remote file to WildFire for analysis.


#### Base Command

`wildfire-upload-file-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upload | URL of the remote file to upload. | Optional | 
| url | Used for the inner polling flow, for uploading a url use the 'upload' argument instead. | Optional | 
| polling | Use XSOAR built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 
| format | Request a structured report (XML or PDF). Only relevant for when using polling=true. Possible values are: xml, pdf. Default is pdf. | Optional | 
| verbose | Receive extended information from WildFire. Only relevant for when using polling=true. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Report.MD5 | string | MD5 hash of the submission. | 
| WildFire.Report.SHA256 | string | SHA256 hash of the submission. | 
| WildFire.Report.Status | string | The status of the submission. | 
| WildFire.Report.URL | string | URL of the submission. | 
| File.Name | string | Name of the file. | 
| File.Type | string | File type, for example: "PE" | 
| File.Size | number | Size of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
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
| WildFire.Report.Network.UDP.IP | string | Submission related IPs, in UDP protocol. | 
| WildFire.Report.Network.UDP.Port | string | Submission related ports, in UDP protocol. | 
| WildFire.Report.Network.TCP.IP | string | Submission related IPs, in TCP protocol. | 
| WildFire.Report.Network.TCP.Port | string | Submission related ports, in TCP protocol. | 
| WildFire.Report.Network.DNS.Query | string | Submission DNS queries. | 
| WildFire.Report.Network.DNS.Response | string | Submission DNS responses. | 
| WildFire.Report.Evidence.md5 | string | Submission evidence MD5 hash. | 
| WildFire.Report.Evidence.Text | string | Submission evidence text. | 
| WildFire.Report.detection_reasons.description | string | Reason for the detection verdict. | 
| WildFire.Report.detection_reasons.name | string | Name of the detection. | 
| WildFire.Report.detection_reasons.type | string | Type of the detection. | 
| WildFire.Report.detection_reasons.verdict | string | Verdict of the detection. | 
| WildFire.Report.detection_reasons.artifacts | unknown | Artifacts of the detection reasons. | 
| WildFire.Report.iocs | unknown | Associated IOCs. | 
| WildFire.Report.verdict | string | The verdict of the report. | 


#### Command Example
``` ```

#### Human Readable Output



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
| hash | Deprecated - Use the sha256 argument instead. | Optional | 
| format | Request a structured report (XML or PDF). Possible values are: xml, pdf. Default is pdf. | Optional | 
| verbose | Receive extended information from WildFire. Possible values are: true, false. Default is false. | Optional | 
| url | Retrieves results for a URL using WildFire. The report format is in JSON. | Optional | 


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
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| WildFire.Report.Status | string | The status of the submissiom. | 
| WildFire.Report.SHA256 | string | SHA256 hash of the submission. | 
| InfoFile.EntryID | string | The EntryID of the report file. | 
| InfoFile.Extension | string | The extension of the report file. | 
| InfoFile.Name | string | The name of the report file. | 
| InfoFile.Info | string | Details of the report file. | 
| InfoFile.Size | number | The size of the report file. | 
| InfoFile.Type | string | The report file type. | 
| WildFire.Report.Network.UDP.IP | string | Submission related IPs, in UDP protocol. | 
| WildFire.Report.Network.UDP.Port | string | Submission related ports, in UDP protocol. | 
| WildFire.Report.Network.TCP.IP | string | Submission related IPs, in TCP protocol. | 
| WildFire.Report.Network.TCP.Port | string | Submission related ports, in TCP protocol. | 
| WildFire.Report.Network.DNS.Query | string | Submission DNS queries. | 
| WildFire.Report.Network.DNS.Response | string | Submission DNS responses. | 
| WildFire.Report.Evidence.md5 | string | Submission evidence MD5 hash. | 
| WildFire.Report.Evidence.Text | string | Submission evidence text. | 
| WildFire.Report.detection_reasons.description | string | Reason for the detection verdict. | 
| WildFire.Report.detection_reasons.name | string | Name of the detection. | 
| WildFire.Report.detection_reasons.type | string | Type of the detection. | 
| WildFire.Report.detection_reasons.verdict | string | Verdict of the detection. | 
| WildFire.Report.detection_reasons.artifacts | unknown | Artifacts of the detection reasons. | 
| WildFire.Report.iocs | unknown | Associated IOCs. | 
| WildFire.Report.verdict | string | The verdict of the report. | 


#### Command Example
``` ```

#### Human Readable Output



### wildfire-get-verdict
***
Returns a verdict for a hash.


#### Base Command

`wildfire-get-verdict`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | Hash to get the verdict for. | Required | 


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



### wildfire-get-verdicts
***
Returns a verdict regarding multiple hashes, stored in a TXT file or given as list.


#### Base Command

`wildfire-get-verdicts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EntryID | EntryID of the text file that contains multiple hashes. Limit is 500 hashes. | Optional | 
| hash_list | A list of hashes to get verdicts for. | Optional | 


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


#### Base Command

`wildfire-upload-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upload | URL to submit to WildFire. | Optional | 
| url | Used for the inner polling flow, for uploading a url use the 'upload' argument instead. | Optional | 
| polling | Use XSOAR built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 
| format | Request a structured report (XML or PDF). Only relevant for when using polling=true. Possible values are: xml, pdf. Default is pdf. | Optional | 
| verbose | Receive extended information from WildFire. Only relevant for when using polling=true. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Report.MD5 | string | MD5 of the submission. | 
| WildFire.Report.SHA256 | string | SHA256 of the submission. | 
| WildFire.Report.Status | string | The status of the submission. | 
| WildFire.Report.URL | string | URL of the submission. | 
| File.Name | string | Name of the file. | 
| File.Type | string | File type, for example: "PE" | 
| File.Size | number | Size of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
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
| WildFire.Report.Network.UDP.IP | string | Submission related IPs, in UDP protocol. | 
| WildFire.Report.Network.UDP.Port | string | Submission related ports, in UDP protocol. | 
| WildFire.Report.Network.TCP.IP | string | Submission related IPs, in TCP protocol. | 
| WildFire.Report.Network.TCP.Port | string | Submission related ports, in TCP protocol. | 
| WildFire.Report.Network.DNS.Query | string | Submission DNS queries. | 
| WildFire.Report.Network.DNS.Response | string | Submission DNS responses. | 
| WildFire.Report.Evidence.md5 | string | Submission evidence MD5 hash. | 
| WildFire.Report.Evidence.Text | string | Submission evidence text. | 
| WildFire.Report.detection_reasons.description | string | Reason for the detection verdict. | 
| WildFire.Report.detection_reasons.name | string | Name of the detection. | 
| WildFire.Report.detection_reasons.type | string | Type of the detection. | 
| WildFire.Report.detection_reasons.verdict | string | Verdict of the detection. | 
| WildFire.Report.detection_reasons.artifacts | unknown | Artifacts of the detection reasons. | 
| WildFire.Report.iocs | unknown | Associated IOCs. | 
| WildFire.Report.verdict | string | The verdict of the report. | 


#### Command Example
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



### wildfire-get-url-webartifacts
***
Get web artifacts for a URL webpage. An empty tgz will be returned, no matter what the verdict, or even if the URL is malformed.


#### Base Command

`wildfire-get-url-webartifacts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL of the webpage. | Required | 
| types | Whether to download as screenshots or as downloadable files. if not specified, both will be downloaded. Possible values are: download_files, screenshot. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | The EntryID of the webartifacts. | 
| InfoFile.Extension | string | Extension of the webartifacts. | 
| InfoFile.Name | string | Name of the webartifacts. | 
| InfoFile.Info | string | Details of the webartifacts. | 
| InfoFile.Size | number | Size of the webartifacts. | 
| InfoFile.Type | string | The webartifacts file type. | 


#### Command Example
``` ```

#### Human Readable Output



### Commands
#### The following commands were removed in this version:
* *commandName* - this command was replaced by XXX.
* *commandName* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *commandName* command:
* *argumentName* - this argument was replaced by XXX.
* *argumentName* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *commandName* command:
* *argumentName* - is now required.
* *argumentName* - supports now comma separated values.

### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.