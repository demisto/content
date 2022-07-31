ANY.RUN is a cloud-based sanbox with interactive access.
## Configure ANY.RUN on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ANY.RUN.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Username | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### anyrun-get-history
***
Get analysis history.


#### Base Command

`anyrun-get-history`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team | If true, gets team history. If empty, gets your submitted analyses history. Possible values are: true, false. Default is false. | Optional | 
| skip | The number of analyses to skip. Possible values are: . Default is 0. | Optional | 
| limit | Limits the history retrieved/searched to the specified number of executed analyses. The range is 1-100. Default is 25. | Optional | 
| filter | File name, hash, or task ID by which to filter the task history. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.Task.Name | String | Task name. | 
| ANYRUN.Task.Verdict | String | ANY.RUN verdict for the submitted file's status. | 
| ANYRUN.Task.Related | String | ANY.RUN link to a related file. | 
| ANYRUN.Task.File | String | ANY.RUN link to download the submitted file. | 
| ANYRUN.Task.Date | Date | The date that the file was submitted for analysis. | 
| ANYRUN.Task.Hash.MD5 | String | MD5 hash of the submitted file. | 
| ANYRUN.Task.Hash.SHA1 | String | SHA1 hash of the submitted file. | 
| ANYRUN.Task.Hash.SHA256 | String | SHA256 hash of the submitted file. | 
| ANYRUN.Task.Hash.HeadHash | String | Head hash of the submitted file. | 
| ANYRUN.Task.Hash.SSDeep | String | SSDeep hash of the submitted file. | 

### anyrun-get-report
***
Gets the report of a task created for a submitted file or URL.


#### Base Command

`anyrun-get-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task | Unique task ID. A task ID is returned when submitting a file or URL for analysis using the `anyrun-run-analysis` command. Task IDs can also be located in the `ID` field of the output of executing the `anyrun-get-history` command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.Task.AnalysisDate | String | Date and time the analysis was executed. | 
| ANYRUN.Task.Behavior.Category | String | Category of a process behavior. | 
| ANYRUN.Task.Behavior.Action | String | Actions performed by a process. | 
| ANYRUN.Task.Behavior.ThreatLevel | Number | Threat score associated with a process behavior. | 
| ANYRUN.Task.Behavior.ProcessUUID | String | Unique ID of the process whose behaviors are being profiled. | 
| ANYRUN.Task.Connection.Reputation | String | Connection reputation. | 
| ANYRUN.Task.Connection.ProcessUUID | String | ID of the process that created the connection. | 
| ANYRUN.Task.Connection.ASN | String | Connection autonomous system network. | 
| ANYRUN.Task.Connection.Country | String | Connection country. | 
| ANYRUN.Task.Connection.Protocol | String | Connection protocol. | 
| ANYRUN.Task.Connection.Port | Number | Connection port number. | 
| ANYRUN.Task.Connection.IP | String | Connection IP number. | 
| ANYRUN.Task.DnsRequest.Reputation | String | Reputation of the DNS request. | 
| ANYRUN.Task.DnsRequest.IP | Unknown | IP addresses associated with a DNS request. | 
| ANYRUN.Task.DnsRequest.Domain | String | Domain resolution of a DNS request. | 
| ANYRUN.Task.Threat.ProcessUUID | String | Unique process ID from where the threat originated. | 
| ANYRUN.Task.Threat.Msg | String | Threat message. | 
| ANYRUN.Task.Threat.Class | String | Class of the threat. | 
| ANYRUN.Task.Threat.SrcPort | Number | Port on which the threat originated. | 
| ANYRUN.Task.Threat.DstPort | Number | Destination port of the threat. | 
| ANYRUN.Task.Threat.SrcIP | String | Source IP address where the threat originated. | 
| ANYRUN.Task.Threat.DstIP | String | Destination IP address of the threat. | 
| ANYRUN.Task.HttpRequest.Reputation | String | Reputation of the HTTP request. | 
| ANYRUN.Task.HttpRequest.Country | String | HTTP request country. | 
| ANYRUN.Task.HttpRequest.ProcessUUID | String | ID of the process making the HTTP request. | 
| ANYRUN.Task.HttpRequest.Body | Unknown | HTTP request body parameters and details. | 
| ANYRUN.Task.HttpRequest.HttpCode | Number | HTTP request response code. | 
| ANYRUN.Task.HttpRequest.Status | String | Status of the HTTP request. | 
| ANYRUN.Task.HttpRequest.ProxyDetected | Boolean | Whether the HTTP request was made through a proxy. | 
| ANYRUN.Task.HttpRequest.Port | Number | HTTP request port. | 
| ANYRUN.Task.HttpRequest.IP | String | HTTP request IP address. | 
| ANYRUN.Task.HttpRequest.URL | String | HTTP request URL. | 
| ANYRUN.Task.HttpRequest.Host | String | HTTP request host. | 
| ANYRUN.Task.HttpRequest.Method | String | HTTP request method type. | 
| ANYRUN.Task.FileInfo | String | Details of the submitted file. | 
| ANYRUN.Task.OS | String | OS of the sandbox in which the file was analyzed. | 
| ANYRUN.Task.ID | String | The unique ID of the task. | 
| ANYRUN.Task.MIME | String | The MIME of the file submitted for analysis. | 
| ANYRUN.Task.MD5 | String | The MD5 hash of the file submitted for analysis. | 
| ANYRUN.Task.SHA1 | String | The SHA1 hash of the file submitted for analysis. | 
| ANYRUN.Task.SHA256 | String | The SHA256 hash of the file submitted for analysis. | 
| ANYRUN.Task.SSDeep | String | SSDeep hash of the file submitted for analysis. | 
| ANYRUN.Task.Verdict | String | ANY.RUN verdict for the maliciousness of the submitted file or URL. | 
| ANYRUN.Task.Process.FileName | String | File name of the process. | 
| ANYRUN.Task.Process.PID | Number | Process identification number. | 
| ANYRUN.Task.Process.PPID | Number | Parent process identification number. | 
| ANYRUN.Task.Process.ProcessUUID | String | Unique process ID \(used by ANY.RUN\). | 
| ANYRUN.Task.Process.CMD | String | Process command. | 
| ANYRUN.Task.Process.Path | String | Path of the executed command. | 
| ANYRUN.Task.Process.User | String | User who executed the command. | 
| ANYRUN.Task.Process.IntegrityLevel | String | The process integrity level. | 
| ANYRUN.Task.Process.ExitCode | Number | Process exit code. | 
| ANYRUN.Task.Process.MainProcess | Boolean | Whether the process is the main process. | 
| ANYRUN.Task.Process.Version.Company | String | Company responsible for the program executed. | 
| ANYRUN.Task.Process.Version.Description | String | Description of the type of program. | 
| ANYRUN.Task.Process.Version.Version | String | Version of the program executed. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | Type of indicator. | 
| DBotScore.Vendor | String | Vendor used to calculate the score. | 
| File.Extension | String | Extension of the file submitted for analysis. | 
| File.Name | String | The name of the file submitted for analysis. | 
| File.MD5 | String | MD5 hash of the file submitted for analysis. | 
| File.SHA1 | String | SHA1 hash of the file submitted for analysis. | 
| File.SHA256 | String | SHA256 hash of the file submitted for analysis. | 
| File.SSDeep | String | SSDeep hash of the file submitted for analysis. | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | String | For malicious files, the reason that the vendor made the decision. | 
| URL.Data | String | URL data. | 
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | String | For malicious URLs, the reason that the vendor made the decision. | 
| ANYRUN.Task.Status | String | Task analysis status. | 

### anyrun-run-analysis
***
Submit a file or url for analysis.


#### Base Command

`anyrun-run-analysis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| obj_type | Type of new task. Possible values are: file, url, remote file. Default is file. | Optional | 
| file | EntryID of the file to analyze. | Optional | 
| obj_url | URL, used only if 'obj_type' command argument is 'url' or 'download'. Permitted size is 5-512 characters long. | Optional | 
| env_bitness | Bitness of OS. Possible values are: 32, 64. Default is 32. | Optional | 
| env_version | Version of Windows OS. Possible values are: Windows Vista, Windows 7, Windows 8.1, Windows 10. Default is Windows 7. | Optional | 
| env_type | Environment preset type. Possible values are: complete, clean, office. Default is complete. | Optional | 
| opt_network_connect | Network connection state. Possible values are: true, false. Default is true. | Optional | 
| opt_kernel_heavyevasion | Heavy evasion option. Possible values are: true, false. Default is false. | Optional | 
| opt_privacy_type | Privacy settings for generated task. Possible values are: owner, bylink, public. Default is owner. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.Task.ID | String | ID of the task created to analyze the submission. | 
