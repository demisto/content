ANY.RUN is a cloud-based sandbox with interactive access.

## Use Cases
ANY.RUN Sandbox is an online interactive sandbox for malware analysis, a tool for detection, monitoring, and research of cyber threats in real time.

1. Submit a file, remote file, or URL to ANY.RUN for analysis using the following OS:
    * Windows
    * Ubuntu
    * Android
2. Retrieve report details for a given analysis task ID in various formats:
    * Json summary
    * HTML
    * IOCs
3. View history of analysis tasks.
4. View personal analysis limits.
5. Download file submission sample, analysis network traffic dumps


## Configure ANY.RUN Sandbox in Cortex

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ANYRUN.
3. Click **Add instance** to create and configure a new integration instance.
4. Click **Test** to validate the connection to ANY.RUN Cloud Sandbox.

| **Parameter** | **Description**                                                                                                                                                | **Required** |
| --- |----------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| ANY.RUN Sandbox API-KEY | ANY.RUN API-KEY without prefix                                                                                                                                 | True |
| Server's FQDN | Go to Settings &amp; Info → Settings → Integrations → API Keys. Click Copy API URL. Your FQDN is saved in the clipboard. Inline it without http/https protocol | True |
| XSOAR API-KEY ID | In the API Keys table, locate the ID field. Note your corresponding ID number                                                                                  | True |
| XSOAR API-KEY | XSOAR API-KEY                                                                                                                                                  | True |


## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
The commands allow you to launch and download only your own tasks, public submissions are not available at this point.

### anyrun-detonate-file-windows

***
Perform File analysis using Windows VM.

#### Base Command

`anyrun-detonate-file-windows`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | XSOAR Incident file data. | Required | 
| env_version | Version of OS. Possible values are: 7, 10, 11. Default is 10. | Optional | 
| env_bitness | Bitness of Operation System. Possible values are: 32, 64. Default is 64. | Optional | 
| env_type | Environment preset type. You can select **development** env for OS Windows 10 x64. For all other cases, **complete** env is required. Possible values are: development, complete. Default is complete. | Optional | 
| env_locale | Operation system language. Use locale identifier or country name (Ex: "en-US" or "Brazil"). Case insensitive. Default is en-US. | Optional | 
| opt_network_connect | Network connection state. Default is True. | Optional | 
| opt_network_fakenet | FakeNet feature status. Default is False. | Optional | 
| opt_network_tor | TOR using. Default is False. | Optional | 
| opt_network_geo | Tor geo location option. Example: US, AU. Default is fastest. | Optional | 
| opt_network_mitm | HTTPS MITM proxy option. Default is False. | Optional | 
| opt_network_residential_proxy | Residential proxy using. Default is False. | Optional | 
| opt_network_residential_proxy_geo | Residential proxy geo location option. Example: US, AU. Default is fastest. | Optional | 
| opt_privacy_type | Privacy settings. Possible values are: public, bylink, owner, byteam. Default is bylink. | Optional | 
| opt_timeout | Timeout option. Size range: 10-660. Default is 240. | Optional | 
| obj_ext_startfolder | Start file analysis from the specified directory. Possible values are: desktop, home, downloads, appdata, temp, windows, root. Default is temp. | Optional | 
| obj_ext_cmd | Optional command line. | Optional | 
| obj_force_elevation | Forces the file to execute with elevated privileges and an elevated token (for PE32, PE32+, PE64 files only). Default is False. | Optional | 
| obj_ext_extension | Change extension to valid. Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.TaskID | String | Task UUID. | 

### anyrun-detonate-url-windows

***
Perform URL analysis using Windows VM.

#### Base Command

`anyrun-detonate-url-windows`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| obj_url | Target URL. Size range 5-512. Example: (http/https)://(your-link). | Required | 
| env_version | Version of OS. Possible values are: 7, 10, 11. Default is 10. | Optional | 
| env_bitness | Bitness of Operation System. Possible values are: 32, 64. Default is 64. | Optional | 
| env_type | Environment preset type. You can select **development** env for OS Windows 10 x64. For all other cases, **complete** env is required. Possible values are: development, complete. Default is complete. | Optional | 
| env_locale | Operation system language. Use locale identifier or country name (Ex: "en-US" or "Brazil"). Case insensitive. Default is en-US. | Optional | 
| opt_network_connect | Network connection state. Default is True. | Optional | 
| opt_network_fakenet | FakeNet feature status. Default is False. | Optional | 
| opt_network_tor | TOR using. Default is False. | Optional | 
| opt_network_geo | Tor geo location option. Example: US, AU. Default is fastest. | Optional | 
| opt_network_mitm | HTTPS MITM proxy option. Default is False. | Optional | 
| opt_network_residential_proxy | Residential proxy using. Default is False. | Optional | 
| opt_network_residential_proxy_geo | Residential proxy geo location option. Example: US, AU. Default is fastest. | Optional | 
| opt_privacy_type | Privacy settings. Possible values are: public, bylink, owner, byteam. Default is bylink. | Optional | 
| opt_timeout | Timeout option. Size range: 10-660. Default is 240. | Optional | 
| obj_ext_browser | Browser name. Possible values are: Google Chrome, Mozilla Firefox, Internet Explorer, Microsoft Edge. Default is Google Chrome. | Optional | 
| obj_ext_extension | Change extension to valid. Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.TaskID | String | Task UUID. | 

### anyrun-detonate-file-linux

***
Perform File analysis using Ubuntu VM.

#### Base Command

`anyrun-detonate-file-linux`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | XSOAR Incident file data. | Required | 
| env_locale | Operation system language. Use locale identifier or country name (Ex: "en-US" or "Brazil"). Case insensitive. Default is en-US. | Optional | 
| env_os | Operation system. Default is ubuntu. | Optional | 
| opt_network_connect | Network connection state. Default is True. | Optional | 
| opt_network_fakenet | FakeNet feature status. Default is False. | Optional | 
| opt_network_tor | TOR using. Default is False. | Optional | 
| opt_network_geo | Tor geo location option. Example: US, AU. Default is fastest. | Optional | 
| opt_network_mitm | HTTPS MITM proxy option. Default is False. | Optional | 
| opt_network_residential_proxy | Residential proxy using. Default is False. | Optional | 
| opt_network_residential_proxy_geo | Residential proxy geo location option. Example: US, AU. Default is fastest. | Optional | 
| opt_privacy_type | Privacy settings. Possible values are: public, bylink, owner, byteam. Default is bylink. | Optional | 
| opt_timeout | Timeout option. Size range: 10-660. Default is 240. | Optional | 
| obj_ext_startfolder | Start file analysis from the specified directory. Possible values are: desktop, home, downloads, appdata, temp, windows, root. Default is temp. | Optional | 
| obj_ext_cmd | Optional command line. | Optional | 
| run_as_root | Run file with superuser privileges. Default is True. | Optional | 
| obj_ext_extension | Change extension to valid. Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.TaskID | String | Task UUID. | 

### anyrun-detonate-url-linux

***
Perform URL analysis using Ubuntu VM.

#### Base Command

`anyrun-detonate-url-linux`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| obj_url | Target URL. Size range 5-512. Example: (http/https)://(your-link). | Required | 
| env_locale | Operation system language. Use locale identifier or country name (Ex: "en-US" or "Brazil"). Case insensitive. Default is en-US. | Optional | 
| env_os | Operation system. Default is ubuntu. | Optional | 
| opt_network_connect | Network connection state. Default is True. | Optional | 
| opt_network_fakenet | FakeNet feature status. Default is False. | Optional | 
| opt_network_tor | TOR using. Default is False. | Optional | 
| opt_network_geo | Tor geo location option. Example: US, AU. Default is fastest. | Optional | 
| opt_network_mitm | HTTPS MITM proxy option. Default is False. | Optional | 
| opt_network_residential_proxy | Residential proxy using. Default is False. | Optional | 
| opt_network_residential_proxy_geo | Residential proxy geo location option. Example: US, AU. Default is fastest. | Optional | 
| opt_privacy_type | Privacy settings. Possible values are: public, bylink, owner, byteam. Default is bylink. | Optional | 
| opt_timeout | Timeout option. Size range: 10-660. Default is 120. | Optional | 
| obj_ext_browser | Browser name. Possible values are: Google Chrome, Mozilla Firefox. Default is Google Chrome. | Optional | 
| obj_ext_extension | Change extension to valid. Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.TaskID | String | Task UUID. | 

### anyrun-detonate-file-android

***
Perform File analysis using Android VM.

#### Base Command

`anyrun-detonate-file-android`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | XSOAR Entry ID. | Required | 
| env_locale | Operation system language. Use locale identifier or country name (Ex: "en-US" or "Brazil"). Case insensitive. Default is en-US. | Optional | 
| opt_network_connect | Network connection state. Default is True. | Optional | 
| opt_network_fakenet | FakeNet feature status. Default is False. | Optional | 
| opt_network_tor | TOR using. Default is False. | Optional | 
| opt_network_geo | Tor geo location option. Example: US, AU. Default is fastest. | Optional | 
| opt_network_mitm | HTTPS MITM proxy option. Default is False. | Optional | 
| opt_network_residential_proxy | Residential proxy using. Default is False. | Optional | 
| opt_network_residential_proxy_geo | Residential proxy geo location option. Example: US, AU. Default is fastest. | Optional | 
| opt_privacy_type | Privacy settings. Possible values are: public, bylink, owner, byteam. Default is bylink. | Optional | 
| opt_timeout | Timeout option. Size range: 10-660. Default is 120. | Optional | 
| obj_ext_cmd | Optional command line. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.TaskID | String | Task UUID. | 

### anyrun-detonate-url-android

***
Perform URL analysis using Android VM.

#### Base Command

`anyrun-detonate-url-android`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| obj_url | Target URL. Size range 5-512. Example: (http/https)://(your-link). | Required | 
| env_locale | Operation system language. Use locale identifier or country name (Ex: "en-US" or "Brazil"). Case insensitive. Default is en-US. | Optional | 
| opt_network_connect | Network connection state. Default is True. | Optional | 
| opt_network_fakenet | FakeNet feature status. Default is False. | Optional | 
| opt_network_tor | TOR using. Default is False. | Optional | 
| opt_network_geo | Tor geo location option. Example: US, AU. Default is fastest. | Optional | 
| opt_network_mitm | HTTPS MITM proxy option. Default is False. | Optional | 
| opt_network_residential_proxy | Residential proxy using. Default is False. | Optional | 
| opt_network_residential_proxy_geo | Residential proxy geo location option. Example: US, AU. Default is fastest. | Optional | 
| opt_privacy_type | Privacy settings. Possible values are: public, bylink, owner, byteam. Default is bylink. | Optional | 
| opt_timeout | Timeout option. Size range: 10-660. Default is 120. | Optional | 
| obj_ext_browser | Browser name. Possible values are: Google Chrome, Mozilla Firefox. Default is Google Chrome. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.TaskID | String | Task UUID. | 

### anyrun-get-user-limits

***
Get user available limits to perform the Sandbox analysis.

#### Base Command

`anyrun-get-user-limits`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.SandboxLimits.web.minute | String | Defines limits for interactive usage. Value of -1 indicates unlimited usage. | 
| ANYRUN.SandboxLimits.web.hour | String | Defines limits for interactive usage. Value of -1 indicates unlimited usage. | 
| ANYRUN.SandboxLimits.web.day | String | Defines limits for interactive usage. Value of -1 indicates unlimited usage. | 
| ANYRUN.SandboxLimits.web.month | String | Defines limits for interactive usage. Value of -1 indicates unlimited usage. | 
| ANYRUN.SandboxLimits.api.minute | String | Defines limits for API usage. Value of -1 indicates unlimited usage. | 
| ANYRUN.SandboxLimits.api.hour | String | Defines limits for API usage. Value of -1 indicates unlimited usage. | 
| ANYRUN.SandboxLimits.api.day | String | Defines limits for API usage. Value of -1 indicates unlimited usage. | 
| ANYRUN.SandboxLimits.api.month | String | Defines limits for API usage. Value of -1 indicates unlimited usage. | 
| ANYRUN.SandboxLimits.parallels.total | String | Defines limits for parallel runs. | 
| ANYRUN.SandboxLimits.parallels.available | String | Defines limits for parallel runs. | 

### anyrun-get-analysis-history

***
Get analysis history

#### Base Command

`anyrun-get-analysis-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team | Leave this field blank to get your history or specify to get team history. Default is False. | Optional | 
| skip | Skip the specified number of tasks. Default is 0. | Optional | 
| limit | Specify the number of tasks in the result set (not more than 100). Default is 25. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.SandboxHistory.tasks.uuid | String | Task UUID. | 
| ANYRUN.SandboxHistory.tasks.verdict | String | ANY.RUN verdict for the submitted file status. | 
| ANYRUN.SandboxHistory.tasks.name | String | Task name. | 
| ANYRUN.SandboxHistory.tasks.related | String | ANY.RUN link to a related file. | 
| ANYRUN.SandboxHistory.tasks.pcap | String | ANY.RUN link to the network traffic dump. | 
| ANYRUN.SandboxHistory.tasks.file | String | ANY.RUN link to the file sample. | 
| ANYRUN.SandboxHistory.tasks.json | String | ANY.RUN link to json summary. | 
| ANYRUN.SandboxHistory.tasks.misp | String | ANY.RUN link to misp report. | 
| ANYRUN.SandboxHistory.tasks.tags | String | ANY.RUN related tags array. | 
| ANYRUN.SandboxHistory.tasks.date | Date | The date that the file was submitted for analysis. | 
| ANYRUN.SandboxHistory.tasks.hashes.md5 | String | MD5 hash of the submitted file. | 
| ANYRUN.SandboxHistory.tasks.hashes.sha1 | String | SHA1 hash of the submitted file. | 
| ANYRUN.SandboxHistory.tasks.hashes.sha256 | String | SHA256 hash of the submitted file. | 
| ANYRUN.SandboxHistory.tasks.hashes.ssdeep | String | SSDeep hash of the submitted file. | 

### anyrun-delete-task

***
Deletes analysis task according to specified task uuid.

#### Base Command

`anyrun-delete-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_uuid | Sandbox task uuid. | Required | 

#### Context Output

There is no context output for this command.
### anyrun-get-analysis-report

***
Returns the analysis report summary.

#### Base Command

`anyrun-get-analysis-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_uuid | Sandbox task uuid. | Required | 
| report_format | Report format. Possible values are: summary, html, ioc. Default is summary. | Optional | 
| incident_info | XSOAR Related icnident info. | Required | 

#### Context Output

| **Path**                                                      | **Type** | **Description** |
|---------------------------------------------------------------| --- | --- |
| ANYRUN.SandboxAnalysis.analysis.creationText                     | String | Date and time the analysis was executed. | 
| ANYRUN.SandboxAnalysis.incidents.desc               | String | Category of a process behavior. | 
| ANYRUN.SandboxAnalysis.incidents.title                   | String | Actions performed by a process. | 
| ANYRUN.SandboxAnalysis.incidents.threatLevel             | Number | Threat score associated with a process behavior. | 
| ANYRUN.SandboxAnalysis.incidents.process               | String | Unique ID of the process whose behaviors are being profiled. | 
| ANYRUN.SandboxAnalysis.network.connections.reputation         | String | Connection reputation. | 
| ANYRUN.SandboxAnalysis.network.connections.process            | String | ID of the process that created the connection. | 
| ANYRUN.SandboxAnalysis.network.connections.asn                | String | Connection autonomous system network. | 
| ANYRUN.SandboxAnalysis.network.connections.country            | String | Connection country. | 
| ANYRUN.SandboxAnalysis.network.connections.protocol           | String | Connection protocol. | 
| ANYRUN.SandboxAnalysis.network.connections.port               | Number | Connection port number. | 
| ANYRUN.SandboxAnalysis.network.connections.ip                 | String | Connection IP number. | 
| ANYRUN.SandboxAnalysis.network.dnsRequests.reputation         | String | Reputation of the DNS request. | 
| ANYRUN.SandboxAnalysis.network.dnsRequests.ips                | Unknown | IP addresses associated with a DNS request. | 
| ANYRUN.SandboxAnalysis.network.dnsRequests.domain             | String | Domain resolution of a DNS request. | 
| ANYRUN.SandboxAnalysis.network.httpRequests.reputation        | String | Reputation of the HTTP request. | 
| ANYRUN.SandboxAnalysis.network.httpRequests.country           | String | HTTP request country. | 
| ANYRUN.SandboxAnalysis.network.httpRequests.process           | String | ID of the process making the HTTP request. | 
| ANYRUN.SandboxAnalysis.network.httpRequests.httpCode          | Number | HTTP request response code. | 
| ANYRUN.SandboxAnalysis.network.httpRequests.status            | String | Status of the HTTP request. | 
| ANYRUN.SandboxAnalysis.network.httpRequests.proxyDetected     | Boolean | Whether the HTTP request was made through a proxy. | 
| ANYRUN.SandboxAnalysis.network.httpRequests.port              | Number | HTTP request port. | 
| ANYRUN.SandboxAnalysis.network.httpRequests.ip                | String | HTTP request IP address. | 
| ANYRUN.SandboxAnalysis.network.httpRequests.url               | String | HTTP request URL. | 
| ANYRUN.SandboxAnalysis.network.httpRequests.host              | String | HTTP request host. | 
| ANYRUN.SandboxAnalysis.network.httpRequests.method            | String | HTTP request method type. | 
| ANYRUN.SandboxAnalysis.environments.os.title                  | String | OS of the sandbox in which the file was analyzed. | 
| ANYRUN.SandboxAnalysis.analysis.uuid                          | String | The unique ID of the task. | 
| ANYRUN.SandboxAnalysis.modified.files.info.mime               | String | The MIME of the file submitted for analysis. | 
| ANYRUN.SandboxAnalysis.modified.files.hashes.md5              | String | The MD5 hash of the file submitted for analysis. | 
| ANYRUN.SandboxAnalysis.modified.files.hashes.sha1             | String | The SHA1 hash of the file submitted for analysis. | 
| ANYRUN.SandboxAnalysis.modified.files.hashes.sha256           | String | The SHA256 hash of the file submitted for analysis. | 
| ANYRUN.SandboxAnalysis.modified.files.hashes.ssdeep           | String | SSDeep hash of the file submitted for analysis. | 
| ANYRUN.SandboxAnalysis.analysis.scores.verdict.threatLevelText | String | ANY.RUN verdict for the maliciousness of the submitted file or URL. | 
| ANYRUN.SandboxAnalysis.modified.files.filename                | String | File name of the process. | 
| ANYRUN.SandboxAnalysis.process.PID                            | Number | Process identification number. | 
| ANYRUN.SandboxAnalysis.process.PPID                           | Number | Parent process identification number. | 
| ANYRUN.SandboxAnalysis.process.ProcessUUID                    | String | Unique process ID \(used by ANY.RUN\). | 
| ANYRUN.SandboxAnalysis.process.CMD                            | String | Process command. | 
| ANYRUN.SandboxAnalysis.processes.context.userName             | String | User who executed the command. | 
| ANYRUN.SandboxAnalysis.processes.context.integrityLevel       | String | The process integrity level. | 
| ANYRUN.SandboxAnalysis.processes.exitCode                     | Number | Process exit code. | 
| ANYRUN.SandboxAnalysis.processes.versionInfo.company          | String | Company responsible for the program executed. | 
| ANYRUN.SandboxAnalysis.processes.versionInfo.description      | String | Description of the type of program. | 
| ANYRUN.SandboxAnalysis.processes.versionInfo.version          | String | Version of the program executed. | 


### anyrun-download-analysis-pcap

***
Returns the analysis network traffic dump.

#### Base Command

`anyrun-download-analysis-pcap`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_uuid | Sandbox task uuid. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.SandboxAnalysisReportPcap | File | The analysis network traffic dump .pcap file. | 

### anyrun-download-analysis-sample

***
Returns the analysis file in zip archive. Archive password: infected

#### Base Command

`anyrun-download-analysis-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_uuid | Sandbox task uuid. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.SandboxAnalysisReportSample | File | The analysis sample. | 

### anyrun-get-analysis-verdict

***
Returns a threat level text. Possible values: No threats detected, Suspicious activity, Malicious activity

#### Base Command

`anyrun-get-analysis-verdict`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_uuid | Sandbox task uuid. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.SandboxAnalysisReportVerdict | String | The analysis verdict. | 
