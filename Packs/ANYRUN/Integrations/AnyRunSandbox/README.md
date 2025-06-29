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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.SandboxAnalysis.mitre.name | String | MITRE Technic text description | 
| ANYRUN.SandboxAnalysis.mitre.phases | String |  | 
| ANYRUN.SandboxAnalysis.mitre.id | String |  | 
| ANYRUN.SandboxAnalysis.debugStrings | Unknown |  | 
| ANYRUN.SandboxAnalysis.incidents.process | String |  | 
| ANYRUN.SandboxAnalysis.incidents.events.time | Date |  | 
| ANYRUN.SandboxAnalysis.incidents.events.cmdline | String |  | 
| ANYRUN.SandboxAnalysis.incidents.events.image | String |  | 
| ANYRUN.SandboxAnalysis.incidents.mitre.v | String |  | 
| ANYRUN.SandboxAnalysis.incidents.mitre.sid | String |  | 
| ANYRUN.SandboxAnalysis.incidents.mitre.tid | String |  | 
| ANYRUN.SandboxAnalysis.incidents.count | String |  | 
| ANYRUN.SandboxAnalysis.incidents.firstSeen | Date |  | 
| ANYRUN.SandboxAnalysis.incidents.source | String |  | 
| ANYRUN.SandboxAnalysis.incidents.desc | String |  | 
| ANYRUN.SandboxAnalysis.incidents.title | String |  | 
| ANYRUN.SandboxAnalysis.incidents.threatLevel | String |  | 
| ANYRUN.SandboxAnalysis.incidents.events.typeValue | String |  | 
| ANYRUN.SandboxAnalysis.incidents.events.key | String |  | 
| ANYRUN.SandboxAnalysis.incidents.events.value | String |  | 
| ANYRUN.SandboxAnalysis.incidents.events.name | String |  | 
| ANYRUN.SandboxAnalysis.incidents.events.operation | String |  | 
| ANYRUN.SandboxAnalysis.incidents.events.cmdParent | String |  | 
| ANYRUN.SandboxAnalysis.incidents.events.cmdChild | String |  | 
| ANYRUN.SandboxAnalysis.modified.registry.time | Date |  | 
| ANYRUN.SandboxAnalysis.modified.registry.process | String |  | 
| ANYRUN.SandboxAnalysis.modified.registry.operation | String |  | 
| ANYRUN.SandboxAnalysis.modified.registry.value | String |  | 
| ANYRUN.SandboxAnalysis.modified.registry.name | String |  | 
| ANYRUN.SandboxAnalysis.modified.registry.key | String |  | 
| ANYRUN.SandboxAnalysis.modified.files.process | String |  | 
| ANYRUN.SandboxAnalysis.modified.files.size | String |  | 
| ANYRUN.SandboxAnalysis.modified.files.filename | String |  | 
| ANYRUN.SandboxAnalysis.modified.files.time | Date |  | 
| ANYRUN.SandboxAnalysis.modified.files.info.mime | String |  | 
| ANYRUN.SandboxAnalysis.modified.files.info.file | String |  | 
| ANYRUN.SandboxAnalysis.modified.files.permanentUrl | String |  | 
| ANYRUN.SandboxAnalysis.modified.files.hashes.ssdeep | String |  | 
| ANYRUN.SandboxAnalysis.modified.files.hashes.sha256 | String |  | 
| ANYRUN.SandboxAnalysis.modified.files.hashes.sha1 | String |  | 
| ANYRUN.SandboxAnalysis.modified.files.hashes.md5 | String |  | 
| ANYRUN.SandboxAnalysis.modified.files.threatLevel | String |  | 
| ANYRUN.SandboxAnalysis.modified.files.type | String |  | 
| ANYRUN.SandboxAnalysis.network.threats | Unknown |  | 
| ANYRUN.SandboxAnalysis.network.connections.reputation | String |  | 
| ANYRUN.SandboxAnalysis.network.connections.tlsFingerprint.ja3SFullstring | String |  | 
| ANYRUN.SandboxAnalysis.network.connections.tlsFingerprint.ja3S | String |  | 
| ANYRUN.SandboxAnalysis.network.connections.tlsFingerprint.ja3Fullstring | String |  | 
| ANYRUN.SandboxAnalysis.network.connections.tlsFingerprint.ja3 | String |  | 
| ANYRUN.SandboxAnalysis.network.connections.time | Date |  | 
| ANYRUN.SandboxAnalysis.network.connections.asn | String |  | 
| ANYRUN.SandboxAnalysis.network.connections.country | String |  | 
| ANYRUN.SandboxAnalysis.network.connections.protocol | String |  | 
| ANYRUN.SandboxAnalysis.network.connections.port | String |  | 
| ANYRUN.SandboxAnalysis.network.connections.ip | String |  | 
| ANYRUN.SandboxAnalysis.network.connections.process | String |  | 
| ANYRUN.SandboxAnalysis.network.connections.tlsFingerprint.jarm | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.country | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.reputation | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.process | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.httpCode | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.status | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.user-agent | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.proxyDetected | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.port | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.ip | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.url | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.host | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.method | String |  | 
| ANYRUN.SandboxAnalysis.network.httpRequests.time | Date |  | 
| ANYRUN.SandboxAnalysis.network.dnsRequests.reputationNumber | String |  | 
| ANYRUN.SandboxAnalysis.network.dnsRequests.reputation | String |  | 
| ANYRUN.SandboxAnalysis.network.dnsRequests.ips | String |  | 
| ANYRUN.SandboxAnalysis.network.dnsRequests.domain | String |  | 
| ANYRUN.SandboxAnalysis.network.dnsRequests.time | Date |  | 
| ANYRUN.SandboxAnalysis.malconf | Unknown |  | 
| ANYRUN.SandboxAnalysis.processes.synchronization | Unknown |  | 
| ANYRUN.SandboxAnalysis.processes.modules | Unknown |  | 
| ANYRUN.SandboxAnalysis.processes.hasMalwareConfig | String |  | 
| ANYRUN.SandboxAnalysis.processes.parentUUID | String |  | 
| ANYRUN.SandboxAnalysis.processes.status | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.malwareConfig | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.privEscalation | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.stealing | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.networkLoader | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.network | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.lowAccess | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.knownThreat | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.injects | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.exploitable | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.executableDropped | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.debugOutput | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.crashedApps | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.specs.autoStart | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.loadsSusp | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.injected | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.dropped | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.verdict.threatLevelText | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.verdict.threatLevel | String |  | 
| ANYRUN.SandboxAnalysis.processes.scores.verdict.score | String |  | 
| ANYRUN.SandboxAnalysis.processes.context.userName | String |  | 
| ANYRUN.SandboxAnalysis.processes.context.integrityLevel | String |  | 
| ANYRUN.SandboxAnalysis.processes.context.rebootNumber | String |  | 
| ANYRUN.SandboxAnalysis.processes.versionInfo.version | String |  | 
| ANYRUN.SandboxAnalysis.processes.versionInfo.description | String |  | 
| ANYRUN.SandboxAnalysis.processes.versionInfo.company | String |  | 
| ANYRUN.SandboxAnalysis.processes.mainProcess | String |  | 
| ANYRUN.SandboxAnalysis.processes.fileType | String |  | 
| ANYRUN.SandboxAnalysis.processes.fileName | String |  | 
| ANYRUN.SandboxAnalysis.processes.commandLine | String |  | 
| ANYRUN.SandboxAnalysis.processes.image | String |  | 
| ANYRUN.SandboxAnalysis.processes.uuid | String |  | 
| ANYRUN.SandboxAnalysis.processes.ppid | String |  | 
| ANYRUN.SandboxAnalysis.processes.important | String |  | 
| ANYRUN.SandboxAnalysis.processes.pid | String |  | 
| ANYRUN.SandboxAnalysis.processes.exitCode | String |  | 
| ANYRUN.SandboxAnalysis.processes.times.terminate | Date |  | 
| ANYRUN.SandboxAnalysis.processes.times.start | Date |  | 
| ANYRUN.SandboxAnalysis.processes.resolvedCOM.title | String |  | 
| ANYRUN.SandboxAnalysis.processes.synchronization.operation | String |  | 
| ANYRUN.SandboxAnalysis.processes.synchronization.type | String |  | 
| ANYRUN.SandboxAnalysis.processes.synchronization.name | String |  | 
| ANYRUN.SandboxAnalysis.processes.synchronization.time | Date |  | 
| ANYRUN.SandboxAnalysis.processes.modules.image | String |  | 
| ANYRUN.SandboxAnalysis.processes.modules.time | Date |  | 
| ANYRUN.SandboxAnalysis.processes.scores.monitoringReason | String |  | 
| ANYRUN.SandboxAnalysis.processes.times.monitoringSince | Date |  | 
| ANYRUN.SandboxAnalysis.counters.synchronization.type.event | String |  | 
| ANYRUN.SandboxAnalysis.counters.synchronization.type.mutex | String |  | 
| ANYRUN.SandboxAnalysis.counters.synchronization.operation.create | String |  | 
| ANYRUN.SandboxAnalysis.counters.synchronization.operation.open | String |  | 
| ANYRUN.SandboxAnalysis.counters.synchronization.total | String |  | 
| ANYRUN.SandboxAnalysis.counters.registry.delete | String |  | 
| ANYRUN.SandboxAnalysis.counters.registry.write | String |  | 
| ANYRUN.SandboxAnalysis.counters.registry.read | String |  | 
| ANYRUN.SandboxAnalysis.counters.registry.total | String |  | 
| ANYRUN.SandboxAnalysis.counters.files.malicious | String |  | 
| ANYRUN.SandboxAnalysis.counters.files.suspicious | String |  | 
| ANYRUN.SandboxAnalysis.counters.files.text | String |  | 
| ANYRUN.SandboxAnalysis.counters.files.unknown | String |  | 
| ANYRUN.SandboxAnalysis.counters.network.threats | String |  | 
| ANYRUN.SandboxAnalysis.counters.network.dns | String |  | 
| ANYRUN.SandboxAnalysis.counters.network.connections | String |  | 
| ANYRUN.SandboxAnalysis.counters.network.http | String |  | 
| ANYRUN.SandboxAnalysis.counters.processes.malicious | String |  | 
| ANYRUN.SandboxAnalysis.counters.processes.suspicious | String |  | 
| ANYRUN.SandboxAnalysis.counters.processes.monitored | String |  | 
| ANYRUN.SandboxAnalysis.counters.processes.total | String |  | 
| ANYRUN.SandboxAnalysis.environments.hotfixes.title | String |  | 
| ANYRUN.SandboxAnalysis.environments.software.version | String |  | 
| ANYRUN.SandboxAnalysis.environments.software.title | String |  | 
| ANYRUN.SandboxAnalysis.environments.internetExplorer.kbnum | String |  | 
| ANYRUN.SandboxAnalysis.environments.internetExplorer.version | String |  | 
| ANYRUN.SandboxAnalysis.environments.os.bitness | String |  | 
| ANYRUN.SandboxAnalysis.environments.os.softSet | String |  | 
| ANYRUN.SandboxAnalysis.environments.os.servicePack | String |  | 
| ANYRUN.SandboxAnalysis.environments.os.major | String |  | 
| ANYRUN.SandboxAnalysis.environments.os.productType | String |  | 
| ANYRUN.SandboxAnalysis.environments.os.variant | String |  | 
| ANYRUN.SandboxAnalysis.environments.os.product | String |  | 
| ANYRUN.SandboxAnalysis.environments.os.build | String |  | 
| ANYRUN.SandboxAnalysis.environments.os.title | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.dumps | Unknown |  | 
| ANYRUN.SandboxAnalysis.analysis.content.screenshots.thumbnailUrl | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.screenshots.permanentUrl | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.screenshots.time | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.screenshots.uuid | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.sslkeys.present | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.pcap.permanentUrl | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.pcap.present | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.video.permanentUrl | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.video.present | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.mainObject.hashes.ssdeep | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.mainObject.hashes.sha256 | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.mainObject.hashes.sha1 | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.mainObject.hashes.md5 | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.mainObject.url | String |  | 
| ANYRUN.SandboxAnalysis.analysis.content.mainObject.type | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.knownThreat | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.malwareConfig | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.notStarted | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.privEscalation | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.torUsed | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.suspStruct | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.stealing | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.staticDetections | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.spam | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.serviceLauncher | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.rebooted | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.networkThreats | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.networkLoader | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.multiprocessing | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.memOverrun | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.lowAccess | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.exploitable | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.executableDropped | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.debugOutput | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.crashedTask | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.crashedApps | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.cpuOverrun | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.autoStart | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.specs.injects | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.verdict.threatLevelText | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.verdict.threatLevel | String |  | 
| ANYRUN.SandboxAnalysis.analysis.scores.verdict.score | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.automatization.uac | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.privateSample | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.privacy | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.network | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.hideSource | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.video | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.presentation | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.tor.used | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.mitm | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.heavyEvasion | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.fakeNet | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.additionalTime | String |  | 
| ANYRUN.SandboxAnalysis.analysis.options.timeout | String |  | 
| ANYRUN.SandboxAnalysis.analysis.tags | Unknown |  | 
| ANYRUN.SandboxAnalysis.analysis.stopExecText | Date |  | 
| ANYRUN.SandboxAnalysis.analysis.stopExec | Date |  | 
| ANYRUN.SandboxAnalysis.analysis.creationText | Date |  | 
| ANYRUN.SandboxAnalysis.analysis.creation | Date |  | 
| ANYRUN.SandboxAnalysis.analysis.duration | String |  | 
| ANYRUN.SandboxAnalysis.analysis.sandbox.plan.name | String |  | 
| ANYRUN.SandboxAnalysis.analysis.sandbox.name | String |  | 
| ANYRUN.SandboxAnalysis.analysis.reports.graph | String |  | 
| ANYRUN.SandboxAnalysis.analysis.reports.STIX | String |  | 
| ANYRUN.SandboxAnalysis.analysis.reports.HTML | String |  | 
| ANYRUN.SandboxAnalysis.analysis.reports.MISP | String |  | 
| ANYRUN.SandboxAnalysis.analysis.reports.IOC | String |  | 
| ANYRUN.SandboxAnalysis.analysis.permanentUrl | String |  | 
| ANYRUN.SandboxAnalysis.analysis.uuid | String |  | 
| ANYRUN.SandboxAnalysis.status | String |  | 

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
