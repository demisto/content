ANY.RUN is a cloud-based sandbox with interactive access.

## Use Cases

ANY.RUN Sandbox is an online interactive sandbox for malware analysis, a tool for detection, monitoring, and research of cyber threats in real time.

1. Submit a file, remote file, or URL to ANY.RUN for analysis using the following OS:
    * Windows
    * Ubuntu, Debian
    * Android
2. Retrieve report details for a given analysis task ID in various formats:
    * Json summary
    * HTML
    * IOCs
3. View history of analysis tasks.
4. View personal analysis limits.
5. Download file submission sample, analysis network traffic dumps

## Requirements

Integration is officially supported from XSOAR 8.x

## Generate API token

* Follow [ANY.RUN Sandbox](https://app.any.run/)
* [1] Profile > [2] API and Limits > [3] Generate > [4] Copy

![ANY.RUN Generate API KEY](../../doc_files/ANYRUN_API_TOKEN.png)

## Configure ANY.RUN Sandbox in Cortex

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ANY.RUN.
3. Click **Add instance** to create and configure a new integration instance.
4. Insert ANY.RUN API-KEY into the **Password** parameter.
5. Please use "ANY.RUN" as username.
6. Click **Test** to validate the URLs, token, and connection.

| **Parameter**                                                                                                   | **Description**                                                                                                                                                 | **Required** |
|-----------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| Password                                                                                                        | ANY.RUN API-KEY without prefix.                                                                                                                                 | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

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
| ANYRUN_DetonateFileWindows.TaskID | String | Task UUID. |

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
| ANYRUN_DetonateUrlWindows.TaskID | String | Task UUID. |

### anyrun-detonate-file-linux

***
Perform File analysis using Linux VM.

#### Base Command

`anyrun-detonate-file-linux`

#### Input

| **Argument Name** | **Description**                                                                                                                                 | **Required** |
| --- |-------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| file | XSOAR Incident file data.                                                                                                                       | Required |
| env_locale | Operation system language. Use locale identifier or country name (Ex: "en-US" or "Brazil"). Case insensitive. Default is en-US.                 | Optional |
| env_os | Operation system. Possible values are: ubuntu, debian. Default is ubuntu.                                                                       | Optional |
| opt_network_connect | Network connection state. Default is True.                                                                                                      | Optional |
| opt_network_fakenet | FakeNet feature status. Default is False.                                                                                                       | Optional |
| opt_network_tor | TOR using. Default is False.                                                                                                                    | Optional |
| opt_network_geo | Tor geo location option. Example: US, AU. Default is fastest.                                                                                   | Optional |
| opt_network_mitm | HTTPS MITM proxy option. Default is False.                                                                                                      | Optional |
| opt_network_residential_proxy | Residential proxy using. Default is False.                                                                                                      | Optional |
| opt_network_residential_proxy_geo | Residential proxy geo location option. Example: US, AU. Default is fastest.                                                                     | Optional |
| opt_privacy_type | Privacy settings. Possible values are: public, bylink, owner, byteam. Default is bylink.                                                        | Optional |
| opt_timeout | Timeout option. Size range: 10-660. Default is 240.                                                                                             | Optional |
| obj_ext_startfolder | Start file analysis from the specified directory. Possible values are: desktop, home, downloads, appdata, temp, windows, root. Default is temp. | Optional |
| obj_ext_cmd | Optional command line.                                                                                                                          | Optional |
| run_as_root | Run file with superuser privileges. Default is True.                                                                                            | Optional |
| obj_ext_extension | Change extension to valid. Default is True.                                                                                                     | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN_DetonateFileLinux.TaskID | String | Task UUID. |

### anyrun-detonate-url-linux

***
Perform URL analysis using Linux VM.

#### Base Command

`anyrun-detonate-url-linux`

#### Input

| **Argument Name** | **Description**                                                                                                                | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------------| --- |
| obj_url | Target URL. Size range 5-512. Example: (http/https)://(your-link).                                                             | Required |
| env_locale | Operation system language. Use locale identifier or country name (Ex: "en-US" or "Brazil"). Case insensitive. Default is en-US. | Optional |
| env_os | Operation system. Possible values are: ubuntu, debian. Default is ubuntu.                                                      | Optional |
| opt_network_connect | Network connection state. Default is True.                                                                                     | Optional |
| opt_network_fakenet | FakeNet feature status. Default is False.                                                                                      | Optional |
| opt_network_tor | TOR using. Default is False.                                                                                                   | Optional |
| opt_network_geo | Tor geo location option. Example: US, AU. Default is fastest.                                                                  | Optional |
| opt_network_mitm | HTTPS MITM proxy option. Default is False.                                                                                     | Optional |
| opt_network_residential_proxy | Residential proxy using. Default is False.                                                                                     | Optional |
| opt_network_residential_proxy_geo | Residential proxy geo location option. Example: US, AU. Default is fastest.                                                    | Optional |
| opt_privacy_type | Privacy settings. Possible values are: public, bylink, owner, byteam. Default is bylink.                                       | Optional |
| opt_timeout | Timeout option. Size range: 10-660. Default is 120.                                                                            | Optional |
| obj_ext_browser | Browser name. Possible values are: Google Chrome, Mozilla Firefox. Default is Google Chrome.                                   | Optional |
| obj_ext_extension | Change extension to valid. Default is True.                                                                                    | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN_DetonateUrlLinux.TaskID | String | Task UUID. |

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
| ANYRUN_DetonateFileAndroid.TaskID | String | Task UUID. |

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
| ANYRUN_DetonateUrlAndroid.TaskID | String | Task UUID. |

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
Get analysis history.

#### Base Command

`anyrun-get-analysis-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team | Leave this field blank to get your history or specify to get team history. Default is False.. | Optional |
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

| **Argument Name** | **Description**                                                             | **Required** |
| --- |-----------------------------------------------------------------------------| --- |
| task_uuid | Sandbox task uuid.                                                          | Required |
| report_format | Report format. Possible values are: summary, html, ioc. Default is summary. | Optional |

#### Context Output

| **Path**                                                                 | **Type** | **Description**                                         |
|--------------------------------------------------------------------------| --- |---------------------------------------------------------|
| ANYRUN.IOCs                                                              | String | A comma-separated string of IOC values from the report.' |
| ANYRUN.SandboxAnalysis.mitre.name                                        | String | MITRE Technic text description.                         |
| ANYRUN.SandboxAnalysis.mitre.phases                                      | String | MITRE Technic phases.                                   |
| ANYRUN.SandboxAnalysis.mitre.id                                          | String | MITRE Technic identifier.                               |
| ANYRUN.SandboxAnalysis.debugStrings                                      | Unknown | Analysis debug information.                             |
| ANYRUN.SandboxAnalysis.incidents.process                                 | String | Analysis process.                                       |
| ANYRUN.SandboxAnalysis.incidents.events.time                             | Date | Event time.                                             |
| ANYRUN.SandboxAnalysis.incidents.events.cmdline                          | String | Event command line.                                     |
| ANYRUN.SandboxAnalysis.incidents.events.image                            | String | Event image.                                            |
| ANYRUN.SandboxAnalysis.incidents.mitre.v                                 | String | MITRE version.                                          |
| ANYRUN.SandboxAnalysis.incidents.mitre.sid                               | String | SID.                                                    |
| ANYRUN.SandboxAnalysis.incidents.mitre.tid                               | String | TID.                                                    |
| ANYRUN.SandboxAnalysis.incidents.count                                   | String | Count of related incidents.                             |
| ANYRUN.SandboxAnalysis.incidents.firstSeen                               | Date | Incident first seen date.                               |
| ANYRUN.SandboxAnalysis.incidents.source                                  | String | Incident source.                                        |
| ANYRUN.SandboxAnalysis.incidents.desc                                    | String | Incident description.                                   |
| ANYRUN.SandboxAnalysis.incidents.title                                   | String | Incident title.                                         |
| ANYRUN.SandboxAnalysis.incidents.threatLevel                             | String | Incident threat level.                                  |
| ANYRUN.SandboxAnalysis.incidents.events.typeValue                        | String | Event type value.                                       |
| ANYRUN.SandboxAnalysis.incidents.events.key                              | String | Event key.                                              |
| ANYRUN.SandboxAnalysis.incidents.events.value                            | String | Event value.                                            |
| ANYRUN.SandboxAnalysis.incidents.events.name                             | String | Event name.                                             |
| ANYRUN.SandboxAnalysis.incidents.events.operation                        | String | Event operation.                                        |
| ANYRUN.SandboxAnalysis.incidents.events.cmdParent                        | String | Event parent cmd.                                       |
| ANYRUN.SandboxAnalysis.incidents.events.cmdChild                         | String | Event child cmd.                                        |
| ANYRUN.SandboxAnalysis.modified.registry.time                            | Date | Registry time.                                          |
| ANYRUN.SandboxAnalysis.modified.registry.process                         | String | Registry process.                                       |
| ANYRUN.SandboxAnalysis.modified.registry.operation                       | String | Registry operation.                                     |
| ANYRUN.SandboxAnalysis.modified.registry.value                           | String | Registry value.                                         |
| ANYRUN.SandboxAnalysis.modified.registry.name                            | String | Registry name.                                          |
| ANYRUN.SandboxAnalysis.modified.registry.key                             | String | Registry key.                                           |
| ANYRUN.SandboxAnalysis.modified.files.process                            | String | File process.                                           |
| ANYRUN.SandboxAnalysis.modified.files.size                               | String | File size.                                              |
| ANYRUN.SandboxAnalysis.modified.files.filename                           | String | Filename.                                               |
| ANYRUN.SandboxAnalysis.modified.files.time                               | Date | File creating time.                                     |
| ANYRUN.SandboxAnalysis.modified.files.info.mime                          | String | File MIME type.                                         |
| ANYRUN.SandboxAnalysis.modified.files.info.file                          | String | File content.                                           |
| ANYRUN.SandboxAnalysis.modified.files.permanentUrl                       | String | File url.                                               |
| ANYRUN.SandboxAnalysis.modified.files.hashes.ssdeep                      | String | File SSDeep.                                            |
| ANYRUN.SandboxAnalysis.modified.files.hashes.sha256                      | String | File sha256 hash.                                       |
| ANYRUN.SandboxAnalysis.modified.files.hashes.sha1                        | String | File sha1 hash.                                         |
| ANYRUN.SandboxAnalysis.modified.files.hashes.md5                         | String | File md5 hash.                                          |
| ANYRUN.SandboxAnalysis.modified.files.threatLevel                        | String | File threat level.                                      |
| ANYRUN.SandboxAnalysis.modified.files.type                               | String | File type.                                              |
| ANYRUN.SandboxAnalysis.network.threats                                   | Unknown | Analysis network threats.                               |
| ANYRUN.SandboxAnalysis.network.connections.reputation                    | String | Network connection reputation.                          |
| ANYRUN.SandboxAnalysis.network.connections.tlsFingerprint.ja3SFullstring | String | Network connection ja3S.                                |
| ANYRUN.SandboxAnalysis.network.connections.tlsFingerprint.ja3S           | String | Network connection ja3S.                                |
| ANYRUN.SandboxAnalysis.network.connections.tlsFingerprint.ja3Fullstring  | String | Network connection ja3F.                                |
| ANYRUN.SandboxAnalysis.network.connections.tlsFingerprint.ja3            | String | Network connection ja3F.                                |
| ANYRUN.SandboxAnalysis.network.connections.time                          | Date | Network connection time.                                |
| ANYRUN.SandboxAnalysis.network.connections.asn                           | String | Network connection ASN.                                 |
| ANYRUN.SandboxAnalysis.network.connections.country                       | String | Network connection country.                             |
| ANYRUN.SandboxAnalysis.network.connections.protocol                      | String | Network connection protocol.                            |
| ANYRUN.SandboxAnalysis.network.connections.port                          | String | Network connection port.                                |
| ANYRUN.SandboxAnalysis.network.connections.ip                            | String | Network connection ip.                                  |
| ANYRUN.SandboxAnalysis.network.connections.process                       | String | Network connection processes.                           |
| ANYRUN.SandboxAnalysis.network.connections.tlsFingerprint.jarm           | String | Network connection jarm.                                |
| ANYRUN.SandboxAnalysis.network.httpRequests.country                      | String | HTTP Request country.                                   |
| ANYRUN.SandboxAnalysis.network.httpRequests.reputation                   | String | HTTP Request reputation.                                |
| ANYRUN.SandboxAnalysis.network.httpRequests.process                      | String | HTTP Request related process.                           |
| ANYRUN.SandboxAnalysis.network.httpRequests.httpCode                     | String | HTTP Request status code.                               |
| ANYRUN.SandboxAnalysis.network.httpRequests.status                       | String | HTTP Request status.                                    |
| ANYRUN.SandboxAnalysis.network.httpRequests.user-agent                   | String | HTTP Request User-Agent header value.                   |
| ANYRUN.SandboxAnalysis.network.httpRequests.proxyDetected                | String | HTTP Request is proxy detected.                         |
| ANYRUN.SandboxAnalysis.network.httpRequests.port                         | String | HTTP Request port.                                      |
| ANYRUN.SandboxAnalysis.network.httpRequests.ip                           | String | HTTP Request ip.                                        |
| ANYRUN.SandboxAnalysis.network.httpRequests.url                          | String | HTTP Request url.                                       |
| ANYRUN.SandboxAnalysis.network.httpRequests.host                         | String | HTTP Request host.                                      |
| ANYRUN.SandboxAnalysis.network.httpRequests.method                       | String | HTTP Request method.                                    |
| ANYRUN.SandboxAnalysis.network.httpRequests.time                         | Date | HTTP Request time estimate.                             |
| ANYRUN.SandboxAnalysis.network.dnsRequests.reputationNumber              | String | DNS Request reputation number.                          |
| ANYRUN.SandboxAnalysis.network.dnsRequests.reputation                    | String | DNS Request reputation.                                 |
| ANYRUN.SandboxAnalysis.network.dnsRequests.ips                           | String | DNS Request IPs.                                        |
| ANYRUN.SandboxAnalysis.network.dnsRequests.domain                        | String | DNS Request domain.                                     |
| ANYRUN.SandboxAnalysis.network.dnsRequests.time                          | Date | DNS Request time estimate.                              |
| ANYRUN.SandboxAnalysis.malconf                                           | Unknown | Analysis malconf.                                       |
| ANYRUN.SandboxAnalysis.processes.synchronization                         | Unknown | Analysis processes synchronization.                     |
| ANYRUN.SandboxAnalysis.processes.modules                                 | Unknown | Analysis processes modules.                             |
| ANYRUN.SandboxAnalysis.processes.hasMalwareConfig                        | String | Process has malware config.                             |
| ANYRUN.SandboxAnalysis.processes.parentUUID                              | String | Process parent UUID.                                    |
| ANYRUN.SandboxAnalysis.processes.status                                  | String | Process status.                                         |
| ANYRUN.SandboxAnalysis.processes.scores.specs.malwareConfig              | String | Process malware config.                                 |
| ANYRUN.SandboxAnalysis.processes.scores.specs.privEscalation             | String | Process priv escalation.                                |
| ANYRUN.SandboxAnalysis.processes.scores.specs.stealing                   | String | Process stealing.                                       |
| ANYRUN.SandboxAnalysis.processes.scores.specs.networkLoader              | String | Process network loader.                                 |
| ANYRUN.SandboxAnalysis.processes.scores.specs.network                    | String | Process network.                                        |
| ANYRUN.SandboxAnalysis.processes.scores.specs.lowAccess                  | String | Process low access.                                     |
| ANYRUN.SandboxAnalysis.processes.scores.specs.knownThreat                | String | Process known threat.                                   |
| ANYRUN.SandboxAnalysis.processes.scores.specs.injects                    | String | Process inject.                                         |
| ANYRUN.SandboxAnalysis.processes.scores.specs.exploitable                | String | Process exploitable.                                    |
| ANYRUN.SandboxAnalysis.processes.scores.specs.executableDropped          | String | Process executable dropped.                             |
| ANYRUN.SandboxAnalysis.processes.scores.specs.debugOutput                | String | Process debug output.                                   |
| ANYRUN.SandboxAnalysis.processes.scores.specs.crashedApps                | String | Process crashed apps.                                   |
| ANYRUN.SandboxAnalysis.processes.scores.specs.autoStart                  | String | Process auto start.                                     |
| ANYRUN.SandboxAnalysis.processes.scores.loadsSusp                        | String | Process loads susp.                                     |
| ANYRUN.SandboxAnalysis.processes.scores.injected                         | String | Process injected.                                       |
| ANYRUN.SandboxAnalysis.processes.scores.dropped                          | String | Process dropped.                                        |
| ANYRUN.SandboxAnalysis.processes.scores.verdict.threatLevelText          | String | Process threat level text.                              |
| ANYRUN.SandboxAnalysis.processes.scores.verdict.threatLevel              | String | Process threat level.                                   |
| ANYRUN.SandboxAnalysis.processes.scores.verdict.score                    | String | Process score.                                          |
| ANYRUN.SandboxAnalysis.processes.context.userName                        | String | Process context username.                               |
| ANYRUN.SandboxAnalysis.processes.context.integrityLevel                  | String | Process context integrity level.                        |
| ANYRUN.SandboxAnalysis.processes.context.rebootNumber                    | String | Process context reboot number.                          |
| ANYRUN.SandboxAnalysis.processes.versionInfo.version                     | String | Process version.                                        |
| ANYRUN.SandboxAnalysis.processes.versionInfo.description                 | String | Process description.                                    |
| ANYRUN.SandboxAnalysis.processes.versionInfo.company                     | String | Process company.                                        |
| ANYRUN.SandboxAnalysis.processes.mainProcess                             | String | Process main process.                                   |
| ANYRUN.SandboxAnalysis.processes.fileType                                | String | Process file type.                                      |
| ANYRUN.SandboxAnalysis.processes.fileName                                | String | Process filename.                                       |
| ANYRUN.SandboxAnalysis.processes.commandLine                             | String | Process cmd.                                            |
| ANYRUN.SandboxAnalysis.processes.image                                   | String | Process image.                                          |
| ANYRUN.SandboxAnalysis.processes.uuid                                    | String | Process uuid.                                           |
| ANYRUN.SandboxAnalysis.processes.ppid                                    | String | Process PPID.                                           |
| ANYRUN.SandboxAnalysis.processes.important                               | String | Process important.                                      |
| ANYRUN.SandboxAnalysis.processes.pid                                     | String | Process PID.                                            |
| ANYRUN.SandboxAnalysis.processes.exitCode                                | String | Process exit code.                                      |
| ANYRUN.SandboxAnalysis.processes.times.terminate                         | Date | Process time terminate.                                 |
| ANYRUN.SandboxAnalysis.processes.times.start                             | Date | Process time start.                                     |
| ANYRUN.SandboxAnalysis.processes.resolvedCOM.title                       | String | Process resolved COM title.                             |
| ANYRUN.SandboxAnalysis.processes.synchronization.operation               | String | Process sync operation.                                 |
| ANYRUN.SandboxAnalysis.processes.synchronization.type                    | String | Process sync type.                                      |
| ANYRUN.SandboxAnalysis.processes.synchronization.name                    | String | Process sync name.                                      |
| ANYRUN.SandboxAnalysis.processes.synchronization.time                    | Date | Process sync time.                                      |
| ANYRUN.SandboxAnalysis.processes.modules.image                           | String | Process module image.                                   |
| ANYRUN.SandboxAnalysis.processes.modules.time                            | Date | Process module time.                                    |
| ANYRUN.SandboxAnalysis.processes.scores.monitoringReason                 | String | Process monitoring reason.                              |
| ANYRUN.SandboxAnalysis.processes.times.monitoringSince                   | Date | Process monitoring since.                               |
| ANYRUN.SandboxAnalysis.counters.synchronization.type.event               | String | Process sync event.                                     |
| ANYRUN.SandboxAnalysis.counters.synchronization.type.mutex               | String | Process sync mutex.                                     |
| ANYRUN.SandboxAnalysis.counters.synchronization.operation.create         | String | Process sync operation create.                          |
| ANYRUN.SandboxAnalysis.counters.synchronization.operation.open           | String | Process sync operation open.                            |
| ANYRUN.SandboxAnalysis.counters.synchronization.total                    | String | Process sync total.                                     |
| ANYRUN.SandboxAnalysis.counters.registry.delete                          | String | Registry delete.                                        |
| ANYRUN.SandboxAnalysis.counters.registry.write                           | String | Registry write.                                         |
| ANYRUN.SandboxAnalysis.counters.registry.read                            | String | Registry read.                                          |
| ANYRUN.SandboxAnalysis.counters.registry.total                           | String | Registry total.                                         |
| ANYRUN.SandboxAnalysis.counters.files.malicious                          | String | File malicious count.                                   |
| ANYRUN.SandboxAnalysis.counters.files.suspicious                         | String | File suspicious count.                                  |
| ANYRUN.SandboxAnalysis.counters.files.text                               | String | File text.                                              |
| ANYRUN.SandboxAnalysis.counters.files.unknown                            | String | File unknown count.                                     |
| ANYRUN.SandboxAnalysis.counters.network.threats                          | String | Network threats count.                                  |
| ANYRUN.SandboxAnalysis.counters.network.dns                              | String | Network dns count.                                      |
| ANYRUN.SandboxAnalysis.counters.network.connections                      | String | Network connections count.                              |
| ANYRUN.SandboxAnalysis.counters.network.http                             | String | Network networks count.                                 |
| ANYRUN.SandboxAnalysis.counters.processes.malicious                      | String | Malicious processes count.                              |
| ANYRUN.SandboxAnalysis.counters.processes.suspicious                     | String | Suspicious processes count.                             |
| ANYRUN.SandboxAnalysis.counters.processes.monitored                      | String | Monitored processes count.                              |
| ANYRUN.SandboxAnalysis.counters.processes.total                          | String | Total processes count.                                  |
| ANYRUN.SandboxAnalysis.environments.hotfixes.title                       | String | Environment hotfixes title.                             |
| ANYRUN.SandboxAnalysis.environments.software.version                     | String | Environment software version.                           |
| ANYRUN.SandboxAnalysis.environments.software.title                       | String | Environment software title.                             |
| ANYRUN.SandboxAnalysis.environments.internetExplorer.kbnum               | String | Environment Internet Explorer KBNUM.                    |
| ANYRUN.SandboxAnalysis.environments.internetExplorer.version             | String | Environment Internet Explorer version.                  |
| ANYRUN.SandboxAnalysis.environments.os.bitness                           | String | Environment OS version.                                 |
| ANYRUN.SandboxAnalysis.environments.os.softSet                           | String | Environment OS software set.                            |
| ANYRUN.SandboxAnalysis.environments.os.servicePack                       | String | Environment OS service pack.                            |
| ANYRUN.SandboxAnalysis.environments.os.major                             | String | Environment OS major version.                           |
| ANYRUN.SandboxAnalysis.environments.os.productType                       | String | Environment OS product type.                            |
| ANYRUN.SandboxAnalysis.environments.os.variant                           | String | Environment OS variant.                                 |
| ANYRUN.SandboxAnalysis.environments.os.product                           | String | Environment OS product.                                 |
| ANYRUN.SandboxAnalysis.environments.os.build                             | String | Environment OS build.                                   |
| ANYRUN.SandboxAnalysis.environments.os.title                             | String | Environment OS title.                                   |
| ANYRUN.SandboxAnalysis.analysis.content.dumps                            | Unknown | Content dumps.                                          |
| ANYRUN.SandboxAnalysis.analysis.content.screenshots.thumbnailUrl         | String | Screenshots thumbnail url.                              |
| ANYRUN.SandboxAnalysis.analysis.content.screenshots.permanentUrl         | String | Screenshots permanent url.                              |
| ANYRUN.SandboxAnalysis.analysis.content.screenshots.time                 | String | Screenshots time.                                       |
| ANYRUN.SandboxAnalysis.analysis.content.screenshots.uuid                 | String | Screenshots uuid.                                       |
| ANYRUN.SandboxAnalysis.analysis.content.sslkeys.present                  | String | SSL keys present.                                       |
| ANYRUN.SandboxAnalysis.analysis.content.pcap.permanentUrl                | String | Pcap dump permanent url.                                |
| ANYRUN.SandboxAnalysis.analysis.content.pcap.present                     | String | Pcap present.                                           |
| ANYRUN.SandboxAnalysis.analysis.content.video.permanentUrl               | String | Video permanent url.                                    |
| ANYRUN.SandboxAnalysis.analysis.content.video.present                    | String | Video present.                                          |
| ANYRUN.SandboxAnalysis.analysis.content.mainObject.hashes.ssdeep         | String | Main object ssdeep.                                     |
| ANYRUN.SandboxAnalysis.analysis.content.mainObject.hashes.sha256         | String | Main object sha256.                                     |
| ANYRUN.SandboxAnalysis.analysis.content.mainObject.hashes.sha1           | String | Main object sha1.                                       |
| ANYRUN.SandboxAnalysis.analysis.content.mainObject.hashes.md5            | String | Main object md5.                                        |
| ANYRUN.SandboxAnalysis.analysis.content.mainObject.url                   | String | Main object url.                                        |
| ANYRUN.SandboxAnalysis.analysis.content.mainObject.type                  | String | Main object type.                                       |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.knownThreat                 | String | Specs known threat.                                     |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.malwareConfig               | String | Specs malware Config.                                   |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.notStarted                  | String | Specs not started.                                      |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.privEscalation              | String | Specs priv escalation.                                  |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.torUsed                     | String | Specs TOR used.                                         |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.suspStruct                  | String | Specs susp structure.                                   |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.stealing                    | String | Specs stealing.                                         |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.staticDetections            | String | Specs static detections.                                |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.spam                        | String | Specs spam.                                             |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.serviceLauncher             | String | Specs service launcher.                                 |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.rebooted                    | String | Specs rebooted.                                         |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.networkThreats              | String | Specs network threats.                                  |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.networkLoader               | String | Specs network loader.                                   |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.multiprocessing             | String | Specs multiprocessing.                                  |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.memOverrun                  | String | Specs memory overrun.                                   |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.lowAccess                   | String | Specs low access.                                       |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.exploitable                 | String | Specs exploitable.                                      |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.executableDropped           | String | Specs executable dropped.                               |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.debugOutput                 | String | Specs debug output.                                     |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.crashedTask                 | String | Specs crashed task.                                     |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.crashedApps                 | String | Specs crashed apps.                                     |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.cpuOverrun                  | String | Specs CPU overrun.                                      |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.autoStart                   | String | Specs auto start.                                       |
| ANYRUN.SandboxAnalysis.analysis.scores.specs.injects                     | String | Specs injects.                                          |
| ANYRUN.SandboxAnalysis.analysis.scores.verdict.threatLevelText           | String | Verdict threat level text.                              |
| ANYRUN.SandboxAnalysis.analysis.scores.verdict.threatLevel               | String | Verdict threat level.                                   |
| ANYRUN.SandboxAnalysis.analysis.scores.verdict.score                     | String | Verdict score.                                          |
| ANYRUN.SandboxAnalysis.analysis.options.automatization.uac               | String | Options automatization UAC.                             |
| ANYRUN.SandboxAnalysis.analysis.options.privateSample                    | String | Options private sample.                                 |
| ANYRUN.SandboxAnalysis.analysis.options.privacy                          | String | Options privacy.                                        |
| ANYRUN.SandboxAnalysis.analysis.options.network                          | String | Options network.                                        |
| ANYRUN.SandboxAnalysis.analysis.options.hideSource                       | String | Options hide source.                                    |
| ANYRUN.SandboxAnalysis.analysis.options.video                            | String | Options video.                                          |
| ANYRUN.SandboxAnalysis.analysis.options.presentation                     | String | Options presentation.                                   |
| ANYRUN.SandboxAnalysis.analysis.options.tor.used                         | String | Options tor used.                                       |
| ANYRUN.SandboxAnalysis.analysis.options.mitm                             | String | Options MITM proxy.                                     |
| ANYRUN.SandboxAnalysis.analysis.options.heavyEvasion                     | String | Options kernel heavy evasion.                           |
| ANYRUN.SandboxAnalysis.analysis.options.fakeNet                          | String | Options fake network.                                   |
| ANYRUN.SandboxAnalysis.analysis.options.additionalTime                   | String | Options additional time.                                |
| ANYRUN.SandboxAnalysis.analysis.options.timeout                          | String | Options timeout.                                        |
| ANYRUN.SandboxAnalysis.analysis.tags                                     | Unknown | Analysis tags.                                          |
| ANYRUN.SandboxAnalysis.analysis.stopExecText                             | Date | Analysis stopExecText.                                  |
| ANYRUN.SandboxAnalysis.analysis.stopExec                                 | Date | Analysis creation stopExec.                             |
| ANYRUN.SandboxAnalysis.analysis.creationText                             | Date | Analysis creation text.                         |
| ANYRUN.SandboxAnalysis.analysis.creation                                 | Date | Analysis creation date.                                 |
| ANYRUN.SandboxAnalysis.analysis.duration                                 | String | Analysis duration.                                      |
| ANYRUN.SandboxAnalysis.analysis.sandbox.plan.name                        | String | Analysis sandbox user plan name.                        |
| ANYRUN.SandboxAnalysis.analysis.sandbox.name                             | String | Analysis sandbox name.                                  |
| ANYRUN.SandboxAnalysis.analysis.reports.graph                            | String | Analysis reports graph.                                 |
| ANYRUN.SandboxAnalysis.analysis.reports.STIX                             | String | Analysis STIX report url.                               |
| ANYRUN.SandboxAnalysis.analysis.reports.HTML                             | String | Analysis HTML report url.                               |
| ANYRUN.SandboxAnalysis.analysis.reports.MISP                             | String | Analysis MISP report url.                               |
| ANYRUN.SandboxAnalysis.analysis.reports.IOC                              | String | Analysis IOC report url.                                |
| ANYRUN.SandboxAnalysis.analysis.permanentUrl                             | String | Analysis permanent url.                                 |
| ANYRUN.SandboxAnalysis.analysis.uuid                                     | String | Analysis uuid.                                          |
| ANYRUN.SandboxAnalysis.status                                            | String | Analysis status.                                        |

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

There is no context output for this command.

### anyrun-download-analysis-sample

***
Returns the analysis file in zip archive. Archive password: infected.

#### Base Command

`anyrun-download-analysis-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_uuid | Sandbox task uuid. | Required |

#### Context Output

There is no context output for this command.

### anyrun-get-analysis-verdict

***
Returns a threat level text. Possible values: No threats detected, Suspicious activity, Malicious activity.

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
