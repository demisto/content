Use the FireEye HX integration to access information about endpoints, acquisitions, alerts, indicators, and containment.

  

 Use Cases
---------

 FireEye HX integration can be used for the following use cases:

 ### Monitor FireEye HX alerts

 Simply use the ‘fetch-incidents’ option in the integration settings (as explained in ‘Fetched incidents data’ section above) for a continues pull of alerts to the Cortex XSOAR platform.

 ### Search Hosts

 Search all hosts or a subset of hosts for a specific file or indicator.  
The produces a list of hosts with a list of results for each host.

 Find more information on ‘Additional Information’ section below.

 ### Apply or remove containment from hosts

 Containment prevents further compromise of a host system and its components by restricting the hostʼs ability to communicate.

 ### Host containment

 To request that a specific host be contained so that it no longer has access to other systems, run the fireeye-host-containment command and pass either the host name or its agent ID, for example, fireeye-host-containment hostname=“DESKTOP-HK8OI62”

 Notes:

  * Some hosts are ineligible for containment.
 * The time it takes to contain a host varies, based on factors such as agent connectivity, network traffic, and other jobs running in your environment .
 * You cannot contain a host if the agent package for that host is not available on the FireEye HX Series appliance.
  ### Host containment removal

 To release a specific host from containment, run the fireeye-cancel-containment command and pass either the host name or its agent ID, for example fireeye-cancel-containment agentId=”uGvn34ZkM3bfSf1nOT”

  

 Prerequisites
-------------

 Make sure you have a valid **user account** on the FireEye HX Series appliance associated with the *api\_admin* or *api\_analyst* role.

 For more information about setting up user accounts on the FireEye HX Series appliance, see the FireEye HX Series System Administration Guide.

  

 Configure FireEye HX on Cortex XSOAR
------------------------------------

  2. Navigate to **Settings** > **Integrations** > **Servers & Services**.
 4. Search for FireEye HX.
 6. Click **Add instance** to create and configure a new integration instance.  
 
	 *  **Name**: A textual name for the integration instance.
	 *  **Server URL**: Exchange server URL.
	 *  **Credentials: **Your personal account username.
	 *  **Password**: Your personal account password.
	 *  **Version**: The API version. Default is 3.
	 *  **Fetched incidents data**: The integration imports FireEye HX alerts as Cortex XSOAR incidents**. **The first pull of incidents will fetch the last 100 alerts on FireEye HX.
	  
 8. Click **Test** to validate the URLs and token.
   

 Commands
--------

 You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

  2. [Contain a host: fireeye-hx-host-containment](#h_4940381161531225583805)
 4. [Release host from containment: fireeye-hx-cancel-containment](#h_753562077941531225590399)
 6. [Get alert list: fireeye-hx-get-alerts](#h_3659112741821531225598795)
 8. [Get alert details: fireeye-hx-get-alert](#h_4996266442681531225609912)
 10. [Suppress an alert: fireeye-hx-suppress-alert](#h_2089802313531531225618306)
 12. [Get indicator list: fireeye-get-indicators](#h_6259227744371531225635704)
 14. [Get indicator information: fireeye-get-indicator](#h_3177394125201531225647008)
 16. [Find hostname correlated with agent-ID or agent-ID correlated with hostname: fireeye-get-host-information](#h_1285237886021531225659162)
 18. [Acquire a file: fireeye-file-acquisition](#h_9238521966831531225671914)
 20. [Delete a file acquisition: fireeye-delete-file-acquisition](#h_8039477917631531225683376)
 22. [Acquire data: fireeye-data-acquisition](#h_284510558421531225696011)
 24. [Delete data acquisition: fireeye-delete-data-acquisition](#h_7751566479201531225716697)
   

 ### 1. Contain a host

  Contains a specific host, so it cannot access to other systems.

 ##### Command Limitations

  * Some hosts cannot be contained.
 * The time it takes to contain a host varies, based on factors such as agent connectivity, network traffic, and other jobs running in your environment.
 * You can only contain a host if the agent package for that host is available on the FireEye HX Series appliance.
  ##### Base Command

 fireeye-hx-host-containment

 ##### Input

 All arguments are optional, but you need to specify at least one to run this command.

    **Argument Name** **Description** **Required**     hostName The host name to be contained. If the *hostName* is not specified, the *agentId* is required. Optional   agentId The agent ID running on the host to be contained. If the *agentId* is not specified, the *hostName* is required. Optional    ##### 

 ##### Context Output

    **Path** **Description**     FireEyeHX.Hosts.\_id FireEye HX Agent ID   FireEyeHX.Hosts.agent\_version The agent version   FireEyeHX.Hosts.excluded\_from\_containment Determines whether the host is excluded from containment   FireEyeHX.Hosts.containment\_missing\_software Boolean value to indicate for containment missing software   FireEyeHX.Hosts.containment\_queued Determines whether the host is queued for containment   FireEyeHX.Hosts.containment\_state The containment state of the host. Possible values normal   FireEyeHX.Hosts.stats.alerting\_conditions The number of conditions that have alerted the host   FireEyeHX.Hosts.stats.alerts Total number of alerts, including exploit-detection alerts   FireEyeHX.Hosts.stats.exploit\_blocks The number of blocked exploits on the host   FireEyeHX.Hosts.stats.malware\_alerts The number of malware alerts associated with the host   FireEyeHX.Hosts.hostname Host name   FireEyeHX.Hosts.domain Domain name   FireEyeHX.Hosts.timezone Host time zone   FireEyeHX.Hosts.primary\_ip\_address Host IP address   FireEyeHX.Hosts.last\_poll\_timestamp The timestamp of the last system poll performed on the host   FireEyeHX.Hosts.initial\_agent\_checkin Timestamp of the initial agent check-in   FireEyeHX.Hosts.last\_alert\_timestamp The time stamp of the last alert for the host   FireEyeHX.Hosts.last\_exploit\_block\_timestamp Time when the last exploit was blocked on the host. The value is null if no exploits were blocked   FireEyeHX.Hosts.os.product\_name Operating system   FireEyeHX.Hosts.os.bitness OS bitness (32 or 64)   FireEyeHX.Hosts.os.platform  Family of operating systems

  * win
 * osx
 * linux
     FireEyeHX.Hosts.primary\_mac The host MAC address    ##### 

 ##### Command Examples

 !fireeye-hx-host-containment agentId=”uGvn34ZkM3bfSf1nOT”

 !fireeye-hx-host-containment hostname=“DESKTOP-HK8OI62”

 ##### Context Example

  { "FireEyeHX":{ "Hosts":{ "last\_alert":{ "url":"/hx/api/v3/alerts/5", "\_id":5 }, "domain":"DEMISTO", "last\_exploit\_block\_timestamp":null, "containment\_state":"contain", "timezone":"Eastern Daylight Time", "gmt\_offset\_seconds":-14400, "initial\_agent\_checkin":"2018-03-26T14:21:31.273Z", "stats":{ "alerting\_conditions":1, "exploit\_alerts":0, "acqs":11, "malware\_false\_positive\_alerts":0, "alerts":1, "exploit\_blocks":0, "malware\_cleaned\_count":0, "malware\_alerts":0, "malware\_quarantined\_count":0 }, "primary\_mac":"XX-XX-XX-XX-XX-XX", "hostname":"DESKTOP-XXX", "primary\_ip\_address":"^^^XX.XX.XX.XX^^^", "last\_audit\_timestamp":"2018-05-03T13:59:23.000Z", "last\_alert\_timestamp":"2018-04-16T08:59:51.693+00:00", "containment\_queued":false, "sysinfo":{ "url":"/hx/api/v3/hosts/uGvnGVpZkDSFySf2ZOiT/sysinfo" }, "last\_exploit\_block":null, "reported\_clone":false, "url":"/hx/api/v3/hosts/uGvnGVpZkeySf2ZOiT", "excluded\_from\_containment":false, "last\_poll\_timestamp":"2018-05-03T14:01:22.000Z", "last\_poll\_ip":"^^^XX.XX.XX.XX^^^", "containment\_missing\_software":false, "\_id":" uGvnGVpZkDSFySf2ZOiT ", "os":{ "kernel\_version":null, "platform":"win", "patch\_level":null, "bitness":"64-bit", "product\_name":"Windows 10 Enterprise Evaluation" }, "agent\_version":"26.21.10" } } }  

 ### 2. Release host from containment

  Releases a specific host from containment.

 ##### Base Command

 fireeye-hx-cancel-containment

 ##### Input

 All arguments are optional, but you need to specify at least one to run this command.

    **Argument Name** **Description** **Required**     hostName The host name to be contained. If the *hostName* is not specified, the *agentId* is required. Optional   agentId The agent ID running on the host to be contained. If the *agentId* is not specified, the *hostName* is required. Optional    ##### 

 ##### Context Output

    **Path** **Description**     FireEyeHX.Hosts.\_id FireEye HX Agent ID   FireEyeHX.Hosts.agent\_version The agent version   FireEyeHX.Hosts.excluded\_from\_containment Determines whether the host is excluded from containment   FireEyeHX.Hosts.containment\_missing\_software Boolean value to indicate for containment missing software   FireEyeHX.Hosts.containment\_queued Determines whether the host is queued for containment   FireEyeHX.Hosts.containment\_state The containment state of the host. Possible values normal   FireEyeHX.Hosts.stats.alerting\_conditions The number of conditions that have alerted the host   FireEyeHX.Hosts.stats.alerts Total number of alerts, including exploit-detection alerts   FireEyeHX.Hosts.stats.exploit\_blocks The number of blocked exploits on the host   FireEyeHX.Hosts.stats.malware\_alerts The number of malware alerts associated with the host   FireEyeHX.Hosts.hostname Host name   FireEyeHX.Hosts.domain Domain name   FireEyeHX.Hosts.timezone Host time zone   FireEyeHX.Hosts.primary\_ip\_address Host IP address   FireEyeHX.Hosts.last\_poll\_timestamp The timestamp of the last system poll performed on the host   FireEyeHX.Hosts.initial\_agent\_checkin Timestamp of the initial agent check-in   FireEyeHX.Hosts.last\_alert\_timestamp The time stamp of the last alert for the host   FireEyeHX.Hosts.last\_exploit\_block\_timestamp Time when the last exploit was blocked on the host. The value is null if no exploits were blocked   FireEyeHX.Hosts.os.product\_name Operating system   FireEyeHX.Hosts.os.bitness OS bitness (32 or 64)   FireEyeHX.Hosts.os.platform  Family of operating systems

  * win
 * osx
 * linux
     FireEyeHX.Hosts.primary\_mac The host MAC address    ##### 

 ##### Command Examples

 !fireeye-hx-cancel-containment agentId=”uGvn34ZkM3bfSf1nOT”

 !fireeye-hx-cancel-containment hostname=“DESKTOP-HK8OI62”

 ##### Context Example

 { "FireEyeHX": { "Hosts": { "last\_alert": { "url": "/hx/api/v3/alerts/5", "\_id": 5 }, "domain": "DEMISTO", "last\_exploit\_block\_timestamp": null, "containment\_state": "normal", "timezone": "Eastern Daylight Time", "gmt\_offset\_seconds": -14400, "initial\_agent\_checkin": "2018-03-26T14:21:31.273Z", "stats": { "alerting\_conditions": 1, "exploit\_alerts": 0, "acqs": 11, "malware\_false\_positive\_alerts": 0, "alerts": 1, "exploit\_blocks": 0, "malware\_cleaned\_count": 0, "malware\_alerts": 0, "malware\_quarantined\_count": 0 }, "primary\_mac": "XX-XX-XX-XX-XX-XX", "hostname": "DESKTOP-XXX", "primary\_ip\_address": "^^^XX.XX.XX.XX^^^", "last\_audit\_timestamp": "2018-05-03T13:59:23.000Z", "last\_alert\_timestamp": "2018-04-16T08:59:51.693+00:00", "containment\_queued": false, "sysinfo": { "url": "/hx/api/v3/hosts/uGvnGVpZkDSFySf2ZOiT/sysinfo" }, "last\_exploit\_block": null, "reported\_clone": false, "url": "/hx/api/v3/hosts/uGvnGVpZkeySf2ZOiT", "excluded\_from\_containment": false, "last\_poll\_timestamp": "2018-05-03T14:01:22.000Z", "last\_poll\_ip": "^^^XX.XX.XX.XX^^^", "containment\_missing\_software": false, "\_id": " uGvnGVpZkDSFySf2ZOiT ", "os": { "kernel\_version": null, "platform": "win", "patch\_level": null, "bitness": "64-bit", "product\_name": "Windows 10 Enterprise Evaluation" }, "agent\_version": "26.21.10" } } }   

 ### 3. Get alert list

  Gets a list of alerts according to specified filters.

 ##### Base Command

 fireeye-hx-get-alerts

 ##### Input

    **Argument Name** **Description** **Required**     hasShareMode Identifies which alerts result from indicators with the specified share mode Optional   resolution Sorts the results by the specified field Optional   agentId Filter by the agent ID Optional   conditionId Filter by condition ID Optional   eventAt Filter event occurred time (ISO-8601 timestamp) Optional   alertId Filter by alert ID Optional   matchedAt Filter by match detection time (ISO-8601 timestamp) Optional   minId Filter that returns only records with an *AlertId* field value great than the *minId* value Optional   reportedAt Filter by reported time (ISO-8601 timestamp) Optional   IOCsource Source of alert (indicator of compromise) Optional   EXDsource Source of alert (exploit detection) Optional   MALsource Source of alert (malware alert) Optional   minId Return only records with an ID greater than *minId*  Optional   limit Specifies the number of results to return Optional   sort Sorts the results by the specified field in ascending order Optional   sortOrder The sort order for the results Optional    ##### 

 ##### Context Output

    **Path** **Description**     FireEyeHX.Alerts.\_id FireEye alert ID   FireEyeHX.Alerts.agent.\_id FireEye agent ID   FireEyeHX.Alerts.agent.containment\_state Host containment state   FireEyeHX.Alerts.condition.\_id The condition unique ID   FireEyeHX.Alerts.event\_at Time when the event occured   FireEyeHX.Alerts.matched\_at Time when the event was matched   FireEyeHX.Alerts.reported\_at Time when the event was reported   FireEyeHX.Alerts.source Source of alert   FireEyeHX.Alerts.matched\_source\_alerts.\_id Source alert ID   FireEyeHX.Alerts.matched\_source\_alerts.appliance\_id Appliance ID   FireEyeHX.Alerts.matched\_source\_alerts.meta Source alert meta   FireEyeHX.Alerts.matched\_source\_alerts.indicator\_id Indicator ID   FireEyeHX.Alerts.resolution Alert resolution   FireEyeHX.Alerts.event\_type Event type    ##### 

 ##### Command Example

 !fireeye-hx-get-alerts limit="10" sort="id" sortOrder="descending"

 ##### Raw Output

  { "FireEyeHX": { "Alerts": { "\_id": 5, "agent": { "\_id": "uGvnGVp…4bKeySf2ZOiT", "containment\_state": "normal", "url": "/hx/api/v3/hosts/ uGvnGVp…4bKeySf2ZOiT " }, "condition": { "\_id": "CSaoSZFw…JNPW0mw==", "url": "/hx/api/v3/conditions/ CSaoSZFw…JNPW0mw ==" }, "event\_at": "2018-04-16T08:59:02.061Z", "event\_id": 7885715, "event\_type": "fileWriteEvent", "event\_values": { "fileWriteEvent/closed": 1, "fileWriteEvent/dataAtLowestOffset": "dGVzdGVzdA==", "fileWriteEvent/devicePath": "\\Device\\HarddiskVolume2", "fileWriteEvent/drive": "C", "fileWriteEvent/fileExtension": "txt", "fileWriteEvent/fileName": "testest - Copy.txt", "fileWriteEvent/filePath": "Users\\demistodev\\Documents", "fileWriteEvent/fullPath": "C:\\Users\\User\\Documents\\testest - Copy.txt", "fileWriteEvent/lowestFileOffsetSeen": 0, "fileWriteEvent/md5": " c3add7b947…817c79f7b7bd ", "fileWriteEvent/numBytesSeenWritten": 7, "fileWriteEvent/pid": 3308, "fileWriteEvent/process": "explorer.exe", "fileWriteEvent/processPath": "C:\\Windows", "fileWriteEvent/size": 7, "fileWriteEvent/textAtLowestOffset": "testest", "fileWriteEvent/timestamp": "2018-04-16T08:59:02.061Z", "fileWriteEvent/username": "DEMISTO\\User", "fileWriteEvent/writes": 1 }, "is\_false\_positive": null, "matched\_at": "2018-04-16T08:59:10.000Z", "matched\_source\_alerts": [], "reported\_at": "2018-04-16T08:59:51.693Z", "resolution": "ALERT", "source": "IOC", "url": "/hx/api/v3/alerts/5" } }, "File": [ { "Extension": "txt", "MD5": "c3add7b947…817c79f7b7bd", "Name": "testest - Copy.txt", "Path": "C:\\Users\\User\\Documents\\testest - Copy.txt" } ], "IP": [], "RrgistryKey": [] }   

 ### 4. Get alert details

  Retrieves the details of a specific alert.

 ##### Base Command

 fireeye-hx-get-alert

 ##### Input

    **Argument Name** **Description** **Required**   alertId ID of alert to get details of Required     

 ##### Context Output

    **Path** **Description**     FireEyeHX.Alerts.\_id FireEye alert ID   FireEyeHX.Alerts.agent.\_id FireEye agent ID   FireEyeHX.Alerts.agent.containment\_state Host containment state   FireEyeHX.Alerts.condition.\_id The condition unique ID   FireEyeHX.Alerts.event\_at Time when the event occurred   FireEyeHX.Alerts.matched\_at Time when the event was matched   FireEyeHX.Alerts.reported\_at Time when the event was reported   FireEyeHX.Alerts.source Source of alert   FireEyeHX.Alerts.matched\_source\_alerts.\_id Source alert ID   FireEyeHX.Alerts.matched\_source\_alerts.appliance\_id Appliance ID   FireEyeHX.Alerts.matched\_source\_alerts.meta Source alert meta   FireEyeHX.Alerts.matched\_source\_alerts.indicator\_id Indicator ID   FireEyeHX.Alerts.resolution Alert resolution   FireEyeHX.Alerts.event\_type Event type    ##### 

 ##### Command Example

 !fireeye-hx-get-alert alertId=5

 ##### Context Example

  { "FireEyeHX": { "Alerts": { "\_id": 5, "agent": { "\_id": "uGvnGVpZkM4bKeySf2ZOiT", "containment\_state": "normal", "url": "/hx/api/v3/hosts/uGvnGVpZkM4bKeySf2ZOiT" }, "condition": { "\_id": "CSaoSZFwVBtjGJBJNPW0mw==", "url": "/hx/api/v3/conditions/CSaoSZFwVBtjGJBJNPW0mw==" }, "event\_at": "2018-04-16T08:59:02.061Z", "event\_id": 7885715, "event\_type": "fileWriteEvent", "event\_values": { "fileWriteEvent/closed": 1, "fileWriteEvent/dataAtLowestOffset": "dGVzdGVzdA==", "fileWriteEvent/devicePath": "\\Device\\HarddiskVolume2", "fileWriteEvent/drive": "C", "fileWriteEvent/fileExtension": "txt", "fileWriteEvent/fileName": "testest - Copy.txt", "fileWriteEvent/filePath": "Users\\demistodev\\Documents", "fileWriteEvent/fullPath": "C:\\Users\\demistodev\\Documents\\testest - Copy.txt", "fileWriteEvent/lowestFileOffsetSeen": 0, "fileWriteEvent/md5": "c3add7b94781ee70ec7c817c79f7b7bd", "fileWriteEvent/numBytesSeenWritten": 7, "fileWriteEvent/pid": 3308, "fileWriteEvent/process": "explorer.exe", "fileWriteEvent/processPath": "C:\\Windows", "fileWriteEvent/size": 7, "fileWriteEvent/textAtLowestOffset": "testest", "fileWriteEvent/timestamp": "2018-04-16T08:59:02.061Z", "fileWriteEvent/username": "DEMISTO\\demistodev", "fileWriteEvent/writes": 1 }, "is\_false\_positive": null, "matched\_at": "2018-04-16T08:59:10.000Z", "matched\_source\_alerts": [], "reported\_at": "2018-04-16T08:59:51.693Z", "resolution": "ALERT", "source": "IOC", "url": "/hx/api/v3/alerts/5" } } }   

 ### 5. Suppress an alert

  Suppresses an alert.

 ##### Base Command

 fireeye-hx-suppress-alert

 ##### Input

    **Argument Name** **Description** **Required**   alertId ID of alert to suppress (listed in the output of the get-alerts command) Required     

 ##### Context Output

 There is no context output for this command.

 ##### Command Example

 !fireeye-hx-suppress-alert alertId=2

  

  

 ### 6. Get indicator list

  Gets a list of indicators.

 ##### Base Command

 fireeye-hx-get-indicators

 ##### Input

    **Argument Name** **Description** **Required**     category The indicator category Optional   searchTerm The searchTerm can be any name, category, signature, source, or condition value. Optional   shareMode Determines who can see the indicator. You must belong to the correct authorization group . Optional   sort Sorts the results by the specified field in ascending order Optional   createdBy Person who created the indicator Optional   alerted Whether the indicator resulted in alerts Optional   limit Limit the number of results Optional    ##### 

 ##### Context Output

    **Path** **Description**     FireEyeHX.Indicators.\_id FireEye unique indicator ID   FireEyeHX.Indicators.name The indicator name as displayed in the UI   FireEyeHX.Indicators.description Indicator description   FireEyeHX.Indicators.category.name Category name   FireEyeHX.Indicators.created\_by The *Created By* field as displayed in UI   FireEyeHX.Indicators.active\_since Date that the indicator became active   FireEyeHX.Indicators.stats.source\_alerts Total number of source alerts associated with this indicator   FireEyeHX.Indicators.stats.alerted\_agents Total number of agents with FireEye HX alerts associated with this indicator   FireEyeHX.Indicators.platforms List of OS families    ##### 

 ##### Command Example

 !fireeye-hx-get-indicators sort="activeSince" alerted="yes"

 ##### Raw Output

  "FireEyeHX": { "Indicators": [ { "category": { "url": "/hx/api/v3/indicator\_categories/custom", "\_id": 2, "uri\_name": "Custom", "name": "Custom", "share\_mode": "unrestricted" }, "display\_name": null, "description": "", "create\_actor": { "username": "admin", "\_id": 1000 }, "platforms": [ "win", "osx" ], "url": "/hx/api/v3/indicators/custom/txt", "\_revision": "20180501131901519705101701", "update\_actor": { "username": "admin", "\_id": 1000 }, "create\_text": null, "created\_by": "admin", "active\_since": "2018-05-01T13:19:01.519Z", "meta": null, "signature": null, "stats": { "active\_conditions": 2, "alerted\_agents": 0, "source\_alerts": 0 }, … ] } }   

 ### 7. Get indicator information

  Retrieves information of a specific indicator.

 ##### Base Command

 fireeye-hx-get-indicator

 ##### Input

    **Input Parameter** **Description** **Required**   category Indicator category Required   name Indicator name Required     

 ##### Context Output

    **Path** **Description**     FireEyeHX.Indicators.\_id FireEye unique indicator ID.   FireEyeHX.Indicators.name The indicator name as displayed in the UI   FireEyeHX.Indicators.description Indicator description   FireEyeHX.Indicators.category.name Category name   FireEyeHX.Indicators.created\_by The *Created By* field as displayed in UI   FireEyeHX.Indicators.active\_since Date that the indicator became active   FireEyeHX.Indicators.stats.source\_alerts Total number of source alerts associated with this indicator   FireEyeHX.Indicators.stats.alerted\_agents Total number of agents with FireEye HX alerts associated with this indicator   FireEyeHX.Indicators.platforms List of OS families   FireEyeHX.Conditions.\_id FireEye unique condition ID   FireEyeHX.Conditions.event\_type Event type   FireEyeHX.Conditions.enabled Indicates whether the condition is enabled    ##### 

 ##### Command Example

 !fireeye-hx-get-indicator category=Custom name="test indicator"

 ##### Raw Output

  { "FireEyeHX": { "Indicators": { "category": { "url": "/hx/api/v3/indicator\_categories/custom", "\_id": 2, "uri\_name": "Custom", "name": "Custom", "share\_mode": "unrestricted" }, "display\_name": null, "description": "", "create\_actor": { "username": "admin", "\_id": 1000 }, "platforms": [ "win", "osx" ], "url": "/hx/api/v3/indicators/custom/txt", "\_revision": "20180501131901519705101701", "update\_actor": { "username": "admin", "\_id": 1000 }, "create\_text": null, "created\_by": "admin", "active\_since": "2018-05-01T13:19:01.519Z", "meta": null, "signature": null, "stats": { "active\_conditions": 2, "alerted\_agents": 0, "source\_alerts": 0 }, "\_id": "00807331-8982-4e27-94f0-abe873f88366", "uri\_name": "txt", "name": "txt" }, "Conditions": [ { "tests": [ { "operator": "equal", "token": "ipv4NetworkEvent/remoteIP", "type": "text", "value": "^^^8.8.8.8^^^" } ], "event\_type": "ipv4NetworkEvent", "url": "/hx/api/v3/conditions/G7fmpVr1gxFU2JKXUIu2Cg", "enabled": true, "\_id": "G7fmpVr1gxFU2JKXUIu2Cg==", "is\_private": false, "uuid": "1bb7e6a5-5af5-4311-94d8-9297508bb60a" }, { "tests": [ { "operator": "equal", "token": "dnsLookupEvent/hostname", "type": "text", "value": "google.com" } ], "event\_type": "dnsLookupEvent", "url": "/hx/api/v3/conditions/vCc2bJosTJdxrhkqvanEFw", "enabled": true, "\_id": "vCc2bJosTJdxrhkqvanEFw==", "is\_private": false, "uuid": "bc27366c-9a2c-4c97-b1ae-192abda9c417" } ] } }   

 ### 8. Find hostname correlated with agent-ID or agent-ID correlated with hostname

  Returns agent-ID for specified hostname, or hostname for specified agent-ID.

 ##### Base Command

 fireeye-hx-get-host-information

 ##### Input

    **Argument Name** **Description** **Required**     agentId The agent ID. If the agent ID is not specified, the host Name must be specified. Optional   hostName The host name. If the host name is not specified, the agent ID must be specified. Optional    ##### 

 ##### Context Output

    **Path** **Description**     FireEyeHX.Hosts.\_id FireEye HX Agent ID   FireEyeHX.Hosts.agent\_version The agent version   FireEyeHX.Hosts.excluded\_from\_containment Determines whether the host is excluded from containment   FireEyeHX.Hosts.containment\_missing\_software Boolean value to indicate for containment missing software   FireEyeHX.Hosts.containment\_queued Determines whether the host is queued for containment   FireEyeHX.Hosts.containment\_state The containment state of the host. Possible values normal   FireEyeHX.Hosts.stats.alerting\_conditions The number of conditions that have alerted for the host   FireEyeHX.Hosts.stats.alerts Total number of alerts, including exploit-detection alerts   FireEyeHX.Hosts.stats.exploit\_blocks The number of blocked exploits on the host   FireEyeHX.Hosts.stats.malware\_alerts The number of malware alerts associated with the host   FireEyeHX.Hosts.hostname The host name   FireEyeHX.Hosts.domain Domain name   FireEyeHX.Hosts.timezone Host time zone   FireEyeHX.Hosts.primary\_ip\_address The host IP address   FireEyeHX.Hosts.last\_poll\_timestamp The timestamp of the last system poll performed on the host   FireEyeHX.Hosts.initial\_agent\_checkin Timestamp of the initial agent check-in   FireEyeHX.Hosts.last\_alert\_timestamp The time stamp of the last alert for the host   FireEyeHX.Hosts.last\_exploit\_block\_timestamp Time when the last exploit was blocked on the host. The value is null if no exploits have been blocked.   FireEyeHX.Hosts.os.product\_name Specific operating system   FireEyeHX.Hosts.os.bitness OS Bitness (32 or 64)   FireEyeHX.Hosts.os.platform  OS families

  * win
 * osx
 * linux
     FireEyeHX.Hosts.primary\_mac The host MAC address    ##### 

 ##### Command Example

 !fireeye-hx-get-host-information hostName=”DESKTOP-XXX”

 ##### Context Example

  { "FireEyeHX": { "Hosts": { "last\_alert": { "url": "/hx/api/v3/alerts/5", "\_id": 5 }, "domain": "DEMISTO", "last\_exploit\_block\_timestamp": null, "containment\_state": "normal", "timezone": "Eastern Daylight Time", "gmt\_offset\_seconds": -14400, "initial\_agent\_checkin": "2018-03-26T14:21:31.273Z", "stats": { "alerting\_conditions": 1, "exploit\_alerts": 0, "acqs": 11, "malware\_false\_positive\_alerts": 0, "alerts": 1, "exploit\_blocks": 0, "malware\_cleaned\_count": 0, "malware\_alerts": 0, "malware\_quarantined\_count": 0 }, "primary\_mac": "XX-XX-XX-XX-XX-XX", "hostname": "DESKTOP-XXX", "primary\_ip\_address": "^^^XX.XX.XX.XX^^^", "last\_audit\_timestamp": "2018-05-03T13:59:23.000Z", "last\_alert\_timestamp": "2018-04-16T08:59:51.693+00:00", "containment\_queued": false, "sysinfo": { "url": "/hx/api/v3/hosts/uGvnGVpZkDSFySf2ZOiT/sysinfo" }, "last\_exploit\_block": null, "reported\_clone": false, "url": "/hx/api/v3/hosts/uGvnGVpZkeySf2ZOiT", "excluded\_from\_containment": false, "last\_poll\_timestamp": "2018-05-03T14:01:22.000Z", "last\_poll\_ip": "^^^XX.XX.XX.XX^^^", "containment\_missing\_software": false, "\_id": " uGvnGVpZkDSFySf2ZOiT ", "os": { "kernel\_version": null, "platform": "win", "patch\_level": null, "bitness": "64-bit", "product\_name": "Windows 10 Enterprise Evaluation" }, "agent\_version": "26.21.10" } }, "Endpoint": { "MACAddress": "XX-XX-XX-XX-XX-XX", "Domain": "DEMISTO", "IPAddress": "^^^XX.XX.XX.XX^^^", "Hostname": "DESKTOP-XXX", "OSVersion": "Windows 10 Enterprise Evaluation", "OS": "win", "ID": " uGvnGVpZkDSFySf2ZOiT " }, }   

 ### 9. Acquire file

  Acquires a specific file as a password protected zip file.

 Command Limitations

  * Acquisitions are stored for 14 days or until the aggregate size of all acquisitions exceeds the acquisition space limit, which is from 30 GB to 9 TB, depending on the HX Series appliance**.** 
 * When the acquisition space is completely full and automatic triages fill 10 percent of the acquisition space, the HX Series appliance reclaims disk space by removing automatic triage collections.
 * When the acquisition space is 90 percent full, no new acquisitions can be created, and bulk acquisitions that are running might be canceled**.** 
  ##### Base Command

 fireeye-hx-file-acquisition

 ##### Input

    **Argument Name** **Description** **Required**     fileName The file name Required   filePath The file path Required   acquireUsing Whether to aqcuire the file using the API or RAW. By default, raw file will be acquired. Use API option when file is encrypted. Optional   agentId The agent ID associated with the host that holds the file. If the hostName is not specified, the agentId must be specified. Optional   hostName The host that holds the file. If the agentId is not specified, hostName must be specified. Optional    ##### 

 ##### Context Output

    **Path** **Description**     FireEyeHX.Acquisitions.Files.\_id The acquisition unique ID   FireEyeHX.Acquisitions.Files.state The acquisition state   FireEyeHX.Acquisitions.Files.md5 File MD5   FireEyeHX.Acquisitions.Files.req\_filename The file name   FireEyeHX.Acquisitions.Files.req\_path The file path   FireEyeHX.Acquisitions.Files.host.\_id FireEye HX agent ID    ##### 

 ##### Command Example

 !fireeye-hx-file-acquisition fileName="test.txt"filePath="C:\\Users\\user\\Documents" hostName="DESKTOP-DES01" 

 ##### Raw Output

  "FireEyeHX": { "Acquisitions": { "Files": { "\_id": 13, "\_revision": "206073441021688", "alert": null, "comment": null, "condition": null, "error\_message": "The acquisition completed with issues.", "external\_id": null, "finish\_time": "2018-04-26T07:34:14.100Z", "host": { "\_id": "uGvnGVpZkKeySf2ZT", "url": "/hx/api/v3/hosts/ uGvnGVpZkKeySf2ZT " }, "indicator": null, "md5": "ee26908bf9…64b37da4754a", "req\_filename": "ex.txt", "req\_path": "C:\\Users\\user\\Documents", "req\_use\_api": null, "request\_actor": { "\_id": 1001, "username": "api" }, "request\_time": "2018-04-26T07:33:03.000Z", "state": "COMPLETE", "url": "/hx/api/v3/acqs/files/13", "zip\_passphrase": "unzip-me" } } }   

 ### 10. Delete file acquisition

  Deletes the file acquisition, by acquisition ID.

 ##### Base Command

 fireeye-hx-delete-file-acquisition

 ##### Input

    **Argument Name** **Description** **Required**   acquisitionId  The acquisition ID Required     

 ##### Context Output

 There is no context output.

 ##### Command Example

 !fireeye-hx-delete-file-acquisition acquisitionId=10

  

 ### 11. Acquire data

  Initiate a data acquisition process that gathers artifacts from the system disk and memory. The data is fetched as a MANS file.

 **Limitations**

  * Acquisitions are stored for 14 days or until the aggregate size of all acquisitions exceeds the acquisition space limit, which is from 30 GB to 9 TB, depending on the HX Series appliance**.** 
 * When the acquisition space is completely full and automatic triages fill 10 percent of the acquisition space, the HX Series appliance reclaims disk space by removing automatic triage collections.
 * When the acquisition space is 90 percent full, no new acquisitions can be created, and bulk acquisitions that are running might be canceled**.** 
  ##### Base Command

 fireeye-hx-data-acquisition

 ##### Input

    **Argument Name** **Description** **Required**     script Acquisition script in JSON format Optional   scriptName The script name. If the Acquisition script is specified, you must also specify the script name. Optional   defaultSystemScript Use default script. Select the host system. Optional   agentId The agent ID. If the host name is not specified, the agent ID must be specified. Optional   hostName The host name. If the agent ID is not specified, the host name must be specified. Optional    ##### 

 ##### Context Output

    **Path** **Description**     FireEyeHX.Acquisitions.Data.\_id The acquisition unique ID   FireEyeHX.Acquisitions.Data.state The acquisition state   FireEyeHX.Acquisitions.Data.md5 File MD5   FireEyeHX.Acquisitions.Data.host.\_id Time that the acquisition completed    ##### 

 ##### Command Example

 ! fireeye-hx-data-acquisition hostName="DESKTOP-DES01" defaultSystemScript=win

 ##### Raw Output

 { "FireEyeHX": { "Acquisitions": { "Data": { "comment": null, "zip\_passphrase": null, "request\_actor": { "username": "api", "\_id": 1001 }, "name": "test", "script": { "download": "/hx/api/v3/scripts/131ab1da5086fe09f5a210437de366007867fa26.json", "url": "/hx/api/v3/scripts/^^^131ab1da5086fe09f5a210437de366007867fa26^^^", "\_id": "^^^131ab1da5086fe09f5a210437de366007867fa26^^^" }, "finish\_time": "2018-05-15T11:58:18.541Z", "\_revision": "20180515115818542250101787", "error\_message": "The triage completed with issues.", "state": "COMPLETE", "request\_time": "2018-05-15T11:57:22.000Z", "url": "/hx/api/v3/acqs/live/28", "host": { "url": "/hx/api/v3/hosts/uGvnGVpZkM4bKeySf2ZOiT", "\_id": "uGvnGVpZkXXXX2ZOiT" }, "download": "/hx/api/v3/acqs/live/28.mans", "\_id": 28, "external\_id": null, "md5": null } } }, "File": { "Info": "mans", "SHA1": "^^^4374d09a27ef85XXXXX66785c040d7febff7d8^^^", "Name": "agent\_uGvnGVpZkMXXXX2ZOiT\_data.mans", "Extension": "mans", "Size": 5154, "EntryID": "383@1", "SSDeep": "96:JraN9hyFIVls4Dst99i462teLuf0XXXXyU2y46Gd/pV:xapyFIVibPi462teLuf0TXdLNJLU23dt", "SHA256": "7944d5e86ce2bXXXXe154d4c2923ddf47016a07b84b460f08b0f2f", "Type": "Zip archive data, at least v2.0 to extract\n", "MD5": "^^^c24a2c4aeXXXXf89e1e012dae^^^" } }   

 ### 12. Delete data acquisition

  Deletes data acquisition, by acquisition ID.

 ##### Base Command

 fireeye-hx-delete-data-acquisition

 ##### Input

    **Input Parameter** **Description** **Required**    acquisitionId

   The acquisition ID Required     

 ##### Context Output

 There is no context output for this command.

 ##### Command Example

 !fireeye-hx-delete-data-acquisition acquisitionId=10

  

  

 Error Responses - Timeout Error
-------------------------------

 **Timeout error** indicates that time limitation for the command has exceeded before results are returned.

 To resolve this issue, configure new time limitation for the command.

  

  2. Navigate to **Settings** > **About** > **Troubleshooting** > **Server Configuration**.
 4. click **Add Server Configuration**.
 6. Set the **key** field using this format: FireEye HX.<*command-name*>.timeout.
 8. Set the **value** field to the desired time limit for the command to run (in minutes).
  ![](https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/FireEyeHX_mceclip0.png)

  

 Known Limitations
-----------------

 ### Acquisitions limitations

  * Acquisitions are stored for 14 days or until the aggregate size of all acquisitions exceeds the acquisition space limit, which is from 30 GB to 9 TB, depending on the HX Series appliance**.** 
 * When the acquisition space is completely full and automatic triages fill 10 percent of the acquisition space, the HX Series appliance reclaims disk space by removing automatic triage collections.
 * When the acquisition space is 90 percent full, no new acquisitions can be created, and bulk acquisitions that are running might be canceled**.** 
  ### Containment Limitations

  * Some hosts cannot be contained.
 * The time it takes to contain a host varies, based on factors such as agent connectivity, network traffic, and other jobs running in your environment.
 * You can only contain a host if the agent package for that host is available on the HX Series appliance.
   

 Command Timeout
---------------

 The following commands have high potential to exceed the default time limit for a running command. To avoid command timeout, change the command timeout settings.

  * fireeye-hx-search
 * fireeye-hx-data-acquisition
 * fireeye-hx-file-acquisition
  ### Configure Command Timeout

  2. Navigate to **Settings** > **About** > **Troubleshooting**.
 4. In the **Server Configuration** section, click **Add Server Configuration**.
 6. Set the ***K****ey***’ field using this format: FireEye HX.timeout
 8. Set the ***Value*** field to the timeout you need (in minutes).
  