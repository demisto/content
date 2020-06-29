Infocyte can pivot off incidents to automate triage, validate events with forensic data and enabling dynamic response actions against any or all host using both agentless or agented endpoint access.
This integration was integrated and tested with version 3008.0.1.2800 of Infocyte
## Configure Infocyte on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Infocyte.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| InstanceName | Instance Name. You can find this in your Infocyte url: <pre>https://*InstanceName*.infocyte.com</pre> | True |
| APIKey | API Key | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| max_fetch | Maximum number of incidents per fetch | False |
| first_fetch | Initial fetch time in days | False |
| insecure | Trust any certificate -- not secure | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### infocyte-scan-host
***
Kicks off a Scan (forensic collection) against an endpoint


#### Base Command

`infocyte-scan-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Hostname or ip address of target endpoint | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Task.userTaskId | string | Task id used with infocyte\-get\-taskstatus. This id is returned from any async command/task. |
| Infocyte.Task.type | string | Task type (SCAN or RESPONSE) |
| Infocyte.Task.target | string | Hostname or ip of target provided |


#### Command Example
```!infocyte-scan-host target="pegasusactual"```

#### Context Example
```
{
    "Infocyte": {
        "Task": {
            "host": "pegasusactual",
            "type": "SCAN",
            "userTaskId": "28854b93-8f26-43fa-afd9-69450755916a"
        }
    }
}
```

#### Human Readable Output

type | userTaskId                           | host
---- | ------------------------------------ | -------------
SCAN | 28854b93-8f26-43fa-afd9-69450755916a | pegasusactual

### infocyte-isolate-host
***
Isolates a host to only communicate to Infocyte and other security tools


#### Base Command

`infocyte-isolate-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Hostname or ip address of target endpoint | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Task.userTaskId | string | Task id used with taskstatus |
| Infocyte.Task.type | string | Task type (SCAN or RESPONSE) |
| Infocyte.Task.target | string | Hostname or ip of target provided |
| Infocyte.Task.extensionName | string | Name of extension ran |


#### Command Example
```!infocyte-isolate-host target="pegasusactual"```

#### Context Example
```
{
    "Infocyte": {
        "Task": {
            "extensionName": "Host Isolation",
            "target": "pegasusactual",
            "type": "RESPONSE",
            "userTaskId": "e4eac99b-ef71-46ec-8b51-bea5cd5caa35"
        }
    }
}
```

#### Human Readable Output

type     | userTaskId                           | extensionName  | target
-------- | ------------------------------------ | -------------- | -------------
RESPONSE | e4eac99b-ef71-46ec-8b51-bea5cd5caa35 | Host Isolation | pegasusactual

### infocyte-restore-host
***
Restore an isolated host


#### Base Command

`infocyte-restore-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Hostname or ip address of target endpoint | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Task.userTaskId | string | Task id used with infocyte\-get\-taskstatus. This id is returned from any async command/task. |
| Infocyte.Task.type | string | Task type (SCAN or RESPONSE) |
| Infocyte.Task.target | string | Hostname or ip of target provided |
| Infocyte.Task.extensionName | string | Name of extension ran |


#### Command Example
```!infocyte-restore-host target="pegasusactual"```

#### Context Example
```
{
    "Infocyte": {
        "Task": {
            "extensionName": "Host Isolation Restore",
            "target": "pegasusactual",
            "type": "RESPONSE",
            "userTaskId": "e95eae57-2fee-4f79-9c2c-723ed035723d"
        }
    }
}
```

#### Human Readable Output

type     | userTaskId                           | extensionName          | target
-------- | ------------------------------------ | ---------------------- | -------------
RESPONSE | e95eae57-2fee-4f79-9c2c-723ed035723d | Host Isolation Restore | pegasusactual


### infocyte-kill-process
***
Kills a process on target endpoint


#### Base Command

`infocyte-kill-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Hostname or ip address of target endpoint | Required | 
| processName | Name of process to search for and kill on target endpoint | Optional | 
| sha1 | SHA1 of process image to search for and kill | Optional | 
| processId | Pid of process to search for and kill on target endpoint | Optional | 
| processPath | Path of of process to search for and kill on target endpoint | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!infocyte-kill-process target="pegasusactual"```

#### Context Example
```
{
    "Infocyte": {
        "Task": {
            "extensionName": "Terminate Process",
            "target": "pegasusactual",
            "type": "RESPONSE",
            "userTaskId": "3f0e5549-c7e3-42fb-8fa3-5adbeba733c5"
        }
    }
}
```

#### Human Readable Output

type     | userTaskId                           | extensionName     | target
-------- | ------------------------------------ | ----------------- | -------------
RESPONSE | 3f0e5549-c7e3-42fb-8fa3-5adbeba733c5 | Terminate Process | pegasusactual


### infocyte-run-response
***
Runs the named Infocyte extension on target host. Extensions are Infocyte script modules that run against a host or set of hosts to either collect additional data or perform a response action like killing a process or changing a configuration. Some Infocyte defined response actions are supported natively through prebuild XSOAR integrated commands like [infocyte-kill-process](#infocyte-kill-process).

You can find the available open sourced extensions here:
https://github.com/Infocyte/extensions

Extensions can be loaded into your instance here:
https://\<_instancename_\>.infocyte.com/admin/extensions/list


#### Base Command

`infocyte-run-response`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Hostname or ip address of target endpoint | Required | 
| extensionName | Name of extension loaded in Infocyte to run on target host | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Task.userTaskId | string | Task id used with infocyte\-get\-taskstatus. This id is returned from any async command/task. |
| Infocyte.Task.type | string | Task type (SCAN or RESPONSE) |
| Infocyte.Task.target | string | Hostname or ip of target provided |
| Infocyte.Task.extensionName | string | Name of extension ran |


#### Command Example
```!infocyte-run-response target="pegasusactual" extensionName="Yara Scanner"```

#### Context Example
```
{
    "Infocyte": {
        "Task": {
            "extensionName": "Yara Scanner",
            "target": "pegasusactual",
            "type": "RESPONSE",
            "userTaskId": "d5213898-7538-4ee6-bbd8-4979420ae234"
        }
    }
}
```

#### Human Readable Output

**type**     | **userTaskId** | **extensionName** | **target**
--- | --- | --- | ---
RESPONSE | d5213898-7538-4ee6-bbd8-4979420ae234 | Yara Scanner  | pegasusactual


### infocyte-get-taskstatus
***
Gets status of an Infocyte task (scan, response action, etc.)


#### Base Command

`infocyte-get-taskstatus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userTaskId | Task id used with infocyte-get-taskstatus. This id is returned from any async command/task. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Task.userTaskId | string | Task id used with infocyte\-get\-taskstatus. This id is returned from any async command/task. | 
| Infocyte.Scan.scanId | string | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte\-get\-taskstatus and is present in all job\-based data schemas. | 
| Infocyte.Task.type | string | Task type (SCAN or RESPONSE) | 
| Infocyte.Task.progress | number | Percent completed | 
| Infocyte.Task.message | string | Message regarding the current status | 
| Infocyte.Task.status | string | Current status of task (created, active, completed, cancelled, failed) | 
| Infocyte.Task.timeElapsed | number | Seconds since task created | 


#### Command Example
```!infocyte-get-taskstatus userTaskId="873ea61b-1705-49e6-87a5-57db12369ea1"```

#### Context Example
```
{
    "Infocyte": {
        "Task": {
            "message": "Complete",
            "progress": 100,
            "scanId": "27673898-f615-484c-9731-6526192aff21",
            "status": "Completed",
            "timeElapsed": 396,
            "type": "RESPONSE",
            "userTaskId": "873ea61b-1705-49e6-87a5-57db12369ea1"
        }
    }
}
```

#### Human Readable Output

timeElapsed | userTaskId | type | status | scanId | message  | progress
----------- | ------------------------------------ | -------- | --------- | ------------------------------------ | -------- | --------
 396 | 873ea61b-1705-49e6-87a5-57db12369ea1 | RESPONSE | Completed | 27673898-f615-484c-9731-6526192aff21 | Complete | 100

### infocyte-get-scanresult
***
Retrieve metadata and results for a scan against multiple hosts


#### Base Command

`infocyte-get-scanresult`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte-get-taskstatus and is present in all job-based data schemas | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Scan.scanId | string | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte\-get\-taskstatus and is present in all job\-based data schemas | 
| Infocyte.Scan.completedOn | date | Time scan was completed on target | 
| Infocyte.Scan.alertCount | number | number of alerts associated with scan of host | 
| Infocyte.Scan.compromisedObjects | number | Bad files, artifacts, and events found | 
| Infocyte.Scan.objectCount | number | Total files, artifacts, and events collected | 
| Infocyte.Scan.Host.hostname | string | Hostname | 
| Infocyte.Scan.Host.ip | string | IP Address of Host | 
| Infocyte.Scan.Host.osVersion | string | Operating system of host | 
| Infocyte.Scan.Alert.id | string | Infocyte alertId | 
| Infocyte.Scan.Alert.name | string | Name of alerted file or alert | 
| Infocyte.Scan.Alert.type | string | Type of object or artifact (process, module, artifact, autostart, script, etc.) | 
| Infocyte.Scan.Alert.threatName | string | Threat category assigned by extension logic (Good, Low risk, Unknown, Suspicious, Bad) | 
| Infocyte.Scan.Alert.threatScore | number | 0\-10 confidence score. Higher = more confident. | 
| Infocyte.Scan.Alert.avPositive | number | Number of engines and threat intel sources flagging the object as bad | 
| Infocyte.Scan.Alert.avTotal | number | Number of engines and threat intel sources that analyzed the object | 
| Infocyte.Scan.Alert.synapseScore | number | Infocyte proprietary machine learning score on maliciousness. Negative (especially below \-1) indicates backdoor or remote access tool features (generally bad), positive is good | 
| Infocyte.Scan.Alert.size | number | Size of object/file in bytes | 
| Infocyte.Scan.Alert.flagname | string | Name of user assigned flag in Infocyte on this artifact | 
| Infocyte.Scan.Alert.flagWeight | number | 0\-10 user\-assigned score assigned to the flag. Higher = more critical | 
| Infocyte.Scan.Alert.hostname | string | Hostname of target host | 
| Infocyte.Scan.Alert.sha1 | string | Sha1 (fileRepId) of file | 


#### Command Example
```!infocyte-get-scanresult scanId="27673898-f615-484c-9731-6526192aff21"```

#### Context Example
```
{
    "Infocyte": {
        "Scan": {
            "Alert": {},
            "Host": {
                "hostname": "pegasusactual",
                "ip": "192.168.x.x",
                "osVersion": "Windows 10 Pro 2004 Professional 64-bit"
            },
            "alertCount": 0,
            "completeOn": "2020-06-04T12:50:57.532Z",
            "compromisedObjects": 0,
            "hostCount": 1,
            "objectCount": 223,
            "scanId": "27673898-f615-484c-9731-6526192aff21"
        }
    }
}
```

#### Human Readable Output

compromisedObjects | alertCount | scanId                               | objectCount | completeOn         | hostCount
------------------ | ---------- | ------------------------------------ | ----------- | ------------------ | ---------
0 | 0 | 27673898-f615-484c-9731-6526192aff21 | 223 | 6/4/20 12:50:57 PM | 1


#### Hosts
hostname | ip | osVersion
--- | --- | ---
pegasusactual | 192.168.x.x | Windows 10 Pro 2004 Professional 64-bit

### infocyte-get-hostscanresult
***
Retrieve results for a scan on a target host


#### Base Command

`infocyte-get-hostscanresult`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte-get-taskstatus and is present in all job-based data schemas | Required | 
| target | Hostname or ip address of target endpoint | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Scan.scanId | string | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte\-get\-taskstatus and is present in all job\-based data schemas | 
| Infocyte.Scan.hostId | string | Infocyte Id assigned to the target host | 
| Infocyte.Scan.os | string | Operating system of the target host | 
| Infocyte.Scan.compromised | boolean | Flagged if system has a malicious item found | 
| Infocyte.Scan.alertCount | number | number of alerts associated with scan of host | 
| Infocyte.Scan.hostname | string | Hostname of target host | 
| Infocyte.Scan.ip | string | Ip of target host | 
| Infocyte.Scan.compromisedObjects | number | Bad files, artifacts, and events found | 
| Infocyte.Scan.objectCount | number | Total number of files, artifacts, and events inspected or retrieved | 
| Infocyte.Scan.Alert.id | string | Infocyte alertId | 
| Infocyte.Scan.Alert.name | string | Name of alerted file or alert | 
| Infocyte.Scan.Alert.type | string | Type of object or artifact (process, module, artifact, autostart, script, etc.) | 
| Infocyte.Scan.Alert.threatName | string | Threat category assigned by extension logic (Good, Low risk, Unknown, Suspicious, Bad) | 
| Infocyte.Scan.Alert.threatScore | number | 0\-10 confidence score. Higher = more confident. | 
| Infocyte.Scan.Alert.avPositive | number | Number of engines and threat intel sources flagging the object as bad | 
| Infocyte.Scan.Alert.avTotal | number | Number of engines and threat intel sources that analyzed the object | 
| Infocyte.Scan.Alert.synapseScore | number | Infocyte proprietary machine learning score on maliciousness. Negative (especially below \-1) indicates backdoor or remote access tool features (generally bad), positive is good | 
| Infocyte.Scan.Alert.size | number | Size of object/file in bytes | 
| Infocyte.Scan.Alert.flagname | string | Name of user assigned flag in Infocyte on this artifact | 
| Infocyte.Scan.Alert.flagWeight | number | 0\-10 user\-assigned score assigned to the flag. Higher = more critical | 
| Infocyte.Scan.Alert.sha1 | string | Sha1 (fileRepId) of file | 


#### Command Example
```!infocyte-get-hostscanresult scanId="27673898-f615-484c-9731-6526192aff21" target="pegasusactual"```

#### Context Example
```
{
    "Infocyte": {
        "Scan": {
            "Alert": {},
            "alertCount": 0,
            "completedOn": "2020-06-04T12:50:24.674Z",
            "compromised": false,
            "hostId": "558feacbbae80c63d54ec1252ac34bdc285b20a7",
            "hostname": "pegasusactual",
            "ip": "192.168.x.x",
            "os": null,
            "scanId": "27673898-f615-484c-9731-6526192aff21",
            "success": true
        }
    }
}
```

#### Human Readable Output

success | hostId                                   | ip            | alertCount | scanId                               | compromised | completedOn        | hostname
------- | ---------------------------------------- | ------------- | ---------- | ------------------------------------ | ----------- | ------------------ | -------------
True    | 558feacbbae80c63d54ec1252ac34bdc285b20a7 | 192.168.x.x | 0          | 27673898-f615-484c-9731-6526192aff21 | False       | 6/4/20 12:50:24 PM | pegasusactual
  

### infocyte-get-responseresult
***
Gets the results of a response action.


#### Base Command

`infocyte-get-responseresult`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte-get-taskstatus and is present in all job-based data schemas | Required | 
| target | Hostname or ip address of target endpoint | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Response.scanId | string | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte\-get\-taskstatus and is present in all job\-based data schemas | 
| Infocyte.Response.hostId | string | Infocyte Id assigned to the target host | 
| Infocyte.Response.os | string | Operating system of the target host | 
| Infocyte.Response.success | boolean | Flag if extention successfully ran and completed (not necessarily if it performed everything correctly) | 
| Infocyte.Response.threatStatus | string | Threat category assigned by extension logic (Good, Low risk, Unknown, Suspicious, Bad) | 
| Infocyte.Response.compromised | boolean | Flagged if system has a malicious item found | 
| Infocyte.Response.completedOn | date | Datetime stamp that action completed | 
| Infocyte.Response.messages | string | Logs of the response action taking place on the target endpoint | 
| Infocyte.Response.hostname | string | Hostname of target host | 
| Infocyte.Response.ip | string | Ip of target host | 
| Infocyte.Response.extensionId | string | Id of Infocyte extension being run | 
| Infocyte.Response.extensionName | string | Name of Infocyte extension being run | 


#### Command Example
```!infocyte-get-responseresult scanId="27673898-f615-484c-9731-6526192aff21"```

#### Context Example
```
{
  "Infocyte.Response": {
    "completedOn": "2020-06-04T12:50:24.674Z",
    "compromised": false,
    "extensionId": "2ffd753a-ba60-4414-8991-52aa54615e73",
    "extensionName": "Terminate Process",
    "hostId": "558feacbbae80c63d54ec1252ac34bdc285b20a7",
    "hostname": "pegasusactual",
    "ip": "192.168.x.x",
    "messages": [
      "Finding and killing processes that match the following search terms (name, path, or pid):\nTerm[1]: C:\\windows\\system32\\calc.exe\nTerm[2]: 17604\nTerm[3]: calculator",
      "Killed calculator.exe [pid: 40396] with image path: c:\\program files\\windowsapps\\microsoft.windowscalculator_10.2002.13.0_x64__8wekyb3d8bbwe\\calculator.exe",
      "Killed 1 processes."
    ],
    "os": "Windows 10 Pro 2004 Professional 64-bit",
    "scanId": "27673898-f615-484c-9731-6526192aff21",
    "success": true,
    "threatStatus": "Good"
  }
}
```

#### Human Readable Output

success | os                                      | ip            | threatStatus | completedOn        | extensionName     | hostname
------- | --------------------------------------- | ------------- | ------------ | ------------------ | ----------------- | -------------
True    | Windows 10 Pro 2004 Professional 64-bit | 192.168.x.x | Good         | 6/4/20 12:50:24 PM | Terminate Process | pegasusactual

##### Messages
Finding and killing processes that match the following search terms (name, path, or pid):
Term[1]: C:\\windows\\system32\\calc.exe
Term[2]: 17604
Term[3]: calculator
Killed calculator.exe [pid: 40396] with image path: c:\\program files\\windowsapps\\microsoft.windowscalculator_10.2002.13.0_x64__8wekyb3d8bbwe\\calculator.exe
Killed 1 processes.


### infocyte-get-alerts
***
Retrieve alert by alertId, since a lastAlertId, since LastRun (if no arguments provided)


#### Base Command

`infocyte-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | Infocyte alertId to look up | Optional | 
| lastAlertId | Last alertId to start fetching from | Optional | 
| max | Number of alerts to fetch | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Alert.id | string | Infocyte alertId | 
| Infocyte.Alert.scanId | string | Infocyte scanId the alert originated from | 
| Infocyte.Alert.name | string | Name of alerted file or alert | 
| Infocyte.Alert.type | string | Type of object or artifact (process, module, artifact, autostart, script, etc.) | 
| Infocyte.Alert.threatName | string | Threat category assigned by extension logic (Good, Low risk, Unknown, Suspicious, Bad) | 
| Infocyte.Alert.hasAvScan | boolean | True if it has been scanned by AV and/or sandbox malware engines | 
| Infocyte.Alert.threatScore | number | 0\-10 confidence score. Higher = more confident. | 
| Infocyte.Alert.avPositive | number | Number of engines and threat intel sources flagging the object as bad | 
| Infocyte.Alert.avTotal | number | Number of engines and threat intel sources that analyzed the object | 
| Infocyte.Alert.synapseScore | number | Infocyte proprietary machine learning score on maliciousness. Negative (especially below \-1) indicates backdoor or remote access tool features (generally bad), positive is good | 
| Infocyte.Alert.size | number | Size of object/file in bytes | 
| Infocyte.Alert.flagname | string | Name of user assigned flag in Infocyte on this artifact | 
| Infocyte.Alert.flagWeight | number | 0\-10 user\-assigned score assigned to the flag. Higher = more critical | 
| Infocyte.Alert.createdOn | date | Datetime stamp the alert | 
| Infocyte.Alert.hostname | string | Hostname of target host | 
| Infocyte.Alert.sha1 | string | Sha1 (fileRepId) of file | 
| Infocyte.Alert.signed | boolean | Valid and unexpired digital signature on file | 
| Infocyte.Alert.managed | boolean | File has been hash validated as part of a linux package manager | 


#### Command Example
```!infocyte-get-alerts alertId="d2e1499e-8b11-4300-9848-c1e97094834b"```

#### Context Example
```
{
    "Infocyte": {
        "Alert": [
            {
                "avPositives": 53,
                "avTotal": 66,
                "createdOn": "2020-05-28T05:57:18.404Z",
                "flagName": null,
                "flagWeight": null,
                "hasAvScan": true,
                "hostname": "pegasusactual",
                "id": "d2e1499e-8b11-4300-9848-c1e97094834b",
                "managed": null,
                "name": "mimikatz.exe",
                "scanId": "aeac5ff3-52e9-4073-b37f-a23cadd3c69e",
                "sha1": "4a45814547f237bbd96db61dec58c0e3fd5c7558",
                "signed": true,
                "size": "1255176",
                "synapseScore": null,
                "threatName": "Bad",
                "threatScore": 9,
                "threatWeight": 8,
                "type": "Artifact"
            }
        ]
    }
}
```

#### Human Readable Output

name         | threatName | sha1                                     | id                                   | type     | av    | size
------------ | ---------- | ---------------------------------------- | ------------------------------------ | -------- | ----- | -------
mimikatz.exe | Bad        | 4a45814547f237bbd96db61dec58c0e3fd5c7558 | d2e1499e-8b11-4300-9848-c1e97094834b | Artifact | 53/66 | 1255176
