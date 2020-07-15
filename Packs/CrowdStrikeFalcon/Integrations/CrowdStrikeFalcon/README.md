The CrowdStrike Falcon OAuth 2 API integration (formerly Falcon Firehose API), enables fetching and resolving detections, searching devices, getting behaviors by ID, containing hosts, and lifting host containment.

## Configure CrowdStrike Falcon on Demisto
1.  Navigate to **Settings** \> **Integrations** \> **Servers &
    Services**.
2.  Search for CrowdstrikeFalcon.
3.  Click **Add instance** to create and configure a new integration
    instance.
    -   **Name**: a textual name for the integration instance.
    -   **Server URL (e.g., https://api.crowdstrike.com)**
    -   **Client ID**
    -   **Secret**
    -   **First fetch timestamp ( , e.g., 12 hours, 7 days)**
    -   **Max incidents per fetch**
    -   **Fetch query**
    -   **Fetch incidents**
    -   **Incident type**
    -   **Trust any certificate (not secure)**
    -   **Use system proxy**

4.  Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### 1. Search for a device

---

Searches for devices that match the query.

##### Base Command

`cs-falcon-search-device`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Returns devices that match the query. | Optional
| ids | A CSV list of device IDs to limit by which to limit the results. | Optional
| status | Returns devices that match the specified status. | Optional
| hostname | Returns devices that match the specified hostname. | Optional
| platform_name | Returns devices that match the specified platform name. | Optional
| site_name | Returns devices that match the specified site name. | Optional

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
  CrowdStrike.Device.ID | String | The ID of the device.
  CrowdStrike.Device.LocalIP | String | The local IP address of the device.
  CrowdStrike.Device.ExternalIP | String | The external IP address of the device.
  CrowdStrike.Device.Hostname | String | The hostname of the device.
  CrowdStrike.Device.OS | String | The operating system of the device.
  CrowdStrike.Device.MacAddress | String | The Mac address of the device.
  CrowdStrike.Device.FirstSeen | String | The first seen time of the device.
  CrowdStrike.Device.LastSeen | String | The last seen time of the device.
  CrowdStrike.Device.PolicyType | String | The policy types of the device.

 

##### Command Example

`!cs-falcon-search-device ids=336474ea6a524e7c68575f6508d84781,459146dbe524472e73751a43c63324f3`

##### Context Example
```
    {
        "CrowdStrike.Device": [
            {
                "ExternalIP": "94.188.164.68", 
                "MacAddress": "8c-85-90-3d-ed-3e", 
                "Hostname": "154.132.82-test-co.in-addr.arpa", 
                "LocalIP": "192.168.1.76", 
                "LastSeen": "2019-03-28T02:36:41Z", 
                "OS": "Mojave (10.14)", 
                "ID": "336474ea6a524e7c68575f6508d84781", 
                "FirstSeen": "2017-12-28T22:38:11Z"
            }, 
            {
                "ExternalIP": "94.188.164.68", 
                "MacAddress": "f0-18-98-74-8c-31", 
                "Hostname": "154.132.82-test-co.in-addr.arpa", 
                "LocalIP": "172.22.14.237", 
                "LastSeen": "2019-03-17T10:03:17Z", 
                "OS": "Mojave (10.14)", 
                "ID": "459146dbe524472e73751a43c63324f3", 
                "FirstSeen": "2017-12-10T11:01:20Z"
            }
        ]
    }
```
##### Human Readable Output

### Devices

| ID | Hostname | OS | Mac Address | Local IP | External IP | First Seen | Last Seen |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 336474ea6a524e7c68575f6508d84781 | 154.132.82-test-co.in-addr.arpa | Mojave (10.14) | 8c-85-90-3d-ed-3e | 192.168.1.76 | 94.188.164.68 | 2017-12-28T22:38:11Z | 2019-03-28T02:36:41Z |
| 459146dbe524472e73751a43c63324f3 | 154.132.82-test-co.in-addr.arpa | Mojave (10.14) | f0-18-98-74-8c-31 | 172.22.14.237 | 94.188.164.68 | 2017-12-10T11:01:20Z | 2019-03-17T10:03:17Z |

 

### 2. Get a behavior

---
Searches for and fetches the behavior that matches the query.

##### Base Command

`cs-falcon-get-behavior`

##### Input

  | **Argument Name** | **Description** | **Required** |
  |---|---|---|
  behavior_id | The ID of the the behavior. | Required

 

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Behavior.FileName | String | The file name in the behavior. |
  CrowdStrike.Behavior.Scenario | String | The scenario name in the behavior.
  CrowdStrike.Behavior.MD5 | String | The MD5 hash of the IoC in the behavior.
  CrowdStrike.Behavior.SHA256 | String | The SHA256 hash of the IoC in the behavior.
  CrowdStrike.Behavior.IOCType | String | Type of the indicator of compromise.
  CrowdStrike.Behavior.IOCValue | String | The value of the IoC.
  CrowdStrike.Behavior.CommandLine | String | The command line executed in the behavior.
  CrowdStrike.Behavior.UserName | String | The user name related to the behavior.
  CrowdStrike.Behavior.SensorID | String | The sensor ID related to the behavior.
  CrowdStrike.Behavior.ParentProcessID | String | The ID of the parent process.
  CrowdStrike.Behavior.ProcessID | String | The process ID of the behavior.
  CrowdStrike.Behavior.ID | String | The ID of the behavior.

 

##### Command Example

`!cs-falcon-get-behavior behavior_id=3206`

##### Context Example
```
    {
        "CrowdStrike.Behavior": [
            {
                "IOCType": "sha256", 
                "ProcessID": "197949010450449117", 
                "Scenario": "known_malware", 
                "CommandLine": "/Library/spokeshave.jn/spokeshave.jn.app/Contents/MacOS/spokeshave.jn", 
                "UserName": "user@u-MacBook-Pro-2.local", 
                "FileName": "spokeshave.jn", 
                "SHA256": "df8896dbe70a16419103be954ef2cdbbb1cecd2a865df5a0a2847d9a9fe7a266", 
                "ID": "3206", 
                "IOCValue": "df8896dbe70a16419103be954ef2cdbbb1cecd2a865df5a0a2847d9a9fe7a266", 
                "MD5": "b41d753a4b61c9fe4486190c3b78e124"
            }, 
            {
                "IOCType": "sha256", 
                "ProcessID": "197949016741905142", 
                "Scenario": "known_malware", 
                "ParentProcessID": "197949014644753130", 
                "CommandLine": "./xSf", 
                "UserName": "root@u-MacBook-Pro-2.local", 
                "FileName": "xSf", 
                "SensorID": "68b5432856c1496d7547947fc7d1aae4", 
                "SHA256": "791d88ca295847bb6dd174e0ebad62f01f0cae56c157b7a11fd70bb457c97d9b", 
                "ID": "3206", 
                "IOCValue": "791d88ca295847bb6dd174e0ebad62f01f0cae56c157b7a11fd70bb457c97d9b", 
                "MD5": "06dc9ff1857dcd4cdcd125b277955134"
            }
        ]
    }
```
##### Human Readable Output

### Behavior ID: 3206

| ID | File Name | Command Line | Scenario | IOC Type | IOC Value | User Name | SHA256 | MD5 | Process ID | 
| ------ | --------------- | ----------------------------------------------------------------------- | ---------------- | ---------- | ------------------------------------------------------------------ | --------------------------------------- | ------------------------------------------------------------------ | ---------------------------------- | -------------------- |
| 3206 |   spokeshave.jn |  /Library/spokeshave.jn/spokeshave.jn.app/Contents/MacOS/spokeshave.jn |   known\_malware   | sha256 |    df8896dbe70a16419103be954ef2cdbbb1cecd2a865df5a0a2847d9a9fe7a266   | user@u-MacBook-Pro-2.local |   df8896dbe70a16419103be954ef2cdbbb1cecd2a865df5a0a2847d9a9fe7a266   | b41d753a4b61c9fe4486190c3b78e124|   197949010450449117|
|  3206   |xSf             |./xSf                                                                   |known\_malware   |sha256     |791d88ca295847bb6dd174e0ebad62f01f0cae56c157b7a11fd70bb457c97d9b|   root@u-MacBook-Pro-2.local|          791d88ca295847bb6dd174e0ebad62f01f0cae56c157b7a11fd70bb457c97d9b   |06dc9ff1857dcd4cdcd125b277955134   |197949016741905142|

 

### 3. Search for detections

---
Search for details of specific detections, either using a filter query,
or by providing the IDs of the detections.

##### Base Command

`cs-falcon-search-detection`

##### Input

  | **Argument Name** | **Description** | **Required** |
  |---|---|---|
  |ids|                 IDs of the detections to search. If provided, will override other arguments.|                                                                                                        Optional
  |filter              | Filter detections using a query in Falcon Query Language (FQL). e.g. filter="device.hostname:‘CS-SE-TG-W7-01’" For a full list of valid filter options, see the [CrowdStrike Falcon documentation](https://falcon.crowdstrike.com/support/documentation/2/query-api-reference#detectionsearch). | Optional

 

##### Context Output

 | **Path** | **Type** | **Description** |
| --- | --- | --- |
  |CrowdStrike.Detection.Behavior.FileName          |String|     The file name in the behavior.
  |CrowdStrike.Detection.Behavior.Scenario          |String|     The scenario name in the behavior.
|  CrowdStrike.Detection.Behavior.MD5               |String|     The MD5 hash of the IoC in the behavior.
 | CrowdStrike.Detection.Behavior.SHA256            |String|     The SHA256 hash of the IoC in the behavior.
  |CrowdStrike.Detection.Behavior.IOCType           |String|     The type of the IoC.
  |CrowdStrike.Detection.Behavior.IOCValue          |String|     The value of the IoC.
  |CrowdStrike.Detection.Behavior.CommandLine       |String|     The command line executed in the behavior.
  |CrowdStrike.Detection.Behavior.UserName          |String|     The user name related to the behavior.
  |CrowdStrike.Detection.Behavior.SensorID          |String|     The sensor ID related to the behavior.
  |CrowdStrike.Detection.Behavior.ParentProcessID   |String|     The ID of the parent process.
  |CrowdStrike.Detection.Behavior.ProcessID         |String|     The process ID of the behavior.
  |CrowdStrike.Detection.Behavior.ID                |String|     The ID of the behavior.
  |CrowdStrike.Detection.System                     |String|     The system name of the detection.
  |CrowdStrike.Detection.CustomerID                 |String|     The ID of the customer (CID).
  |CrowdStrike.Detection.MachineDomain              |String|     The name of the domain of the detection machine.
  |CrowdStrike.Detection.ID                         |String|     The detection ID.
  |CrowdStrike.Detection.ProcessStartTime           |Date|       The start time of the process that generated the detection.

 

##### Command Example

`!cs-falcon-search-detection ids=ldt:07893fedd2604bc66c3f7de8d1f537e3:1898376850347,ldt:68b5432856c1496d7547947fc7d1aae4:1092318056279064902`

##### Context Example
```
    {
        "CrowdStrike.Detection": [
            {
                "Status": "false_positive", 
                "ProcessStartTime": "2019-03-21T20:32:55.654489974Z", 
                "Behavior": [
                    {
                        "IOCType": "domain", 
                        "ProcessID": "2279170016592", 
                        "Scenario": "intel_detection", 
                        "ParentProcessID": "2257232915544", 
                        "CommandLine": "C:\\Python27\\pythonw.exe -c __import__('idlelib.run').run.main(True) 1250", 
                        "UserName": "josh", 
                        "FileName": "pythonw.exe", 
                        "SensorID": "07893fedd2604bc66c3f7de8d1f537e3", 
                        "SHA256": "d1e9361680c4b2112e2ed647d5b87b96e4e9e557e75353657b9ce1b1babc0805", 
                        "ID": "4900", 
                        "IOCValue": "systemlowcheck.com", 
                        "MD5": "8b162b81d4efc177a2719bb8d7dbe46a"
                    }, 
                    {
                        "IOCType": "domain", 
                        "ProcessID": "2283087267593", 
                        "Scenario": "intel_detection", 
                        "ParentProcessID": "2279170016592", 
                        "CommandLine": "ping.exe systemlowcheck.com", 
                        "UserName": "josh", 
                        "FileName": "PING.EXE", 
                        "SensorID": "07893fedd2604bc66c3f7de8d1f537e3", 
                        "SHA256": "7bf496d5b9f227cce033f204e21743008c3f4b081d44b02500eda4efbccf3281", 
                        "ID": "4900", 
                        "IOCValue": "systemlowcheck.com", 
                        "MD5": "70c24a306f768936563abdadb9ca9108"
                    }
                ], 
                "MaxSeverity": 70, 
                "System": "DESKTOP-S49VMIL", 
                "ID": "ldt:07893fedd2604bc66c3f7de8d1f537e3:1898376850347", 
                "MachineDomain": "", 
                "ShowInUi": true, 
                "CustomerID": "ed33ec93d2444d38abd3925803938a75"
            }, 
            {
                "Status": "new", 
                "ProcessStartTime": "2019-02-04T07:05:57.083205971Z", 
                "Behavior": [
                    {
                        "IOCType": "sha256", 
                        "ProcessID": "201917905370426448", 
                        "Scenario": "known_malware", 
                        "ParentProcessID": "201917902773103685", 
                        "CommandLine": "./xSf", 
                        "UserName": "user@u-MacBook-Pro-2.local", 
                        "FileName": "xSf", 
                        "SensorID": "68b5432856c1496d7547947fc7d1aae4", 
                        "SHA256": "791d88ca295847bb6dd174e0ebad62f01f0cae56c157b7a11fd70bb457c97d9b", 
                        "ID": "3206", 
                        "IOCValue": "791d88ca295847bb6dd174e0ebad62f01f0cae56c157b7a11fd70bb457c97d9b", 
                        "MD5": "06dc9ff1857dcd4cdcd125b277955134"
                    }, 
                    {
                        "IOCType": "sha256", 
                        "ProcessID": "201917905370426448", 
                        "Scenario": "known_malware", 
                        "ParentProcessID": "201917902773103685", 
                        "CommandLine": "./xSf", 
                        "UserName": "user@u-MacBook-Pro-2.local", 
                        "FileName": "xSf", 
                        "SensorID": "68b5432856c1496d7547947fc7d1aae4", 
                        "SHA256": "791d88ca295847bb6dd174e0ebad62f01f0cae56c157b7a11fd70bb457c97d9b", 
                        "ID": "3206", 
                        "IOCValue": "791d88ca295847bb6dd174e0ebad62f01f0cae56c157b7a11fd70bb457c97d9b", 
                        "MD5": "06dc9ff1857dcd4cdcd125b277955134"
                    }
                ], 
                "MaxSeverity": 30, 
                "System": "u-MacBook-Pro-2.local", 
                "ID": "ldt:68b5432856c1496d7547947fc7d1aae4:1092318056279064902", 
                "MachineDomain": "", 
                "ShowInUi": true, 
                "CustomerID": "ed33ec93d2444d38abd3925803938a75"
            }
        ]
    }
```
##### Human Readable Output

### Detections Found:

  |ID                                                         |Status|            System                 |     Process Start Time     |          Customer ID                       | Max Severity|
  |----------------------------------------------------------| ----------------- |--------------------------- |-------------------------------- |---------------------------------- |--------------|
  |ldt:07893fedd2604bc66c3f7de8d1f537e3:1898376850347       |  false\_positive |  DESKTOP-S49VMIL            | 2019-03-21T20:32:55.654489974Z  | ed33ec93d2444d38abd3925803938a75  | 70|
  |ldt:68b5432856c1496d7547947fc7d1aae4:1092318056279064902|   new             |  u-MacBook-Pro-2.local  | 2019-02-04T07:05:57.083205971Z  | ed33ec93d2444d38abd3925803938a75  | 30|

 

### 4. Resolve a detection

* * * * *

Resolves and updates a detection.

##### Base Command

`cs-falcon-resolve-detection`

##### Input

  | **Argument Name** | **Description** | **Required** |
  |---|---|---|
  |ids                  |A CSV list of one or more IDs to resolve.                 |Required
  |status               |The status to which you want to transition a detection.   |Optional
  |assigned\_to\_uuid   |A user ID, for example: 1234567891234567891.              |Optional
  |show\_in\_ui         |If set to true, will display the dectection in the UI.    |Optional

 

##### Context Output

There is no context output for this command.

### 5. Contain a host

* * * * *

Contains or lifts containment for a specified host. When contained, a
host can only communicate with the CrowdStrike cloud and any IPs
specified in your containment policy.

##### Base Command

`cs-falcon-contain-host`

##### Input

   | **Argument Name** | **Description** | **Required** |
  |---|---|---|
  ids    |             The host agent ID (AID) of the host to contain. Get an agent ID from a detection. |  Required

 

##### Context Output

There is no context output for this command.

### 6. Lift the containment for a host

* * * * *

Lifts containment from a host, which returns its network communications
to normal.

##### Base Command

`cs-falcon-lift-host-containment`

##### Input

  | **Argument Name** | **Description** | **Required** |
  |---|---|---|
  |ids            |     The host agent ID (AID) of the host you want to contain. Get an agent ID from a detection  | Required

 

##### Context Output

There is no context output for this command.


### 7. cs-falcon-run-command
---
Sends commands to hosts.
##### Base Command

`cs-falcon-run-command`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma separated list of host agent ID’s for which to run commands (can be retrieved by running cs-falcon-search-device command). | Required | 
| command_type | The command type to run. | Required | 
| full_command | The full command to run. | Required | 
| scope | The scope for which to run the command. | Optional | 



##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | string | The ID of the host for which the command was running. | 
| CrowdStrike.Command.Stdout | string | The standard output of the command. | 
| CrowdStrike.Command.Stderr | string | The standard error of the command. | 
| CrowdStrike.Command.BaseCommand | string | The base command. | 
| CrowdStrike.Command.FullCommand | string | The full command. | 


##### Command Example
`cs-falcon-run-command host_ids=284771ee197e422d5176d6634a62b934 command_type=ls full_command="ls C:\\"`

##### Context Example
```
{
    'CrowdStrike': {
        'Command': [{
            'HostID': '284771ee197e422d5176d6634a62b934',
            'Stdout': 'Directory listing for C:\\ -\n\n'
            'Name                                     Type         Size (bytes)    Size (MB)       '
            'Last Modified (UTC-5)     Created (UTC-5)          \n----                             '
            '        ----         ------------    ---------       ---------------------     -------'
            '--------          \n$Recycle.Bin                             <Directory>  --          '
            '    --              11/27/2018 10:54:44 AM    9/15/2017 3:33:40 AM     \nITAYDI       '
            '                            <Directory>  --              --              11/19/2018 1:'
            '31:42 PM     11/19/2018 1:31:42 PM    ',
            'Stderr': '',
            'BaseCommand': 'ls',
            'Command': 'ls C:\\'
        }]
}
```

##### Human Readable Output
### Command ls C:\\ results
|BaseCommand|Command|HostID|Stderr|Stdout|
|---|---|---|---|---|
| ls | ls C:\ | 284771ee197e422d5176d6634a62b934 |  | Directory listing for C:\ -<br/><br/>Name                                     Type         Size (bytes)    Size (MB)       Last Modified (UTC-5)     Created (UTC-5)          <br/>----                                     ----         ------------    ---------       ---------------------     ---------------          <br/>$Recycle.Bin                             &lt;Directory&gt;  --              --              11/27/2018 10:54:44 AM    9/15/2017 3:33:40 AM     <br/>ITAYDI                                   &lt;Directory&gt;  --              --              11/19/2018 1:31:42 PM     11/19/2018 1:31:42 PM     |

### 8. cs-falcon-upload-script
---
Uploads a script to Falcon.

##### Base Command
`cs-falcon-upload-script`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The script name to upload. | Required | 
| permission_type | The permission type for the custom script. Can be: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins. | Optional |
| content | The Contents of the PowerShell script. | Required |  


##### Command Example
`!cs-falcon-upload-script name=greatscript content="Write-Output 'Hello, World!'"`

##### Human Readable Output
The script was uploaded successfully.

### 9. cs-falcon-upload-file
---
Uploads a file to the CrowdStrike cloud (can be used for the RTR `put` command).

##### Base Command
`cs-falcon-upload-file`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The file entry ID to upload. | Required |  

##### Command Example
`!cs-falcon-upload-file entry_id=4@4`

##### Human Readable Output
The file was uploaded successfully.

### 10. cs-falcon-delete-file
---
Deletes a file based on the ID given. Can delete only one file at a time.

##### Base Command
`cs-falcon-delete-file`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The file ID to delete (can be retrieved by running cs-falcon-list-files command).| Required | 


##### Command Example
`!cs-falcon-delete-file file_id=le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a`

##### Human Readable Output
File le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a was deleted successfully.

### 11. cs-falcon-get-file
---
Returns files based on the IDs given. These are used for the RTR `put` command.

##### Base Command
`cs-falcon-get-file`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | A comma separated list of file IDs to get (can be retrieved by running cs-falcon-list-files command). | Required | 



##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.File.ID | string | The ID of the file. |
| CrowdStrike.File.CreatedBy | string | The email of the user who created the file. |
| CrowdStrike.File.CreatedTime | date | The creation date of the file. |
| CrowdStrike.File.Description | string | The description of the file. |
| CrowdStrike.File.Type | string | The type of the file. For example, script. |
| CrowdStrike.File.ModifiedBy | string | The email of the user who modified the file. |
| CrowdStrike.File.ModifiedTime | date | The modification date of the file. |
| CrowdStrike.File.Name | string | The full file name. |
| CrowdStrike.File.Permission | string | The permission type of the file. Can be: "public", "group" or "private". |
| CrowdStrike.File.SHA256 | string | The SHA-256 hash of the file. |
| File.Type | string | The file type |
| File.Name | string | The full file name. |
| File.SHA256 | string | The SHA-256 hash of the file. |
| File.Size | number | The size of the file in bytes. |

##### Command Example
`!cs-falcon-get-file file_id=le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a`

##### Context Example
```
{
    'CrowdStrike': {
        'File': [
            {
                'CreatedBy': 'spongobob@demisto.com',
                'CreatedTime': '2019-10-17T13:41:48.487520845Z',
                'Description': 'Demisto',
                'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
                'ModifiedBy': 'spongobob@demisto.com',
                'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
                'Name': 'Demisto',
                'Permission': 'private',
                'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
                'Type': 'script'
            }
        ]
}
```

##### Human Readable Output
### CrowdStrike Falcon file le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a
|CreatedBy|CreatedTime|Description|ID|ModifiedBy|ModifiedTime|Name|Permission|SHA256|Type|
|---|---|---|---|---|---|---|---|---|---|
| spongobob@demisto.com | 2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a | spongobob@demisto.com | 2019-10-17T13:41:48.487521161Z | Demisto | private | 5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc | script |

### 12. cs-falcon-list-files
---
Returns Returns a list of put-file ID's that are available for the user in the `put` command.

##### Base Command
`cs-falcon-list-files`

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.File.ID | string | The ID of the file. |
| CrowdStrike.File.CreatedBy | string | The email of the user who created the file. |
| CrowdStrike.File.CreatedTime | date | The creation date of the file. |
| CrowdStrike.File.Description | string | The description of the file. |
| CrowdStrike.File.Type | string | The type of the file. For example, script. |
| CrowdStrike.File.ModifiedBy | string | The email of the user who modified the file. |
| CrowdStrike.File.ModifiedTime | date | The modification date of the file. |
| CrowdStrike.File.Name | string | The full file name. |
| CrowdStrike.File.Permission | string | The permission type of the file. Can be: "public", "group" or "private". |
| CrowdStrike.File.SHA256 | string | The SHA-256 hash of the file. |
| File.Type | string | The file type |
| File.Name | string | The full file name. |
| File.SHA256 | string | The SHA-256 hash of the file. |
| File.Size | number | The size of the file in bytes. |

##### Command Example
`!cs-falcon-list-files`

##### Context Example
```
{
    'CrowdStrike': {
        'File': [
            {
                'CreatedBy': 'spongobob@demisto.com',
                'CreatedTime': '2019-10-17T13:41:48.487520845Z',
                'Description': 'Demisto',
                'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
                'ModifiedBy': 'spongobob@demisto.com',
                'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
                'Name': 'Demisto',
                'Permission': 'private',
                'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
                'Type': 'script'
            }
        ]
}
```

##### Human Readable Output
### CrowdStrike Falcon files
|CreatedBy|CreatedTime|Description|ID|ModifiedBy|ModifiedTime|Name|Permission|SHA256|Type|
|---|---|---|---|---|---|---|---|---|---|
| spongobob@demisto.com | 2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a | spongobob@demisto.com | 2019-10-17T13:41:48.487521161Z | Demisto | private | 5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc | script |

### 13. cs-falcon-get-script
---
Return custom scripts based on the ID. Used for the RTR `runscript` command.

##### Base Command
`cs-falcon-get-script`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | A comma separated list of script IDs to get (can be retrieved by running cs-falcon-list-scripts command). | Required | 



##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Script.ID | string | The ID of the script. |
| CrowdStrike.Script.CreatedBy | string | The email of the user who created the script. |
| CrowdStrike.Script.CreatedTime | date | The creation date of the script. |
| CrowdStrike.Script.Description | string | The description of the script. |
| CrowdStrike.Script.ModifiedBy | string | The email of the user who modified the script. |
| CrowdStrike.Script.ModifiedTime | date | The modification date of the script. |
| CrowdStrike.Script.Name | string | The script name. |
| CrowdStrike.Script.Permission | string | The permission type of the script. Can be: "public", "group" or "private". |
| CrowdStrike.Script.SHA256 | string | The SHA-256 hash of the script. |
| CrowdStrike.Script.RunAttemptCount | number | The number of the script run attempts. |
| CrowdStrike.Script.RunSuccessCount | number | List of platforms OS for which the script can run. For example, windows. |
| CrowdStrike.Script.Platform | string | List of platforms OS for which the script can run. For example, windows. |
| CrowdStrike.Script.WriteAccess | boolean | Whether the user has write access to the script. |

##### Command Example
`!cs-falcon-get-script file_id=le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a`

##### Context Example
```
{
    'CrowdStrike': {
        'Script': [
            {
                'CreatedBy': 'spongobob@demisto.com',
                'CreatedTime': '2019-10-17T13:41:48.487520845Z',
                'Description': 'Demisto',
                'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
                'ModifiedBy': 'spongobob@demisto.com',
                'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
                'Name': 'Demisto',
                'Permission': 'private',
                'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
                'RunAttemptCount': 0,
                'RunSuccessCount': 0,
                'WriteAccess': True
            }
        ]
}
```

##### Human Readable Output
### CrowdStrike Falcon script le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a
|CreatedBy|CreatedTime|Description|ID|ModifiedBy|ModifiedTime|Name|Permission|SHA256|
|---|---|---|---|---|---|---|---|---|
| spongobob@demisto.com | 2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a | spongobob@demisto.com | 2019-10-17T13:41:48.487521161Z | Demisto | private | 5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc |


### 14. cs-falcon-delete-script
---
Deletes a script based on the ID given. Can delete only one script at a time.

##### Base Command
`cs-falcon-delete-script`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | The script ID to delete (can be retrieved by running cs-falcon-list-scripts command).| Required | 


##### Command Example
`!cs-falcon-delete-script script_id=le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a`

##### Human Readable Output
Script le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a was deleted successfully.

### 15. cs-falcon-list-scripts
---
Returns a list of custom script IDs that are available for the user in the `runscript` command.

##### Base Command
`cs-falcon-list-scripts`

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Script.ID | string | The ID of the script. |
| CrowdStrike.Script.CreatedBy | string | The email of the user who created the script. |
| CrowdStrike.Script.CreatedTime | date | The creation date of the script. |
| CrowdStrike.Script.Description | string | The description of the script. |
| CrowdStrike.Script.ModifiedBy | string | The email of the user who modified the script. |
| CrowdStrike.Script.ModifiedTime | date | The modification date of the script. |
| CrowdStrike.Script.Name | string | The script name. |
| CrowdStrike.Script.Permission | string | The permission type of the script. Can be: "public", "group" or "private". |
| CrowdStrike.Script.SHA256 | string | The SHA-256 hash of the script. |
| CrowdStrike.Script.RunAttemptCount | number | The number of the script run attempts. |
| CrowdStrike.Script.RunSuccessCount | number | List of platforms OS for which the script can run. For example, windows. |
| CrowdStrike.Script.Platform | string | List of platforms OS for which the script can run. For example, windows. |
| CrowdStrike.Script.WriteAccess | boolean | Whether the user has write access to the script. |

##### Command Example
`!cs-falcon-list-scripts`

##### Context Example
```
{
    'CrowdStrike': {
        'Script': [
            {
                'CreatedBy': 'spongobob@demisto.com',
                'CreatedTime': '2019-10-17T13:41:48.487520845Z',
                'Description': 'Demisto',
                'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
                'ModifiedBy': 'spongobob@demisto.com',
                'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
                'Name': 'Demisto',
                'Permission': 'private',
                'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
                'RunAttemptCount': 0,
                'RunSuccessCount': 0,
                'WriteAccess': True
            }
        ]
}
```

##### Human Readable Output
### CrowdStrike Falcon scripts
| CreatedBy | CreatedTime | Description | ID | ModifiedBy | ModifiedTime | Name | Permission| SHA256 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| spongobob@demisto.com |  2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a | spongobob@demisto.com | 2019-10-17T13:41:48.487521161Z | Demisto | private | 5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc |


### 16. cs-falcon-run-script
---
Runs a script on the agent host.
##### Base Command

`cs-falcon-run-script`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma separated list of host agent ID’s for which to run commands (can be retrieved by running cs-falcon-search-device command). | Required | 
| script_name | The name of the script to run. | Optional | 
| raw | The PowerShell script code to run. | Optional | 

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | string | The ID of the host for which the command was running. | 
| CrowdStrike.Command.Stdout | string | The standard output of the command. | 
| CrowdStrike.Command.Stderr | string | The standard error of the command. | 
| CrowdStrike.Command.BaseCommand | string | The base command. | 
| CrowdStrike.Command.FullCommand | string | The full command. | 


##### Command Example
`cs-falcon-run-script host_ids=284771ee197e422d5176d6634a62b934 raw="Write-Output 'Hello, World!"`

##### Context Example
```
{
    'CrowdStrike': {
        'Command': [{
            'HostID': '284771ee197e422d5176d6634a62b934',
                'Stdout': 'Hello, World!',
                'Stderr': '',
                'BaseCommand': 'runscript',
                'Command': "runscript -Raw=Write-Output 'Hello, World!"
        }]
}
```

##### Human Readable Output
### Command runscript -Raw=Write-Output 'Hello, World! results
|BaseCommand|Command|HostID|Stderr|Stdout|
|---|---|---|---|---|
| runscript | runscript -Raw=Write-Output 'Hello, World! | 284771ee197e422d5176d6634a62b934 |  | Hello, World! |                                    Type         Size (bytes)    Size (MB)       Last Modified (UTC-5)     Created (UTC-5)          <br/>----                                     ----         ------------    ---------       ---------------------     ---------------          <br/>$Recycle.Bin                             &lt;Directory&gt;  --              --              11/27/2018 10:54:44 AM    9/15/2017 3:33:40 AM     <br/>ITAYDI                                   &lt;Directory&gt;  --              --              11/19/2018 1:31:42 PM     11/19/2018 1:31:42 PM     |
