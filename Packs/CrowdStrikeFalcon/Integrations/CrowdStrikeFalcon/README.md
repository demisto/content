The CrowdStrike Falcon OAuth 2 API integration (formerly Falcon Firehose API), enables fetching and resolving detections, searching devices, getting behaviors by ID, containing hosts, and lifting host containment.

## Configure Crowdstrike Falcon on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CrowdstrikeFalcon.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g., https://api.crowdstrike.com\) | True |
| client_id | Client ID | True |
| secret | Secret | True |
| fetch_time | First fetch timestamp \(`<number>` `<time unit>`, e.g., 12 hours, 7 days\) | False |
| incidents_per_fetch | Max incidents per fetch | False |
| fetch_query | Fetch query | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| fetch_incidents_or_detections | Fetch types | False |

4.  Click **Test** to validate the URLs, token, and connection.

### 1. Search for a device

---

Searches for devices that match the query.

#### Base Command

`cs-falcon-search-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | The query by which to filter the device. | Optional | 
| ids | A comma-separated list of device IDs by which to limit the results. | Optional | 
| status | The status of the device. Possible values are: "Normal", "containment_pending", "contained", and "lift_containment_pending". | Optional | 
| hostname | The host name of the device. | Optional | 
| platform_name | The platform name of the device. Possible values are: "Windows","Mac", and "Linux". | Optional | 
| site_name | The site name of the device. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| <span>CrowdStrike.Device.ID</span> | String | The ID of the device. | 
| CrowdStrike.Device.LocalIP | String | The local IP address of the device. | 
| CrowdStrike.Device.ExternalIP | String | The external IP address of the device. | 
| CrowdStrike.Device.Hostname | String | The host name of the device. | 
| CrowdStrike.Device.OS | String | The operating system of the device. | 
| CrowdStrike.Device.MacAddress | String | The MAC address of the device. | 
| CrowdStrike.Device.FirstSeen | String | The first time the device was seen. | 
| CrowdStrike.Device.LastSeen | String | The last time the device was seen. | 
| CrowdStrike.Device.PolicyType | String | The policy type of the device. | 
| CrowdStrike.Device.Status | String | The device status. | 
| Endpoint.Hostname | String | The endpoint's hostname. | 
| Endpoint.OS | String | The endpoint's operation system. | 
| Endpoint.OSVersion | String | The endpoint's operation system version. | 
| Endpoint.IPAddress | String | The endpoint's IP address. | 
| Endpoint.ID | String | The endpoint's ID. | 
| Endpoint.Status | String | The endpoint's status. | 
| Endpoint.IsIsolated | String | The endpoint's isolation status. | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 


#### Command Example

`!cs-falcon-search-device ids=336474ea6a524e7c68575f6508d84781,459146dbe524472e73751a43c63324f3`

#### Context Example
```
    {
        "CrowdStrike.Device(val.ID === obj.ID)": [
            {
                "ExternalIP": "94.188.164.68", 
                "MacAddress": "8c-85-90-3d-ed-3e", 
                "Hostname": "154.132.82-test-co.in-addr.arpa", 
                "LocalIP": "192.168.1.76", 
                "LastSeen": "2019-03-28T02:36:41Z", 
                "OS": "Mojave (10.14)", 
                "ID": "336474ea6a524e7c68575f6508d84781", 
                "FirstSeen": "2017-12-28T22:38:11Z",
                "Status": "contained"
            }, 
            {
                "ExternalIP": "94.188.164.68", 
                "MacAddress": "f0-18-98-74-8c-31", 
                "Hostname": "154.132.82-test-co.in-addr.arpa", 
                "LocalIP": "172.22.14.237", 
                "LastSeen": "2019-03-17T10:03:17Z", 
                "OS": "Mojave (10.14)", 
                "ID": "459146dbe524472e73751a43c63324f3", 
                "FirstSeen": "2017-12-10T11:01:20Z",
                "Status": "contained"
            }
        ],
      "Endpoint(val.ID === obj.ID)": [
            {
              "Hostname": "154.132.82-test-co.in-addr.arpa",
              "ID": "336474ea6a524e7c68575f6508d84781",
              "IPAddress": "192.168.1.76", 
              "OS": "Mojave (10.14)",
              "Status": "Online",
              "￿Vendor": "CrowdStrike Falcon",
              "￿MACAddress": "1-1-1-1"
            },
            {
              "Hostname": "154.132.82-test-co.in-addr.arpa", 
              "ID": "459146dbe524472e73751a43c63324f3",
              "IPAddress": "172.22.14.237", 
              "OS": "Mojave (10.14)", 
              "Status": "Online",
              "￿Vendor": "CrowdStrike Falcon",
              "￿MACAddress": "1-1-1-1"
            }
        ]
    }
```
#### Human Readable Output

### Devices

| ID | Hostname | OS | Mac Address | Local IP | External IP | First Seen | Last Seen | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 336474ea6a524e7c68575f6508d84781 | 154.132.82-test-co.in-addr.arpa | Mojave (10.14) | 8c-85-90-3d-ed-3e | 192.168.1.76 | 94.188.164.68 | 2017-12-28T22:38:11Z | 2019-03-28T02:36:41Z | contained |
| 459146dbe524472e73751a43c63324f3 | 154.132.82-test-co.in-addr.arpa | Mojave (10.14) | f0-18-98-74-8c-31 | 172.22.14.237 | 94.188.164.68 | 2017-12-10T11:01:20Z | 2019-03-17T10:03:17Z | contained |
 

### 2. Get a behavior

---
Searches for and fetches the behavior that matches the query.

#### Base Command

`cs-falcon-get-behavior`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| behavior_id | The ID of the behavior. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Behavior.FileName | String | The file name of the behavior. | 
| CrowdStrike.Behavior.Scenario | String | The scenario name of the behavior. | 
| CrowdStrike.Behavior.MD5 | String | The MD5 hash of the IOC in the behavior. | 
| CrowdStrike.Behavior.SHA256 | String | The SHA256 hash of the IOC in the behavior. | 
| CrowdStrike.Behavior.IOCType | String | The type of the indicator of compromise. | 
| CrowdStrike.Behavior.IOCValue | String | The value of the IOC. | 
| CrowdStrike.Behavior.CommandLine | String | The command line executed in the behavior. | 
| CrowdStrike.Behavior.UserName | String | The user name related to the behavior. | 
| CrowdStrike.Behavior.SensorID | String | The sensor ID related to the behavior. | 
| CrowdStrike.Behavior.ParentProcessID | String | The ID of the parent process. | 
| CrowdStrike.Behavior.ProcessID | String | The process ID of the behavior. | 
| <span>CrowdStrike.Behavior.ID</span> | String | The ID of the behavior. | 

 

#### Command Example

`!cs-falcon-get-behavior behavior_id=3206`

#### Context Example
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
#### Human Readable Output

### Behavior ID: 3206

| ID | File Name | Command Line | Scenario | IOC Type | IOC Value | User Name | SHA256 | MD5 | Process ID | 
| ------ | --------------- | ----------------------------------------------------------------------- | ---------------- | ---------- | ------------------------------------------------------------------ | --------------------------------------- | ------------------------------------------------------------------ | ---------------------------------- | -------------------- |
| 3206 |   spokeshave.jn |  /Library/spokeshave.jn/spokeshave.jn.app/Contents/MacOS/spokeshave.jn |   known\_malware   | sha256 |    df8896dbe70a16419103be954ef2cdbbb1cecd2a865df5a0a2847d9a9fe7a266   | user@u-MacBook-Pro-2.local |   df8896dbe70a16419103be954ef2cdbbb1cecd2a865df5a0a2847d9a9fe7a266   | b41d753a4b61c9fe4486190c3b78e124|   197949010450449117|
|  3206   |xSf             |./xSf                                                                   |known\_malware   |sha256     |791d88ca295847bb6dd174e0ebad62f01f0cae56c157b7a11fd70bb457c97d9b|   root@u-MacBook-Pro-2.local|          791d88ca295847bb6dd174e0ebad62f01f0cae56c157b7a11fd70bb457c97d9b   |06dc9ff1857dcd4cdcd125b277955134   |197949016741905142|

 

### 3. Search for detections

---
Search for details of specific detections, either using a filter query,
or by providing the IDs of the detections.

#### Base Command

`cs-falcon-search-detection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the detections to search. If provided, will override other arguments. | Optional | 
| filter | Filter detections using a query in Falcon Query Language (FQL).<br/>e.g., filter="device.hostname:'CS-SE-TG-W7-01'"<br/>For a full list of valid filter options, see: https://falcon.crowdstrike.com/support/documentation/2/query-api-reference#detectionsearch | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Detection.Behavior.FileName | String | The file name of the behavior. | 
| CrowdStrike.Detection.Behavior.Scenario | String | The scenario name of the behavior. | 
| CrowdStrike.Detection.Behavior.MD5 | String | The MD5 hash of the IOC of the behavior. | 
| CrowdStrike.Detection.Behavior.SHA256 | String | The SHA256 hash of the IOC of the behavior. | 
| CrowdStrike.Detection.Behavior.IOCType | String | The type of the IOC. | 
| CrowdStrike.Detection.Behavior.IOCValue | String | The value of the IOC. | 
| CrowdStrike.Detection.Behavior.CommandLine | String | The command line executed in the behavior. | 
| CrowdStrike.Detection.Behavior.UserName | String | The user name related to the behavior. | 
| CrowdStrike.Detection.Behavior.SensorID | String | The sensor ID related to the behavior. | 
| CrowdStrike.Detection.Behavior.ParentProcessID | String | The ID of the parent process. | 
| CrowdStrike.Detection.Behavior.ProcessID | String | The process ID of the behavior. | 
| <span>CrowdStrike.Detection.Behavior.ID</span> | String | The ID of the behavior. | 
| CrowdStrike.Detection.System | String | The system name of the detection. | 
| CrowdStrike.Detection.CustomerID | String | The ID of the customer \(CID\). | 
| CrowdStrike.Detection.MachineDomain | String | The name of the domain of the detection machine. | 
| <span>CrowdStrike.Detection.ID</span> | String | The detection ID. | 
| CrowdStrike.Detection.ProcessStartTime | Date | The start time of the process that generated the detection. | 

 

#### Command Example

`!cs-falcon-search-detection ids=ldt:07893fedd2604bc66c3f7de8d1f537e3:1898376850347,ldt:68b5432856c1496d7547947fc7d1aae4:1092318056279064902`

#### Context Example
```
    {
        "CrowdStrike.Detection(val.ID === obj.ID)": [
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
#### Human Readable Output

### Detections Found:

  |ID                                                         |Status|            System                 |     Process Start Time     |          Customer ID                       | Max Severity|
  |----------------------------------------------------------| ----------------- |--------------------------- |-------------------------------- |---------------------------------- |--------------|
  |ldt:07893fedd2604bc66c3f7de8d1f537e3:1898376850347       |  false\_positive |  DESKTOP-S49VMIL            | 2019-03-21T20:32:55.654489974Z  | ed33ec93d2444d38abd3925803938a75  | 70|
  |ldt:68b5432856c1496d7547947fc7d1aae4:1092318056279064902|   new             |  u-MacBook-Pro-2.local  | 2019-02-04T07:05:57.083205971Z  | ed33ec93d2444d38abd3925803938a75  | 30|

 

### 4. Resolve a detection

* * * * *

Resolves and updates a detection using the provided arguments. At least one optional argument must be passed, otherwise no change will take place.

#### Base Command

`cs-falcon-resolve-detection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of one or more IDs to resolve. | Required | 
| status | The status to which to transition a detection. Possible values are: "new", "in_progress", "true_positive", "false_positive", and "ignored". | Optional | 
| assigned_to_uuid | A user ID, for example: 1234567891234567891. username and assigned_to_uuid are mutually exclusive. | Optional | 
| comment | Optional comment to add to the detection. Comments are displayed with the detection in Falcon and are usually used to provide context or notes for other Falcon users. | Optional | 
| show_in_ui | If true, displays the detection in the UI. | Optional | 
| username | Username to assign the detections to. (This is usually the user’s email address, but may vary based on your configuration). username and assigned_to_uuid are mutually exclusive. | Optional | 
 

#### Context Output

There is no context output for this command.

### 5. Contain a host

* * * * *

Contains containment for a specified host. When contained, a
host can only communicate with the CrowdStrike cloud and any IPs
specified in your containment policy.

#### Base Command

`cs-falcon-contain-host`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The host agent ID (AID) of the host to contain. Get an agent ID from a detection. | Required | 

 

#### Context Output

There is no context output for this command.

### 6. Lift the containment for a host

* * * * *

Lifts containment from a host, which returns its network communications
to normal.

#### Base Command

`cs-falcon-lift-host-containment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The host agent ID (AID) of the host to contain. Get an agent ID from a detection | Required | 

 

#### Context Output

There is no context output for this command.


### 7. cs-falcon-run-command
---
Sends commands to hosts.

#### Base Command

`cs-falcon-run-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma-separated list of host agent IDs for which to run commands. (Can be retrieved by running the 'cs-falcon-search-device' command.) | Required | 
| command_type | The type of command to run. | Required | 
| full_command | The full command to run. | Required | 
| scope | The scope for which to run the command. Possible values are: "read", "write", and "admin". Default is "read". (NOTE: In order to run the CrowdStrike RTR `put` command, it is necessary to pass `scope=admin`.) | Optional | 
| target | The target for which to run the command. Possible values are: "single" and "batch". Default is "batch". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | String | The ID of the host for which the command was running. | 
| CrowdStrike.Command.SessionID | string | The ID of the session of the host. | 
| CrowdStrike.Command.Stdout | String | The standard output of the command. | 
| CrowdStrike.Command.Stderr | String | The standard error of the command. | 
| CrowdStrike.Command.BaseCommand | String | The base command. | 
| CrowdStrike.Command.FullCommand | String | The full command. | 
| CrowdStrike.Command.TaskID | string | \(For single host\) The ID of the command request which has been accepted. | 
| CrowdStrike.Command.Complete | boolean | \(For single host\) True if the command completed. | 
| CrowdStrike.Command.NextSequenceID | number | \(For single host\) The next sequence ID. | 


#### Command Example
`cs-falcon-run-command host_ids=284771ee197e422d5176d6634a62b934 command_type=ls full_command="ls C:\\"`

#### Context Example
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

#### Human Readable Output
### Command ls C:\\ results
|BaseCommand|Command|HostID|Stderr|Stdout|
|---|---|---|---|---|
| ls | ls C:\ | 284771ee197e422d5176d6634a62b934 |  | Directory listing for C:\ -<br/><br/>Name                                     Type         Size (bytes)    Size (MB)       Last Modified (UTC-5)     Created (UTC-5)          <br/>----                                     ----         ------------    ---------       ---------------------     ---------------          <br/>$Recycle.Bin                             &lt;Directory&gt;  --              --              11/27/2018 10:54:44 AM    9/15/2017 3:33:40 AM     <br/>ITAYDI                                   &lt;Directory&gt;  --              --              11/19/2018 1:31:42 PM     11/19/2018 1:31:42 PM     |

### 8. cs-falcon-upload-script
---
Uploads a script to Falcon.

#### Base Command
`cs-falcon-upload-script`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The script name to upload. | Required | 
| permission_type | The permission type for the custom script. Possible values are: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins. Default is "private". | Optional | 
| content | The content of the PowerShell script. | Required | 


#### Command Example
`!cs-falcon-upload-script name=greatscript content="Write-Output 'Hello, World!'"`

#### Human Readable Output
The script was uploaded successfully.

### 9. cs-falcon-upload-file
---
Uploads a file to the CrowdStrike cloud. (Can be used for the RTR `put` command.)

#### Base Command
`cs-falcon-upload-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The file entry ID to upload. | Required |  

#### Command Example
`!cs-falcon-upload-file entry_id=4@4`

#### Human Readable Output
The file was uploaded successfully.

### 10. cs-falcon-delete-file
---
Deletes a file based on the provided ID. Can delete only one file at a time.

#### Base Command
`cs-falcon-delete-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The ID of the file to delete. (The ID of the file can be retrieved by running the 'cs-falcon-list-files' command.). | Required | 


#### Command Example
`!cs-falcon-delete-file file_id=le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a`

#### Human Readable Output
File le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a was deleted successfully.

### 11. cs-falcon-get-file
---
Returns files based on the IDs given. These are used for the RTR `put` command.

#### Base Command
`cs-falcon-get-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | A comma-separated list of file IDs to get. (The list of file IDs can be retrieved by running the 'cs-falcon-list-files' command.) | Required | 



#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| <span>CrowdStrike.File.ID</span> | String | The ID of the file. | 
| CrowdStrike.File.CreatedBy | String | The email address of the user who created the file. | 
| CrowdStrike.File.CreatedTime | Date | The date and time the file was created. | 
| CrowdStrike.File.Description | String | The description of the file. | 
| CrowdStrike.File.Type | String | The type of the file. For example, script. | 
| CrowdStrike.File.ModifiedBy | String | The email address of the user who modified the file. | 
| CrowdStrike.File.ModifiedTime | Date | The date and time the file was modified. | 
| <span>CrowdStrike.File.Name</span> | String | The full name of the file. | 
| CrowdStrike.File.Permission | String | The permission type of the file. Possible values are: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins | 
| CrowdStrike.File.SHA256 | String | The SHA-256 hash of the file. | 
| File.Type | String | The file type. | 
| <span>File.Name</span> | String | The full name of the file. | 
| File.SHA256 | String | The SHA-256 hash of the file. | 
| File.Size | Number | The size of the file in bytes. | 

#### Command Example
`!cs-falcon-get-file file_id=le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a`

#### Context Example
```
{
    'CrowdStrike.File(val.ID === obj.ID)': [
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

#### Human Readable Output
### CrowdStrike Falcon file le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a
|CreatedBy|CreatedTime|Description|ID|ModifiedBy|ModifiedTime|Name|Permission|SHA256|Type|
|---|---|---|---|---|---|---|---|---|---|
| spongobob@demisto.com | 2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a | spongobob@demisto.com | 2019-10-17T13:41:48.487521161Z | Demisto | private | 5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc | script |

### 12. cs-falcon-list-files
---
Returns Returns a list of put-file ID's that are available for the user in the `put` command.

#### Base Command
`cs-falcon-list-files`

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| <span>CrowdStrike.File.ID</span> | String | The ID of the file. | 
| CrowdStrike.File.CreatedBy | String | The email address of the user who created the file. | 
| CrowdStrike.File.CreatedTime | Date | The date and time the file was created. | 
| CrowdStrike.File.Description | String | The description of the file. | 
| CrowdStrike.File.Type | String | The type of the file. For example, script. | 
| CrowdStrike.File.ModifiedBy | String | The email address of the user who modified the file. | 
| CrowdStrike.File.ModifiedTime | Date | The date and time the file was modified. | 
| <span>CrowdStrike.File.Name</span> | String | The full name of the file. | 
| CrowdStrike.File.Permission | String | The permission type of the file. Possible values are: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins. | 
| CrowdStrike.File.SHA256 | String | The SHA-256 hash of the file. | 
| File.Type | String | The file type. | 
| <span>File.Name</span> | String | The full name of the file. | 
| File.SHA256 | String | The SHA-256 hash of the file. | 
| File.Size | Number | The size of the file in bytes. | 

#### Command Example
`!cs-falcon-list-files`

#### Context Example
```
{
    'CrowdStrike.File(val.ID === obj.ID)': [
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

#### Human Readable Output
### CrowdStrike Falcon files
|CreatedBy|CreatedTime|Description|ID|ModifiedBy|ModifiedTime|Name|Permission|SHA256|Type|
|---|---|---|---|---|---|---|---|---|---|
| spongobob@demisto.com | 2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a | spongobob@demisto.com | 2019-10-17T13:41:48.487521161Z | Demisto | private | 5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc | script |

### 13. cs-falcon-get-script
---
Return custom scripts based on the ID. Used for the RTR `runscript` command.

#### Base Command
`cs-falcon-get-script`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | A comma-separated list of script IDs to return. (The script IDs can be retrieved by running the 'cs-falcon-list-scripts' command.) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| <span>CrowdStrike.Script.ID</span> | String | The ID of the script. | 
| CrowdStrike.Script.CreatedBy | String | The email address of the user who created the script. | 
| CrowdStrike.Script.CreatedTime | Date | The date and time the script was created. | 
| CrowdStrike.Script.Description | String | The description of the script. | 
| CrowdStrike.Script.ModifiedBy | String | The email address of the user who modified the script. | 
| CrowdStrike.Script.ModifiedTime | Date | The date and time the script was modified. | 
| <span>CrowdStrike.Script.Name</span> | String | The script name. | 
| CrowdStrike.Script.Permission | String | Permission type of the script. Possible values are: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins. | 
| CrowdStrike.Script.SHA256 | String | The SHA-256 hash of the script file. | 
| CrowdStrike.Script.RunAttemptCount | Number | The number of times the script attempted to run. | 
| CrowdStrike.Script.RunSuccessCount | Number | The number of times the script ran successfully. | 
| CrowdStrike.Script.Platform | String | The list of operating system platforms on which the script can run. For example, Windows. | 
| CrowdStrike.Script.WriteAccess | Boolean | Whether the user has write access to the script. | 

#### Command Example
`!cs-falcon-get-script file_id=le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a`

#### Context Example
```
{
    'CrowdStrike.Script(val.ID === obj.ID)': [
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

#### Human Readable Output
### CrowdStrike Falcon script le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a
|CreatedBy|CreatedTime|Description|ID|ModifiedBy|ModifiedTime|Name|Permission|SHA256|
|---|---|---|---|---|---|---|---|---|
| spongobob@demisto.com | 2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a | spongobob@demisto.com | 2019-10-17T13:41:48.487521161Z | Demisto | private | 5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc |


### 14. cs-falcon-delete-script
---
Deletes a script based on the ID given. Can delete only one script at a time.

#### Base Command
`cs-falcon-delete-script`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | Script ID to delete. (Script IDs can be retrieved by running the 'cs-falcon-list-scripts' command.) | Required | 

#### Command Example
`!cs-falcon-delete-script script_id=le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a`

#### Human Readable Output
Script le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a was deleted successfully.

### 15. cs-falcon-list-scripts
---
Returns a list of custom script IDs that are available for the user in the `runscript` command.

#### Base Command
`cs-falcon-list-scripts`

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| <span>CrowdStrike.Script.ID</span> | String | The ID of the script. | 
| CrowdStrike.Script.CreatedBy | String | The email address of the user who created the script. | 
| CrowdStrike.Script.CreatedTime | Date | The date and time the script was created. | 
| CrowdStrike.Script.Description | String | The description of the script. | 
| CrowdStrike.Script.ModifiedBy | String | The email address of the user who modified the script. | 
| CrowdStrike.Script.ModifiedTime | Date | The date and time the script was modified. | 
| <span>CrowdStrike.Script.Name</span> | String | The script name. | 
| CrowdStrike.Script.Permission | String | Permission type of the script. Possible values are: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins. | 
| CrowdStrike.Script.SHA256 | String | The SHA-256 hash of the script file. | 
| CrowdStrike.Script.RunAttemptCount | Number | The number of times the script attempted to run. | 
| CrowdStrike.Script.RunSuccessCount | Number | The number of times the script ran successfully. | 
| CrowdStrike.Script.Platform | String | The list of operating system platforms on which the script can run. For example, Windows. | 
| CrowdStrike.Script.WriteAccess | Boolean | Whether the user has write access to the script. | 

#### Command Example
`!cs-falcon-list-scripts`

#### Context Example
```
{
    'CrowdStrike.Script(val.ID === obj.ID)': [
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

#### Human Readable Output
### CrowdStrike Falcon scripts
| CreatedBy | CreatedTime | Description | ID | ModifiedBy | ModifiedTime | Name | Permission| SHA256 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| spongobob@demisto.com |  2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a | spongobob@demisto.com | 2019-10-17T13:41:48.487521161Z | Demisto | private | 5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc |


### 16. cs-falcon-run-script
---
Runs a script on the agent host.
#### Base Command

`cs-falcon-run-script`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_name | The name of the script to run. | Optional | 
| host_ids | A comma-separated list of host agent IDs to run commands. (The list of host agent IDs can be retrieved by running the 'cs-falcon-search-device' command.) | Required | 
| raw | The PowerShell script code to run. | Optional | 
| timeout | The amount of time to wait before the request times out (in seconds). Maximum is 600 (10 minutes). Default value is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | String | The ID of the host for which the command was running. | 
| CrowdStrike.Command.SessionID | String | The ID of the session of the host. | 
| CrowdStrike.Command.Stdout | String | The standard output of the command. | 
| CrowdStrike.Command.Stderr | String | The standard error of the command. | 
| CrowdStrike.Command.BaseCommand | String | The base command. | 
| CrowdStrike.Command.FullCommand | String | The full command. | 


#### Command Example
`cs-falcon-run-script host_ids=284771ee197e422d5176d6634a62b934 raw="Write-Output 'Hello, World!"`

#### Context Example
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

#### Human Readable Output
### Command runscript -Raw=Write-Output 'Hello, World! results
|BaseCommand|Command|HostID|Stderr|Stdout|
|---|---|---|---|---|
| runscript | runscript -Raw=Write-Output 'Hello, World! | 284771ee197e422d5176d6634a62b934 |  | Hello, World! |                                    Type         Size (bytes)    Size (MB)       Last Modified (UTC-5)     Created (UTC-5)          <br/>----                                     ----         ------------    ---------       ---------------------     ---------------          <br/>$Recycle.Bin                             &lt;Directory&gt;  --              --              11/27/2018 10:54:44 AM    9/15/2017 3:33:40 AM     <br/>ITAYDI                                   &lt;Directory&gt;  --              --              11/19/2018 1:31:42 PM     11/19/2018 1:31:42 PM     |


### 17. cs-falcon-run-get-command
***
Batch executes `get` command across hosts to retrieve files.
The running status you requested the `get` command can be checked with `cs-falcon-status-get-command`.

#### Base Command

`cs-falcon-run-get-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | List of host agent IDs on which to run the RTR command. | Required | 
| file_path | Full path to the file that will be retrieved from each host in the batch. | Required | 
| optional_hosts | List of a subset of hosts on which to run the command. | Optional | 
| timeout | The number of seconds to wait for the request before it times out. In ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | Optional | 
| timeout_duration | The amount of time to wait for the request before it times out. In duration syntax. For example: 10s. Valid units are: ns, us, ms, s, m, h. Maximum value is 10 minutes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | string | The ID of the host on which the command was running. | 
| CrowdStrike.Command.Stdout | string | The standard output of the command. | 
| CrowdStrike.Command.Stderr | string | The standard error of the command. | 
| CrowdStrike.Command.BaseCommand | string | The base command. | 
| CrowdStrike.Command.TaskID | string | The ID of the command that was running on the host. | 
| CrowdStrike.Command.GetRequestID | string | The ID of the command request that was accepted. | 
| CrowdStrike.Command.Complete | boolean | True if the command completed. | 
| CrowdStrike.Command.FilePath | string | The file path. | 


#### Command Example
`cs-falcon-run-get-command host_ids=edfd6a04ad134c4344f8fb119a3ad88e file_path="""c:\Windows\notepad.exe"""`

#### Context Example
```
{
  "CrowdStrike.Command(val.TaskID === obj.TaskID)": [
    {
      "BaseCommand": "get",
      "Complete": True,
      "FilePath": "c:\\Windows\\notepad.exe",
      "GetRequestID": "84ee4d50-f499-482e-bac6-b0e296149bbf",
      "HostID": "edfd6a04ad134c4344f8fb119a3ad88e",
      "Stderr": "",
      "Stdout": "C:\\Windows\\notepad.exe",
      "TaskID": "b5c8f140-280b-43fd-8501-9900f837510b"
    }
  ]
}
```

#### Human Readable Output
### Get command has requested for a file c:\Windows\notepad.exe
|BaseCommand|Complete|FilePath|GetRequestID|HostID|Stderr|Stdout|TaskID|
|---|---|---|---|---|---|---|---|
| get | true | c:\Windows\notepad.exe | 107199bc-544c-4b0c-8f20-3094c062a115 | edfd6a04ad134c4344f8fb119a3ad88e |  | C:\Windows\notepad.exe | 9c820b97-6a60-4238-bc23-f63513970ec8 |



### 18. cs-falcon-status-get-command
***
Retrieves the status of the batch get command which you requested at `cs-falcon-run-get-command`.

#### Base Command

`cs-falcon-status-get-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_ids | The list of IDs of the command requested. | Required | 
| timeout | The number of seconds to wait for the request before it times out. In ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | Optional | 
| timeout_duration | The amount of time to wait for the request before it times out. In duration syntax. For example: 10s. Valid units are: ns, us, ms, s, m, h. Maximum value is 10 minutes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| <span>CrowdStrike.File.ID</span> | string | The ID of the file. | 
| CrowdStrike.File.TaskID | string | The ID of the command that is running. | 
| CrowdStrike.File.CreatedAt | date | The date the file was created. | 
| CrowdStrike.File.DeletedAt | date | The date the file was deleted. | 
| CrowdStrike.File.UpdatedAt | date | The date the file was last updated. | 
| <span>CrowdStrike.File.Name</span> | string | The full name of the file. | 
| CrowdStrike.File.SHA256 | string | The SHA256 hash of the file. | 
| CrowdStrike.File.Size | number | The size of the file in bytes. | /span> | string | The full name of the file. | 
| File.Size | number | The size of the file in bytes. | 
| File.SHA256 | string | The SHA256 hash of the file. | 


#### Command Example
`!cs-falcon-status-get-command request_ids="84ee4d50-f499-482e-bac6-b0e296149bbf"`

#### Context Example
```
{
  "CrowdStrike.File(val.ID === obj.ID || val.TaskID === obj.TaskID)": [
    {
      "CreatedAt": "2020-05-01T16:09:00Z",
      "DeletedAt": None,
      "ID": 185596,
      "Name": "\\Device\\HarddiskVolume2\\Windows\\notepad.exe",
      "SHA256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3",
      "Size": 0,
      "TaskID": "b5c8f140-280b-43fd-8501-9900f837510b",
      "UpdatedAt": "2020-05-01T16:09:00Z"
    }
  ],
  "File(val.MD5 \u0026\u0026 val.MD5 == obj.MD5 || val.SHA1 \u0026\u0026 val.SHA1 == obj.SHA1 || val.SHA256 \u0026\u0026 val.SHA256 == obj.SHA256 || val.SHA512 \u0026\u0026 val.SHA512 == obj.SHA512 || val.CRC32 \u0026\u0026 val.CRC32 == obj.CRC32 || val.CTPH \u0026\u0026 val.CTPH == obj.CTPH || val.SSDeep \u0026\u0026 val.SSDeep == obj.SSDeep)": [
    {
      "Name": "\\Device\\HarddiskVolume2\\Windows\\notepad.exe",
      "SHA256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3",
      "Size": 0
    }
  ]
}
```

#### Human Readable Output
### CrowdStrike Falcon files
|CreatedAt|DeletedAt|ID|Name|SHA256|Size|TaskID|UpdatedAt|
|---|---|---|---|---|---|---|---|
| 2020-05-01T16:09:00Z |  | 185596 | \\Device\\HarddiskVolume2\\Windows\\notepad.exe | f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3 | 0 | b5c8f140-280b-43fd-8501-9900f837510b | 2020-05-01T16:09:00Z |


### 19. cs-falcon-status-command
***
Get status of an executed command on a host


#### Base Command

`cs-falcon-status-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The ID of the command requested. | Required | 
| sequence_id | The sequence ID in chunk requests. | Optional | 
| scope | The scope for which to run the command. Possible values are: "read", "write", or "admin". Default is "read". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.TaskID | string | The ID of the command request that was accepted. | 
| CrowdStrike.Command.Stdout | string | The standard output of the command. | 
| CrowdStrike.Command.Stderr | string | The standard error of the command. | 
| CrowdStrike.Command.BaseCommand | string | The base command. | 
| CrowdStrike.Command.Complete | boolean | True if the command completed. | 
| CrowdStrike.Command.SequenceID | number | The sequence ID in the current request. | 
| CrowdStrike.Command.NextSequenceID | number | The sequence ID for the next request in the chunk request. | 


#### Command Example
`!cs-falcon-status-command request_id="ae323961-5aa8-442e-8461-8d05c4541d7d"`

#### Context Example
```
{
  "CrowdStrike.Command(val.TaskID === obj.TaskID)": [
    {
      "BaseCommand": "ls",
      "Complete": true,
      "NextSequenceID": null,
      "SequenceID": null,
      "Stderr": "",
      "Stdout": "Directory listing for C:\\ -\n\nName                                     Type         Size (bytes)    Size (MB)       Last Modified (UTC+9)     Created (UTC+9)          \n----                                     ----         ------------    ---------       ---------------------     ---------------          \n$Recycle.Bin                             \u003cDirectory\u003e  --              --              2020/01/10 16:05:59       2019/03/19 13:52:43      \nConfig.Msi                               \u003cDirectory\u003e  --              --              2020/05/01 23:12:50       2020/01/10 16:52:09      \nDocuments and Settings                   \u003cDirectory\u003e  --              --              2019/09/12 15:03:21       2019/09/12 15:03:21      \nPerfLogs                                 \u003cDirectory\u003e  --              --              2019/03/19 13:52:43       2019/03/19 13:52:43      \nProgram Files                            \u003cDirectory\u003e  --              --              2020/01/10 17:11:47       2019/03/19 13:52:43      \nProgram Files (x86)                      \u003cDirectory\u003e  --              --              2020/05/01 23:12:53       2019/03/19 13:52:44      \nProgramData                              \u003cDirectory\u003e  --              --              2020/01/10 17:16:51       2019/03/19 13:52:44      \nRecovery                                 \u003cDirectory\u003e  --              --              2019/09/11 20:13:59       2019/09/11 20:13:59      \nSystem Volume Information                \u003cDirectory\u003e  --              --              2019/09/12 15:08:21       2019/09/11 20:08:43      \nUsers                                    \u003cDirectory\u003e  --              --              2019/09/22 22:26:11       2019/03/19 13:37:22      \nWindows                                  \u003cDirectory\u003e  --              --              2020/05/01 23:09:08       2019/03/19 13:37:22      \npagefile.sys                             .sys         2334928896      2226.762        2020/05/02 2:10:05        2019/09/11 20:08:44      \nswapfile.sys                             .sys         268435456       256             2020/05/01 23:09:13       2019/09/11 20:08:44      \n",
      "TaskID": "ae323961-5aa8-442e-8461-8d05c4541d7d"
    }
  ]
}
```

#### Human Readable Output
### Command status results
|BaseCommand|Complete|Stdout|TaskID|
|---|---|---|---|
| ls | true | Directory listing for C:\\ ...... | ae323961-5aa8-442e-8461-8d05c4541d7d |


### 20. cs-falcon-get-extracted-file
***
Get RTR extracted file contents for specified session and sha256.


#### Base Command

`cs-falcon-get-extracted-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The host agent ID. | Required | 
| sha256 | The SHA256 hash of the file. | Required | 
| filename | The filename to use for the archive name and the file within the archive. | Optional | 


#### Context Output

There is no context output for this command.


#### Command Example
`!cs-falcon-get-extracted-file host_id="edfd6a04ad134c4344f8fb119a3ad88e" sha256="f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3"`

#### Context Example
There is no context output for this command.

#### Human Readable Output
There is no human readable for this command.


### 21. cs-falcon-list-host-files
***
Get a list of files for the specified RTR session on a host.


#### Base Command

`cs-falcon-list-host-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The ID of the host agent that lists files in the session. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | string | The ID of the host for which the command was running. | 
| CrowdStrike.Command.TaskID | string | The ID of the command request that was accepted. | 
| CrowdStrike.Command.SessionID | string | The ID of the session of the host. | 
| <span>CrowdStrike.File.ID</span> | string | The ID of the file. | 
| CrowdStrike.File.CreatedAt | date | The date the file was created. | 
| CrowdStrike.File.DeletedAt | date | The date the file was deleted. | 
| CrowdStrike.File.UpdatedAt | date | The date the file was last updated. | 
|<span>CrowdStrike.File.Name</span> | string | The full name of the file. | 
| CrowdStrike.File.SHA256 | string | The SHA256 hash of the file. | 
| CrowdStrike.File.Size | number | The size of the file in bytes. | 
| <span>File.Name</span> | string | The full name of the file. | 
| File.Size | number | The size of the file in bytes. | 
| File.SHA256 | string | The SHA256 hash of the file. | 


#### Command Example
`!cs-falcon-list-host-files host_id="edfd6a04ad134c4344f8fb119a3ad88e"`

#### Context Example
```
{
  "CrowdStrike.Command(val.TaskID === obj.TaskID)": [
    {
      "HostID": "edfd6a04ad134c4344f8fb119a3ad88e",
      "SessionID": "fdd6408f-6688-441b-8659-41bcad25441c",
      "TaskID": "1269ad9e-c11f-4e38-8aba-1a0275304f9c"
    }
  ],
  "CrowdStrike.File(val.ID === obj.ID)": [
    {
      "CreatedAt": "2020-05-01T17:57:42Z",
      "DeletedAt": None,
      "ID": 186811,
      "Name": "\\Device\\HarddiskVolume2\\Windows\\notepad.exe",
      "SHA256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3",
      "Size": 0,
      "Stderr": None,
      "Stdout": None,
      "UpdatedAt": "2020-05-01T17:57:42Z"
    }
  ],
  "File(val.MD5 \u0026\u0026 val.MD5 == obj.MD5 || val.SHA1 \u0026\u0026 val.SHA1 == obj.SHA1 || val.SHA256 \u0026\u0026 val.SHA256 == obj.SHA256 || val.SHA512 \u0026\u0026 val.SHA512 == obj.SHA512 || val.CRC32 \u0026\u0026 val.CRC32 == obj.CRC32 || val.CTPH \u0026\u0026 val.CTPH == obj.CTPH || val.SSDeep \u0026\u0026 val.SSDeep == obj.SSDeep)": [
    {
      "Name": "\\Device\\HarddiskVolume2\\Windows\\notepad.exe",
      "SHA256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3",
      "Size": 0
    }
  ]
}
```

#### Human Readable Output
### CrowdStrike Falcon files
|CreatedAt|DeletedAt|ID|Name|SHA256|Size|Stderr|Stdout|UpdatedAt|
|---|---|---|---|---|---|---|---|---|
| 2020-05-01T17:57:42Z |  | 186811 | \\Device\\HarddiskVolume2\\Windows\\notepad.exe | f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3 | 0 |  |  | 2020-05-01T17:57:42Z |


### 22. cs-falcon-refresh-session
***
Refresh a session timeout on a single host.


#### Base Command

`cs-falcon-refresh-session`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The ID of the host for which to extend the session. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | string | The ID of the host for which the command was running. | 
| CrowdStrike.Command.TaskID | string | The ID of the command request which has been accepted. | 
| CrowdStrike.Command.SessionID | string | The ID of the session of the host. | 
| <span>CrowdStrike.File.ID</span> | string | The ID of the file. | 
| CrowdStrike.File.CreatedAt | date | The creation date of the file. | 
| CrowdStrike.File.DeletedAt | date | The deletion date of the file. | 
| CrowdStrike.File.UpdatedAt | date | The last updated date of the file. | 
| <span>CrowdStrike.File.Name</span> | string | The full file name. | 
| CrowdStrike.File.SHA256 | string | The SHA\-256 hash of the file. | 
| CrowdStrike.File.Size | number | The size of the file in bytes. | 
| <span>File.Name</span> | string | The full file name. | 
| File.Size | number | The size of the file in bytes. | 
| File.SHA256 | string | The SHA\-256 hash of the file. | 


#### Command Example
`!cs-falcon-refresh-session host_id=edfd6a04ad134c4344f8fb119a3ad88e`

#### Context Example
There is no context output for this command.

#### Human Readable Output
CrowdStrike Session Refreshed: fdd6408f-6688-441b-8659-41bcad25441c


### 23. cs-falcon-search-iocs
***
Deprecated. Use the cs-falcon-search-custom-iocs command instead.


#### Base Command

`cs-falcon-search-iocs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| types | A comma-separated list of indicator types. Valid types are: "sha256", "sha1", "md5", "domain", "ipv4", "ipv6". | Optional | 
| values | A comma-separated list of indicator values. | Optional | 
| policies | A comma-separated list of indicator policies. | Optional | 
| share_levels | The level at which the indicator will be shared. Only "red" share level (not shared) is supported, which indicates that the IOC is not shared with other Falcon Host customers. | Optional | 
| sources | A comma-separated list of IOC sources. | Optional | 
| from_expiration_date | Start of date range in which to search (YYYY-MM-DD format). | Optional | 
| to_expiration_date | End of date range in which to search (YYYY-MM-DD format). | Optional | 
| limit | The maximum number of records to return. The minimum is 1 and the maximum is 500. Default is 100. | Optional | 
| sort | The order in which the results are returned. Possible values are: "type.asc", "type.desc", "value.asc", "value.desc", "policy.asc", "policy.desc", "share_level.asc", "share_level.desc", "expiration_timestamp.asc", and "expiration_timestamp.desc". | Optional | 
| offset | The offset to begin the list from. For example, start from the 10th record and return the list. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| <span>CrowdStrike.IOC.ID</span> | string | The full ID of the indicator \(type:value\). | 
| CrowdStrike.IOC.Policy | string | The policy of the indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.ShareLevel | string | The level at which the indicator will be shared. | 
| CrowdStrike.IOC.Expiration | string | The datetime when the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | string | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | string | The datetime the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 


#### Command Example
```!cs-falcon-search-iocs types="domain"```

#### Context Example
```json
{
    "CrowdStrike": {
        "IOC": [
            {
                "CreatedTime": "2020-09-30T10:59:37Z",
                "Expiration": "2020-10-30T00:00:00Z",
                "ID": "domain:value",
                "ModifiedTime": "2020-09-30T10:59:37Z",
                "Policy": "none",
                "ShareLevel": "red",
                "Type": "domain",
                "Value": "value"
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicators of Compromise
>|CreatedTime|Expiration|ID|ModifiedTime|Policy|ShareLevel|Type|Value|
>|---|---|---|---|---|---|---|---|
>| 2020-09-30T10:59:37Z | 2020-10-30T00:00:00Z | domain:value | 2020-09-30T10:59:37Z | none | red | domain | value |

### 24. cs-falcon-get-ioc
***
Deprecated. Use the cs-falcon-get-custom-ioc command instead.


#### Base Command

`cs-falcon-get-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The IOC type to retrieve. Possible values are: "sha256", "sha1", "md5", "domain", "ipv4", and "ipv6". | Required | 
| value | The string representation of the indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| <span>CrowdStrike.IOC.ID</span> | string | The full ID of the indicator \(type:value\). | 
| CrowdStrike.IOC.Policy | string | The policy of the indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.ShareLevel | string | The level at which the indicator will be shared. | 
| CrowdStrike.IOC.Expiration | string | The date and time when the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | string | The date and time the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | string | The datetime the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 


#### Command Example
```!cs-falcon-get-ioc type="domain" value="test.domain.com"```

#### Context Example
```json
{
    "CrowdStrike": {
        "IOC": {
            "CreatedTime": "2020-10-02T13:55:26Z",
            "Description": "Test ioc",
            "Expiration": "2020-11-01T00:00:00Z",
            "ID": "domain:test.domain.com",
            "ModifiedTime": "2020-10-02T13:55:26Z",
            "Policy": "none",
            "ShareLevel": "red",
            "Source": "Demisto playbook",
            "Type": "domain",
            "Value": "test.domain.com"
        }
    }
}
```

#### Human Readable Output

>### Indicator of Compromise
>|CreatedTime|Description|Expiration|ID|ModifiedTime|Policy|ShareLevel|Source|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|
>| 2020-10-02T13:55:26Z | Test ioc | 2020-11-01T00:00:00Z | domain:test.domain.com | 2020-10-02T13:55:26Z | none | red | Demisto playbook | domain | test.domain.com |


### 25. cs-falcon-upload-ioc
***
Deprecated. Use the cs-falcon-upload-custom-ioc command instead.


#### Base Command

`cs-falcon-upload-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_type | The type of the indicator. Possible values are: "sha256", "md5", "domain", "ipv4", and "ipv6". | Required | 
| value | The string representation of the indicator. | Required | 
| policy | The policy to enact when the value is detected on a host. Possible values are: "detect" and "none". A value of "none" is equivalent to turning the indicator off. Default is "detect". | Optional | 
| share_level | The level at which the indicator will be shared. Only "red" share level (not shared) is supported, which indicates that the IOC is not shared with other Falcon Host customers. | Optional | 
| expiration_days | The number of days for which the indicator should be valid. This only applies to domain, ipv4, and ipv6 types. Default is 30. | Optional | 
| source | The source where this indicator originated. This can be used for tracking where this indicator was defined. Limited to 200 characters. | Optional | 
| description | A meaningful description of the indicator. Limited to 200 characters. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| <span>CrowdStrike.IOC.ID</span> | string | The full ID of the indicator \(type:value\). | 
| CrowdStrike.IOC.Policy | string | The policy of the indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.ShareLevel | string | The level at which the indicator will be shared. | 
| CrowdStrike.IOC.Expiration | string | The datetime when the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | string | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | string | The date and time the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 


#### Command Example
```!cs-falcon-upload-ioc ioc_type="domain" value="test.domain.com" policy="none" share_level="red" source="Demisto playbook" description="Test ioc"```

#### Context Example
```json
{
    "CrowdStrike": {
        "IOC": {
            "CreatedTime": "2020-10-02T13:55:26Z",
            "Description": "Test ioc",
            "Expiration": "2020-11-01T00:00:00Z",
            "ID": "domain:test.domain.com",
            "ModifiedTime": "2020-10-02T13:55:26Z",
            "Policy": "none",
            "ShareLevel": "red",
            "Source": "Demisto playbook",
            "Type": "domain",
            "Value": "test.domain.com"
        }
    }
}
```

#### Human Readable Output

>### Custom IOC was created successfully
>|CreatedTime|Description|Expiration|ID|ModifiedTime|Policy|ShareLevel|Source|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|
>| 2020-10-02T13:55:26Z | Test ioc | 2020-11-01T00:00:00Z | domain:test.domain.com | 2020-10-02T13:55:26Z | none | red | Demisto playbook | domain | test.domain.com |


### 26. cs-falcon-update-ioc
***
Deprecated. Use the cs-falcon-update-custom-ioc command instead.


#### Base Command

`cs-falcon-update-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_type | The type of the indicator. Possible values are: "sha256", "md5", "sha1", "domain", "ipv4", and "ipv6". | Required | 
| value | The string representation of the indicator. | Required | 
| policy | The policy to enact when the value is detected on a host. Possible values are: "detect" and "none". A value of "none" is equivalent to turning the indicator off. Default is "detect". | Optional | 
| share_level | The level at which the indicator will be shared. Only "red" share level (not shared) is supported, which indicates that the IOC is not shared with other Falcon Host customers. | Optional | 
| expiration_days | The number of days for which the indicator should be valid. This only applies to domain, ipv4, and ipv6 types. Default is 30. | Optional | 
| source | The source where this indicator originated. This can be used for tracking where this indicator was defined. Limited to 200 characters. | Optional | 
| description | A meaningful description of the indicator. Limited to 200 characters. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| <span>CrowdStrike.IOC.ID</span> | string | The full ID of the indicator \(type:value\). | 
| CrowdStrike.IOC.Policy | string | The policy of the indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.ShareLevel | string | The level at which the indicator will be shared. | 
| CrowdStrike.IOC.Expiration | string | The datetime when the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | string | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | string | The date and time the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 


#### Command Example
```!cs-falcon-update-ioc ioc_type="domain" value="test.domain.com" policy="detect" description="Benign domain IOC"```

#### Context Example
```json
{
    "CrowdStrike": {
        "IOC": {
            "CreatedTime": "2020-10-02T13:55:26Z",
            "Description": "Benign domain IOC",
            "Expiration": "2020-11-01T00:00:00Z",
            "ID": "domain:test.domain.com",
            "ModifiedTime": "2020-10-02T13:55:33Z",
            "Policy": "detect",
            "ShareLevel": "red",
            "Source": "Demisto playbook",
            "Type": "domain",
            "Value": "test.domain.com"
        }
    }
}
```

#### Human Readable Output

>### Custom IOC was created successfully
>|CreatedTime|Description|Expiration|ID|ModifiedTime|Policy|ShareLevel|Source|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|
>| 2020-10-02T13:55:26Z | Benign domain IOC | 2020-11-01T00:00:00Z | domain:test.domain.com | 2020-10-02T13:55:33Z | detect | red | Demisto playbook | domain | test.domain.com |


### 27. cs-falcon-delete-ioc
***
Deprecated. Use the cs-falcon-delete-custom-ioc command instead.


#### Base Command

`cs-falcon-delete-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The IOC type to delete. Possible values are: "sha256", "sha1", "md5", "domain", "ipv4", and "ipv6". | Required | 
| value | The string representation of the indicator to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cs-falcon-delete-ioc type="domain" value="test.domain.com"```


#### Human Readable Output

>Custom IOC domain:test.domain.com was successfully deleted.

### 28. cs-falcon-device-count-ioc
***
Number of hosts that observed the given IOC.


#### Base Command

`cs-falcon-device-count-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The IOC type. Possible values are: "sha256", "sha1", "md5", "domain", "ipv4", and "ipv6". | Required | 
| value | The string representation of the indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| <span>CrowdStrike.IOC.ID</span> | string | The full ID of the indicator \(type:value\). | 
| CrowdStrike.IOC.DeviceCount | number | The number of devices the IOC ran on. | 


#### Command Example
```!cs-falcon-device-count-ioc type="domain" value="value"```

#### Context Example
```json
{
    "CrowdStrike": {
        "IOC": {
            "DeviceCount": 1,
            "ID": "domain:value",
            "Type": "domain",
            "Value": "value"
        }
    }
}
```

#### Human Readable Output

>Indicator of Compromise **domain:value** device count: **1**

### 29. cs-falcon-processes-ran-on
***
Get processes associated with a given IOC.


#### Base Command

`cs-falcon-processes-ran-on`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The IOC type. Possible values are: "sha256", "sha1", "md5", "domain", "ipv4", and "ipv6". | Required | 
| value | The string representation of the indicator. | Required | 
| device_id | The device ID to check against. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| <span>CrowdStrike.IOC.ID</span> | string | The full ID of the indicator \(type:value\). | 
| <span>CrowdStrike.IOC.Process.ID</span> | number | The processes IDs associated with the given IOC. | 
| CrowdStrike.IOC.Process.DeviceID | number | The device the process ran on. | 


#### Command Example
```!cs-falcon-processes-ran-on device_id=15dbb9d8f06b45fe9f61eb46e829d986 type=domain value=value```

#### Context Example
```json
{
    "CrowdStrike": {
        "IOC": {
            "ID": "domain:value",
            "Process": {
                "DeviceID": "pid",
                "ID": [
                    "pid:pid:650164094720"
                ]
            },
            "Type": "domain",
            "Value": "value"
        }
    }
}
```

#### Human Readable Output

>### Processes with custom IOC domain:value on device device_id.
>|Process ID|
>|---|
>| pid:pid:650164094720 |


### 30. cs-falcon-process-details
***
Retrieves the details of a process, according to process ID, that is running or that previously ran.


#### Base Command

`cs-falcon-process-details`
#### Input

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of process IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Process.process_id | String | The process ID. | 
| CrowdStrike.Process.process_id_local | String | Local ID of the process. | 
| CrowdStrike.Process.device_id | String | The device the process ran on. | 
| CrowdStrike.Process.file_name | String | The path of the file that ran the process. | 
| CrowdStrike.Process.command_line | String | The command line command execution. | 
| CrowdStrike.Process.start_timestamp_raw | String | The start datetime of the process in Unix epoch time format. For example: 132460167512852140. | 
| CrowdStrike.Process.start_timestamp | String | The start datetime of the process in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.Process.stop_timestamp_raw | Date | The stop datetime of the process in Unix epoch time format. For example: 132460167512852140. | 
| CrowdStrike.Process.stop_timestamp | Date | The stop datetime of the process in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 


#### Command Example
```!cs-falcon-process-details ids="pid:pid:pid"```

#### Context Example
```json
{
    "CrowdStrike": {
        "Process": {
            "command_line": "\"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe\"",
            "device_id": "deviceId",
            "file_name": "\\Device\\HarddiskVolume1\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
            "process_id": "deviceId:pid",
            "process_id_local": "pid",
            "start_timestamp": "2020-10-01T09:05:51Z",
            "start_timestamp_raw": "132460167512852140",
            "stop_timestamp": "2020-10-02T06:43:45Z",
            "stop_timestamp_raw": "132460946259334768"
        }
    }
}
```

#### Human Readable Output

>### Details for process: pid:pid:pid.
>|command_line|device_id|file_name|process_id|process_id_local|start_timestamp|start_timestamp_raw|stop_timestamp|stop_timestamp_raw|
>|---|---|---|---|---|---|---|---|---|
>| "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" | deviceId | \Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe | device_id:pid | pid | 2020-10-01T09:05:51Z | 132460167512852140 | 2020-10-02T06:43:45Z | 132460946259334768 |


### 31. cs-falcon-device-ran-on
***
Returns a list of device IDs on which an indicator ran.


#### Base Command

`cs-falcon-device-ran-on`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of indicator. Possible values are: "domain", "ipv4", "ipv6", "md5", "sha1", or "sha256". | Required | 
| value | The string representation of the indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.DeviceID | string | Device IDs on which an indicator ran. | 


#### Command Example
```!cs-falcon-device-ran-on type=domain value=value```

#### Context Example
```json
{
    "CrowdStrike": {
        "DeviceID": [
            "15dbb9d8f06b45fe9f61eb46e829d986"
        ]
    }
}
```

#### Human Readable Output

>### Devices that encountered the IOC domain:value
>|Device ID|
>|---|
>| 15dbb9d8f06b45fe9f61eb46e829d986 |


### 32. cs-falcon-list-detection-summaries
***
Lists detection summaries.


#### Base Command

`cs-falcon-list-detection-summaries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fetch_query | The query used to filter the results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Detections.cid | String | The organization's customer ID \(CID\). | 
| CrowdStrike.Detections.created_timestamp | Date | The datetime when the detection occurred in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.Detections.detection_id | String | The ID of the detection. | 
| CrowdStrike.Detections.device.device_id | String | The device ID as seen by CrowdStrike. | 
| CrowdStrike.Detections.device.cid | String | The CrowdStrike Customer ID \(CID\) to which the device belongs. | 
| CrowdStrike.Detections.device.agent_load_flags | String | The CrowdStrike agent load flags. | 
| CrowdStrike.Detections.device.agent_local_time | Date | The local time of the sensor. | 
| CrowdStrike.Detections.device.agent_version | String | The version of the agent that the device is running. For example: 5.32.11406.0. | 
| CrowdStrike.Detections.device.bios_manufacturer | String | The BIOS manufacturer. | 
| CrowdStrike.Detections.device.bios_version | String | The device's BIOS version. | 
| CrowdStrike.Detections.device.config_id_base | String | The base of the sensor that the device is running. | 
| CrowdStrike.Detections.device.config_id_build | String | The version of the sensor that the device is running. For example: 11406. | 
| CrowdStrike.Detections.device.config_id_platform | String | The platform ID of the sensor that the device is running. | 
| CrowdStrike.Detections.device.external_ip | String | The external IP address of the device. | 
| CrowdStrike.Detections.device.hostname | String | The host name of the device. | 
| CrowdStrike.Detections.device.first_seen | Date | The datetime when the host was first seen by CrowdStrike. | 
| CrowdStrike.Detections.device.last_seen | Date | The datetime when the host was last seen by CrowdStrike. | 
| CrowdStrike.Detections.device.local_ip | String | The local IP address of the device. | 
| CrowdStrike.Detections.device.mac_address | String | The MAC address of the device. | 
| CrowdStrike.Detections.device.major_version | String | The major version of the operating system. | 
| CrowdStrike.Detections.device.minor_version | String | The minor version of the operating system. | 
| CrowdStrike.Detections.device.os_version | String | The operating system of the device. | 
| CrowdStrike.Detections.device.platform_id | String | The platform ID of the device that runs the sensor. | 
| CrowdStrike.Detections.device.platform_name | String | The platform name of the device. | 
| CrowdStrike.Detections.device.product_type_desc | String | The value indicating the product type. For example, 1 = Workstation, 2 = Domain Controller, 3 = Server. | 
| CrowdStrike.Detections.device.status | String | The containment status of the machine. Possible values are: "normal", "containment_pending", "contained", and "lift_containment_pending". | 
| CrowdStrike.Detections.device.system_manufacturer | String | The system manufacturer of the device. | 
| CrowdStrike.Detections.device.system_product_name | String | The product name of the system. | 
| CrowdStrike.Detections.device.modified_timestamp | Date | The datetime the device was last modified in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.Detections.behaviors.device_id | String | The ID of the device associated with the behavior. | 
| CrowdStrike.Detections.behaviors.timestamp | Date | The datetime the behavior detection occurred in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.Detections.behaviors.behavior_id | String | The ID of the behavior. | 
| CrowdStrike.Detections.behaviors.filename | String | The file name of the triggering process. | 
| CrowdStrike.Detections.behaviors.alleged_filetype | String | The file extension of the behavior's filename. | 
| CrowdStrike.Detections.behaviors.cmdline | String | The command line of the triggering process. | 
| CrowdStrike.Detections.behaviors.scenario | String | The name of the scenario to which the behavior belongs. | 
| CrowdStrike.Detections.behaviors.objective | String | The name of the objective associated with the behavior. | 
| CrowdStrike.Detections.behaviors.tactic | String | The name of the tactic associated with the behavior. | 
| CrowdStrike.Detections.behaviors.technique | String | The name of the technique associated with the behavior. | 
| CrowdStrike.Detections.behaviors.severity | Number | The severity rating for the behavior. The value can be any integer between 1-100. | 
| CrowdStrike.Detections.behaviors.confidence | Number | The true positive confidence rating for the behavior. The value can be any integer between 1-100. | 
| CrowdStrike.Detections.behaviors.ioc_type | String | The type of the triggering IOC. Possible values are: "hash_sha256", "hash_md5", "domain", "filename", "registry_key", "command_line", and "behavior". | 
| CrowdStrike.Detections.behaviors.ioc_value | String | The IOC value. | 
| CrowdStrike.Detections.behaviors.ioc_source | String | The source that triggered an IOC detection. Possible values are: "library_load", "primary_module", "file_read", and "file_write". | 
| CrowdStrike.Detections.behaviors.ioc_description | String | The IOC description. | 
| CrowdStrike.Detections.behaviors.user_name | String | The user name. | 
| CrowdStrike.Detections.behaviors.user_id | String | The Security Identifier \(SID\) of the user in Windows. | 
| CrowdStrike.Detections.behaviors.control_graph_id | String | The behavior hit key for the Threat Graph API. | 
| CrowdStrike.Detections.behaviors.triggering_process_graph_id | String | The ID of the process that triggered the behavior detection. | 
| CrowdStrike.Detections.behaviors.sha256 | String | The SHA256 of the triggering process. | 
| CrowdStrike.Detections.behaviors.md5 | String | The MD5 of the triggering process. | 
| CrowdStrike.Detections.behaviors.parent_details.parent_sha256 | String | The SHA256 hash of the parent process. | 
| CrowdStrike.Detections.behaviors.parent_details.parent_md5 | String | The MD5 hash of the parent process. | 
| CrowdStrike.Detections.behaviors.parent_details.parent_cmdline | String | The command line of the parent process. | 
| CrowdStrike.Detections.behaviors.parent_details.parent_process_graph_id | String | The process graph ID of the parent process. | 
| CrowdStrike.Detections.behaviors.pattern_disposition | Number | The pattern associated with the action performed on the behavior. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.indicator | Boolean | Whether the detection behavior is similar to an indicator. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.detect | Boolean | Whether this behavior is detected. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.inddet_mask | Boolean | Whether this behavior is an inddet mask. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.sensor_only | Boolean | Whether this detection is sensor only. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.rooting | Boolean | Whether this behavior is rooting. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.kill_process | Boolean | Whether this detection kills the process. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.kill_subprocess | Boolean | Whether this detection kills the subprocess. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.quarantine_machine | Boolean | Whether this detection was on a quarantined machine. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.quarantine_file | Boolean | Whether this detection was on a quarantined file. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.policy_disabled | Boolean | Whether this policy is disabled. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.kill_parent | Boolean | Whether this detection kills the parent process. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.operation_blocked | Boolean | Whether the operation is blocked. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.process_blocked | Boolean | Whether the process is blocked. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.registry_operation_blocked | Boolean | Whether the registry operation is blocked. | 
| CrowdStrike.Detections.email_sent | Boolean | Whether an email is sent about this detection. | 
| CrowdStrike.Detections.first_behavior | Date | The datetime of the first behavior. | 
| CrowdStrike.Detections.last_behavior | Date | The datetime of the last behavior. | 
| CrowdStrike.Detections.max_confidence | Number | The highest confidence value of all behaviors. The value can be any integer between 1-100. | 
| CrowdStrike.Detections.max_severity | Number | The highest severity value of all behaviors. Value can be any integer between 1-100. | 
| CrowdStrike.Detections.max_severity_displayname | String | The name used in the UI to determine the severity of the detection. Possible values are: "Critical", "High", "Medium", and "Low". | 
| CrowdStrike.Detections.show_in_ui | Boolean | Whether the detection displays in the UI. | 
| CrowdStrike.Detections.status | String | The status of detection. | 
| CrowdStrike.Detections.assigned_to_uid | String | The UID of the user for whom the detection is assigned. | 
| CrowdStrike.Detections.assigned_to_name | String | The human-readable name of the user to whom the detection is currently assigned. | 
| CrowdStrike.Detections.hostinfo.domain | String | The domain of the Active Directory. | 
| CrowdStrike.Detections.seconds_to_triaged | Number | The amount of time it took to move a detection from "new" to "in_progress". | 
| CrowdStrike.Detections.seconds_to_resolved | Number | The amount of time it took to move a detection from new to a resolved state \("true_positive", "false_positive", and "ignored"\). | 


#### Command Example
```!cs-falcon-list-detection-summaries```

#### Context Example
```json
{
    "CrowdStrike": {
        "Detections": [
            {
                "behaviors": [
                    {
                        "alleged_filetype": "exe",
                        "behavior_id": "10197",
                        "cmdline": "choice  /m crowdstrike_sample_detection",
                        "confidence": 80,
                        "control_graph_id": "ctg:ctg:ctg",
                        "device_id": "deviceid",
                        "display_name": "",
                        "filename": "choice.exe",
                        "filepath": "",
                        "ioc_description": "",
                        "ioc_source": "",
                        "ioc_type": "",
                        "ioc_value": "",
                        "md5": "md5",
                        "objective": "Falcon Detection Method",
                        "parent_details": {
                            "parent_cmdline": "\"C:\\Windows\\system32\\cmd.exe\" ",
                            "parent_md5": "md5",
                            "parent_process_graph_id": "pid:pid:pid",
                            "parent_sha256": "sha256"
                        },
                        "pattern_disposition": 0,
                        "pattern_disposition_details": {
                            "bootup_safeguard_enabled": false,
                            "critical_process_disabled": false,
                            "detect": false,
                            "fs_operation_blocked": false,
                            "inddet_mask": false,
                            "indicator": false,
                            "kill_parent": false,
                            "kill_process": false,
                            "kill_subprocess": false,
                            "operation_blocked": false,
                            "policy_disabled": false,
                            "process_blocked": false,
                            "quarantine_file": false,
                            "quarantine_machine": false,
                            "registry_operation_blocked": false,
                            "rooting": false,
                            "sensor_only": false
                        },
                        "scenario": "suspicious_activity",
                        "severity": 30,
                        "sha256": "sha256",
                        "tactic": "Malware",
                        "tactic_id": "",
                        "technique": "Malicious File",
                        "technique_id": "",
                        "template_instance_id": "382",
                        "timestamp": "2020-07-06T08:10:44Z",
                        "triggering_process_graph_id": "pid:pid:pid",
                        "user_id": "user_id",
                        "user_name": "user_name"
                    }
                ],
                "behaviors_processed": [
                    "pid:pid:pid:10197"
                ],
                "cid": "cid",
                "created_timestamp": "2020-07-06T08:10:55.538668036Z",
                "detection_id": "ldt:ldt:ldt",
                "device": {
                    "agent_load_flags": "0",
                    "agent_local_time": "2020-07-02T01:42:07.640Z",
                    "agent_version": "5.32.11406.0",
                    "bios_manufacturer": "Google",
                    "bios_version": "Google",
                    "cid": "cid",
                    "config_id_base": "id",
                    "config_id_build": "id",
                    "config_id_platform": "3",
                    "device_id": "device_id",
                    "external_ip": "external_ip",
                    "first_seen": "2020-02-10T12:40:18Z",
                    "hostname": "FALCON-CROWDSTR",
                    "last_seen": "2020-07-06T07:59:12Z",
                    "local_ip": "local_ip",
                    "mac_address": "mac_address",
                    "major_version": "major_version",
                    "minor_version": "minor_version",
                    "modified_timestamp": "modified_timestamp",
                    "os_version": "os_version",
                    "platform_id": "platform_id",
                    "platform_name": "platform_name",
                    "product_type": "product_type",
                    "product_type_desc": "product_type_desc",
                    "status": "status",
                    "system_manufacturer": "system_manufacturer",
                    "system_product_name": "system_product_name"
                },
                "email_sent": false,
                "first_behavior": "2020-07-06T08:10:44Z",
                "hostinfo": {
                    "domain": ""
                },
                "last_behavior": "2020-07-06T08:10:44Z",
                "max_confidence": 80,
                "max_severity": 30,
                "max_severity_displayname": "Low",
                "seconds_to_resolved": 0,
                "seconds_to_triaged": 0,
                "show_in_ui": true,
                "status": "new"
            }
        ]
    }
}
```

#### Human Readable Output

>### CrowdStrike Detections
>|detection_id|created_time|status|max_severity|
>|---|---|---|---|
>| ldt:ldt:ldt | 2020-07-06T08:10:55.538668036Z | new | Low |


### 33. cs-falcon-list-incident-summaries
***
Lists incident summaries.


#### Base Command

`cs-falcon-list-incident-summaries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fetch_query | The query used to filter the results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Incidents.incident_id | String | The ID of the incident. | 
| CrowdStrike.Incidents.cid | String | The organization's customer ID \(CID\). | 
| CrowdStrike.Incidents.host_ids | String | The device IDs of all the hosts on which the incident occurred. | 
| CrowdStrike.Incidents.hosts.device_id | String | The device ID as seen by CrowdStrike. | 
| CrowdStrike.Incidents.hosts.cid | String | The host's organization's customer ID \(CID\). | 
| CrowdStrike.Incidents.hosts.agent_load_flags | String | The CrowdStrike agent load flags. | 
| CrowdStrike.Incidents.hosts.agent_local_time | Date | The local time of the sensor. | 
| CrowdStrike.Incidents.hosts.agent_version | String | The version of the agent that the device is running. For example: 5.32.11406.0. | 
| CrowdStrike.Incidents.hosts.bios_manufacturer | String | The BIOS manufacturer. | 
| CrowdStrike.Incidents.hosts.bios_version | String | The BIOS version of the device. | 
| CrowdStrike.Incidents.hosts.config_id_base | String | The base of the sensor that the device is running. | 
| CrowdStrike.Incidents.hosts.config_id_build | String | The version of the sensor that the device is running. For example: 11406. | 
| CrowdStrike.Incidents.hosts.config_id_platform | String | The platform ID of the sensor that the device is running. | 
| CrowdStrike.Incidents.hosts.external_ip | String | The external IP address of the host. | 
| CrowdStrike.Incidents.hosts.hostname | String | The name of the host. | 
| CrowdStrike.Incidents.hosts.first_seen | Date | The date and time when the host was first seen by CrowdStrike. | 
| CrowdStrike.Incidents.hosts.last_seen | Date | The date and time when the host was last seen by CrowdStrike. | 
| CrowdStrike.Incidents.hosts.local_ip | String | The device's local IP address. | 
| CrowdStrike.Incidents.hosts.mac_address | String | The device's MAC address. | 
| CrowdStrike.Incidents.hosts.major_version | String | The major version of the operating system. | 
| CrowdStrike.Incidents.hosts.minor_version | String | The minor version of the operating system. | 
| CrowdStrike.Incidents.hosts.os_version | String | The operating system of the host. | 
| CrowdStrike.Incidents.hosts.platform_id | String | The platform ID of the device that runs the sensor. | 
| CrowdStrike.Incidents.hosts.platform_name | String | The platform name of the host. | 
| CrowdStrike.Incidents.hosts.product_type_desc | String | The value indicating the product type. For example, 1 = Workstation, 2 = Domain Controller, 3 = Server. | 
| CrowdStrike.Incidents.hosts.status | String | The incident status as a number. For example, 20 = New, 25 = Reopened, 30 = In Progress, 40 = Closed. | 
| CrowdStrike.Incidents.hosts.system_manufacturer | String | The system manufacturer of the device. | 
| CrowdStrike.Incidents.hosts.system_product_name | String | The product name of the system. | 
| CrowdStrike.Incidents.hosts.modified_timestamp | Date | The datetime when a user modified the incident in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.Incidents.created | Date | The time that the incident was created. | 
| CrowdStrike.Incidents.start | Date | The recorded time of the earliest incident. | 
| CrowdStrike.Incidents.end | Date | The recorded time of the latest incident. | 
| CrowdStrike.Incidents.state | String | The state of the incident. | 
| CrowdStrike.Incidents.status | Number | The status of the incident. | 
|<span>CrowdStrike.Incidents.name</span> | String | The name of the incident. | 
| CrowdStrike.Incidents.description | String | The description of the incident. | 
| CrowdStrike.Incidents.tags | String | The tags of the incident. | 
| CrowdStrike.Incidents.fine_score | Number | The incident score. | 


#### Command Example
```!cs-falcon-list-incident-summaries```


### 34. Endpoint
***
Lists incident summaries.

#### Base Command

`endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Endpoint ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The endpoint's hostname. | 
| Endpoint.OS | String | The endpoint's operation system. | 
| Endpoint.OSVersion | String | The endpoint's operation system version. | 
| Endpoint.IPAddress | String | The endpoint's IP address. | 
| Endpoint.ID | String | The endpoint's ID. | 
| Endpoint.Status | String | The endpoint's status. | 
| Endpoint.IsIsolated | String | The endpoint's isolation status. | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 


#### Command Example
```!endpoint id=15dbb9d5fe9f61eb46e829d986```

#### Context Example
```json
{
  "Endpoint":
    {
      "Hostname": "Hostname",
      "ID": "15dbb9d5fe9f61eb46e829d986",
      "IPAddress": "1.1.1.1",
      "OS": "Windows",
      "OSVersion": "Windows Server 2019",
      "Status": "Online",
      "￿Vendor": "CrowdStrike Falcon",
      "￿MACAddress": "1-1-1-1"
    }
}
```

#### Human Readable Output

>### Endpoints
>|ID|IPAddress|OS|OSVersion|Hostname|Status|MACAddress|Vendor
>|---|---|---|---|---|---|---|---|
>| 15dbb9d8f06b45fe9f61eb46e829d986 | 1.1.1.1 | Windows | Windows Server 2019| Hostname | Online | 1-1-1-1 | CrowdStrike Falcon|\n"
### cs-falcon-create-host-group
***
Create a host group


#### Base Command

`cs-falcon-create-host-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the host. | Required | 
| group_type | The group type of the group. Can be 'static' or 'dynamic'. Possible values are: static, dynamic. | Optional | 
| description | The description of the host. | Optional | 
| assignment_rule | The assignment rule. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.HostGroup.id | String | The ID of the host group. | 
| CrowdStrike.HostGroup.group_type | String | The group type of the host group. | 
| CrowdStrike.HostGroup.name | String | The name of the host group. | 
| CrowdStrike.HostGroup.description | String | The description of the host group. | 
| CrowdStrike.HostGroup.created_by | String | The client that created the host group. | 
| CrowdStrike.HostGroup.created_timestamp | Date | 'The datetime when the host group was created in ISO time format. For example: 2019-10-17T13:41:48.487520845Z.' | 
| CrowdStrike.HostGroup.modified_by | String | The client that modified the host group. | 
| CrowdStrike.HostGroup.modified_timestamp | Date | 'The datetime when the host group was last modified in ISO time format. For example: 2019-10-17T13:41:48.487520845Z.' | 


#### Command Example
```!cs-falcon-create-host-group name="test_name_1" description="test_description" group_type=static```

#### Context Example
```json
{
    "CrowdStrike": {
        "HostGroup": {
            "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
            "created_timestamp": "2021-08-25T08:02:02.060242909Z",
            "description": "test_description",
            "group_type": "static",
            "id": "f82edc8a565d432a8114ebdbf255f5b2",
            "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
            "modified_timestamp": "2021-08-25T08:02:02.060242909Z",
            "name": "test_name_1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|created_by|created_timestamp|description|group_type|id|modified_by|modified_timestamp|name|
>|---|---|---|---|---|---|---|---|
>| api-client-id:2bf188d347e44e08946f2e61ef590c24 | 2021-08-25T08:02:02.060242909Z | test_description | static | f82edc8a565d432a8114ebdbf255f5b2 | api-client-id:2bf188d347e44e08946f2e61ef590c24 | 2021-08-25T08:02:02.060242909Z | test_name_1 |

### cs-falcon-update-host-group
***
Update a host group.


#### Base Command

`cs-falcon-update-host-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_group_id | The ID of the host group. | Required | 
| name | The name of the host group. | Optional | 
| description | The description of the host group. | Optional | 
| assignment_rule | The assignment rule. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.HostGroup.id | String | The ID of the host group. | 
| CrowdStrike.HostGroup.group_type | String | The group type of the host group. | 
| CrowdStrike.HostGroup.name | String | The name of the host group. | 
| CrowdStrike.HostGroup.description | String | The description of the host group. | 
| CrowdStrike.HostGroup.created_by | String | The client that created the host group. | 
| CrowdStrike.HostGroup.created_timestamp | Date | 'The datetime when the host group was created in ISO time format. For
        example: 2019-10-17T13:41:48.487520845Z.' | 
| CrowdStrike.HostGroup.modified_by | String | The client that modified the host group. | 
| CrowdStrike.HostGroup.modified_timestamp | Date | 'The datetime when the host group was last modified in ISO time format.
        For example: 2019-10-17T13:41:48.487520845Z.' | 


#### Command Example
```!cs-falcon-update-host-group host_group_id=4902d5686bed41ba88a37439f38913ba name="test_name_update_1" description="test_description_update"```

#### Context Example
```json
{
    "CrowdStrike": {
        "HostGroup": {
            "assignment_rule": "device_id:[''],hostname:['']",
            "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
            "created_timestamp": "2021-08-22T07:48:35.111070562Z",
            "description": "test_description_update",
            "group_type": "static",
            "id": "4902d5686bed41ba88a37439f38913ba",
            "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
            "modified_timestamp": "2021-08-25T08:02:05.295663156Z",
            "name": "test_name_update_1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|assignment_rule|created_by|created_timestamp|description|group_type|id|modified_by|modified_timestamp|name|
>|---|---|---|---|---|---|---|---|---|
>| device_id:[''],hostname:[''] | api-client-id:2bf188d347e44e08946f2e61ef590c24 | 2021-08-22T07:48:35.111070562Z | test_description_update | static | 4902d5686bed41ba88a37439f38913ba | api-client-id:2bf188d347e44e08946f2e61ef590c24 | 2021-08-25T08:02:05.295663156Z | test_name_update_1 |

### cs-falcon-list-host-group-members
***
Get the list of host group members.


#### Base Command

`cs-falcon-list-host-group-members`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_group_id | The ID of the host group. | Optional | 
| filter | The query by which to filter the devices that belong to the host group. | Optional | 
| offset | Page offset. | Optional | 
| limit | Maximum number of results on a page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Device.ID | String | The ID of the device. | 
| CrowdStrike.Device.LocalIP | String | The local IP address of the device. | 
| CrowdStrike.Device.ExternalIP | String | The external IP address of the device. | 
| CrowdStrike.Device.Hostname | String | The host name of the device. | 
| CrowdStrike.Device.OS | String | The operating system of the device. | 
| CrowdStrike.Device.MacAddress | String | The MAC address of the device. | 
| CrowdStrike.Device.FirstSeen | String | The first time the device was seen. | 
| CrowdStrike.Device.LastSeen | String | The last time the device was seen. | 
| CrowdStrike.Device.Status | String | The device status. | 


#### Command Example
```!cs-falcon-list-host-group-members```

#### Context Example
```json
{
    "CrowdStrike": {
        "Device": [
            {
                "ExternalIP": "35.224.136.145",
                "FirstSeen": "2021-08-12T16:13:26Z",
                "Hostname": "FALCON-CROWDSTR",
                "ID": "75b2dba7ba8d450da481ed6830cc9d9d",
                "LastSeen": "2021-08-23T04:59:48Z",
                "LocalIP": "10.128.0.21",
                "MacAddress": "42-01-0a-80-00-15",
                "OS": "Windows Server 2019",
                "Status": "normal"
            },
            {
                "ExternalIP": "35.224.136.145",
                "FirstSeen": "2020-02-10T12:40:18Z",
                "Hostname": "FALCON-CROWDSTR",
                "ID": "15dbb9d8f06b45fe9f61eb46e829d986",
                "LastSeen": "2021-08-25T07:42:47Z",
                "LocalIP": "10.128.0.7",
                "MacAddress": "42-01-0a-80-00-07",
                "OS": "Windows Server 2019",
                "Status": "contained"
            },
            {
                "ExternalIP": "35.224.136.145",
                "FirstSeen": "2021-08-23T05:04:41Z",
                "Hostname": "INSTANCE-1",
                "ID": "046761c46ec84f40b27b6f79ce7cd32c",
                "LastSeen": "2021-08-25T07:49:06Z",
                "LocalIP": "10.128.0.20",
                "MacAddress": "42-01-0a-80-00-14",
                "OS": "Windows Server 2019",
                "Status": "normal"
            },
            {
                "ExternalIP": "35.224.136.145",
                "FirstSeen": "2021-08-11T13:57:29Z",
                "Hostname": "INSTANCE-1",
                "ID": "07007dd3f95c4d628fb097072bf7f7f3",
                "LastSeen": "2021-08-23T04:45:37Z",
                "LocalIP": "10.128.0.20",
                "MacAddress": "42-01-0a-80-00-14",
                "OS": "Windows Server 2019",
                "Status": "normal"
            },
            {
                "ExternalIP": "35.224.136.145",
                "FirstSeen": "2021-08-08T11:33:21Z",
                "Hostname": "falcon-crowdstrike-sensor-centos7",
                "ID": "0bde2c4645294245aca522971ccc44c4",
                "LastSeen": "2021-08-25T07:50:47Z",
                "LocalIP": "10.128.0.19",
                "MacAddress": "42-01-0a-80-00-13",
                "OS": "CentOS 7.9",
                "Status": "normal"
            }
        ]
    }
}
```

#### Human Readable Output

>### Devices
>|ID|External IP|Local IP|Hostname|OS|Mac Address|First Seen|Last Seen|Status|
>|---|---|---|---|---|---|---|---|---|
>| 0bde2c4645294245aca522971ccc44c4 | 35.224.136.145 | 10.128.0.19 | falcon-crowdstrike-sensor-centos7 | CentOS 7.9 | 42-01-0a-80-00-13 | 2021-08-08T11:33:21Z | 2021-08-25T07:50:47Z | normal |

### cs-falcon-add-host-group-members
***
Add host group members.


#### Base Command

`cs-falcon-add-host-group-members`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_group_id | The ID of the host group. | Required | 
| host_ids | A comma-separated list of host agent IDs to run commands.(The list of host agent IDs can be retrieved by running the 'cs-falcon-search-device' command.) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.HostGroup.id | String | The ID of the host group. | 
| CrowdStrike.HostGroup.group_type | String | The group type of the host group. | 
| CrowdStrike.HostGroup.name | String | The name of the host group. | 
| CrowdStrike.HostGroup.description | String | The description of the host group. | 
| CrowdStrike.HostGroup.created_by | String | The client that created the host group. | 
| CrowdStrike.HostGroup.created_timestamp | Date | 'The datetime when the host group was created in ISO time format. For
        example: 2019-10-17T13:41:48.487520845Z.' | 
| CrowdStrike.HostGroup.modified_by | String | The client that modified the host group. | 
| CrowdStrike.HostGroup.modified_timestamp | Date | 'The datetime when the host group was last modified in ISO time format.
        For example: 2019-10-17T13:41:48.487520845Z.' | 


#### Command Example
```!cs-falcon-add-host-group-members host_group_id="4902d5686bed41ba88a37439f38913ba" host_ids="0bde2c4645294245aca522971ccc44c4"```

#### Context Example
```json
{
    "CrowdStrike": {
        "HostGroup": {
            "assignment_rule": "device_id:[''],hostname:['falcon-crowdstrike-sensor-centos7','']",
            "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
            "created_timestamp": "2021-08-22T07:48:35.111070562Z",
            "description": "test_description_update",
            "group_type": "static",
            "id": "4902d5686bed41ba88a37439f38913ba",
            "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
            "modified_timestamp": "2021-08-25T08:02:05.295663156Z",
            "name": "test_name_update_1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|assignment_rule|created_by|created_timestamp|description|group_type|id|modified_by|modified_timestamp|name|
>|---|---|---|---|---|---|---|---|---|
>| device_id:[''],hostname:['falcon-crowdstrike-sensor-centos7',''] | api-client-id:2bf188d347e44e08946f2e61ef590c24 | 2021-08-22T07:48:35.111070562Z | test_description_update | static | 4902d5686bed41ba88a37439f38913ba | api-client-id:2bf188d347e44e08946f2e61ef590c24 | 2021-08-25T08:02:05.295663156Z | test_name_update_1 |

### cs-falcon-remove-host-group-members
***
Remove host group members.


#### Base Command

`cs-falcon-remove-host-group-members`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_group_id | The ID of the host group. | Required | 
| host_ids | A comma-separated list of host agent IDs to run commands. (The list of host agent IDs can be retrieved by running the 'cs-falcon-search-device' command.)| Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.HostGroup.id | String | The ID of the host group. | 
| CrowdStrike.HostGroup.group_type | String | The group type of the host group. | 
| CrowdStrike.HostGroup.name | String | The name of the host group. | 
| CrowdStrike.HostGroup.description | String | The description of the host group. | 
| CrowdStrike.HostGroup.created_by | String | The client that created the host group. | 
| CrowdStrike.HostGroup.created_timestamp | Date | 'The datetime when the host group was created in ISO time format. For
        example: 2019-10-17T13:41:48.487520845Z.' | 
| CrowdStrike.HostGroup.modified_by | String | The client that modified the host group. | 
| CrowdStrike.HostGroup.modified_timestamp | Date | 'The datetime when the host group was last modified in ISO time format.
        For example: 2019-10-17T13:41:48.487520845Z.' | 


#### Command Example
```!cs-falcon-remove-host-group-members host_group_id="4902d5686bed41ba88a37439f38913ba" host_ids="0bde2c4645294245aca522971ccc44c4"```

#### Context Example
```json
{
    "CrowdStrike": {
        "HostGroup": {
            "assignment_rule": "device_id:[''],hostname:['']",
            "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
            "created_timestamp": "2021-08-22T07:48:35.111070562Z",
            "description": "test_description_update",
            "group_type": "static",
            "id": "4902d5686bed41ba88a37439f38913ba",
            "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
            "modified_timestamp": "2021-08-25T08:02:05.295663156Z",
            "name": "test_name_update_1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|assignment_rule|created_by|created_timestamp|description|group_type|id|modified_by|modified_timestamp|name|
>|---|---|---|---|---|---|---|---|---|
>| device_id:[''],hostname:[''] | api-client-id:2bf188d347e44e08946f2e61ef590c24 | 2021-08-22T07:48:35.111070562Z | test_description_update | static | 4902d5686bed41ba88a37439f38913ba | api-client-id:2bf188d347e44e08946f2e61ef590c24 | 2021-08-25T08:02:05.295663156Z | test_name_update_1 |

### cs-falcon-resolve-incident
***
Resolve incidents


#### Base Command

`cs-falcon-resolve-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of incident IDs. | Required | 
| status | The new status of the incident. Can be "New", "In Progress", "Reopened", "Closed". Possible values are: New, In Progress, Reopened, Closed. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cs-falcon-resolve-incident ids="inc:0bde2c4645294245aca522971ccc44c4:f3825bf7df684237a1eb62b39124ebef,inc:07007dd3f95c4d628fb097072bf7f7f3:ecd5c5acd4f042e59be2f990e9ada258" status="Closed"```

#### Human Readable Output

>inc:0bde2c4645294245aca522971ccc44c4:f3825bf7df684237a1eb62b39124ebef changed successfully to Closed
>inc:07007dd3f95c4d628fb097072bf7f7f3:ecd5c5acd4f042e59be2f990e9ada258 changed successfully to Closed
### cs-falcon-list-host-groups
***
List the available host groups.


#### Base Command

`cs-falcon-list-host-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | The query by which to filter the devices that belong to the host group. | Optional | 
| offset | Page offset. | Optional | 
| limit | Maximum number of results on a page. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.HostGroup.id | String | The ID of the host group. | 
| CrowdStrike.HostGroup.group_type | String | The group type of the host group. | 
| CrowdStrike.HostGroup.name | String | The name of the host group. | 
| CrowdStrike.HostGroup.description | String | The description of the host group. | 
| CrowdStrike.HostGroup.created_by | String | The client that created the host group. | 
| CrowdStrike.HostGroup.created_timestamp | Date | The datetime when the host group was created in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.HostGroup.modified_by | String | The client that modified the host group. | 
| CrowdStrike.HostGroup.modified_timestamp | Date | The datetime when the host group was last modified in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 


#### Command Example
```!cs-falcon-list-host-groups```

#### Context Example
```json
{
    "CrowdStrike": {
        "HostGroup": [
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T14:35:23.765624811Z",
                "description": "description",
                "group_type": "static",
                "id": "d70fa742d28a4e6cb0d33b7af599783d",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T14:35:23.765624811Z",
                "name": "InnerServicesModuleMon Aug 23 2021"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T14:35:25.506030441Z",
                "description": "description",
                "group_type": "static",
                "id": "d0ff99dfd3884fba87424c03686e45b6",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T14:35:25.506030441Z",
                "name": "Rasterize_default_instanceMon Aug 23 2021"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['','FALCON-CROWDSTR']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-07-27T12:34:59.13917402Z",
                "description": "",
                "group_type": "static",
                "id": "1fc2e6e1e9c24c5d8d9ce52a9fa8e507",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-07-27T12:34:59.13917402Z",
                "name": "Static by id group test"
            },
            {
                "assignment_rule": "device_id:[],hostname:[]",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-07-27T12:24:18.364057533Z",
                "description": "Group test",
                "group_type": "static",
                "id": "11dbab2a65054041b4e949768aaed0df",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-07-27T12:24:18.364057533Z",
                "name": "Static group test"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T14:35:26.069515348Z",
                "description": "description",
                "group_type": "static",
                "id": "09c88625e1ab49e4bbd525f836f610a7",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T14:35:26.069515348Z",
                "name": "ad-loginMon Aug 23 2021"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T14:35:25.556897468Z",
                "description": "description",
                "group_type": "static",
                "id": "af0e040d7bb04af7bb00da83e4c0e8f2",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T14:35:25.556897468Z",
                "name": "ad-queryMon Aug 23 2021"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T14:35:23.737307612Z",
                "description": "description",
                "group_type": "static",
                "id": "09d2a0d3db384021906db6d3c3a2afcb",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T14:35:23.737307612Z",
                "name": "d2Mon Aug 23 2021"
            },
            {
                "created_by": "akrupnik@paloaltonetworks.com",
                "created_timestamp": "2021-07-27T12:27:43.503021999Z",
                "description": "dhfh",
                "group_type": "staticByID",
                "id": "79843d26a16c4530becc218a791f642c",
                "modified_by": "akrupnik@paloaltonetworks.com",
                "modified_timestamp": "2021-07-27T12:27:43.503021999Z",
                "name": "ddfxgh"
            },
            {
                "assignment_rule": "device.hostname:'FALCON-CROWDSTR'",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-07-27T12:46:39.058352326Z",
                "description": "",
                "group_type": "dynamic",
                "id": "5d88a39652d24de2be42b14b427cc9e3",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-07-27T12:46:39.058352326Z",
                "name": "dynamic 1 group test"
            },
            {
                "assignment_rule": "lkjlk:'FalconGroupingTags/example_tag'",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T13:12:56.338590022Z",
                "description": "",
                "group_type": "dynamic",
                "id": "2f2d825c1bdb42338531c1679557aa1e",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T13:12:56.338590022Z",
                "name": "dynamic 13523 group test"
            },
            {
                "assignment_rule": "lkjlk:'FalconGroupingTags/example_tag'",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-07-27T14:02:05.538065349Z",
                "description": "",
                "group_type": "dynamic",
                "id": "cefe41dfa96a4e60bb1f08b98e1ba232",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-07-27T14:02:05.538065349Z",
                "name": "dynamic 1353 group test"
            },
            {
                "assignment_rule": "tags:'FalconGroupingTags/example_tag'",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-07-27T12:41:33.127997409Z",
                "description": "",
                "group_type": "dynamic",
                "id": "9e9c3cf9a9664d0c8c5c7d8b38546635",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-07-27T12:41:33.127997409Z",
                "name": "dynamic 2 group test"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T14:35:23.7402217Z",
                "description": "description",
                "group_type": "static",
                "id": "f43a275267d74157bbb33bf69d640c4d",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T14:35:23.7402217Z",
                "name": "fcm_default_instanceMon Aug 23 2021"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-11T09:55:23.801049103Z",
                "description": "ilan test",
                "group_type": "dynamic",
                "id": "370322c647374bb298a6a14374bbdfd5",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-11T09:55:23.801049103Z",
                "name": "ilan"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-12T11:24:51.434863056Z",
                "description": "ilan test",
                "group_type": "dynamic",
                "id": "545f5d385b494f3ebf355adefed8ed4a",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-12T11:24:51.434863056Z",
                "name": "ilan 2"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['FALCON-CROWDSTR']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-12T11:55:57.943490809Z",
                "description": "ilan test",
                "group_type": "dynamic",
                "id": "d99b77530ef34a6a8718a60817d72a8f",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-12T11:55:57.943490809Z",
                "name": "ilan 23"
            },
            {
                "assignment_rule": "",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-17T11:28:39.855075106Z",
                "description": "after change",
                "group_type": "dynamic",
                "id": "8a3c2cdeb7524a109bbb44f64b3da814",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T09:26:15.351650252Z",
                "name": "ilan 2345"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-17T11:58:42.453661998Z",
                "description": "ilan test",
                "group_type": "static",
                "id": "b1a0cd73ecab411581cbe467fc3319f5",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-17T11:58:42.453661998Z",
                "name": "ilan 23e"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-11T13:54:59.695821727Z",
                "description": "",
                "group_type": "static",
                "id": "d3fd5d87d317419db20f17dcf6f0d81e",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-11T13:54:59.695821727Z",
                "name": "ilan test 2"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-12T10:56:49.2127345Z",
                "description": "ilan test",
                "group_type": "dynamic",
                "id": "c2c49a308ed446589222b4e30131bee0",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-12T11:35:35.76509212Z",
                "name": "ilan2"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T14:35:23.766284685Z",
                "description": "description",
                "group_type": "static",
                "id": "39def881ea5846f2a2f763bad8ee3468",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T14:35:23.766284685Z",
                "name": "splunkMon Aug 23 2021"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:09:15.36414377Z",
                "description": "description",
                "group_type": "static",
                "id": "7fb5e2b9f1af477f985d4760a92affe4",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:09:15.36414377Z",
                "name": "test_1629731353498"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:12:20.69203954Z",
                "description": "description",
                "group_type": "static",
                "id": "5a47bfc13dc34576a9ba7134744855a7",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:12:20.69203954Z",
                "name": "test_1629731538458"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:14:20.650781714Z",
                "description": "description2",
                "group_type": "static",
                "id": "be91aa4837614069a7452023f19164af",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:14:23.026511269Z",
                "name": "test_16297316587261629731658726"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:18:53.896505566Z",
                "description": "description2",
                "group_type": "static",
                "id": "f2f7132beb0743b4889921149a97ca6b",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:18:56.2598933Z",
                "name": "test_16297319320381629731932038"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:19:51.91067257Z",
                "description": "description2",
                "group_type": "static",
                "id": "055de83f2f704b5f85d7ddbc2a163697",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:19:54.269898808Z",
                "name": "test_16297319902371629731990237"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:25:42.99601887Z",
                "description": "description",
                "group_type": "static",
                "id": "9b22f3c6b5864d17b54740a067a0ed17",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:25:42.99601887Z",
                "name": "test_1629732339973"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:26:12.280379354Z",
                "description": "description2",
                "group_type": "static",
                "id": "c929e5f5b5fd4b8ab71ceb4af853cbc0",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:26:14.973676462Z",
                "name": "test_16297323698941629732369894"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:26:58.717706381Z",
                "description": "description2",
                "group_type": "static",
                "id": "d9539d6a273b4f3dbfb1746e7e0c2ec6",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:27:01.648623079Z",
                "name": "test_16297324168771629732416877"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:28:18.674512647Z",
                "description": "description2",
                "group_type": "static",
                "id": "bc4572145fe148059d4a709206232dbc",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:28:21.781563212Z",
                "name": "test_16297324965761629732496576"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['FALCON-CROWDSTR','INSTANCE-1','falcon-crowdstrike-sensor-centos7']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:31:41.142748214Z",
                "description": "description2",
                "group_type": "static",
                "id": "af60190df8d4437c96ae8d1ef946f3cf",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:31:43.800147323Z",
                "name": "test_16297326990981629732699098"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:34:20.195778795Z",
                "description": "description2",
                "group_type": "static",
                "id": "b0fe6af9bad34688844daf3cec6acef0",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:34:23.212828317Z",
                "name": "test_16297328579781629732857978"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:34:55.837119719Z",
                "description": "description2",
                "group_type": "static",
                "id": "9dd1ecf3cdb540a48a82660be22f1039",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:34:58.490114093Z",
                "name": "test_16297328938791629732893879"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-23T15:37:42.911344704Z",
                "description": "description2",
                "group_type": "static",
                "id": "1bcd536b2b4545b9b9373aa29e8ee676",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-23T15:37:45.620464598Z",
                "name": "test_16297330605301629733060530"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-24T07:05:55.813475476Z",
                "description": "description2",
                "group_type": "static",
                "id": "9333f3df1b2b4905ae4abc532a438cdb",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-24T07:05:58.805702883Z",
                "name": "test_16297887501421629788750142"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-24T07:07:30.422517324Z",
                "description": "description2",
                "group_type": "static",
                "id": "d193ffdeac4f45afbdeb2f0b3ebcb78c",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-24T07:07:34.291988227Z",
                "name": "test_16297888481381629788848138"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-24T08:03:15.522772079Z",
                "description": "description2",
                "group_type": "static",
                "id": "ee2bbca82b44413dab8ddb112e34454a",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-24T08:03:18.622015517Z",
                "name": "test_16297921932741629792193274"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T09:09:52.379925975Z",
                "description": "description",
                "group_type": "static",
                "id": "ba4f6fd641784dc787f4a19f0488e400",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T09:09:52.379925975Z",
                "name": "test_1629967211800"
            },
            {
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T12:34:36.934507422Z",
                "description": "description",
                "group_type": "static",
                "id": "beabe1b9a09d4591bff9d080a96e46e3",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T12:34:36.934507422Z",
                "name": "test_162996721180000"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T08:46:09.996065663Z",
                "description": "description2",
                "group_type": "static",
                "id": "a853d878f8e94093b42cd49e04e7f7f6",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T08:46:11.572092204Z",
                "name": "test_16299675695531629967569553"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T08:53:15.35181954Z",
                "description": "description2",
                "group_type": "static",
                "id": "95dd4fd340054a108e8363d2bf5d6e5e",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T08:53:17.041535905Z",
                "name": "test_16299679949831629967994983"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T08:59:52.639696743Z",
                "description": "description2",
                "group_type": "static",
                "id": "e512275c2dc1450ea6133d7c6e77cae5",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T08:59:54.538170036Z",
                "name": "test_16299683923121629968392312"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T09:06:21.891707157Z",
                "description": "description2",
                "group_type": "static",
                "id": "724cf2a7106241b4a3d4139d2a264f11",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T09:06:23.846219163Z",
                "name": "test_16299687814871629968781487"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T09:12:53.982989Z",
                "description": "description2",
                "group_type": "static",
                "id": "e8f2ec25841e4d93bb07dbe6aa326742",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T09:12:55.571265187Z",
                "name": "test_16299691732871629969173287"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T09:17:58.206157753Z",
                "description": "description2",
                "group_type": "static",
                "id": "25141ce104e445849d05a4149ea019ea",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T09:17:59.659515838Z",
                "name": "test_16299694779051629969477905"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T09:19:23.276267291Z",
                "description": "description2",
                "group_type": "static",
                "id": "09bfcc12e3b046ddaea45a5d216f9581",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T09:19:25.318976241Z",
                "name": "test_16299695623981629969562398"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T09:26:22.538367707Z",
                "description": "description2",
                "group_type": "static",
                "id": "62e4b5a4764e4313b540664b5be3fea2",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T09:26:25.085214782Z",
                "name": "test_16299699813871629969981387"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T09:33:46.303790983Z",
                "description": "description2",
                "group_type": "static",
                "id": "b214e5c58229462b96e580c5934c20db",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T09:33:48.288311235Z",
                "name": "test_16299704254441629970425444"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T09:55:09.157561612Z",
                "description": "description2",
                "group_type": "static",
                "id": "9a7291431c3046ccb7b750240f924854",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T09:55:10.741852436Z",
                "name": "test_16299717065381629971706538"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "created_timestamp": "2021-08-26T10:02:50.175530821Z",
                "description": "description2",
                "group_type": "static",
                "id": "29ae859b9a01409d83bf7fb7f7a04c69",
                "modified_by": "api-client-id:2bf188d347e44e08946f2e61ef590c24",
                "modified_timestamp": "2021-08-26T10:02:52.026307768Z",
                "name": "test_16299721694081629972169408"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|assignment_rule|created_by|created_timestamp|description|group_type|id|modified_by|modified_timestamp|name|
>|---|---|---|---|---|---|---|---|---|
>| device_id:[''],hostname:[''] | api-client-id:2bf188d347e44e08946f2e61ef590c24 | 2021-08-26T10:02:50.175530821Z | description2 | static | 29ae859b9a01409d83bf7fb7f7a04c69 | api-client-id:2bf188d347e44e08946f2e61ef590c24 | 2021-08-26T10:02:52.026307768Z | test_16299721694081629972169408 |

### cs-falcon-delete-host-groups
***
Delete the requested host groups.


#### Base Command

`cs-falcon-delete-host-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_group_id | A comma-separated list of the IDs of the host groups to be deleted. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cs-falcon-delete-host-groups host_group_id=29ae859b9a01409d83bf7fb7f7a04c69,9a7291431c3046ccb7b750240f924854```

#### Human Readable Output

>host group id 29ae859b9a01409d83bf7fb7f7a04c69 deleted successfully
>host group id 9a7291431c3046ccb7b750240f924854 deleted successfully


### cs-falcon-search-custom-iocs
***
Returns a list of your uploaded IOCs that match the search criteria.


#### Base Command

`cs-falcon-search-custom-iocs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| types | A comma-separated list of indicator types. Valid types are: "sha256", "sha1", "md5", "domain", "ipv4", "ipv6". | Optional | 
| values | A comma-separated list of indicator values. | Optional | 
| sources | A comma-separated list of IOC sources. | Optional | 
| expiration | The date on which the indicator will become inactive (ISO 8601 format, i.e. YYYY-MM-DDThh:mm:ssZ). | Optional | 
| limit | The maximum number of records to return. The minimum is 1 and the maximum is 500. Default is 50. | Optional | 
| sort | The order in which the results are returned. Possible values are: "type.asc", "type.desc", "value.asc", "value.desc", "policy.asc", "policy.desc", "share_level.asc", "share_level.desc", "expiration_timestamp.asc", and "expiration_timestamp.desc". | Optional | 
| offset | The offset to begin the list from. For example, start from the 10th record and return the list. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| CrowdStrike.IOC.ID | string | The full ID of the indicator. | 
| CrowdStrike.IOC.Severity | string | The severity level to apply to this indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.Action | string | Action to take when a host observes the custom IOC. | 
| CrowdStrike.IOC.Expiration | date | The datetime when the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | date | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | date | The datetime the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 


#### Command Example
```!cs-falcon-search-custom-iocs types="domain"```

#### Context Example
```json
{
    "CrowdStrike": {
        "IOC": [
            {
                "CreatedTime": "2020-09-30T10:59:37Z",
                "Expiration": "2020-10-30T00:00:00Z",
                "ID": "4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r",
                "ModifiedTime": "2020-09-30T10:59:37Z",
                "Severity": "high",
                "Action": "prevent",
                "Type": "domain",
                "Value": "value"
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicators of Compromise
>|CreatedTime|Expiration|ID|ModifiedTime|Severity|Action|Type|Value|
>|---|---|---|---|---|---|---|---|
>| 2020-09-30T10:59:37Z | 2020-10-30T00:00:00Z | 4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r | 2020-09-30T10:59:37Z | high | prevent | domain | value |

### cs-falcon-get-custom-ioc
***
Gets the full definition of one or more indicators that you are watching.


#### Base Command

`cs-falcon-get-custom-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The IOC type to retrieve. Possible values are: "sha256", "sha1", "md5", "domain", "ipv4", and "ipv6". Either ioc_id or ioc_type and value must be provided. | Optional | 
| value | The string representation of the indicator. Either ioc_id or ioc_type and value must be provided. | Optional | 
| ioc_id | The ID of the IOC to get. Can be retrieved by running the cs-falcon-search-custom-iocs command. Either ioc_id or ioc_type and value must be provided. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| CrowdStrike.IOC.ID | string | The full ID of the indicator. | 
| CrowdStrike.IOC.Severity | string | The severity level to apply to this indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.Action | string | Action to take when a host observes the custom IOC. | 
| CrowdStrike.IOC.Expiration | date | The datetime when the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | date | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | date | The datetime the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 


#### Command Example
```!cs-falcon-get-custom-ioc type="domain" value="test.domain.com"```

#### Context Example
```json
{
    "CrowdStrike": {
        "IOC": [
            {
                "CreatedTime": "2020-09-30T10:59:37Z",
                "Expiration": "2020-10-30T00:00:00Z",
                "ID": "4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r",
                "ModifiedTime": "2020-09-30T10:59:37Z",
                "Severity": "high",
                "Action": "prevent",
                "Source": "Demisto playbook",
                "Type": "domain",
                "Value": "test.domain.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicator of Compromise
>|CreatedTime|Description|Expiration|ID|ModifiedTime|Severity|Action|Source|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|
>| 2020-10-02T13:55:26Z | Test ioc | 2020-11-01T00:00:00Z | 4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r | 2020-10-02T13:55:26Z | high | prevent | Demisto playbook | domain | test.domain.com |

### cs-falcon-upload-custom-ioc
***
Uploads an indicator for CrowdStrike to monitor.


#### Base Command

`cs-falcon-upload-custom-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_type | The type of the indicator. Possible values are: "sha256", "md5", "domain", "ipv4", and "ipv6". | Required | 
| value | The string representation of the indicator. | Required | 
| action | Action to take when a host observes the custom IOC. Possible values are: no_action - Save the indicator for future use, but take no action. No severity required. allow - Applies to hashes only. Allow the indicator and do not detect it. Severity does not apply and should not be provided. prevent_no_ui - Applies to hashes only. Block and detect the indicator, but hide it from Activity > Detections. Has a default severity value. prevent - Applies to hashes only. Block the indicator and show it as a detection at the selected severity. detect - Enable detections for the indicator at the selected severity. | Required | 
| platforms | The platforms that the indicator applies to. You can enter multiple platform names, separated by commas. Possible values are: mac, windows and linux. | Required | 
| severity | The severity level to apply to this indicator. Possible values are: informational, low, medium, high and critical. | Required for the prevent and detect actions. Optional for no_action. | 
| expiration | The date on which the indicator will become inactive (ISO 8601 format, i.e. YYYY-MM-DDThh:mm:ssZ). | Optional | 
| source | The source where this indicator originated. This can be used for tracking where this indicator was defined. Limited to 200 characters. | Optional | 
| description | A meaningful description of the indicator. Limited to 200 characters. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| CrowdStrike.IOC.ID | string | The full ID of the indicator. | 
| CrowdStrike.IOC.Severity | string | The severity level to apply to this indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.Action | string | Action to take when a host observes the custom IOC. | 
| CrowdStrike.IOC.Expiration | date | The datetime when the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | date | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | date | The datetime the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 


#### Command Example
```!cs-falcon-upload-custom-ioc ioc_type="domain" value="test.domain.com" action="prevent" severity="high" source="Demisto playbook" description="Test ioc" platforms="mac"```

#### Context Example
```json
{
    "CrowdStrike": {
        "IOC": {
            "CreatedTime": "2020-10-02T13:55:26Z",
            "Description": "Test ioc",
            "Expiration": "2020-11-01T00:00:00Z",
            "ID": "4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r",
            "ModifiedTime": "2020-10-02T13:55:26Z",
            "Action": "prevent",
            "Severity": "high",
            "Source": "Demisto playbook",
            "Type": "domain",
            "Value": "test.domain.com"
        }
    }
}
```

#### Human Readable Output

>### Custom IOC was created successfully
>|CreatedTime|Description|Expiration|ID|ModifiedTime|Action|Severity|Source|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|
>| 2020-10-02T13:55:26Z | Test ioc | 2020-11-01T00:00:00Z | 4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r | 2020-10-02T13:55:26Z | prevent | high | Demisto playbook | domain | test.domain.com |

### cs-falcon-update-custom-ioc
***
Updates an indicator for CrowdStrike to monitor.


#### Base Command

`cs-falcon-update-custom-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_id | The ID of the IOC to delete. Can be retrieved by running the cs-falcon-search-custom-iocs command. | Required | 
| action | Action to take when a host observes the custom IOC. Possible values are: no_action - Save the indicator for future use, but take no action. No severity required. allow - Applies to hashes only. Allow the indicator and do not detect it. Severity does not apply and should not be provided. prevent_no_ui - Applies to hashes only. Block and detect the indicator, but hide it from Activity > Detections. Has a default severity value. prevent - Applies to hashes only. Block the indicator and show it as a detection at the selected severity. detect - Enable detections for the indicator at the selected severity. | Optional | 
| platforms | The platforms that the indicator applies to. You can enter multiple platform names, separated by commas. Possible values are: mac, windows and linux. | Optional | 
| severity | The severity level to apply to this indicator. Possible values are: informational, low, medium, high and critical. | Required for the prevent and detect actions. Optional for no_action. | 
| expiration | The date on which the indicator will become inactive (ISO 8601 format, i.e. YYYY-MM-DDThh:mm:ssZ). | Optional | 
| source | The source where this indicator originated. This can be used for tracking where this indicator was defined. Limited to 200 characters. | Optional | 
| description | A meaningful description of the indicator. Limited to 200 characters. | Optional | 
| applied_globally | Whether the indicator is applied globally. Possible values are: true and false. Either applied_globally or host_groups must be provided. | Optional |
| host_groups | List of host group IDs that the indicator applies to. Can be retrieved by running the cs-falcon-list-host-groups command. Either applied_globally or host_groups must be provided. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| CrowdStrike.IOC.ID | string | The full ID of the indicator \(type:value\). | 
| CrowdStrike.IOC.Policy | string | The policy of the indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.ShareLevel | string | The level at which the indicator will be shared. | 
| CrowdStrike.IOC.Expiration | string | The datetime when the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | string | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | string | The date and time the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 


#### Command Example
```!cs-falcon-update-custom-ioc  ioc_id="4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r" severity="high"```

#### Context Example
```json
{
    "CrowdStrike": {
        "IOC": {
            "CreatedTime": "2020-10-02T13:55:26Z",
            "Description": "Test ioc",
            "Expiration": "2020-11-01T00:00:00Z",
            "ID": "4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r",
            "ModifiedTime": "2020-10-02T13:55:26Z",
            "Action": "prevent",
            "Severity": "high",
            "Source": "Demisto playbook",
            "Type": "domain",
            "Value": "test.domain.com"
        }
    }
}
```

#### Human Readable Output

>### Custom IOC was updated successfully
>|CreatedTime|Description|Expiration|ID|ModifiedTime|Action|Severity|Source|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|
>| 2020-10-02T13:55:26Z | Test ioc | 2020-11-01T00:00:00Z | 4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r | 2020-10-02T13:55:26Z | prevent | high | Demisto playbook | domain | test.domain.com |

### cs-falcon-delete-custom-ioc
***
Deletes a monitored indicator.


#### Base Command

`cs-falcon-delete-custom-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_id | The ID of the IOC to delete. Can be retrieved by running the cs-falcon-search-custom-iocs command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cs-falcon-delete-custom-ioc ioc_id="4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r"```


#### Human Readable Output

>Custom IOC 4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r was successfully deleted.
