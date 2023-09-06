The CrowdStrike Falcon OAuth 2 API integration (formerly Falcon Firehose API), enables fetching and resolving detections, searching devices, getting behaviors by ID, containing hosts, and lifting host containment.

## Configure Crowdstrike Falcon on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CrowdstrikeFalcon.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., <https://api.crowdstrike.com>) |  | True |
    | Client ID |  | True |
    | Secret |  | True |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Max incidents per fetch |  | False |
    | Detections fetch query |  | False |
    | Incidents fetch query |  | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Mirroring Direction | Choose the direction to mirror the detection: Incoming \(from CrowdStrike Falcon to XSOAR\), Outgoing \(from XSOAR to CrowdStrike Falcon\), or Incoming and Outgoing \(to/from CrowdStrike Falcon and XSOAR\). | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Close Mirrored XSOAR Incident | When selected, closes the CrowdStrike Falcon incident or detection, which is mirrored in Cortex XSOAR. | False |
    | Close Mirrored CrowdStrike Falcon Incident or Detection | When selected, closes the XSOAR incident, which is mirrored in CrowdStrike Falcon. | False |
    | Fetch types | Choose what to fetch - incidents, detections, or both. | False |
    | Advanced: Minutes to look back when fetching | Use this parameter to determine how far back to look in the search for incidents that were created before the last run time and did not match the query when they were created. | False |


4.  Click **Test** to validate the URLs, token, and connection.

### Required API client scope

In order to use the CrowdStrike Falcon integration, your API client must be provisioned with the following scope and permissions:

- Real Time Response - Read and Write
- Alerts - Read and Write
- IOC Manager - Read and Write
- IOCs - Read and Write
- IOA Exclusions - Read and Write
- Machine Learning Exclusions - Read and Write
- Detections - Read and Write
- Hosts - Read and Write
- Host Groups - Read and Write
- Incidents - Read and Write
- Spotlight Vulnerabilities - Read
- User Management - Read
- On-Demand Scans (ODS) - Read and Write
- Identity Protection Entities - Read and Write
- Identity Protection Detections - Read and Write
- Identity Protection Timeline - Read
- Identity Protection Assessment - Read

### Incident Mirroring
 
You can enable incident mirroring between Cortex XSOAR incidents and CrowdStrike Falcon incidents or detections (available from Cortex XSOAR version 6.0.0).

To setup the mirroring follow these instructions:

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **CrowdStrike Falcon** and select your integration instance.
3. Enable **Fetches incidents**.
4. In the *Fetch types* integration parameter, select what to mirror - incidents or detections or both.
5. Optional: You can go to the *Incidents fetch query* or *Detections fetch query* parameter and select the query to fetch the incidents or detections from CrowdStrike Falcon.
6. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:
    - Incoming - Any changes in CrowdStrike Falcon incidents (`state`, `status`, `tactics`, `techniques`, `objectives`, `tags`, `hosts.hostname`)
      or detections (`status`, `severity`, `behaviors.tactic`, `behaviors.scenario`, `behaviors.objective`, `behaviors.technique`, `device.hostname`) 
      will be reflected in XSOAR incidents.
    - Outgoing - Any changes in XSOAR incidents will be reflected in CrowdStrike Falcon incidents (`tags`, `status`) or detections (`status`).
    - Incoming And Outgoing - Changes in XSOAR incidents and CrowdStrike Falcon incidents or detections will be reflected in both directions.
    - None - Turns off incident mirroring.
7. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding incident or detection is closed in CrowdStrike Falcon.
8. Optional: Check the *Close Mirrored CrowdStrike Falcon Incident or Detection* integration parameter to close the CrowdStrike Falcon incident or detection when the corresponding Cortex XSOAR incident is closed.

Newly fetched incidents or detections will be mirrored in the chosen direction.  However, this selection does not affect existing incidents.

**Important Notes**

- To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and CrowdStrike Falcon.
- When *mirroring in* incidents from CrowdStrike Falcon to Cortex XSOAR:
  - For the `tags` field, tags can only be added from the remote system.
  - When enabling the *Close Mirrored XSOAR Incident* integration parameter, the field in CrowdStrike Falcon that determines whether the incident was closed is the `status` field.
  - In case the *look-back* parameter is initialized with a certain value and during a time that incidents were fetched, if changing 
   the lookback to a number that is greater than the previous value, then in the initial incident fetching there will be incidents duplications.
   If the integration was already set with lookback > 0, and the lookback is not being increased at any point of time, then those incident duplications would not occur.

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
| extended_data | Whether or not to get additional data about the device. Possible values are: "Yes", "No". | Optional | 


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
| CrowdStrike.Device.Status | String | The device status which might be Online, Offline or Unknown. | 
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

`!cs-falcon-search-device ids=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1,a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1`

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
                "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
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
                "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                "FirstSeen": "2017-12-10T11:01:20Z",
                "Status": "contained"
            }
        ],
      "Endpoint(val.ID === obj.ID)": [
            {
              "Hostname": "154.132.82-test-co.in-addr.arpa",
              "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
              "IPAddress": "192.168.1.76", 
              "OS": "Mojave (10.14)",
              "Status": "Online",
              "￿Vendor": "CrowdStrike Falcon",
              "￿MACAddress": "1-1-1-1"
            },
            {
              "Hostname": "154.132.82-test-co.in-addr.arpa", 
              "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
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

>### Devices

>| ID | Hostname | OS | Mac Address | Local IP | External IP | First Seen | Last Seen | Status |
>| --- | --- | --- | --- | --- | --- | --- | --- | --- |
>| a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 154.132.82-test-co.in-addr.arpa | Mojave (10.14) | 8c-85-90-3d-ed-3e | 192.168.1.76 | 94.188.164.68 | 2017-12-28T22:38:11Z | 2019-03-28T02:36:41Z | contained |
>| a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 154.132.82-test-co.in-addr.arpa | Mojave (10.14) | f0-18-98-74-8c-31 | 172.22.14.237 | 94.188.164.68 | 2017-12-10T11:01:20Z | 2019-03-17T10:03:17Z | contained |
 

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
                "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                "ID": "3206", 
                "IOCValue": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                "MD5": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
            }, 
            {
                "IOCType": "sha256", 
                "ProcessID": "197949016741905142", 
                "Scenario": "known_malware", 
                "ParentProcessID": "197949014644753130", 
                "CommandLine": "./xSf", 
                "UserName": "root@u-MacBook-Pro-2.local", 
                "FileName": "xSf", 
                "SensorID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                "ID": "3206", 
                "IOCValue": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                "MD5": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
            }
        ]
    }
```

#### Human Readable Output

>### Behavior ID: 3206

>| ID | File Name | Command Line | Scenario | IOC Type | IOC Value | User Name | SHA256 | MD5 | Process ID | 
>| ------ | --------------- | ----------------------------------------------------------------------- | ---------------- | ---------- | ------------------------------------------------------------------ | --------------------------------------- | ------------------------------------------------------------------ | ---------------------------------- | -------------------- |
>| 3206 |   spokeshave.jn |  /Library/spokeshave.jn/spokeshave.jn.app/Contents/MacOS/spokeshave.jn |   known\_malware   | sha256 |    a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1   | <user@u-MacBook-Pro-2.local> |   a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1   | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1|   197949010450449117|
>|  3206   |xSf             |./xSf                                                                   |known\_malware   |sha256     |a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1|   <root@u-MacBook-Pro-2.local>|          a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1   |a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1   |197949016741905142|

 

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
| filter | Filter detections using a query in Falcon Query Language (FQL).<br/>e.g., filter="device.hostname:'CS-SE-TG-W7-01'"<br/>For a full list of valid filter options, see: <https://falcon.crowdstrike.com/support/documentation/2/query-api-reference#detectionsearch> | Optional | 


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

`!cs-falcon-search-detection ids=ldt:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:1898376850347,ldt:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:1092318056279064902`

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
                        "SensorID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                        "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                        "ID": "4900", 
                        "IOCValue": "systemlowcheck.com", 
                        "MD5": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                    }, 
                    {
                        "IOCType": "domain", 
                        "ProcessID": "2283087267593", 
                        "Scenario": "intel_detection", 
                        "ParentProcessID": "2279170016592", 
                        "CommandLine": "ping.exe systemlowcheck.com", 
                        "UserName": "josh", 
                        "FileName": "PING.EXE", 
                        "SensorID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                        "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                        "ID": "4900", 
                        "IOCValue": "systemlowcheck.com", 
                        "MD5": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                    }
                ], 
                "MaxSeverity": 70, 
                "System": "DESKTOP-S49VMIL", 
                "ID": "ldt:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:1898376850347", 
                "MachineDomain": "", 
                "ShowInUi": true, 
                "CustomerID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
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
                        "SensorID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                        "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                        "ID": "3206", 
                        "IOCValue": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                        "MD5": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                    }, 
                    {
                        "IOCType": "sha256", 
                        "ProcessID": "201917905370426448", 
                        "Scenario": "known_malware", 
                        "ParentProcessID": "201917902773103685", 
                        "CommandLine": "./xSf", 
                        "UserName": "user@u-MacBook-Pro-2.local", 
                        "FileName": "xSf", 
                        "SensorID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                        "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                        "ID": "3206", 
                        "IOCValue": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", 
                        "MD5": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                    }
                ], 
                "MaxSeverity": 30, 
                "System": "u-MacBook-Pro-2.local", 
                "ID": "ldt:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:1092318056279064902", 
                "MachineDomain": "", 
                "ShowInUi": true, 
                "CustomerID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
            }
        ]
    }
```

#### Human Readable Output

>### Detections Found:

>|ID                                                         |Status|            System                 |     Process Start Time     |          Customer ID                       | Max Severity|
>|----------------------------------------------------------| ----------------- |--------------------------- |-------------------------------- |---------------------------------- |--------------|
>|ldt:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:1898376850347       |  false\_positive |  DESKTOP-S49VMIL            | 2019-03-21T20:32:55.654489974Z  | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1  | 70|
>|ldt:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:1092318056279064902|   new             |  u-MacBook-Pro-2.local  | 2019-02-04T07:05:57.083205971Z  | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1  | 30|

 

### 4. Resolve a detection

* * * * *

Resolves and updates a detection using the provided arguments. At least one optional argument must be passed, otherwise no change will take place. Note: IDP detections are not supported.

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
| ids | The host agent ID (AID) of the host to contain. Get an agent ID from a detection. Can also be a comma separated list of IDs. | Required | 

 

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
| queue_offline | Any commands run against an offline-queued session will be queued up and executed when the host comes online. | Optional | 
| timeout | The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. | Optional | 


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

`cs-falcon-run-command host_ids=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 command_type=ls full_command="ls C:\\"`

#### Context Example

```
{
    'CrowdStrike': {
        'Command': [{
            'HostID': 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
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

>### Command ls C:\\ results

>|BaseCommand|Command|HostID|Stderr|Stdout|
>|---|---|---|---|---|
>| ls | ls C:\ | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |  | Directory listing for C:\ -<br/><br/>Name                                     Type         Size (bytes)    Size (MB)       Last Modified (UTC-5)     Created (UTC-5)          <br/>----                                     ----         ------------    ---------       ---------------------     ---------------          <br/>$Recycle.Bin                             &lt;Directory&gt;  --              --              11/27/2018 10:54:44 AM    9/15/2017 3:33:40 AM     <br/>ITAYDI                                   &lt;Directory&gt;  --              --              11/19/2018 1:31:42 PM     11/19/2018 1:31:42 PM     |

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

`!cs-falcon-delete-file file_id=le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1`

#### Human Readable Output

File le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 was deleted successfully.

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

`!cs-falcon-get-file file_id=le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1`

#### Context Example

```
{
    'CrowdStrike.File(val.ID === obj.ID)': [
        {
            'CreatedBy': 'spongobob@demisto.com',
            'CreatedTime': '2019-10-17T13:41:48.487520845Z',
            'Description': 'Demisto',
            'ID': 'le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
            'ModifiedBy': 'spongobob@demisto.com',
            'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
            'Name': 'Demisto',
            'Permission': 'private',
            'SHA256': 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
            'Type': 'script'
        }
    ]
}
```

#### Human Readable Output

>### CrowdStrike Falcon file le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1

>|CreatedBy|CreatedTime|Description|ID|ModifiedBy|ModifiedTime|Name|Permission|SHA256|Type|
>|---|---|---|---|---|---|---|---|---|---|
>| <spongobob@demisto.com> | 2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | <spongobob@demisto.com> | 2019-10-17T13:41:48.487521161Z | Demisto | private | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | script |

### 12. cs-falcon-list-files

---
Returns a list of put-file ID's that are available for the user in the `put` command.

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
            'ID': 'le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
            'ModifiedBy': 'spongobob@demisto.com',
            'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
            'Name': 'Demisto',
            'Permission': 'private',
            'SHA256': 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
            'Type': 'script'
        }
    ]
}
```

#### Human Readable Output

>### CrowdStrike Falcon files

>|CreatedBy|CreatedTime|Description|ID|ModifiedBy|ModifiedTime|Name|Permission|SHA256|Type|
>|---|---|---|---|---|---|---|---|---|---|
>| <spongobob@demisto.com> | 2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | <spongobob@demisto.com> | 2019-10-17T13:41:48.487521161Z | Demisto | private | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | script |

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

`!cs-falcon-get-script file_id=le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1`

#### Context Example

```
{
    'CrowdStrike.Script(val.ID === obj.ID)': [
       {
           'CreatedBy': 'spongobob@demisto.com',
           'CreatedTime': '2019-10-17T13:41:48.487520845Z',
           'Description': 'Demisto',
           'ID': 'le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
           'ModifiedBy': 'spongobob@demisto.com',
           'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
           'Name': 'Demisto',
           'Permission': 'private',
           'SHA256': 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
           'RunAttemptCount': 0,
           'RunSuccessCount': 0,
           'WriteAccess': True
       }
    ]
}
```

#### Human Readable Output

>### CrowdStrike Falcon script le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1

>|CreatedBy|CreatedTime|Description|ID|ModifiedBy|ModifiedTime|Name|Permission|SHA256|
>|---|---|---|---|---|---|---|---|---|
>| <spongobob@demisto.com> | 2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | <spongobob@demisto.com> | 2019-10-17T13:41:48.487521161Z | Demisto | private | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |


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

`!cs-falcon-delete-script script_id=le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1`

#### Human Readable Output

Script le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 was deleted successfully.

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
            'ID': 'le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
            'ModifiedBy': 'spongobob@demisto.com',
            'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
            'Name': 'Demisto',
            'Permission': 'private',
            'SHA256': 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
            'RunAttemptCount': 0,
            'RunSuccessCount': 0,
            'WriteAccess': True
        }
    ]
}
```

#### Human Readable Output

>### CrowdStrike Falcon scripts

>| CreatedBy | CreatedTime | Description | ID | ModifiedBy | ModifiedTime | Name | Permission| SHA256 |
>| --- | --- | --- | --- | --- | --- | --- | --- | --- |
>| <spongobob@demisto.com> |  2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | <spongobob@demisto.com> | 2019-10-17T13:41:48.487521161Z | Demisto | private | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |


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
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. | Optional | 


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

`cs-falcon-run-script host_ids=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 raw="Write-Output 'Hello, World!"`

#### Context Example

```
{
    'CrowdStrike': {
        'Command': [{
            'HostID': 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
                'Stdout': 'Hello, World!',
                'Stderr': '',
                'BaseCommand': 'runscript',
                'Command': "runscript -Raw=Write-Output 'Hello, World!"
        }]
}
```

#### Human Readable Output

>### Command runscript -Raw=Write-Output 'Hello, World! results

>|BaseCommand|Command|HostID|Stderr|Stdout|
>|---|---|---|---|---|
>| runscript | runscript -Raw=Write-Output 'Hello, World! | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |  | Hello, World! |                                    Type         Size (bytes)    Size (MB)       Last Modified (UTC-5)     Created (UTC-5)          <br/>----                                     ----         ------------    ---------       ---------------------     ---------------          <br/>$Recycle.Bin                             &lt;Directory&gt;  --              --              11/27/2018 10:54:44 AM    9/15/2017 3:33:40 AM     <br/>ITAYDI                                   &lt;Directory&gt;  --              --              11/19/2018 1:31:42 PM     11/19/2018 1:31:42 PM     |


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

`cs-falcon-run-get-command host_ids=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 file_path="""c:\Windows\notepad.exe"""`

#### Context Example

```
{
  "CrowdStrike.Command(val.TaskID === obj.TaskID)": [
    {
      "BaseCommand": "get",
      "Complete": True,
      "FilePath": "c:\\Windows\\notepad.exe",
      "GetRequestID": "84ee4d50-f499-482e-bac6-b0e296149bbf",
      "HostID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "Stderr": "",
      "Stdout": "C:\\Windows\\notepad.exe",
      "TaskID": "b5c8f140-280b-43fd-8501-9900f837510b"
    }
  ]
}
```

#### Human Readable Output

>### Get command has requested for a file c:\Windows\notepad.exe

>|BaseCommand|Complete|FilePath|GetRequestID|HostID|Stderr|Stdout|TaskID|
>|---|---|---|---|---|---|---|---|
>| get | true | c:\Windows\notepad.exe | 107199bc-544c-4b0c-8f20-3094c062a115 | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |  | C:\Windows\notepad.exe | 9c820b97-6a60-4238-bc23-f63513970ec8 |



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
      "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "Size": 0,
      "TaskID": "b5c8f140-280b-43fd-8501-9900f837510b",
      "UpdatedAt": "2020-05-01T16:09:00Z"
    }
  ],
  "File(val.MD5 \u0026\u0026 val.MD5 == obj.MD5 || val.SHA1 \u0026\u0026 val.SHA1 == obj.SHA1 || val.SHA256 \u0026\u0026 val.SHA256 == obj.SHA256 || val.SHA512 \u0026\u0026 val.SHA512 == obj.SHA512 || val.CRC32 \u0026\u0026 val.CRC32 == obj.CRC32 || val.CTPH \u0026\u0026 val.CTPH == obj.CTPH || val.SSDeep \u0026\u0026 val.SSDeep == obj.SSDeep)": [
    {
      "Name": "\\Device\\HarddiskVolume2\\Windows\\notepad.exe",
      "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "Size": 0
    }
  ]
}
```

#### Human Readable Output

>### CrowdStrike Falcon files

>|CreatedAt|DeletedAt|ID|Name|SHA256|Size|TaskID|UpdatedAt|
>|---|---|---|---|---|---|---|---|
>| 2020-05-01T16:09:00Z |  | 185596 | \\Device\\HarddiskVolume2\\Windows\\notepad.exe | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 0 | b5c8f140-280b-43fd-8501-9900f837510b | 2020-05-01T16:09:00Z |


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

>### Command status results

>|BaseCommand|Complete|Stdout|TaskID|
>|---|---|---|---|
>| ls | true | Directory listing for C:\\ ...... | ae323961-5aa8-442e-8461-8d05c4541d7d |


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

`!cs-falcon-get-extracted-file host_id="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" sha256="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"`

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

`!cs-falcon-list-host-files host_id="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"`

#### Context Example

```
{
  "CrowdStrike.Command(val.TaskID === obj.TaskID)": [
    {
      "HostID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
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
      "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "Size": 0,
      "Stderr": None,
      "Stdout": None,
      "UpdatedAt": "2020-05-01T17:57:42Z"
    }
  ],
  "File(val.MD5 \u0026\u0026 val.MD5 == obj.MD5 || val.SHA1 \u0026\u0026 val.SHA1 == obj.SHA1 || val.SHA256 \u0026\u0026 val.SHA256 == obj.SHA256 || val.SHA512 \u0026\u0026 val.SHA512 == obj.SHA512 || val.CRC32 \u0026\u0026 val.CRC32 == obj.CRC32 || val.CTPH \u0026\u0026 val.CTPH == obj.CTPH || val.SSDeep \u0026\u0026 val.SSDeep == obj.SSDeep)": [
    {
      "Name": "\\Device\\HarddiskVolume2\\Windows\\notepad.exe",
      "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "Size": 0
    }
  ]
}
```

#### Human Readable Output

>### CrowdStrike Falcon files

>|CreatedAt|DeletedAt|ID|Name|SHA256|Size|Stderr|Stdout|UpdatedAt|
>|---|---|---|---|---|---|---|---|---|
>| 2020-05-01T17:57:42Z |  | 186811 | \\Device\\HarddiskVolume2\\Windows\\notepad.exe | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 0 |  |  | 2020-05-01T17:57:42Z |


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

`!cs-falcon-refresh-session host_id=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1`

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

```!cs-falcon-processes-ran-on device_id=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 type=domain value=value```

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
            "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
        ]
    }
}
```

#### Human Readable Output

>### Devices that encountered the IOC domain:value

>|Device ID|
>|---|
>| a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |


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
Returns information about an endpoint, does not support regex.

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
>| a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 1.1.1.1 | Windows | Windows Server 2019| Hostname | Online | 1-1-1-1 | CrowdStrike Falcon|\n"

### 35. cs-falcon-create-host-group

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
            "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "created_timestamp": "2021-08-25T08:02:02.060242909Z",
            "description": "test_description",
            "group_type": "static",
            "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
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
>| api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2021-08-25T08:02:02.060242909Z | test_description | static | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2021-08-25T08:02:02.060242909Z | test_name_1 |

### 36. cs-falcon-update-host-group

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

```!cs-falcon-update-host-group host_group_id=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 name="test_name_update_1" description="test_description_update"```

#### Context Example

```json
{
    "CrowdStrike": {
        "HostGroup": {
            "assignment_rule": "device_id:[''],hostname:['']",
            "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "created_timestamp": "2021-08-22T07:48:35.111070562Z",
            "description": "test_description_update",
            "group_type": "static",
            "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
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
>| device_id:[''],hostname:[''] | api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2021-08-22T07:48:35.111070562Z | test_description_update | static | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2021-08-25T08:02:05.295663156Z | test_name_update_1 |

### 37. cs-falcon-list-host-group-members

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
                "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
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
                "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
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
                "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
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
                "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
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
                "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
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
>| a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 35.224.136.145 | 10.128.0.19 | falcon-crowdstrike-sensor-centos7 | CentOS 7.9 | 42-01-0a-80-00-13 | 2021-08-08T11:33:21Z | 2021-08-25T07:50:47Z | normal |

### 38. cs-falcon-add-host-group-members

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

```!cs-falcon-add-host-group-members host_group_id="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" host_ids="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"```

#### Context Example

```json
{
    "CrowdStrike": {
        "HostGroup": {
            "assignment_rule": "device_id:[''],hostname:['falcon-crowdstrike-sensor-centos7','']",
            "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "created_timestamp": "2021-08-22T07:48:35.111070562Z",
            "description": "test_description_update",
            "group_type": "static",
            "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
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
>| device_id:[''],hostname:['falcon-crowdstrike-sensor-centos7',''] | api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2021-08-22T07:48:35.111070562Z | test_description_update | static | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2021-08-25T08:02:05.295663156Z | test_name_update_1 |

### 39. cs-falcon-remove-host-group-members

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

```!cs-falcon-remove-host-group-members host_group_id="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" host_ids="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"```

#### Context Example

```json
{
    "CrowdStrike": {
        "HostGroup": {
            "assignment_rule": "device_id:[''],hostname:['']",
            "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "created_timestamp": "2021-08-22T07:48:35.111070562Z",
            "description": "test_description_update",
            "group_type": "static",
            "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
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
>| device_id:[''],hostname:[''] | api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2021-08-22T07:48:35.111070562Z | test_description_update | static | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2021-08-25T08:02:05.295663156Z | test_name_update_1 |

### 40. cs-falcon-resolve-incident

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

```!cs-falcon-resolve-incident ids="inc:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1,inc:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" status="Closed"```

#### Human Readable Output

>inc:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 changed successfully to Closed
>inc:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 changed successfully to Closed

### 41. cs-falcon-list-host-groups

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
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T14:35:23.765624811Z",
                "description": "description",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T14:35:23.765624811Z",
                "name": "InnerServicesModuleMon Aug 23 2021"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T14:35:25.506030441Z",
                "description": "description",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T14:35:25.506030441Z",
                "name": "Rasterize_default_instanceMon Aug 23 2021"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['','FALCON-CROWDSTR']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-07-27T12:34:59.13917402Z",
                "description": "",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-07-27T12:34:59.13917402Z",
                "name": "Static by id group test"
            },
            {
                "assignment_rule": "device_id:[],hostname:[]",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-07-27T12:24:18.364057533Z",
                "description": "Group test",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-07-27T12:24:18.364057533Z",
                "name": "Static group test"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T14:35:26.069515348Z",
                "description": "description",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T14:35:26.069515348Z",
                "name": "ad-loginMon Aug 23 2021"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T14:35:25.556897468Z",
                "description": "description",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T14:35:25.556897468Z",
                "name": "ad-queryMon Aug 23 2021"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T14:35:23.737307612Z",
                "description": "description",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T14:35:23.737307612Z",
                "name": "d2Mon Aug 23 2021"
            },
            {
                "created_by": "someone@email.com",
                "created_timestamp": "2021-07-27T12:27:43.503021999Z",
                "description": "dhfh",
                "group_type": "staticByID",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "someone@email.com",
                "modified_timestamp": "2021-07-27T12:27:43.503021999Z",
                "name": "ddfxgh"
            },
            {
                "assignment_rule": "device.hostname:'FALCON-CROWDSTR'",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-07-27T12:46:39.058352326Z",
                "description": "",
                "group_type": "dynamic",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-07-27T12:46:39.058352326Z",
                "name": "dynamic 1 group test"
            },
            {
                "assignment_rule": "lkjlk:'FalconGroupingTags/example_tag'",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T13:12:56.338590022Z",
                "description": "",
                "group_type": "dynamic",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T13:12:56.338590022Z",
                "name": "dynamic 13523 group test"
            },
            {
                "assignment_rule": "lkjlk:'FalconGroupingTags/example_tag'",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-07-27T14:02:05.538065349Z",
                "description": "",
                "group_type": "dynamic",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-07-27T14:02:05.538065349Z",
                "name": "dynamic 1353 group test"
            },
            {
                "assignment_rule": "tags:'FalconGroupingTags/example_tag'",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-07-27T12:41:33.127997409Z",
                "description": "",
                "group_type": "dynamic",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-07-27T12:41:33.127997409Z",
                "name": "dynamic 2 group test"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T14:35:23.7402217Z",
                "description": "description",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T14:35:23.7402217Z",
                "name": "fcm_default_instanceMon Aug 23 2021"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-11T09:55:23.801049103Z",
                "description": "ilan test",
                "group_type": "dynamic",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-11T09:55:23.801049103Z",
                "name": "ilan"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-12T11:24:51.434863056Z",
                "description": "ilan test",
                "group_type": "dynamic",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-12T11:24:51.434863056Z",
                "name": "ilan 2"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['FALCON-CROWDSTR']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-12T11:55:57.943490809Z",
                "description": "ilan test",
                "group_type": "dynamic",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-12T11:55:57.943490809Z",
                "name": "ilan 23"
            },
            {
                "assignment_rule": "",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-17T11:28:39.855075106Z",
                "description": "after change",
                "group_type": "dynamic",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T09:26:15.351650252Z",
                "name": "ilan 2345"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-17T11:58:42.453661998Z",
                "description": "ilan test",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-17T11:58:42.453661998Z",
                "name": "ilan 23e"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-11T13:54:59.695821727Z",
                "description": "",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-11T13:54:59.695821727Z",
                "name": "ilan test 2"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-12T10:56:49.2127345Z",
                "description": "ilan test",
                "group_type": "dynamic",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-12T11:35:35.76509212Z",
                "name": "ilan2"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T14:35:23.766284685Z",
                "description": "description",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T14:35:23.766284685Z",
                "name": "splunkMon Aug 23 2021"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:09:15.36414377Z",
                "description": "description",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:09:15.36414377Z",
                "name": "test_1629731353498"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:12:20.69203954Z",
                "description": "description",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:12:20.69203954Z",
                "name": "test_1629731538458"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:14:20.650781714Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:14:23.026511269Z",
                "name": "test_16297316587261629731658726"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:18:53.896505566Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:18:56.2598933Z",
                "name": "test_16297319320381629731932038"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:19:51.91067257Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:19:54.269898808Z",
                "name": "test_16297319902371629731990237"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:25:42.99601887Z",
                "description": "description",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:25:42.99601887Z",
                "name": "test_1629732339973"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:26:12.280379354Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:26:14.973676462Z",
                "name": "test_16297323698941629732369894"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:26:58.717706381Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:27:01.648623079Z",
                "name": "test_16297324168771629732416877"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:28:18.674512647Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:28:21.781563212Z",
                "name": "test_16297324965761629732496576"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['FALCON-CROWDSTR','INSTANCE-1','falcon-crowdstrike-sensor-centos7']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:31:41.142748214Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:31:43.800147323Z",
                "name": "test_16297326990981629732699098"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:34:20.195778795Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:34:23.212828317Z",
                "name": "test_16297328579781629732857978"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:34:55.837119719Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:34:58.490114093Z",
                "name": "test_16297328938791629732893879"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-23T15:37:42.911344704Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-23T15:37:45.620464598Z",
                "name": "test_16297330605301629733060530"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-24T07:05:55.813475476Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-24T07:05:58.805702883Z",
                "name": "test_16297887501421629788750142"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-24T07:07:30.422517324Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-24T07:07:34.291988227Z",
                "name": "test_16297888481381629788848138"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-24T08:03:15.522772079Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-24T08:03:18.622015517Z",
                "name": "test_16297921932741629792193274"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T09:09:52.379925975Z",
                "description": "description",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-26T09:09:52.379925975Z",
                "name": "test_1629967211800"
            },
            {
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T12:34:36.934507422Z",
                "description": "description",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-26T12:34:36.934507422Z",
                "name": "test_162996721180000"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T08:46:09.996065663Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-26T08:46:11.572092204Z",
                "name": "test_16299675695531629967569553"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T08:53:15.35181954Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-26T08:53:17.041535905Z",
                "name": "test_16299679949831629967994983"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T08:59:52.639696743Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-26T08:59:54.538170036Z",
                "name": "test_16299683923121629968392312"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T09:06:21.891707157Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-26T09:06:23.846219163Z",
                "name": "test_16299687814871629968781487"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T09:12:53.982989Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-26T09:12:55.571265187Z",
                "name": "test_16299691732871629969173287"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T09:17:58.206157753Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-26T09:17:59.659515838Z",
                "name": "test_16299694779051629969477905"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T09:19:23.276267291Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-26T09:19:25.318976241Z",
                "name": "test_16299695623981629969562398"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T09:26:22.538367707Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-26T09:26:25.085214782Z",
                "name": "test_16299699813871629969981387"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T09:33:46.303790983Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-26T09:33:48.288311235Z",
                "name": "test_16299704254441629970425444"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T09:55:09.157561612Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_timestamp": "2021-08-26T09:55:10.741852436Z",
                "name": "test_16299717065381629971706538"
            },
            {
                "assignment_rule": "device_id:[''],hostname:['']",
                "created_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "created_timestamp": "2021-08-26T10:02:50.175530821Z",
                "description": "description2",
                "group_type": "static",
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "modified_by": "api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
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
>| device_id:[''],hostname:[''] | api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2021-08-26T10:02:50.175530821Z | description2 | static | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | api-client-id:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2021-08-26T10:02:52.026307768Z | test_16299721694081629972169408 |

### 42. cs-falcon-delete-host-groups

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

```!cs-falcon-delete-host-groups host_group_id=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1,a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1```

#### Human Readable Output

>host group id a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 deleted successfully
>host group id a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 deleted successfully


### 43. cs-falcon-search-custom-iocs

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


#### Command example

```!cs-falcon-search-custom-iocs limit=2```

#### Context Example

```json
{
    "CrowdStrike": {
        "IOC": [
            {
                "Action": "no_action",
                "CreatedBy": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "CreatedTime": "2022-02-16T17:17:25.992164453Z",
                "Description": "test",
                "Expiration": "2022-02-17T13:47:57Z",
                "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "ModifiedBy": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "ModifiedTime": "2022-02-16T17:17:25.992164453Z",
                "Platforms": [
                    "mac"
                ],
                "Severity": "informational",
                "Source": "Cortex XSOAR",
                "Type": "ipv4",
                "Value": "1.1.8.9"
            },
            {
                "Action": "no_action",
                "CreatedBy": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "CreatedTime": "2022-02-16T17:16:44.514398876Z",
                "Description": "test",
                "Expiration": "2022-02-17T13:47:57Z",
                "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "ModifiedBy": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "ModifiedTime": "2022-02-16T17:16:44.514398876Z",
                "Platforms": [
                    "mac"
                ],
                "Severity": "informational",
                "Source": "Cortex XSOAR",
                "Type": "ipv4",
                "Value": "4.1.8.9"
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicators of Compromise

>|ID|Action|Severity|Type|Value|Expiration|CreatedBy|CreatedTime|Description|ModifiedBy|ModifiedTime|Platforms|Policy|ShareLevel|Source|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | no_action | informational | ipv4 | 1.1.8.9 | 2022-02-17T13:47:57Z | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2022-02-16T17:17:25.992164453Z | test | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2022-02-16T17:17:25.992164453Z | mac |  |  | Cortex XSOAR |  |
>| a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | no_action | informational | ipv4 | 4.1.8.9 | 2022-02-17T13:47:57Z | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2022-02-16T17:16:44.514398876Z | test | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2022-02-16T17:16:44.514398876Z | mac |  |  | Cortex XSOAR |  |

### 44. cs-falcon-get-custom-ioc

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


#### Command example

```!cs-falcon-get-custom-ioc type=ipv4 value=7.5.9.8```

#### Context Example

```json
{
    "CrowdStrike": {
        "IOC": {
            "Action": "no_action",
            "CreatedBy": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "CreatedTime": "2022-02-16T14:25:22.968603813Z",
            "Expiration": "2022-02-17T17:55:09Z",
            "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "ModifiedBy": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "ModifiedTime": "2022-02-16T14:25:22.968603813Z",
            "Platforms": [
                "linux"
            ],
            "Severity": "informational",
            "Source": "cortex xsoar",
            "Tags": [
                "test",
                "test1"
            ],
            "Type": "ipv4",
            "Value": "7.5.9.8"
        }
    }
}
```

#### Human Readable Output

>### Indicator of Compromise

>|ID|Action|Severity|Type|Value|Expiration|CreatedBy|CreatedTime|Description|ModifiedBy|ModifiedTime|Platforms|Policy|ShareLevel|Source|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | no_action | informational | ipv4 | 7.5.9.8 | 2022-02-17T17:55:09Z | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2022-02-16T14:25:22.968603813Z |  | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2022-02-16T14:25:22.968603813Z | linux |  |  | cortex xsoar | test,<br/>test1 |

### 45. cs-falcon-upload-custom-ioc

***
Uploads an indicator for CrowdStrike to monitor.


#### Base Command

`cs-falcon-upload-custom-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_type | The type of the indicator. Possible values are: "sha256", "md5", "domain", "ipv4", and "ipv6". | Required | 
| value | A comma separated list of indicators. More than one value can be supplied in order to upload multiple IOCs of the same type but with different values. Note that the uploaded IOCs will have the same properties (as supplied in other arguments). | Required | 
| action | Action to take when a host observes the custom IOC. Possible values are: no_action - Save the indicator for future use, but take no action. No severity required. allow - Applies to hashes only. Allow the indicator and do not detect it. Severity does not apply and should not be provided. prevent_no_ui - Applies to hashes only. Block and detect the indicator, but hide it from Activity > Detections. Has a default severity value. prevent - Applies to hashes only. Block the indicator and show it as a detection at the selected severity. detect - Enable detections for the indicator at the selected severity. | Required | 
| platforms | The platforms that the indicator applies to. You can enter multiple platform names, separated by commas. Possible values are: mac, windows and linux. | Required | 
| severity | The severity level to apply to this indicator. Possible values are: informational, low, medium, high and critical. | Required for the prevent and detect actions. Optional for no_action. | 
| expiration | The date on which the indicator will become inactive (ISO 8601 format, i.e. YYYY-MM-DDThh:mm:ssZ). | Optional | 
| source | The source where this indicator originated. This can be used for tracking where this indicator was defined. Limited to 200 characters. | Optional | 
| description | A meaningful description of the indicator. Limited to 200 characters. | Optional | 
| applied_globally | Whether the indicator is applied globally. Either applied_globally or host_groups must be provided. Possible values are: true, false. | Optional | 
| host_groups | List of host group IDs that the indicator applies to. Can be retrieved by running the cs-falcon-list-host-groups command. Either applied_globally or host_groups must be provided. | Optional | 
| tags | List of tags to apply to the indicator. | Optional | 

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
| CrowdStrike.IOC.Tags | Unknown | The tags of the IOC. | 
| CrowdStrike.IOC.Platforms | Unknown | The platforms of the IOC. | 

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
            "Value": "test.domain.com",
            "Platforms": ["mac"]
        }
    }
}
```

#### Human Readable Output

>### Custom IOC was created successfully

>|CreatedTime|Description|Expiration|ID|ModifiedTime|Action|Severity|Source|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|
>| 2020-10-02T13:55:26Z | Test ioc | 2020-11-01T00:00:00Z | 4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r | 2020-10-02T13:55:26Z | prevent | high | Demisto playbook | domain | test.domain.com |

### 46. cs-falcon-update-custom-ioc

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

### 47. cs-falcon-delete-custom-ioc

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

### 48. cs-falcon-batch-upload-custom-ioc

***
Uploads a batch of indicators.


#### Base Command

`cs-falcon-batch-upload-custom-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| multiple_indicators_json | A JSON object with list of CS Falcon indicators to upload. | Required | 
| timeout | The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| CrowdStrike.IOC.ID | string | The full ID of the indicator. | 
| CrowdStrike.IOC.Severity | string | The severity level to apply to this indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.Action | string | Action to take when a host observes the custom IOC. | 
| CrowdStrike.IOC.Expiration | string | The datetime when the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | date | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | date | The datetime the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 
| CrowdStrike.IOC.Tags | Unknown | The tags of the IOC. | 
| CrowdStrike.IOC.Platforms | Unknown | The platforms of the IOC. | 

#### Command example

```!cs-falcon-batch-upload-custom-ioc multiple_indicators_json=`[{"description": "test", "expiration": "2022-02-17T13:47:57Z", "type": "ipv4", "severity": "Informational", "value": "1.1.8.9", "action": "no_action", "platforms": ["mac"], "source": "Cortex XSOAR", "applied_globally": true}]` ```

#### Context Example

```json
{
    "CrowdStrike": {
        "IOC": {
            "Action": "no_action",
            "CreatedBy": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "CreatedTime": "2022-02-16T17:17:25.992164453Z",
            "Description": "test",
            "Expiration": "2022-02-17T13:47:57Z",
            "ID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "ModifiedBy": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "ModifiedTime": "2022-02-16T17:17:25.992164453Z",
            "Platforms": [
                "mac"
            ],
            "Severity": "informational",
            "Source": "Cortex XSOAR",
            "Type": "ipv4",
            "Value": "1.1.8.9"
        }
    }
}
```

#### Human Readable Output

>### Custom IOC 1.1.8.9 was created successfully

>|Action|CreatedBy|CreatedTime|Description|Expiration|ID|ModifiedBy|ModifiedTime|Platforms|Severity|Source|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| no_action | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2022-02-16T17:17:25.992164453Z | test | 2022-02-17T13:47:57Z | "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2022-02-16T17:17:25.992164453Z | mac | informational | Cortex XSOAR | ipv4 | 1.1.8.9 |

### 49. cs-falcon-rtr-kill-process

***
Execute an active responder kill command on a single host.

#### Base Command

`cs-falcon-rtr-kill-process`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The host ID in which you would like to kill the given process. | Required | 
| process_ids | A comma-separated list of process IDs to kill. | Required | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.kill.ProcessID | String | The process ID that was killed. | 
| CrowdStrike.Command.kill.Error | String | The error message raised if the command was failed. | 
| CrowdStrike.Command.kill.HostID | String | The host ID. | 

#### Command example

```!cs-falcon-rtr-kill-process host_id=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 process_ids=5260,123```

#### Context Example

```json
{
  "CrowdStrike": {
    "Command": {
      "kill": [
        {
          "Error": "Cannot find a process with the process identifier 123.",
          "HostID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
          "ProcessID": "123"
        },
        {
          "Error": "Success",
          "HostID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
          "ProcessID": "5260"
        }
      ]
    }
  }
}
```

#### Human Readable Output

> ### CrowdStrike Falcon kill command on host a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:

>|ProcessID|Error|
>|---|---|
>| 123 | Cannot find a process with the process identifier 123. |
>| 5260 | Success |
>Note: you don't see the following IDs in the results as the request was failed for them.
> ID 123 failed as it was not found.

### 50. cs-falcon-rtr-remove-file

***
Batch executes an RTR active-responder remove file across the hosts mapped to the given batch ID.

#### Base Command

`cs-falcon-rtr-remove-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma-separated list of the hosts IDs in which you would like to remove the file. | Required | 
| file_path | The path to a file or a directoty that you would like to remove. | Required | 
| os | The operatin system of the hosts given. As the revome command is different in each operatin system, you can choose only one operating system. Possible values are: Windows, Linux, Mac. | Required | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.rm.HostID | String | The host ID. | 
| CrowdStrike.Command.rm.Error | String | The error message raised if the command was failed. | 

#### Command example

```!cs-falcon-rtr-remove-file file_path="c:\\testfolder" host_ids=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 os=Windows```

#### Context Example

```json
{
  "CrowdStrike": {
    "Command": {
      "rm": {
        "Error": "Success",
        "HostID": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
      }
    }
  }
}
```

#### Human Readable Output

> ### CrowdStrike Falcon rm over the file: c:\testfolder

>|HostID|Error|
>|---|---|
>| a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | Success |

### 51. cs-falcon-rtr-list-processes

***
Executes an RTR active-responder ps command to get a list of active processes across the given host.

#### Base Command

`cs-falcon-rtr-list-processes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The host ID in which you would like to get the processes list from. | Required | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.ps.Filename | String | The the name of the result file to be returned. | 

#### Command example

```!cs-falcon-rtr-list-processes host_id=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1```

#### Context Example

```json
{
  "CrowdStrike": {
    "Command": {
      "ps": {
        "Filename": "ps-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
      }
    }
  },
  "File": {
    "EntryID": "1792@5e02fcd0-37ad-4124-836d-7e769ba0ae86",
    "Info": "text/plain",
    "MD5": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    "Name": "ps-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    "SHA1": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a115919af3",
    "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    "SHA512": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    "SSDeep": "768:4jcAkTBaZ61QUEcDBdMoFwIxVvroYrohrbY2akHLnsa5fbqFEJtPNObzVj0ff+3K:4IraZ61QUEcDBdMoFwIxRJEbY2akHLnr",
    "Size": 30798,
    "Type": "ASCII text"
  }
}
```

#### Human Readable Output

> ### CrowdStrike Falcon ps command on host a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:

>|Stdout|
>|---|
>|TOO MUCH INFO TO DISPLAY|

### 52. cs-falcon-rtr-list-network-stats

***
Executes an RTR active-responder netstat command to get a list of network status and protocol statistics across the given
host.

#### Base Command

`cs-falcon-rtr-list-network-stats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The host ID in which you would like to get the network status and protocol statistics list from. | Required | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.netstat.Filename | String | The the name of the result file to be returned. | 

#### Command example

```!cs-falcon-rtr-list-network-stats host_id=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1```

#### Context Example

```json
{
  "CrowdStrike": {
    "Command": {
      "netstat": {
        "Filename": "netstat-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
      }
    }
  },
  "File": {
    "EntryID": "1797@5e02fcd0-37ad-4124-836d-7e769ba0ae86",
    "Info": "text/plain",
    "MD5": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    "Name": "netstat-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    "SHA1": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1864ce595",
    "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    "SHA512": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    "SSDeep": "48:XSvprPoeCfd8saowYL8zjt6yjjRchg24OI58RtTLvWptl6TtCla5n1lEtClMw/u:CRQeCxRmxVpIHUchCIvsCo",
    "Size": 4987,
    "Type": "ASCII text, with CRLF line terminators"
  }
}
```

#### Human Readable Output

> ### CrowdStrike Falcon netstat command on host a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:

>|Stdout|
>|---|
>|TOO MUCH INFO TO DISPLAY|

### 53. cs-falcon-rtr-read-registry

***
Executes an RTR active-responder read registry keys command across the given hosts. This command is valid only for
Windows hosts.

#### Base Command

`cs-falcon-rtr-read-registry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma-separated list of the hosts IDs in which you would like to get the registry keys from. | Required | 
| registry_keys | A comma-separated list of the registy keys, subkeys or value to get. | Required | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!cs-falcon-rtr-read-registry host_ids=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 registry_keys=`
HKEY_LOCAL_MACHINE,HKEY_USERS````

#### Context Example

```json
{
  "File": [
    {
      "EntryID": "1806@5e02fcd0-37ad-4124-836d-7e769ba0ae86",
      "Info": "text/plain",
      "MD5": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "Name": "reg-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1HKEY_USERS",
      "SHA1": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a139dd0333",
      "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "SHA512": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "SSDeep": "12:uSn3PtdoI1pZI2WUNI2e6NI2vboI2vbP3I2zd:uSQIpZIII1aIUMIUjIcd",
      "Size": 656,
      "Type": "ASCII text, with CRLF, LF line terminators"
    },
    {
      "EntryID": "1807@5e02fcd0-37ad-4124-836d-7e769ba0ae86",
      "Info": "text/plain",
      "MD5": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "Name": "reg-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1HKEY_LOCAL_MACHINE",
      "SHA1": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a18e3b4919",
      "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "SHA512": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "SSDeep": "6:zYuSugMQEYPtdWCMwdiwf2Jai2FU42DGE25/:zYuSnMQXPtd9/eJqy7yfh",
      "Size": 320,
      "Type": "ASCII text, with CRLF, LF line terminators"
    }
  ]
}
```

#### Human Readable Output

> ### CrowdStrike Falcon reg command on hosts ['a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1']:

>|FileName| Stdout                    |
>|---------------------------|---|
>| reg-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1HKEY_USERS | TOO MUCH INFO TO DISPLAY  |
>| reg-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1HKEY_LOCAL_MACHINE | TOO MUCH INFO TO DISPLAY  |

### 54. cs-falcon-rtr-list-scheduled-tasks

***
Executes an RTR active-responder netstat command to get a list of scheduled tasks across the given host. This command is
valid only for Windows hosts.

#### Base Command

`cs-falcon-rtr-list-scheduled-tasks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma-separated list of the hosts IDs in which you would like to get the list of scheduled tasks from. | Required | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!cs-falcon-rtr-list-scheduled-tasks host_ids=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1```

#### Context Example

```json
{
  "CrowdStrike": {
    "Command": {
      "runscript": {
        "Filename": "runscript-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
      }
    }
  },
  "File": {
    "EntryID": "1812@5e02fcd0-37ad-4124-836d-7e769ba0ae86",
    "Info": "text/plain",
    "MD5": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    "Name": "runscript-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    "SHA1": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1c589bf80",
    "SHA256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    "SHA512": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    "SSDeep": "3072:zjQ3/3YHGa8dbXbpbItbo4W444ibNb9MTf2Wat4cuuEqk4W4ybmF54c4eEEEjX6f:EXN8Nbw",
    "Size": 299252,
    "Type": "ASCII text"
  }
}
```

#### Human Readable Output

> ### CrowdStrike Falcon runscript command on host a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:

>| Stdout                    |
---------------------------|---|
>| TOO MUCH INFO TO DISPLAY  |

### 55. cs-falcon-rtr-retrieve-file

***
Gets the RTR extracted file contents for the specified file path.

#### Base Command

`cs-falcon-rtr-retrieve-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma-separated list of the hosts IDs in which you would like to get file from. | Required | 
| file_path | The file path of the required file to extract. | Required | 
| filename | The filename to use for the archive name and the file within the archive. | Optional | 
| interval_in_seconds | interval between polling. Default is 60 seconds. Must be higher than 10. | Optional | 
| hosts_and_requests_ids | This is an internal argument used for the polling process, not to be used by the user. | Optional | 
| SHA256 | This is an internal argument used for the polling process, not to be used by the user. | Optional | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.File.FileName | String | The file name. | 
| CrowdStrike.File.HostID | String | The hosd ID. | 
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | EntryID of the file | 
| File.Info | String | Information about the file. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The extension of the file. | 

#### Command example

```!cs-falcon-rtr-retrieve-file file_path=`C:\Windows\System32\Windows.Media.FaceAnalysis.dll` host_ids=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1,a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1```

#### Human Readable Output

> Waiting for the polling execution

### 56. cs-falcon-get-detections-for-incident

***
Gets the detections for a specific incident.


#### Base Command

`cs-falcon-get-detections-for-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident's id to get detections for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IncidentDetection.incident_id | String | The incident id. | 
| CrowdStrike.IncidentDetection.behavior_id | String | The behavior id connected to the incident. | 
| CrowdStrike.IncidentDetection.detection_ids | String | A list of detection ids connected to the incident. | 

#### Command example

```!cs-falcon-get-detections-for-incident incident_id=`inc:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1````

#### Context Example

```json
{
    "CrowdStrike": {
        "IncidentDetection": {
            "behavior_id": "ind:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:162589633341-10303-6705920",
            "detection_ids": [
                "ldt:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:38655034604"
            ],
            "incident_id": "inc:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
        }
    }
}
```

#### Human Readable Output

>### Detection For Incident

>|behavior_id|detection_ids|incident_id|
>|---|---|---|
>| ind:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:162590282130-10303-6707968 | ldt:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:38656254663 | inc:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |
>| ind:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:162596456872-10303-6710016 | ldt:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:38657629548 | inc:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |
>| ind:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:162597577534-10305-6712576 | ldt:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:38658614774 | inc:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |
>| ind:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:162589633341-10303-6705920 | ldt:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:38655034604 | inc:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |


### 17. cs-falcon-update-incident-comment

---
Updates CrowdStrike Incident with the comment.

#### Base Command

`cs-falcon-update-incident-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of incident IDs. | Required | 
| comment | A comment added to the CrowdStrike incident. | Required | 

#### Context Output

#### Command Example

`cs-falcon-update-incident-comment ids=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 comment="Some comment"`


# Spotlight

### Using Spotlight APIs

Spotlight identifies and gives info about specific vulnerabilities on your hosts using the Falcon sensor.

### Required API client scope

To access the Spotlight API, your API client must be assigned the spotlight-vulnerabilities:read scope.

### Validating API data

The Falcon sensor continuously monitors hosts for any changes and reports them as they occur.
Depending on the timing of requests, Spotlight APIs can return values that are different from those shown by the Falcon console or an external source.
There are other factors that can cause differences between API responses and other data sources.

### API query syntax

If an API query doesn’t exactly match the query used on the Spotlight Vulnerabilities page, the values might differ.

### Expired vulnerabilities in Spotlight APIs

If a host is deleted or inactive for 45 days, the status of vulnerabilities on that host changes to expired. Expired vulnerabilities are removed from Spotlight after 3 days. 
Expired vulnerabilities are only visible in API responses and are not included in reports or the Falcon console.
An external data source might not use the same data retention policy, which can lead to discrepancies with Spotlight APIs. For more info, see Data retention in Spotlight [https://falcon.crowdstrike.com/login/?next=%2Fdocumentation%2F43%2Ffalcon-spotlight-overview#data-retention-in-spotlight].

### The following commands uses the Spotlight API:

### cs-falcon-spotlight-search-vulnerability

***
Retrieve vulnerability details according to the selected filter. Each request requires at least one filter parameter. Supported with the CrowdStrike Spotlight license.

#### Base Command

`cs-falcon-spotlight-search-vulnerability`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
|filter| Limit the vulnerabilities returned to specific properties. Each value must be enclosed in single quotes and placed immediately after the colon with no space. | Optional |
| aid |  Unique agent identifier (AID) of a sensor | Optional |
| cve_id | Unique identifier for a vulnerability as cataloged in the National Vulnerability Database (NVD). This filter supports multiple values and negation | Optional |
| cve_severity | Severity of the CVE. The possible values are: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN, or NONE. | Optional |
| tags | Name of a tag assigned to a host. Retrieve tags from Host Tags APIs | Optional |
| status | Status of a vulnerability. This filter supports multiple values and negation. The possible values are: open, closed, reopen, expired. | Optional |
| platform_name | Operating system platform. This filter supports negation. The possible values are: Windows, Mac, Linux. | Optional |
| host_group | Unique system-assigned ID of a host group. Retrieve the host group ID from Host Group APIs | Optional |
| host_type | Type of host a sensor is running on | Optional |
| last_seen_within | Filter for vulnerabilities based on the number of days since a host last connected to CrowdStrike Falcon | Optional |
| is_suppressed | Indicates if the vulnerability is suppressed by a suppression rule | Optional |
| display_remediation_info | Display remediation information type of data to be returned for each vulnerability entity | Optional |
| display_evaluation_logic_info | Whether to return logic information type of data for each vulnerability entity | Optional |
| display_host_info | Whether to return host information type of data for each vulnerability entity | Optional |
| limit | Maximum number of items to return (1-5000) | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Vulnerability.id | String | Unique system-assigned ID of the vulnerability. | 
| CrowdStrike.Vulnerability.cid | String | Unique system-generated customer identifier (CID) of the account | 
| CrowdStrike.Vulnerability.aid | String | Unique agent identifier (AID) of the sensor where the vulnerability was found | 
| CrowdStrike.Vulnerability.created_timestamp | String | UTC date and time that the vulnerability was created in Spotlight | 
| CrowdStrike.Vulnerability.updated_timestamp | String | UTC date and time of the last update made on the vulnerability | 
| CrowdStrike.Vulnerability.status | String | Vulnerability's current status. Possible values are: open, closed, reopen, or expired | 
| CrowdStrike.Vulnerability.apps.product_name_version | String | Name and version of the product associated with the vulnerability | 
| CrowdStrike.Vulnerability.apps.sub_status | String | Status of each product associated with the vulnerability. Possible values are: open, closed, or reopen | 
| CrowdStrike.Vulnerability.apps.remediation.ids | String | Remediation ID of each product associated with the vulnerability | 
| CrowdStrike.Vulnerability.host_info.hostname | String | Name of the machine | 
| CrowdStrike.Vulnerability.host_info.instance_id | String | Cloud instance ID of the host | 
| CrowdStrike.Vulnerability.host_info.service_provider_account_id | String | Cloud service provider account ID for the host | 
| CrowdStrike.Vulnerability.host_info.service_provider | String | Cloud service provider for the host | 
| CrowdStrike.Vulnerability.host_info.os_build | String | Operating system build |
| CrowdStrike.Vulnerability.host_info.product_type_desc | String | Type of host a sensor is running on | 
| CrowdStrike.Vulnerability.host_info.local_ip | String | Device's local IP address |
| CrowdStrike.Vulnerability.host_info.machine_domain | String | Active Directory domain name | 
| CrowdStrike.Vulnerability.host_info.os_version | String | Operating system version |
| CrowdStrike.Vulnerability.host_info.ou | String | Active directory organizational unit name | 
| CrowdStrike.Vulnerability.host_info.site_name | String | Active directory site name |
| CrowdStrike.Vulnerability.host_info.system_manufacturer | String | Name of the system manufacturer | 
| CrowdStrike.Vulnerability.host_info.groups.id | String | Array of host group IDs that the host is assigned to |
| CrowdStrike.Vulnerability.host_info.groups.name | String | Array of host group names that the host is assigned to |
| CrowdStrike.Vulnerability.host_info.tags | String | Name of a tag assigned to a host |
| CrowdStrike.Vulnerability.host_info.platform | String | Operating system platform |
| CrowdStrike.Vulnerability.remediation.entities.id | String | Unique ID of the remediation |
| CrowdStrike.Vulnerability.remediation.entities.reference | String | Relevant reference for the remediation that can be used to get additional details for the remediation |
| CrowdStrike.Vulnerability.remediation.entities.title | String | Short description of the remediation |
| CrowdStrike.Vulnerability.remediation.entities.action | String | Expanded description of the remediation |
| CrowdStrike.Vulnerability.remediation.entities.link | String |  Link to the remediation page for the vendor |
| CrowdStrike.Vulnerability.cve.id | String | Unique identifier for a vulnerability as cataloged in the National Vulnerability Database (NVD) |
| CrowdStrike.Vulnerability.cve.base_score | String | Base score of the CVE (float value between 1 and 10) |
| CrowdStrike.Vulnerability.cve.severity | String | CVSS severity rating of the vulnerability |
| CrowdStrike.Vulnerability.cve.exploit_status | String | Numeric value of the most severe known exploit |
| CrowdStrike.Vulnerability.cve.exprt_rating | String | ExPRT rating assigned by CrowdStrike's predictive AI rating system |
| CrowdStrike.Vulnerability.cve.description | String | Brief explanation of the CVE |
| CrowdStrike.Vulnerability.cve.published_date | String | UTC timestamp with the date and time the vendor published the CVE |
| CrowdStrike.Vulnerability.cve.vendor_advisory | String | Link to the vendor page where the CVE was disclosed |
| CrowdStrike.Vulnerability.cve.exploitability_score | String | Exploitability score of the CVE (float values from 1-4) |
| CrowdStrike.Vulnerability.cve.impact_score | String | Impact score of the CVE (float values from 1-6) |
| CrowdStrike.Vulnerability.cve.vector | String | Textual representation of the metric values used to score the vulnerability |
| CrowdStrike.Vulnerability.cve.remediation_level | String | CVSS remediation level of the vulnerability (U = Unavailable, or O = Official fix) |
| CrowdStrike.Vulnerability.cve.cisa_info.is_cisa_kev | String | Whether to filter for vulnerabilities that are in the CISA Known Exploited Vulnerabilities (KEV) catalog |
| CrowdStrike.Vulnerability.cve.cisa_info.due_date | String | Date before which CISA mandates subject organizations to patch the vulnerability |
| CrowdStrike.Vulnerability.cve.spotlight_published_date | String | UTC timestamp with the date and time Spotlight enabled coverage for the vulnerability |
| CrowdStrike.Vulnerability.cve.actors | String | Adversaries associated with the vulnerability |
| CrowdStrike.Vulnerability.cve.name | String | The vulnerability name |

#### Command example

``` cs-falcon-spotlight-search-vulnerability filter=status:['open','closed'] cve_id=CVE-2021-2222 cve_severity='LOW,HIGH' display_host_info=false display_evaluation_logic_info=false display_remediation_info=false limit=1 ```

#### Context Example

```json
{
    "resources": [
        {
            "id": "id_num",
            "cid": "cid_num",
            "aid": "aid_num",
            "created_timestamp": "2021-07-13T01:12:57Z",
            "updated_timestamp": "2022-10-27T18:32:21Z",
            "status": "open",
            "apps": [
                {
                    "product_name_version": "product",
                    "sub_status": "open",
                    "remediation": {
                        "ids": [
                            "1234"
                        ]
                    },
                    "evaluation_logic": {
                        "id": "1234"
                    }
                }
            ],
            "suppression_info": {
                "is_suppressed": false
            },
            "cve": {
                "id": "CVE-2021-2222",
                "base_score": 5.5,
                "severity": "MEDIUM",
                "exploit_status": 0,
                "exprt_rating": "LOW",
                "remediation_level": "O",
                "cisa_info": {
                    "is_cisa_kev": false
                },
                "spotlight_published_date": "2021-05-10T17:08:00Z",
                "description": "description\n",
                "published_date": "2021-02-25T23:15:00Z",
                "vendor_advisory": [
                    "web address"
                ],
                "exploitability_score": 1.8,
                "impact_score": 3.6,
                "vector": "vendor"
            }
        }
    ]
}
```

| CVE ID | CVE Severity | CVE Base Score | CVE Published Date | CVE Impact Score | CVE Exploitability Score | CVE Vector | 
| --- | --- | --- | --- | --- | --- |  --- |
| CVE-2021-2222 | LOW | 5.5 | 2021-05-10T17:08:00Z | 3.6 | 0 | vendor |

### cs-falcon-spotlight-list-host-by-vulnerability

***
Retrieve vulnerability details for a specific ID and host. Supported with the CrowdStrike Spotlight license.

#### Base Command

`cs-falcon-spotlight-list-host-by-vulnerability`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_ids | Unique identifier for a vulnerability as cataloged in the National Vulnerability Database (NVD). This filter supports multiple values and negation | Required |
| limit | Maximum number of items to return (1-5000) | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.VulnerabilityHost.id | String | Unique system-assigned ID of the vulnerability. | 
| CrowdStrike.VulnerabilityHost.cid | String | Unique system-generated customer identifier (CID) of the account | 
| CrowdStrike.VulnerabilityHost.aid | String | Unique agent identifier (AID) of the sensor where the vulnerability was found | 
| CrowdStrike.VulnerabilityHost.created_timestamp | String | UTC date and time that the vulnerability was created in Spotlight | 
| CrowdStrike.VulnerabilityHost.updated_timestamp | String | UTC date and time of the last update made on the vulnerability | 
| CrowdStrike.VulnerabilityHost.status | String | Vulnerability's current status. Possible values are: open, closed, reopen, or expired. | 
| CrowdStrike.VulnerabilityHost.apps.product_name_version | String | Name and version of the product associated with the vulnerability | 
| CrowdStrike.VulnerabilityHost.apps.sub_status | String | Status of each product associated with the vulnerability | 
| CrowdStrike.VulnerabilityHost.apps.remediation.ids | String | Remediation ID of each product associated with the vulnerability |
| CrowdStrike.VulnerabilityHost.apps.evaluation_logic.id | String | Unique system-assigned ID of the vulnerability evaluation logic |
| CrowdStrike.VulnerabilityHost.suppression_info.is_suppressed | String | Indicates if the vulnerability is suppressed by a suppression rule |
| CrowdStrike.VulnerabilityHost.host_info.hostname | String | Name of the machine | 
| CrowdStrike.VulnerabilityHost.host_info.instance_id | String | Cloud service provider account ID for the host | 
| CrowdStrike.VulnerabilityHost.host_info.service_provider_account_id | String | Cloud service provider for the host | 
| CrowdStrike.VulnerabilityHost.host_info.service_provider | String | Operating system build | 
| CrowdStrike.VulnerabilityHost.host_info.os_build | String | Operating system build |
| CrowdStrike.VulnerabilityHost.host_info.product_type_desc | String | Type of host a sensor is running on | 
| CrowdStrike.VulnerabilityHost.host_info.local_ip | String | Device's local IP address |
| CrowdStrike.VulnerabilityHost.host_info.machine_domain | String | Active Directory domain name | 
| CrowdStrike.VulnerabilityHost.host_info.os_version | String | Operating system version |
| CrowdStrike.VulnerabilityHost.host_info.ou | String | Active directory organizational unit name | 
| CrowdStrike.VulnerabilityHost.host_info.site_name | String | Active directory site name |
| CrowdStrike.VulnerabilityHost.host_info.system_manufacturer | String | Name of the system manufacturer | 
| CrowdStrike.VulnerabilityHost.host_info.groups.id | String | Array of host group IDs that the host is assigned to |
| CrowdStrike.VulnerabilityHost.host_info.groups.name | String | Array of host group names that the host is assigned to |
| CrowdStrike.VulnerabilityHost.host_info.tags | String | Name of a tag assigned to a host |
| CrowdStrike.VulnerabilityHost.host_info.platform | String | Operating system platform |
| CrowdStrike.VulnerabilityHost.cve.id | String | Unique identifier for a vulnerability as cataloged in the National Vulnerability Database (NVD) |

#### Command example

``` cs-falcon-spotlight-list-host-by-vulnerability cve_ids=CVE-2021-2222 ```

#### Context Example

```json
{
        {
            "id": "id",
            "cid": "cid",
            "aid": "aid",
            "created_timestamp": "2021-09-16T15:12:42Z",
            "updated_timestamp": "2022-10-19T00:54:43Z",
            "status": "open",
            "apps": [
                {
                    "product_name_version": "prod",
                    "sub_status": "open",
                    "remediation": {
                        "ids": [
                            "id"
                        ]
                    },
                    "evaluation_logic": {
                        "id": "id"
                    }
                }
            ],
            "suppression_info": {
                "is_suppressed": false
            },
            "host_info": {
                "hostname": "host",
                "local_ip": "10.128.0.7",
                "machine_domain": "",
                "os_version": "version",
                "ou": "",
                "site_name": "",
                "system_manufacturer": "manufactor",
                "tags": [],
                "platform": "Windows",
                "instance_id": "instance id",
                "service_provider_account_id": "id",
                "service_provider": "id",
                "os_build": "os build",
                "product_type_desc": "Server"
            },
            "cve": {
                "id": "CVE-20212-2222"
            }
        }
    
}
```

#### Human Readable Output

| CVE ID | Host Info hostname | Host Info os Version | Host Info Product Type Desc | Host Info Local IP | Host Info ou | Host Info Machine Domain | Host Info Site Name | CVE Exploitability Score | CVE Vector |
| --- | --- | --- | --- |  --- | --- |  --- | --- |  --- | --- |
| CVE-20212-2222 |  host | 1 | Server | ip |  |  | site | 5.5 |  |

### cve

Retrieve vulnerability details according to the selected filter. Each request requires at least one filter parameter. Supported with the CrowdStrike Spotlight license.

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | Deprecated. Use cve instead. | Optional |
| cve | Unique identifier for a vulnerability as cataloged in the National Vulnerability Database (NVD). This filter supports multiple values and negation | Optional |

#### Command example

``` cve cve_id=CVE-2021-2222 ```

#### Human Readable Output

| ID | Severity | Published Date | Base Score |
| --- | --- | --- | --- |
| CVE-2021-2222 | HIGH | 2021-09-16T15:12:42Z | 1 |


### cs-falcon-create-ml-exclusion

***
Create an ML exclusion.

#### Base Command

`cs-falcon-create-ml-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | Value to match for exclusion. | Required | 
| excluded_from | A comma-separated list from where to exclude the exclusion. Possible values are: blocking, extraction. | Required | 
| comment | Comment describing why the exclusions were created. | Optional | 
| groups | A comma-separated list of group ID(s) impacted by the exclusion OR all if empty. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.MLExclusion.id | String | The ML exclusion ID. | 
| CrowdStrike.MLExclusion.value | String | The ML exclusion value. | 
| CrowdStrike.MLExclusion.regexp_value | String | A regular expression for matching the excluded value. | 
| CrowdStrike.MLExclusion.value_hash | String | An hash of the value field. | 
| CrowdStrike.MLExclusion.excluded_from | String | What the exclusion applies to \(e.g., a specific ML model\). | 
| CrowdStrike.MLExclusion.groups.id | String | Group's ID that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.group_type | String | Groups type that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.name | String | Groups name that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.description | String | Groups description that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.assignment_rule | String | Groups assignment rule that the exclusion is associated with. | 
| CrowdStrike.MLExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.MLExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.MLExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.MLExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.MLExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.MLExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.MLExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.MLExclusion.created_on | Date | Indicate who created the rule. | 
| CrowdStrike.MLExclusion.created_by | String | The date when the exclusion rule was created. | 

#### Command example

```!cs-falcon-create-ml-exclusion value=/demo-test excluded_from=blocking groups=999999```

#### Context Example

```json
{
    "CrowdStrike": {
        "MLExclusion": {
            "applied_globally": false,
            "created_by": "api-client-id:123456",
            "created_on": "2023-03-06T13:57:14.853546312Z",
            "excluded_from": [
                "blocking"
            ],
            "groups": [
                {
                    "assignment_rule": "device_id",
                    "created_by": "admin@test.com",
                    "created_timestamp": "2023-01-23T15:01:11.846726918Z",
                    "description": "",
                    "group_type": "static",
                    "id": "999999",
                    "modified_by": "admin@test.com",
                    "modified_timestamp": "2023-01-23T15:18:52.316882546Z",
                    "name": "Lab env"
                }
            ],
            "id": "123456",
            "last_modified": "2023-03-06T13:57:14.853546312Z",
            "modified_by": "api-client-id:123456",
            "regexp_value": "\\/demo-test",
            "value": "/demo-test",
            "value_hash": "abcdef123456"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon machine learning exclusion

>|Id|Value|RegexpValue|ValueHash|ExcludedFrom|Groups|AppliedGlobally|LastModified|ModifiedBy|CreatedOn|CreatedBy|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 123456 | /demo-test | \/demo-test | abcdef123456 | ***values***: blocking | **-**	***id***: 999999<br/>	***group_type***: static<br/>	***name***: Lab env<br/>	***description***: <br/>	***assignment_rule***: device_id:<br/>	***created_by***: <admin@test.com><br/>	***created_timestamp***: 2023-01-23T15:01:11.846726918Z<br/>	***modified_by***: <admin@test.com><br/>	***modified_timestamp***: 2023-01-23T15:18:52.316882546Z |  | 2023-03-06T13:57:14.853546312Z | api-client-id:123456 | 2023-03-06T13:57:14.853546312Z | api-client-id:123456 |


### cs-falcon-update-ml-exclusion

***
Updates an ML exclusion. At least one argument is required in addition to the ID argument.

#### Base Command

`cs-falcon-update-ml-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the exclusion to update. | Required | 
| value | Value to match for the exclusion (the exclusion pattern). | Optional | 
| comment | Comment describing why the exclusions were created. | Optional | 
| groups | A comma-separated list of group ID(s) impacted by the exclusion. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.MLExclusion.id | String | The ML exclusion ID. | 
| CrowdStrike.MLExclusion.value | String | The ML exclusion value. | 
| CrowdStrike.MLExclusion.regexp_value | String | A regular expression for matching the excluded value. | 
| CrowdStrike.MLExclusion.value_hash | String | An hash of the value field. | 
| CrowdStrike.MLExclusion.excluded_from | String | What the exclusion applies to \(e.g., a specific ML model\). | 
| CrowdStrike.MLExclusion.groups.id | String | Groups ID that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.group_type | String | Groups type that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.name | String | Groups name that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.description | String | Groups description that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.assignment_rule | String | Groups assignment rule that the exclusion is associated with. | 
| CrowdStrike.MLExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.MLExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.MLExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.MLExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.MLExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.MLExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.MLExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.MLExclusion.created_on | Date | Indicate who created the rule. | 
| CrowdStrike.MLExclusion.created_by | String | The date when the exclusion rule was created. | 

#### Command example

```!cs-falcon-update-ml-exclusion id=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 comment=demo-comment```

#### Context Example

```json
{
    "CrowdStrike": {
        "MLExclusion": {
            "applied_globally": false,
            "created_by": "api-client-id:123456",
            "created_on": "2023-03-06T13:56:25.940685483Z",
            "excluded_from": [
                "extraction",
                "blocking"
            ],
            "groups": [
                {
                    "assignment_rule": "device_id:",
                    "created_by": "admin@test.com",
                    "created_timestamp": "2023-01-23T15:01:11.846726918Z",
                    "description": "",
                    "group_type": "static",
                    "id": "999999",
                    "modified_by": "admin@test.com",
                    "modified_timestamp": "2023-01-23T15:18:52.316882546Z",
                    "name": "Lab env"
                }
            ],
            "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "last_modified": "2023-03-06T13:57:21.57829431Z",
            "modified_by": "api-client-id:123456",
            "regexp_value": "\\/demo",
            "value": "/demo",
            "value_hash": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon machine learning exclusion

>|Id|Value|RegexpValue|ValueHash|ExcludedFrom|Groups|AppliedGlobally|LastModified|ModifiedBy|CreatedOn|CreatedBy|
>|---|---|---|---|---|---|---|---|---|---|---|
>| a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | /demo | \/demo | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | ***values***: extraction, blocking | **-**	***id***: 999999<br/>	***group_type***: static<br/>	***name***: Lab env<br/>	***description***: <br/>	***assignment_rule***: device_id:<br/>	***created_by***: <admin@test.com><br/>	***created_timestamp***: 2023-01-23T15:01:11.846726918Z<br/>	***modified_by***: <admin@test.com><br/>	***modified_timestamp***: 2023-01-23T15:18:52.316882546Z |  | 2023-03-06T13:57:21.57829431Z | api-client-id:123456 | 2023-03-06T13:56:25.940685483Z | api-client-id:123456 |


### cs-falcon-delete-ml-exclusion

***
Delete the ML exclusions by ID.

#### Base Command

`cs-falcon-delete-ml-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of exclusion IDs to delete. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!cs-falcon-delete-ml-exclusion ids=123456```

#### Human Readable Output

>'The machine learning exclusions with IDs '123456' was successfully deleted.'

### cs-falcon-search-ml-exclusion

***
Get a list of ML exclusions by specifying their IDs, value, or a specific filter.

#### Base Command

### cs-falcon-search-ml-exclusion

***
Get a list of ML exclusions by specifying their IDs, value, or a specific filter.

#### Base Command

`cs-falcon-search-ml-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | A custom filter by which the exclusions should be filtered.<br/> The syntax follows the pattern `&lt;property&gt;:[operator]'&lt;value&gt;'` for example: value:'test'.<br/> Available filters: applied_globally, created_by, created_on, last_modified, modified_by, value.<br/> For more information, see: <https://www.falconpy.io/Service-Collections/Falcon-Query-Language>. | Optional | 
| value | The value by which the exclusions should be filtered. | Optional | 
| ids | A comma-separated list of exclusion IDs to retrieve. The IDs overwrite the filter and value. | Optional | 
| limit | The maximum number of records to return. [1-500]. Applies only if the IDs argument is not supplied. | Optional | 
| offset | The offset to start retrieving records from. Applies only if the IDs argument is not supplied. | Optional | 
| sort | How to sort the retrieved exclusions. Possible values are: applied_globally.asc, applied_globally.desc, created_by.asc, created_by.desc, created_on.asc, created_on.desc, last_modified.asc, last_modified.desc, modified_by.asc, modified_by.desc, value.asc, value.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.MLExclusion.id | String | The ML exclusion ID. | 
| CrowdStrike.MLExclusion.value | String | The ML exclusion value. | 
| CrowdStrike.MLExclusion.regexp_value | String | A regular expression for matching the excluded value. | 
| CrowdStrike.MLExclusion.value_hash | String | A hash of the value field. | 
| CrowdStrike.MLExclusion.excluded_from | String | What the exclusion applies to \(e.g., a specific ML model\). | 
| CrowdStrike.MLExclusion.groups.id | String | Groups ID that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.group_type | String | Groups type that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.name | String | Groups name that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.description | String | Groups description that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.assignment_rule | String | Groups assignment rule that the exclusion is associated with. | 
| CrowdStrike.MLExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.MLExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.MLExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.MLExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.MLExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.MLExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.MLExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.MLExclusion.created_on | Date | Indicate who created the rule. | 
| CrowdStrike.MLExclusion.created_by | String | The date when the exclusion rule was created. | 

#### Command example

```!cs-falcon-search-ml-exclusion limit=1```

#### Context Example

```json
{
    "CrowdStrike": {
        "MLExclusion": {
            "applied_globally": false,
            "created_by": "api-client-id:123456",
            "created_on": "2023-03-01T18:51:07.196018144Z",
            "excluded_from": [
                "blocking"
            ],
            "groups": [
                {
                    "assignment_rule": "device_id",
                    "created_by": "admin@test.com",
                    "created_timestamp": "2023-01-23T15:01:11.846726918Z",
                    "description": "",
                    "group_type": "static",
                    "id": "999999",
                    "modified_by": "admin@test.com",
                    "modified_timestamp": "2023-01-23T15:18:52.316882546Z",
                    "name": "Lab env"
                }
            ],
            "id": "123456",
            "last_modified": "2023-03-01T18:51:07.196018144Z",
            "modified_by": "api-client-id:123456",
            "regexp_value": "\\/MosheTest2-432",
            "value": "/MosheTest2-432",
            "value_hash": "abcdef123456"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon machine learning exclusions

>|Id|Value|RegexpValue|ValueHash|ExcludedFrom|Groups|AppliedGlobally|LastModified|ModifiedBy|CreatedOn|CreatedBy|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 123456 | /MosheTest2-432 | \/MosheTest2-432 | abcdef123456 | ***values***: blocking | **-**	***id***: 999999<br/>	***group_type***: static<br/>	***name***: Lab env<br/>	***description***: <br/>	***assignment_rule***: device_id<br/>	***created_by***: <admin@test.com><br/>	***created_timestamp***: 2023-01-23T15:01:11.846726918Z<br/>	***modified_by***: <admin@test.com><br/>	***modified_timestamp***: 2023-01-23T15:18:52.316882546Z |  | 2023-03-01T18:51:07.196018144Z | api-client-id:123456 | 2023-03-01T18:51:07.196018144Z | api-client-id:123456 |


### cs-falcon-create-ioa-exclusion

***
Create an IOA exclusion.

#### Base Command

`cs-falcon-create-ioa-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exclusion_name | Name of the exclusion. | Required | 
| pattern_name | Name of the exclusion pattern. | Optional | 
| pattern_id | ID of the exclusion pattern. | Required | 
| cl_regex | Command line regular expression. | Required | 
| ifn_regex | Image file name regular expression. | Required | 
| comment | Comment describing why the exclusions were created. | Optional | 
| description | Exclusion description. | Optional | 
| detection_json | JSON formatted detection template. | Optional | 
| groups | A comma-separated list of group ID(s) impacted by the exclusion OR all if empty. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOAExclusion.id | String | A unique identifier for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.name | String | The name of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.description | String | A description of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_id | String | The identifier of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_name | String | The name of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.ifn_regex | String | A regular expression used for file name matching. | 
| CrowdStrike.IOAExclusion.cl_regex | String | A regular expression used for command line matching. | 
| CrowdStrike.IOAExclusion.detection_json | String | A JSON string that describes the detection logic for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.groups.id | String | Groups ID that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.group_type | String | Groups type that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.name | String | Groups name that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.description | String | Groups description that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.assignment_rule | String | Groups assignment rule that the exclusion is associated with. | 
| CrowdStrike.IOAExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.IOAExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.IOAExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.IOAExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.IOAExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.IOAExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.IOAExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.IOAExclusion.created_on | Date | Indicate who created the rule. | 
| CrowdStrike.IOAExclusion.created_by | String | The date when the exclusion rule was created. | 

#### Command example

```!cs-falcon-create-ioa-exclusion exclusion_name=demo-test pattern_id=101010 cl_regex=.* ifn_regex="c:\\\\windows\\\\system32\\\\test.exe" groups=999999```

#### Context Example

```json
{
    "CrowdStrike": {
        "IOAExclusion": {
            "applied_globally": false,
            "cl_regex": ".*",
            "created_by": "api-client-id:123456",
            "created_on": "2023-03-06T13:57:41.746172897Z",
            "description": "",
            "detection_json": "",
            "groups": [
                {
                    "assignment_rule": "device_id",
                    "created_by": "admin@test.com",
                    "created_timestamp": "2023-01-23T15:01:11.846726918Z",
                    "description": "",
                    "group_type": "static",
                    "id": "999999",
                    "modified_by": "admin@test.com",
                    "modified_timestamp": "2023-01-23T15:18:52.316882546Z",
                    "name": "Lab env"
                }
            ],
            "id": "123456",
            "ifn_regex": "c:\\\\windows\\\\system32\\\\test.exe",
            "last_modified": "2023-03-06T13:57:41.746172897Z",
            "modified_by": "api-client-id:123456",
            "name": "demo-test",
            "pattern_id": "101010",
            "pattern_name": ""
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon IOA exclusion

>|Id|Name|PatternId|IfnRegex|ClRegex|Groups|AppliedGlobally|LastModified|ModifiedBy|CreatedOn|CreatedBy|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 123456 | demo-test | 101010 | c:\\windows\\system32\\poqexec\.exe | .* | **-**	***id***: 999999<br/>	***group_type***: static<br/>	***name***: Lab env<br/>	***description***: <br/>	***assignment_rule***: device_id<br/>	***created_by***: <admin@test.com><br/>	***created_timestamp***: 2023-01-23T15:01:11.846726918Z<br/>	***modified_by***: <admin@test.com><br/>	***modified_timestamp***: 2023-01-23T15:18:52.316882546Z |  | 2023-03-06T13:57:41.746172897Z | api-client-id:123456 | 2023-03-06T13:57:41.746172897Z | api-client-id:123456 |


### cs-falcon-update-ioa-exclusion

***
Updates an IOA exclusion. At least one argument is required in addition to the ID argument.

#### Base Command

`cs-falcon-update-ioa-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the exclusion to update. | Required | 
| exclusion_name | Name of the exclusion. | Optional | 
| pattern_id | ID of the exclusion pattern to update. | Optional | 
| pattern_name | Name of the exclusion pattern. | Optional | 
| cl_regex | Command line regular expression. | Optional | 
| ifn_regex | Image file name regular expression. | Optional | 
| comment | Comment describing why the exclusions was created. | Optional | 
| description | Exclusion description. | Optional | 
| detection_json | JSON formatted detection template. | Optional | 
| groups | A comma-separated list of group ID(s) impacted by the exclusion. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOAExclusion.id | String | A unique identifier for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.name | String | The name of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.description | String | A description of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_id | String | The identifier of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_name | String | The name of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.ifn_regex | String | A regular expression used for file name matching. | 
| CrowdStrike.IOAExclusion.cl_regex | String | A regular expression used for command line matching. | 
| CrowdStrike.IOAExclusion.detection_json | String | A JSON string that describes the detection logic for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.groups.id | String | Groups ID that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.group_type | String | Groups type that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.name | String | Groups name that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.description | String | Groups description that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.assignment_rule | String | Groups assignment rule that the exclusion is associated with. | 
| CrowdStrike.IOAExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.IOAExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.IOAExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.IOAExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.IOAExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.IOAExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.IOAExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.IOAExclusion.created_on | Date | Indicate who created the rule. | 
| CrowdStrike.IOAExclusion.created_by | String | The date when the exclusion rule was created. | 

#### Command example

```!cs-falcon-update-ioa-exclusion id=123456 description=demo-description```

#### Context Example

```json
{
    "CrowdStrike": {
        "IOAExclusion": {
            "applied_globally": false,
            "cl_regex": ".*",
            "created_by": "api-client-id:123456",
            "created_on": "2023-03-06T13:46:58.137122925Z",
            "description": "demo-description",
            "detection_json": "",
            "groups": [
                {
                    "assignment_rule": "device_id",
                    "created_by": "admin@test.com",
                    "created_timestamp": "2023-01-23T15:01:11.846726918Z",
                    "description": "",
                    "group_type": "static",
                    "id": "999999",
                    "modified_by": "admin@test.com",
                    "modified_timestamp": "2023-01-23T15:18:52.316882546Z",
                    "name": "Lab env"
                }
            ],
            "id": "123456",
            "ifn_regex": "c:\\\\windows\\\\system32\\\\poqexec\\.exe",
            "last_modified": "2023-03-06T13:57:49.086458198Z",
            "modified_by": "api-client-id:123456",
            "name": "demo",
            "pattern_id": "101010",
            "pattern_name": ""
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon IOA exclusion

>|Id|Name|Description|PatternId|IfnRegex|ClRegex|Groups|AppliedGlobally|LastModified|ModifiedBy|CreatedOn|CreatedBy|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 123456 | demo | demo-description | 101010 | c:\\windows\\system32\\poqexec\.exe | .* | **-**	***id***: 999999<br/>	***group_type***: static<br/>	***name***: Lab env<br/>	***description***: <br/>	***assignment_rule***: device_id<br/>	***created_by***: <admin@test.com><br/>	***created_timestamp***: 2023-01-23T15:01:11.846726918Z<br/>	***modified_by***: <admin@test.com><br/>	***modified_timestamp***: 2023-01-23T15:18:52.316882546Z |  | 2023-03-06T13:57:49.086458198Z | api-client-id:123456 | 2023-03-06T13:46:58.137122925Z | api-client-id:123456 |


### cs-falcon-delete-ioa-exclusion

***
Delete the IOA exclusions by ID.

#### Base Command

`cs-falcon-delete-ioa-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of exclusion IDs to delete. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!cs-falcon-delete-ioa-exclusion ids=123456```

#### Human Readable Output

>'The IOA exclusions with IDs '123456' was successfully deleted.'


### cs-falcon-search-ioa-exclusion

***
Get a list of IOA exclusions by specifying their IDs or a filter.

#### Base Command

`cs-falcon-search-ioa-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | A custom filter by which the exclusions should be filtered.<br/> The syntax follows the pattern `&lt;property&gt;:[operator]'&lt;value&gt;'` for example: name:'test'.<br/> Available filters: applied_globally, created_by, created_on, name, last_modified, modified_by, value, pattern.<br/> For more information, see: <https://www.falconpy.io/Service-Collections/Falcon-Query-Language>. | Optional | 
| name | The name by which the exclusions should be filtered. | Optional | 
| ids | A comma-separated list of exclusion IDs to retrieve. The IDs overwrite the filter and name. | Optional | 
| limit | The limit of how many exclusions to retrieve. Default is 50. Applies only if the IDs argument is not supplied. | Optional | 
| offset | The offset of how many exclusions to skip. Default is 0. Applies only if the IDs argument is not supplied. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOAExclusion.id | String | A unique identifier for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.name | String | The name of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.description | String | A description of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_id | String | The identifier of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_name | String | The name of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.ifn_regex | String | A regular expression used for file name matching. | 
| CrowdStrike.IOAExclusion.cl_regex | String | A regular expression used for command line matching. | 
| CrowdStrike.IOAExclusion.detection_json | String | A JSON string that describes the detection logic for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.groups.id | String | Groups ID that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.group_type | String | Groups type that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.name | String | Groups name that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.description | String | Groups description that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.assignment_rule | String | Groups assignment rule that the exclusion is associated with. | 
| CrowdStrike.IOAExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.IOAExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.IOAExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.IOAExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.IOAExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.IOAExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.IOAExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.IOAExclusion.created_on | Date | Indicate who created the rule. | 
| CrowdStrike.IOAExclusion.created_by | String | The date when the exclusion rule was created. | 

#### Command example

```!cs-falcon-search-ioa-exclusion limit=1```

#### Context Example

```json
{
    "CrowdStrike": {
        "IOAExclusion": {
            "applied_globally": true,
            "cl_regex": "regex",
            "created_by": "user@test.com",
            "created_on": "2023-02-06T16:42:19.29906839Z",
            "description": "demo description",
            "detection_json": "",
            "groups": [],
            "id": "123456",
            "ifn_regex": ".*\\\\Windows\\\\System32\\\\choice\\.exe",
            "last_modified": "2023-02-26T15:30:04.554767735Z",
            "modified_by": "api-client-id:123456",
            "name": "My IOA Exclusion",
            "pattern_id": "101010",
            "pattern_name": "P_name"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon IOA exclusions

>|Id|Name|Description|PatternId|PatternName|IfnRegex|ClRegex|AppliedGlobally|LastModified|ModifiedBy|CreatedOn|CreatedBy|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 123456 | My IOA Exclusion | demo description | 101010 | P_name | .*\\Windows\\System32\\choice\.exe | choice\s+/m\s+crowdstrike_sample_detection |  | 2023-02-26T15:30:04.554767735Z | api-client-id:123456 | 2023-02-06T16:42:19.29906839Z | <user@test.com> |


### cs-falcon-list-quarantined-file

***
Get quarantine file metadata by specified IDs or filter.

#### Base Command

`cs-falcon-list-quarantined-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of quarantined file IDs to retrieve. | Optional | 
| filter | A custom filter by which the retrieve quarantined file should be filtered. | Optional | 
| sha256 | A comma-separated list of SHA256 hash of the files to retrieve. | Optional | 
| filename | A comma-separated list of the name of the files to retrieve. | Optional | 
| state | Filter the retrieved files by state. | Optional | 
| hostname | A comma-separated list of the hostnames of the files to retrieve. | Optional | 
| username | A comma-separated list of the usernames of the files to retrieve. | Optional | 
| limit | Maximum number of IDs to return. Max 5000. Default 50. | Optional | 
| offset | Starting index of the overall result set from which to return IDs. Default 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.QuarantinedFile.id | String | A unique identifier for the quarantined file. | 
| CrowdStrike.QuarantinedFile.aid | String | The agent identifier of the agent that quarantined the file. | 
| CrowdStrike.QuarantinedFile.cid | String | The unique identifier for the customer that who the agent. | 
| CrowdStrike.QuarantinedFile.sha256 | String | The SHA256 hash value of the quarantined file. | 
| CrowdStrike.QuarantinedFile.paths.path | String | The full path of the quarantined file. | 
| CrowdStrike.QuarantinedFile.paths.filename | String | The name of the quarantined file. | 
| CrowdStrike.QuarantinedFile.paths.state | String | The current state of the quarantined file path \(e.g., "purged"\). | 
| CrowdStrike.QuarantinedFile.state | String | The current state of the quarantined file \(e.g., "unrelease_pending"\). | 
| CrowdStrike.QuarantinedFile.detect_ids | String | The detection identifiers associated with the quarantined file. | 
| CrowdStrike.QuarantinedFile.hostname | String | The hostname of the agent that quarantined the file. | 
| CrowdStrike.QuarantinedFile.username | String | The username associated with the quarantined file. | 
| CrowdStrike.QuarantinedFile.date_updated | Date | The date the quarantined file was last updated. | 
| CrowdStrike.QuarantinedFile.date_created | Date | The date the quarantined file was created. | 

#### Command example

```!cs-falcon-list-quarantined-file limit=1```

#### Context Example

```json
{
    "CrowdStrike": {
        "QuarantinedFile": {
            "aid": "a123456",
            "cid": "c123456",
            "date_created": "2022-12-13T14:23:49Z",
            "date_updated": "2023-03-06T13:47:30Z",
            "detect_ids": [
                "ldt:a123456:456789"
            ],
            "hostname": "INSTANCE-1",
            "id": "a123456_sha123456",
            "paths": [
                {
                    "filename": "nc.exe",
                    "path": "\\Device\\HarddiskVolume3\\Users\\admin\\Downloads\\hamuzim\\test.exe",
                    "state": "quarantined"
                }
            ],
            "sha256": "sha123456",
            "state": "deleted",
            "username": "admin"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon Quarantined File

>|Id|Aid|Cid|Sha256|Paths|State|DetectIds|Hostname|Username|DateUpdated|DateCreated|
>|---|---|---|---|---|---|---|---|---|---|---|
>| a123456_sha123456 | a123456 | c123456 | sha123456 | **-**	***path***: \Device\HarddiskVolume3\Users\admin\Downloads\hamuzim\netcat-1.11\nc.exe<br/>	***filename***: nc.exe<br/>	***state***: quarantined | deleted | ***values***: ldt:a123456:456789 | INSTANCE-1 | admin | 2023-03-06T13:47:30Z | 2022-12-13T14:23:49Z |


### cs-falcon-apply-quarantine-file-action

***
Apply action to quarantined file by file IDs or filter.

#### Base Command

`cs-falcon-apply-quarantine-file-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of quarantined file IDs to update. | Optional | 
| action | Action to perform against the quarantined file. Possible values are: delete, release, unrelease. | Required | 
| comment | Comment to appear along with the action taken. | Required | 
| filter | Update files based on a custom filter. | Optional | 
| sha256 | A comma-separated list of quarantined files SHA256 to update. | Optional | 
| filename | A comma-separated list of quarantined file names to update. | Optional | 
| state | Update files based on the state. | Optional | 
| hostname | A comma-separated list of quarantined file hostnames to update. | Optional | 
| username | A comma-separated list of quarantined files username to update. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!cs-falcon-apply-quarantine-file-action filename=nc.exe action=delete comment=demo-comment```

#### Human Readable Output

>The Quarantined File with IDs ['a123456_sha123456'] was successfully updated.

### cs-falcon-ods-query-scan

***
Retrieve ODS scan details.

#### Base Command

`cs-falcon-ods-query-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Valid CS-Falcon-FQL filter to query with. | Optional | 
| ids | Comma-separated list of scan IDs to retrieve details about. If set, will override all other arguments. | Optional | 
| initiated_from | Comma-separated list of scan initiation sources to filter by. | Optional | 
| status | Comma-separated list of scan statuses to filter by. | Optional | 
| severity | Comma-separated list of scan severities to filter by. | Optional | 
| scan_started_on | UTC-format time of scan start to filter by. | Optional | 
| scan_completed_on | UTC-format time of the scan completion to filter by. | Optional | 
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Maximum number of resources to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.ODSScan.id | String | A unique identifier for the scan event. | 
| CrowdStrike.ODSScan.cid | String | A unique identifier for the client that triggered the scan. | 
| CrowdStrike.ODSScan.profile_id | String | A unique identifier for the scan profile used in the scan. | 
| CrowdStrike.ODSScan.description | String | The ID of the description of the scan. | 
| CrowdStrike.ODSScan.scan_inclusions | String | The files or folders included in the scan. | 
| CrowdStrike.ODSScan.initiated_from | String | The source of the scan initiation. | 
| CrowdStrike.ODSScan.quarantine | Boolean | Whether the scan was set to quarantine. | 
| CrowdStrike.ODSScan.cpu_priority | Number | The CPU priority for the scan \(1-5\). | 
| CrowdStrike.ODSScan.preemption_priority | Number | The preemption priority for the scan. | 
| CrowdStrike.ODSScan.metadata.host_id | String | A unique identifier for the host that was scanned. | 
| CrowdStrike.ODSScan.metadata.host_scan_id | String | A unique identifier for the scan that was performed on the host. | 
| CrowdStrike.ODSScan.metadata.scan_host_metadata_id | String | A unique identifier for the metadata associated with the host scan. | 
| CrowdStrike.ODSScan.metadata.filecount.scanned | Number | The number of files that were scanned. | 
| CrowdStrike.ODSScan.metadata.filecount.malicious | Number | The number of files that were identified as malicious. | 
| CrowdStrike.ODSScan.metadata.filecount.quarantined | Number | The number of files that were quarantined. | 
| CrowdStrike.ODSScan.metadata.filecount.skipped | Number | The number of files that were skipped during the scan. | 
| CrowdStrike.ODSScan.metadata.filecount.traversed | Number | The number of files that were traversed during the scan. | 
| CrowdStrike.ODSScan.metadata.status | String | The status of the scan on this host \(e.g., "pending", "running", "completed", or "failed"\). | 
| CrowdStrike.ODSScan.metadata.started_on | Date | The date and time that the scan started. | 
| CrowdStrike.ODSScan.metadata.completed_on | Date | The date and time that the scan completed. | 
| CrowdStrike.ODSScan.metadata.last_updated | Date | The date and time that the metadata was last updated. | 
| CrowdStrike.ODSScan.status | String | The status of the scan \(e.g., "pending", "running", "completed", or "failed"\). | 
| CrowdStrike.ODSScan.hosts | String | A list of the host IDs that were scanned. | 
| CrowdStrike.ODSScan.endpoint_notification | Boolean | A boolean value indicating whether endpoint notifications are enabled. | 
| CrowdStrike.ODSScan.pause_duration | Number | The number of minutes to pause between scanning each file in hours. | 
| CrowdStrike.ODSScan.max_duration | Number | The maximum amount of time to allow for the scan job in hours. | 
| CrowdStrike.ODSScan.max_file_size | Number | The maximum file size \(in MB\) to scan. | 
| CrowdStrike.ODSScan.sensor_ml_level_detection | Number | The level of detection sensitivity for the local sensor machine learning model. | 
| CrowdStrike.ODSScan.sensor_ml_level_prevention | Number | The level of prevention sensitivity for the local sensor machine learning model. | 
| CrowdStrike.ODSScan.cloud_ml_level_detection | Number | The level of detection sensitivity for the cloud machine learning model. | 
| CrowdStrike.ODSScan.cloud_ml_level_prevention | Number | The level of prevention sensitivity for the cloud machine learning model. | 
| CrowdStrike.ODSScan.policy_setting | Number | A list of policy setting IDs for the scan job \(these correspond to specific policy settings in the Falcon console\). | 
| CrowdStrike.ODSScan.scan_started_on | Date | The timestamp when the scan was started. | 
| CrowdStrike.ODSScan.scan_completed_on | Date | The timestamp when the scan was completed. | 
| CrowdStrike.ODSScan.created_on | Date | The timestamp when the scan was created. | 
| CrowdStrike.ODSScan.created_by | String | The ID of the user who created the scan job. | 
| CrowdStrike.ODSScan.last_updated | Date | The timestamp when the scan job was last updated. | 

#### Command example

```!cs-falcon-ods-query-scan  initiated_from=some_admin_name severity=high scan_started_on=2023-02-27T09:51:33.91608286Z```

#### Context Example

```json
{
    "CrowdStrike": {
        "ODSScan": [
            {
                "cid": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "cloud_ml_level_detection": 4,
                "cloud_ml_level_prevention": 4,
                "cpu_priority": 5,
                "created_by": "someone@email.com",
                "created_on": "2023-05-03T08:45:41.688556439Z",
                "endpoint_notification": true,
                "file_paths": [
                    "C:\\Users\\admin\\Downloads\\hamuzim\\netcat-1.11\\eicar_com.exe"
                ],
                "filecount": {},
                "hosts": [
                    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                ],
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "initiated_from": "some_admin_name",
                "last_updated": "2023-05-03T08:45:43.348230927Z",
                "max_duration": 0,
                "max_file_size": 60,
                "metadata": [
                    {
                        "completed_on": "2023-05-03T08:45:43.274953782Z",
                        "filecount": {
                            "malicious": 0,
                            "quarantined": 0,
                            "scanned": 0,
                            "skipped": 0,
                            "traversed": 0
                        },
                        "host_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                        "host_scan_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                        "last_updated": "2023-05-03T08:45:43.61797613Z",
                        "scan_host_metadata_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                        "started_on": "2023-05-03T08:45:43.069273028Z",
                        "status": "completed"
                    }
                ],
                "pause_duration": 2,
                "policy_setting": [
                    26439818675190,
                    26405458936832,
                    26405458936833,
                    26405458936834,
                    26405458936835,
                    26405458936840,
                    26405458936841,
                    26405458936842,
                    26405458936843,
                    26456998543793,
                    26456998544045,
                    26456998543652,
                    26456998543653,
                    26456998543656,
                    26456998543654,
                    26456998543950,
                    26456998543963
                ],
                "preemption_priority": 1,
                "profile_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "quarantine": true,
                "scan_completed_on": "2023-05-03T08:45:43.274953782Z",
                "scan_inclusions": [
                    "**\\Downloads\\**"
                ],
                "scan_started_on": "2023-02-27T09:51:33.91608286Z",
                "sensor_ml_level_detection": 4,
                "sensor_ml_level_prevention": 4,
                "status": "completed"
            },
            {
                "cid": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "cloud_ml_level_detection": 3,
                "cloud_ml_level_prevention": 3,
                "cpu_priority": 4,
                "created_by": "someone@email.com",
                "created_on": "2023-03-12T14:54:43.659773852Z",
                "endpoint_notification": true,
                "filecount": {},
                "hosts": [
                    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                ],
                "id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "initiated_from": "some_admin_name",
                "last_updated": "2023-04-05T16:56:14.972317443Z",
                "max_duration": 2,
                "max_file_size": 60,
                "metadata": [
                    {
                        "completed_on": "2023-03-12T14:57:37.338506965Z",
                        "filecount": {
                            "malicious": 0,
                            "quarantined": 0,
                            "scanned": 0,
                            "skipped": 0,
                            "traversed": 518485
                        },
                        "host_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                        "host_scan_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                        "last_updated": "2023-03-12T14:57:37.338585331Z",
                        "scan_host_metadata_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                        "started_on": "2023-02-27T09:51:33.91608286Z",
                        "status": "completed"
                    }
                ],
                "pause_duration": 2,
                "policy_setting": [
                    26439818674573,
                    26439818674574,
                    26439818674575,
                    26405458936832,
                    26456998543653,
                    26456998543656,
                    26456998543654,
                    26456998543950,
                    26456998543963
                ],
                "preemption_priority": 1,
                "profile_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "quarantine": true,
                "scan_completed_on": "2023-03-12T14:57:37.338506965Z",
                "scan_inclusions": [
                    "*"
                ],
                "scan_started_on": "2023-03-12T14:54:45.210172175Z",
                "sensor_ml_level_detection": 3,
                "sensor_ml_level_prevention": 3,
                "status": "failed"
            }
        ]
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon ODS Scans

>|ID|Status|Severity|File Count|Description|Hosts/Host groups|End time|Start time|Run by|
>|---|---|---|---|---|---|---|---|---|
>| a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | failed |  | scanned: 0<br/>malicious: 0<br/>quarantined: 0<br/>skipped: 0<br/>traversed: 518464 | desc3456346 | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |  | 2023-02-27T09:51:33.91608286Z | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |
>| a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | failed |  | scanned: 0<br/>malicious: 0<br/>quarantined: 0<br/>skipped: 0<br/>traversed: 518511 |  | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2023-03-13T14:50:26.259846586Z | 2023-02-27T09:51:33.91608286Z | <someone@email.com> |

### cs-falcon-ods-query-scheduled-scan

***
Retrieve ODS scheduled scan details.

#### Base Command

`cs-falcon-ods-query-scheduled-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Valid CS-Falcon-FQL filter to query with. | Optional | 
| ids | Comma-separated list of scan IDs to retrieve details about. If set. will override all other arguments. | Optional | 
| initiated_from | Comma-separated list of scan initiation sources to filter by. | Optional | 
| status | Comma-separated list of scan statuses to filter by. | Optional | 
| created_on | UTC-format time of scan creation to filter by. | Optional | 
| created_by | UTC-format time of scan creator to filter by. | Optional | 
| start_timestamp | UTC-format time of scan start to filter by. | Optional | 
| deleted | Deleted scans only. | Optional | 
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Maximum number of resources to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.ODSScheduledScan.id | String | Unique identifier for the scan. | 
| CrowdStrike.ODSScheduledScan.cid | String | Identifier for the customer or organization that owns the scan. | 
| CrowdStrike.ODSScheduledScan.description | String | The ID of the description of the scan. | 
| CrowdStrike.ODSScheduledScan.file_paths | String | The file or folder paths scanned. | 
| CrowdStrike.ODSScheduledScan.scan_exclusions | String | The file or folder exclusions from the scan. | 
| CrowdStrike.ODSScheduledScan.initiated_from | String | The source of the scan initiation. | 
| CrowdStrike.ODSScheduledScan.cpu_priority | Number | The CPU priority for the scan \(1-5\). | 
| CrowdStrike.ODSScheduledScan.preemption_priority | Number | The preemption priority for the scan. | 
| CrowdStrike.ODSScheduledScan.status | String | The status of the scan, whether it's "scheduled", "running", "completed", etc. | 
| CrowdStrike.ODSScheduledScan.host_groups | String | The host groups targeted by the scan. | 
| CrowdStrike.ODSScheduledScan.endpoint_notification | Boolean | Whether notifications of the scan were sent to endpoints. | 
| CrowdStrike.ODSScheduledScan.pause_duration | Number | The pause duration of scan in hours. | 
| CrowdStrike.ODSScheduledScan.max_duration | Number | The max duration of scan in hours. | 
| CrowdStrike.ODSScheduledScan.max_file_size | Number | The maximum file size that the scan can handle in MB. | 
| CrowdStrike.ODSScheduledScan.sensor_ml_level_detection | Number | The machine learning detection level for the sensor. | 
| CrowdStrike.ODSScheduledScan.cloud_ml_level_detection | Number | The machine learning detection level for the cloud. | 
| CrowdStrike.ODSScheduledScan.schedule.start_timestamp | Date | The timestamp when the first scan was created. | 
| CrowdStrike.ODSScheduledScan.schedule.interval | Number | The interval between scans. | 
| CrowdStrike.ODSScheduledScan.created_on | Date | The timestamp when the scan was created. | 
| CrowdStrike.ODSScheduledScan.created_by | String | The user who created the scan. | 
| CrowdStrike.ODSScheduledScan.last_updated | Date | The timestamp when the scan was last updated. | 
| CrowdStrike.ODSScheduledScan.deleted | Boolean | Whether the scan has been deleted. | 
| CrowdStrike.ODSScheduledScan.quarantine | Boolean | Whether the scan was set to quarantine. | 
| CrowdStrike.ODSScheduledScan.metadata.host_id | String | Scan host IDs. | 
| CrowdStrike.ODSScheduledScan.metadata.last_updated | Date | The date and time when the detection event was last updated. | 
| CrowdStrike.ODSScheduledScan.sensor_ml_level_prevention | Number | The cloud machine learning prevention level for the sensor. | 
| CrowdStrike.ODSScheduledScan.cloud_ml_level_prevention | Number | The cloud machine learning prevention level for the cloud. | 

#### Command example

```!cs-falcon-ods-query-scheduled-scan ids=123456789```

#### Context Example

```json
{
    "CrowdStrike": {
        "ODSScheduledScan": {
            "cid": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "cloud_ml_level_detection": 2,
            "cloud_ml_level_prevention": 2,
            "cpu_priority": 3,
            "created_by": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "created_on": "2023-05-08T09:04:20.8414225Z",
            "deleted": false,
            "endpoint_notification": true,
            "host_groups": [
                "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
            ],
            "id": "123456789",
            "initiated_from": "cloud_scheduled",
            "last_updated": "2023-05-08T09:22:48.408487143Z",
            "max_duration": 2,
            "max_file_size": 60,
            "metadata": [
                {
                    "host_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                    "last_updated": "2023-05-08T09:22:48.408487143Z"
                }
            ],
            "pause_duration": 3,
            "policy_setting": [
                26439818674573,
                26439818674574,
                26439818675074,
                26405458936702,
                26405458936703,
                26405458936707,
                26439818675124,
                26439818675125,
                26439818675157,
                26439818675158,
                26439818675182,
                26439818675183,
                26439818675190,
                26439818675191,
                26439818675196,
                26439818675197,
                26439818675204,
                26439818675205,
                26405458936760,
                26405458936761,
                26405458936793,
                26405458936794,
                26405458936818,
                26405458936819,
                26405458936825,
                26405458936826,
                26405458936832,
                26405458936833,
                26405458936840,
                26405458936841,
                26456998543793,
                26456998544045,
                26456998543652,
                26456998543653,
                26456998543656,
                26456998543654,
                26456998543950,
                26456998543963
            ],
            "preemption_priority": 15,
            "quarantine": true,
            "scan_inclusions": [
                "*"
            ],
            "schedule": {
                "interval": 14,
                "start_timestamp": "2023-05-20T06:49"
            },
            "sensor_ml_level_detection": 2,
            "sensor_ml_level_prevention": 2,
            "status": "scheduled"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon ODS Scheduled Scans

>|ID|Hosts targeted|Description|Host groups|Start time|Created by|
>|---|---|---|---|---|---|
>|  123456789 | 1 |  | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | 2023-05-20T06:49 | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |

### cs-falcon-ods-query-scan-host

***
Retrieve ODS scan host details.

#### Base Command

`cs-falcon-ods-query-scan-host`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Valid CS-Falcon-FQL filter to query with. | Optional | 
| host_ids | Comma-separated list of host IDs to filter by. | Optional | 
| scan_ids | Comma-separated list of scan IDs to filter by. | Optional | 
| status | Comma-separated list of scan statuses to filter by. | Optional | 
| started_on | UTC-format time of scan start to filter by. | Optional | 
| completed_on | UTC-format time of scan completion to filter by. | Optional | 
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Maximum number of resources to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.ODSScanHost.id | String | A unique identifier for the scan event. | 
| CrowdStrike.ODSScanHost.cid | String | A unique identifier for the client that triggered the scan. | 
| CrowdStrike.ODSScanHost.scan_id | String | A unique identifier for the scan. | 
| CrowdStrike.ODSScanHost.profile_id | String | A unique identifier for the scan profile used in the scan. | 
| CrowdStrike.ODSScanHost.host_id | String | A unique identifier for the host that was scanned | 
| CrowdStrike.ODSScanHost.host_scan_id | String | A unique identifier for the scan that was performed on the host. | 
| CrowdStrike.ODSScanHost.filecount.scanned | Number | The number of files that were scanned during the scan. | 
| CrowdStrike.ODSScanHost.filecount.malicious | Number | The number of files that were detected as malicious during the scan. | 
| CrowdStrike.ODSScanHost.filecount.quarantined | Number | The number of files that were quarantined during the scan. | 
| CrowdStrike.ODSScanHost.filecount.skipped | Number | The number of files that were skipped during the scan. | 
| CrowdStrike.ODSScanHost.status | String | The status of the scan \(e.g., "completed", "pending", "cancelled", "running", or "failed"\) | 
| CrowdStrike.ODSScanHost.severity | Number | A severity score assigned to the scan, ranging from 0 to 100 | 
| CrowdStrike.ODSScanHost.started_on | Date | The date and time when the scan was started. | 
| CrowdStrike.ODSScanHost.completed_on | Date | The date and time when the scan was completed. | 
| CrowdStrike.ODSScanHost.last_updated | Date | The date and time when the scan event was last updated. | 

#### Command example

```!cs-falcon-ods-query-scan-host filter="scan_id:[\"123456789\",\"987654321\"]"```

#### Context Example

```json
{
    "CrowdStrike": {
        "ODSScanHost": [
            {
                "cid": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "filecount": {},
                "host_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "id": "123456789",
                "last_updated": "2022-11-27T17:15:50.056840267Z",
                "profile_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "scan_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "status": "pending"
            },
            {
                "cid": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "completed_on": "2023-05-07T08:28:56.856506979Z",
                "filecount": {
                    "malicious": 0,
                    "quarantined": 0,
                    "scanned": 0,
                    "skipped": 0,
                    "traversed": 524581
                },
                "host_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "host_scan_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "id": "987654321",
                "last_updated": "2023-05-07T08:28:56.856575358Z",
                "profile_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "scan_id": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "started_on": "2023-05-07T08:25:48.336234188Z",
                "status": "completed"
            }
        ]
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon ODS Scan Hosts

>|ID|Scan ID|Host ID|Filecount|Status|Severity|Started on|
>|---|---|---|---|---|---|---|
>| 123456789 | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 |  | pending |  |  |
>| 987654321 | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 | scanned: 0<br/>malicious: 0<br/>quarantined: 0<br/>skipped: 0<br/>traversed: 524581 | completed |  | 2023-05-07T08:25:48.336234188Z |

### cs-falcon-ods-query-malicious-files

***
Retrieve ODS malicious file details.

#### Base Command

`cs-falcon-ods-query-malicious-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Valid CS-Falcon-FQL filter to query with. | Optional | 
| file_ids | Comma-separated list of malicious file IDs to retrieve details about. If set, will override all other arguments. | Optional | 
| host_ids | Comma-separated list of host IDs to filter by. | Optional | 
| scan_ids | Comma-separated list of scan IDs to filter by. | Optional | 
| file_paths | Comma-separated list of file paths to filter by. | Optional | 
| file_names | Comma-separated list of file names to filter by. | Optional | 
| hash | Comma-separated list of hashes to filter by. | Optional | 
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Maximum number of resources to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.ODSMaliciousFile.id | String | A unique identifier of the detection event. | 
| CrowdStrike.ODSMaliciousFile.cid | String | A unique identifier for the client that triggered the detection event. | 
| CrowdStrike.ODSMaliciousFile.scan_id | String | A unique identifier for the scan that triggered the detection event. | 
| CrowdStrike.ODSMaliciousFile.host_id | String | A unique identifier for the scan that detected the file on the host. | 
| CrowdStrike.ODSMaliciousFile.host_scan_id | String | A unique identifier for the scan that detected the file on the host. | 
| CrowdStrike.ODSMaliciousFile.filepath | String | The full path to the malicious file on the host system. | 
| CrowdStrike.ODSMaliciousFile.filename | String | The name of the malicious file. | 
| CrowdStrike.ODSMaliciousFile.hash | String | A SHA-256 hash of the malicious file, which can be used to identify it. | 
| CrowdStrike.ODSMaliciousFile.pattern_id | Number | The identifier of the pattern used to detect the malicious file. | 
| CrowdStrike.ODSMaliciousFile.severity | Number | A severity score assigned to the detection event, ranging from 0 to 100. | 
| CrowdStrike.ODSMaliciousFile.quarantined | Boolean | A Boolean value indicating whether the file has been quarantined. | 
| CrowdStrike.ODSMaliciousFile.last_updated | Date | The date and time when the detection event was last updated. | 

#### Command example

```!cs-falcon-ods-query-malicious-files```

#### Human Readable Output

>No malicious files match the arguments/filter.

### cs-falcon-ods-create-scan

***
Create an ODS scan and wait for results.

#### Base Command

`cs-falcon-ods-create-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hosts | List of hosts to be scanned. "hosts" OR "host_groups" must be set. | Optional | 
| host_groups | List of host groups to be scanned. "hosts" OR "host_groups" must be set. | Optional | 
| file_paths | List of file paths to be scanned. "file_paths" OR "scan_inclusions" must be set. | Optional | 
| scan_inclusions | List of included files or locations for this scan. "file_paths" OR "scan_inclusions" must be set. | Optional | 
| scan_exclusions | List of excluded files or locations for this scan. | Optional | 
| initiated_from | Scan origin. | Optional | 
| cpu_priority | Set the scan CPU priority. Possible values are: Highest, High, Medium, Low, Lowest. Default is Low. | Optional | 
| description | Scan description. | Optional | 
| quarantine | Flag indicating if identified threats should be quarantined. | Optional | 
| pause_duration | Amount of time (in hours) for scan pauses. Default is 2. | Optional | 
| sensor_ml_level_detection | Sensor ML detection level. | Optional | 
| sensor_ml_level_prevention | Sensor ML prevention level. | Optional | 
| cloud_ml_level_detection | Cloud ML detection level for the scan. | Optional | 
| cloud_ml_level_prevention | Cloud ML prevention level for the scan. | Optional | 
| max_duration | Maximum time (in hours) the scan is allowed to execute. Default is 2. | Optional | 
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional | 
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.ODSScan.id | String | A unique identifier for the scan event. | 
| CrowdStrike.ODSScan.cid | String | A unique identifier for the client that triggered the scan. | 
| CrowdStrike.ODSScan.profile_id | String | A unique identifier for the scan profile used in the scan. | 
| CrowdStrike.ODSScan.description | String | The ID of the description of the scan. | 
| CrowdStrike.ODSScan.scan_inclusions | String | The files or folders included in the scan. | 
| CrowdStrike.ODSScan.initiated_from | String | The source of the scan initiation. | 
| CrowdStrike.ODSScan.quarantine | Boolean | Whether the scan was set to quarantine. | 
| CrowdStrike.ODSScan.cpu_priority | Number | The CPU priority for the scan \(1-5\). | 
| CrowdStrike.ODSScan.preemption_priority | Number | The preemption priority for the scan. | 
| CrowdStrike.ODSScan.metadata.host_id | String | A unique identifier for the host that was scanned. | 
| CrowdStrike.ODSScan.metadata.host_scan_id | String | A unique identifier for the scan that was performed on the host. | 
| CrowdStrike.ODSScan.metadata.scan_host_metadata_id | String | A unique identifier for the metadata associated with the host scan. | 
| CrowdStrike.ODSScan.metadata.filecount.scanned | Number | The number of files that were scanned. | 
| CrowdStrike.ODSScan.metadata.filecount.malicious | Number | The number of files that were identified as malicious. | 
| CrowdStrike.ODSScan.metadata.filecount.quarantined | Number | The number of files that were quarantined. | 
| CrowdStrike.ODSScan.metadata.filecount.skipped | Number | The number of files that were skipped during the scan. | 
| CrowdStrike.ODSScan.metadata.filecount.traversed | Number | The number of files that were traversed during the scan. | 
| CrowdStrike.ODSScan.metadata.status | String | The status of the scan on this host \(e.g., "pending", "running", "completed", or "failed"\). | 
| CrowdStrike.ODSScan.metadata.started_on | Date | The date and time that the scan started. | 
| CrowdStrike.ODSScan.metadata.completed_on | Date | The date and time that the scan completed. | 
| CrowdStrike.ODSScan.metadata.last_updated | Date | The date and time that the metadata was last updated. | 
| CrowdStrike.ODSScan.status | String | The status of the scan \(e.g., "pending", "running", "completed", or "failed"\). | 
| CrowdStrike.ODSScan.hosts | String | A list of the host IDs that were scanned. | 
| CrowdStrike.ODSScan.endpoint_notification | Boolean | A boolean value indicating whether endpoint notifications are enabled. | 
| CrowdStrike.ODSScan.pause_duration | Number | The number of hours to pause between scanning each file. | 
| CrowdStrike.ODSScan.max_duration | Number | The maximum amount of time to allow for the scan job in hours. | 
| CrowdStrike.ODSScan.max_file_size | Number | The maximum file size \(in MB\) to scan. | 
| CrowdStrike.ODSScan.sensor_ml_level_detection | Number | The level of detection sensitivity for the local sensor machine learning model. | 
| CrowdStrike.ODSScan.sensor_ml_level_prevention | Number | The level of prevention sensitivity for the local sensor machine learning model. | 
| CrowdStrike.ODSScan.cloud_ml_level_detection | Number | The level of detection sensitivity for the cloud machine learning model. | 
| CrowdStrike.ODSScan.cloud_ml_level_prevention | Number | The level of prevention sensitivity for the cloud machine learning model. | 
| CrowdStrike.ODSScan.policy_setting | Number | A list of policy setting IDs for the scan job \(these correspond to specific policy settings in the Falcon console\). | 
| CrowdStrike.ODSScan.scan_started_on | Date | The timestamp when the scan was started. | 
| CrowdStrike.ODSScan.scan_completed_on | Date | The timestamp when the scan was completed. | 
| CrowdStrike.ODSScan.created_on | Date | The timestamp when the scan was created. | 
| CrowdStrike.ODSScan.created_by | String | The ID of the user who created the scan job. | 
| CrowdStrike.ODSScan.last_updated | Date | The timestamp when the scan job was last updated. | 

#### Command example

```!cs-falcon-ods-create-scan host_groups=7471ba0636b34cbb8c65fae7979a6a9b scan_inclusions=* cpu_priority=Highest max_duration=1 pause_duration=1```

#### Context Example

```json
{
    "CrowdStrike": {
        "ODSScan": {
            "cid": "20879a8064904ecfbb62c118a6a19411",
            "cloud_ml_level_detection": 2,
            "cloud_ml_level_prevention": 2,
            "cpu_priority": 5,
            "created_by": "f7acf1bd5d3d4b40afe77546cbbaefde",
            "created_on": "2023-06-11T13:23:05.139153881Z",
            "filecount": {
                "malicious": 0,
                "quarantined": 0,
                "scanned": 0,
                "skipped": 0,
                "traversed": 0
            },
            "host_groups": [
                "7471ba0636b34cbb8c65fae7979a6a9b"
            ],
            "id": "9ba8489e9f604b61bf9b4a2c5f95ede7",
            "initiated_from": "cloud_adhoc",
            "last_updated": "2023-06-11T13:23:05.139153881Z",
            "max_duration": 1,
            "max_file_size": 60,
            "metadata": [
                {
                    "filecount": {},
                    "host_id": "046761c46ec84f40b27b6f79ce7cd32c",
                    "last_updated": "2023-06-11T13:23:05.139153881Z",
                    "scan_host_metadata_id": "31052e821a5a4189a1a9a2814cc88e4e",
                    "status": "complete"
                }
            ],
            "pause_duration": 1,
            "policy_setting": [
                26439818674573,
                26439818674574,
                26439818675074,
                26405458936702,
                26405458936703,
                26456998543654,
                26456998543950,
                26456998543963
            ],
            "preemption_priority": 1,
            "profile_id": "335198a96e1a4a6b880d62b2e7ccbb91",
            "quarantine": true,
            "scan_inclusions": [
                "*"
            ],
            "sensor_ml_level_detection": 2,
            "sensor_ml_level_prevention": 2,
            "status": "complete"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon ODS Scans
>
>|ID|Status|Severity|File Count|Description|Hosts/Host groups|End time|Start time|Run by|
>|---|---|---|---|---|---|---|---|---|
>| 9ba8489e9f604b61bf9b4a2c5f95ede7 | complete |  |  |  | 7471ba0636b34cbb8c65fae7979a6a9b |  |  | f7acf1bd5d3d4b40afe77546cbbaefde |


### cs-falcon-ods-create-scheduled-scan

***
Create an ODS scheduled scan.

#### Base Command

`cs-falcon-ods-create-scheduled-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_groups | List of host groups to be scanned. | Required | 
| file_paths | List of file paths to be scanned. "file_paths" OR "scan_inclusions" must be set. | Optional | 
| scan_inclusions | List of included files or locations for this scan. "file_paths" OR "scan_inclusions" must be set. | Optional | 
| scan_exclusions | List of excluded files or locations for this scan. | Optional | 
| initiated_from | Scan origin. | Optional | 
| cpu_priority | Set the scan CPU priority. Possible values are: Highest, High, Medium, Low, Lowest. Default is Low. | Optional | 
| description | Scan description. | Optional | 
| quarantine | Flag indicating if identified threats should be quarantined. | Optional | 
| pause_duration | Amount of time (in hours) for scan pauses. Default is 2. | Optional | 
| sensor_ml_level_detection | Sensor ML detection level. | Optional | 
| sensor_ml_level_prevention | Sensor ML prevention level. | Optional | 
| cloud_ml_level_detection | Cloud ML detection level for the scan. | Optional | 
| cloud_ml_level_prevention | Cloud ML prevention level for the scan. | Optional | 
| max_duration | Maximum time (in hours) the scan is allowed to execute. Default is 2. | Optional | 
| schedule_start_timestamp | When to start the first scan. Supports english expressions such as "tommorow" or "in an hour". | Required | 
| schedule_interval | Set the schedule interval. Possible values are: Never, Daily, Weekly, Every other week, Every four weeks, Monthly. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.ODSScheduledScan.id | String | Unique identifier for the scan. | 
| CrowdStrike.ODSScheduledScan.cid | String | Identifier for the customer or organization that owns the scan. | 
| CrowdStrike.ODSScheduledScan.description | String | The ID of the description of the scan. | 
| CrowdStrike.ODSScheduledScan.file_paths | String | The file or folder paths scanned. | 
| CrowdStrike.ODSScheduledScan.scan_exclusions | String | The file or folder exclusions from the scan. | 
| CrowdStrike.ODSScheduledScan.initiated_from | String | The source of the scan initiation. | 
| CrowdStrike.ODSScheduledScan.cpu_priority | Number | The CPU priority for the scan \(1-5\). | 
| CrowdStrike.ODSScheduledScan.preemption_priority | Number | The preemption priority for the scan. | 
| CrowdStrike.ODSScheduledScan.status | String | The status of the scan, whether it's "scheduled", "running", "completed", etc. | 
| CrowdStrike.ODSScheduledScan.host_groups | String | The host groups targeted by the scan. | 
| CrowdStrike.ODSScheduledScan.endpoint_notification | Boolean | Whether notifications of the scan were sent to endpoints. | 
| CrowdStrike.ODSScheduledScan.pause_duration | Number | The pause duration of scan in hours. | 
| CrowdStrike.ODSScheduledScan.max_duration | Number | The max duration of scan in hours. | 
| CrowdStrike.ODSScheduledScan.max_file_size | Number | The maximum file size that the scan can handle in MB. | 
| CrowdStrike.ODSScheduledScan.sensor_ml_level_detection | Number | The machine learning detection level for the sensor. | 
| CrowdStrike.ODSScheduledScan.cloud_ml_level_detection | Number | The machine learning detection level for the cloud. | 
| CrowdStrike.ODSScheduledScan.schedule.start_timestamp | Date | The timestamp when the first scan was created. | 
| CrowdStrike.ODSScheduledScan.schedule.interval | Number | The interval between scans. | 
| CrowdStrike.ODSScheduledScan.created_on | Date | The timestamp when the scan was created. | 
| CrowdStrike.ODSScheduledScan.created_by | String | The user who created the scan. | 
| CrowdStrike.ODSScheduledScan.last_updated | Date | The timestamp when the scan was last updated. | 
| CrowdStrike.ODSScheduledScan.deleted | Boolean | Whether the scan has been deleted. | 
| CrowdStrike.ODSScheduledScan.quarantine | Boolean | Whether the scan was set to quarantine. | 
| CrowdStrike.ODSScheduledScan.metadata.host_id | String | Scan host IDs. | 
| CrowdStrike.ODSScheduledScan.metadata.last_updated | Date | The date and time when the detection event was last updated. | 
| CrowdStrike.ODSScheduledScan.sensor_ml_level_prevention | Number | The machine learning prevention level for the sensor. | 
| CrowdStrike.ODSScheduledScan.cloud_ml_level_prevention | Number | The machine learning prevention level for the cloud. | 

#### Command example

```!cs-falcon-ods-create-scheduled-scan host_groups=7471ba0636b34cbb8c65fae7979a6a9b schedule_interval=daily schedule_start_timestamp=tomorrow cpu_priority=Highest scan_inclusions=*```

#### Context Example

```json
{
    "CrowdStrike": {
        "ODSScan": {
            "cid": "20879a8064904ecfbb62c118a6a19411",
            "cloud_ml_level_detection": 2,
            "cloud_ml_level_prevention": 2,
            "cpu_priority": 5,
            "created_by": "f7acf1bd5d3d4b40afe77546cbbaefde",
            "created_on": "2023-06-11T13:23:10.564070276Z",
            "deleted": false,
            "host_groups": [
                "7471ba0636b34cbb8c65fae7979a6a9b"
            ],
            "id": "7d08d9a3088f49b3aa20efafc355aef0",
            "initiated_from": "cloud_scheduled",
            "last_updated": "2023-06-11T13:23:10.564070276Z",
            "max_duration": 2,
            "max_file_size": 60,
            "metadata": [
                {
                    "host_id": "046761c46ec84f40b27b6f79ce7cd32c",
                    "last_updated": "2023-06-11T13:23:10.564070276Z"
                }
            ],
            "pause_duration": 2,
            "policy_setting": [
                26439818674573,
                26439818674574,
                26439818675074,
                26405458936702,
                26405458936703,
                26405458936707,
                26439818675124,
                26439818675125,
                26439818675157,
                26439818675158,
                26439818675182,
                26439818675183,
                26439818675190,
                26439818675191,
                26439818675196,
                26439818675197,
                26439818675204,
                26439818675205,
                26405458936760,
                26405458936761,
                26405458936793,
                26405458936794,
                26405458936818,
                26405458936819,
                26405458936825,
                26405458936826,
                26405458936832,
                26405458936833,
                26405458936840,
                26405458936841,
                26456998543793,
                26456998544045,
                26456998543652,
                26456998543653,
                26456998543656,
                26456998543654,
                26456998543950,
                26456998543963
            ],
            "preemption_priority": 15,
            "quarantine": true,
            "scan_inclusions": [
                "*"
            ],
            "schedule": {
                "interval": 1,
                "start_timestamp": "2023-06-12T13:23"
            },
            "sensor_ml_level_detection": 2,
            "sensor_ml_level_prevention": 2,
            "status": "scheduled"
        }
    }
}
```

#### Human Readable Output

>### Scheduled Scan Created
>
>|Scan ID|
>|---|
>| 7d08d9a3088f49b3aa20efafc355aef0 |


### cs-falcon-ods-delete-scheduled-scan

***
Delete ODS scheduled scans.

#### Base Command

`cs-falcon-ods-delete-scheduled-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Comma-separated list of scheduled scan IDs to delete. | Optional | 
| filter | Valid CS-Falcon-FQL filter to delete scans by. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!cs-falcon-ods-delete-scheduled-scan  ids=9acf0c069d3d4a5b82badb170966e77c```

#### Human Readable Output

>### Deleted Scans:

>|Scan ID|
>|---|
>| 9acf0c069d3d4a5b82badb170966e77c |

### cs-falcon-list-identity-entities

***
List identity entities.

#### Base Command

`cs-falcon-list-identity-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | API type. Possible values are: USER, ENDPOINT. | Required | 
| sort_key | The key to sort by. Possible values are: RISK_SCORE, PRIMARY_DISPLAY_NAME, SECONDARY_DISPLAY_NAME, MOST_RECENT_ACTIVITY, ENTITY_ID. | Optional |
| sort_order | The sort order. Possible values are: DESCENDING, ASCENDING. Default is ASCENDING. | Optional | 
| entity_id | Comma separated list of entity IDs to look for. | Optional | 
| primary_display_name | Primary display name to filter by. | Optional | 
| secondary_display_name | Secondary display name to filter by. | Optional | 
| max_risk_score_severity | The maximum risk score severity to filter by. Possible values are: NORMAL, MEDIUM, HIGH. | Optional | 
| min_risk_score_severity | The minimum risk score severity to filter by. Possible values are: NORMAL, MEDIUM, HIGH. | Optional | 
| enabled | Whether to get only enabled or disabled identity entities. Possible values are: true, false. | Optional | 
| email | Filter by email. | Optional | 
| next_token | The hash for the next page. | Optional | 
| page_size |  The page size. The limit is 1000. Default is 50. | Optional | 
| page | The page number. Default is 1.  | Optional | 
| limit | The maximum number of identity entities to list. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IDPEntity.IsHuman | Boolean | Whether the identity entity is human made. | 
| CrowdStrike.IDPEntity.IsProgrammatic | Boolean | Whether the identity entity is programmatic made. | 
| CrowdStrike.IDPEntity.IsAdmin | String | Whether the identity entity is admin made. | 
| CrowdStrike.IDPEntity.PrimaryDisplayName | String | The identity entity primary display name. | 
| CrowdStrike.IDPEntity.RiskFactors.Type | Unknown | The identity entity risk factor type. | 
| CrowdStrike.IDPEntity.RiskFactors.Severity | Unknown | The identity entity risk factor severity. | 
| CrowdStrike.IDPEntity.RiskScore | Number | The identity entity risk score. | 
| CrowdStrike.IDPEntity.RiskScoreSeverity | String | The identity entity risk score severity. | 
| CrowdStrike.IDPEntity.SecondaryDisplayName | String | The identity entity secondary display name. | 
| CrowdStrike.IDPEntity.EmailAddresses | String | The identity entity email address. | 