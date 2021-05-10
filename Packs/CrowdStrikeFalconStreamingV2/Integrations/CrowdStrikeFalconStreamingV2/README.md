## Overview
Use CrowdStrike Falcon Streaming v2 integration to connect to CrowdStrike Falcon stream and fetch events as incidents to demisto.


## Define CrowdStrike API client
In order to use the integration, an API client need to be defined, and its ID and secret should be configured in the integration instance.

Follow [this article](https://www.crowdstrike.com/blog/tech-center/get-access-falcon-apis/) in order to get access to CrowdStrike API, and generate client ID and client secret.

The required scope is Event streams.

## Configure CrowdStrike Falcon Streaming v2 on Demisto
1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for CrowdStrike Falcon Streaming v2
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Cloud Base URL (e.g. https://api.crowdstrike.com)__
    * __Client ID__
    * __Client Secret__
    * __Application ID__
    * __Event type to fetch__
    * __Offset to fetch events from__
    * __Stream client read timeout__
    * __Incident type__
    * __Store sample events for mapping__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

#### Important Notes
 - If you're using Falcon's commercial cloud, use the default value of the Cloud base URL.
   If you use another CrowdStrike cloud environment, use one of the following:
     - GovCloud: https://api.laggar.gcw.crowdstrike.com
     - EU cloud: https://api.eu-1.crowdstrike.com
 - Offset to fetch events from should have an integer value, in order to fetch all events set it to 0 (as the default value).
   
   Only events starting from this offset will be fetched
   
   For example, if set to 10: the event with offset 9 will not be fetched, and events with offsets 10 and 11 will be fetched.
   
 - Event type to fetch parameter accepts multiple values, so choose as many as you want to fetch.
   
   In order to fetch all events of all types, you can leave it empty.
   
   You can also add event type that is not listed, by entering it in the parameter value.
    
 - In order to run multiple clients (stream consumers) simultaneously, each integration instance should have unique application ID. The application ID can be of length up to 32 characters.

## Fetched Incidents Data
Event metadata will be fetched as the incident details, which contain the following:
* Type
* Offset
* Creation time
* Used ID 
* Service Name
* Detection Name
* Detection Description
* Severity

## Mapping incoming events
Because this is a push-based streaming integration, it cannot fetch sample events in the mapping wizard.

In order to view sample events, enable events storage by selecting the checkbox of the integration parameter **Store sample events for mapping**. 

The last events (maximum of 20) are fetched every 1 minute. Allow the integration to run for at least 5 minutes before running the command.
After you finish mapping, it is recommended to turn off the **Store sample events for mapping** to reduce performance overhead.

For Cortex XSOAR version 6.0 and above, you will be able to fetch samples in the mapping wizard

For earlier versions, you should run the `crowdstrike-falcon-streaming-get-sample-events` command.

The command output is as follows:
```json
{
    "event": {
        "ComputerName": "FALCON-CROWDSTR",
        "DetectId": "ldt:15dbb9d8f06b45fe9f61eb46e829d986:55929758895",
        "DetectName": "Suspicious Activity",
        "FileName": "choice.exe",
        "FilePath": "\\Device\\HarddiskVolume1\\Windows\\System32",
        "GrandparentCommandLine": "C:\\Windows\\Explorer.EXE",
        "GrandparentImageFileName": "\\Device\\HarddiskVolume1\\Windows\\explorer.exe",
        "MD5String": "463b5477ff96ab86a01ba49bcc02b539",
        "MachineDomain": "FALCON-CROWDSTR",
        "Objective": "Falcon Detection Method",
        "ParentCommandLine": "\"C:\\Windows\\system32\\cmd.exe\" ",
        "ParentImageFileName": "\\Device\\HarddiskVolume1\\Windows\\System32\\cmd.exe",
        "ParentProcessId": 79569204402,
        "PatternDispositionDescription": "Detection, standard detection.",
        "PatternDispositionFlags": {
            "BootupSafeguardEnabled": false,
            "CriticalProcessDisabled": false,
            "Detect": false,
            "FsOperationBlocked": false,
            "InddetMask": false,
            "Indicator": false,
            "KillParent": false,
            "KillProcess": false,
            "KillSubProcess": false,
            "OperationBlocked": false,
            "PolicyDisabled": false,
            "ProcessBlocked": false,
            "QuarantineFile": false,
            "QuarantineMachine": false,
            "RegistryOperationBlocked": false,
            "Rooting": false,
            "SensorOnly": false
        },
        "PatternDispositionValue": 0,
        "ProcessEndTime": 1592479032,
        "ProcessId": 79867150228,
        "ProcessStartTime": 1592479032,
        "Severity": 2,
        "SeverityName": "Low",
        "Tactic": "Falcon Overwatch",
        "Technique": "Malicious Activity",
        "UserName": "admin"
    },
    "metadata": {
        "customerIDString": "20874a8064904ecfbb62c118a6a19411",
        "eventCreationTime": 1592479032000,
        "eventType": "DetectionSummaryEvent",
        "offset": 70628,
        "version": "1.0"
    }
}
```

You can now upload that JSON file to the mapping wizard and continue as usual.
