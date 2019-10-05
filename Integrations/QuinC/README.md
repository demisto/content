## Overview
---

This integration was integrated and tested with version xx of Quinc
## Quinc Playbook
---

## Use Cases
---

## Configure Quinc on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Quinc.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (FQDN or IP address in X.X.X.X format)__
    * __The token is required to connect to Quinc.__
    * __Scheme__
    * __Trust any certificate (insecure)__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. accessdata-get-jobstatus
2. accessdata-legacyagent-get-processlist
3. accessdata-legacyagent-get-memorydump
4. accessdata-read-casefile
### accessdata-get-jobstatus
---
Get status of job
##### Base Command

`accessdata-get-jobstatus`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseID | ID of case | Required | 
| jobID | ID of job | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| State | string | Job state | 
| Result | string | Job result | 


##### Command Example
`accessdata-get-jobstatus caseID=1 jobID=854`

##### Context Example
```
{
    "Accessdata.Job": {
        "State": "Success", 
        "ID": "854", 
        "Result": {
            "Usb": false, 
            "Drivers": false, 
            "Routing": false, 
            "SMBSessions": false, 
            "SMBSessionsDetails": {
                "Code": 0, 
                "File": null
            }, 
            "Certificates": true, 
            "taskStatus": {
                "OperationType": 12, 
                "IsShare": false, 
                "Started": "2019-10-04T22:10:24Z", 
                "SiteServerId": null, 
                "Submitted": "2019-10-04T22:02:21.109807Z", 
                "JobId": "2e667db2-ee5a-4522-aff8-4047769bd211", 
                "Ended": "0001-01-01T00:00:00", 
                "Connection": "X.X.X.X", 
                "ItemGuid": "f7d5833f-79a7-4dbc-8bd9-0f021e20af00", 
                "TaskId": "9645eb6b-5bc5-4342-823b-8aa0e4594c27", 
                "CurrentState": 3
            }, 
            "ResultId": "b21bd6b3-48b5-44ca-a265-9029912a08cd", 
            "DNSCacheDetails": {
                "Code": 0, 
                "File": null
            }, 
            "Status": null, 
            "Users": false, 
            "NICDetails": {
                "Code": 0, 
                "File": null
            }, 
            "ResultFiles": [
                {
                    "Path": "\\\\X.X.X.X\\D$\\Program Files\\AccessData\\QuinC\\app\\demo\\Demo Case\\c00a2abf-1076-412b-8dea-67305fb8015f\\Jobs\\job_854\\9645eb6b-5bc5-4342-823b-8aa0e4594c27\\1\\snapshot.xml", 
                    "Hash": "2356d44b3444e10e57f96838559af940", 
                    "Filename": "snapshot.xml"
                }, 
                {
                    "Path": "\\\\X.X.X.X\\D$\\Program Files\\AccessData\\QuinC\\app\\demo\\Demo Case\\c00a2abf-1076-412b-8dea-67305fb8015f\\Jobs\\job_854\\9645eb6b-5bc5-4342-823b-8aa0e4594c27\\1\\certificates.xml", 
                    "Hash": "cc01e8745696fcb6141fc67bfbb07763", 
                    "Filename": "certificates.xml"
                }
            ], 
            "Timestamp": "2019-10-04T22:20:21Z", 
            "ServicesDetails": {
                "Code": 0, 
                "File": null
            }, 
            "JobId": "2e667db2-ee5a-4522-aff8-4047769bd211", 
            "Volume": false, 
            "Registry": false, 
            "Services": false, 
            "UsbDetails": {
                "Code": 0, 
                "File": null
            }, 
            "RoutingDetails": {
                "Code": 0, 
                "File": null
            }, 
            "ArpDetails": {
                "Code": 0, 
                "File": null
            }, 
            "CertificateDetails": {
                "Code": 0, 
                "File": "\\\\X.X.X.X\\D$\\Program Files\\AccessData\\QuinC\\app\\demo\\Demo Case\\c00a2abf-1076-412b-8dea-67305fb8015f\\Jobs\\job_854\\9645eb6b-5bc5-4342-823b-8aa0e4594c27\\1\\certificates.xml"
            }, 
            "PrefetchDetails": {
                "Code": 0, 
                "File": null
            }, 
            "VolumeDetails": {
                "Code": 0, 
                "File": null
            }, 
            "LiveRegistry": false, 
            "ResultType": 18, 
            "Snapshot": true, 
            "Prefetch": false, 
            "OperationType": 12, 
            "DNSCache": false, 
            "DriversDetails": {
                "Code": 0, 
                "File": null
            }, 
            "TasksDetails": {
                "Code": 0, 
                "File": null
            }, 
            "Arp": false, 
            "Tasks": false, 
            "UserMessage": null, 
            "NIC": false, 
            "RegistryDetails": {
                "Code": 0, 
                "File": null
            }, 
            "TaskId": "9645eb6b-5bc5-4342-823b-8aa0e4594c27", 
            "LiveRegistryDetails": {
                "Code": 0, 
                "File": null
            }, 
            "SnapshotDetails": {
                "Code": 0, 
                "File": "\\\\X.X.X.X\\D$\\Program Files\\AccessData\\QuinC\\app\\demo\\Demo Case\\c00a2abf-1076-412b-8dea-67305fb8015f\\Jobs\\job_854\\9645eb6b-5bc5-4342-823b-8aa0e4594c27\\1\\snapshot.xml"
            }, 
            "Message": null, 
            "UsersDetails": {
                "Code": 0, 
                "File": null
            }
        }
    }
}
```

##### Human Readable Output
Job completed successfully

### accessdata-legacyagent-get-processlist
---
Return list of process from legacy agent
##### Base Command

`accessdata-legacyagent-get-processlist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseid | ID of case | Required | 
| target_ip | IP address of agent | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Accessdata.Job(val.Type=="Volatile").ID | string | ID of job | 


##### Command Example
`accessdata-legacyagent-get-processlist caseid=1 target_ip=X.X.X.X`

##### Context Example
```
{
    "Accessdata.Job": {
        "Type": "Volatile", 
        "ID": 857
    }
}
```

##### Human Readable Output
JobID: 857

### accessdata-legacyagent-get-memorydump
---
Creates legacy agent memory dump
##### Base Command

`accessdata-legacyagent-get-memorydump`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseid | ID of case | Required | 
| target_ip | IP address of agent | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Accessdata.Job.ID | string | ID of job | 


##### Command Example
`accessdata-legacyagent-get-memorydump caseid=1 target_ip=X.X.X.X`

##### Context Example
```
{
    "Accessdata.Job": {
        "Type": "LegacyMemoryDump", 
        "ID": 858
    }
}
```

##### Human Readable Output
JobID: 858

### accessdata-read-casefile
---
Reads file from case folder and puts its contents to current context
##### Base Command

`accessdata-read-casefile`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filepath | Path to case file | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Accessdata.File.Contents | string | Contents of the file | 


##### Command Example
`accessdata-read-casefile filepath="\\X.X.X.X\D$\Program Files\AccessData\QuinC\app\demo\Demo Case\c00a2abf-1076-412b-8dea-67305fb8015f\Jobs\job_852\84040804-2e76-4912-bfe6-891f453fb335\1\snapshot.xml"`

##### Context Example
```
{
    "Accessdata.File.Contents": "<?xml version=\"1.0\"?>\r\n<root>\r\n<Process resultitemtype=\"15\"><Name>agentcore.exe</Name><Path>C:\\Program Files\\AccessData\\Agent\\agentcore.exe</Path><StartTime>2019-09-24 14:21:05</StartTime><WorkingDir>C:\\WINDOWS\\system32\\</WorkingDir><CommandLine>\"C:\\Program Files\\AccessData\\Agent\\agentcore.exe\"</CommandLine><LinkTime>0</LinkTime><Subsystem>0</Subsystem><Imagebase>0</Imagebase><Characteristics>0</Characteristics><Checksum>0</Checksum><KernelTime>0</KernelTime><UserTime>0</UserTime><Privileges>0</Privileges><PID>2868</PID><ParentPID>604</ParentPID><User>SYSTEM</User><Group/><MD5>28CE7780A0BAAC124972F5E983010B99</MD5><SHA1>89D6FBD96D0BBF4AF4B0C3450905A2B6E4567E23</SHA1><FuzzySize>49152</FuzzySize><Fuzzy>HRk2vY5DHiMQPfjfX1mRrNPEIYZ9j/QTMK2/LFkCDWTjUsq9K1FI</Fuzzy><Fuzzy2X>xshI/oUh9K2/BkCrsq9Kk</Fuzzy2X><KFFStatus>0</KFFStatus><FromAgent/><EffectiveUser/><EffectiveGroup/><Size>2788720</Size><EProcBlockLoc>0</EProcBlockLoc><WindowTitle/><Loaded_DLL_List><DLL><Name>ntdll.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\ntdll.dll</Path></DLL><DLL><Name>KERNEL32.DLL</Name><Path>C:\\WINDOWS\\System32\\KERNEL32.DLL</Path></DLL><DLL><Name>KERNELBASE.dll</Name><Path>C:\\WINDOWS\\System32\\KERNELBASE.dll</Path></DLL><DLL><Name>ADVAPI32.dll</Name><Path>C:\\WINDOWS\\System32\\ADVAPI32.dll</Path></DLL><DLL><Name>msvcrt.dll</Name><Path>C:\\WINDOWS\\System32\\msvcrt.dll</Path></DLL><DLL><Name>sechost.dll</Name><Path>C:\\WINDOWS\\System32\\sechost.dll</Path></DLL><DLL><Name>RPCRT4.dll</Name><Path>C:\\WINDOWS\\System32\\RPCRT4.dll</Path></DLL><DLL><Name>WS2_32.dll</Name><Path>C:\\WINDOWS\\System32\\WS2_32.dll</Path></DLL><DLL><Name>USER32.dll</Name><Path>C:\\WINDOWS\\System32\\USER32.dll</Path></DLL><DLL><Name>win32u.dll</Name><Path>C:\\WINDOWS\\System32\\win32u.dll</Path></DLL><DLL><Name>GDI32.dll</Name><Path>C:\\WINDOWS\\System32\\GDI32.dll</Path></DLL><DLL><Name>gdi32full.dll</Name><Path>C:\\WINDOWS\\System32\\gdi32full.dll</Path></DLL><DLL><Name>msvcp_win.dll</Name><Path>C:\\WINDOWS\\System32\\msvcp_win.dll</Path></DLL><DLL><Name>ucrtbase.dll</Name><Path>C:\\WINDOWS\\System32\\ucrtbase.dll</Path></DLL><DLL><Name>SHELL32.dll</Name><Path>C:\\WINDOWS\\System32\\SHELL32.dll</Path></DLL><DLL><Name>cfgmgr32.dll</Name><Path>C:\\WINDOWS\\System32\\cfgmgr32.dll</Path></DLL><DLL><Name>shcore.dll</Name><Path>C:\\WINDOWS\\System32\\shcore.dll</Path></DLL><DLL><Name>combase.dll</Name><Path>C:\\WINDOWS\\System32\\combase.dll> . . . </Version><MD5>46EDB80093592036AE006965C8CAF9BE</MD5><SHA1>DACDDC9FDF31F97CC110C163F2BB26158FD6D240</SHA1><FuzzySize>24576</FuzzySize><Fuzzy>BJDdtFnfVIUyIAA95gROBX2i6Nu1UHVSj3jd79EQVcSFWpFNOPRQvRcnYwj0+N</Fuzzy><Fuzzy2X>jtdIUyZDROBXMHV5OoNOP4mnXj</Fuzzy2X><CreateTime>2019-09-21 03:35:03</CreateTime><KFFStatus>0</KFFStatus><PID>0</PID><baseAddress>0</baseAddress><ImageSize>0</ImageSize><ProcessName/><FromAgent/></DLL>\r\n</root>\r\n"
}
```

##### Human Readable Output
<?xml version="1.0"?>
<root>
<Process resultitemtype="15"><Name>agentcore.exe</Name><Path>C:\Program Files\AccessData\Agent\agentcore.exe</Path><StartTime>2019-09-24 14:21:05</StartTime><WorkingDir>C:\WINDOWS\system32\</WorkingDir><CommandLine>"C:\Program Files\AccessData\Agent\agentcore.exe"</CommandLine><LinkTime>0</LinkTime><Subsystem>0</Subsystem><Imagebase>0</Imagebase><Characteristics>0</Characteristics><Checksum>0</Checksum><KernelTime>0</KernelTime><UserTime>0</UserTime><Privileges>0</Privileges><PID>2868</PID><ParentPID>604</ParentPID><User>SYSTEM</User><Group/><MD5>28CE7780A0BAAC124972F5E983010B99</MD5><SHA1>89D6FBD96D0BBF4AF4B0C3450905A2B6E4567E23</SHA1><FuzzySize>49152</FuzzySize><Fuzzy>HRk2vY5DHiMQPfjfX1mRrNPEIYZ9j/QTMK2/LFkCDWTjUsq9K1FI</Fuzzy><Fuzzy2X>xshI/oUh9K2/BkCrsq9Kk</Fuzzy2X><KFFStatus>0</KFFStatus><FromAgent/><EffectiveUser/><EffectiveGroup/><Size>2788720</Size><EProcBlockLoc>0</EProcBlockLoc><WindowTitle/><Loaded_DLL_List><DLL><Name>ntdll.dll</Name><Path>C:\WINDOWS\SYSTEM32\ntdll.dll</Path></DLL><DLL><Name>KERNEL32.DLL</Name><Path>C:\WINDOWS\System32\KERNEL32.DLL</Path></DLL><DLL><Name>KERNELBASE.dll</Name><Path>C:\WINDOWS\System32\KERNELBASE.dll</Path></DLL><DLL><Name>ADVAPI32.dll</Name><Path>C:\WINDOWS\System32\ADVAPI32.dll</Path></DLL><DLL><Name>msvcrt.dll</Name><Path>C:\WINDOWS\System32\msvcrt.dll</Path></DLL><DLL><Name>sechost.dll</Name><Path>C:\WINDOWS\System32\sechost.dll</Path></DLL><DLL><Name>RPCRT4.dll</Name><Path>C:\WINDOWS\System32\RPCRT4.dll</Path></DLL><DLL><Name>WS2_32.dll</Name><Path>C:\WINDOWS\System32\WS2_32.dll<
...
...
...
<DLL id="C:\WINDOWS\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.17134.1006_none_d3fbb8f77c940c3f\COMCTL32.dll"><Name>COMCTL32.dll</Name><Description>Common Controls Library</Description><Path>C:\WINDOWS\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.17134.1006_none_d3fbb8f77c940c3f\COMCTL32.dll</Path><Version>5.82 (WinBuild.160101.0800)</Version><MD5>EB73880D07CDB79FDE95BC004EBA9D81</MD5><SHA1>876171064BEF3298F9D4E3FC356AEDFA1642D1CB</SHA1><FuzzySize>49152</FuzzySize><Fuzzy>eA9cxqsIjgJTj7WeLAJAu09f9+1s4iTJVpEuzXCW4</Fuzzy><Fuzzy2X>eSLsIjgJES+WpTJBzSD</Fuzzy2X><CreateTime>2019-09-21 03:33:15</CreateTime><KFFStatus>0</KFFStatus><PID>0</PID><baseAddress>0</baseAddress><ImageSize>0</ImageSize><ProcessName/><FromAgent/></DLL>
<DLL id="C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.17134.1006_none_04e6abdcd726860d\gdiplus.dll"><Name>gdiplus.dll</Name><Description>Microsoft GDI+</Description><Path>C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.17134.1006_none_04e6abdcd726860d\gdiplus.dll</Path><Version>10.0.17134.982 (WinBuild.160101.0800)</Version><MD5>46EDB80093592036AE006965C8CAF9BE</MD5><SHA1>DACDDC9FDF31F97CC110C163F2BB26158FD6D240</SHA1><FuzzySize>24576</FuzzySize><Fuzzy>BJDdtFnfVIUyIAA95gROBX2i6Nu1UHVSj3jd79EQVcSFWpFNOPRQvRcnYwj0+N</Fuzzy><Fuzzy2X>jtdIUyZDROBXMHV5OoNOP4mnXj</Fuzzy2X><CreateTime>2019-09-21 03:35:03</CreateTime><KFFStatus>0</KFFStatus><PID>0</PID><baseAddress>0</baseAddress><ImageSize>0</ImageSize><ProcessName/><FromAgent/></DLL>
</root>


## Additional Information
---

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
