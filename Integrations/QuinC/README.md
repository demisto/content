## Overview
---
Use the Quinc integration to protect against and provide additional visibility into phishing and other malicious email attacks.
This integration was integrated and tested with version 20190926 of QuinC
## Quinc Playbook
---

## Configure Quinc on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for QuinC.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL with scheme (FQDN or IP address in X.X.X.X format with scheme specified)__
    * __The token is required to connect to Quinc.__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. accessdata-legacyagent-get-processlist
2. accessdata-legacyagent-get-memorydump
3. accessdata-read-casefile
4. accessdata-jobstatus-scan
5. accessdata-get-jobstatus-processlist
6. accessdata-get-jobstatus-memorydump
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
| Accessdata.Job.ID | string | ID of job | 
| Accessdata.Job.CaseID | string | Case ID | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 


##### Command Example
`accessdata-legacyagent-get-processlist caseid=1 target_ip=X.X.X.X`

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": 992, 
        "Type": "Volatile", 
        "CaseID": "1", 
        "State": "Unknown", 
        "CaseJobID": "1_992"
    }
}
```

##### Human Readable Output
JobID: 992

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
| Accessdata.Job.CaseID | string | Case ID | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 


##### Command Example
`accessdata-legacyagent-get-memorydump caseid=1 target_ip=X.X.X.X`

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": 993, 
        "Type": "LegacyMemoryDump", 
        "CaseID": "1", 
        "State": "Unknown", 
        "CaseJobID": "1_993"
    }
}
```

##### Human Readable Output
JobID: 993

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
`accessdata-read-casefile filepath="\\X.X.X.X\D$\Program Files\AccessData\QuinC\app\demo\Demo Case\c00a2abf-1076-412b-8dea-67305fb8015f\Jobs\job_987\f6fac193-89ff-4f3f-92ac-0871c30621c0\1\snapshot.xml"`

##### Context Example
```
{
    "Accessdata.File.Contents": "<?xml version=\"1.0\"?>\r\n<root>\r\n<Process resultitemtype=\"15\"><Name>addm.exe</Name><Path/><StartTime>0000-00-00 00:00:00</StartTime><WorkingDir/><CommandLine/><LinkTime>0</LinkTime><Subsystem>0</Subsystem><Imagebase>0</Imagebase><Characteristics>0</Characteristics><Checksum>0</Checksum><KernelTime>0</KernelTime><UserTime>0</UserTime><Privileges>0</Privileges><PID>5324</PID><ParentPID>2868</ParentPID><User/><Group/><MD5>00000000000000000000000000000000</MD5><SHA1>0000000000000000000000000000000000000000</SHA1><FuzzySize>0</FuzzySize><Fuzzy/><Fuzzy2X/><KFFStatus>0</KFFStatus><FromAgent/><EffectiveUser/><EffectiveGroup/><Size>-1</Size><EProcBlockLoc>0</EProcBlockLoc><WindowTitle/><Open_Sockets_List count=\"1\"><Socket resultitemtype=\"13\"><Port>49914</Port><LocalAddress>127.0.0.1</LocalAddress><RemotePort>0</RemotePort><RemoteAddress>0.0.0.0</RemoteAddress><Proto>TCP</Proto><State>2</State><RealState>2</RealState><ProcessName>addm.exe</ProcessName><FromAgent/><PID>5324</PID></Socket></Open_Sockets_List></Process><Process resultitemtype=\"15\"><Name>adiso.exe</Name><Path/><StartTime>0000-00-00 00:00:00</StartTime><WorkingDir/><CommandLine/><LinkTime>0</LinkTime><Subsystem>0</Subsystem><Imagebase>0</Imagebase><Characteristics>0</Characteristics><Checksum>0</Checksum><KernelTime>0</KernelTime><UserTime>0</UserTime><Privileges>0</Privileges><PID>9092</PID><ParentPID>5324</ParentPID><User/><Group/><MD5>00000000000000000000000000000000</MD5><SHA1>0000000000000000000000000000000000000000</SHA1><FuzzySize>0</FuzzySize><Fuzzy/><Fuzzy2X/><KFFStatus>0</KFFStatus><FromAgent/><EffectiveUser/><EffectiveGroup/><Size>-1</Size><EProcBlockLoc>0</EProcBlockLoc><WindowTitle/></Process><Process resultitemtype=\"15\"><Name>agentcore.exe</Name><Path>C:\\Program Files\\AccessData\\Agent\\agentcore.exe</Path><StartTime>2019-09-24 14:21:05</StartTime><WorkingDir>C:\\WINDOWS\\system32\\</WorkingDir><CommandLine>\"C:\\Program Files\\AccessData\\Agent\\agentcore.exe\"</CommandLine><LinkTime>0</LinkTime><Subsystem>0</Subsystem><Imagebase>0</Imagebase><Characteristics>0</Characteristics><Checksum>0</Checksum><KernelTime>0</KernelTime><UserTime>0</UserTime><Privileges>0</Privileges><PID>2868</PID><ParentPID>604</ParentPID><User>SYSTEM</User><Group/><MD5>28CE7780A0BAAC124972F5E983010B99</MD5><SHA1>89D6FBD96D0BBF4AF4B0C3450905A2B6E4567E23</SHA1><FuzzySize>49152</FuzzySize><Fuzzy>HRk2vY5DHiMQPfjfX1mRrNPEIYZ9j/QTMK2/LFkCDWTjUsq9K1FI</Fuzzy><Fuzzy2X>xshI/oUh9K2/BkCrsq9Kk</Fuzzy2X><KFFStatus>0</KFFStatus><FromAgent/><EffectiveUser/><EffectiveGroup/><Size>2788720</Size><EProcBlockLoc>0</EProcBlockLoc><WindowTitle/><Loaded_DLL_List><DLL><Name>ntdll.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\ntdll.dll</Path></DLL><DLL><Name>KERNEL32.DLL</Name><Path>C:\\WINDOWS\\System32\\KERNEL32.DLL</Path></DLL><DLL><Name>KERNELBASE.dll</Name><Path>C:\\WINDOWS\\System32\\KERNELBASE.dll</Path></DLL><DLL><Name>ADVAPI32.dll</Name><Path>C:\\WINDOWS\\System32\\ADVAPI32.dll</Path></DLL><DLL><Name>msvcrt.dll</Name><Path>C:\\WINDOWS\\System32\\msvcrt.dll</Path></DLL><DLL><Name>sechost.dll</Name><Path>C:\\WINDOWS\\System32\\sechost.dll</Path></DLL><DLL><Name>RPCRT4.dll</Name><Path>C:\\WINDOWS\\System32\\RPCRT4.dll</Path></DLL><DLL><Name>WS2_32.dll</Name><Path>C:\\WINDOWS\\System32\\WS2_32.dll</Path></DLL><DLL><Name>USER32.dll</Name><Path>C:\\WINDOWS\\System32\\USER32.dll</Path></DLL><DLL><Name>win32u.dll</Name><Path>C:\\WINDOWS\\System32\\win32u.dll</Path></DLL><DLL><Name>GDI32.dll</Name><Path>C:\\WINDOWS\\System32\\GDI32.dll</Path></DLL><DLL><Name>gdi32full.dll</Name><Path>C:\\WINDOWS\\System32\\gdi32full.dll</Path></DLL><DLL><Name>msvcp_win.dll</Name><Path>C:\\WINDOWS\\System32\\msvcp_win.dll</Path></DLL><DLL><Name>ucrtbase.dll</Name><Path>C:\\WINDOWS\\System32\\ucrtbase.dll</Path></DLL><DLL><Name>SHELL32.dll</Name><Path>C:\\WINDOWS\\System32\\SHELL32.dll</Path></DLL><DLL><Name>cfgmgr32.dll</Name><Path>C:\\WINDOWS\\System32\\cfgmgr32.dll</Path></DLL><DLL><Name>shcore.dll</Name><Path>C:\\WINDOWS\\System32\\shcore.dll</Path></DLL><DLL><Name>combase.dll</Name><Path>C:\\WINDOWS\\System32\\combase.dll</Path></DLL><DLL><Name>bcryptPrimitives.dll</Name><Path>C:\\WINDOWS\\System32\\bcryptPrimitives.dll</Path></DLL><DLL><Name>windows.storage.dll</Name><Path>C:\\WINDOWS\\System32\\windows.storage.dll</Path></DLL><DLL><Name>shlwapi.dll</Name><Path>C:\\WINDOWS\\System32\\shlwapi.dll</Path></DLL><DLL><Name>kernel.appcore.dll</Name><Path>C:\\WINDOWS\\System32\\kernel.appcore.dll</Path></DLL><DLL><Name>profapi.dll</Name><Path>C:\\WINDOWS\\System32\\profapi.dll</Path></DLL><DLL><Name>powrprof.dll</Name><Path>C:\\WINDOWS\\System32\\powrprof.dll</Path></DLL><DLL><Name>FLTLIB.DLL</Name><Path>C:\\WINDOWS\\System32\\FLTLIB.DLL</Path></DLL><DLL><Name>ole32.dll</Name><Path>C:\\WINDOWS\\System32\\ole32.dll</Path></DLL><DLL><Name>CRYPT32.dll</Name><Path>C:\\WINDOWS\\System32\\CRYPT32.dll</Path></DLL><DLL><Name>MSASN1.dll</Name><Path>C:\\WINDOWS\\System32\\MSASN1.dll</Path></DLL><DLL><Name>WINTRUST.dll</Name><Path>C:\\WINDOWS\\System32\\WINTRUST.dll</Path></DLL><DLL><Name>PSAPI.DLL</Name><Path>C:\\WINDOWS\\System32\\PSAPI.DLL</Path></DLL><DLL><Name>SETUPAPI.dll</Name><Path>C:\\WINDOWS\\System32\\SETUPAPI.dll</Path></DLL><DLL><Name>fipscomm.dll</Name><Path>C:\\Program Files\\AccessData\\Agent\\fipscomm.dll</Path></DLL><DLL><Name>msi.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\msi.dll</Path></DLL><DLL><Name>MSVCP140.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\MSVCP140.dll</Path></DLL><DLL><Name>ad_globals.dll</Name><Path>C:\\Program Files\\AccessData\\Agent\\ad_globals.dll</Path></DLL><DLL><Name>LIBEAY32.dll</Name><Path>C:\\Program Files\\AccessData\\Agent\\LIBEAY32.dll</Path></DLL><DLL><Name>boost_system-vc140-mt-1_59.dll</Name><Path>C:\\Program Files\\AccessData\\Agent\\boost_system-vc140-mt-1_59.dll</Path></DLL><DLL><Name>SSLEAY32.dll</Name><Path>C:\\Program Files\\AccessData\\Agent\\SSLEAY32.dll</Path></DLL><DLL><Name>boost_date_time-vc140-mt-1_59.dll</Name><Path>C:\\Program Files\\AccessData\\Agent\\boost_date_time-vc140-mt-1_59.dll</Path></DLL><DLL><Name>boost_regex-vc140-mt-1_59.dll</Name><Path>C:\\Program Files\\AccessData\\Agent\\boost_regex-vc140-mt-1_59.dll</Path></DLL><DLL><Name>VCRUNTIME140.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\VCRUNTIME140.dll</Path></DLL><DLL><Name>VERSION.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\VERSION.dll</Path></DLL><DLL><Name>bcrypt.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\bcrypt.dll</Path></DLL><DLL><Name>NETAPI32.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\NETAPI32.dll</Path></DLL><DLL><Name>ad_log.dll</Name><Path>C:\\Program Files\\AccessData\\Agent\\ad_log.dll</Path></DLL><DLL><Name>boost_thread-vc140-mt-1_59.dll</Name><Path>C:\\Program Files\\AccessData\\Agent\\boost_thread-vc140-mt-1_59.dll</Path></DLL><DLL><Name>SRVCLI.DLL</Name><Path>C:\\WINDOWS\\SYSTEM32\\SRVCLI.DLL</Path></DLL><DLL><Name>boost_chrono-vc140-mt-1_59.dll</Name><Path>C:\\Program Files\\AccessData\\Agent\\boost_chrono-vc140-mt-1_59.dll</Path></DLL><DLL><Name>NETUTILS.DLL</Name><Path>C:\\WINDOWS\\SYSTEM32\\NETUTILS.DLL</Path></DLL><DLL><Name>wkscli.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\wkscli.dll</Path></DLL><DLL><Name>CRYPTSP.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\CRYPTSP.dll</Path></DLL><DLL><Name>rsaenh.dll</Name><Path>C:\\WINDOWS\\system32\\rsaenh.dll</Path></DLL><DLL><Name>CRYPTBASE.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\CRYPTBASE.dll</Path></DLL><DLL><Name>mssign32.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\mssign32.dll</Path></DLL><DLL><Name>imagehlp.dll</Name><Path>C:\\WINDOWS\\System32\\imagehlp.dll</Path></DLL><DLL><Name>WININET.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\WININET.dll</Path></DLL><DLL><Name>ncrypt.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\ncrypt.dll</Path></DLL><DLL><Name>NTASN1.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\NTASN1.dll</Path></DLL><DLL><Name>mswsock.dll</Name><Path>C:\\WINDOWS\\system32\\mswsock.dll</Path></DLL><DLL><Name>gpapi.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\gpapi.dll</Path></DLL><DLL><Name>cryptnet.dll</Name><Path>C:\\Windows\\System32\\cryptnet.dll</Path></DLL><DLL><Name>PROPSYS.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\PROPSYS.dll</Path></DLL><DLL><Name>OLEAUT32.dll</Name><Path>C:\\WINDOWS\\System32\\OLEAUT32.dll</Path></DLL><DLL><Name>clbcatq.dll</Name><Path>C:\\WINDOWS\\System32\\clbcatq.dll</Path></DLL><DLL><Name>OneCoreUAPCommonProxyStub.dll</Name><Path>C:\\Windows\\System32\\OneCoreUAPCommonProxyStub.dll</Path></DLL><DLL><Name>edputil.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\edputil.dll</Path></DLL><DLL><Name>urlmon.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\urlmon.dll</Path></DLL><DLL><Name>iertutil.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\iertutil.dll</Path></DLL><DLL><Name>Windows.StateRepositoryPS.dll</Name><Path>C:\\Windows\\System32\\Windows.StateRepositoryPS.dll</Path></DLL><DLL><Name>SspiCli.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\SspiCli.dll</Path></DLL><DLL><Name>CLDAPI.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\CLDAPI.dll</Path></DLL><DLL><Name>WinTypes.dll</Name><Path>C:\\Windows\\System32\\WinTypes.dll</Path></DLL><DLL><Name>pcacli.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\pcacli.dll</Path></DLL><DLL><Name>MPR.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\MPR.dll</Path></DLL><DLL><Name>sfc_os.dll</Name><Path>C:\\WINDOWS\\System32\\sfc_os.dll</Path></DLL><DLL><Name>IPHLPAPI.DLL</Name><Path>C:\\WINDOWS\\SYSTEM32\\IPHLPAPI.DLL</Path></DLL><DLL><Name>WINNSI.DLL</Name><Path>C:\\WINDOWS\\SYSTEM32\\WINNSI.DLL</Path></DLL><DLL><Name>NSI.dll</Name><Path>C:\\WINDOWS\\System32\\NSI.dll</Path></DLL><DLL><Name>WINHTTP.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\WINHTTP.dll</Path></DLL><DLL><Name>dhcpcsvc6.DLL</Name><Path>C:\\WINDOWS\\SYSTEM32\\dhcpcsvc6.DLL</Path></DLL><DLL><Name>dhcpcsvc.DLL</Name><Path>C:\\WINDOWS\\SYSTEM32\\dhcpcsvc.DLL</Path></DLL><DLL><Name>webio.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\webio.dll</Path></DLL><DLL><Name>DNSAPI.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\DNSAPI.dll</Path></DLL><DLL><Name>rasadhlp.dll</Name><Path>C:\\Windows\\System32\\rasadhlp.dll</Path></DLL><DLL><Name>fwpuclnt.dll</Name><Path>C:\\WINDOWS\\System32\\fwpuclnt.dll</Path></DLL></Loaded_DLL_List><Open_Sockets_List count=\"3\"><Socket resultitemtype=\"13\"><Port>3999</Port><LocalAddress>0.0.0.0</LocalAddress><RemotePort>0</RemotePort><RemoteAddress>0.0.0.0</RemoteAddress><Proto>TCP</Proto><State>2</State><RealState>2</RealState><ProcessName>agentcore.exe</ProcessName><FromAgent/><PID>2868</PID></Socket><Socket resultitemtype=\"13\"><Port>49931</Port><LocalAddress>127.0.0.1</LocalAddress><RemotePort>49928</RemotePort><RemoteAddress>127.0.0.1</RemoteAddress><Proto>TCP</Proto><State>5</State><RealState>5</RealState><ProcessName>agentcore.exe</ProcessName><FromAgent/><PID>2868</PID></Socket><Socket resultitemtype=\"13\"><Port>3999</Port><LocalAddress>0000:0000:0000:0000:0000:0000:0000:0000%0</LocalAddress><RemotePort>0</RemotePort><RemoteAddress>0000:0000:0000:0000:0000:0000:0000:0000%0</RemoteAddress><Proto>TCP</Proto><State>2</State><RealState>2</RealState><ProcessName>agentcore.exe</ProcessName><FromAgent/><PID>2868</PID></Socket></Open_Sockets_List></Process><Process resultitemtype=\"15\"><Name>applicationframehost.exe</Name><Path>C:\\WINDOWS\\system32\\ApplicationFrameHost.exe</Path><StartTime>2019-09-25 07:00:34</StartTime><WorkingDir>C:\\WINDOWS\\system32\\</WorkingDir><CommandLine>C:\\WINDOWS\\system32\\ApplicationFrameHost.exe -Embedding</CommandLine><LinkTime>0</LinkTime><Subsystem>0</Subsystem><Imagebase>0</Imagebase><Characteristics>0</Characteristics><Checksum>0</Checksum><KernelTime>0</KernelTime><UserTime>0</UserTime><Privileges>0</Privileges><PID>6448</PID><ParentPID>816</ParentPID><User>ediscovery</User><Group/><MD5>76536655C6CC49E27F7E8D195F55CCA7</MD5><SHA1>6E5A4FDB4447E215CF5EB0127A5780FD5742D29C</SHA1><FuzzySize>1536</FuzzySize><Fuzzy>d1YmB1ucLzcYeN22+XTGja0Kj+1EL3URqrNEPhu</Fuzzy><Fuzzy2X>3dBzb5GjQ+1ELSqBEc</Fuzzy2X><KFFStatus>0</KFFStatus><FromAgent/><EffectiveUser/><EffectiveGroup/><Size>69800</Size><EProcBlockLoc>0</EProcBlockLoc><WindowTitle/><Loaded_DLL_List><DLL><Name>ntdll.dll</Name><Path>C:\\WINDOWS\\SYSTEM32\\ntdll.dll</Path></DLL><DLL><Name>KERNEL32.DLL</Name><Path>C:\\WINDOWS\\System32\\KERNEL32.DLL</Path></DLL><DLL><Name>KERNELBASE.dll</Name><Path>C:\\WINDOWS\\System32\\KERNELBASE.dll</Path></DLL><DLL><Name>msvcrt.dll</Name><Path>C:\\WINDOWS\\System32\\msvcrt.dll</Path></DLL><DLL><Name>combase.dll</Name><Path>C:\\WINDOWS\\System32\\combase.dll</Path></DLL><DLL><Name>ucrtbase.dll</Name><Path>C:\\WINDOWS\\System32\\ucrtbase.dll</Path></DLL><DLL><Name>RPCRT4.dll</Name><Path>C:\\WINDOWS\\System32\\RPCRT4.dll</Path></DLL><DLL><Name>bcryptPrimitives.dll</Name><Path>C:\\WINDOWS\\System32\\bcryptPrimitives.dll</Path></DLL><DLL><Name>kernel.appcore.dll</Name><Path>C:\\WINDOWS\\System32\\kernel.appcore.dll</Path></DLL><DLL><Name>clbcatq.dll</Name><Path>C:\\WINDOWS\\System32\\clbcatq.dll</Path></DLL><DLL><Name>ApplicationFrame.dll</Name><Path>C:\\WINDOWS\\System32\\ApplicationFrame.dll</Path></DLL><DLL><Name>SHCORE.dll</Name><Path>C:\\WINDOWS\\System32\\SHCORE.dll</Path></DLL><DLL><Name>SHLWAPI.dll</Name><Path>C:\\WINDOWS\\System32\\SHLWAPI.dll</Path></DLL><DLL><Name>GDI32.dll</Name><Path>C:\\WINDOWS\\System32\\GDI32.dll</Path></DLL><DLL><Name>gdi32full.dll</Name><Path>C:\\WINDOWS\\System32\\gdi32full.dll</Path></DLL><DLL><Name>msvcp_win.dll</Name><Path>C:\\WINDOWS\\System32\\msvcp_win.dll</Path></DLL><DLL><Name>USER32.dll</Name><Path>C:\\WINDOWS\\System32\\USER32.dll</Path></DLL><DLL><Name>win32u.dll</Name><Path>C:\\WINDOWS\\System32\\win32u.dll</Path></DLL><DLL><Name>OLEAUT32.dll</Name><Path>C:\\WINDOWS\\System32\\OLEAUT32.dll</Path></DLL><DLL><Name>PROPSYS.dll</Name><Path>C:\\WINDOWS\\System32\\PROPSYS.dll</Path></DLL><DLL><Name>sechost.dll</Name><Path>C:\\WINDOWS\\System32\\sechost.dll</Path></DLL><DLL><Name>twinapi.appcore.dll</Name><Path>C:\\WINDOWS\\System32\\twinapi.appcore.dll</Path></DLL><DLL><Name>UxTheme.dll</Name><Path>C:\\WINDOWS\\System32\\UxTheme.dll</Path></DLL><DLL><Name>DEVOBJ.dll</Name><Path>C:\\WINDOWS\\System32\\DEVOBJ.dll</Path></DLL><DLL><Name>cfgmgr32.dll</Name><Path>C:\\WINDOWS\\System32\\cfgmgr32.dll</Path></DLL><DLL><Name>bcp47mrm.dll</Name><Path>C:\\WINDOWS\\System32\\bcp47mrm.dll</Path></DLL><DLL><Name>TWINAPI.dll</Name><Path>C:\\WINDOWS\\System32\\TWINAPI.dll</Path></DLL><DLL><Name>d2d1.dll</Name><Path>C:\\WINDOWS\\System32\\d2d1.dll</Path></DLL><DLL><Name>d3d11.dll</Name><Path>C:\\WINDOWS\\System32\\d3d11.dll</Path></DLL><DLL><Name>dwmapi.dll</Name><Path>C:\\WINDOWS\\System32\\dwmapi.dll</Path></DLL> ... BE</MD5><SHA1>DACDDC9FDF31F97CC110C163F2BB26158FD6D240</SHA1><FuzzySize>24576</FuzzySize><Fuzzy>BJDdtFnfVIUyIAA95gROBX2i6Nu1UHVSj3jd79EQVcSFWpFNOPRQvRcnYwj0+N</Fuzzy><Fuzzy2X>jtdIUyZDROBXMHV5OoNOP4mnXj</Fuzzy2X><CreateTime>2019-09-21 03:35:03</CreateTime><KFFStatus>0</KFFStatus><PID>0</PID><baseAddress>0</baseAddress><ImageSize>0</ImageSize><ProcessName/><FromAgent/></DLL>\r\n</root>\r\n"
}
```

##### Human Readable Output
<?xml version="1.0"?>
<root>
<Process resultitemtype="15"><Name>addm.exe</Name><Path/><StartTime>0000-00-00 00:00:00</StartTime><WorkingDir/><CommandLine/><LinkTime>0</LinkTime><Subsystem>0</Subsystem><Imagebase>0</Imagebase><Characteristics>0</Characteristics><Checksum>0</Checksum><KernelTime>0</KernelTime><UserTime>0</UserTime ... </MD5><SHA1>DACDDC9FDF31F97CC110C163F2BB26158FD6D240</SHA1><FuzzySize>24576</FuzzySize><Fuzzy>BJDdtFnfVIUyIAA95gROBX2i6Nu1UHVSj3jd79EQVcSFWpFNOPRQvRcnYwj0+N</Fuzzy><Fuzzy2X>jtdIUyZDROBXMHV5OoNOP4mnXj</Fuzzy2X><CreateTime>2019-09-21 03:35:03</CreateTime><KFFStatus>0</KFFStatus><PID>0</PID><baseAddress>0</baseAddress><ImageSize>0</ImageSize><ProcessName/><FromAgent/></DLL>
</root>


### accessdata-jobstatus-scan
---
Checks status of the job
##### Base Command

`accessdata-jobstatus-scan`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseJobID | Concatenated CaseID and JobID (like "1_800") | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CaseID | string | Case ID | 
| ID | string | Job ID | 
| CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 
| State | string | State of job's execution | 


##### Command Example
`accessdata-jobstatus-scan caseJobID=1_987`

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": "987", 
        "CaseID": "1", 
        "State": "Success", 
        "CaseJobID": "1_987"
    }
}
```

##### Human Readable Output
Current job state: Success

### accessdata-get-jobstatus-processlist
---
Get snapshot path from result of the process list job
##### Base Command

`accessdata-get-jobstatus-processlist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseID | ID of the case | Required | 
| jobID | ID of the job | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| State | string | Job state | 
| Result | string | Job result | 


##### Command Example
`accessdata-get-jobstatus-processlist caseID=1 jobID=987`

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": "987", 
        "Result": {
            "SnapshotDetails": {
                "File": "\\\\X.X.X.X\\D$\\Program Files\\AccessData\\QuinC\\app\\demo\\Demo Case\\c00a2abf-1076-412b-8dea-67305fb8015f\\Jobs\\job_987\\f6fac193-89ff-4f3f-92ac-0871c30621c0\\1\\snapshot.xml"
            }
        }, 
        "CaseID": "1", 
        "State": "Success", 
        "CaseJobID": "1_987"
    }
}
```

##### Human Readable Output
\\X.X.X.X\D$\Program Files\AccessData\QuinC\app\demo\Demo Case\c00a2abf-1076-412b-8dea-67305fb8015f\Jobs\job_987\f6fac193-89ff-4f3f-92ac-0871c30621c0\1\snapshot.xml

### accessdata-get-jobstatus-memorydump
---
Get memory dump path from result of the memory dump job
##### Base Command

`accessdata-get-jobstatus-memorydump`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseID | ID of the case | Required | 
| jobID | ID of the job | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| State | string | Job state | 
| Result | string | Job result | 


##### Command Example
`accessdata-get-jobstatus-memorydump caseID=1 jobID=989`

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": "989", 
        "Result": "\\\\X.X.X.X\\data\\SiteServer\\storage\\8ffafb2e-d077-4165-9aa7-f00cda29cce2\\1\\memdump.mem", 
        "CaseID": "1", 
        "State": "Success", 
        "CaseJobID": "1_989"
    }
}
```

##### Human Readable Output
\\X.X.X.X\data\SiteServer\storage\8ffafb2e-d077-4165-9aa7-f00cda29cce2\1\memdump.mem
