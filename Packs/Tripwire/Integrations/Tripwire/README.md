Tripwire is a file integrity management (FIM), monitors files and folders on systems and is triggered when they have changed.
This integration was integrated and tested with version 1 of Tripwire
## Configure Tripwire on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Tripwire.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Server URL \(e.g. https://tripwire.com\) | True |
    | credentials | Username | True |
    | isFetch | Fetch incidents | False |
    | incidentType | Incident type | False |
    | max_fetch | Maximum number of incidents per fetch | False |
    | first_fetch | First fetch time | False |
    | rule_oids | Rule ids | False |
    | node_oids | Node ids | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### tripwire-versions-list
***
Returns all Element Versions that meet the search critiera.


#### Base Command

`tripwire-versions-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| version_oids | Versions IDs given comma seperated. | Optional | 
| element_oids | Elements IDs of elements versions to fetch, comma seperated. | Optional | 
| element_names | Element names of elements versions to fetch. (case insensitive) .comma seperated. | Optional | 
| node_oids | Nodes IDs of elements versions to fetch. comma seperated. | Optional | 
| node_names | Nodes names of elements versions to fetch. comma seperated. | Optional | 
| rule_oids | Rules IDs of elements versions to fetch. comma seperated. | Optional | 
| rule_names | Rules names of elements versions to fetch. comma seperated. | Optional | 
| version_hashes | Possible Hashes value (md5, sha1, sha256, sha512) of elements versions to fetch. comma seperated. | Optional | 
| baseline_version_ids | Last baseline versions of elements versions to fetch. comma seperated. | Optional | 
| start_detected_time | Start detected time of element versions to fetch.<br/>The format can be either relative e.g. "2 days" or date time "2020-11-24T17:07:27Z".<br/>When using start time , please make sure to use end time too, if not end time will be set to current time by default. | Optional | 
| start_received_time | Start received time of element versions to fetch.<br/>The format can be either relative e.g. "2 days" or date time "2020-11-24T17:07:27Z".<br/>When using start time , please make sure to use end time too, if not end time will be set to current time by default. | Optional | 
| limit | Limit for the number of returned results. Default is 50. | Optional | 
| start | start index from which the results are returned. | Optional | 
| end_detected_time | End detected time of element versions to fetch.<br/>The format can be either relative e.g. "2 days" or date time "2020-11-24T17:07:27Z". | Optional | 
| end_received_time | End recieved time of element versions to fetch.<br/>The format can be either relative e.g. "2 days" or date time "2020-11-24T17:07:27Z". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tripwire.Versions.approvalId | String | Approval IDs of elements versions. | 
| Tripwire.Versions.baselineVersion | String | Last baseline versions of elements versions. | 
| Tripwire.Versions.changeType | String | Change types of elements versions | 
| Tripwire.Versions.elementId | String | Elements IDs of elements versions. | 
| Tripwire.Versions.elementName | String | Element names of elements versions. | 
| Tripwire.Versions.exists | Boolean | Exists condition of elements versions. | 
| Tripwire.Versions.id | String | ID of element versions. | 
| Tripwire.Versions.isPromoted | Boolean | True if the element version has been promoted. | 
| Tripwire.Versions.md5 | String | MD5 hashes of elements versions. | 
| Tripwire.Versions.nodeId | String | Nodes IDs of elements versions. | 
| Tripwire.Versions.nodeName | String | Nodes names of elements versions. | 
| Tripwire.Versions.outsideMaintenanceWindow | Boolean | Outside maintenance window condition of elements versions. | 
| Tripwire.Versions.promotionComment | String | Promotion comments of elements versions. | 
| Tripwire.Versions.ruleId | String | Rules IDs of elements versions. | 
| Tripwire.Versions.ruleName | String | Rules names of elements versions. | 
| Tripwire.Versions.scanId | String | Scan IDs of elements versions. | 
| Tripwire.Versions.severity | Number | Severities of elements versions. | 
| Tripwire.Versions.sha1 | String | SHA1 hashes of elements versions. | 
| Tripwire.Versions.sha256 | String | SHA256 hashes of elements versions. | 
| Tripwire.Versions.sha512 | String | SHA512 hashes of elements versions. | 
| Tripwire.Versions.timeDetected | Date | Times detected of elements versions. | 
| Tripwire.Versions.timeReceived | Date | Times received of elements versions. | 


#### Command Example
```!tripwire-versions-list node_ids start_detected_time=30 days' end_detected_time='1 day' node_names='ip-10-128-0-12.eu-west-1.compute.internal' rule_ids='-1y2p0ij32e8ch:-1y2p0ij3233dx'```

#### Context Example
```json
{
    "Tripwire": {
        "Versions": [
            {
                "approvalId": "",
                "baselineVersion": "-1y2y0yy32e8ch:-1y2p0yy3239dk",
                "changeType": "BASELINE",
                "elementId": "-1y2p0ij32e8cc:-1y2p0ij323hx2",
                "elementName": "/home/test/monitored-folder",
                "exists": true,
                "id": "-1y2p0ij32e8ch:-1y2p0ij323hx1",
                "isPromoted": false,
                "md5": "",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "nodeName": "test machine",
                "outsideMaintenanceWindow": false,
                "promotionComment": "",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij323i7o",
                "ruleName": "Test rule",
                "scanId": "-1y2p0ij32e86g:-1y2p0ij323hx3",
                "severity": 0,
                "sha1": "",
                "sha256": "",
                "sha512": "",
                "timeDetected": "2020-10-20T14:17:59.000Z",
                "timeReceived": "2020-10-20T14:17:59.000Z"
            },
            {
                "approvalId": "",
                "baselineVersion": "-1y2p0yy32e8ch:-1y2p0ij3239dj",
                "changeType": "BASELINE",
                "elementId": "-1y2p0yy32e8cc:-1y2p0ij323hx0",
                "elementName": "/home/Test/monitored-folder/test.txt",
                "exists": true,
                "id": "-1y2p0yy32e8ch:-1y2p0ij323hwz",
                "isPromoted": false,
                "md5": "",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "nodeName": "Test machine",
                "outsideMaintenanceWindow": false,
                "promotionComment": "",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij323i7o",
                "ruleName": "Test rule",
                "scanId": "-1y2p0ij32e86g:-1y2p0ij323hx3",
                "severity": 0,
                "sha1": "609707CA10549208F8396FFB381E60B3626AA408",
                "sha256": "",
                "sha512": "",
                "timeDetected": "2020-10-20T14:17:59.000Z",
                "timeReceived": "2020-10-20T14:17:59.000Z"
            },
            {
                "approvalId": "",
                "baselineVersion": "-1y2p0ij32e8ch:-1y2p0ij323htj",
                "changeType": "BASELINE",
                "elementId": "-1y2p0ij32e8cc:-1y2p0ij323htk",
                "elementName": "/etc/test/test/test",
                "exists": false,
                "id": "-1y2p0ij32e8ch:-1y2p0ij323htj",
                "isPromoted": false,
                "md5": "",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "nodeName": "Test machine",
                "outsideMaintenanceWindow": false,
                "promotionComment": "",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij32bqux",
                "ruleName": "Init Scripts",
                "scanId": "-1y2p0ij32e86g:-1y2p0ij323hwn",
                "severity": 0,
                "sha1": "",
                "sha256": "",
                "sha512": "",
                "timeDetected": "2020-10-20T14:23:41.000Z",
                "timeReceived": "2020-10-20T14:23:41.000Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Tripwire Versions list results
>The number of returned results is: 50
>|id|timeDetected|elementName|changeType|nodeName|ruleName|
>|---|---|---|---|---|---|
>| -1y2p0ij32e8ch:-1y2p0ij323hx1 | 2020-10-20T14:17:59.000Z | /home/test/monitored-folder | BASELINE | test machine | Test rule |
>| -1y2p0ij32e8ch:-1y2p0ij323hwz | 2020-10-20T14:17:59.000Z | /home/test/monitored-folder/test.txt | BASELINE | test machine | Test rule |
>| -1y2p0ij32e8ch:-1y2p0ij323htj | 2020-10-20T14:23:41.000Z | /etc/test/test/test | BASELINE | test machine | Init Scripts |


### tripwire-rules-list
***
Returns a list of all rules or those that match the provided filter criteria.


#### Base Command

`tripwire-rules-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_oids | IDs of rules to fetch. comma seperated. | Optional | 
| rule_names | Names of rules to fetch. comma seperated. | Optional | 
| rule_types | Types of rules to fetch. comma seperated. | Optional | 
| limit | Page limit for paging support. Default is 50. | Optional | 
| start   | start index from which the results are returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tripwire.Rules.command | String | Content of the rule. | 
| Tripwire.Rules.elementName | String | Include Command Output Capture Rules with matching element name. | 
| Tripwire.Rules.id | String | IDs of rules. | 
| Tripwire.Rules.importedTime | Date | Imported times of rules. | 
| Tripwire.Rules.modifiedTime | Date | Modified times of rules. | 
| Tripwire.Rules.name | String | Names of rules. | 
| Tripwire.Rules.severity | Number | Severities of rules. | 
| Tripwire.Rules.timeoutMillis | Number | Include Command Output Capture Rules with matching timeout in milliseconds. | 
| Tripwire.Rules.trackingId | String | Tracking ids of rules. | 
| Tripwire.Rules.type | String | Types of rules. | 


#### Command Example
```!tripwire-rules-list```

#### Context Example
```json
{
    "Tripwire": {
        "Rules": [
            {
                "command": "%Windir%/system32/sc.exe sdshow Fax",
                "elementName": "sc sdshow Fax",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c200",
                "importedTime": "2020-09-30T17:33:23.330Z",
                "modifiedTime": "2020-09-30T17:33:23.330Z",
                "name": "Fax Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000041",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "(echo Set oFSO = CreateObject(\"Scripting.FileSystemObject\"^) & echo EMET_Dll = \"%SystemRooT%\\AppPatch\\emet.dll\" & echo If oFSO.FileExists(EMET_Dll^) then & echo WScript.Echo oFSO.GetFileVersion(EMET_Dll^) & echo Else & echo WScript.Echo \"EMET Is Not Installed\" & echo End If) > \"$(TEMP_DIR)\"\\EMET_Version.vbs & %SystemRoot%\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\EMET_Version.vbs & del \"$(TEMP_DIR)\"\\EMET_Version.vbs",
                "elementName": "EMET Version",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1zz",
                "importedTime": "2020-09-30T17:33:23.344Z",
                "modifiedTime": "2020-09-30T17:33:23.344Z",
                "name": "EMET Version",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0007536",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow RasAuto",
                "elementName": "sc sdshow RasAuto",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1zy",
                "importedTime": "2020-09-30T17:33:23.350Z",
                "modifiedTime": "2020-09-30T17:33:23.350Z",
                "name": "RasAuto Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000051",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%systemRoot%\\system32\\dism.exe /online /Get-ProvisionedAppxPackages /ScratchDir:\"$(TEMP_DIR)\"",
                "elementName": "List of App Packages",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1zv",
                "importedTime": "2020-09-30T17:33:23.360Z",
                "modifiedTime": "2020-09-30T17:33:23.360Z",
                "name": "Get the List of App Packages",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0006849",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "(echo Const HKEY_LOCAL_MACHINE = ^&H80000002 & echo strComputer = \".\" & echo vers = \"\" & echo Set oFSO = CreateObject(\"Scripting.FileSystemObject\"^) & echo EMET_Dll = \"C:\\Windows\\AppPatch\\emet.dll\" & echo If oFSO.FileExists(EMET_Dll^) then & echo vers = Mid(oFSO.GetFileVersion(EMET_Dll^),1,1^) & echo Else & echo WScript.Echo \"EMET is not installed.\" & echo Wscript.Quit & echo End If & echo Set oReg=GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\\" ^& strComputer ^& \"\\root\\default:StdRegProv\"^) & echo strKeyPath = \"Software\\Policies\\Microsoft\\EMET\\Defaults\" & echo strRegKeyPath = \"SOFTWARE\\Microsoft\\EMET\" & echo oReg.EnumValues HKEY_LOCAL_MACHINE,strKeyPath,arrValueNames,arrValueTypes & echo oReg.EnumKey HKEY_LOCAL_MACHINE, strRegKeyPath, arrRegistryValueNames & echo If (vers = \"3\"^) Then & echo ValueNames=Array(\"7z\",\"7zFM\",\"7zGUI\",\"Chrome\",\"Firefox\",\"FirefoxPluginContainer\",\"GoogleTalk\",\"iTunes\",\"Java\",\"Javaw\",\"Javaws\",\"LiveMessenger\",\"LiveSync\",\"LiveWriter\",\"Lync\",\"mIRC\",\"MOE\",\"Opera\",\"PhotoshopCS2\",\"PhotoshopCS264\",\"PhotoshopCS3\",\"PhotoshopCS364\",\"PhotoshopCS4\",\"PhotoshopCS464\",\"PhotoshopCS5\",\"PhotoshopCS51\",\"PhotoshopCS5164\",\"PhotoshopCS564\",\"Pidgin\",\"QuickTimePlayer\",\"RealConverter\",\"RealPlayer\",\"Safari\",\"Skype\",\"Thunderbird\",\"ThunderbirdPluginContainer\",\"UnRAR\",\"VLC\",\"Winamp\",\"WindowsLiveSync\",\"WindowsMediaPlayer\",\"WinRARConsole\",\"WinRARGUI\",\"Winzip\",\"Winzip64\"^) & echo RegistryValueNames=Array(\"7z.exe\",\"7zfm.exe\",\"7zg.exe\",\"chrome.exe\",\"firefox.exe\",\"plugin-container.exe\",\"googletalk.exe\",\"itunes.exe\",\"java.exe\",\"javaw.exe\",\"javaws.exe\",\"msnmsgr.exe\",\"WLSync.exe\",\"windowslivewriter.exe\",\"communicator.exe\",\"mirc.exe\",\"MOE.exe\",\"opera.exe\",\"Photoshop.exe\",\"pidgin.exe\",\"QuickTimePlayer.exe\",\"realconverter.exe\",\"realplay.exe\",\"Safari.exe\",\"Skype.exe\",\"thunderbird.exe\",\"plugin-container.exe\",\"unrar.exe\",\"vlc.exe\",\"winamp.exe\",\"WindowsLiveSync.exe\",\"wmplayer.exe\",\"rar.exe\",\"winrar.exe\",\"winzip32.exe\",\"winzip64.exe\"^) & echo IsAppFound = checkSoftware(arrRegistryValueNames, RegistryValueNames^) & echo If (IsAppFound = \"1\"^) or (IsAppFound = \"\"^) Then & echo IsAppGPOFound = checkSoftware(arrValueNames, ValueNames^) & echo If IsAppGPOFound ^<^> \"0\" Then & echo WScript.Echo \"Default Protections for other Popular Software is not configured.\" & echo End If & echo End if & echo Elseif (vers = \"4\"^) Then & echo ValueNames=Array(\"7z\",\"7zFM\",\"7zGUI\",\"Chrome\",\"Firefox\",\"FirefoxPluginContainer\",\"FoxitReader\",\"GoogleTalk\",\"iTunes\",\"LiveWriter\",\"LyncCommunicator\",\"mIRC\",\"Opera\",\"PhotoGallery\",\"Photoshop\",\"Pidgin\",\"QuickTimePlayer\",\"RealConverter\",\"RealPlayer\",\"Safari\",\"SkyDrive\",\"Skype\",\"Thunderbird\",\"ThunderbirdPluginContainer\",\"UnRAR\",\"VLC\",\"Winamp\",\"WindowsLiveMail\",\"WindowsMediaPlayer\",\"WinRARConsole\",\"WinRARGUI\",\"Winzip\",\"Winzip64\"^) & echo RegistryValueNames=Array(\"7z.exe\",\"7zfm.exe\",\"7zg.exe\",\"chrome.exe\",\"firefox.exe\",\"plugin-container.exe\",\"foxit reader.exe\",\"googletalk.exe\",\"itunes.exe\",\"windowslivewriter.exe\",\"communicator.exe\",\"mirc.exe\",\"opera.exe\",\"WLXPhotoGallery.exe\",\"Photoshop.exe\",\"pidgin.exe\",\"QuickTimePlayer.exe\",\"realconverter.exe\",\"realplay.exe\",\"Safari.exe\",\"SkyDrive.exe\",\"Skype.exe\",\"thunderbird.exe\",\"plugin-container.exe\",\"unrar.exe\",\"vlc.exe\",\"winamp.exe\",\"wlmail.exe\",\"wmplayer.exe\",\"rar.exe\",\"winrar.exe\",\"winzip32.exe\",\"winzip64.exe\"^) & echo IsAppFound = checkSoftware(arrRegistryValueNames, RegistryValueNames^) & echo If (IsAppFound = \"1\"^) or (IsAppFound = \"\"^) Then & echo IsAppGPOFound = checkSoftware(arrValueNames, ValueNames^) & echo If IsAppGPOFound ^<^> \"0\" Then & echo WScript.Echo \"Default Protections for other Popular Software is not configured.\" & echo End If & echo End if & echo Elseif (vers = \"5\"^) Then & echo ValueNames=Array(\"7z\",\"7zFM\",\"7zGUI\",\"Chrome\",\"Firefox\",\"FirefoxPluginContainer\",\"FoxitReader\",\"GoogleTalk\",\"iTunes\",\"LiveWriter\",\"LyncCommunicator\",\"mIRC\",\"Opera\",\"Opera_New_Versions\",\"PhotoGallery\",\"Photoshop\",\"Pidgin\",\"QuickTimePlayer\",\"RealConverter\",\"RealPlayer\",\"Safari\",\"SkyDrive\",\"Skype\",\"Thunderbird\",\"ThunderbirdPluginContainer\",\"UnRAR\",\"VLC\",\"Winamp\",\"WindowsLiveMail\",\"WindowsMediaPlayer\",\"WinRARConsole\",\"WinRARGUI\",\"Winzip\",\"Winzip64\"^) & echo RegistryValueNames=Array(\"7z.exe\",\"7zfm.exe\",\"7zg.exe\",\"chrome.exe\",\"firefox.exe\",\"plugin-container.exe\",\"foxit reader.exe\",\"googletalk.exe\",\"itunes.exe\",\"windowslivewriter.exe\",\"communicator.exe\",\"mirc.exe\",\"opera.exe\",\"opera.exe\",\"WLXPhotoGallery.exe\",\"Photoshop.exe\",\"pidgin.exe\",\"QuickTimePlayer.exe\",\"realconverter.exe\",\"realplay.exe\",\"Safari.exe\",\"SkyDrive.exe\",\"Skype.exe\",\"thunderbird.exe\",\"plugin-container.exe\",\"unrar.exe\",\"vlc.exe\",\"winamp.exe\",\"wlmail.exe\",\"wmplayer.exe\",\"rar.exe\",\"winrar.exe\",\"winzip32.exe\",\"winzip64.exe\"^) & echo IsAppFound = checkSoftware(arrRegistryValueNames, RegistryValueNames^) & echo If (IsAppFound = \"1\"^) or (IsAppFound = \"\"^) Then & echo IsAppGPOFound = checkSoftware(arrValueNames, ValueNames^) & echo If IsAppGPOFound ^<^> \"0\" Then & echo WScript.Echo \"Default Protections for other Popular Software is not configured.\" & echo End If & echo End if & echo Else & echo Wscript.Echo \"EMET version is not supported: \" ^& vers & echo Wscript.Quit & echo End If & echo Function checkSoftware(arrValueNames, ValueNames^) & echo Dim isFound & echo If Not IsNull(arrValueNames^) Then & echo isDiff = 0 & echo For i = 0 To UBound(ValueNames^) & echo isFound = False & echo For j = 0 To UBound(arrValueNames^) & echo If Ucase(ValueNames(i^)^) = Ucase(arrValueNames(j^)^) Then & echo isFound = True & echo End If & echo Next & echo If Not isFound Then & echo isDiff = 1 & echo End If & echo Next & echo End If & echo checkSoftware = isDiff & echo End Function) > %SystemRoot%\\Temp\\PopularSoftware.vbs & %SystemRoot%\\system32\\cscript /nologo %SystemRoot%\\Temp\\PopularSoftware.vbs & del %SystemRoot%\\Temp\\PopularSoftware.vbs",
                "elementName": "EMET Default Protections for Popular Software",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1zu",
                "importedTime": "2020-09-30T17:33:23.366Z",
                "modifiedTime": "2020-09-30T17:33:23.366Z",
                "name": "EMET Default Protections for Popular Software",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0007535",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "echo On Error Resume Next > \"$(TEMP_DIR)\"\\TFTPClient.vbs & echo set objFSO = createobject(\"Scripting.FileSystemObject\") >> \"$(TEMP_DIR)\"\\TFTPClient.vbs & echo if objFSO.FileExists(\"%windir%\\system32\\tftp.exe\") then >> \"$(TEMP_DIR)\"\\TFTPClient.vbs & echo wscript.echo \"echo TFTP Client Exists\" >> \"$(TEMP_DIR)\"\\TFTPClient.vbs & echo else >> \"$(TEMP_DIR)\"\\TFTPClient.vbs & echo wscript.echo \"echo TFTP Client Does Not Exist\" >> \"$(TEMP_DIR)\"\\TFTPClient.vbs & echo end if >> \"$(TEMP_DIR)\"\\TFTPClient.vbs & \"%SystemRoot%\"\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\TFTPClient.vbs > \"$(TEMP_DIR)\"\\TFTPClient.bat & \"$(TEMP_DIR)\"\\TFTPClient.bat & del \"$(TEMP_DIR)\"\\TFTPClient.bat & del \"$(TEMP_DIR)\"\\TFTPClient.vbs",
                "description": "This rule verifies that the TFTP Client is installed or not.",
                "elementName": "TFTP Client",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1zr",
                "importedTime": "2020-09-30T17:33:23.374Z",
                "modifiedTime": "2020-09-30T17:33:23.374Z",
                "name": "TFTP Client Rule",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0005087",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "net localgroup \"Power Users\"",
                "elementName": "Power Users Group",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1zq",
                "importedTime": "2020-09-30T17:33:23.381Z",
                "modifiedTime": "2020-09-30T17:33:23.381Z",
                "name": "Power Users Group",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0005132",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow HTTPFilter",
                "elementName": "sc sdshow HTTPFilter",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1zn",
                "importedTime": "2020-09-30T17:33:23.398Z",
                "modifiedTime": "2020-09-30T17:33:23.398Z",
                "name": "HTTPFilter Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000046",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "(echo On Error Resume Next & echo Set WSHShell = WScript.CreateObject(\"WScript.Shell\"^) & echo Set objFSO = CreateObject(\"Scripting.FileSystemObject\"^) & echo FilePath = WSHShell.RegRead(\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\McAfeeFramework\\ImagePath\"^) & echo If FilePath ^<^>\"\" Then & echo FilePath =Ucase(FilePath^) & echo FilePath = Mid(FilePath, InStr(FilePath,\"\"\"\"^),InStrRev(FilePath,\"\"\"\"^)^) & echo FilePath = replace(FilePath,\"\"\"\", \"\"^) & echo If objFSO.FileExists(FilePath^) Then & echo Else & echo Wscript.Echo \"File does not exist.\" & echo End If & echo Else & echo WScript.echo \"File Not Found.\" & echo End if) > \"$(TEMP_DIR)\"\\FrameworkService.vbs & %SystemRoot%\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\FrameworkService.vbs & del \"$(TEMP_DIR)\"\\FrameworkService.vbs",
                "elementName": "FrameworkService.exe",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1zk",
                "importedTime": "2020-09-30T17:33:23.428Z",
                "modifiedTime": "2020-09-30T17:33:23.428Z",
                "name": "FrameworkService.exe Exist",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0004160",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "(echo Set oWMI = GetObject(\"winmgmts:\"^) & echo Set oShares = oWMI.ExecQuery(\"select Name from Win32_Share where Type=0\"^) & echo For Each oShare In oShares & echo Set oShareSecSetting = GetObject( _ & echo \"winmgmts:Win32_LogicalShareSecuritySetting.Name='\" ^& oShare.Name ^& \"'\"^) & echo WScript.Echo oShareSecSetting.Caption & echo iRC = oShareSecSetting.GetSecurityDescriptor(oSecurityDescriptor^) & echo aDACL = oSecurityDescriptor.DACL & echo For Each oAce In aDACL & echo Set oTrustee = oAce.Trustee & echo WScript.Echo \"Trustee Name: \" ^& oTrustee.Name & echo WScript.Echo & echo Next & echo Next) > \"$(TEMP_DIR)\"\\SharedFolderPermission.vbs & %SystemRoot%\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\SharedFolderPermission.vbs & del \"$(TEMP_DIR)\"\\SharedFolderPermission.vbs",
                "elementName": "Shared Folder Permission",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1zh",
                "importedTime": "2020-09-30T17:33:23.440Z",
                "modifiedTime": "2020-09-30T17:33:23.440Z",
                "name": "Verify Shared Folder Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0006266",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "(echo On Error Resume Next & echo strComputer = \".\" & echo Set oFSO = CreateObject(\"Scripting.FileSystemObject\"^) & echo wnStoreExFile = \"%SystemRoot%\\WinStore\\WinStore.UI.WinMD\" & echo wnMediaExFile = \"%SystemDrive%\\Program Files\\Windows Media Player\\wmplayer.exe\" & echo wnMediaExFileX86 = \"%SystemDrive%\\Program Files (x86)\\Windows Media Player\\wmplayer.exe\" & echo AutoDownloadKey=\"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsStore\\WindowsUpdate\\AutoDownload\" & echo AutoDownloadRegValue=\"\" & echo Set WSHShell = WScript.CreateObject(\"WScript.Shell\"^) & echo AutoDownloadRegValue = WSHShell.RegRead(AutoDownloadKey^) & echo AutoDownloadRegValueTemp=\"\" & echo If AutoDownloadRegValue ^<^> 2 then & echo AutoDownloadKey=\"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsStore\\AutoDownload\" & echo AutoDownloadRegValueTemp = WSHShell.RegRead(AutoDownloadKey^) & echo if AutoDownloadRegValueTemp ^<^> \"\" then & echo AutoDownloadRegValue = AutoDownloadRegValueTemp & echo end if & echo End if & echo If oFSO.FileExists(wnStoreExFile^) then & echo RemoveWinStoreRegValue = WSHShell.RegRead(\"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsStore\\RemoveWindowsStore\"^) & echo WScript.Echo \"AutoDownload \"^&AutoDownloadRegValue & echo WScript.Echo \"RemoveWindowsStore \"^&RemoveWinStoreRegValue & echo Else & echo WScript.Echo \"Windows Store Is Not Installed\" & echo End If & echo If (oFSO.FileExists(wnMediaExFile^) Or oFSO.FileExists(wnMediaExFileX86^)^) then & echo regGroupPrivacyValue = WSHShell.RegRead(\"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\GroupPrivacyAcceptance\"^) & echo regAutoUpdateValue = WSHShell.RegRead(\"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\DisableAutoUpdate\"^) & echo WScript.Echo \"GroupPrivacyAcceptance \"^&regGroupPrivacyValue & echo WScript.Echo \"DisableAutoUpdate \"^&regAutoUpdateValue & echo Else & echo WScript.Echo \"Windows Media Player Is Not Installed\" & echo End If) > \"$(TEMP_DIR)\"\\checkWindowsComponent.vbs & %SystemRoot%\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\checkWindowsComponent.vbs & del \"$(TEMP_DIR)\"\\checkWindowsComponent.vbs",
                "elementName": "Check Windows Components",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1ze",
                "importedTime": "2020-09-30T17:33:23.449Z",
                "modifiedTime": "2020-09-30T17:33:23.449Z",
                "name": "Check Windows Components",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0007702",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "(echo On Error Resume Next & echo ExhangeRoot = \"HKLM\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\" & echo regDSADatabaseFile = ExhangeRoot ^& \"\\DSA Database file\" & echo regDatabaseLogFilesPath = ExhangeRoot ^& \"\\Database log files path\" & echo regDSAWorkingDirectory = ExhangeRoot ^& \"\\DSA Working Directory\" & echo Set WSHShell = WScript.CreateObject(\"WScript.Shell\"^) & echo Set fso = CreateObject(\"Scripting.FileSystemObject\"^) & echo DSADatabaseFile = WSHShell.RegRead(regDSADatabaseFile^) & echo DatabaseLogFilesPath = WSHShell.RegRead(regDatabaseLogFilesPath^) & echo DSAWorkingDirectory = WSHShell.RegRead(regDSAWorkingDirectory^) & echo Dim DTDSDisk(3^) & echo Set disk = fso.GetDrive(fso.GetDriveName(fso.GetAbsolutepathname(DSADatabaseFile^)^)^) & echo DTDSDisk(0^) = disk.DriveLetter & echo Set disk = fso.GetDrive(fso.GetDriveName(fso.GetAbsolutepathname(DatabaseLogFilesPath^)^)^) & echo DTDSDisk(1^) = disk.DriveLetter & echo Set disk = fso.GetDrive(fso.GetDriveName(fso.GetAbsolutepathname(DSAWorkingDirectory^)^)^) & echo DTDSDisk(2^) = disk.DriveLetter & echo strComputer = \".\" & echo Set objWMIService = GetObject(\"winmgmts:\" _ & echo ^& \"{impersonationLevel=impersonate}!\\\\\" ^& strComputer ^& \"\\root\\cimv2\"^) & echo Set colShares = objWMIService.ExecQuery(\"Select * from Win32_Share\"^) & echo For each objShare in colShares & echo If (objShare.Name ^<^> \"NETLOGON\" and objShare.Name ^<^> \"SYSVOL\" and right(objShare.Name,1^) ^<^> \"$\"^) then & echo Set fso = CreateObject(\"Scripting.FileSystemObject\"^) & echo sharePath = Trim(objShare.Path^) & echo exists = fso.FolderExists(sharePath^) & echo if(exists^) Then & echo diskMatch = false & echo Set disk = fso.GetDrive(fso.GetDriveName(fso.GetAbsolutepathname(objShare.Path^)^)^) & echo For i = 0 to 2 & echo If (DTDSDisk(i^) = disk.DriveLetter^) Then & echo diskMatch = true & echo End if & echo Next & echo if (diskMatch^) then & echo Wscript.echo \"sharePath:\" ^& sharePath & echo Wscript.Echo \"Name: \" ^& objShare.Name & echo Wscript.Echo \"Path: \" ^& objShare.Path & echo end if & echo end if & echo End if & echo Next) > \"$(TEMP_DIR)\"\\DirectoryServerDataFileLocations.vbs & %SystemRoot%\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\DirectoryServerDataFileLocations.vbs & del \"$(TEMP_DIR)\"\\DirectoryServerDataFileLocations.vbs",
                "elementName": "Directory Server Data File Locations",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1zb",
                "importedTime": "2020-09-30T17:33:23.461Z",
                "modifiedTime": "2020-09-30T17:33:23.461Z",
                "name": "Directory Server Data File Locations",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0007485",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%WINDIR%\\System32\\Auditpol /resourceSACL /type:Key /view /user:everyone 2>NUL",
                "elementName": "Check Global Object Access Auditing of the Registry",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1za",
                "importedTime": "2020-09-30T17:33:23.465Z",
                "modifiedTime": "2020-09-30T17:33:23.465Z",
                "name": "Check Global Object Access Auditing of the Registry",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0007622",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "echo On Error Resume Next >\"$(TEMP_DIR)\"\\logFile.vbs & echo Set WSHShell = WScript.CreateObject(\"WScript.Shell\") >>\"$(TEMP_DIR)\"\\logFile.vbs & echo FilePath = WSHShell.RegRead(\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Application\\File\") >>\"$(TEMP_DIR)\"\\logFile.vbs & echo if FilePath ^<^>\"\" then >>\"$(TEMP_DIR)\"\\logFile.vbs & echo FilePath=\"cacls \"+ FilePath >>\"$(TEMP_DIR)\"\\logFile.vbs & echo WScript.echo FilePath >>\"$(TEMP_DIR)\"\\logFile.vbs & echo end if >>\"$(TEMP_DIR)\"\\logFile.vbs & \"%SystemRoot%\"\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\logFile.vbs >\"$(TEMP_DIR)\"\\logFile.bat & \"$(TEMP_DIR)\"\\logFile.bat & del \"$(TEMP_DIR)\"\\logFile.bat & del \"$(TEMP_DIR)\"\\logFile.vbs",
                "elementName": "AppEvent",
                "excludePattern": "^\\s*$|^.*\\>cacls\\s+.*$",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1z7",
                "importedTime": "2020-09-30T17:33:23.474Z",
                "modifiedTime": "2020-09-30T17:33:23.474Z",
                "name": "AppEvent Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0004093",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "echo On Error Resume Next >\"$(TEMP_DIR)\"\\logFile.vbs & echo Set WSHShell = WScript.CreateObject(\"WScript.Shell\") >>\"$(TEMP_DIR)\"\\logFile.vbs & echo NTPServer = WSHShell.RegRead(\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\W32time\\Parameters\\NtpServer\") >>\"$(TEMP_DIR)\"\\logFile.vbs & echo NTPType = WSHShell.RegRead(\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\W32time\\Parameters\\Type\") >>\"$(TEMP_DIR)\"\\logFile.vbs & echo If (NTPType = \"NTP\") or (NTPType = \"AllSync\") Then >>\"$(TEMP_DIR)\"\\logFile.vbs & echo NTPServer = Left(NTPServer, InStrRev(NTPServer, \",\")-1) >>\"$(TEMP_DIR)\"\\logFile.vbs & echo If NTPServer = \"time.windows.com\" Then >>\"$(TEMP_DIR)\"\\logFile.vbs & echo WScript.echo \"NTP Server \" + NTPServer + \". This should configure to an authorized time server in http://tycho.usno.navy.mil/ntp.html\" >>\"$(TEMP_DIR)\"\\logFile.vbs & echo End IF >>\"$(TEMP_DIR)\"\\logFile.vbs & echo End If >>\"$(TEMP_DIR)\"\\logFile.vbs & \"%SystemRoot%\"\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\logFile.vbs & del \"$(TEMP_DIR)\"\\logFile.vbs",
                "elementName": "Configure NTP Client",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1z6",
                "importedTime": "2020-09-30T17:33:23.480Z",
                "modifiedTime": "2020-09-30T17:33:23.480Z",
                "name": "Configure NTP Client",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0005886",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow RemoteRegistry",
                "elementName": "sc sdshow RemoteRegistry",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1z3",
                "importedTime": "2020-09-30T17:33:23.490Z",
                "modifiedTime": "2020-09-30T17:33:23.490Z",
                "name": "RemoteRegistry Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000031",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow POP3Svc",
                "elementName": "sc sdshow POP3Svc",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1z0",
                "importedTime": "2020-09-30T17:33:23.514Z",
                "modifiedTime": "2020-09-30T17:33:23.514Z",
                "name": "POP3Svc Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000036",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow VSS",
                "elementName": "sc sdshow VSS",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1yv",
                "importedTime": "2020-09-30T17:33:23.525Z",
                "modifiedTime": "2020-09-30T17:33:23.525Z",
                "name": "VSS Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0004244",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "$(WINDOWS_PS) \"cd cert:\\LocalMachine; Get-ChildItem -Recurse Cert: | Format-List -Property PSParentPath, Subject, Thumbprint, Issuer\"",
                "elementName": "Certificate Property",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1yt",
                "importedTime": "2020-09-30T17:33:23.537Z",
                "modifiedTime": "2020-09-30T17:33:23.537Z",
                "name": "Certificate Property Information",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0006439",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow NWCWorkstation",
                "elementName": "sc sdshow NWCWorkstation",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1yq",
                "importedTime": "2020-09-30T17:33:23.544Z",
                "modifiedTime": "2020-09-30T17:33:23.544Z",
                "name": "NWCWorkstation Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000042",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "(echo On Error Resume Next & echo strComputer = \".\" & echo isRunning = False & echo Incorrect = \"\" & echo Set oWMI = GetObject(\"winmgmts:{impersonationLevel=impersonate,authenticationLevel=Pkt}!\\\\\" _ & echo     ^& strComputer ^& \"\\root\\cimv2\"^) & echo Set WShShell = WScript.CreateObject(\"WScript.Shell\"^) & echo. & echo ' Determine processor of the machine & echo Set colSettings = oWMI.ExecQuery(\"SELECT * FROM Win32_Processor\"^) & echo For Each objProcessor In colSettings & echo     If objProcessor.AddressWidth = 64 Then & echo         Pro6432=\"Wow6432node\\\" & echo     Else & echo         Pro6432=\"\" & echo     End If & echo Next & echo. & echo ' Verify that McAfee anti-virus software is running correctly & echo Set McSrvs = oWMI.ExecQuery( \"Select * From Win32_Service Where Name='mcshield'\", , 48 ^) & echo For Each service in McSrvs & echo     If service.State = \"Running\" Then & echo         ' Determine if On Access Scan is enabled & echo         OAS = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\\" ^& Pro6432 ^& _ & echo             \"McAfee\\SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\OASEnabled\"^) & echo         If (OAS = 3^) Then & echo             WScript.Echo \"McAfee Anti-virus Software Is Running Correctly\" & echo             isRunning = True & echo         else & echo             Incorrect = vbNewLine ^& vbtab ^& \"On Access Scan Is Disabled\" & echo         End If & echo     End If & echo Next & echo. & echo ' Verify that Sophos anti-virus software is running & echo Set SophosSrvs = oWMI.ExecQuery( \"Select * From Win32_Service Where Name='SAVService'\", , 48 ^) & echo. & echo For Each service in SophosSrvs & echo     If service.State = \"Running\" Then & echo         wscript.echo \"Sophos Anti-virus Software Is Running\" & echo         isRunning = True & echo     End If & echo Next & echo. & echo ' Verify that Symantec Endpoint Protection is running correctly & echo Set SepSrvs = oWMI.ExecQuery( \"Select * From Win32_Service Where Name='SepMasterService'\", , 48 ^) & echo. & echo ' Verify that Symantec Endpoint Protection service is running & echo For Each service in SepSrvs & echo     If service.State = \"Running\" Then & echo         ' Network Thread Protection & echo         NTP = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\SMC\\smc_engine_status\"^) & echo         ' Virus and Spyware Protection. It includes 3 functions: & echo         ' File System auto-protect and Download Insight & echo         ' Outlook auto-protect & echo         FSA_DI = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\\" ^& Pro6432 ^& _ & echo             \"Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan\\OnOff\"^) & echo         OA = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\\" ^& Pro6432 ^& _ & echo             \"Symantec\\Symantec Endpoint Protection\\AV\\Storages\\MicrosoftExchangeClient\\RealTimeScan\\OnOff\"^) & echo         If (( NTP And FSA_DI And OA^) = 1^) Then & echo             WScript.Echo \"Symantec Endpoint Protection Anti-virus Software Is Running Correctly\" & echo             isRunning = True & echo         Else & echo             if (NTP ^<^> 1^) Then & echo                 Incorrect = vbNewLine ^& vbtab ^& \"Network Thread Protection Is Disabled\" & echo             End If & echo             If ((FSA_DI And OA^) ^<^> 1^) Then & echo                 Incorrect = Incorrect ^& vbnewline ^& vbtab ^& \"Virus and Spyware Protection Is Disabled\" & echo             End If & echo         End If & echo     End If & echo Next & echo. & echo ' Verify that Trend ServerProtection anti-virus software is running & echo Set TrendSrvs = oWMI.ExecQuery( \"Select * From Win32_Service Where Name='SpntSvc'\", , 48 ^) & echo For Each service in TrendSrvs & echo     If service.State = \"Running\" Then & echo         wscript.echo \"Trend ServerProtection Anti-virus Software Is Running\" & echo         isRunning = True & echo     End If & echo Next & echo. & echo ' Verify that Kaspersky Endpoint Security software is running correctly  & echo ' (File Anti-Virus, Firewall, Network Attack Blocker are enabled^) & echo Set KESSrvs = oWMI.ExecQuery( \"Select * From Win32_Service Where Name='AVP'\", , 48 ^) & echo For Each service in KESSrvs & echo     If service.State = \"Running\" Then & echo         Set kesVer = \"8\" & echo         Const HKEY_LOCAL_MACHINE = ^&H80000002 & echo. & echo         Set objReg=GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\default:StdRegProv\"^) & echo. & echo         strKeyPath = \"SOFTWARE\\\" ^& Pro6432 ^& \"KasperskyLab\\protected\" & echo         objReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, arrSubKeys & echo. & echo         For Each Subkey in arrSubKeys & echo         if Instr(SubKey,\"KES\"^) ^<^> 0 Then & echo             kesVer = SubKey & echo         End If & echo         Next & echo         ' Check File Anti-Virus & echo         FileAV = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\\" ^& Pro6432 ^& \"KasperskyLab\\protected\\\" ^& kesVer ^& \"\\profiles\\Protection\\profiles\\File_Monitoring\\enabled\"^) & echo         ' Check Firewall & echo         FW = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\\" ^& Pro6432 ^& \"KasperskyLab\\protected\\\" ^& kesVer ^& \"\\profiles\\Protection\\profiles\\Firewall\\enabled\"^) & echo         ' Check Network Attack Blocker & echo         NAB = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\\" ^& Pro6432 ^& \"KasperskyLab\\protected\\\" ^& kesVer ^& \"\\profiles\\Protection\\profiles\\ids\\enabled\"^) & echo         If (( FileAV And FW And NAB^) = 1^) Then & echo             WScript.Echo \"Kaspersky Endpoint Security Anti-virus Software Is Running Correctly\" & echo             isRunning = True & echo         Else & echo             If (FileAV ^<^> 1^) Then & echo                 Incorrect = vbNewLine ^& vbtab ^& \"File Anti-Virus Protection Is Disabled\" & echo             End If & echo             If (FW ^<^> 1^) Then & echo                 Incorrect = Incorrect ^& vbnewline ^& vbtab ^& \"Firewall Protection Is Disabled\" & echo             End If & echo             If (NAB ^<^> 1^) Then & echo                 Incorrect = Incorrect ^& vbnewline ^& vbtab ^& \"Network Attack Blocker Protection Is Disabled\" & echo             End If & echo         End If & echo     End If & echo Next & echo. & echo ' Verify that Microsoft Forefront Endpoint Protection is running correctly & echo Set McMpSvc = oWMI.ExecQuery( \"Select * From Win32_Service Where Name='MsMpSvc'\", , 48 ^) & echo For Each service in McMpSvc & echo     If service.State = \"Running\" Then & echo          ' Determine if Real-time Protection is enabled & echo          RealTime = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft Antimalware\\Real-Time Protection\\DisableRealtimeMonitoring\"^) & echo          If (RealTime = 0^) Then & echo              WScript.Echo \"Microsoft Forefront Endpoint Protection Anti-virus Software Is Running Correctly\" & echo              isRunning = True & echo          else & echo               Incorrect = vbNewLine ^& vbtab ^& \"Real-time Protection Is Disabled\" & echo          End If & echo     End If & echo Next & echo. & echo ' Verify that TrendMicro OfficeScan anti-virus software is running & echo Set TrendOSSrvs = oWMI.ExecQuery( \"Select * From Win32_Service Where Name='ntrtscan'\", , 48 ^) & echo For Each service in TrendOSSrvs & echo     If service.State = \"Running\" Then & echo         wscript.echo \"TrendMicro OfficeScan Anti-virus Software Is Running\" & echo         isRunning = True & echo     End If & echo Next  & echo.  & echo If (Not isRunning^) Then & echo     WScript.Echo \"Anti-virus Software Is Not Running or Its Functions Are Not Running Correctly\" ^& Incorrect & echo     WScript.Quit(-1^) & echo End If & echo WScript.Quit(0^)) > \"$(TEMP_DIR)\"\\AVStatus.vbs & %SystemRoot%\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\AVStatus.vbs & del \"$(TEMP_DIR)\"\\AVStatus.vbs",
                "description": "This rule detects that the installed Anti-Virus software is actively running.",
                "elementName": "Anti-virus Status",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1yn",
                "importedTime": "2020-09-30T17:33:23.553Z",
                "modifiedTime": "2020-09-30T17:33:23.553Z",
                "name": "Cybercrime Controls Anti-virus Status",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0006054",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "cd \"%SystemRoot%\" & dir /b/s POSIX.EXE PSXSS.EXE PSXDLL.DLL",
                "description": "POSIX Subsystem files should also be removed",
                "elementName": "POSIX Subsystem File",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1yk",
                "importedTime": "2020-09-30T17:33:23.565Z",
                "modifiedTime": "2020-09-30T17:33:23.565Z",
                "name": "POSIX Subsystem File Components ",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000053",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow AppMgr",
                "elementName": "sc sdshow AppMgr",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1yh",
                "importedTime": "2020-09-30T17:33:23.574Z",
                "modifiedTime": "2020-09-30T17:33:23.574Z",
                "name": "AppMgr Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000026",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow Spooler",
                "elementName": "sc sdshow Spooler",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1ye",
                "importedTime": "2020-09-30T17:33:23.584Z",
                "modifiedTime": "2020-09-30T17:33:23.584Z",
                "name": "Spooler Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000050",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow MSFtpsvc",
                "elementName": "sc sdshow MSFtpsvc",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1yb",
                "importedTime": "2020-09-30T17:33:23.591Z",
                "modifiedTime": "2020-09-30T17:33:23.591Z",
                "name": "MSFtpsvc Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000065",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "(echo On Error Resume Next & echo isInstalled = False & echo. & echo Set WShShell = WScript.CreateObject(\"WScript.Shell\"^) & echo Set oWMI = GetObject(\"winmgmts:{impersonationLevel=impersonate,authenticationLevel=Pkt}!\\\\.\\root\\cimv2\"^) & echo ' Determine processor of the machine & echo Set colSettings = oWMI.ExecQuery(\"SELECT * FROM Win32_Processor\"^) & echo For Each objProcessor In colSettings & echo If objProcessor.AddressWidth = 64 Then & echo Pro6432=\"Wow6432node\\\" & echo Else & echo Pro6432=\"\" & echo End If & echo Next & echo. & echo ' Verify that McAfee Software is up to date & echo AVDatDate = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\\" ^& Pro6432 ^& \"McAfee\\AvEngine\\AVDatDate\"^) & echo If Err.number = 0 Then & echo AVDatDateDiff = DateDiff(\"d\",AVDatDate, Date^) & echo If AVDatDateDiff ^> 2 Then & echo WScript.Echo \"McAfee Anti-virus Software Is Not up to Date\" & echo Else & echo WScript.Echo \"McAfee Anti-virus Software Is up to Date\" & echo End If & echo isInstalled = True & echo End If & echo Err.Clear & echo. & echo ' Verify that Sophos Software is up to date & echo AVDef = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\\" ^& Pro6432 ^& \"Sophos\\AutoUpdate\\UpdateStatus\\LastUpdateTime\"^) & echo If Err.number = 0 Then & echo AVDef = FormatDateTime(DateAdd(\"s\",AVDef,\"01/01/1970 00:00:00\"^),2^) & echo AVDateDiff = DateDiff(\"d\",AVDef, Date^) & echo If AVDateDiff ^> 2 Then & echo WScript.Echo \"Sophos Anti-virus Software Is Not up to Date\" & echo Else & echo WScript.Echo \"Sophos Anti-virus Software Is up to Date\" & echo End If & echo isInstalled = True & echo End If & echo Err.Clear & echo. & echo ' Verify that Symantec Endpoint Protection Software is up to date & echo AVDef = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\\" ^& Pro6432 ^& _ & echo \"Symantec\\Symantec Endpoint Protection\\CurrentVersion\\SharedDefs\\DEFWATCH_10\"^) & echo. & echo If Err.number = 0 Then & echo ArrAVDef = Split(AVDef,\"\\\"^) & echo AVDef = ArrAVDef(UBound(ArrAVDef^)^) & echo YearDef = Left(AVDef, 4^) & echo MonthDef = Mid(AVDef, 5, 2^) & echo DayDef = Mid(AVDef, 7, 2^) & echo AVDateDiff = DateDiff(\"d\",MonthDef ^& \"/\" ^& DayDef ^& \"/\" ^& YearDef, Date^) & echo If AVDateDiff ^> 2 Then & echo WScript.Echo \"Symantec Endpoint Protection Anti-virus Software Is Not up to Date\" & echo Else & echo WScript.Echo \"Symantec Endpoint Protection Anti-virus Software Is up to Date\" & echo End If & echo isInstalled = True & echo End If & echo Err.Clear & echo.  & echo ' Verify that Trend ServerProtection Software is up to date & echo AVHome = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\\" ^& Pro6432 ^& _ & echo \"TrendMicro\\ServerProtect\\CurrentVersion\\HomeDirectory\"^) & echo If Err.number = 0 Then & echo Set fso = CreateObject(\"Scripting.FileSystemObject\"^) & echo If (Pro6432 ^<^> \"\"^) then & echo AVHome=AVHome ^& \"\\x64\" & echo End if & echo Set AVHomeF = fso.GetFolder(AVHome^) & echo Set AVFiles = AVHomeF.Files & echo Version = 0 & echo AVDef = \"1/1/1970 0:00:00\" & echo For each avFile In AVFiles & echo FileName = avFile.Name & echo If (InStr(FileName,\"lpt$vpn.\"^) = 1^) Then & echo If (Mid(FileName, InStr(FileName,\".\"^)+1^) ^> Version^) Then & echo AVDef = avFile.DateCreated & echo Version = Mid(FileName, InStr(FileName,\".\"^)+1^) & echo End If & echo End If & echo Next & echo AVDateDiff= DateDiff(\"d\",AVDef,Date^) & echo If AVDateDiff ^> 2 Then & echo WScript.Echo \"Trend Micro ServerProtection Anti-virus Software Is Not up to Date\" & echo Else & echo WScript.Echo \"Trend Micro ServerProtection Anti-virus Software Is up to Date\" & echo End If & echo isInstalled = True & echo End If & echo Err.Clear & echo. & echo ' Verify that Kaspersky Endpoint Security Software is up to date & echo Const HKEY_LOCAL_MACHINE = ^&H80000002 & echo Set kesVer = \"8\" & echo Set objReg=GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\default:StdRegProv\"^) & echo strKeyPath = \"SOFTWARE\\\" ^& Pro6432 ^& \"KasperskyLab\\protected\" & echo objReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, arrSubKeys & echo For Each strSubKey in arrSubKeys & echo if Instr(strSubKey,\"KES\"^) ^<^> 0 Then & echo kesVer = strSubKey & echo End If & echo Next & echo isUpdate = False & echo Set oReg = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\default:StdRegProv\"^) & echo oReg.EnumKey HKEY_LOCAL_MACHINE,\"SOFTWARE\\\" ^& Pro6432 ^& \"KasperskyLab\\protected\\\" ^& kesVer ^& \"\\profiles\", arrSubKeys & echo. & echo For Each strSubkey In arrSubKeys & echo If (InStr(strSubKey,\"Updater\"^) ^> 0^) Then & echo keyName=\"HKEY_LOCAL_MACHINE\\SOFTWARE\\\" ^& Pro6432 ^& \"KasperskyLab\\protected\\\" ^& kesVer ^& \"\\profiles\\\" ^& strSubkey ^& \"\\schedule\\LastRunTime\" & echo AVDef = Wshshell.RegRead(keyname^) & echo If Err.number = 0 Then & echo AVDef = FormatDateTime(DateAdd(\"s\",AVDef,\"01/01/1970 00:00:00\"^),2^) & echo AVDateDiff = DateDiff(\"d\",AVDef, Date^) & echo If AVDateDiff ^<= 2 Then & echo isUpdate = True & echo End If & echo End If & echo Err.Clear         & echo End If        & echo Next & echo If (Not IsNull(arrSubKeys^)^) Then & echo If isUpdate Then & echo WScript.Echo \"Kaspersky Endpoint Security Anti-virus Software Is up to Date\" & echo Else & echo WScript.Echo \"Kaspersky Endpoint Security Anti-virus Software Is Not up to Date\" & echo End If & echo isInstalled = True & echo End If & echo Err.Clear & echo. & echo ' Verify that Mircrosoft Forefront Endpoint Protection Software is up to date & echo Set AVService = oWMI.ExecQuery( \"Select * From Win32_Service Where Name='MsMpSvc'\", , 48^) & echo For Each service in AVService & echo oReg.GetBinaryValue HKEY_LOCAL_MACHINE, \"SOFTWARE\\Microsoft\\Microsoft Antimalware\\Signature Updates\", \"ASSignatureApplied\", strRetVal & echo ASDef = BinaryToDate(strRetVal^) & echo ASDateDiff = 3 & echo AVDateDiff = 3 & echo ASDateDiff = DateDiff(\"d\",ASDef, Date^) & echo oReg.GetBinaryValue HKEY_LOCAL_MACHINE, \"SOFTWARE\\Microsoft\\Microsoft Antimalware\\Signature Updates\", \"AVSignatureApplied\", strRetVal & echo AVDef = BinaryToDate(strRetVal^) & echo AVDateDiff = DateDiff(\"d\",AVDef, Date^) & echo.      & echo If (ASDateDiff ^> 2^) Or (AVDateDiff ^> 2^) Then & echo WScript.Echo \"Microsoft Forefront Endpoint Protection Anti-virus Software Is Not up to Date\" & echo else & echo WScript.Echo \"Microsoft Forefront Endpoint Protection Anti-virus Software Is up to Date\" & echo End if & echo isInstalled = True & echo Next & echo. & echo ' Verify that TrendMicro OfficeSan Software is up to date & echo Set AVService = oWMI.ExecQuery( \"Select * From Win32_Service Where Name='ntrtscan'\", , 48^) & echo For Each service in AVService & echo strRetVal = WSHShell.RegRead (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\\" ^& Pro6432 ^& \"\\TrendMicro\\PC-cillinNTCorp\\CurrentVersion\\Schedule Update\\LastScheduleUpdate\"^) & echo AVDateDiff = 172801 & echo strCurrentTime = (now(^) - #1/1/1970#^) * 86400 & echo AVDateDiff = strCurrentTime - strRetVal & echo If (AVDateDiff ^> 172800^) Then & echo WScript.Echo \"TrendMicro OfficeScan Anti-virus Software Is Not up to Date\" & echo else & echo WScript.Echo \"TrendMicro OfficeScan Anti-virus Software Is up to Date\" & echo End if & echo isInstalled = True & echo Next & echo. & echo ' Function BinaryToDate will covert a binary DATE_TIME structure into a variant date set & echo Function BinaryToDate(bArray^) & echo Dim Seconds, Days, dateTime & echo Set dateTime = CreateObject(\"WbemScripting.SWbemDateTime\"^) & echo Seconds = bArray(7^)*(2^^56^) + bArray(6^)*(2^^48^) + bArray(5^)*(2^^40^) + bArray(4^)*(2^^32^) + bArray(3^)*(2^^24^) + bArray(2^)*(2^^16^) + bArray(1^)*(2^^8^) + bArray(0^) & echo Days = Seconds/(1E7*86400^) & echo dateTime.SetVarDate CDate(DateSerial(1601, 1, 1^) + Days^), false & echo BinaryToDate = dateTime.GetVarDate(^) & echo End Function & echo. & echo If (Not isInstalled^) Then & echo WScript.echo \"Anti-virus Software Is Not Installed.\" & echo WScript.quit(-1^) & echo End If & echo WScript.Quit(0^)) > \"$(TEMP_DIR)\"\\AVUpdate.vbs & %SystemRoot%\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\AVUpdate.vbs & del \"$(TEMP_DIR)\"\\AVUpdate.vbs",
                "description": "This rule detects that the installed Anti-Virus software has recently updated the virus definitions.",
                "elementName": "Anti-virus Update",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1y8",
                "importedTime": "2020-09-30T17:33:23.599Z",
                "modifiedTime": "2020-09-30T17:33:23.599Z",
                "name": "Cybercrime Controls Anti-virus Update",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0006055",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/cacls.exe \"%SystemRoot%\"\\inf\\usbstor.inf",
                "elementName": "Permissions",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1y7",
                "importedTime": "2020-09-30T17:33:23.606Z",
                "modifiedTime": "2020-09-30T17:33:23.606Z",
                "name": "usbstor.inf Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0004050",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow NtFrs",
                "elementName": "sc sdshow NtFrs",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1y4",
                "importedTime": "2020-09-30T17:33:23.613Z",
                "modifiedTime": "2020-09-30T17:33:23.613Z",
                "name": "NtFrs Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000067",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "(echo On Error resume next & echo strComputer = \".\" & echo isStandalone=\"true\" & echo Set objWMIService = GetObject(\"winmgmts:\\\\\" ^& strComputer ^& \"\\root\\cimv2\"^) & echo Set WshShell = CreateObject(\"Wscript.Shell\"^) & echo ArrSubKeyName=Array(\"Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\EnableFirewall\",\"Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\DefaultInboundAction\",\"Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\DefaultOutboundAction\",\"Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\DisableNotifications\",\"Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\DisableUnicastResponsesToMulticastBroadcast\",\"Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\AllowLocalPolicyMerge\",\"Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\AllowLocalIPsecPolicyMerge\",\"Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging\\LogFilePath\",\"Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging\\LogFileSize\",\"Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging\\LogDroppedPackets\",\"Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging\\LogSuccessfulConnections\",\"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LocalAccountTokenFilterPolicy\"^) & echo Set colItems = objWMIService.ExecQuery(\"SELECT * FROM Win32_ComputerSystem\"^) & echo For Each objItem In colItems & echo If (objItem.DomainRole ^<^> 0^) and (objItem.DomainRole ^<^> 2^) then & echo IsStandalone=\"false\" & echo End if & echo Next & echo If (IsStandalone = \"true\"^) Then & echo Wscript.echo \"Domain Role: Standalone\" & echo Else & echo Wscript.echo \"Domain Role: Member of domain\" & echo End If & echo For Each subKeyName In ArrSubKeyName & echo keyName = \"HKEY_LOCAL_MACHINE\\\" ^& subKeyName & echo Value= WshShell.RegRead(keyname^) & echo If (Err.Number ^<^> 0^) Then & echo wscript.echo keyName ^& \":\" & echo err.Clear & echo Else & echo wscript.echo keyName ^& \":\" ^& Value & echo End If & echo Next) > \"$(TEMP_DIR)\"\\Hkey.vbs & %SystemRoot%\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\Hkey.vbs & del \"$(TEMP_DIR)\"\\Hkey.vbs",
                "elementName": "Get the Configuration of Domain",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1y1",
                "importedTime": "2020-09-30T17:33:23.633Z",
                "modifiedTime": "2020-09-30T17:33:23.633Z",
                "name": "Get the Configuration of Domain",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0007513",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "(%Windir%/system32/reg.exe query HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\262144\\Paths /s) | (%Windir%/system32/find.exe /i \"ItemData\")",
                "description": "This rule will list all paths that have 'Security Level' is Unrestricted type.",
                "elementName": "Unrestricted",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1xy",
                "importedTime": "2020-09-30T17:33:23.642Z",
                "modifiedTime": "2020-09-30T17:33:23.642Z",
                "name": "SRP - Unrestricted Security Level Rule",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0004618",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "echo On Error Resume Next >\"$(TEMP_DIR)\"\\logFile.vbs & echo Set WSHShell = WScript.CreateObject(\"WScript.Shell\") >>\"$(TEMP_DIR)\"\\logFile.vbs & echo FilePath = WSHShell.RegRead(\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\System\\File\") >>\"$(TEMP_DIR)\"\\logFile.vbs & echo if FilePath ^<^>\"\" then >>\"$(TEMP_DIR)\"\\logFile.vbs & echo FilePath=\"cacls \"+ FilePath >>\"$(TEMP_DIR)\"\\logFile.vbs & echo WScript.echo FilePath >>\"$(TEMP_DIR)\"\\logFile.vbs & echo end if >>\"$(TEMP_DIR)\"\\logFile.vbs & \"%SystemRoot%\"\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\logFile.vbs > \"$(TEMP_DIR)\"\\logFile.bat & \"$(TEMP_DIR)\"\\logFile.bat & del \"$(TEMP_DIR)\"\\logFile.bat & del \"$(TEMP_DIR)\"\\logFile.vbs",
                "elementName": "SysEvent",
                "excludePattern": "^\\s*$|^.*\\>cacls\\s+.*$",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1xv",
                "importedTime": "2020-09-30T17:33:23.649Z",
                "modifiedTime": "2020-09-30T17:33:23.649Z",
                "name": "SysEvent Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0004094",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "(echo On Error Resume Next & echo CreateFolder_AppendData = ^&h000004:Delete = ^&h010000:DeleteSubfolders_Files = ^&h000040:TraverseFolder_ExecuteFile = ^&h000020:ReadAttributes = ^&h000080:ReadPermissions = ^&h020000:ListFolder_ReadData = ^&h000001:ReadExtendedAttributes = ^&h000008:Synchronize = ^&h100000:WriteAttributes = ^&h000100:ChangePermissions = ^&h040000:CreateFiles_WriteData = ^&h000002:WriteExtendedAttributes = ^&h000010:TakeOwnerShip = ^&h080000:GENERIC_ALL = ^&H10000000:GENERIC_READ = ^&H80000000:GENERIC_WRITE = ^&H40000000:GENERIC_EXECUTE = ^&H20000000:Err=0:LFileName=\"\":Namepaths=\"\":Isprinted=0:DatabaseLogFilesPaths=\"\":DSAWorkingDirectories=\"\":ExhangeRoot = \"HKLM\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\":regDSADatabaseFile = ExhangeRoot ^& \"\\DSA Database file\":regDatabaseLogFilesPath = ExhangeRoot ^& \"\\Database log files path\":regDSAWorkingDirectory = ExhangeRoot ^& \"\\DSA Working Directory\" & echo Set WSHShell = WScript.CreateObject(\"WScript.Shell\"^):DSADatabaseFile = WSHShell.RegRead(regDSADatabaseFile^):DatabaseLogFilesPath = WSHShell.RegRead(regDatabaseLogFilesPath^):DSAWorkingDirectory = WSHShell.RegRead(regDSAWorkingDirectory^) & echo If DSAWorkingDirectory ^<^> \"\" Then:DSAWorkingDirectories=ListFiles(DSAWorkingDirectory^):End If:If DatabaseLogFilesPath ^<^> \"\" Then:If lcase(trim(DatabaseLogFilesPath^)^) ^<^> lcase(trim(DSAWorkingDirectory^)^) Then:DatabaseLogFilesPaths=ListFiles(DatabaseLogFilesPath^):End If:End If:LFileName=ConcatFile(LFileName,DSADatabaseFile^):LFileName=ConcatFile(LFileName,DatabaseLogFilesPaths^):LFileName=ConcatFile(LFileName,DSAWorkingDirectories^) & echo If LFileName ^<^> \"\" Then & echo Name = Split(LFileName , \";\"^) & echo for each Namepath in Name & echo if NamePath ^<^>\"\" then & echo Isprinted=0 & echo Set wmiFileSecSetting = GetObject(\"winmgmts:Win32_LogicalFileSecuritySetting.path=\" ^& chr(39^) ^& Namepath ^& chr(39^)^):RetVal = wmiFileSecSetting.GetSecurityDescriptor(wmiSecurityDescriptor^):intControlFlags = wmiSecurityDescriptor.ControlFlags & echo If Err ^<^> 0 Then & echo Err=0 & echo Else & echo Set dicAllowDACL = CreateObject(\"Scripting.Dictionary\"^):Set dicDenyDACL = CreateObject(\"Scripting.Dictionary\"^):DACL = wmiSecurityDescriptor.DACL & echo If not isNUll (DACL^) then & echo For each wmiAce in DACL & echo intAccessMask = wmiAce.AccessMask:Set Trustee = wmiAce.Trustee:Account=Trustee.Domain ^& \"\\\" ^& Trustee.Name & echo if wmiAce.AceType = 0 then & echo if dicAllowDACL.Exists(Account^) then:dicAllowDACL.Item(Account^) = dicAllowDACL.Item(Account^) OR intAccessMask:else:dicAllowDACL.add Account, intAccessMask:end if & echo else & echo if dicDenyDACL.Exists(Account^) then:dicDenyDACL.Item(Account^) = dicDenyDACL.Item(Account^) OR intAccessMask:else:dicDenyDACL.add Account, intAccessMask:end if & echo end if & echo Next & echo for each deny in dicDenyDACL.keys & echo if dicAllowDACL.Exists(deny^) then:dicAllowDACL.Item(deny^) = dicAllowDACL.Item(deny^) AND (dicDenyDACL.item(deny^) XOR ^&h1fffff^):end if & echo Next & echo If dicAllowDACL.Count ^> 0 Then & echo for each allow in dicAllowDACL.keys & echo StrPers=\"\":UserAccount=lcase(allow^) & echo If (UserAccount ^<^> \"builtin\\administrators\"^) and (UserAccount ^<^> \"nt authority\\system\"^) then & echo If ((dicAllowDACL.item(allow^) And ^&h1f01ff^) ^<^> Synchronize^) And ((dicAllowDACL.item(allow^) And ^&h1f01ff^) ^<^> 0^) then & echo If dicAllowDACL.item(allow^) AND CreateFolder_AppendData Then:StrPers=StrPers ^& \", \" ^& \"CreateFolder_AppendData\":End If & echo If dicAllowDACL.item(allow^) AND Delete Then:StrPers=StrPers ^& \", \" ^& \"Delete\":End If & echo If dicAllowDACL.item(allow^) AND DeleteSubfolders_Files Then:StrPers=StrPers ^& \", \" ^& \"DeleteSubfolders_Files\":End If & echo If dicAllowDACL.item(allow^) AND TraverseFolder_ExecuteFile Then:StrPers=StrPers ^& \", \" ^& \"TraverseFolder_ExecuteFile\":End If & echo If dicAllowDACL.item(allow^) AND ReadAttributes Then:StrPers=StrPers ^& \", \" ^& \"ReadAttributes\":End If & echo If dicAllowDACL.item(allow^) AND ReadPermissions Then:StrPers=StrPers ^& \", \" ^& \"ReadPermissions\":End If & echo If dicAllowDACL.item(allow^) AND ListFolder_ReadData Then:StrPers=StrPers ^& \", \" ^& \"ListFolder_ReadData\":End If & echo If dicAllowDACL.item(allow^) AND ReadExtendedAttributes Then:StrPers=StrPers ^& \", \" ^& \"ReadExtendedAttributes\":End If & echo If dicAllowDACL.item(allow^) AND WriteAttributes Then:StrPers=StrPers ^& \", \" ^& \"WriteAttributes\":End If & echo If dicAllowDACL.item(allow^) AND ChangePermissions Then:StrPers=StrPers ^& \", \" ^& \"ChangePermissions\":End If & echo If dicAllowDACL.item(allow^) AND CreateFiles_WriteData Then:StrPers=StrPers ^& \", \" ^& \"CreateFiles_WriteData\":End If & echo If dicAllowDACL.item(allow^) AND WriteExtendedAttributes Then:StrPers=StrPers ^& \", \" ^& \"WriteExtendedAttributes\":End If & echo If dicAllowDACL.item(allow^) AND TakeOwnerShip Then:StrPers=StrPers ^& \", \" ^& \"TakeOwnerShip\":End If & echo StrPers=Mid(StrPers,3^) & echo else & echo StrPers=GENERICALL(dicAllowDACL.item(allow^)^) & echo end if & echo If StrPers ^<^> \"\" Then:If Isprinted=0 Then:Isprinted=1:wscript.echo \"Folder/File: \" ^& Namepath:End If:wscript.echo vbTab ^& allow ^& \":\" ^& StrPers:End If & echo End If & echo next & echo End If & echo end if & echo End If & echo End If & echo Next & echo End If & echo Function ConcatFile(Conc,FileA^):If FileA ^<^> \"\" Then:If Conc ^<^> \"\" Then:If InStr(Conc ^& \";\",FileA ^& \";\"^) =0 Then:Conc= Conc ^& \";\" ^& FileA:End if:else:Conc= FileA:End If:End If:ConcatFile=Conc:End Function & echo Function ListFiles(Directory^) & echo DirPaths= \"cmd /c dir /B /A:-d \"+Directory+\" & exit\" : StrLs=\"\":Directory=Replace(Directory,chr(34^),\"\"^): Set objExecDir = WSHShell.Exec(DirPaths^):Do Until objExecDir.StdOut.AtEndOfStream:StrL = objExecDir.StdOut.ReadLine(^):StrL = trim(replace(StrL,vbtab,\" \"^)^):If StrL ^<^> \"\" Then:If StrLs = \"\" Then:StrLs=Directory+\"\\\"+StrL:Else:StrLs=StrLs+\";\"+Directory+\"\\\"+StrL:End If:End If:Loop:ListFiles=StrLs: & echo End Function & echo Function GENERICALL(Perm^) & echo GENERICEXECUTE=\"TraverseFolder_ExecuteFile\":GENERICREAD=\"ListFolder_ReadData, ReadAttributes, ReadExtendedAttributes, ReadPermissions\":GENERICWRITE=\"CreateFiles_WriteData, CreateFolder_AppendData, WriteAttributes, WriteExtendedAttributes\":GENERICALLs=\"CreateFolder_AppendData, Delete, DeleteSubfolders_Files, TraverseFolder_ExecuteFile, ReadAttributes, ReadPermissions, ListFolder_ReadData, ReadExtendedAttributes, WriteAttributes, ChangePermissions, CreateFiles_WriteData, WriteExtendedAttributes, TakeOwnerShip\":StrPer=\"\" & echo If Perm And GENERIC_ALL Then:StrPer=GENERICALLs:else:If Perm And GENERIC_EXECUTE then:StrPer=StrPer ^& \", \" ^& GENERICEXECUTE:End If:If Perm And GENERIC_READ then:StrPer=StrPer ^& \", \" ^& GENERICREAD:End If:If Perm And GENERIC_WRITE then:StrPer=StrPer ^& \", \" ^& GENERICWRITE:End If:If left(StrPer,1^)=\",\" Then:StrPer=Trim(Mid(StrPer,2^)^):End If:End If:GENERICALL=StrPer & echo End Function) > \"$(TEMP_DIR)\"\\NTDSPers.vbs & %SystemRoot%\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\NTDSPers.vbs & del \"$(TEMP_DIR)\"\\NTDSPers.vbs",
                "elementName": "Data File Access Permissions",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1xu",
                "importedTime": "2020-09-30T17:33:23.653Z",
                "modifiedTime": "2020-09-30T17:33:23.653Z",
                "name": "Data File Access Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0007483",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "echo option Explicit  > \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo On Error Resume Next  >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo Dim objShell >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo Dim NoAutoUpdate, WUServer >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo Dim NoAutoUpdateValue, WUServerValue, ProtocolHttp >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo NoAutoUpdate = \"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\\NoAutoUpdate\" >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo WUServer = \"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUServer\" >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo Set objShell = CreateObject(\"WScript.Shell\") >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo NoAutoUpdateValue = objShell.RegRead(NoAutoUpdate) >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo if (NoAutoUpdateValue=0) then >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo   WUServerValue = objShell.RegRead(WUServer) >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo   WUServerValue=LTrim(WUServerValue) >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo  if (Len(WUServerValue)=0) then >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo    WScript.Echo \"Value of WUServer registry is not configured.\" >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo  end if >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & echo end if >> \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & %SystemRoot%\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs & del \"$(TEMP_DIR)\"\\NoAutoUpdate.vbs",
                "elementName": "Check Configure Automatic Updates",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1xr",
                "importedTime": "2020-09-30T17:33:23.667Z",
                "modifiedTime": "2020-09-30T17:33:23.667Z",
                "name": "Check Configure Automatic Updates",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0005691",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/bootcfg.exe",
                "elementName": "boot.ini options",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1xo",
                "importedTime": "2020-09-30T17:33:23.675Z",
                "modifiedTime": "2020-09-30T17:33:23.675Z",
                "name": "Checking boot.ini File Options",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0003148",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "(echo On Error Resume Next & echo CreateFolder_AppendData = ^&h000004 & echo Delete = ^&h010000 & echo DeleleteSubfolders_Files = ^&h000040 & echo TraverseFolder_ExecuteFile = ^&h000020 & echo ReadAttributes = ^&h000080 & echo ReadPermissions = ^&h020000 & echo ListFolder_ReadData = ^&h000001 & echo ReadExtendedAttributes = ^&h000008 & echo Synchronize = ^&h100000 & echo WriteAttributes = ^&h000100 & echo ChangePermissions = ^&h040000 & echo CreateFiles_WriteData = ^&h000002 & echo WriteExtendedAttributes = ^&h000010 & echo TakeOwnerShip = ^&h080000 & echo OBJECT_INHERIT_ACE = 1 & echo CONTAINER_INHERIT_ACE = 2 & echo INHERIT_ONLY_ACE = 8 & echo GENERIC_ALL = ^&H10000000 & echo GENERIC_READ = ^&H80000000 & echo GENERIC_WRITE = ^&H40000000 & echo GENERIC_EXECUTE = ^&H20000000 & echo Set WSHShell = WScript.CreateObject(\"WScript.Shell\"^) & echo SYSTEMDRIVE=lcase(WSHShell.expandenvironmentstrings(\"%SYSTEMDRIVE%\"^)^) & echo NamePaths=SYSTEMDRIVE ^& \"\\\\;\" ^& SYSTEMDRIVE ^& \"\\\\windows;\" ^& SYSTEMDRIVE ^& \"\\\\Program Files;\" ^& SYSTEMDRIVE ^& \"\\\\Program Files (x86)\" & echo Name = Split(Namepaths , \";\"^) & echo for each Namepath in Name & echo if NamePath ^<^>\"\" then & echo objectpath = \"winmgmts:Win32_LogicalFileSecuritySetting.path='\" ^& NamePath ^& \"'\" & echo Set wmiFileSecSetting = GetObject(objectpath^) & echo RetVal = wmiFileSecSetting.GetSecurityDescriptor(wmiSecurityDescriptor^) & echo intControlFlags = wmiSecurityDescriptor.ControlFlags & echo wscript.echo \"Folder/File: \" ^& Namepath & echo If Err ^<^> 0 Then & echo wscript.echo vbTab ^& \"Folder/File does not exist.\" & echo Err=0 & echo Else & echo If intControlFlags AND 4096 Then & echo Set dicAllowDACL = CreateObject(\"Scripting.Dictionary\"^) & echo DACL = wmiSecurityDescriptor.DACL & echo If not isNUll (DACL^) then & echo For each wmiAce in DACL & echo intAccessMask = wmiAce.AccessMask & echo Set Trustee = wmiAce.Trustee & echo Account=Trustee.Domain ^& \"\\\" ^& Trustee.Name ^& \";\" ^& wmiAce.AceFlags & echo if wmiAce.AceType = 0 then & echo if dicAllowDACL.Exists(Account^) then & echo dicAllowDACL.Item(Account^) = dicAllowDACL.Item(Account^) OR intAccessMask & echo else & echo dicAllowDACL.add Account, intAccessMask & echo end if & echo else & echo Isdeny=1 & echo end if & echo Next & echo If Isdeny=0 then & echo If dicAllowDACL.Count ^> 0 Then & echo for each allow in dicAllowDACL.keys & echo StrPermissions=\"\" & echo If ((dicAllowDACL.item(allow^) And ^&h1f01ff^) ^<^> Synchronize^) And ((dicAllowDACL.item(allow^) And ^&h1f01ff^) ^<^> 0^) then & echo If dicAllowDACL.item(allow^) AND CreateFolder_AppendData Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"CreateFolder_AppendData\" & echo End If & echo If dicAllowDACL.item(allow^) AND Delete Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"Delete\" & echo End If & echo If dicAllowDACL.item(allow^) AND DeleteSubfolders_Files Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"DeleteSubfolders_Files\" & echo End If & echo If dicAllowDACL.item(allow^) AND TraverseFolder_ExecuteFile Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"TraverseFolder_ExecuteFile\" & echo End If & echo If dicAllowDACL.item(allow^) AND ReadAttributes Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"ReadAttributes\" & echo End If & echo If dicAllowDACL.item(allow^) AND ReadPermissions Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"ReadPermissions\" & echo End If & echo If dicAllowDACL.item(allow^) AND ListFolder_ReadData Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"ListFolder_ReadData\" & echo End If & echo If dicAllowDACL.item(allow^) AND ReadExtendedAttributes Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"ReadExtendedAttributes\" & echo End If & echo If dicAllowDACL.item(allow^) AND WriteAttributes Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"WriteAttributes\" & echo End If & echo If dicAllowDACL.item(allow^) AND ChangePermissions Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"ChangePermissions\" & echo End If & echo If dicAllowDACL.item(allow^) AND CreateFiles_WriteData Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"CreateFiles_WriteData\" & echo End If & echo If dicAllowDACL.item(allow^) AND WriteExtendedAttributes Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"WriteExtendedAttributes\" & echo End If & echo If dicAllowDACL.item(allow^) AND TakeOwnerShip Then & echo StrPermissions=StrPermissions ^& \", \" ^& \"TakeOwnerShip\" & echo End If & echo accs=Split(allow,\";\"^) & echo acc=accs(0^) & echo intIN=accs(1^) & echo StrPermissions=Mid(StrPermissions,3^) & echo else & echo StrPermissions=GENERICALL(dicAllowDACL.item(allow^)^) & echo end if & echo accs=Split(allow,\";\"^) & echo acc=accs(0^) & echo intIN=accs(1^) & echo If StrPermissions ^<^> \"\" Then & echo StrPermissions=StrPermissions ^& \":\" ^& PerApp(intIN^) & echo wscript.echo vbTab ^& acc ^& \":\" ^& StrPermissions & echo End If & echo next & echo Else & echo WScript.Echo vbTab ^& \"Does not exist Allow permissions.\" & echo End If & echo else & echo wscript.echo vbTab ^& Trustee.Domain ^& \"With deny Permissions.\" & echo ENd if & echo else & echo wscript.echo vbtab ^& \"No DACL present in security descriptor.\" & echo end if & echo else & echo wscript.echo vbtab ^& \"[\"^&NamePath ^&\"] includes inheritable permissions from this object's parent.\" & echo End if & echo End If & echo End If & echo Next & echo Function PerApp(intIN^) & echo If intIN And OBJECT_INHERIT_ACE Then & echo If intIN And CONTAINER_INHERIT_ACE Then & echo If intIN And INHERIT_ONLY_ACE Then & echo PerApp=\"SubfoldersAndFilesOnly\" & echo Else & echo PerApp=\"ThisFolderSubfoldersAndFiles\" & echo End If & echo Else & echo If intIN And INHERIT_ONLY_ACE Then & echo PerApp=\"FilesOnly\" & echo Else & echo PerApp=\"ThisFolderAndFiles\" & echo End If & echo End If & echo Else & echo If intIN And CONTAINER_INHERIT_ACE Then & echo If intIN And INHERIT_ONLY_ACE Then & echo PerApp=\"SubfoldersOnly\" & echo Else & echo PerApp=\"ThisFolderAndSubfolders\" & echo End If & echo Else & echo PerApp=\"ThisFolderOnly\" & echo End If & echo End If & echo End Function & echo Function GENERICALL(Perm^) & echo GENERICEXECUTE=\"TraverseFolder_ExecuteFile\" & echo GENERICREAD=\"ListFolder_ReadData, ReadAttributes, ReadExtendedAttributes, ReadPermissions\" & echo GENERICWRITE=\"CreateFiles_WriteData, CreateFolder_AppendData, WriteAttributes, WriteExtendedAttributes\" & echo GENERICALLs=\"CreateFolder_AppendData, Delete, DeleteSubfolders_Files, TraverseFolder_ExecuteFile, ReadAttributes, ReadPermissions, ListFolder_ReadData, ReadExtendedAttributes, WriteAttributes, ChangePermissions, CreateFiles_WriteData, WriteExtendedAttributes, TakeOwnerShip\" & echo StrPer=\"\" & echo If Perm And GENERIC_ALL Then & echo StrPer=GENERICALLs & echo else & echo If Perm And GENERIC_EXECUTE then & echo StrPer=StrPer ^& \", \" ^& GENERICEXECUTE & echo End If & echo If Perm And GENERIC_READ then & echo StrPer=StrPer ^& \", \" ^& GENERICREAD & echo End If & echo If Perm And GENERIC_WRITE then & echo StrPer=StrPer ^& \", \" ^& GENERICWRITE & echo End If & echo If left(StrPer,1^)=\",\" Then & echo StrPer=Trim(Mid(StrPer,2^)^) & echo End If & echo End If & echo GENERICALL=StrPer & echo End Function) > \"$(TEMP_DIR)\"\\SystemPermissions.vbs & %SystemRoot%\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\SystemPermissions.vbs & del \"$(TEMP_DIR)\"\\SystemPermissions.vbs",
                "elementName": "Get Permissions of System Folder",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1xn",
                "importedTime": "2020-09-30T17:33:23.682Z",
                "modifiedTime": "2020-09-30T17:33:23.682Z",
                "name": "Get Permissions of System Folder",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0006873",
                "type": "Command Output Capture Rule"
            },
            {
                "id": "-1y2p0ij32e7oz:-1y2p0ij32c1xi",
                "importedTime": "2020-09-30T17:33:23.711Z",
                "isRealTime": false,
                "modifiedTime": "2020-09-30T17:33:23.711Z",
                "name": "Policy Test Files",
                "startPoints": [
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1xh",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\winmsd.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1xf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\wscript.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1xe",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\xcopy.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1xd",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\cluster.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1xc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\cmd.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1xb",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\compact.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1xa",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\command.com",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1x9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\convert.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1x8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\cscript.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1x7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\dfscmd.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1x6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\diskcomp.com",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1x5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\diskcopy.com",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1x4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\doskey.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1x3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\exe2bin.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1x2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\expand.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1x1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\fc.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1x0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\find.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\findstr.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wy",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\finger.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wx",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\forcedos.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ww",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\format.com",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\hostname.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wu",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\iisreset.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wt",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\ipconfig.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ws",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\ipxroute.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wr",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\label.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\logoff.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wp",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\makecab.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wo",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\mem.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wn",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\mmc.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wm",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\mountvol.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wl",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\msiexec.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\msg.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\ntsd.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wi",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\pathping.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wh",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\ping.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wg",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\rasdial.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\recover.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1we",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\replace.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wd",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\reset.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\routemon.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wb",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\runonce.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1wa",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\shadow.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1w9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\share.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1w8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\syskey.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1w7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\taskmgr.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1w6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\tlntsess.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1w5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\tlntsvr.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1w4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\tracert.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1w3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\tree.com",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1w2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\tsadmin.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1w1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\tscon.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1w0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\system32\\mshta.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vy",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Program Files",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vx",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\Administrator",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\All Users",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vu",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\All Users\\Documents\\DrWatson",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vt",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\Default User",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vs",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\Temp",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vr",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\$NtServicePackUninstall$",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\CSC",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vp",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\Debug",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vo",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\Registration",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vn",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\repair",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vm",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\Debug\\UserMode",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vl",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\appmgmt",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\config",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\DTCLog",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vi",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\GroupPolicy",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vh",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\ias",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vg",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\NTMSData",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\reinstallbackups",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ve",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\Setup",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vd",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\at.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\drwatson.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1vb",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\drwtsn32.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1va",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\edlin.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1v9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\net.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1v8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\reg.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1v7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\regedt32.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1v6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\rexec.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1v5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\subst.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1v4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\telnet.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1v3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\spool\\printers",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1v2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Program Files\\Resource Kit",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1v1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\rsh.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1v0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\dllcache",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1uz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\security",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1uy",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\cacls.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ux",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\debug.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1uw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Temp",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1uv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\AUTOEXEC.BAT",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1uu",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\boot.ini",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ut",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\config.sys",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1us",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\io.sys",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ur",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\msdos.sys",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1uq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\ntbootdd.sys",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1up",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\ntdetect.com",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1uo",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\ntldr",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1un",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\arp.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1um",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\nbtstat.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ul",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\netstat.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1uk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\nslookup.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1uj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\ntbackup.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ui",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\regini.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1uh",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\route.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ug",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\secedit.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1uf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\systeminfo.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ue",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\All Users\\Application Data\\Microsoft\\Media Index",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ud",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\All Users\\Application Data\\Microsoft\\User Account Pictures\\guest.bmp",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1uc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\All Users\\DRM",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ub",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\All Users\\Documents",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ua",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\All Users\\DRM\\drmv2.lic",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1u9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\All Users\\DRM\\drmv2.sst",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1u8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\All Users\\Application Data",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1u7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\All Users\\Application Data\\Microsoft\\Crypto\\DSS\\MachineKeys",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1u6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Documents and Settings\\All Users\\Application Data\\Microsoft\\Crypto\\RSA\\MachineKeys",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1u5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\append.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1u4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\chkdsk.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1u3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\chkntfs.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1u2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\cipher.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1u1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\$Recycle.bin",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1u0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\Programdata",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\CCM\\Cache",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ty",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\CCM\\Cache\\skpswi.dat",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tx",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\CCM\\Inventory\\idmifs",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\CCM\\Inventory\\noidmifs",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\CCM\\Logs",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tu",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\Debug\\WPD",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tt",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\PCHealth\\ERRORREP\\QHEADLES",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ts",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\PCHealth\\ERRORREP\\QSIGNOFF",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tr",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\Registration\\CRMLog",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\Debug\\WIA",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tp",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\FxsTmp",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1to",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\com\\dmp",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tn",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\spool\\drivers\\color",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tm",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\Tasks",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tl",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\Tasks\\Microsoft\\Windows\\PLA\\System",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\tracing",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\Tasks\\Microsoft\\Windows\\WindowsCalendar",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ti",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\Microsoft\\Crypto\\RSA\\MachineKeys",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1th",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\eventtriggers.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tg",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\netsh.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\sc.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1te",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\regsvr32.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1td",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\tftp.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\attrib.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1tb",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\ftp.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ta",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\net1.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1t9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\rcp.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m5",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1t8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\runas.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1t7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1t6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMROOT)\\regedit.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1t5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\users\\All Users\\Microsoft\\Media Index",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1t4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\users\\All Users\\Microsoft\\User Account Pictures",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1t3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\users\\All users\\Microsoft\\User Account Pictures\\Default Pictures",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1t2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\users\\All Users\\Microsoft\\Crypto\\DSS\\MachineKeys",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1t1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\users\\All Users\\Microsoft\\Crypto\\RSA\\MachineKeys",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1t0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\users\\All Users\\Microsoft\\DRM\\Server",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\users\\All Users\\Microsoft\\Windows\\DRM",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sy",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\users\\All Users\\Microsoft\\Windows\\DRM\\Cache",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sx",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\users\\All Users\\Microsoft\\eHome",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\users\\Public\\Recorded TV",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEMDRIVE)\\users\\Public\\Recorded TV\\Sample Media",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1su",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\ACW.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1st",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\alg.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ss",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\AtBroker.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sr",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\audiodg.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\autoconv.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sp",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\autofmt.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1so",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\bcdedit.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sn",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\BitLockerWizard.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sm",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\bitsadmin.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sl",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\bootcfg.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\cmdkey.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\DFDWiz.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1si",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\dfrgfat.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sh",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\dfrgifc.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sg",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\dfrgui.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\dfsr.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1se",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\dialer.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sd",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\diskpart.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\dispdiag.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sb",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\eventcreate.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1sa",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\FirewallControlPanel.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1s9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\FirewallSettings.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1s8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\getmac.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1s7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\icacls.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1s6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\mobsync.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1s5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\MRINFO.EXE",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1s4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\mrt.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1s3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\rekeywiz.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1s2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\Robocopy.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1s1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\Rpcping.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1s0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\schtasks.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\sysedit.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ry",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\SystemPropertiesAdvanced.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rx",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\SystemPropertiesComputerName.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\SystemPropertiesDataExecutionPrevention.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\SystemPropertiesHardware.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ru",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\SystemPropertiesPerformance.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rt",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\SystemPropertiesProtection.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rs",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\SystemPropertiesRemote.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rr",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\systray.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\takeown.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rp",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\tracerpt.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ro",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\tscupgrd.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rn",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\tsdiscon.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rm",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\tskill.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rl",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\tsshutdn.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m6",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1rk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(SYSTEM32DIR)\\Utilman.exe",
                        "type": "PersistentStartPoint"
                    }
                ],
                "trackingId": "R0000001",
                "type": "Windows File System Rule"
            },
            {
                "command": "%Windir%\\system32\\net.exe users Support_388945a0 | %Windir%\\system32\\find.exe /i \"Account active\"",
                "elementName": "Check Active Support_388945a0 Account",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1re",
                "importedTime": "2020-09-30T17:33:24.016Z",
                "modifiedTime": "2020-09-30T17:33:24.016Z",
                "name": "Check Support_388945a0 Account",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0005668",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow Netman",
                "elementName": "sc sdshow Netman",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1rb",
                "importedTime": "2020-09-30T17:33:24.025Z",
                "modifiedTime": "2020-09-30T17:33:24.025Z",
                "name": "Netman Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000030",
                "type": "Command Output Capture Rule"
            },
            {
                "id": "-1y2p0ij32e7p7:-1y2p0ij32c1r8",
                "importedTime": "2020-09-30T17:33:24.044Z",
                "isRealTime": false,
                "modifiedTime": "2020-09-30T17:33:24.044Z",
                "name": "Policy Registry Values Extension",
                "startPoints": [
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1r7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\TabletPC|PreventHandwritingDataSharing",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1r5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion|CurrentVersion",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1r4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SYSTEM\\CurrentControlSet\\Services\\simptcp|DisplayName",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1r3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters|SupportedEncryptionTypes",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1r2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows NT\\Printers|DoNotInstallCompatibleDriverFromWindowsUpdate",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1r1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata|PreventDeviceMetadataFromNetwork",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1r0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\DriverSearching|SearchOrderConfig",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_ADDON_MANAGEMENT|*",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qy",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_BEHAVIORS|*",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qx",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_MIME_SNIFFING|*",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_DISABLE_MK_PROTOCOL|*",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_ACTIVEXINSTALL|*",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qu",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_PROTOCOL_LOCKDOWN|*",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qt",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_ACTIVEXINSTALL|(Reserved)",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qs",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_ACTIVEXINSTALL|iexplore.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qr",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_ACTIVEXINSTALL|explorer.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_ZONE_ELEVATION|*",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qp",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Ext|RestrictToList",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qo",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_MIME_HANDLING|*",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qn",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_SECURITYBAND|(Reserved)",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qm",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_SECURITYBAND|explorer.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ql",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_SECURITYBAND|iexplore.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_WINDOW_RESTRICTIONS|*",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_LOCALMACHINE_LOCKDOWN|(Reserved)",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qi",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_LOCALMACHINE_LOCKDOWN|explorer.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qh",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_LOCALMACHINE_LOCKDOWN|iexplore.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qg",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_OBJECT_CACHING|*",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetCache|Enabled",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qe",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions|DenyRemovableDevices",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qd",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM_Services)\\ehRecvr|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM_Services)\\ehSched|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qb",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM_Services)\\ehstart|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1qa",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM_Services)\\idsvc|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1q9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM_Services)\\Mcx2Svc|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1q8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM_Services)\\NetTcpPortSharing|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1q7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM_Services)\\TabletInputService|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1q6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM_Services)\\wcncsvc|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m3",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1q5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\IPSec\\ICFv4|BypassFirewall",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1q4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\NetCache|NoConfigCache",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1q3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows NT\\Printers|RegisterSpoolerRemoteRpcEndPoint",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1q2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows NT\\Printers|PublishPrinters",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1q1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows NT\\Printers|ServerThread",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1q0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\System|HelpQualifiedRootDir",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows NT\\DCOM\\AppCompat|AllowLocalActivationSecurityCheckExemptionList",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1py",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\PCHealth\\ErrorReporting\\DW|DWNoExternalURL",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1px",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\PCHealth\\ErrorReporting\\DW|DWNoFileCollection",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\PCHealth\\ErrorReporting\\DW|DWNoSecondLevelCollection",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\PCHealth\\ErrorReporting|ForceQueueMode",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pu",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\PCHealth\\ErrorReporting\\DW|DWFileTreeRoot",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pt",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\PCHealth\\ErrorReporting\\DW|DWReporteeName",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ps",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\windows\\Group Policy\\{A2E30F80-D7DE-11d2-BBDE-00C04F86AE3B}|NoSlowLink",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pr",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{A2E30F80-D7DE-11d2-BBDE-00C04F86AE3B}|NoBackgroundPolicy",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{A2E30F80-D7DE-11d2-BBDE-00C04F86AE3B}|NoGPOListChanges",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pp",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\System|UserPolicyMode",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1po",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\PCHealth\\HelpSvc|Headlines",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pn",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\PCHealth\\HelpSvc|MicrosoftKBSearch",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pm",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\AppCompat|DisablePropPage",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pl",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\AppCompat|DisableWizard",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Task Scheduler5.0|Disable Advanced",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Task Scheduler5.0|Property Pages",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pi",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Task Scheduler5.0|Execution",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ph",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Task Scheduler5.0|Allow Browse",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pg",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Task Scheduler5.0|DragAndDrop",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Task Scheduler5.0|Task Creation",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pe",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Task Scheduler5.0|Task Deletion",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pd",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Installer|AlwaysInstallElevated",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Installer|TransformsSecure",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pb",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Installer|DisableUserInstalls",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1pa",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\WindowsMediaPlayer|DesktopShortcut",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1p9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\WindowsMediaPlayer|QuickLaunchShortcut",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1p8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\WindowsMovieMaker|MovieMaker",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1p7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU|ScheduledInstallDay",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1p6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU|ScheduledInstallTime",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1p5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU|NoAUAsDefaultShutdownOption",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1p4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU|RescheduleWaitTime",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1p3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings|ListBox_Support_ZoneMapKey",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1p2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMapKey|http://*.update.microsoft.com",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1p1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMapKey|http://*.windowsupdate.com",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1p0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMapKey|http://*.windowsupdate.microsoft.com",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1oz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMapKey|https://*.update.microsoft.com",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1oy",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap|ProxyByPass",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ox",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Template Policies|Internet",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ow",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Intranet Settings\\Template Policies|Intranet",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ov",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Local Machine Zone Settings\\Template Policies|Local Machine Zone",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ou",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Local Machine Zone Lockdown Settings\\Template Policies|Locked-Down Local Machine Zone",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ot",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Restricted Sites Settings\\Template Policies|Restricted Sites",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1os",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Trusted Sites Settings\\Template Policies|Trusted Sites",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1or",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EFS|LastGoodEfsConfiguration",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1oq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\ProtectedRoots|Flags",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1op",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\AutoEnrollment|AEPolicy",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1oo",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows NT\\Printers|DisableWebPrinting",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1on",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers|TransparentEnabled",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1om",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers|PolicyScope",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ol",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers|ExecutableTypes",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ok",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\TrustedPublisher\\Safer|AuthenticodeFlags",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1oj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers|DefaultLevel",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1oi",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\IcmpSettings|AllowInboundMaskRequest",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1oh",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\IcmpSettings|AllowInboundRouterRequest",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1og",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\IcmpSettings|AllowInboundTimestampRequest",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1of",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\IcmpSettings|AllowOutboundPacketTooBig",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1oe",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\IcmpSettings|AllowOutboundParameterProblem",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1od",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\IcmpSettings|AllowOutboundSourceQuench",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1oc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\IcmpSettings|AllowOutboundTimeExceeded",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ob",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\IcmpSettings|AllowRedirect",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1oa",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\IcmpSettings|AllowOutboundDestinationUnreachable",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1o9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM_CCS)\\Control\\Lsa\\MSV1_0|allownullsessionfallback",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1o8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM_CCS)\\Control\\Lsa\\pku2u|AllowOnlineID",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1o7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM_CCS)\\Control\\Lsa|UseMachineId",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1o6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service\\WinRS|AllowRemoteShellAccess",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1o5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Explorer|NoDataExecutionPrevention",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1o4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\HomeGroup|DisableHomeGroup",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1o3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU|NoAutoRebootWithLoggedOnUsers",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1o2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters|SMBServerNameHardeningLevel",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1o1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM_Services)\\Wlansvc|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1o0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Windows\\Sidebar|OverrideMoreGadgetsLink",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SYSTEM\\CurrentControlSet\\Services\\tcpip6\\Parameters|DisableComponents",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ny",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging|LogFilePath",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nx",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging|LogFilePath",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile|DefaultInboundAction",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile|DefaultOutboundAction",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nu",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile|DisableUnicastResponsesToMulticastBroadcast",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nt",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile|AllowLocalPolicyMerge",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ns",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile|AllowLocalIPsecPolicyMerge",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nr",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging|LogFileSize",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging|LogDroppedPackets",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1np",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging|LogSuccessfulConnections",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1no",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging|LogSuccessfulConnections",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nn",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging|LogDroppedPackets",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nm",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging|LogFileSize",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nl",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile|AllowLocalIPsecPolicyMerge",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile|AllowLocalPolicyMerge",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile|DisableUnicastResponsesToMulticastBroadcast",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ni",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile|DisableNotifications",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nh",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile|DefaultOutboundAction",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ng",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile|DefaultInboundAction",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile|AllowLocalIPsecPolicyMerge",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ne",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile|AllowLocalPolicyMerge",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nd",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile|DefaultOutboundAction",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile|DefaultInboundAction",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1nb",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile|EnableFirewall",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1na",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile|EnableFirewall",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m3",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1n9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Microsoft\\INetStp",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m2",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1n8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Classes\\APPid",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1n7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Microsoft\\Ole|LegacyAuthenticationLevel",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1n6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters|DisabledComponents",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1n5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU|NoAutoUpdate",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1n4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Windows\\Sidebar|TurnOffUserInstalledGadgets",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1n3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Windows\\Sidebar|TurnOffUnsignedGadgets",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1n2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Windows Collaboration|TurnOffWindowsCollaboration",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1n1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services|fDenyTSConnections",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1n0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\GameUX|DownloadGameInfo",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Digital Locker|DoNotRunDigitalLocker",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1my",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\HandwritingErrorReports|PreventHandwritingErrorReports",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mx",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings|DisableSendGenericDriverNotFoundToWER",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings|DisableSystemRestore",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings|AllowRemoteRPC",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mu",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Windows Search|AllowIndexingEncryptedStoresOrItems",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mt",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Windows Search|PreventIndexingUncachedExchangeFolders",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ms",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet|SpyNetReporting",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mr",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Windows Error Reporting|Disabled",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Windows Error Reporting|LoggingDisabled",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mp",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Windows Error Reporting|DontSendAdditionalData",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mo",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Explorer|NoHeapTerminationOnCorruption",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mn",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System|ReportControllerMissing",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mm",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows Mail|DisableCommunities",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ml",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows Mail|ManualLaunchAllowed",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Paths\\*|ItemData",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Access\\Security|Level",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mi",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Access\\Security|DontTrustInstalledFiles",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mh",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Common\\Security|AutomationSecurity",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m3",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mg",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Common|VbaOff",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Excel\\Security|Level",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1me",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Excel\\Security|AccessVBOM",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1md",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Excel\\Security|DontTrustInstalledFiles",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Outlook\\Security|Level",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1mb",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\PowerPoint\\Security|Level",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ma",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\PowerPoint\\Security|AccessVBOM",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1m9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\PowerPoint\\Security|DontTrustInstalledFiles",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1m8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Publisher\\Security|Level",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1m7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Publisher\\Security|DontTrustInstalledFiles",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1m6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Word\\Security|Level",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1m5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Word\\Security|AccessVBOM",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1m4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\11.0\\Word\\Security|DontTrustInstalledFiles",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m3",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1m3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Office\\12.0\\Common|VbaOff",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1m2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_BEHAVIORS|(Reserved)",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1m1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_BEHAVIORS|explorer.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1m0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_BEHAVIORS|iexplore.exe",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Network Connections|NC_StdDomainUserSetLocation",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ly",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition|Force_Tunneling",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lx",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition|6to4_State",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\IPHTTPS\\IPHTTPSInterface|IPHTTPS_ClientState",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\IPHTTPS\\IPHTTPSInterface|IPHTTPS_ClientUrl",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lu",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition|ISATAP_State",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lt",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition|Teredo_State",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ls",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\9D7815A6-7EE4-497E-8888-515A05F02364|DCSettingIndex",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lr",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\9D7815A6-7EE4-497E-8888-515A05F02364|ACSettingIndex",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy|DisableQueryRemoteServer",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lp",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy|EnableQueryRemoteServer",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lo",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}|ScenarioExecutionEnabled",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ln",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\AppCompat|DisableInventory",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lm",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer|NoAutorun",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ll",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\Explorer|NoAutoplayfornonVolume",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\Windows\\GameUX|GameUpdateOptions",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\WAU|Disabled",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1li",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\PCHealth\\ErrorReporting\\DW|DWAllowHeadless",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lh",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SYSTEM\\CurrentControlSet\\Services\\bthserv|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lg",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SYSTEM\\CurrentControlSet\\Services\\HomeGroupListener|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SYSTEM\\CurrentControlSet\\Services\\HomeGroupProvider|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1le",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SYSTEM\\CurrentControlSet\\Services\\WPCSvc|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ld",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SYSTEM\\CurrentControlSet\\Services\\W3Svc|DisplayName",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lc",
                        "recurseLevel": -1,
                        "severity": 0,
                        "target": "$(HKLM)\\SYSTEM\\CurrentControlSet\\Services\\tlntsvr",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m2",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1lb",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer|HonorAutorunSetting",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": false,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1la",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1l9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings|DisableSendRequestAdditionalSoftwareToWER",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1l8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion|CurrentBuildNumber",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1l7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\WindowsMediaPlayer|PreventCodecDownload",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1l6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy|fMinimizeConnections",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1l5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters|EnableIPAutoConfigurationLimits",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1l4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System|MaxDevicePasswordFailedAttempts",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1l3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy|fBlockNonDomain",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1l2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service|AllowUnencryptedTraffic",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1l1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service|DisableRunAs",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1l0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service|AllowBasic",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client|AllowDigest",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ky",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client|AllowUnencryptedTraffic",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kx",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client|AllowBasic",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsStore|RemoveWindowsStore",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsStore\\WindowsUpdate|AutoDownload",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ku",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds|AllowBasicAuthInClear",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kt",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LocationAndSensors|DisableLocation",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ks",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System|EnableSmartScreen",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kr",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings|SEHOP",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings|DEP",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kp",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults|IE",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ko",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings|ASLR",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kn",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI|DisablePasswordReveal",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1km",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Biometrics|Enabled",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kl",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Appx|AllowAllTrustedApps",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\AppCompat|DisablePcaUI",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services|ViewMessage",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ki",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services|ShareControlMessage",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kh",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E|DCSettingIndex",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kg",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System|AllowDomainPINLogon",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System|DisableLockScreenAppNotifications",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ke",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System|EnumerateLocalUsers",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kd",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System|DontEnumerateConnectedUsers",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Control Panel\\International|BlockUserInputMethodsForSignIn",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1kb",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer|NoUseStoreOpenWith",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ka",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch|DriverLoadPolicy",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1k9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DriverSearching|DriverServerSelection",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1k8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Servicing|UseWindowsUpdate",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1k7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint|NoWarningNoElevationOnInstall",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1k6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint|UpdatePromptSettings",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1k5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint|InForest",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1k4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|FDVHideRecoveryPage",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1k3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|FDVAllowUserCert",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1k2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0|AuditReceivingNTLMTraffic",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1k1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|FDVEnforceUserCert",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1k0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|FDVDiscoveryVolumeType",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|OSHardwareEncryption",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jy",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|RDVHardwareEncryption",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jx",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|RDVPassphrase",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|RDVRecoveryKey",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|RDVRecoveryPassword",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ju",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|RDVAllowSoftwareEncryptionFailover",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jt",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|RDVAllowedHardwareEncryptionAlgorithms",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1js",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|RDVRestrictHardwareEncryptionAlgorithms",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jr",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|RDVManageDRA",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|RDVRecovery",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jp",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|RDVRequireActiveDirectoryBackup",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jo",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|RDVActiveDirectoryInfoToStore",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jn",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|RDVActiveDirectoryBackup",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jm",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|RDVHideRecoveryPage",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jl",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|RDVAllowUserCert",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jk",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|RDVEnforceUserCert",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jj",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|RDVDenyCrossOrg",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ji",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|RDVDiscoveryVolumeType",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jh",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions|DenyDeviceClasses",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jg",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|OSPassphrase",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jf",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|OSRecoveryKey",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1je",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|OSRecoveryPassword",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jd",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|OSAllowSoftwareEncryptionFailover",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jc",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|OSAllowedHardwareEncryptionAlgorithms",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1jb",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|OSRestrictHardwareEncryptionAlgorithms",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ja",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|OSManageDRA",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1j9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|OSRecovery",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1j8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|OSRequireActiveDirectoryBackup",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1j7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|OSActiveDirectoryInfoToStore",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1j6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|OSActiveDirectoryBackup",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1j5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|OSHideRecoveryPage",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1j4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|UseAdvancedStartup",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1j3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|EnableBDEWithNoTPM",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1j2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|UseTPMKeyPIN",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1j1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|UseTPMPIN",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1j0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|UseTPM",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1iz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|UseTPMKey",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1iy",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|UseEnhancedPin",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ix",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|OSAllowSecureBootForIntegrity",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1iw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|MinimumPIN",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1iv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions|DenyDeviceClassesRetroactive",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1iu",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|FDVHardwareEncryption",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1it",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE|FDVPassphrase",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1is",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|FDVRecoveryKey",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ir",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|FDVRecoveryPassword",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1iq",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|FDVAllowSoftwareEncryptionFailover",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ip",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|FDVAllowedHardwareEncryptionAlgorithms",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1io",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|FDVRestrictHardwareEncryptionAlgorithms",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1in",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|FDVManageDRA",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1im",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|FDVRecovery",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1il",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|FDVRequireActiveDirectoryBackup",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ik",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|FDVActiveDirectoryInfoToStore",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ij",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|FDVActiveDirectoryBackup",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ii",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|EncryptionMethodNoDiffuser",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ih",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\abfc2519-3608-4c2a-94ea-171b0ed546ab|DCSettingIndex",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ig",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\Microsoft\\FVE|RDVDenyWriteAccess",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1if",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System|LocalAccountTokenFilterPolicy",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ie",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System|NoConnectedUser",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1id",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system|InactivityTimeoutSecs",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ic",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NtFrs|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ib",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters|Type",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1ia",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient|Enabled",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1i9",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE|EncryptionMethod",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1i8",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\sppsvc|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1i7",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Power|Start",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1i6",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\Software\\Policies\\Microsoft\\PCHealth\\ErrorReporting|IncludeKernelFaults",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1i5",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization|NoLockScreenSlideshow",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m2",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1i4",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system\\Audit|ProcessCreationIncludeCmdLine_Enabled",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1i3",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System|DontDisplayNetworkSelectionUI",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m2",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1i2",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system|MSAOptional",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m2",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1i1",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system|DisableAutomaticRestartSignOn",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1i0",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate|DoNotConnectToWindowsUpdateInternetLocations",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1hz",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization|NoLockScreenCamera",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1hy",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search|ConnectedSearchPrivacy",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1hx",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Skydrive|DisableFileSync",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m4",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1hw",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore|DisableOSUpgrade",
                        "type": "PersistentStartPoint"
                    },
                    {
                        "archiveContent": true,
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7m2",
                        "filterOnlyLeaves": false,
                        "id": "-1y2p0ij32e7pq:-1y2p0ij32c1hv",
                        "recurseLevel": 0,
                        "severity": 0,
                        "target": "$(HKLM)\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting|BypassDataThrottling",
                        "type": "PersistentStartPoint"
                    }
                ],
                "trackingId": "R0004166",
                "type": "Windows Registry Rule"
            },
            {
                "command": "(echo On Error Resume Next & echo strComputer = \".\" & echo vers = \"\" & echo Set oFSO = CreateObject(\"Scripting.FileSystemObject\"^) & echo Set WSHShell = WScript.CreateObject(\"WScript.Shell\"^) & echo Set RegExp = New RegExp & echo RegExp.IgnoreCase = True & echo RegExp.Global = True & echo isExist=0 & echo EMET_Dll = \"C:\\Windows\\AppPatch\\emet.dll\" & echo If oFSO.FileExists(EMET_Dll^) Then & echo vers = Mid(oFSO.GetFileVersion(EMET_Dll^),1,1^) & echo Else & echo WScript.Echo \"EMET is not installed.\" & echo WScript.Quit & echo End If & echo If (vers = \"3\"^) Then & echo bcdedit_command = \"C:\\Windows\\system32\\bcdedit.exe\" & echo If oFSO.FileExists(bcdedit_command^) Then & echo bcdedit_command = bcdedit_command & echo Else & echo WScript.Quit & echo End If & echo Set objWshScriptExec = WSHShell.Exec(bcdedit_command^) & echo Set objStdOut = objWshScriptExec.StdOut & echo While Not objStdOut.AtEndOfStream & echo strLine = objStdOut.ReadLine & echo RegExp.Pattern = \"^.*nx[\\ \\t]+(?:OptIn|AlwaysOff)\" & echo Set m = RegExp.Execute(strLine^) & echo If m.Count ^<^> 0 Then & echo isExist=1 & echo End If & echo Wend & echo If isExist=0 Then & echo WScript.Quit & echo Else & echo DEP_value = WSHShell.RegRead(\"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings\\DEP\"^) & echo If (DEP_value ^<^> \"1\"^) And (DEP_value ^<^> \"2\"^) Then & echo WScript.Echo \"DEP is not set to Application Opt Out or Always On.\" & echo End If & echo End If & echo ElseIf (vers = \"4\" or vers = \"5\"^) Then & echo Set objWMIService = GetObject(\"winmgmts:\" ^& \"{impersonationLevel=impersonate}!\\\\\" ^& strComputer ^& \"\\root\\cimv2\"^) & echo Set colProcesses = objWMIService.ExecQuery(\"select * from win32_process where Caption='EMET_Agent.exe'\" ^) & echo EMET_Home = \"\" & echo For Each objProcess In colProcesses & echo EMET_Home = objProcess.ExecutablePath & echo Next & echo EMET_Home= Replace(EMET_Home, Right(EMET_Home, 14^), \"\"^) & echo EMET_conf = EMET_Home ^& \"EMET_conf.exe\" & echo If oFSO.FileExists(EMET_conf^) Then & echo EMET_conf = EMET_conf & echo Else & echo WScript.Echo \"File \" ^& EMET_conf ^& \" does not exist.\" & echo WScript.Quit & echo End If & echo command= EMET_conf ^& \" --list_system\" & echo Set objWshScriptExec = WSHShell.Exec(command^) & echo Set objStdOut = objWshScriptExec.StdOut & echo While Not objStdOut.AtEndOfStream & echo strLine = objStdOut.ReadLine & echo RegExp.Pattern = \"^.*DEP:[\\ \\t]+(?:Application[\\ \\t]+Opt[\\ \\t]+In|Disabled)\" & echo Set m = RegExp.Execute(strLine^) & echo If m.Count ^<^> 0 Then & echo isExist=1 & echo End If & echo Wend & echo If isExist=0 Then & echo WScript.Quit & echo Else & echo DEP_value = WSHShell.RegRead(\"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings\\DEP\"^) & echo If (DEP_value ^<^> \"1\"^) And (DEP_value ^<^> \"2\"^) Then & echo WScript.Echo \"DEP is not set to Application Opt Out or Always On.\" & echo End If & echo End If & echo Else & echo WScript.Echo \"EMET version is not supported: \" ^& vers & echo WScript.Quit & echo End If) > %SystemRoot%\\Temp\\DEP.vbs & %SystemRoot%\\system32\\cscript /nologo %SystemRoot%\\Temp\\DEP.vbs & del %SystemRoot%\\Temp\\DEP.vbs",
                "elementName": "DEP Settings",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1hn",
                "importedTime": "2020-09-30T17:33:24.364Z",
                "modifiedTime": "2020-09-30T17:33:24.364Z",
                "name": "EMET - Data Execution Prevention (DEP) Settings",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0007566",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/cacls.exe \"%SystemRoot%\"\\inf\\usbstor.pnf",
                "elementName": "Permissions",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1hk",
                "importedTime": "2020-09-30T17:33:24.374Z",
                "modifiedTime": "2020-09-30T17:33:24.374Z",
                "name": "usbstor.pnf Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0004051",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow LicenseService",
                "elementName": "sc sdshow LicenseService",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1hh",
                "importedTime": "2020-09-30T17:33:24.383Z",
                "modifiedTime": "2020-09-30T17:33:24.383Z",
                "name": "LicenseService Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000039",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow Clipsrv",
                "elementName": "sc sdshow Clipsrv",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1he",
                "importedTime": "2020-09-30T17:33:24.392Z",
                "modifiedTime": "2020-09-30T17:33:24.392Z",
                "name": "Clipsrv Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000066",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "echo On Error Resume Next >\"$(TEMP_DIR)\"\\logFile.vbs & echo const HKEY_LOCAL_MACHINE = ^&H80000002 >> \"$(TEMP_DIR)\"\\logFile.vbs & echo strComputer = \".\"  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo Set objReg=GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\\"^& strComputer ^& \"\\root\\default:StdRegProv\")  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo strKeyPath = \"System\\CurrentControlSet\\Control\\LSA\"  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo strValueName = \"Notification Packages\"  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo Return = objReg.GetMultiStringValue(HKEY_LOCAL_MACHINE,strKeyPath,strValueName,arrValues)  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo If (Return = 0) And (Err.Number = 0) Then  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo  For Each strValue In arrValues  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo If (strValue=\"EnPasFltV2x86\") or (strValue=\"EnPasFltV2x64\") Then  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo    strValue1 = strValue  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo End If  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo  Next  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo Else  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo  Wscript.Echo \"GetMultiStringValue failed. Error = \" ^& Err.Number  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo End If  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo FilePath=\"%systemroot%\\system32\\\"+strValue1+\".dll\"  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo FilePath=\"dir \"+FilePath  >> \"$(TEMP_DIR)\"\\logFile.vbs & echo WScript.echo FilePath  >> \"$(TEMP_DIR)\"\\logFile.vbs & \"%SystemRoot%\"\\system32\\cscript /nologo \"$(TEMP_DIR)\"\\logFile.vbs > \"$(TEMP_DIR)\"\\logFile.bat & \"$(TEMP_DIR)\"\\logFile.bat & del \"$(TEMP_DIR)\"\\logFile.bat & del \"$(TEMP_DIR)\"\\logFile.vbs",
                "elementName": "Attribute of EnPasFltV2x86.dll or EnPasFltV2x64.dll File",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1hd",
                "importedTime": "2020-09-30T17:33:24.397Z",
                "modifiedTime": "2020-09-30T17:33:24.397Z",
                "name": "Check Attribute of EnPasFltV2x86.dll or EnPasFltV2x64.dll File",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0005673",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow TlntSvr",
                "elementName": "sc sdshow TlntSvr",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1ha",
                "importedTime": "2020-09-30T17:33:24.405Z",
                "modifiedTime": "2020-09-30T17:33:24.405Z",
                "name": "TlntSvr Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000059",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow W3SVC",
                "elementName": "sc sdshow W3SVC",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1h7",
                "importedTime": "2020-09-30T17:33:24.413Z",
                "modifiedTime": "2020-09-30T17:33:24.413Z",
                "name": "W3SVC Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000034",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%systemRoot%\\system32\\dism.exe /online /get-features /ScratchDir:\"$(TEMP_DIR)\"",
                "elementName": "Information of Features",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1h0",
                "importedTime": "2020-09-30T17:33:24.427Z",
                "modifiedTime": "2020-09-30T17:33:24.427Z",
                "name": "Get Information of Features",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0006848",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow WMServer",
                "elementName": "sc sdshow WMServer",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1gx",
                "importedTime": "2020-09-30T17:33:24.435Z",
                "modifiedTime": "2020-09-30T17:33:24.435Z",
                "name": "WMServer Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0004247",
                "type": "Command Output Capture Rule"
            },
            {
                "command": "%Windir%/system32/sc.exe sdshow TapiSrv",
                "elementName": "sc sdshow TapiSrv",
                "id": "-1y2p0ij32e7pw:-1y2p0ij32c1gw",
                "importedTime": "2020-09-30T17:33:24.441Z",
                "modifiedTime": "2020-09-30T17:33:24.441Z",
                "name": "TapiSrv Service Permissions",
                "severity": 0,
                "timeoutMillis": 1800000,
                "trackingId": "R0000060",
                "type": "Command Output Capture Rule"
            },
            {
                "id": "-1y2p0ij32e7pm:-1y2p0ij32c1gt",
                "importedTime": "2020-09-30T17:33:24.454Z",
                "modifiedTime": "2020-09-30T17:33:24.454Z",
                "name": "Local Machine RSoP",
                "startPoints": [
                    {
                        "criteriaId": "-1y2p0ij32e7ps:-1y2p0ij32e7ly",
                        "id": "-1y2p0ij32e7pk:-1y2p0ij32c1gs",
                        "scope": "computer",
                        "severity": 0,
                        "target": "",
                        "type": "RsopPersistentStartPoint"
                    }
                ],
                "trackingId": "R0000047",
                "type": "Windows RSoP Rule"
            }
        ]
    }
}
```

#### Human Readable Output

>### Tripwire Rules list results
>The number of returned results is: 50
>|name|id|severity|elementName|type|command|importedTime|modifiedTime|
>|---|---|---|---|---|---|---|---|
>| Fax Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c200 | 0 | sc sdshow Fax | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow Fax | 2020-09-30T17:33:23.330Z | 2020-09-30T17:33:23.330Z |
>| EMET Version | -1y2p0ij32e7pw:-1y2p0ij32c1zz | 0 | EMET Version | Command Output Capture Rule | (echo Set oFSO = CreateObject("Scripting.FileSystemObject"^) & echo EMET_Dll = "%SystemRooT%\AppPatch\emet.dll" & echo If oFSO.FileExists(EMET_Dll^) then & echo WScript.Echo oFSO.GetFileVersion(EMET_Dll^) & echo Else & echo WScript.Echo "EMET Is Not Installed" & echo End If) > "$(TEMP_DIR)"\EMET_Version.vbs & %SystemRoot%\system32\cscript /nologo "$(TEMP_DIR)"\EMET_Version.vbs & del "$(TEMP_DIR)"\EMET_Version.vbs | 2020-09-30T17:33:23.344Z | 2020-09-30T17:33:23.344Z |
>| RasAuto Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1zy | 0 | sc sdshow RasAuto | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow RasAuto | 2020-09-30T17:33:23.350Z | 2020-09-30T17:33:23.350Z |
>| Get the List of App Packages | -1y2p0ij32e7pw:-1y2p0ij32c1zv | 0 | List of App Packages | Command Output Capture Rule | %systemRoot%\system32\dism.exe /online /Get-ProvisionedAppxPackages /ScratchDir:"$(TEMP_DIR)" | 2020-09-30T17:33:23.360Z | 2020-09-30T17:33:23.360Z |
>| EMET Default Protections for Popular Software | -1y2p0ij32e7pw:-1y2p0ij32c1zu | 0 | EMET Default Protections for Popular Software | Command Output Capture Rule | (echo Const HKEY_LOCAL_MACHINE = ^&H80000002 & echo strComputer = "." & echo vers = "" & echo Set oFSO = CreateObject("Scripting.FileSystemObject"^) & echo EMET_Dll = "C:\Windows\AppPatch\emet.dll" & echo If oFSO.FileExists(EMET_Dll^) then & echo vers = Mid(oFSO.GetFileVersion(EMET_Dll^),1,1^) & echo Else & echo WScript.Echo "EMET is not installed." & echo Wscript.Quit & echo End If & echo Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" ^& strComputer ^& "\root\default:StdRegProv"^) & echo strKeyPath = "Software\Policies\Microsoft\EMET\Defaults" & echo strRegKeyPath = "SOFTWARE\Microsoft\EMET" & echo oReg.EnumValues HKEY_LOCAL_MACHINE,strKeyPath,arrValueNames,arrValueTypes & echo oReg.EnumKey HKEY_LOCAL_MACHINE, strRegKeyPath, arrRegistryValueNames & echo If (vers = "3"^) Then & echo ValueNames=Array("7z","7zFM","7zGUI","Chrome","Firefox","FirefoxPluginContainer","GoogleTalk","iTunes","Java","Javaw","Javaws","LiveMessenger","LiveSync","LiveWriter","Lync","mIRC","MOE","Opera","PhotoshopCS2","PhotoshopCS264","PhotoshopCS3","PhotoshopCS364","PhotoshopCS4","PhotoshopCS464","PhotoshopCS5","PhotoshopCS51","PhotoshopCS5164","PhotoshopCS564","Pidgin","QuickTimePlayer","RealConverter","RealPlayer","Safari","Skype","Thunderbird","ThunderbirdPluginContainer","UnRAR","VLC","Winamp","WindowsLiveSync","WindowsMediaPlayer","WinRARConsole","WinRARGUI","Winzip","Winzip64"^) & echo RegistryValueNames=Array("7z.exe","7zfm.exe","7zg.exe","chrome.exe","firefox.exe","plugin-container.exe","googletalk.exe","itunes.exe","java.exe","javaw.exe","javaws.exe","msnmsgr.exe","WLSync.exe","windowslivewriter.exe","communicator.exe","mirc.exe","MOE.exe","opera.exe","Photoshop.exe","pidgin.exe","QuickTimePlayer.exe","realconverter.exe","realplay.exe","Safari.exe","Skype.exe","thunderbird.exe","plugin-container.exe","unrar.exe","vlc.exe","winamp.exe","WindowsLiveSync.exe","wmplayer.exe","rar.exe","winrar.exe","winzip32.exe","winzip64.exe"^) & echo IsAppFound = checkSoftware(arrRegistryValueNames, RegistryValueNames^) & echo If (IsAppFound = "1"^) or (IsAppFound = ""^) Then & echo IsAppGPOFound = checkSoftware(arrValueNames, ValueNames^) & echo If IsAppGPOFound ^<^> "0" Then & echo WScript.Echo "Default Protections for other Popular Software is not configured." & echo End If & echo End if & echo Elseif (vers = "4"^) Then & echo ValueNames=Array("7z","7zFM","7zGUI","Chrome","Firefox","FirefoxPluginContainer","FoxitReader","GoogleTalk","iTunes","LiveWriter","LyncCommunicator","mIRC","Opera","PhotoGallery","Photoshop","Pidgin","QuickTimePlayer","RealConverter","RealPlayer","Safari","SkyDrive","Skype","Thunderbird","ThunderbirdPluginContainer","UnRAR","VLC","Winamp","WindowsLiveMail","WindowsMediaPlayer","WinRARConsole","WinRARGUI","Winzip","Winzip64"^) & echo RegistryValueNames=Array("7z.exe","7zfm.exe","7zg.exe","chrome.exe","firefox.exe","plugin-container.exe","foxit reader.exe","googletalk.exe","itunes.exe","windowslivewriter.exe","communicator.exe","mirc.exe","opera.exe","WLXPhotoGallery.exe","Photoshop.exe","pidgin.exe","QuickTimePlayer.exe","realconverter.exe","realplay.exe","Safari.exe","SkyDrive.exe","Skype.exe","thunderbird.exe","plugin-container.exe","unrar.exe","vlc.exe","winamp.exe","wlmail.exe","wmplayer.exe","rar.exe","winrar.exe","winzip32.exe","winzip64.exe"^) & echo IsAppFound = checkSoftware(arrRegistryValueNames, RegistryValueNames^) & echo If (IsAppFound = "1"^) or (IsAppFound = ""^) Then & echo IsAppGPOFound = checkSoftware(arrValueNames, ValueNames^) & echo If IsAppGPOFound ^<^> "0" Then & echo WScript.Echo "Default Protections for other Popular Software is not configured." & echo End If & echo End if & echo Elseif (vers = "5"^) Then & echo ValueNames=Array("7z","7zFM","7zGUI","Chrome","Firefox","FirefoxPluginContainer","FoxitReader","GoogleTalk","iTunes","LiveWriter","LyncCommunicator","mIRC","Opera","Opera_New_Versions","PhotoGallery","Photoshop","Pidgin","QuickTimePlayer","RealConverter","RealPlayer","Safari","SkyDrive","Skype","Thunderbird","ThunderbirdPluginContainer","UnRAR","VLC","Winamp","WindowsLiveMail","WindowsMediaPlayer","WinRARConsole","WinRARGUI","Winzip","Winzip64"^) & echo RegistryValueNames=Array("7z.exe","7zfm.exe","7zg.exe","chrome.exe","firefox.exe","plugin-container.exe","foxit reader.exe","googletalk.exe","itunes.exe","windowslivewriter.exe","communicator.exe","mirc.exe","opera.exe","opera.exe","WLXPhotoGallery.exe","Photoshop.exe","pidgin.exe","QuickTimePlayer.exe","realconverter.exe","realplay.exe","Safari.exe","SkyDrive.exe","Skype.exe","thunderbird.exe","plugin-container.exe","unrar.exe","vlc.exe","winamp.exe","wlmail.exe","wmplayer.exe","rar.exe","winrar.exe","winzip32.exe","winzip64.exe"^) & echo IsAppFound = checkSoftware(arrRegistryValueNames, RegistryValueNames^) & echo If (IsAppFound = "1"^) or (IsAppFound = ""^) Then & echo IsAppGPOFound = checkSoftware(arrValueNames, ValueNames^) & echo If IsAppGPOFound ^<^> "0" Then & echo WScript.Echo "Default Protections for other Popular Software is not configured." & echo End If & echo End if & echo Else & echo Wscript.Echo "EMET version is not supported: " ^& vers & echo Wscript.Quit & echo End If & echo Function checkSoftware(arrValueNames, ValueNames^) & echo Dim isFound & echo If Not IsNull(arrValueNames^) Then & echo isDiff = 0 & echo For i = 0 To UBound(ValueNames^) & echo isFound = False & echo For j = 0 To UBound(arrValueNames^) & echo If Ucase(ValueNames(i^)^) = Ucase(arrValueNames(j^)^) Then & echo isFound = True & echo End If & echo Next & echo If Not isFound Then & echo isDiff = 1 & echo End If & echo Next & echo End If & echo checkSoftware = isDiff & echo End Function) > %SystemRoot%\Temp\PopularSoftware.vbs & %SystemRoot%\system32\cscript /nologo %SystemRoot%\Temp\PopularSoftware.vbs & del %SystemRoot%\Temp\PopularSoftware.vbs | 2020-09-30T17:33:23.366Z | 2020-09-30T17:33:23.366Z |
>| TFTP Client Rule | -1y2p0ij32e7pw:-1y2p0ij32c1zr | 0 | TFTP Client | Command Output Capture Rule | echo On Error Resume Next > "$(TEMP_DIR)"\TFTPClient.vbs & echo set objFSO = createobject("Scripting.FileSystemObject") >> "$(TEMP_DIR)"\TFTPClient.vbs & echo if objFSO.FileExists("%windir%\system32\tftp.exe") then >> "$(TEMP_DIR)"\TFTPClient.vbs & echo wscript.echo "echo TFTP Client Exists" >> "$(TEMP_DIR)"\TFTPClient.vbs & echo else >> "$(TEMP_DIR)"\TFTPClient.vbs & echo wscript.echo "echo TFTP Client Does Not Exist" >> "$(TEMP_DIR)"\TFTPClient.vbs & echo end if >> "$(TEMP_DIR)"\TFTPClient.vbs & "%SystemRoot%"\system32\cscript /nologo "$(TEMP_DIR)"\TFTPClient.vbs > "$(TEMP_DIR)"\TFTPClient.bat & "$(TEMP_DIR)"\TFTPClient.bat & del "$(TEMP_DIR)"\TFTPClient.bat & del "$(TEMP_DIR)"\TFTPClient.vbs | 2020-09-30T17:33:23.374Z | 2020-09-30T17:33:23.374Z |
>| Power Users Group | -1y2p0ij32e7pw:-1y2p0ij32c1zq | 0 | Power Users Group | Command Output Capture Rule | net localgroup "Power Users" | 2020-09-30T17:33:23.381Z | 2020-09-30T17:33:23.381Z |
>| HTTPFilter Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1zn | 0 | sc sdshow HTTPFilter | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow HTTPFilter | 2020-09-30T17:33:23.398Z | 2020-09-30T17:33:23.398Z |
>| FrameworkService.exe Exist | -1y2p0ij32e7pw:-1y2p0ij32c1zk | 0 | FrameworkService.exe | Command Output Capture Rule | (echo On Error Resume Next & echo Set WSHShell = WScript.CreateObject("WScript.Shell"^) & echo Set objFSO = CreateObject("Scripting.FileSystemObject"^) & echo FilePath = WSHShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\McAfeeFramework\ImagePath"^) & echo If FilePath ^<^>"" Then & echo FilePath =Ucase(FilePath^) & echo FilePath = Mid(FilePath, InStr(FilePath,""""^),InStrRev(FilePath,""""^)^) & echo FilePath = replace(FilePath,"""", ""^) & echo If objFSO.FileExists(FilePath^) Then & echo Else & echo Wscript.Echo "File does not exist." & echo End If & echo Else & echo WScript.echo "File Not Found." & echo End if) > "$(TEMP_DIR)"\FrameworkService.vbs & %SystemRoot%\system32\cscript /nologo "$(TEMP_DIR)"\FrameworkService.vbs & del "$(TEMP_DIR)"\FrameworkService.vbs | 2020-09-30T17:33:23.428Z | 2020-09-30T17:33:23.428Z |
>| Verify Shared Folder Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1zh | 0 | Shared Folder Permission | Command Output Capture Rule | (echo Set oWMI = GetObject("winmgmts:"^) & echo Set oShares = oWMI.ExecQuery("select Name from Win32_Share where Type=0"^) & echo For Each oShare In oShares & echo Set oShareSecSetting = GetObject( _ & echo "winmgmts:Win32_LogicalShareSecuritySetting.Name='" ^& oShare.Name ^& "'"^) & echo WScript.Echo oShareSecSetting.Caption & echo iRC = oShareSecSetting.GetSecurityDescriptor(oSecurityDescriptor^) & echo aDACL = oSecurityDescriptor.DACL & echo For Each oAce In aDACL & echo Set oTrustee = oAce.Trustee & echo WScript.Echo "Trustee Name: " ^& oTrustee.Name & echo WScript.Echo & echo Next & echo Next) > "$(TEMP_DIR)"\SharedFolderPermission.vbs & %SystemRoot%\system32\cscript /nologo "$(TEMP_DIR)"\SharedFolderPermission.vbs & del "$(TEMP_DIR)"\SharedFolderPermission.vbs | 2020-09-30T17:33:23.440Z | 2020-09-30T17:33:23.440Z |
>| Check Windows Components | -1y2p0ij32e7pw:-1y2p0ij32c1ze | 0 | Check Windows Components | Command Output Capture Rule | (echo On Error Resume Next & echo strComputer = "." & echo Set oFSO = CreateObject("Scripting.FileSystemObject"^) & echo wnStoreExFile = "%SystemRoot%\WinStore\WinStore.UI.WinMD" & echo wnMediaExFile = "%SystemDrive%\Program Files\Windows Media Player\wmplayer.exe" & echo wnMediaExFileX86 = "%SystemDrive%\Program Files (x86)\Windows Media Player\wmplayer.exe" & echo AutoDownloadKey="HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore\WindowsUpdate\AutoDownload" & echo AutoDownloadRegValue="" & echo Set WSHShell = WScript.CreateObject("WScript.Shell"^) & echo AutoDownloadRegValue = WSHShell.RegRead(AutoDownloadKey^) & echo AutoDownloadRegValueTemp="" & echo If AutoDownloadRegValue ^<^> 2 then & echo AutoDownloadKey="HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore\AutoDownload" & echo AutoDownloadRegValueTemp = WSHShell.RegRead(AutoDownloadKey^) & echo if AutoDownloadRegValueTemp ^<^> "" then & echo AutoDownloadRegValue = AutoDownloadRegValueTemp & echo end if & echo End if & echo If oFSO.FileExists(wnStoreExFile^) then & echo RemoveWinStoreRegValue = WSHShell.RegRead("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore\RemoveWindowsStore"^) & echo WScript.Echo "AutoDownload "^&AutoDownloadRegValue & echo WScript.Echo "RemoveWindowsStore "^&RemoveWinStoreRegValue & echo Else & echo WScript.Echo "Windows Store Is Not Installed" & echo End If & echo If (oFSO.FileExists(wnMediaExFile^) Or oFSO.FileExists(wnMediaExFileX86^)^) then & echo regGroupPrivacyValue = WSHShell.RegRead("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer\GroupPrivacyAcceptance"^) & echo regAutoUpdateValue = WSHShell.RegRead("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer\DisableAutoUpdate"^) & echo WScript.Echo "GroupPrivacyAcceptance "^&regGroupPrivacyValue & echo WScript.Echo "DisableAutoUpdate "^&regAutoUpdateValue & echo Else & echo WScript.Echo "Windows Media Player Is Not Installed" & echo End If) > "$(TEMP_DIR)"\checkWindowsComponent.vbs & %SystemRoot%\system32\cscript /nologo "$(TEMP_DIR)"\checkWindowsComponent.vbs & del "$(TEMP_DIR)"\checkWindowsComponent.vbs | 2020-09-30T17:33:23.449Z | 2020-09-30T17:33:23.449Z |
>| Directory Server Data File Locations | -1y2p0ij32e7pw:-1y2p0ij32c1zb | 0 | Directory Server Data File Locations | Command Output Capture Rule | (echo On Error Resume Next & echo ExhangeRoot = "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" & echo regDSADatabaseFile = ExhangeRoot ^& "\DSA Database file" & echo regDatabaseLogFilesPath = ExhangeRoot ^& "\Database log files path" & echo regDSAWorkingDirectory = ExhangeRoot ^& "\DSA Working Directory" & echo Set WSHShell = WScript.CreateObject("WScript.Shell"^) & echo Set fso = CreateObject("Scripting.FileSystemObject"^) & echo DSADatabaseFile = WSHShell.RegRead(regDSADatabaseFile^) & echo DatabaseLogFilesPath = WSHShell.RegRead(regDatabaseLogFilesPath^) & echo DSAWorkingDirectory = WSHShell.RegRead(regDSAWorkingDirectory^) & echo Dim DTDSDisk(3^) & echo Set disk = fso.GetDrive(fso.GetDriveName(fso.GetAbsolutepathname(DSADatabaseFile^)^)^) & echo DTDSDisk(0^) = disk.DriveLetter & echo Set disk = fso.GetDrive(fso.GetDriveName(fso.GetAbsolutepathname(DatabaseLogFilesPath^)^)^) & echo DTDSDisk(1^) = disk.DriveLetter & echo Set disk = fso.GetDrive(fso.GetDriveName(fso.GetAbsolutepathname(DSAWorkingDirectory^)^)^) & echo DTDSDisk(2^) = disk.DriveLetter & echo strComputer = "." & echo Set objWMIService = GetObject("winmgmts:" _ & echo ^& "{impersonationLevel=impersonate}!\\" ^& strComputer ^& "\root\cimv2"^) & echo Set colShares = objWMIService.ExecQuery("Select * from Win32_Share"^) & echo For each objShare in colShares & echo If (objShare.Name ^<^> "NETLOGON" and objShare.Name ^<^> "SYSVOL" and right(objShare.Name,1^) ^<^> "$"^) then & echo Set fso = CreateObject("Scripting.FileSystemObject"^) & echo sharePath = Trim(objShare.Path^) & echo exists = fso.FolderExists(sharePath^) & echo if(exists^) Then & echo diskMatch = false & echo Set disk = fso.GetDrive(fso.GetDriveName(fso.GetAbsolutepathname(objShare.Path^)^)^) & echo For i = 0 to 2 & echo If (DTDSDisk(i^) = disk.DriveLetter^) Then & echo diskMatch = true & echo End if & echo Next & echo if (diskMatch^) then & echo Wscript.echo "sharePath:" ^& sharePath & echo Wscript.Echo "Name: " ^& objShare.Name & echo Wscript.Echo "Path: " ^& objShare.Path & echo end if & echo end if & echo End if & echo Next) > "$(TEMP_DIR)"\DirectoryServerDataFileLocations.vbs & %SystemRoot%\system32\cscript /nologo "$(TEMP_DIR)"\DirectoryServerDataFileLocations.vbs & del "$(TEMP_DIR)"\DirectoryServerDataFileLocations.vbs | 2020-09-30T17:33:23.461Z | 2020-09-30T17:33:23.461Z |
>| Check Global Object Access Auditing of the Registry | -1y2p0ij32e7pw:-1y2p0ij32c1za | 0 | Check Global Object Access Auditing of the Registry | Command Output Capture Rule | %WINDIR%\System32\Auditpol /resourceSACL /type:Key /view /user:everyone 2>NUL | 2020-09-30T17:33:23.465Z | 2020-09-30T17:33:23.465Z |
>| AppEvent Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1z7 | 0 | AppEvent | Command Output Capture Rule | echo On Error Resume Next >"$(TEMP_DIR)"\logFile.vbs & echo Set WSHShell = WScript.CreateObject("WScript.Shell") >>"$(TEMP_DIR)"\logFile.vbs & echo FilePath = WSHShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application\File") >>"$(TEMP_DIR)"\logFile.vbs & echo if FilePath ^<^>"" then >>"$(TEMP_DIR)"\logFile.vbs & echo FilePath="cacls "+ FilePath >>"$(TEMP_DIR)"\logFile.vbs & echo WScript.echo FilePath >>"$(TEMP_DIR)"\logFile.vbs & echo end if >>"$(TEMP_DIR)"\logFile.vbs & "%SystemRoot%"\system32\cscript /nologo "$(TEMP_DIR)"\logFile.vbs >"$(TEMP_DIR)"\logFile.bat & "$(TEMP_DIR)"\logFile.bat & del "$(TEMP_DIR)"\logFile.bat & del "$(TEMP_DIR)"\logFile.vbs | 2020-09-30T17:33:23.474Z | 2020-09-30T17:33:23.474Z |
>| Configure NTP Client | -1y2p0ij32e7pw:-1y2p0ij32c1z6 | 0 | Configure NTP Client | Command Output Capture Rule | echo On Error Resume Next >"$(TEMP_DIR)"\logFile.vbs & echo Set WSHShell = WScript.CreateObject("WScript.Shell") >>"$(TEMP_DIR)"\logFile.vbs & echo NTPServer = WSHShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\Parameters\NtpServer") >>"$(TEMP_DIR)"\logFile.vbs & echo NTPType = WSHShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\Parameters\Type") >>"$(TEMP_DIR)"\logFile.vbs & echo If (NTPType = "NTP") or (NTPType = "AllSync") Then >>"$(TEMP_DIR)"\logFile.vbs & echo NTPServer = Left(NTPServer, InStrRev(NTPServer, ",")-1) >>"$(TEMP_DIR)"\logFile.vbs & echo If NTPServer = "time.windows.com" Then >>"$(TEMP_DIR)"\logFile.vbs & echo WScript.echo "NTP Server " + NTPServer + ". This should configure to an authorized time server in http://tycho.usno.navy.mil/ntp.html" >>"$(TEMP_DIR)"\logFile.vbs & echo End IF >>"$(TEMP_DIR)"\logFile.vbs & echo End If >>"$(TEMP_DIR)"\logFile.vbs & "%SystemRoot%"\system32\cscript /nologo "$(TEMP_DIR)"\logFile.vbs & del "$(TEMP_DIR)"\logFile.vbs | 2020-09-30T17:33:23.480Z | 2020-09-30T17:33:23.480Z |
>| RemoteRegistry Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1z3 | 0 | sc sdshow RemoteRegistry | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow RemoteRegistry | 2020-09-30T17:33:23.490Z | 2020-09-30T17:33:23.490Z |
>| POP3Svc Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1z0 | 0 | sc sdshow POP3Svc | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow POP3Svc | 2020-09-30T17:33:23.514Z | 2020-09-30T17:33:23.514Z |
>| VSS Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1yv | 0 | sc sdshow VSS | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow VSS | 2020-09-30T17:33:23.525Z | 2020-09-30T17:33:23.525Z |
>| Certificate Property Information | -1y2p0ij32e7pw:-1y2p0ij32c1yt | 0 | Certificate Property | Command Output Capture Rule | $(WINDOWS_PS) "cd cert:\LocalMachine; Get-ChildItem -Recurse Cert: \| Format-List -Property PSParentPath, Subject, Thumbprint, Issuer" | 2020-09-30T17:33:23.537Z | 2020-09-30T17:33:23.537Z |
>| NWCWorkstation Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1yq | 0 | sc sdshow NWCWorkstation | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow NWCWorkstation | 2020-09-30T17:33:23.544Z | 2020-09-30T17:33:23.544Z |
>| Cybercrime Controls Anti-virus Status | -1y2p0ij32e7pw:-1y2p0ij32c1yn | 0 | Anti-virus Status | Command Output Capture Rule | (echo On Error Resume Next & echo strComputer = "." & echo isRunning = False & echo Incorrect = "" & echo Set oWMI = GetObject("winmgmts:{impersonationLevel=impersonate,authenticationLevel=Pkt}!\\" _ & echo     ^& strComputer ^& "\root\cimv2"^) & echo Set WShShell = WScript.CreateObject("WScript.Shell"^) & echo. & echo ' Determine processor of the machine & echo Set colSettings = oWMI.ExecQuery("SELECT * FROM Win32_Processor"^) & echo For Each objProcessor In colSettings & echo     If objProcessor.AddressWidth = 64 Then & echo         Pro6432="Wow6432node\" & echo     Else & echo         Pro6432="" & echo     End If & echo Next & echo. & echo ' Verify that McAfee anti-virus software is running correctly & echo Set McSrvs = oWMI.ExecQuery( "Select * From Win32_Service Where Name='mcshield'", , 48 ^) & echo For Each service in McSrvs & echo     If service.State = "Running" Then & echo         ' Determine if On Access Scan is enabled & echo         OAS = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\" ^& Pro6432 ^& _ & echo             "McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\OASEnabled"^) & echo         If (OAS = 3^) Then & echo             WScript.Echo "McAfee Anti-virus Software Is Running Correctly" & echo             isRunning = True & echo         else & echo             Incorrect = vbNewLine ^& vbtab ^& "On Access Scan Is Disabled" & echo         End If & echo     End If & echo Next & echo. & echo ' Verify that Sophos anti-virus software is running & echo Set SophosSrvs = oWMI.ExecQuery( "Select * From Win32_Service Where Name='SAVService'", , 48 ^) & echo. & echo For Each service in SophosSrvs & echo     If service.State = "Running" Then & echo         wscript.echo "Sophos Anti-virus Software Is Running" & echo         isRunning = True & echo     End If & echo Next & echo. & echo ' Verify that Symantec Endpoint Protection is running correctly & echo Set SepSrvs = oWMI.ExecQuery( "Select * From Win32_Service Where Name='SepMasterService'", , 48 ^) & echo. & echo ' Verify that Symantec Endpoint Protection service is running & echo For Each service in SepSrvs & echo     If service.State = "Running" Then & echo         ' Network Thread Protection & echo         NTP = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\Symantec\Symantec Endpoint Protection\SMC\smc_engine_status"^) & echo         ' Virus and Spyware Protection. It includes 3 functions: & echo         ' File System auto-protect and Download Insight & echo         ' Outlook auto-protect & echo         FSA_DI = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\" ^& Pro6432 ^& _ & echo             "Symantec\Symantec Endpoint Protection\AV\Storages\Filesystem\RealTimeScan\OnOff"^) & echo         OA = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\" ^& Pro6432 ^& _ & echo             "Symantec\Symantec Endpoint Protection\AV\Storages\MicrosoftExchangeClient\RealTimeScan\OnOff"^) & echo         If (( NTP And FSA_DI And OA^) = 1^) Then & echo             WScript.Echo "Symantec Endpoint Protection Anti-virus Software Is Running Correctly" & echo             isRunning = True & echo         Else & echo             if (NTP ^<^> 1^) Then & echo                 Incorrect = vbNewLine ^& vbtab ^& "Network Thread Protection Is Disabled" & echo             End If & echo             If ((FSA_DI And OA^) ^<^> 1^) Then & echo                 Incorrect = Incorrect ^& vbnewline ^& vbtab ^& "Virus and Spyware Protection Is Disabled" & echo             End If & echo         End If & echo     End If & echo Next & echo. & echo ' Verify that Trend ServerProtection anti-virus software is running & echo Set TrendSrvs = oWMI.ExecQuery( "Select * From Win32_Service Where Name='SpntSvc'", , 48 ^) & echo For Each service in TrendSrvs & echo     If service.State = "Running" Then & echo         wscript.echo "Trend ServerProtection Anti-virus Software Is Running" & echo         isRunning = True & echo     End If & echo Next & echo. & echo ' Verify that Kaspersky Endpoint Security software is running correctly  & echo ' (File Anti-Virus, Firewall, Network Attack Blocker are enabled^) & echo Set KESSrvs = oWMI.ExecQuery( "Select * From Win32_Service Where Name='AVP'", , 48 ^) & echo For Each service in KESSrvs & echo     If service.State = "Running" Then & echo         Set kesVer = "8" & echo         Const HKEY_LOCAL_MACHINE = ^&H80000002 & echo. & echo         Set objReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv"^) & echo. & echo         strKeyPath = "SOFTWARE\" ^& Pro6432 ^& "KasperskyLab\protected" & echo         objReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, arrSubKeys & echo. & echo         For Each Subkey in arrSubKeys & echo         if Instr(SubKey,"KES"^) ^<^> 0 Then & echo             kesVer = SubKey & echo         End If & echo         Next & echo         ' Check File Anti-Virus & echo         FileAV = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\" ^& Pro6432 ^& "KasperskyLab\protected\" ^& kesVer ^& "\profiles\Protection\profiles\File_Monitoring\enabled"^) & echo         ' Check Firewall & echo         FW = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\" ^& Pro6432 ^& "KasperskyLab\protected\" ^& kesVer ^& "\profiles\Protection\profiles\Firewall\enabled"^) & echo         ' Check Network Attack Blocker & echo         NAB = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\" ^& Pro6432 ^& "KasperskyLab\protected\" ^& kesVer ^& "\profiles\Protection\profiles\ids\enabled"^) & echo         If (( FileAV And FW And NAB^) = 1^) Then & echo             WScript.Echo "Kaspersky Endpoint Security Anti-virus Software Is Running Correctly" & echo             isRunning = True & echo         Else & echo             If (FileAV ^<^> 1^) Then & echo                 Incorrect = vbNewLine ^& vbtab ^& "File Anti-Virus Protection Is Disabled" & echo             End If & echo             If (FW ^<^> 1^) Then & echo                 Incorrect = Incorrect ^& vbnewline ^& vbtab ^& "Firewall Protection Is Disabled" & echo             End If & echo             If (NAB ^<^> 1^) Then & echo                 Incorrect = Incorrect ^& vbnewline ^& vbtab ^& "Network Attack Blocker Protection Is Disabled" & echo             End If & echo         End If & echo     End If & echo Next & echo. & echo ' Verify that Microsoft Forefront Endpoint Protection is running correctly & echo Set McMpSvc = oWMI.ExecQuery( "Select * From Win32_Service Where Name='MsMpSvc'", , 48 ^) & echo For Each service in McMpSvc & echo     If service.State = "Running" Then & echo          ' Determine if Real-time Protection is enabled & echo          RealTime = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Antimalware\Real-Time Protection\DisableRealtimeMonitoring"^) & echo          If (RealTime = 0^) Then & echo              WScript.Echo "Microsoft Forefront Endpoint Protection Anti-virus Software Is Running Correctly" & echo              isRunning = True & echo          else & echo               Incorrect = vbNewLine ^& vbtab ^& "Real-time Protection Is Disabled" & echo          End If & echo     End If & echo Next & echo. & echo ' Verify that TrendMicro OfficeScan anti-virus software is running & echo Set TrendOSSrvs = oWMI.ExecQuery( "Select * From Win32_Service Where Name='ntrtscan'", , 48 ^) & echo For Each service in TrendOSSrvs & echo     If service.State = "Running" Then & echo         wscript.echo "TrendMicro OfficeScan Anti-virus Software Is Running" & echo         isRunning = True & echo     End If & echo Next  & echo.  & echo If (Not isRunning^) Then & echo     WScript.Echo "Anti-virus Software Is Not Running or Its Functions Are Not Running Correctly" ^& Incorrect & echo     WScript.Quit(-1^) & echo End If & echo WScript.Quit(0^)) > "$(TEMP_DIR)"\AVStatus.vbs & %SystemRoot%\system32\cscript /nologo "$(TEMP_DIR)"\AVStatus.vbs & del "$(TEMP_DIR)"\AVStatus.vbs | 2020-09-30T17:33:23.553Z | 2020-09-30T17:33:23.553Z |
>| POSIX Subsystem File Components  | -1y2p0ij32e7pw:-1y2p0ij32c1yk | 0 | POSIX Subsystem File | Command Output Capture Rule | cd "%SystemRoot%" & dir /b/s POSIX.EXE PSXSS.EXE PSXDLL.DLL | 2020-09-30T17:33:23.565Z | 2020-09-30T17:33:23.565Z |
>| AppMgr Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1yh | 0 | sc sdshow AppMgr | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow AppMgr | 2020-09-30T17:33:23.574Z | 2020-09-30T17:33:23.574Z |
>| Spooler Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1ye | 0 | sc sdshow Spooler | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow Spooler | 2020-09-30T17:33:23.584Z | 2020-09-30T17:33:23.584Z |
>| MSFtpsvc Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1yb | 0 | sc sdshow MSFtpsvc | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow MSFtpsvc | 2020-09-30T17:33:23.591Z | 2020-09-30T17:33:23.591Z |
>| Cybercrime Controls Anti-virus Update | -1y2p0ij32e7pw:-1y2p0ij32c1y8 | 0 | Anti-virus Update | Command Output Capture Rule | (echo On Error Resume Next & echo isInstalled = False & echo. & echo Set WShShell = WScript.CreateObject("WScript.Shell"^) & echo Set oWMI = GetObject("winmgmts:{impersonationLevel=impersonate,authenticationLevel=Pkt}!\\.\root\cimv2"^) & echo ' Determine processor of the machine & echo Set colSettings = oWMI.ExecQuery("SELECT * FROM Win32_Processor"^) & echo For Each objProcessor In colSettings & echo If objProcessor.AddressWidth = 64 Then & echo Pro6432="Wow6432node\" & echo Else & echo Pro6432="" & echo End If & echo Next & echo. & echo ' Verify that McAfee Software is up to date & echo AVDatDate = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\" ^& Pro6432 ^& "McAfee\AvEngine\AVDatDate"^) & echo If Err.number = 0 Then & echo AVDatDateDiff = DateDiff("d",AVDatDate, Date^) & echo If AVDatDateDiff ^> 2 Then & echo WScript.Echo "McAfee Anti-virus Software Is Not up to Date" & echo Else & echo WScript.Echo "McAfee Anti-virus Software Is up to Date" & echo End If & echo isInstalled = True & echo End If & echo Err.Clear & echo. & echo ' Verify that Sophos Software is up to date & echo AVDef = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\" ^& Pro6432 ^& "Sophos\AutoUpdate\UpdateStatus\LastUpdateTime"^) & echo If Err.number = 0 Then & echo AVDef = FormatDateTime(DateAdd("s",AVDef,"01/01/1970 00:00:00"^),2^) & echo AVDateDiff = DateDiff("d",AVDef, Date^) & echo If AVDateDiff ^> 2 Then & echo WScript.Echo "Sophos Anti-virus Software Is Not up to Date" & echo Else & echo WScript.Echo "Sophos Anti-virus Software Is up to Date" & echo End If & echo isInstalled = True & echo End If & echo Err.Clear & echo. & echo ' Verify that Symantec Endpoint Protection Software is up to date & echo AVDef = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\" ^& Pro6432 ^& _ & echo "Symantec\Symantec Endpoint Protection\CurrentVersion\SharedDefs\DEFWATCH_10"^) & echo. & echo If Err.number = 0 Then & echo ArrAVDef = Split(AVDef,"\"^) & echo AVDef = ArrAVDef(UBound(ArrAVDef^)^) & echo YearDef = Left(AVDef, 4^) & echo MonthDef = Mid(AVDef, 5, 2^) & echo DayDef = Mid(AVDef, 7, 2^) & echo AVDateDiff = DateDiff("d",MonthDef ^& "/" ^& DayDef ^& "/" ^& YearDef, Date^) & echo If AVDateDiff ^> 2 Then & echo WScript.Echo "Symantec Endpoint Protection Anti-virus Software Is Not up to Date" & echo Else & echo WScript.Echo "Symantec Endpoint Protection Anti-virus Software Is up to Date" & echo End If & echo isInstalled = True & echo End If & echo Err.Clear & echo.  & echo ' Verify that Trend ServerProtection Software is up to date & echo AVHome = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\" ^& Pro6432 ^& _ & echo "TrendMicro\ServerProtect\CurrentVersion\HomeDirectory"^) & echo If Err.number = 0 Then & echo Set fso = CreateObject("Scripting.FileSystemObject"^) & echo If (Pro6432 ^<^> ""^) then & echo AVHome=AVHome ^& "\x64" & echo End if & echo Set AVHomeF = fso.GetFolder(AVHome^) & echo Set AVFiles = AVHomeF.Files & echo Version = 0 & echo AVDef = "1/1/1970 0:00:00" & echo For each avFile In AVFiles & echo FileName = avFile.Name & echo If (InStr(FileName,"lpt$vpn."^) = 1^) Then & echo If (Mid(FileName, InStr(FileName,"."^)+1^) ^> Version^) Then & echo AVDef = avFile.DateCreated & echo Version = Mid(FileName, InStr(FileName,"."^)+1^) & echo End If & echo End If & echo Next & echo AVDateDiff= DateDiff("d",AVDef,Date^) & echo If AVDateDiff ^> 2 Then & echo WScript.Echo "Trend Micro ServerProtection Anti-virus Software Is Not up to Date" & echo Else & echo WScript.Echo "Trend Micro ServerProtection Anti-virus Software Is up to Date" & echo End If & echo isInstalled = True & echo End If & echo Err.Clear & echo. & echo ' Verify that Kaspersky Endpoint Security Software is up to date & echo Const HKEY_LOCAL_MACHINE = ^&H80000002 & echo Set kesVer = "8" & echo Set objReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv"^) & echo strKeyPath = "SOFTWARE\" ^& Pro6432 ^& "KasperskyLab\protected" & echo objReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, arrSubKeys & echo For Each strSubKey in arrSubKeys & echo if Instr(strSubKey,"KES"^) ^<^> 0 Then & echo kesVer = strSubKey & echo End If & echo Next & echo isUpdate = False & echo Set oReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv"^) & echo oReg.EnumKey HKEY_LOCAL_MACHINE,"SOFTWARE\" ^& Pro6432 ^& "KasperskyLab\protected\" ^& kesVer ^& "\profiles", arrSubKeys & echo. & echo For Each strSubkey In arrSubKeys & echo If (InStr(strSubKey,"Updater"^) ^> 0^) Then & echo keyName="HKEY_LOCAL_MACHINE\SOFTWARE\" ^& Pro6432 ^& "KasperskyLab\protected\" ^& kesVer ^& "\profiles\" ^& strSubkey ^& "\schedule\LastRunTime" & echo AVDef = Wshshell.RegRead(keyname^) & echo If Err.number = 0 Then & echo AVDef = FormatDateTime(DateAdd("s",AVDef,"01/01/1970 00:00:00"^),2^) & echo AVDateDiff = DateDiff("d",AVDef, Date^) & echo If AVDateDiff ^<= 2 Then & echo isUpdate = True & echo End If & echo End If & echo Err.Clear         & echo End If        & echo Next & echo If (Not IsNull(arrSubKeys^)^) Then & echo If isUpdate Then & echo WScript.Echo "Kaspersky Endpoint Security Anti-virus Software Is up to Date" & echo Else & echo WScript.Echo "Kaspersky Endpoint Security Anti-virus Software Is Not up to Date" & echo End If & echo isInstalled = True & echo End If & echo Err.Clear & echo. & echo ' Verify that Mircrosoft Forefront Endpoint Protection Software is up to date & echo Set AVService = oWMI.ExecQuery( "Select * From Win32_Service Where Name='MsMpSvc'", , 48^) & echo For Each service in AVService & echo oReg.GetBinaryValue HKEY_LOCAL_MACHINE, "SOFTWARE\Microsoft\Microsoft Antimalware\Signature Updates", "ASSignatureApplied", strRetVal & echo ASDef = BinaryToDate(strRetVal^) & echo ASDateDiff = 3 & echo AVDateDiff = 3 & echo ASDateDiff = DateDiff("d",ASDef, Date^) & echo oReg.GetBinaryValue HKEY_LOCAL_MACHINE, "SOFTWARE\Microsoft\Microsoft Antimalware\Signature Updates", "AVSignatureApplied", strRetVal & echo AVDef = BinaryToDate(strRetVal^) & echo AVDateDiff = DateDiff("d",AVDef, Date^) & echo.      & echo If (ASDateDiff ^> 2^) Or (AVDateDiff ^> 2^) Then & echo WScript.Echo "Microsoft Forefront Endpoint Protection Anti-virus Software Is Not up to Date" & echo else & echo WScript.Echo "Microsoft Forefront Endpoint Protection Anti-virus Software Is up to Date" & echo End if & echo isInstalled = True & echo Next & echo. & echo ' Verify that TrendMicro OfficeSan Software is up to date & echo Set AVService = oWMI.ExecQuery( "Select * From Win32_Service Where Name='ntrtscan'", , 48^) & echo For Each service in AVService & echo strRetVal = WSHShell.RegRead ("HKEY_LOCAL_MACHINE\SOFTWARE\" ^& Pro6432 ^& "\TrendMicro\PC-cillinNTCorp\CurrentVersion\Schedule Update\LastScheduleUpdate"^) & echo AVDateDiff = 172801 & echo strCurrentTime = (now(^) - #1/1/1970#^) * 86400 & echo AVDateDiff = strCurrentTime - strRetVal & echo If (AVDateDiff ^> 172800^) Then & echo WScript.Echo "TrendMicro OfficeScan Anti-virus Software Is Not up to Date" & echo else & echo WScript.Echo "TrendMicro OfficeScan Anti-virus Software Is up to Date" & echo End if & echo isInstalled = True & echo Next & echo. & echo ' Function BinaryToDate will covert a binary DATE_TIME structure into a variant date set & echo Function BinaryToDate(bArray^) & echo Dim Seconds, Days, dateTime & echo Set dateTime = CreateObject("WbemScripting.SWbemDateTime"^) & echo Seconds = bArray(7^)*(2^^56^) + bArray(6^)*(2^^48^) + bArray(5^)*(2^^40^) + bArray(4^)*(2^^32^) + bArray(3^)*(2^^24^) + bArray(2^)*(2^^16^) + bArray(1^)*(2^^8^) + bArray(0^) & echo Days = Seconds/(1E7*86400^) & echo dateTime.SetVarDate CDate(DateSerial(1601, 1, 1^) + Days^), false & echo BinaryToDate = dateTime.GetVarDate(^) & echo End Function & echo. & echo If (Not isInstalled^) Then & echo WScript.echo "Anti-virus Software Is Not Installed." & echo WScript.quit(-1^) & echo End If & echo WScript.Quit(0^)) > "$(TEMP_DIR)"\AVUpdate.vbs & %SystemRoot%\system32\cscript /nologo "$(TEMP_DIR)"\AVUpdate.vbs & del "$(TEMP_DIR)"\AVUpdate.vbs | 2020-09-30T17:33:23.599Z | 2020-09-30T17:33:23.599Z |
>| usbstor.inf Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1y7 | 0 | Permissions | Command Output Capture Rule | %Windir%/system32/cacls.exe "%SystemRoot%"\inf\usbstor.inf | 2020-09-30T17:33:23.606Z | 2020-09-30T17:33:23.606Z |
>| NtFrs Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1y4 | 0 | sc sdshow NtFrs | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow NtFrs | 2020-09-30T17:33:23.613Z | 2020-09-30T17:33:23.613Z |
>| Get the Configuration of Domain | -1y2p0ij32e7pw:-1y2p0ij32c1y1 | 0 | Get the Configuration of Domain | Command Output Capture Rule | (echo On Error resume next & echo strComputer = "." & echo isStandalone="true" & echo Set objWMIService = GetObject("winmgmts:\\" ^& strComputer ^& "\root\cimv2"^) & echo Set WshShell = CreateObject("Wscript.Shell"^) & echo ArrSubKeyName=Array("Software\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall","Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction","Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction","Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications","Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableUnicastResponsesToMulticastBroadcast","Software\Policies\Microsoft\WindowsFirewall\DomainProfile\AllowLocalPolicyMerge","Software\Policies\Microsoft\WindowsFirewall\DomainProfile\AllowLocalIPsecPolicyMerge","Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath","Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize","Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets","Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections","SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy"^) & echo Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_ComputerSystem"^) & echo For Each objItem In colItems & echo If (objItem.DomainRole ^<^> 0^) and (objItem.DomainRole ^<^> 2^) then & echo IsStandalone="false" & echo End if & echo Next & echo If (IsStandalone = "true"^) Then & echo Wscript.echo "Domain Role: Standalone" & echo Else & echo Wscript.echo "Domain Role: Member of domain" & echo End If & echo For Each subKeyName In ArrSubKeyName & echo keyName = "HKEY_LOCAL_MACHINE\" ^& subKeyName & echo Value= WshShell.RegRead(keyname^) & echo If (Err.Number ^<^> 0^) Then & echo wscript.echo keyName ^& ":" & echo err.Clear & echo Else & echo wscript.echo keyName ^& ":" ^& Value & echo End If & echo Next) > "$(TEMP_DIR)"\Hkey.vbs & %SystemRoot%\system32\cscript /nologo "$(TEMP_DIR)"\Hkey.vbs & del "$(TEMP_DIR)"\Hkey.vbs | 2020-09-30T17:33:23.633Z | 2020-09-30T17:33:23.633Z |
>| SRP - Unrestricted Security Level Rule | -1y2p0ij32e7pw:-1y2p0ij32c1xy | 0 | Unrestricted | Command Output Capture Rule | (%Windir%/system32/reg.exe query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths /s) \| (%Windir%/system32/find.exe /i "ItemData") | 2020-09-30T17:33:23.642Z | 2020-09-30T17:33:23.642Z |
>| SysEvent Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1xv | 0 | SysEvent | Command Output Capture Rule | echo On Error Resume Next >"$(TEMP_DIR)"\logFile.vbs & echo Set WSHShell = WScript.CreateObject("WScript.Shell") >>"$(TEMP_DIR)"\logFile.vbs & echo FilePath = WSHShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System\File") >>"$(TEMP_DIR)"\logFile.vbs & echo if FilePath ^<^>"" then >>"$(TEMP_DIR)"\logFile.vbs & echo FilePath="cacls "+ FilePath >>"$(TEMP_DIR)"\logFile.vbs & echo WScript.echo FilePath >>"$(TEMP_DIR)"\logFile.vbs & echo end if >>"$(TEMP_DIR)"\logFile.vbs & "%SystemRoot%"\system32\cscript /nologo "$(TEMP_DIR)"\logFile.vbs > "$(TEMP_DIR)"\logFile.bat & "$(TEMP_DIR)"\logFile.bat & del "$(TEMP_DIR)"\logFile.bat & del "$(TEMP_DIR)"\logFile.vbs | 2020-09-30T17:33:23.649Z | 2020-09-30T17:33:23.649Z |
>| Data File Access Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1xu | 0 | Data File Access Permissions | Command Output Capture Rule | (echo On Error Resume Next & echo CreateFolder_AppendData = ^&h000004:Delete = ^&h010000:DeleteSubfolders_Files = ^&h000040:TraverseFolder_ExecuteFile = ^&h000020:ReadAttributes = ^&h000080:ReadPermissions = ^&h020000:ListFolder_ReadData = ^&h000001:ReadExtendedAttributes = ^&h000008:Synchronize = ^&h100000:WriteAttributes = ^&h000100:ChangePermissions = ^&h040000:CreateFiles_WriteData = ^&h000002:WriteExtendedAttributes = ^&h000010:TakeOwnerShip = ^&h080000:GENERIC_ALL = ^&H10000000:GENERIC_READ = ^&H80000000:GENERIC_WRITE = ^&H40000000:GENERIC_EXECUTE = ^&H20000000:Err=0:LFileName="":Namepaths="":Isprinted=0:DatabaseLogFilesPaths="":DSAWorkingDirectories="":ExhangeRoot = "HKLM\System\CurrentControlSet\Services\NTDS\Parameters":regDSADatabaseFile = ExhangeRoot ^& "\DSA Database file":regDatabaseLogFilesPath = ExhangeRoot ^& "\Database log files path":regDSAWorkingDirectory = ExhangeRoot ^& "\DSA Working Directory" & echo Set WSHShell = WScript.CreateObject("WScript.Shell"^):DSADatabaseFile = WSHShell.RegRead(regDSADatabaseFile^):DatabaseLogFilesPath = WSHShell.RegRead(regDatabaseLogFilesPath^):DSAWorkingDirectory = WSHShell.RegRead(regDSAWorkingDirectory^) & echo If DSAWorkingDirectory ^<^> "" Then:DSAWorkingDirectories=ListFiles(DSAWorkingDirectory^):End If:If DatabaseLogFilesPath ^<^> "" Then:If lcase(trim(DatabaseLogFilesPath^)^) ^<^> lcase(trim(DSAWorkingDirectory^)^) Then:DatabaseLogFilesPaths=ListFiles(DatabaseLogFilesPath^):End If:End If:LFileName=ConcatFile(LFileName,DSADatabaseFile^):LFileName=ConcatFile(LFileName,DatabaseLogFilesPaths^):LFileName=ConcatFile(LFileName,DSAWorkingDirectories^) & echo If LFileName ^<^> "" Then & echo Name = Split(LFileName , ";"^) & echo for each Namepath in Name & echo if NamePath ^<^>"" then & echo Isprinted=0 & echo Set wmiFileSecSetting = GetObject("winmgmts:Win32_LogicalFileSecuritySetting.path=" ^& chr(39^) ^& Namepath ^& chr(39^)^):RetVal = wmiFileSecSetting.GetSecurityDescriptor(wmiSecurityDescriptor^):intControlFlags = wmiSecurityDescriptor.ControlFlags & echo If Err ^<^> 0 Then & echo Err=0 & echo Else & echo Set dicAllowDACL = CreateObject("Scripting.Dictionary"^):Set dicDenyDACL = CreateObject("Scripting.Dictionary"^):DACL = wmiSecurityDescriptor.DACL & echo If not isNUll (DACL^) then & echo For each wmiAce in DACL & echo intAccessMask = wmiAce.AccessMask:Set Trustee = wmiAce.Trustee:Account=Trustee.Domain ^& "\" ^& Trustee.Name & echo if wmiAce.AceType = 0 then & echo if dicAllowDACL.Exists(Account^) then:dicAllowDACL.Item(Account^) = dicAllowDACL.Item(Account^) OR intAccessMask:else:dicAllowDACL.add Account, intAccessMask:end if & echo else & echo if dicDenyDACL.Exists(Account^) then:dicDenyDACL.Item(Account^) = dicDenyDACL.Item(Account^) OR intAccessMask:else:dicDenyDACL.add Account, intAccessMask:end if & echo end if & echo Next & echo for each deny in dicDenyDACL.keys & echo if dicAllowDACL.Exists(deny^) then:dicAllowDACL.Item(deny^) = dicAllowDACL.Item(deny^) AND (dicDenyDACL.item(deny^) XOR ^&h1fffff^):end if & echo Next & echo If dicAllowDACL.Count ^> 0 Then & echo for each allow in dicAllowDACL.keys & echo StrPers="":UserAccount=lcase(allow^) & echo If (UserAccount ^<^> "builtin\administrators"^) and (UserAccount ^<^> "nt authority\system"^) then & echo If ((dicAllowDACL.item(allow^) And ^&h1f01ff^) ^<^> Synchronize^) And ((dicAllowDACL.item(allow^) And ^&h1f01ff^) ^<^> 0^) then & echo If dicAllowDACL.item(allow^) AND CreateFolder_AppendData Then:StrPers=StrPers ^& ", " ^& "CreateFolder_AppendData":End If & echo If dicAllowDACL.item(allow^) AND Delete Then:StrPers=StrPers ^& ", " ^& "Delete":End If & echo If dicAllowDACL.item(allow^) AND DeleteSubfolders_Files Then:StrPers=StrPers ^& ", " ^& "DeleteSubfolders_Files":End If & echo If dicAllowDACL.item(allow^) AND TraverseFolder_ExecuteFile Then:StrPers=StrPers ^& ", " ^& "TraverseFolder_ExecuteFile":End If & echo If dicAllowDACL.item(allow^) AND ReadAttributes Then:StrPers=StrPers ^& ", " ^& "ReadAttributes":End If & echo If dicAllowDACL.item(allow^) AND ReadPermissions Then:StrPers=StrPers ^& ", " ^& "ReadPermissions":End If & echo If dicAllowDACL.item(allow^) AND ListFolder_ReadData Then:StrPers=StrPers ^& ", " ^& "ListFolder_ReadData":End If & echo If dicAllowDACL.item(allow^) AND ReadExtendedAttributes Then:StrPers=StrPers ^& ", " ^& "ReadExtendedAttributes":End If & echo If dicAllowDACL.item(allow^) AND WriteAttributes Then:StrPers=StrPers ^& ", " ^& "WriteAttributes":End If & echo If dicAllowDACL.item(allow^) AND ChangePermissions Then:StrPers=StrPers ^& ", " ^& "ChangePermissions":End If & echo If dicAllowDACL.item(allow^) AND CreateFiles_WriteData Then:StrPers=StrPers ^& ", " ^& "CreateFiles_WriteData":End If & echo If dicAllowDACL.item(allow^) AND WriteExtendedAttributes Then:StrPers=StrPers ^& ", " ^& "WriteExtendedAttributes":End If & echo If dicAllowDACL.item(allow^) AND TakeOwnerShip Then:StrPers=StrPers ^& ", " ^& "TakeOwnerShip":End If & echo StrPers=Mid(StrPers,3^) & echo else & echo StrPers=GENERICALL(dicAllowDACL.item(allow^)^) & echo end if & echo If StrPers ^<^> "" Then:If Isprinted=0 Then:Isprinted=1:wscript.echo "Folder/File: " ^& Namepath:End If:wscript.echo vbTab ^& allow ^& ":" ^& StrPers:End If & echo End If & echo next & echo End If & echo end if & echo End If & echo End If & echo Next & echo End If & echo Function ConcatFile(Conc,FileA^):If FileA ^<^> "" Then:If Conc ^<^> "" Then:If InStr(Conc ^& ";",FileA ^& ";"^) =0 Then:Conc= Conc ^& ";" ^& FileA:End if:else:Conc= FileA:End If:End If:ConcatFile=Conc:End Function & echo Function ListFiles(Directory^) & echo DirPaths= "cmd /c dir /B /A:-d "+Directory+" & exit" : StrLs="":Directory=Replace(Directory,chr(34^),""^): Set objExecDir = WSHShell.Exec(DirPaths^):Do Until objExecDir.StdOut.AtEndOfStream:StrL = objExecDir.StdOut.ReadLine(^):StrL = trim(replace(StrL,vbtab," "^)^):If StrL ^<^> "" Then:If StrLs = "" Then:StrLs=Directory+"\"+StrL:Else:StrLs=StrLs+";"+Directory+"\"+StrL:End If:End If:Loop:ListFiles=StrLs: & echo End Function & echo Function GENERICALL(Perm^) & echo GENERICEXECUTE="TraverseFolder_ExecuteFile":GENERICREAD="ListFolder_ReadData, ReadAttributes, ReadExtendedAttributes, ReadPermissions":GENERICWRITE="CreateFiles_WriteData, CreateFolder_AppendData, WriteAttributes, WriteExtendedAttributes":GENERICALLs="CreateFolder_AppendData, Delete, DeleteSubfolders_Files, TraverseFolder_ExecuteFile, ReadAttributes, ReadPermissions, ListFolder_ReadData, ReadExtendedAttributes, WriteAttributes, ChangePermissions, CreateFiles_WriteData, WriteExtendedAttributes, TakeOwnerShip":StrPer="" & echo If Perm And GENERIC_ALL Then:StrPer=GENERICALLs:else:If Perm And GENERIC_EXECUTE then:StrPer=StrPer ^& ", " ^& GENERICEXECUTE:End If:If Perm And GENERIC_READ then:StrPer=StrPer ^& ", " ^& GENERICREAD:End If:If Perm And GENERIC_WRITE then:StrPer=StrPer ^& ", " ^& GENERICWRITE:End If:If left(StrPer,1^)="," Then:StrPer=Trim(Mid(StrPer,2^)^):End If:End If:GENERICALL=StrPer & echo End Function) > "$(TEMP_DIR)"\NTDSPers.vbs & %SystemRoot%\system32\cscript /nologo "$(TEMP_DIR)"\NTDSPers.vbs & del "$(TEMP_DIR)"\NTDSPers.vbs | 2020-09-30T17:33:23.653Z | 2020-09-30T17:33:23.653Z |
>| Check Configure Automatic Updates | -1y2p0ij32e7pw:-1y2p0ij32c1xr | 0 | Check Configure Automatic Updates | Command Output Capture Rule | echo option Explicit  > "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo On Error Resume Next  >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo Dim objShell >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo Dim NoAutoUpdate, WUServer >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo Dim NoAutoUpdateValue, WUServerValue, ProtocolHttp >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo NoAutoUpdate = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate" >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo WUServer = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\WUServer" >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo Set objShell = CreateObject("WScript.Shell") >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo NoAutoUpdateValue = objShell.RegRead(NoAutoUpdate) >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo if (NoAutoUpdateValue=0) then >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo   WUServerValue = objShell.RegRead(WUServer) >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo   WUServerValue=LTrim(WUServerValue) >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo  if (Len(WUServerValue)=0) then >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo    WScript.Echo "Value of WUServer registry is not configured." >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo  end if >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & echo end if >> "$(TEMP_DIR)"\NoAutoUpdate.vbs & %SystemRoot%\system32\cscript /nologo "$(TEMP_DIR)"\NoAutoUpdate.vbs & del "$(TEMP_DIR)"\NoAutoUpdate.vbs | 2020-09-30T17:33:23.667Z | 2020-09-30T17:33:23.667Z |
>| Checking boot.ini File Options | -1y2p0ij32e7pw:-1y2p0ij32c1xo | 0 | boot.ini options | Command Output Capture Rule | %Windir%/system32/bootcfg.exe | 2020-09-30T17:33:23.675Z | 2020-09-30T17:33:23.675Z |
>| Get Permissions of System Folder | -1y2p0ij32e7pw:-1y2p0ij32c1xn | 0 | Get Permissions of System Folder | Command Output Capture Rule | (echo On Error Resume Next & echo CreateFolder_AppendData = ^&h000004 & echo Delete = ^&h010000 & echo DeleleteSubfolders_Files = ^&h000040 & echo TraverseFolder_ExecuteFile = ^&h000020 & echo ReadAttributes = ^&h000080 & echo ReadPermissions = ^&h020000 & echo ListFolder_ReadData = ^&h000001 & echo ReadExtendedAttributes = ^&h000008 & echo Synchronize = ^&h100000 & echo WriteAttributes = ^&h000100 & echo ChangePermissions = ^&h040000 & echo CreateFiles_WriteData = ^&h000002 & echo WriteExtendedAttributes = ^&h000010 & echo TakeOwnerShip = ^&h080000 & echo OBJECT_INHERIT_ACE = 1 & echo CONTAINER_INHERIT_ACE = 2 & echo INHERIT_ONLY_ACE = 8 & echo GENERIC_ALL = ^&H10000000 & echo GENERIC_READ = ^&H80000000 & echo GENERIC_WRITE = ^&H40000000 & echo GENERIC_EXECUTE = ^&H20000000 & echo Set WSHShell = WScript.CreateObject("WScript.Shell"^) & echo SYSTEMDRIVE=lcase(WSHShell.expandenvironmentstrings("%SYSTEMDRIVE%"^)^) & echo NamePaths=SYSTEMDRIVE ^& "\\;" ^& SYSTEMDRIVE ^& "\\windows;" ^& SYSTEMDRIVE ^& "\\Program Files;" ^& SYSTEMDRIVE ^& "\\Program Files (x86)" & echo Name = Split(Namepaths , ";"^) & echo for each Namepath in Name & echo if NamePath ^<^>"" then & echo objectpath = "winmgmts:Win32_LogicalFileSecuritySetting.path='" ^& NamePath ^& "'" & echo Set wmiFileSecSetting = GetObject(objectpath^) & echo RetVal = wmiFileSecSetting.GetSecurityDescriptor(wmiSecurityDescriptor^) & echo intControlFlags = wmiSecurityDescriptor.ControlFlags & echo wscript.echo "Folder/File: " ^& Namepath & echo If Err ^<^> 0 Then & echo wscript.echo vbTab ^& "Folder/File does not exist." & echo Err=0 & echo Else & echo If intControlFlags AND 4096 Then & echo Set dicAllowDACL = CreateObject("Scripting.Dictionary"^) & echo DACL = wmiSecurityDescriptor.DACL & echo If not isNUll (DACL^) then & echo For each wmiAce in DACL & echo intAccessMask = wmiAce.AccessMask & echo Set Trustee = wmiAce.Trustee & echo Account=Trustee.Domain ^& "\" ^& Trustee.Name ^& ";" ^& wmiAce.AceFlags & echo if wmiAce.AceType = 0 then & echo if dicAllowDACL.Exists(Account^) then & echo dicAllowDACL.Item(Account^) = dicAllowDACL.Item(Account^) OR intAccessMask & echo else & echo dicAllowDACL.add Account, intAccessMask & echo end if & echo else & echo Isdeny=1 & echo end if & echo Next & echo If Isdeny=0 then & echo If dicAllowDACL.Count ^> 0 Then & echo for each allow in dicAllowDACL.keys & echo StrPermissions="" & echo If ((dicAllowDACL.item(allow^) And ^&h1f01ff^) ^<^> Synchronize^) And ((dicAllowDACL.item(allow^) And ^&h1f01ff^) ^<^> 0^) then & echo If dicAllowDACL.item(allow^) AND CreateFolder_AppendData Then & echo StrPermissions=StrPermissions ^& ", " ^& "CreateFolder_AppendData" & echo End If & echo If dicAllowDACL.item(allow^) AND Delete Then & echo StrPermissions=StrPermissions ^& ", " ^& "Delete" & echo End If & echo If dicAllowDACL.item(allow^) AND DeleteSubfolders_Files Then & echo StrPermissions=StrPermissions ^& ", " ^& "DeleteSubfolders_Files" & echo End If & echo If dicAllowDACL.item(allow^) AND TraverseFolder_ExecuteFile Then & echo StrPermissions=StrPermissions ^& ", " ^& "TraverseFolder_ExecuteFile" & echo End If & echo If dicAllowDACL.item(allow^) AND ReadAttributes Then & echo StrPermissions=StrPermissions ^& ", " ^& "ReadAttributes" & echo End If & echo If dicAllowDACL.item(allow^) AND ReadPermissions Then & echo StrPermissions=StrPermissions ^& ", " ^& "ReadPermissions" & echo End If & echo If dicAllowDACL.item(allow^) AND ListFolder_ReadData Then & echo StrPermissions=StrPermissions ^& ", " ^& "ListFolder_ReadData" & echo End If & echo If dicAllowDACL.item(allow^) AND ReadExtendedAttributes Then & echo StrPermissions=StrPermissions ^& ", " ^& "ReadExtendedAttributes" & echo End If & echo If dicAllowDACL.item(allow^) AND WriteAttributes Then & echo StrPermissions=StrPermissions ^& ", " ^& "WriteAttributes" & echo End If & echo If dicAllowDACL.item(allow^) AND ChangePermissions Then & echo StrPermissions=StrPermissions ^& ", " ^& "ChangePermissions" & echo End If & echo If dicAllowDACL.item(allow^) AND CreateFiles_WriteData Then & echo StrPermissions=StrPermissions ^& ", " ^& "CreateFiles_WriteData" & echo End If & echo If dicAllowDACL.item(allow^) AND WriteExtendedAttributes Then & echo StrPermissions=StrPermissions ^& ", " ^& "WriteExtendedAttributes" & echo End If & echo If dicAllowDACL.item(allow^) AND TakeOwnerShip Then & echo StrPermissions=StrPermissions ^& ", " ^& "TakeOwnerShip" & echo End If & echo accs=Split(allow,";"^) & echo acc=accs(0^) & echo intIN=accs(1^) & echo StrPermissions=Mid(StrPermissions,3^) & echo else & echo StrPermissions=GENERICALL(dicAllowDACL.item(allow^)^) & echo end if & echo accs=Split(allow,";"^) & echo acc=accs(0^) & echo intIN=accs(1^) & echo If StrPermissions ^<^> "" Then & echo StrPermissions=StrPermissions ^& ":" ^& PerApp(intIN^) & echo wscript.echo vbTab ^& acc ^& ":" ^& StrPermissions & echo End If & echo next & echo Else & echo WScript.Echo vbTab ^& "Does not exist Allow permissions." & echo End If & echo else & echo wscript.echo vbTab ^& Trustee.Domain ^& "With deny Permissions." & echo ENd if & echo else & echo wscript.echo vbtab ^& "No DACL present in security descriptor." & echo end if & echo else & echo wscript.echo vbtab ^& "["^&NamePath ^&"] includes inheritable permissions from this object's parent." & echo End if & echo End If & echo End If & echo Next & echo Function PerApp(intIN^) & echo If intIN And OBJECT_INHERIT_ACE Then & echo If intIN And CONTAINER_INHERIT_ACE Then & echo If intIN And INHERIT_ONLY_ACE Then & echo PerApp="SubfoldersAndFilesOnly" & echo Else & echo PerApp="ThisFolderSubfoldersAndFiles" & echo End If & echo Else & echo If intIN And INHERIT_ONLY_ACE Then & echo PerApp="FilesOnly" & echo Else & echo PerApp="ThisFolderAndFiles" & echo End If & echo End If & echo Else & echo If intIN And CONTAINER_INHERIT_ACE Then & echo If intIN And INHERIT_ONLY_ACE Then & echo PerApp="SubfoldersOnly" & echo Else & echo PerApp="ThisFolderAndSubfolders" & echo End If & echo Else & echo PerApp="ThisFolderOnly" & echo End If & echo End If & echo End Function & echo Function GENERICALL(Perm^) & echo GENERICEXECUTE="TraverseFolder_ExecuteFile" & echo GENERICREAD="ListFolder_ReadData, ReadAttributes, ReadExtendedAttributes, ReadPermissions" & echo GENERICWRITE="CreateFiles_WriteData, CreateFolder_AppendData, WriteAttributes, WriteExtendedAttributes" & echo GENERICALLs="CreateFolder_AppendData, Delete, DeleteSubfolders_Files, TraverseFolder_ExecuteFile, ReadAttributes, ReadPermissions, ListFolder_ReadData, ReadExtendedAttributes, WriteAttributes, ChangePermissions, CreateFiles_WriteData, WriteExtendedAttributes, TakeOwnerShip" & echo StrPer="" & echo If Perm And GENERIC_ALL Then & echo StrPer=GENERICALLs & echo else & echo If Perm And GENERIC_EXECUTE then & echo StrPer=StrPer ^& ", " ^& GENERICEXECUTE & echo End If & echo If Perm And GENERIC_READ then & echo StrPer=StrPer ^& ", " ^& GENERICREAD & echo End If & echo If Perm And GENERIC_WRITE then & echo StrPer=StrPer ^& ", " ^& GENERICWRITE & echo End If & echo If left(StrPer,1^)="," Then & echo StrPer=Trim(Mid(StrPer,2^)^) & echo End If & echo End If & echo GENERICALL=StrPer & echo End Function) > "$(TEMP_DIR)"\SystemPermissions.vbs & %SystemRoot%\system32\cscript /nologo "$(TEMP_DIR)"\SystemPermissions.vbs & del "$(TEMP_DIR)"\SystemPermissions.vbs | 2020-09-30T17:33:23.682Z | 2020-09-30T17:33:23.682Z |
>| Policy Test Files | -1y2p0ij32e7oz:-1y2p0ij32c1xi |  |  | Windows File System Rule |  | 2020-09-30T17:33:23.711Z | 2020-09-30T17:33:23.711Z |
>| Check Support_388945a0 Account | -1y2p0ij32e7pw:-1y2p0ij32c1re | 0 | Check Active Support_388945a0 Account | Command Output Capture Rule | %Windir%\system32\net.exe users Support_388945a0 \| %Windir%\system32\find.exe /i "Account active" | 2020-09-30T17:33:24.016Z | 2020-09-30T17:33:24.016Z |
>| Netman Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1rb | 0 | sc sdshow Netman | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow Netman | 2020-09-30T17:33:24.025Z | 2020-09-30T17:33:24.025Z |
>| Policy Registry Values Extension | -1y2p0ij32e7p7:-1y2p0ij32c1r8 |  |  | Windows Registry Rule |  | 2020-09-30T17:33:24.044Z | 2020-09-30T17:33:24.044Z |
>| EMET - Data Execution Prevention (DEP) Settings | -1y2p0ij32e7pw:-1y2p0ij32c1hn | 0 | DEP Settings | Command Output Capture Rule | (echo On Error Resume Next & echo strComputer = "." & echo vers = "" & echo Set oFSO = CreateObject("Scripting.FileSystemObject"^) & echo Set WSHShell = WScript.CreateObject("WScript.Shell"^) & echo Set RegExp = New RegExp & echo RegExp.IgnoreCase = True & echo RegExp.Global = True & echo isExist=0 & echo EMET_Dll = "C:\Windows\AppPatch\emet.dll" & echo If oFSO.FileExists(EMET_Dll^) Then & echo vers = Mid(oFSO.GetFileVersion(EMET_Dll^),1,1^) & echo Else & echo WScript.Echo "EMET is not installed." & echo WScript.Quit & echo End If & echo If (vers = "3"^) Then & echo bcdedit_command = "C:\Windows\system32\bcdedit.exe" & echo If oFSO.FileExists(bcdedit_command^) Then & echo bcdedit_command = bcdedit_command & echo Else & echo WScript.Quit & echo End If & echo Set objWshScriptExec = WSHShell.Exec(bcdedit_command^) & echo Set objStdOut = objWshScriptExec.StdOut & echo While Not objStdOut.AtEndOfStream & echo strLine = objStdOut.ReadLine & echo RegExp.Pattern = "^.*nx[\ \t]+(?:OptIn\|AlwaysOff)" & echo Set m = RegExp.Execute(strLine^) & echo If m.Count ^<^> 0 Then & echo isExist=1 & echo End If & echo Wend & echo If isExist=0 Then & echo WScript.Quit & echo Else & echo DEP_value = WSHShell.RegRead("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\SysSettings\DEP"^) & echo If (DEP_value ^<^> "1"^) And (DEP_value ^<^> "2"^) Then & echo WScript.Echo "DEP is not set to Application Opt Out or Always On." & echo End If & echo End If & echo ElseIf (vers = "4" or vers = "5"^) Then & echo Set objWMIService = GetObject("winmgmts:" ^& "{impersonationLevel=impersonate}!\\" ^& strComputer ^& "\root\cimv2"^) & echo Set colProcesses = objWMIService.ExecQuery("select * from win32_process where Caption='EMET_Agent.exe'" ^) & echo EMET_Home = "" & echo For Each objProcess In colProcesses & echo EMET_Home = objProcess.ExecutablePath & echo Next & echo EMET_Home= Replace(EMET_Home, Right(EMET_Home, 14^), ""^) & echo EMET_conf = EMET_Home ^& "EMET_conf.exe" & echo If oFSO.FileExists(EMET_conf^) Then & echo EMET_conf = EMET_conf & echo Else & echo WScript.Echo "File " ^& EMET_conf ^& " does not exist." & echo WScript.Quit & echo End If & echo command= EMET_conf ^& " --list_system" & echo Set objWshScriptExec = WSHShell.Exec(command^) & echo Set objStdOut = objWshScriptExec.StdOut & echo While Not objStdOut.AtEndOfStream & echo strLine = objStdOut.ReadLine & echo RegExp.Pattern = "^.*DEP:[\ \t]+(?:Application[\ \t]+Opt[\ \t]+In\|Disabled)" & echo Set m = RegExp.Execute(strLine^) & echo If m.Count ^<^> 0 Then & echo isExist=1 & echo End If & echo Wend & echo If isExist=0 Then & echo WScript.Quit & echo Else & echo DEP_value = WSHShell.RegRead("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\SysSettings\DEP"^) & echo If (DEP_value ^<^> "1"^) And (DEP_value ^<^> "2"^) Then & echo WScript.Echo "DEP is not set to Application Opt Out or Always On." & echo End If & echo End If & echo Else & echo WScript.Echo "EMET version is not supported: " ^& vers & echo WScript.Quit & echo End If) > %SystemRoot%\Temp\DEP.vbs & %SystemRoot%\system32\cscript /nologo %SystemRoot%\Temp\DEP.vbs & del %SystemRoot%\Temp\DEP.vbs | 2020-09-30T17:33:24.364Z | 2020-09-30T17:33:24.364Z |
>| usbstor.pnf Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1hk | 0 | Permissions | Command Output Capture Rule | %Windir%/system32/cacls.exe "%SystemRoot%"\inf\usbstor.pnf | 2020-09-30T17:33:24.374Z | 2020-09-30T17:33:24.374Z |
>| LicenseService Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1hh | 0 | sc sdshow LicenseService | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow LicenseService | 2020-09-30T17:33:24.383Z | 2020-09-30T17:33:24.383Z |
>| Clipsrv Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1he | 0 | sc sdshow Clipsrv | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow Clipsrv | 2020-09-30T17:33:24.392Z | 2020-09-30T17:33:24.392Z |
>| Check Attribute of EnPasFltV2x86.dll or EnPasFltV2x64.dll File | -1y2p0ij32e7pw:-1y2p0ij32c1hd | 0 | Attribute of EnPasFltV2x86.dll or EnPasFltV2x64.dll File | Command Output Capture Rule | echo On Error Resume Next >"$(TEMP_DIR)"\logFile.vbs & echo const HKEY_LOCAL_MACHINE = ^&H80000002 >> "$(TEMP_DIR)"\logFile.vbs & echo strComputer = "."  >> "$(TEMP_DIR)"\logFile.vbs & echo Set objReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\"^& strComputer ^& "\root\default:StdRegProv")  >> "$(TEMP_DIR)"\logFile.vbs & echo strKeyPath = "System\CurrentControlSet\Control\LSA"  >> "$(TEMP_DIR)"\logFile.vbs & echo strValueName = "Notification Packages"  >> "$(TEMP_DIR)"\logFile.vbs & echo Return = objReg.GetMultiStringValue(HKEY_LOCAL_MACHINE,strKeyPath,strValueName,arrValues)  >> "$(TEMP_DIR)"\logFile.vbs & echo If (Return = 0) And (Err.Number = 0) Then  >> "$(TEMP_DIR)"\logFile.vbs & echo  For Each strValue In arrValues  >> "$(TEMP_DIR)"\logFile.vbs & echo If (strValue="EnPasFltV2x86") or (strValue="EnPasFltV2x64") Then  >> "$(TEMP_DIR)"\logFile.vbs & echo    strValue1 = strValue  >> "$(TEMP_DIR)"\logFile.vbs & echo End If  >> "$(TEMP_DIR)"\logFile.vbs & echo  Next  >> "$(TEMP_DIR)"\logFile.vbs & echo Else  >> "$(TEMP_DIR)"\logFile.vbs & echo  Wscript.Echo "GetMultiStringValue failed. Error = " ^& Err.Number  >> "$(TEMP_DIR)"\logFile.vbs & echo End If  >> "$(TEMP_DIR)"\logFile.vbs & echo FilePath="%systemroot%\system32\"+strValue1+".dll"  >> "$(TEMP_DIR)"\logFile.vbs & echo FilePath="dir "+FilePath  >> "$(TEMP_DIR)"\logFile.vbs & echo WScript.echo FilePath  >> "$(TEMP_DIR)"\logFile.vbs & "%SystemRoot%"\system32\cscript /nologo "$(TEMP_DIR)"\logFile.vbs > "$(TEMP_DIR)"\logFile.bat & "$(TEMP_DIR)"\logFile.bat & del "$(TEMP_DIR)"\logFile.bat & del "$(TEMP_DIR)"\logFile.vbs | 2020-09-30T17:33:24.397Z | 2020-09-30T17:33:24.397Z |
>| TlntSvr Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1ha | 0 | sc sdshow TlntSvr | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow TlntSvr | 2020-09-30T17:33:24.405Z | 2020-09-30T17:33:24.405Z |
>| W3SVC Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1h7 | 0 | sc sdshow W3SVC | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow W3SVC | 2020-09-30T17:33:24.413Z | 2020-09-30T17:33:24.413Z |
>| Get Information of Features | -1y2p0ij32e7pw:-1y2p0ij32c1h0 | 0 | Information of Features | Command Output Capture Rule | %systemRoot%\system32\dism.exe /online /get-features /ScratchDir:"$(TEMP_DIR)" | 2020-09-30T17:33:24.427Z | 2020-09-30T17:33:24.427Z |
>| WMServer Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1gx | 0 | sc sdshow WMServer | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow WMServer | 2020-09-30T17:33:24.435Z | 2020-09-30T17:33:24.435Z |
>| TapiSrv Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1gw | 0 | sc sdshow TapiSrv | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow TapiSrv | 2020-09-30T17:33:24.441Z | 2020-09-30T17:33:24.441Z |
>| Local Machine RSoP | -1y2p0ij32e7pm:-1y2p0ij32c1gt |  |  | Windows RSoP Rule |  | 2020-09-30T17:33:24.454Z | 2020-09-30T17:33:24.454Z |


### tripwire-elements-list
***
Returns a list of all elements or those that match the provided criteria.


#### Base Command

`tripwire-elements-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| element_oids | Id of the element. comma seperated. | Optional | 
| element_names | Name of the element (case insensitive). comma seperated. | Optional | 
| node_oids | Id of the node for this element. comma seperated. | Optional | 
| rule_oids | Id of the rule for this element. comma seperated. | Optional | 
| baseline_version_ids | Latest baseline version Id for this element. comma seperated. | Optional | 
| last_version_id | Id for the latest version of this element. comma seperated. | Optional | 
| limit | Limit for the number of returned results. Default is 50. | Optional | 
| start | start index from which the results are returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tripwire.Elements.baselineVersionId | String | Latest baseline version Id for this element. | 
| Tripwire.Elements.description | String | Element description. | 
| Tripwire.Elements.id | String | Id of the element. | 
| Tripwire.Elements.inScope | Boolean | False if element is no longer in scope for the rule. | 
| Tripwire.Elements.isRestorable | Boolean | True if this can be restored by the restore action. | 
| Tripwire.Elements.lastSuccessDate | Date | Timestamp of last successful run of the rule on the related node. | 
| Tripwire.Elements.lastVersionChangeSeverity | Number | Severity value for the latest version of this element. | 
| Tripwire.Elements.lastVersionChangeType | String | Change type for the latest version of this element | 
| Tripwire.Elements.lastVersionId | String | Id for the latest version of this element. | 
| Tripwire.Elements.lastVersionTime | Date | Time detected of that latest version of this element. | 
| Tripwire.Elements.name | String | Name of the element. | 
| Tripwire.Elements.nodeId | String | Id of the node for this element. | 
| Tripwire.Elements.ruleId | String | Id of the rule for this element. | 


#### Command Example
```!tripwire-elements-list```

#### Context Example
```json
{
    "Tripwire": {
        "Elements": [
            {
                "baselineVersionId": "-1y2p0ij32e8ch:-1y2p0ij3239dk",
                "description": "",
                "id": "-1y2p0ij32e8cc:-1y2p0ij323hx2",
                "inScope": true,
                "isRestorable": false,
                "lastSuccessDate": "2020-11-17T06:36:00.000Z",
                "lastVersionChangeSeverity": 0,
                "lastVersionChangeType": "BASELINE",
                "lastVersionId": "-1y2p0ij32e8ch:-1y2p0ij3239dk",
                "lastVersionTime": "2020-10-21T10:10:39.000Z",
                "name": "/home/test/monitored-folder",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij323i7o"
            },
            {
                "baselineVersionId": "-1y2p0ij32e8ch:-1y2p0ij3239dj",
                "description": "",
                "id": "-1y2p0ij32e8cc:-1y2p0ij323hx0",
                "inScope": true,
                "isRestorable": false,
                "lastSuccessDate": "2020-11-17T06:36:00.000Z",
                "lastVersionChangeSeverity": 10000,
                "lastVersionChangeType": "MODIFIED",
                "lastVersionId": "-1y2p0ij32e8ch:-1y2p0ij32393r",
                "lastVersionTime": "2020-10-22T07:09:01.000Z",
                "name": "/home/test/monitored-folder/test.txt",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij323i7o"
            },
        ]
    }
}
```

#### Human Readable Output

>### Tripwire Elements list results
>The number of returned results is: 50
>|id|name|baselineVersionId|
>|---|---|---|
>| -1y2p0ij32e8cc:-1y2p0ij323hx2 | /home/test/monitored-folder | -1y2p0ij32e8ch:-1y2p0ij3239dk |
>| -1y2p0ij32e8cc:-1y2p0ij323hx0 | /home/test/monitored-folder/test.txt | -1y2p0ij32e8ch:-1y2p0ij3239dj |



### tripwire-nodes-list
***
Returns a list of all nodes or those that match the provided filter criteria.


#### Base Command

`tripwire-nodes-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| node_oids | IDs of nodes to fetch. comma seperated. | Optional | 
| node_ips | IP addresses of nodes to fetch (only finds agent nodes). comma seperated. | Optional | 
| node_mac_adresses | MAC addresses of nodes to fetch. comma seperat. | Optional | 
| node_names | Support for case insensitive search for name parameter. comma seperat. | Optional | 
| node_os_names | Os names of nodes to fetch. comma seperated. | Optional | 
| tags | Tags of nodes to fetch. comma seperated. | Optional | 
| limit | Limit for the number of returned results. Default is 50. | Optional | 
| start | start index from which the results are returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tripwire.Nodes.agentType | String | Agent Type of nodes. | 
| Tripwire.Nodes.agentVersion | String | Agent versions of nodes. | 
| Tripwire.Nodes.auditEnabled | Boolean | Audit enabled condition of nodes. | 
| Tripwire.Nodes.description | String | Descriptions of nodes. | 
| Tripwire.Nodes.elementCount | Number | Element counts of nodes. | 
| Tripwire.Nodes.eventGeneratorEnabled | Boolean | Event generator enabled condition of nodes. | 
| Tripwire.Nodes.eventGeneratorInstalled | Boolean | Event generator installed condition of nodes. | 
| Tripwire.Nodes.hasFailures | Boolean | Has failures condition of nodes. | 
| Tripwire.Nodes.id | String | IDs of nodes. | 
| Tripwire.Nodes.importedTime | Date | Imported times of nodes. | 
| Tripwire.Nodes.ipAddresses | Unknown | IP addresses of nodes \(only finds agent nodes\). | 
| Tripwire.Nodes.isDisabled | Boolean | Is disabled condition of nodes. | 
| Tripwire.Nodes.isSocksProxy | Boolean | Is socks proxy condition of nodes. | 
| Tripwire.Nodes.lastCheck | Date | Last checks of nodes. | 
| Tripwire.Nodes.lastRegistration | Date | Last registration dates of nodes. | 
| Tripwire.Nodes.licensedFeatures | Unknown | Licensed features of nodes. | 
| Tripwire.Nodes.make | String | Make of nodes. | 
| Tripwire.Nodes.maxSeverity | Number | Max severities of nodes. | 
| Tripwire.Nodes.model | String | Models of nodes. | 
| Tripwire.Nodes.modifiedTime | Date | Modified times of nodes. | 
| Tripwire.Nodes.name | String | Names of nodes. | 
| Tripwire.Nodes.realTimeEnabled | Boolean | Real time enabled condition of nodes. | 
| Tripwire.Nodes.rmiHost | String | RMI hosts of nodes. | 
| Tripwire.Nodes.rmiPort | Number | RMI ports of nodes. | 
| Tripwire.Nodes.tags.tag | String | Tags of nodes. | 
| Tripwire.Nodes.tags.tagset | String | Tags sets of nodes. | 
| Tripwire.Nodes.tags.type | String | Tags types of nodes. | 
| Tripwire.Nodes.trackingId | String | Tracking IDs of nodes. | 
| Tripwire.Nodes.type | String | Node type of nodes. | 
| Tripwire.Nodes.version | String | Versions of nodes. | 


#### Command Example
```!tripwire-nodes-list```

#### Context Example
```json
{
    "Tripwire": {
        "Nodes": [
            {
                "agentType": "TE Agent",
                "agentVersion": "8.7.3.2.b2766",
                "auditEnabled": true,
                "description": "Red Hat Enterprise Linux Server release 7.9 3.10.0-1160.el7.x86_64, x86_64",
                "elementCount": 0,
                "eventGeneratorEnabled": true,
                "eventGeneratorInstalled": true,
                "hasFailures": false,
                "id": "-1y2p0ij32e8bu:-1y2p0ij32e7b3",
                "importedTime": "2020-09-30T17:23:16.723Z",
                "ipAddresses": [
                    "172.31.45.155"
                ],
                "isDisabled": false,
                "isSocksProxy": false,
                "lastCheck": "1970-01-02T00:00:00.000Z",
                "lastRegistration": "2020-09-30T18:00:12.400Z",
                "licensedFeatures": [
                    "FSI",
                    "FSI-Policy",
                    "FSI-Remediation"
                ],
                "make": "Red Hat",
                "maxSeverity": 0,
                "model": "Enterprise Linux Server release 7.9",
                "modifiedTime": "2020-09-30T18:00:12.416Z",
                "name": "ip-172-31-45-155.eu-west-1.compute.internal",
                "realTimeEnabled": false,
                "rmiHost": "172.31.45.155",
                "rmiPort": 9899,
                "tags": [
                    {
                        "tag": "Monitoring Enabled",
                        "tagset": "Status",
                        "type": "SYSTEM"
                    },
                    {
                        "tag": "Red Hat",
                        "tagset": "Platform Family",
                        "type": "USER"
                    },
                    {
                        "tag": "Red Hat Enterprise Linux Server 7",
                        "tagset": "Operating System",
                        "type": "SYSTEM"
                    }
                ],
                "trackingId": "USR.108078e1-4d67-4c36-bedf-67b3ad40f03b",
                "type": "Linux Server",
                "version": "3.10.0-1160.el7.x86_64"
            },
            {
                "agentType": "Axon Agent",
                "auditEnabled": true,
                "commonAgentCapabilities": [
                    "ACTION",
                    "COMMAND",
                    "DBI",
                    "DBI_CONFIG_REQUEST",
                    "FILE_CONFIG_REQUEST",
                    "POSIX_FILE",
                    "SUPPORT_BUNDLE",
                    "SYSTEM_CONTEXT",
                    "UPGRADE_REQUEST"
                ],
                "commonAgentOsName": "Linux (CentOS Linux release 7.8.2003 (Core))",
                "commonAgentOsVersion": "#1 SMP Tue Aug 25 17:23:54 UTC 2020 3.10.0-1127.19.1.el7.x86_64",
                "commonAgentUuid": "c1c4e6b8-92f4-4b9a-a46f-dd60163df7f4",
                "commonAgentVersion": "3.18.0.b3066",
                "description": "CentOS Linux release 7.8.2003 3.10.0-1127.19.1.el7.x86_64, x86_64",
                "elementCount": 2581,
                "eventGeneratorEnabled": false,
                "eventGeneratorInstalled": false,
                "hasFailures": true,
                "id": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "importedTime": "2020-10-01T14:41:37.630Z",
                "ipAddresses": [
                    "10.128.0.12"
                ],
                "isDisabled": false,
                "isSocksProxy": false,
                "lastCheck": "2020-12-01T09:31:00.000Z",
                "lastRegistration": "2020-10-20T14:16:01.597Z",
                "licensedFeatures": [
                    "FSI",
                    "FSI-Policy",
                    "FSI-Remediation"
                ],
                "make": "CentOS",
                "maxSeverity": 10000,
                "model": "Linux release 7.8.2003",
                "modifiedTime": "2020-10-20T14:16:01.603Z",
                "name": "ip-10-128-0-12.eu-west-1.compute.internal",
                "realTimeEnabled": false,
                "rmiPort": 0,
                "tags": [
                    {
                        "tag": "CentOS 7",
                        "tagset": "Operating System",
                        "type": "SYSTEM"
                    },
                    {
                        "tag": "Monitoring Enabled",
                        "tagset": "Status",
                        "type": "SYSTEM"
                    },
                    {
                        "tag": "Red Hat",
                        "tagset": "Platform Family",
                        "type": "USER"
                    },
                    {
                        "tag": "Rule Run Errors",
                        "tagset": "Health",
                        "type": "OPERATIONAL"
                    }
                ],
                "trackingId": "USR.d275ffbd-14d4-4acf-9f04-20843cf7c070",
                "type": "Linux Server",
                "version": "3.10.0-1127.19.1.el7.x86_64"
            }
        ]
    }
}
```

#### Human Readable Output

>### Tripwire Nodes list results
>The number of returned results is: 2
>|id|name|make|ipAddresses|type|lastCheck|modifiedTime|
>|---|---|---|---|---|---|---|
>| -1y2p0ij32e8bu:-1y2p0ij32e7b3 | ip-172-31-45-155.eu-west-1.compute.internal | Red Hat | 172.31.45.155 | Linux Server | 1970-01-02T00:00:00.000Z | 2020-09-30T18:00:12.416Z |
>| -1y2p0ij32e8bu:-1y2p0ij323ikt | ip-10-128-0-12.eu-west-1.compute.internal | CentOS | 10.128.0.12 | Linux Server | 2020-12-01T09:31:00.000Z | 2020-10-20T14:16:01.603Z |

