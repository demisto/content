Tripwire is a file integrity management (FIM), FIM monitors files and folders on systems and is triggered when they have changed.
This integration was integrated and tested with v1 of Tripwire
## Configure Tripwire in Cortex


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

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| end_received_time | End received time of element versions to fetch.<br/>The format can be either relative e.g. "2 days" or date time "2020-11-24T17:07:27Z". | Optional | 


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
```!tripwire-versions-list limit=5 start_detected_time=`30 days` end_detected_time=`1 day` node_names=`ip-10-128-0-12.eu-west-1.compute.internal` rule_ids=`-1y2p0ij32e8ch:-1y2p0ij3233dx````

#### Context Example
```json
{
    "Tripwire": {
        "Versions": [
            {
                "approvalId": "",
                "baselineVersion": "-1y2p0ij32e8ch:-1y2p0ij323gbz",
                "changeType": "MODIFIED",
                "elementId": "-1y2p0ij32e8cc:-1y2p0ij323gc0",
                "elementName": "/etc/gshadow",
                "exists": true,
                "id": "-1y2p0ij32e8ch:-1y2p0ij3233dx",
                "isPromoted": false,
                "md5": "",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "nodeName": "ip-10-128-0-12.eu-west-1.compute.internal",
                "outsideMaintenanceWindow": false,
                "promotionComment": "",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij32br02",
                "ruleName": "Critical Configuration Files",
                "scanId": "-1y2p0ij32e86g:-1y2p0ij3233dz",
                "severity": 10000,
                "sha1": "1AF8815150BDD1D6BEE34B4841D6EDD99559C3D9",
                "sha256": "",
                "sha512": "",
                "timeDetected": "2020-11-10T06:39:01.000Z",
                "timeReceived": "2020-11-10T06:39:02.000Z"
            },
            {
                "approvalId": "",
                "baselineVersion": "-1y2p0ij32e8ch:-1y2p0ij323g7t",
                "changeType": "MODIFIED",
                "elementId": "-1y2p0ij32e8cc:-1y2p0ij323g7u",
                "elementName": "/etc/passwd",
                "exists": true,
                "id": "-1y2p0ij32e8ch:-1y2p0ij3233dw",
                "isPromoted": false,
                "md5": "",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "nodeName": "ip-10-128-0-12.eu-west-1.compute.internal",
                "outsideMaintenanceWindow": false,
                "promotionComment": "",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij32br02",
                "ruleName": "Critical Configuration Files",
                "scanId": "-1y2p0ij32e86g:-1y2p0ij3233dz",
                "severity": 10000,
                "sha1": "0315A78C14D468D4C784E640C914CA258627252C",
                "sha256": "",
                "sha512": "",
                "timeDetected": "2020-11-10T06:39:01.000Z",
                "timeReceived": "2020-11-10T06:39:02.000Z"
            },
            {
                "approvalId": "",
                "baselineVersion": "-1y2p0ij32e8ch:-1y2p0ij323g7p",
                "changeType": "MODIFIED",
                "elementId": "-1y2p0ij32e8cc:-1y2p0ij323g7q",
                "elementName": "/etc/group",
                "exists": true,
                "id": "-1y2p0ij32e8ch:-1y2p0ij3233dv",
                "isPromoted": false,
                "md5": "",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "nodeName": "ip-10-128-0-12.eu-west-1.compute.internal",
                "outsideMaintenanceWindow": false,
                "promotionComment": "",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij32br02",
                "ruleName": "Critical Configuration Files",
                "scanId": "-1y2p0ij32e86g:-1y2p0ij3233dz",
                "severity": 10000,
                "sha1": "0E3BE34030EBFA4827DDDC48595671E80A5AB9FF",
                "sha256": "",
                "sha512": "",
                "timeDetected": "2020-11-10T06:39:01.000Z",
                "timeReceived": "2020-11-10T06:39:02.000Z"
            },
            {
                "approvalId": "",
                "baselineVersion": "-1y2p0ij32e8ch:-1y2p0ij323g7f",
                "changeType": "MODIFIED",
                "elementId": "-1y2p0ij32e8cc:-1y2p0ij323g7g",
                "elementName": "/etc/shadow",
                "exists": true,
                "id": "-1y2p0ij32e8ch:-1y2p0ij3233du",
                "isPromoted": false,
                "md5": "",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "nodeName": "ip-10-128-0-12.eu-west-1.compute.internal",
                "outsideMaintenanceWindow": false,
                "promotionComment": "",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij32br02",
                "ruleName": "Critical Configuration Files",
                "scanId": "-1y2p0ij32e86g:-1y2p0ij3233dz",
                "severity": 10000,
                "sha1": "32AD8C6BC2333010924B75F1A4F10C4815FC824A",
                "sha256": "",
                "sha512": "",
                "timeDetected": "2020-11-10T06:39:01.000Z",
                "timeReceived": "2020-11-10T06:39:02.000Z"
            },
            {
                "approvalId": "",
                "baselineVersion": "-1y2p0ij32e8ch:-1y2p0ij322lmh",
                "changeType": "BASELINE",
                "elementId": "-1y2p0ij32e8cc:-1y2p0ij322lmi",
                "elementName": "/home/test/monitored-folder/yana.txt",
                "exists": true,
                "id": "-1y2p0ij32e8ch:-1y2p0ij322lmh",
                "isPromoted": false,
                "md5": "",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "nodeName": "ip-10-128-0-12.eu-west-1.compute.internal",
                "outsideMaintenanceWindow": false,
                "promotionComment": "",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij322lmz",
                "ruleName": "yanas rule",
                "scanId": "-1y2p0ij32e86g:-1y2p0ij322lmk",
                "severity": 0,
                "sha1": "50850598DAEEB40CE6BCCAC7B211885A68A28422",
                "sha256": "",
                "sha512": "",
                "timeDetected": "2020-11-23T05:39:46.000Z",
                "timeReceived": "2020-11-23T05:39:46.000Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Tripwire Versions list results
>The number of returned results is: 5
>|id|timeDetected|elementName|changeType|nodeName|ruleName|
>|---|---|---|---|---|---|
>| -1y2p0ij32e8ch:-1y2p0ij3233dx | 2020-11-10T06:39:01.000Z | /etc/gshadow | MODIFIED | ip-10-128-0-12.eu-west-1.compute.internal | Critical Configuration Files |
>| -1y2p0ij32e8ch:-1y2p0ij3233dw | 2020-11-10T06:39:01.000Z | /etc/passwd | MODIFIED | ip-10-128-0-12.eu-west-1.compute.internal | Critical Configuration Files |
>| -1y2p0ij32e8ch:-1y2p0ij3233dv | 2020-11-10T06:39:01.000Z | /etc/group | MODIFIED | ip-10-128-0-12.eu-west-1.compute.internal | Critical Configuration Files |
>| -1y2p0ij32e8ch:-1y2p0ij3233du | 2020-11-10T06:39:01.000Z | /etc/shadow | MODIFIED | ip-10-128-0-12.eu-west-1.compute.internal | Critical Configuration Files |
>| -1y2p0ij32e8ch:-1y2p0ij322lmh | 2020-11-23T05:39:46.000Z | /home/test/monitored-folder/yana.txt | BASELINE | ip-10-128-0-12.eu-west-1.compute.internal | yanas rule |


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
```!tripwire-rules-list limit=5```

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
            }
        ]
    }
}
```

#### Human Readable Output

>### Tripwire Rules list results
>The number of returned results is: 5
>|name|id|severity|elementName|type|command|importedTime|modifiedTime|
>|---|---|---|---|---|---|---|---|
>| Fax Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c200 | 0 | sc sdshow Fax | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow Fax | 2020-09-30T17:33:23.330Z | 2020-09-30T17:33:23.330Z |
>| EMET Version | -1y2p0ij32e7pw:-1y2p0ij32c1zz | 0 | EMET Version | Command Output Capture Rule | (echo Set oFSO = CreateObject("Scripting.FileSystemObject"^) & echo EMET_Dll = "%SystemRooT%\AppPatch\emet.dll" & echo If oFSO.FileExists(EMET_Dll^) then & echo WScript.Echo oFSO.GetFileVersion(EMET_Dll^) & echo Else & echo WScript.Echo "EMET Is Not Installed" & echo End If) > "$(TEMP_DIR)"\EMET_Version.vbs & %SystemRoot%\system32\cscript /nologo "$(TEMP_DIR)"\EMET_Version.vbs & del "$(TEMP_DIR)"\EMET_Version.vbs | 2020-09-30T17:33:23.344Z | 2020-09-30T17:33:23.344Z |
>| RasAuto Service Permissions | -1y2p0ij32e7pw:-1y2p0ij32c1zy | 0 | sc sdshow RasAuto | Command Output Capture Rule | %Windir%/system32/sc.exe sdshow RasAuto | 2020-09-30T17:33:23.350Z | 2020-09-30T17:33:23.350Z |
>| Get the List of App Packages | -1y2p0ij32e7pw:-1y2p0ij32c1zv | 0 | List of App Packages | Command Output Capture Rule | %systemRoot%\system32\dism.exe /online /Get-ProvisionedAppxPackages /ScratchDir:"$(TEMP_DIR)" | 2020-09-30T17:33:23.360Z | 2020-09-30T17:33:23.360Z |
>| EMET Default Protections for Popular Software | -1y2p0ij32e7pw:-1y2p0ij32c1zu | 0 | EMET Default Protections for Popular Software | Command Output Capture Rule | (echo Const HKEY_LOCAL_MACHINE = ^&H80000002 & echo strComputer = "." & echo vers = "" & echo Set oFSO = CreateObject("Scripting.FileSystemObject"^) & echo EMET_Dll = "C:\Windows\AppPatch\emet.dll" & echo If oFSO.FileExists(EMET_Dll^) then & echo vers = Mid(oFSO.GetFileVersion(EMET_Dll^),1,1^) & echo Else & echo WScript.Echo "EMET is not installed." & echo Wscript.Quit & echo End If & echo Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" ^& strComputer ^& "\root\default:StdRegProv"^) & echo strKeyPath = "Software\Policies\Microsoft\EMET\Defaults" & echo strRegKeyPath = "SOFTWARE\Microsoft\EMET" & echo oReg.EnumValues HKEY_LOCAL_MACHINE,strKeyPath,arrValueNames,arrValueTypes & echo oReg.EnumKey HKEY_LOCAL_MACHINE, strRegKeyPath, arrRegistryValueNames & echo If (vers = "3"^) Then & echo ValueNames=Array("7z","7zFM","7zGUI","Chrome","Firefox","FirefoxPluginContainer","GoogleTalk","iTunes","Java","Javaw","Javaws","LiveMessenger","LiveSync","LiveWriter","Lync","mIRC","MOE","Opera","PhotoshopCS2","PhotoshopCS264","PhotoshopCS3","PhotoshopCS364","PhotoshopCS4","PhotoshopCS464","PhotoshopCS5","PhotoshopCS51","PhotoshopCS5164","PhotoshopCS564","Pidgin","QuickTimePlayer","RealConverter","RealPlayer","Safari","Skype","Thunderbird","ThunderbirdPluginContainer","UnRAR","VLC","Winamp","WindowsLiveSync","WindowsMediaPlayer","WinRARConsole","WinRARGUI","Winzip","Winzip64"^) & echo RegistryValueNames=Array("7z.exe","7zfm.exe","7zg.exe","chrome.exe","firefox.exe","plugin-container.exe","googletalk.exe","itunes.exe","java.exe","javaw.exe","javaws.exe","msnmsgr.exe","WLSync.exe","windowslivewriter.exe","communicator.exe","mirc.exe","MOE.exe","opera.exe","Photoshop.exe","pidgin.exe","QuickTimePlayer.exe","realconverter.exe","realplay.exe","Safari.exe","Skype.exe","thunderbird.exe","plugin-container.exe","unrar.exe","vlc.exe","winamp.exe","WindowsLiveSync.exe","wmplayer.exe","rar.exe","winrar.exe","winzip32.exe","winzip64.exe"^) & echo IsAppFound = checkSoftware(arrRegistryValueNames, RegistryValueNames^) & echo If (IsAppFound = "1"^) or (IsAppFound = ""^) Then & echo IsAppGPOFound = checkSoftware(arrValueNames, ValueNames^) & echo If IsAppGPOFound ^<^> "0" Then & echo WScript.Echo "Default Protections for other Popular Software is not configured." & echo End If & echo End if & echo Elseif (vers = "4"^) Then & echo ValueNames=Array("7z","7zFM","7zGUI","Chrome","Firefox","FirefoxPluginContainer","FoxitReader","GoogleTalk","iTunes","LiveWriter","LyncCommunicator","mIRC","Opera","PhotoGallery","Photoshop","Pidgin","QuickTimePlayer","RealConverter","RealPlayer","Safari","SkyDrive","Skype","Thunderbird","ThunderbirdPluginContainer","UnRAR","VLC","Winamp","WindowsLiveMail","WindowsMediaPlayer","WinRARConsole","WinRARGUI","Winzip","Winzip64"^) & echo RegistryValueNames=Array("7z.exe","7zfm.exe","7zg.exe","chrome.exe","firefox.exe","plugin-container.exe","foxit reader.exe","googletalk.exe","itunes.exe","windowslivewriter.exe","communicator.exe","mirc.exe","opera.exe","WLXPhotoGallery.exe","Photoshop.exe","pidgin.exe","QuickTimePlayer.exe","realconverter.exe","realplay.exe","Safari.exe","SkyDrive.exe","Skype.exe","thunderbird.exe","plugin-container.exe","unrar.exe","vlc.exe","winamp.exe","wlmail.exe","wmplayer.exe","rar.exe","winrar.exe","winzip32.exe","winzip64.exe"^) & echo IsAppFound = checkSoftware(arrRegistryValueNames, RegistryValueNames^) & echo If (IsAppFound = "1"^) or (IsAppFound = ""^) Then & echo IsAppGPOFound = checkSoftware(arrValueNames, ValueNames^) & echo If IsAppGPOFound ^<^> "0" Then & echo WScript.Echo "Default Protections for other Popular Software is not configured." & echo End If & echo End if & echo Elseif (vers = "5"^) Then & echo ValueNames=Array("7z","7zFM","7zGUI","Chrome","Firefox","FirefoxPluginContainer","FoxitReader","GoogleTalk","iTunes","LiveWriter","LyncCommunicator","mIRC","Opera","Opera_New_Versions","PhotoGallery","Photoshop","Pidgin","QuickTimePlayer","RealConverter","RealPlayer","Safari","SkyDrive","Skype","Thunderbird","ThunderbirdPluginContainer","UnRAR","VLC","Winamp","WindowsLiveMail","WindowsMediaPlayer","WinRARConsole","WinRARGUI","Winzip","Winzip64"^) & echo RegistryValueNames=Array("7z.exe","7zfm.exe","7zg.exe","chrome.exe","firefox.exe","plugin-container.exe","foxit reader.exe","googletalk.exe","itunes.exe","windowslivewriter.exe","communicator.exe","mirc.exe","opera.exe","opera.exe","WLXPhotoGallery.exe","Photoshop.exe","pidgin.exe","QuickTimePlayer.exe","realconverter.exe","realplay.exe","Safari.exe","SkyDrive.exe","Skype.exe","thunderbird.exe","plugin-container.exe","unrar.exe","vlc.exe","winamp.exe","wlmail.exe","wmplayer.exe","rar.exe","winrar.exe","winzip32.exe","winzip64.exe"^) & echo IsAppFound = checkSoftware(arrRegistryValueNames, RegistryValueNames^) & echo If (IsAppFound = "1"^) or (IsAppFound = ""^) Then & echo IsAppGPOFound = checkSoftware(arrValueNames, ValueNames^) & echo If IsAppGPOFound ^<^> "0" Then & echo WScript.Echo "Default Protections for other Popular Software is not configured." & echo End If & echo End if & echo Else & echo Wscript.Echo "EMET version is not supported: " ^& vers & echo Wscript.Quit & echo End If & echo Function checkSoftware(arrValueNames, ValueNames^) & echo Dim isFound & echo If Not IsNull(arrValueNames^) Then & echo isDiff = 0 & echo For i = 0 To UBound(ValueNames^) & echo isFound = False & echo For j = 0 To UBound(arrValueNames^) & echo If Ucase(ValueNames(i^)^) = Ucase(arrValueNames(j^)^) Then & echo isFound = True & echo End If & echo Next & echo If Not isFound Then & echo isDiff = 1 & echo End If & echo Next & echo End If & echo checkSoftware = isDiff & echo End Function) > %SystemRoot%\Temp\PopularSoftware.vbs & %SystemRoot%\system32\cscript /nologo %SystemRoot%\Temp\PopularSoftware.vbs & del %SystemRoot%\Temp\PopularSoftware.vbs | 2020-09-30T17:33:23.366Z | 2020-09-30T17:33:23.366Z |


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
```!tripwire-elements-list limit=5```

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
            {
                "baselineVersionId": "-1y2p0ij32e8ch:-1y2p0ij323hwj",
                "description": "",
                "id": "-1y2p0ij32e8cc:-1y2p0ij323hwk",
                "inScope": true,
                "isRestorable": false,
                "lastSuccessDate": "2020-11-10T14:24:00.000Z",
                "lastVersionChangeSeverity": 0,
                "lastVersionChangeType": "BASELINE",
                "lastVersionId": "-1y2p0ij32e8ch:-1y2p0ij323hwj",
                "lastVersionTime": "2020-10-20T14:23:41.000Z",
                "name": "/usr/bin/c89",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij32bqvd"
            },
            {
                "baselineVersionId": "-1y2p0ij32e8ch:-1y2p0ij323hwh",
                "description": "",
                "id": "-1y2p0ij32e8cc:-1y2p0ij323hwi",
                "inScope": true,
                "isRestorable": false,
                "lastSuccessDate": "2020-11-10T14:24:00.000Z",
                "lastVersionChangeSeverity": 0,
                "lastVersionChangeType": "BASELINE",
                "lastVersionId": "-1y2p0ij32e8ch:-1y2p0ij323hwh",
                "lastVersionTime": "2020-10-20T14:23:41.000Z",
                "name": "/usr/bin/c99",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij32bqvd"
            },
            {
                "baselineVersionId": "-1y2p0ij32e8ch:-1y2p0ij323hwf",
                "description": "",
                "id": "-1y2p0ij32e8cc:-1y2p0ij323hwg",
                "inScope": true,
                "isRestorable": false,
                "lastSuccessDate": "2020-11-10T14:24:00.000Z",
                "lastVersionChangeSeverity": 0,
                "lastVersionChangeType": "BASELINE",
                "lastVersionId": "-1y2p0ij32e8ch:-1y2p0ij323hwf",
                "lastVersionTime": "2020-10-20T14:23:41.000Z",
                "name": "/usr/bin/cc",
                "nodeId": "-1y2p0ij32e8bu:-1y2p0ij323ikt",
                "ruleId": "-1y2p0ij32e7pj:-1y2p0ij32bqvd"
            }
        ]
    }
}
```

#### Human Readable Output

>### Tripwire Elements list results
>The number of returned results is: 5
>|id|name|baselineVersionId|
>|---|---|---|
>| -1y2p0ij32e8cc:-1y2p0ij323hx2 | /home/test/monitored-folder | -1y2p0ij32e8ch:-1y2p0ij3239dk |
>| -1y2p0ij32e8cc:-1y2p0ij323hx0 | /home/test/monitored-folder/test.txt | -1y2p0ij32e8ch:-1y2p0ij3239dj |
>| -1y2p0ij32e8cc:-1y2p0ij323hwk | /usr/bin/c89 | -1y2p0ij32e8ch:-1y2p0ij323hwj |
>| -1y2p0ij32e8cc:-1y2p0ij323hwi | /usr/bin/c99 | -1y2p0ij32e8ch:-1y2p0ij323hwh |
>| -1y2p0ij32e8cc:-1y2p0ij323hwg | /usr/bin/cc | -1y2p0ij32e8ch:-1y2p0ij323hwf |


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
```!tripwire-nodes-list limit=5```

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
                "lastCheck": "2020-12-01T14:01:00.000Z",
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
>| -1y2p0ij32e8bu:-1y2p0ij323ikt | ip-10-128-0-12.eu-west-1.compute.internal | CentOS | 10.128.0.12 | Linux Server | 2020-12-01T14:01:00.000Z | 2020-10-20T14:16:01.603Z |
