TDS Polygon is a Malware Detonation & Research platform designed for deep dynamic analysis and enhanced indicators extraction. TDS Polygon analyzes submitted files and urls and extracts deep IOCs that appear when malicious code is triggered and executed. Polygon could be used either for application-level tasks (like smtp-based mail filtering) and analytical purposes (files/urls analysis for verdict, report and indicators).
This integration was integrated and tested with version 3.1 of Group-IB TDS Polygon

## Configure Group-IB TDS Polygon on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Group-IB TDS Polygon.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server URL \(e.g., https://huntbox.group\-ib.com\) | True |
| api_key | API Key | True |
| report_language | Default reports language | True |
| insecure | Trust any certificate \(insecure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### polygon-upload-file
***
Upload file for analysis


#### Base Command

`polygon-upload-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | File ID in Demisto | Required | 
| password | Password for analyzed archive | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Polygon.Analysis.ID | string | Analysis ID in TDS | 
| Polygon.Analysis.EntryID | string | File id in Demisto | 
| Polygon.Analysis.FileName | string | Original file name | 
| Polygon.Analysis.Status | string | The analysis status | 


#### Command Example
!polygon-upload-file file_id=4@br password="123456"

#### Context Example
```
{
    "Polygon": {
        "Analysis": {
            "ID": "U2152031",
            "Status": "In Progress",
            "EntryID": "4@br",
            "FileName": "test.pdf"
        }
    }
}
```

#### Human Readable Output
>File uploaded successfully. Analysis ID: F2136015


### polygon-upload-url
***
Upload URL for analysis


#### Base Command

`polygon-upload-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL for analysis | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Polygon.Analysis.ID | string | Analysis ID in TDS | 
| Polygon.Analysis.URL | string | URL analyzed | 
| Polygon.Analysis.Status | string | Polygon analysis status | 


#### Command Example
```!polygon-upload-url url=http://reqw.xyz/pik.zip```

#### Context Example
```
{
    "Polygon": {
        "Analysis": {
            "ID": "U2152031",
            "Status": "In Progress",
            "URL": "http://reqw.xyz/pik.zip"
        }
    }
}
```

#### Human Readable Output

>Url uploaded successfully. Analysis ID: U2152031

### polygon-analysis-info
***
Get TDS Polygon analysis info


#### Base Command

`polygon-analysis-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tds_analysis_id | Analysis ID in TDS | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | string | The full file name \(including file extension\). | 
| File.MD5 | string | The MD5 hash of the file | 
| File.SHA1 | string | The SHA1 hash of the file | 
| File.SHA256 | string | The SHA256 hash of the file | 
| File.Type | string | File type | 
| File.Malicious.Vendor | string | The vendor that reported the file as malicious | 
| File.Malicious.Description | string | A description explaining why the file was determined to be malicious | 
| DBotScore.Indicator | string | The indicator that was tested | 
| DBotScore.Type | string | The indicator type | 
| DBotScore.Vendor | string | The vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 
| IP.Address | String | IP address | 
| Domain.Name | String | The Domain name | 
| Domain.DNS | String | A list of IP objects resolved by DNS. | 
| URL.Data | String | The URL | 
| URL.Malicious.Vendor | string | The vendor that reported the url as malicious | 
| URL.Malicious.Description | string | A description explaining why the url was determined to be malicious | 
| RegistryKey.Path | String | The path to the registry key | 
| RegistryKey.Value | String | The value at the given RegistryKey. | 
| Process.Name | String | Process name | 
| Process.PID | String | Process PID | 
| Process.CommandLine | String | Process Command Line | 
| Process.Path | String | Process path | 
| Process.StartTime | date | Process start time | 
| Process.EndTime | date | Process end time | 
| Polygon.Analysis.ID | string | TDS File ID | 
| Polygon.Analysis.Name | string | File Name | 
| Polygon.Analysis.Size | number | File Size | 
| Polygon.Analysis.Started | date | Analysis start timestamp | 
| Polygon.Analysis.Analyzed | date | Analysis finish timestamp | 
| Polygon.Analysis.MD5 | string | Analyzed file MD5 hash | 
| Polygon.Analysis.SHA1 | string | Analyzed file SHA1 hash | 
| Polygon.Analysis.SHA256 | string | Analyzed file SHA256 | 
| Polygon.Analysis.Result | boolean | Analysis verdict | 
| Polygon.Analysis.Status | string | Analysis status | 
| Polygon.Analysis.Verdict | string | Analysis verdict | 
| Polygon.Analysis.Probability | string | Verdict probability | 
| Polygon.Analysis.Families | string | Malware families | 
| Polygon.Analysis.Score | number | Polygon score | 
| Polygon.Analysis.Internet-connection | string | Internet availability | 
| Polygon.Analysis.Type | string | File type | 
| Polygon.Analysis.DumpExists | boolean | Network activity dump exists | 
| Polygon.Analysis.File | unknown | The information about files in analysis | 
| Polygon.Analysis.URL | unknown | The information about URL indicators | 
| Polygon.Analysis.IP | unknown | The information about IP indicators | 
| Polygon.Analysis.Domain | unknown | The information about Domain indicators | 
| Polygon.Analysis.RegistryKey | unknown | The information about registry keys which were modified during the analysis | 
| Polygon.Analysis.Process | unknown | The information about processes started during the analysis | 


#### Command Example
```!polygon-analysis-info tds_analysis_id=F2118597```

#### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "ba9fe2cb8ee2421ea24a55306ce9d923",
            "Score": 3,
            "Type": "file",
            "Vendor": "Group-IB TDS Polygon"
        },
        {
            "Indicator": "44b3f79dfd7c5861501a19a3bac89f544c7ff815",
            "Score": 0,
            "Type": "file",
            "Vendor": "Group-IB TDS Polygon"
        },
        {
            "Indicator": "eb57446af5846faa28a726a8b7d43ce5a7fcbd55",
            "Score": 0,
            "Type": "file",
            "Vendor": "Group-IB TDS Polygon"
        },
        {
            "Indicator": "3a29353e30ddd1af92f07ee0f61a3a706ee09a64",
            "Score": 0,
            "Type": "file",
            "Vendor": "Group-IB TDS Polygon"
        },
        {
            "Indicator": "c41542c7dd5a714adfeafec77022ae0a722ff3a8",
            "Score": 0,
            "Type": "file",
            "Vendor": "Group-IB TDS Polygon"
        },
        {
            "Indicator": "svettenkirch.de",
            "Score": 0,
            "Type": "domain",
            "Vendor": "Group-IB TDS Polygon"
        },
        {
            "Indicator": "super.esu.as",
            "Score": 0,
            "Type": "domain",
            "Vendor": "Group-IB TDS Polygon"
        },
        {
            "Indicator": "8.8.8.8",
            "Score": 0,
            "Type": "ip",
            "Vendor": "Group-IB TDS Polygon"
        },
        {
            "Indicator": "79.98.29.14",
            "Score": 0,
            "Type": "ip",
            "Vendor": "Group-IB TDS Polygon"
        },
        {
            "Indicator": "217.114.216.252",
            "Score": 0,
            "Type": "ip",
            "Vendor": "Group-IB TDS Polygon"
        },
        {
            "Indicator": "http://super.esu.as/wp-content/themes/twentyeleven/inc/images/msg.jpg",
            "Score": 0,
            "Type": "url",
            "Vendor": "Group-IB TDS Polygon"
        }
    ],
    "Domain": [
        {
            "DNS": "217.114.216.252",
            "Name": "svettenkirch.de"
        },
        {
            "DNS": "79.98.29.14",
            "Name": "super.esu.as"
        }
    ],
    "File": [
        {
            "MD5": "ba9fe2cb8ee2421ea24a55306ce9d923",
            "Malicious": {
                "Description": "Verdict probability: 64.8%, iocs: JS:Trojan.Agent.DQBF",
                "Vendor": "Group-IB TDS Polygon"
            },
            "Name": "link.pdf",
            "SHA1": "44b3f79dfd7c5861501a19a3bac89f544c7ff815",
            "SHA256": "0d1b77c84c68c50932e28c3462a1962916abbbebb456ce654751ab401aa37697",
            "Type": "PDF document, version 1.7"
        },
        {
            "MD5": "9b52c8a74353d82ef1ebca42c9a7358c",
            "Name": "tmpfujZWn",
            "SHA1": "eb57446af5846faa28a726a8b7d43ce5a7fcbd55",
            "SHA256": "34ce805b7131eda3cec905dfd4e2708ab07dd3f038345b2ba9df51eb8fc915eb",
            "Type": "ASCII text, with no line terminators"
        },
        {
            "MD5": "3641c180f1a2c3f41fb1d974687e3553",
            "Name": "pik.zip",
            "SHA1": "3a29353e30ddd1af92f07ee0f61a3a706ee09a64",
            "SHA256": "c296d2895ac541ba16a237b2ad344b28e803b6990b7713c4c73faa9f722cf9fc",
            "Type": "Zip archive data, at least v2.0 to extract"
        },
        {
            "MD5": "9cd53f781ba0bed013ee87c5e7956f64",
            "Name": "\u041f\u0410\u041e \u00ab\u0413\u0440\u0443\u043f\u043f\u0430 \u041a\u043e\u043c\u043f\u0430\u043d\u0438\u0439 \u041f\u0418\u041a\u00bb \u043f\u043e\u0434\u0440\u043e\u0431\u043d\u043e\u0441\u0442\u0438 \u0437\u0430\u043a\u0430\u0437\u0430.js",
            "SHA1": "c41542c7dd5a714adfeafec77022ae0a722ff3a8",
            "SHA256": "422ea8f21b8652dd760a3f02ac3e2a4345d7e45fce49e1e45f020384c93a29ea",
            "Type": "ASCII text, with CRLF, LF line terminators"
        }
    ],
    "IP": [
        {
            "Address": "8.8.8.8"
        },
        {
            "Address": "79.98.29.14"
        },
        {
            "Address": "217.114.216.252"
        }
    ],
    "Polygon": {
        "Analysis": {
            "Analyzed": "2020-05-07 10:29:42",
            "DumpExists": true,
            "Families": "",
            "ID": "F2118597",
            "Internet-connection": "Available",
            "MD5": "ba9fe2cb8ee2421ea24a55306ce9d923",
            "Name": "link.pdf",
            "Probability": "64.80%",
            "Result": true,
            "SHA1": "44b3f79dfd7c5861501a19a3bac89f544c7ff815",
            "SHA256": "0d1b77c84c68c50932e28c3462a1962916abbbebb456ce654751ab401aa37697",
            "Score": 24.6,
            "Size": 36375,
            "Started": "2020-05-07 10:27:30",
            "Status": "Finished",
            "Type": "PDF document, version 1.7",
            "Verdict": "Malicious"
        }
    },
    "Process": [
        {
            "Child": null,
            "CommandLine": "C:\\Users\\John\\AppData\\Local\\Temp\\tmpknkzql\\link.pdf",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "AcroRd32.exe",
            "PID": "760",
            "Parent": null,
            "Path": "C:\\Program Files\\Adobe\\Reader 9.0\\Reader\\AcroRd32.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": 132333460491406260
        },
        {
            "Child": null,
            "CommandLine": "\"C:\\Users\\John\\AppData\\Local\\Temp\\tmpkf9bqs\\\u041f\u0410\u041e \u00ab\u0413\u0440\u0443\u043f\u043f\u0430 \u041a\u043e\u043c\u043f\u0430\u043d\u0438\u0439 \u041f\u0418\u041a\u00bb \u043f\u043e\u0434\u0440\u043e\u0431\u043d\u043e\u0441\u0442\u0438 \u0437\u0430\u043a\u0430\u0437\u0430.js\"",
            "EndTime": 132333460889687500,
            "Hostname": null,
            "MD5": null,
            "Name": "wscript.exe",
            "PID": "972",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\wscript.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": 132333460491875000
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "(null)",
            "PID": "4",
            "Parent": null,
            "Path": "(null)",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "OSPPSVC.EXE",
            "PID": "180",
            "Parent": null,
            "Path": "C:\\Program Files\\Common Files\\microsoft shared\\OfficeSoftwareProtectionPlatform\\OSPPSVC.EXE",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "audiodg.exe",
            "PID": "1116",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\audiodg.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "csrss.exe",
            "PID": "296",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\csrss.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "csrss.exe",
            "PID": "340",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\csrss.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "dwm.exe",
            "PID": "1276",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\dwm.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "lsass.exe",
            "PID": "396",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\lsass.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "lsm.exe",
            "PID": "404",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\lsm.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "services.exe",
            "PID": "380",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\services.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "smss.exe",
            "PID": "216",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\smss.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "spoolsv.exe",
            "PID": "1168",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\spoolsv.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "svchost.exe",
            "PID": "776",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\svchost.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "svchost.exe",
            "PID": "944",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\svchost.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "svchost.exe",
            "PID": "804",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\svchost.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "svchost.exe",
            "PID": "636",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\svchost.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "svchost.exe",
            "PID": "560",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\svchost.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "svchost.exe",
            "PID": "704",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\svchost.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "svchost.exe",
            "PID": "1220",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\svchost.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "svchost.exe",
            "PID": "724",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\svchost.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "svchost.exe",
            "PID": "1004",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\svchost.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "taskhost.exe",
            "PID": "1296",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\taskhost.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": 132333461081093740,
            "Hostname": null,
            "MD5": null,
            "Name": "WmiPrvSE.exe",
            "PID": "860",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "winlogon.exe",
            "PID": "460",
            "Parent": null,
            "Path": "C:\\Windows\\System32\\winlogon.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        },
        {
            "Child": null,
            "CommandLine": "",
            "EndTime": null,
            "Hostname": null,
            "MD5": null,
            "Name": "explorer.exe",
            "PID": "1344",
            "Parent": null,
            "Path": "C:\\Windows\\explorer.exe",
            "SHA1": null,
            "Sibling": null,
            "StartTime": null
        }
    ],
    "RegistryKey": [
        {
            "Name": null,
            "Path": "\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Adobe\\Acrobat Reader\\9.0\\Installer\\Migrated\\{AC76BA86-7AD7-1033-7B44-A90000000001}",
            "Value": "1"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Adobe\\Acrobat Reader\\9.0\\Originals\\bDisplayedSplash",
            "Value": "1"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Adobe\\Acrobat Reader\\9.0\\AVGeneral\\bLastExitNormal",
            "Value": "0"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Adobe\\Acrobat Reader\\9.0\\AdobeViewer\\Launched",
            "Value": "1"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Adobe\\Acrobat Reader\\9.0\\AdobeViewer\\Launched",
            "Value": "1"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASAPI32\\EnableFileTracing",
            "Value": "0"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASAPI32\\EnableConsoleTracing",
            "Value": "0"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASAPI32\\FileTracingMask",
            "Value": "-65536"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASAPI32\\ConsoleTracingMask",
            "Value": "-65536"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASAPI32\\MaxFileSize",
            "Value": "1048576"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASAPI32\\FileDirectory",
            "Value": "%windir%\\tracing"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASMANCS\\EnableFileTracing",
            "Value": "0"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASMANCS\\EnableConsoleTracing",
            "Value": "0"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASMANCS\\FileTracingMask",
            "Value": "-65536"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASMANCS\\ConsoleTracingMask",
            "Value": "-65536"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASMANCS\\MaxFileSize",
            "Value": "1048576"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Tracing\\wscript_RASMANCS\\FileDirectory",
            "Value": "%windir%\\tracing"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyEnable",
            "Value": "0"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections\\SavedLegacySettings",
            "Value": "{'type': 'b64_struct', 'data': 'RgAAADcAAAAJAAAAAAAAAAAAAAAAAAAABAAAAAAAAADwtLKVehjTAQAAAAAAAAAAAAAAAAIAAAAXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAVHNMAFRzTAAAAAAAAAAAAAQAAAAAAAAAeHNMAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AwAAAAAAAAACAAAAAQAAAAIAAADAqAEOAAAAAAAAAADa2traAAAAAAAAAAAFAAAAAAAAAAAAAAAptQYAAAAAAAAAAAAAAAAA8HNMAPBzTAAAAAAAAAAAAP////8AAAAAAAAAAAAAAAAAAAAAFHRMABR0TAAAAAAAIHRMACB0TAAAAAAAAAAAAAAAAAAAAAAA'}"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\UNCAsIntranet",
            "Value": "0"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\AutoDetect",
            "Value": "1"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count\\{7P5N40RS-N0SO-4OSP-874N-P0S2R0O9SN8R}\\Nqbor\\Ernqre 9.0\\Ernqre\\NpebEq32.rkr",
            "Value": "{'type': 'b64_struct', 'data': 'AAAAAAAAAAABAAAAAAAAAAAAgL8AAIC/AACAvwAAgL8AAIC/AACAvwAAgL8AAIC/AACAvwAAgL//////AAAAAAAAAAAAAAAA'}"
        },
        {
            "Name": null,
            "Path": "\\REGISTRY\\USER\\S-1-5-21-3926359194-3103936542-680984010-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count\\HRZR_PGYFRFFVBA",
            "Value": "{'type': 'b64_struct', 'data': 'AAAAALoAAABhAQAAVElSABAAAAAVAAAAL0cCAE0AaQBjAHIAbwBzAG8AZgB0AC4ASQBuAHQAZQByAG4AZQB0AEUAeABwAGwAbwByAGUAcgAuAEQAZQBmAGEAdQBsAHQAAAAAAAAAAAAAAAAAAAAAACMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqDB4CsOkGAhMAHgLiCx4Cb6m4dgYAAAAFAAAA4gseAjC1HgJU6QYC6Kq4dqECAQ5I6QYCTOsGAjC1HgIAAAAABQAAAAEAAAD8gfJ0DOgGAqECAQ7Q6QYC7eDodqRgGAD+////i43sdhCL7HYBAAAAAQAAAAAAAAD86QYCxOkGAuDpBgJshwN1AQAAAAAAAAD86QYCf4cDdWcbROsAAAAAZO8GAgIAAAAAAAAAwFS4dqECAQ4AAAAAAABLbaTpBgILAAAAQO4GAkDuBgL46QYCCwAAAFDuBgJQ7gYCCOoGAiFSvXYK5aICyv6iAgsAAABQ7gYC'}"
        }
    ],
    "URL": {
        "Data": "http://super.esu.as/wp-content/themes/twentyeleven/inc/images/msg.jpg"
    }
}
```

#### Human Readable Output

>### Analysis F2118597
>|Analyzed|DumpExists|ID|Internet-connection|MD5|Name|Probability|Result|SHA1|SHA256|Score|Size|Started|Status|Type|Verdict|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-05-07 10:29:42 | true | F2118597 | Available | ba9fe2cb8ee2421ea24a55306ce9d923 | link.pdf | 64.80% | true | 44b3f79dfd7c5861501a19a3bac89f544c7ff815 | 0d1b77c84c68c50932e28c3462a1962916abbbebb456ce654751ab401aa37697 | 24.6 | 36375 | 2020-05-07 10:27:30 | Finished | PDF document, version 1.7 | Malicious |


### polygon-export-report
***
Export an archive with TDS Polygon report to War Room


#### Base Command

`polygon-export-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tds_analysis_id | Analysis ID in TDS | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | The report file name | 
| InfoFile.EntryID | string | Report file ID in Demisto | 
| InfoFile.Size | number | The report size | 
| InfoFile.Type | string | The report file type | 
| InfoFile.Info | string | The report file info | 


#### Command Example
```!polygon-export-report tds_analysis_id=F2118597```

#### Context Example
```
{
    "InfoFile": {
        "EntryID": "178@2d0823ab-618b-43e8-83e7-515302bedcec",
        "Extension": "tar",
        "Info": "tar",
        "Name": "report.tar",
        "Size": 5072402,
        "Type": "gzip compressed data, last modified: Mon May 25 12:45:01 2020, max compression"
    }
}
```

#### Human Readable Output



### polygon-export-pcap
***
Network activity dump export


#### Base Command

`polygon-export-pcap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tds_analysis_id | Analysis ID in TDS | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | The dump file name | 
| InfoFile.EntryID | string | The dump file ID in Demisto | 
| InfoFile.Size | number | The dump file size | 
| InfoFile.Type | string | The dump file type | 
| InfoFile.Info | unknown | The dump file info | 


#### Command Example
```!polygon-export-pcap tds_analysis_id=F2118597```

#### Context Example
```
{
    "InfoFile": {
        "EntryID": "186@2d0823ab-618b-43e8-83e7-515302bedcec",
        "Extension": "pcap",
        "Info": "pcap",
        "Name": "dump.pcap",
        "Size": 3655,
        "Type": "tcpdump capture file (little-endian) - version 2.4 (Ethernet, capture length 262144)"
    }
}
```

#### Human Readable Output



### polygon-export-video
***
Screen activity video export


#### Base Command

`polygon-export-video`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tds_analysis_id | Analysis ID in TDS | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | The video file name | 
| InfoFile.EntryID | string | The video file ID in Demisto | 
| InfoFile.Size | number | The video file size | 
| InfoFile.Type | string | The video file type | 
| InfoFile.Info | string | The video file info | 


#### Command Example
```!polygon-export-video tds_analysis_id=F2118597```

#### Context Example
```
{
    "InfoFile": {
        "EntryID": "182@2d0823ab-618b-43e8-83e7-515302bedcec",
        "Extension": "webm",
        "Info": "webm",
        "Name": "video.webm",
        "Size": 79290,
        "Type": "WebM"
    }
}
```

#### Human Readable Output



### file
***
Check file reputation


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hash (MD5, SHA1, SHA256) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | string | The MD5 hash of the file | 
| File.SHA1 | string | The SHA1 hash of the file | 
| File.SHA256 | string | The SHA256 hash of the file | 
| File.Malicious.Vendor | string | The vendor that reported the file as malicious | 
| File.Malicious.Description | string | A description explaining why the file was determined to be malicious | 
| DBotScore.Indicator | string | The indicator that was tested | 
| DBotScore.Type | string | The indicator type | 
| DBotScore.Vendor | string | The vendor that reported the file as malicious | 
| DBotScore.Score | number | Malicious score | 
| Polygon.Analysis.Score | number | Malware score in Polygon | 
| Polygon.Analysis.MD5 | string | The MD5 hash of the file | 
| Polygon.Analysis.SHA1 | string | The SHA1 hash of the file | 
| Polygon.Analysis.SHA256 | string | The SHA256 hash of the file | 
| Polygon.Analysis.Found | bool | File was found in cloud or not | 
| Polygon.Analysis.Verdict | bool | Polygon verdict for file | 
| Polygon.Analysis.Malware-families | string | Malware families | 


#### Command Example
```!file file=eb57446af5846faa28a726a8b7d43ce5a7fcbd55```

#### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "eb57446af5846faa28a726a8b7d43ce5a7fcbd55",
            "Score": 3,
            "Type": "file",
            "Vendor": "Group-IB TDS Polygon"
        }
    ],
    "File": {
        "Malicious": {
            "Description": "TDS Polygon score: 24.0",
            "Vendor": "Group-IB TDS Polygon"
        },
        "SHA1": "eb57446af5846faa28a726a8b7d43ce5a7fcbd55"
    },
    "Polygon": {
        "Analysis": {
            "Found": true,
            "Malware-families": [],
            "SHA1": "eb57446af5846faa28a726a8b7d43ce5a7fcbd55",
            "Score": 24,
            "Verdict": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|Found|Malware-families|SHA1|Score|Verdict|
>|---|---|---|---|---|
>| true |  | eb57446af5846faa28a726a8b7d43ce5a7fcbd55 | 24.0 | true |

