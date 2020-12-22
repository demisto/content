
## Configure Cymulate on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Cymulate.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __x-token__
    * __Fetch incidents__
    * __Incident type__
    * __Show only 'penatrated' incidents__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. cymulate_get_incident_info
### 1. cymulate_get_incident_info
---
This commands return full cymulate's incidents information
##### Base Command

`cymulate_get_incident_info`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attack_id | The attack unique identifier | Required |
| incident_id | The incident unique identifier | Required |
| module_type | The Cymulate module_type | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.Incident.Payload | String | The Cymulatepayload that generated this incident |
| Cymulate.Incident.Name | String | The name of the incident |
| Cymulate.Incident.Status | String | The attack status |
| Cymulate.Incident.Attack_Type | String | The incident Attack_Type |
| Cymulate.Incident.Attack_Vector | String | The incident ID |
| Cymulate.Incident.Timestamp | String | The incident ID |
| Cymulate.Incident.Attack_Payload | String | The incident ID |
| Cymulate.Incident.Md5 | String | The incident ID |
| Cymulate.Incident.Mitigation | String | The incident ID |
| Cymulate.Incident.Module | String | The incident ID |
| Cymulate.Incident.Penetration_Vector | String | The incident ID |
| Cymulate.Incident.Sha1 | String | The incident ID |
| Cymulate.Incident.Sha256 | String | The incident ID |

##### Command Example
```!cymulate_get_incident_info attack_id="5e71e8cc7df91d6b4d460943" incident_id="9bc6591182ca40f3a3bfb3b46e3be025" module_type="IMMEDIATE_THREATS"```

##### Context Example
```
{
    "data": [
        {
            "Attack_Type": "Antivirus",
            "Status": "Penetrated",
            "Sha1": "18e4feb988cb95d71d81e1964aa6280e22361b9f",
            "Description": "New malware created by Chinese-backed Winnti Group has been discovered by researchers at ESET while being used to gain persistence on Microsoft SQL Server (MSSQL) systems.\r\n\r\nThe new malicious tool dubbed skip-2.0 can be used by the attackers to backdoor MSSQL Server 11 and 12 servers, enabling them to connect to any account on the server using a so-called \"magic password\" and hide their activity from the security logs.\r\n\r\nThis backdoor allows the attacker not only to gain persistence in the victim's MSSQL Server through the use of a special password, but also to remain undetected thanks to the multiple log and event publishing mechanisms that are disabled when that password is used.\r\n\r\nThe Winnti Group is an umbrella term used as the name of a collective of Chinese state-backed hacking groups (tracked as Blackfly and Suckfly by Symantec, Wicked Panda by CrowdStrike, BARIUM by Microsoft, APT41 by FireEye) sharing the same malicious tools that have been in use since around 2011.\r\n\r\nThat is when Kaspersky found the hackers' Winnti Trojan on a large number of compromised gaming systems after it got delivered via a game's official update server.\r\n\r\nThe new backdoor, skip-2.0 shares some traits with other Winnti Group malware, in particular, with the PortReuse and ShadowPad backdoors.\r\n\r\nPortReuse, a modular Windows backdoor, was used by the Winnti hackers in an attack targeting the servers of a high-profile Asian mobile software and hardware manufacturer.\r\n\r\nAlso, PortReuse is a network implant that injects itself into a process that is already listening on a network port and waits for an incoming magic packet to trigger the malicious code.\r\n\r\nShadowPad is another Winnti backdoor used by the group as part of a supply chain attack from 2017 that impacted NetSarang, a Soth Korean maker of network connectivity solutions, when the hacking group successfully infected the company's server management software with the backdoor.\r\n\r\nAll three backdoors use the same VMProtected launcher and the group's custom malware packer and, to top it all off, also share multiple other similarities with several other tools associated with the threat group's past operations.\r\n\r\nOnce dropped on an already compromised MSSQL server, the skip-2.0 backdoor proceeds to inject its malicious code within the sqlserv.exe process via the sqllang.dll, hooking multiple functions used for logging an authentication.\r\n\r\nThis allows the malware to bypass the server's built-in authentication mechanism and thus allow its operators to log in even though the account password they entered does not match.\r\n\r\nThis function's hook checks whether the password provided by the user matches the magic password, in that case, the original function will not be called and the hook will return 0, allowing the connection even though the correct password was not provided.\r\n\r\nSkip-2.0 was tested against multiple MSSQL Server versions and found that log in successfully using the special password only with MSSQL Server 11 and 12 was possible.\r\n\r\nWhile MSSQL Server 11 and 12 are not the most recently released versions - they were released in 2012 and 2014 - and they are the most common ones.\r\n\r\nThe skip-2.0 backdoor is an interesting addition to the Winnti Group's arsenal, sharing a great deal of similarities with the group's already known toolset, and allowing the attacker to achieve persistence on an MSSQL Server.\r\n\r\nConsidering that administrative privileges are required for installing the hooks, skip-2.0 must be used on already compromised MSSQL Servers to achieve persistence and stealthiness.",
            "Penetration_Vector": "Dll",
            "Timestamp": "25/12/2019 15:03:15",
            "Related_URLS": "N/A",
            "Attack_Payload": "Skip1Dll.dll",
            "Module": "Immediate Threats Intelligence",
            "Attack_Vector": "Endpoint Security",
            "Mitigation": "Verify that your AV, EPP, EDR, Email Gateway, Web Gateway are up to date.\r\nSearch for malicious traffic using your SIEM based on the IOC's provided.\r\nWhere applicable, block the relevant hashes.",
            "Related_Email_Addresses": "N/A",
            "Name": "Chinese Hackers Use New Malware to Backdoor Microsoft SQL Servers",
            "Sha256": "095785392b61011a861d1106d7e9bb9f34b86877c0fb075d05cca224132238cb",
            "ID": "cd61447e5fc76ebd2a35de651f211ff9",
            "Md5": "30d9ac12711d52a34f87cfa5cea0c85a"
        },
        {
            "Attack_Type": "Antivirus",
            "Status": "Penetrated",
            "Sha1": "4af89296a15c1ea9068a279e05cc4a41b967c956",
            "Description": "New malware created by Chinese-backed Winnti Group has been discovered by researchers at ESET while being used to gain persistence on Microsoft SQL Server (MSSQL) systems.\r\n\r\nThe new malicious tool dubbed skip-2.0 can be used by the attackers to backdoor MSSQL Server 11 and 12 servers, enabling them to connect to any account on the server using a so-called \"magic password\" and hide their activity from the security logs.\r\n\r\nThis backdoor allows the attacker not only to gain persistence in the victim's MSSQL Server through the use of a special password, but also to remain undetected thanks to the multiple log and event publishing mechanisms that are disabled when that password is used.\r\n\r\nThe Winnti Group is an umbrella term used as the name of a collective of Chinese state-backed hacking groups (tracked as Blackfly and Suckfly by Symantec, Wicked Panda by CrowdStrike, BARIUM by Microsoft, APT41 by FireEye) sharing the same malicious tools that have been in use since around 2011.\r\n\r\nThat is when Kaspersky found the hackers' Winnti Trojan on a large number of compromised gaming systems after it got delivered via a game's official update server.\r\n\r\nThe new backdoor, skip-2.0 shares some traits with other Winnti Group malware, in particular, with the PortReuse and ShadowPad backdoors.\r\n\r\nPortReuse, a modular Windows backdoor, was used by the Winnti hackers in an attack targeting the servers of a high-profile Asian mobile software and hardware manufacturer.\r\n\r\nAlso, PortReuse is a network implant that injects itself into a process that is already listening on a network port and waits for an incoming magic packet to trigger the malicious code.\r\n\r\nShadowPad is another Winnti backdoor used by the group as part of a supply chain attack from 2017 that impacted NetSarang, a Soth Korean maker of network connectivity solutions, when the hacking group successfully infected the company's server management software with the backdoor.\r\n\r\nAll three backdoors use the same VMProtected launcher and the group's custom malware packer and, to top it all off, also share multiple other similarities with several other tools associated with the threat group's past operations.\r\n\r\nOnce dropped on an already compromised MSSQL server, the skip-2.0 backdoor proceeds to inject its malicious code within the sqlserv.exe process via the sqllang.dll, hooking multiple functions used for logging an authentication.\r\n\r\nThis allows the malware to bypass the server's built-in authentication mechanism and thus allow its operators to log in even though the account password they entered does not match.\r\n\r\nThis function's hook checks whether the password provided by the user matches the magic password, in that case, the original function will not be called and the hook will return 0, allowing the connection even though the correct password was not provided.\r\n\r\nSkip-2.0 was tested against multiple MSSQL Server versions and found that log in successfully using the special password only with MSSQL Server 11 and 12 was possible.\r\n\r\nWhile MSSQL Server 11 and 12 are not the most recently released versions - they were released in 2012 and 2014 - and they are the most common ones.\r\n\r\nThe skip-2.0 backdoor is an interesting addition to the Winnti Group's arsenal, sharing a great deal of similarities with the group's already known toolset, and allowing the attacker to achieve persistence on an MSSQL Server.\r\n\r\nConsidering that administrative privileges are required for installing the hooks, skip-2.0 must be used on already compromised MSSQL Servers to achieve persistence and stealthiness.",
            "Penetration_Vector": "Dll",
            "Timestamp": "25/12/2019 15:03:14",
            "Related_URLS": "N/A",
            "Attack_Payload": "Skip2Dll.dll",
            "Module": "Immediate Threats Intelligence",
            "Attack_Vector": "Endpoint Security",
            "Mitigation": "Verify that your AV, EPP, EDR, Email Gateway, Web Gateway are up to date.\r\nSearch for malicious traffic using your SIEM based on the IOC's provided.\r\nWhere applicable, block the relevant hashes.",
            "Related_Email_Addresses": "N/A",
            "Name": "Chinese Hackers Use New Malware to Backdoor Microsoft SQL Servers",
            "Sha256": "2518457b6a4812af5084f1f8a3025df5ce3ca3b7721c08c628cab1af415b0c99",
            "ID": "1595f452a74e5743fae63c8063eed9e6",
            "Md5": "64bba3f138d4956cfed166835ed8168f"
        },
        {
            "Attack_Type": "Files",
            "Status": "Penetrated",
            "Sha1": "18e4feb988cb95d71d81e1964aa6280e22361b9f",
            "Description": "New malware created by Chinese-backed Winnti Group has been discovered by researchers at ESET while being used to gain persistence on Microsoft SQL Server (MSSQL) systems.\r\n\r\nThe new malicious tool dubbed skip-2.0 can be used by the attackers to backdoor MSSQL Server 11 and 12 servers, enabling them to connect to any account on the server using a so-called \"magic password\" and hide their activity from the security logs.\r\n\r\nThis backdoor allows the attacker not only to gain persistence in the victim's MSSQL Server through the use of a special password, but also to remain undetected thanks to the multiple log and event publishing mechanisms that are disabled when that password is used.\r\n\r\nThe Winnti Group is an umbrella term used as the name of a collective of Chinese state-backed hacking groups (tracked as Blackfly and Suckfly by Symantec, Wicked Panda by CrowdStrike, BARIUM by Microsoft, APT41 by FireEye) sharing the same malicious tools that have been in use since around 2011.\r\n\r\nThat is when Kaspersky found the hackers' Winnti Trojan on a large number of compromised gaming systems after it got delivered via a game's official update server.\r\n\r\nThe new backdoor, skip-2.0 shares some traits with other Winnti Group malware, in particular, with the PortReuse and ShadowPad backdoors.\r\n\r\nPortReuse, a modular Windows backdoor, was used by the Winnti hackers in an attack targeting the servers of a high-profile Asian mobile software and hardware manufacturer.\r\n\r\nAlso, PortReuse is a network implant that injects itself into a process that is already listening on a network port and waits for an incoming magic packet to trigger the malicious code.\r\n\r\nShadowPad is another Winnti backdoor used by the group as part of a supply chain attack from 2017 that impacted NetSarang, a Soth Korean maker of network connectivity solutions, when the hacking group successfully infected the company's server management software with the backdoor.\r\n\r\nAll three backdoors use the same VMProtected launcher and the group's custom malware packer and, to top it all off, also share multiple other similarities with several other tools associated with the threat group's past operations.\r\n\r\nOnce dropped on an already compromised MSSQL server, the skip-2.0 backdoor proceeds to inject its malicious code within the sqlserv.exe process via the sqllang.dll, hooking multiple functions used for logging an authentication.\r\n\r\nThis allows the malware to bypass the server's built-in authentication mechanism and thus allow its operators to log in even though the account password they entered does not match.\r\n\r\nThis function's hook checks whether the password provided by the user matches the magic password, in that case, the original function will not be called and the hook will return 0, allowing the connection even though the correct password was not provided.\r\n\r\nSkip-2.0 was tested against multiple MSSQL Server versions and found that log in successfully using the special password only with MSSQL Server 11 and 12 was possible.\r\n\r\nWhile MSSQL Server 11 and 12 are not the most recently released versions - they were released in 2012 and 2014 - and they are the most common ones.\r\n\r\nThe skip-2.0 backdoor is an interesting addition to the Winnti Group's arsenal, sharing a great deal of similarities with the group's already known toolset, and allowing the attacker to achieve persistence on an MSSQL Server.\r\n\r\nConsidering that administrative privileges are required for installing the hooks, skip-2.0 must be used on already compromised MSSQL Servers to achieve persistence and stealthiness.",
            "Penetration_Vector": "",
            "Timestamp": "25/12/2019 15:01:29",
            "Related_URLS": "N/A",
            "Attack_Payload": "https://cym-files-download.s3.eu-west-1.amazonaws.com/hotfiles/manual_upload/chinesehackersusenewmalwaretobackdoormicrosoftsqlservers/Skip1Dll.dll?AWSAccessKeyId=AKIAJPJC2Q3D5GWFTK3Q&Expires=1577278973&Signature=0MA9Dw9GHPbOdlHhivQ7U5oKLGA%3D",
            "Module": "Immediate Threats Intelligence",
            "Attack_Vector": "Web Gateway",
            "Mitigation": "Verify that your AV, EPP, EDR, Email Gateway, Web Gateway are up to date.\r\nSearch for malicious traffic using your SIEM based on the IOC's provided.\r\nWhere applicable, block the relevant hashes.",
            "Related_Email_Addresses": "N/A",
            "Name": "Chinese Hackers Use New Malware to Backdoor Microsoft SQL Servers",
            "Sha256": "095785392b61011a861d1106d7e9bb9f34b86877c0fb075d05cca224132238cb",
            "ID": "dc2a1e9b835b5caf685960bb7d9bdfea",
            "Md5": "30d9ac12711d52a34f87cfa5cea0c85a"
        },
        {
            "Attack_Type": "Files",
            "Status": "Penetrated",
            "Sha1": "4af89296a15c1ea9068a279e05cc4a41b967c956",
            "Description": "New malware created by Chinese-backed Winnti Group has been discovered by researchers at ESET while being used to gain persistence on Microsoft SQL Server (MSSQL) systems.\r\n\r\nThe new malicious tool dubbed skip-2.0 can be used by the attackers to backdoor MSSQL Server 11 and 12 servers, enabling them to connect to any account on the server using a so-called \"magic password\" and hide their activity from the security logs.\r\n\r\nThis backdoor allows the attacker not only to gain persistence in the victim's MSSQL Server through the use of a special password, but also to remain undetected thanks to the multiple log and event publishing mechanisms that are disabled when that password is used.\r\n\r\nThe Winnti Group is an umbrella term used as the name of a collective of Chinese state-backed hacking groups (tracked as Blackfly and Suckfly by Symantec, Wicked Panda by CrowdStrike, BARIUM by Microsoft, APT41 by FireEye) sharing the same malicious tools that have been in use since around 2011.\r\n\r\nThat is when Kaspersky found the hackers' Winnti Trojan on a large number of compromised gaming systems after it got delivered via a game's official update server.\r\n\r\nThe new backdoor, skip-2.0 shares some traits with other Winnti Group malware, in particular, with the PortReuse and ShadowPad backdoors.\r\n\r\nPortReuse, a modular Windows backdoor, was used by the Winnti hackers in an attack targeting the servers of a high-profile Asian mobile software and hardware manufacturer.\r\n\r\nAlso, PortReuse is a network implant that injects itself into a process that is already listening on a network port and waits for an incoming magic packet to trigger the malicious code.\r\n\r\nShadowPad is another Winnti backdoor used by the group as part of a supply chain attack from 2017 that impacted NetSarang, a Soth Korean maker of network connectivity solutions, when the hacking group successfully infected the company's server management software with the backdoor.\r\n\r\nAll three backdoors use the same VMProtected launcher and the group's custom malware packer and, to top it all off, also share multiple other similarities with several other tools associated with the threat group's past operations.\r\n\r\nOnce dropped on an already compromised MSSQL server, the skip-2.0 backdoor proceeds to inject its malicious code within the sqlserv.exe process via the sqllang.dll, hooking multiple functions used for logging an authentication.\r\n\r\nThis allows the malware to bypass the server's built-in authentication mechanism and thus allow its operators to log in even though the account password they entered does not match.\r\n\r\nThis function's hook checks whether the password provided by the user matches the magic password, in that case, the original function will not be called and the hook will return 0, allowing the connection even though the correct password was not provided.\r\n\r\nSkip-2.0 was tested against multiple MSSQL Server versions and found that log in successfully using the special password only with MSSQL Server 11 and 12 was possible.\r\n\r\nWhile MSSQL Server 11 and 12 are not the most recently released versions - they were released in 2012 and 2014 - and they are the most common ones.\r\n\r\nThe skip-2.0 backdoor is an interesting addition to the Winnti Group's arsenal, sharing a great deal of similarities with the group's already known toolset, and allowing the attacker to achieve persistence on an MSSQL Server.\r\n\r\nConsidering that administrative privileges are required for installing the hooks, skip-2.0 must be used on already compromised MSSQL Servers to achieve persistence and stealthiness.",
            "Penetration_Vector": "",
            "Timestamp": "25/12/2019 15:01:29",
            "Related_URLS": "N/A",
            "Attack_Payload": "https://cym-files-download.s3.eu-west-1.amazonaws.com/hotfiles/manual_upload/chinesehackersusenewmalwaretobackdoormicrosoftsqlservers/Skip2Dll.dll?AWSAccessKeyId=AKIAJPJC2Q3D5GWFTK3Q&Expires=1577278969&Signature=s9U7QyaNvF%2Fpul0C6bkWc1srCsQ%3D",
            "Module": "Immediate Threats Intelligence",
            "Attack_Vector": "Web Gateway",
            "Mitigation": "Verify that your AV, EPP, EDR, Email Gateway, Web Gateway are up to date.\r\nSearch for malicious traffic using your SIEM based on the IOC's provided.\r\nWhere applicable, block the relevant hashes.",
            "Related_Email_Addresses": "N/A",
            "Name": "Chinese Hackers Use New Malware to Backdoor Microsoft SQL Servers",
            "Sha256": "2518457b6a4812af5084f1f8a3025df5ce3ca3b7721c08c628cab1af415b0c99",
            "ID": "b2aa30c32e06762d09bac485d7c490a5",
            "Md5": "64bba3f138d4956cfed166835ed8168f"
        }
    ]
}
```

##### Human Readable Output
### Cymulate Resutls
|ID|Name|Status|Attack Type|Attack Vector|Timestamp|
|---|---|---|---|---|---|
| cd61447e5fc76ebd2a35de651f211ff9 | Chinese Hackers Use New Malware to Backdoor Microsoft SQL Servers | Penetrated | Antivirus | Endpoint Security | 25/12/2019 15:03:15 |
| 1595f452a74e5743fae63c8063eed9e6 | Chinese Hackers Use New Malware to Backdoor Microsoft SQL Servers | Penetrated | Antivirus | Endpoint Security | 25/12/2019 15:03:14 |
| dc2a1e9b835b5caf685960bb7d9bdfea | Chinese Hackers Use New Malware to Backdoor Microsoft SQL Servers | Penetrated | Files | Web Gateway | 25/12/2019 15:01:29 |
| b2aa30c32e06762d09bac485d7c490a5 | Chinese Hackers Use New Malware to Backdoor Microsoft SQL Servers | Penetrated | Files | Web Gateway | 25/12/2019 15:01:29 |

