import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import base64
import ipaddress
import json
import re
from typing import Any


KNOWN_POWERSHELL_COMMANDS_BREAKPOINTS = [
    "[Convert]::FromBase64String",
    "::ASCII",
    "Replace",
    "ForEach-Object",
    "powershell",
    "New-Object",
    " ",
    "Windows.Forms",
]


PATTERNS = {
    "powershell_suspicious_patterns": [
        {
            "pattern": r"%\w+:~\d+,\d+%",
            "mitreid": "T1027",
            "technique": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
        },
        {
            "pattern": r"(\[char\[[^\]]+\]\]){3,}",
            "mitreid": "T1027",
            "technique": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
        },
        {
            "pattern": r"(cmd\.exe.*\/V:ON|setlocal.*EnableDelayedExpansion)",
            "mitreid": "T1059.003",
            "technique": "Windows Command Shell",
            "tactic": "Execution",
        },
        {
            "pattern": r"\$(env:[a-zA-Z]+)\[\d+\]\s*\+\s*\$env:[a-zA-Z]+\[\d+\]",
            "mitreid": "T1027",
            "technique": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
        },
        {
            "pattern": r"\.AcceptTcpClient\(",
            "mitreid": "T1071",
            "technique": "Application Layer Protocol",
            "tactic": "Command and Control"
        },
        {
            "pattern": r"\.Connect\(",
            "mitreid": "T1071",
            "technique": "Application Layer Protocol",
            "tactic": "Command and Control"
        },
        {
            "pattern": r"\.ConnectAsync\(",
            "mitreid": "T1071",
            "technique": "Application Layer Protocol",
            "tactic": "Command and Control"
        },
        {
            "pattern": r"\.Receive\(",
            "mitreid": "T1071",
            "technique": "Application Layer Protocol",
            "tactic": "Command and Control"
        },
        {
            "pattern": r"\.Send\(",
            "mitreid": "T1071",
            "technique": "Application Layer Protocol",
            "tactic": "Command and Control"
        },
        {
            "pattern": r"\[char\[\]\]\s*\([\d,\s]+\)|-join\s*\(\s*\[char\[\]\][^\]]+\)",
            "mitreid": "T1027",
            "technique": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
        },
        {
            "pattern": r"\b(?:Invoke\-Expression|IEX)\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"},
        {
            "pattern": r"\b(?:Invoke\-WebRequest|\biwr\b)",
            "mitreid": "T1105",
            "technique": "Ingress Tool Transfer",
            "tactic": "Initial Access"
        },
        {
            "pattern": r"\b(?:Upload|Download)String\b",
            "mitreid": "T1105",
            "technique": "Ingress Tool Transfer",
            "tactic": "Initial Access"
        },
        {
            "pattern": r"\bInvoke\-RestMethod.*-Uri\b",
            "mitreid": "T1105", 
            "technique": "Ingress Tool Transfer",
            "tactic": "Initial Access"
        },
        {
            "pattern": r"\bNew\-Object\s+(?:System\.)?Net\.WebClient\b",
            "mitreid": "T1105",
            "technique": "Ingress Tool Transfer",
            "tactic": "Initial Access",
        },
        {
            "pattern": r"\bNew\-Object\s+Net\.Sockets\.(?:TcpClient|UdpClient)\b",
            "mitreid": "T1071",
            "technique": "Application Layer Protocol",
            "tactic": "Command and Control",
        },
        {
            "pattern": r"\bOutFile\b",
            "mitreid": "T1105", 
            "technique": "Ingress Tool Transfer", 
            "tactic": "Initial Access"
        },
        {
            "pattern": r"\bSystem\.Net\.Sockets\.Tcp(?:Client|listener)\b",
            "mitreid": "T1071",
            "technique": "Application Layer Protocol",
            "tactic": "Command and Control",
        },
        {
            "pattern": r"\bSystem\.Net\.WebSockets\.ClientWebSocket\b",
            "mitreid": "T1071",
            "technique": "Application Layer Protocol",
            "tactic": "Command and Control",
        },
        {
            "pattern": r"for\s+%?\w+%?\s+in\s*\([^)]{50,}\)",
            "mitreid": "T1027",
            "technique": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
        },
        {
            "pattern": r"if\s+%?\w+%?\s+geq\s+\d+\s+call\s+%?\w+%?:~\d+%?",
            "mitreid": "T1027",
            "technique": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
        },
    ],

    "recon_commands": [
        {
            "pattern": r"\barp\b",
            "mitreid": "T1018",
            "technique": "Remote System Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\battrib\b",
            "mitreid": "T1083",
            "technique": "File and Directory Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bdir\b",
            "mitreid": "T1083",
            "technique": "File and Directory Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bfsutil\b",
            "mitreid": "T1083",
            "technique": "File and Directory Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bhostname\b",
            "mitreid": "T1082",
            "technique": "System Information Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bipconfig\b",
            "mitreid": "T1016",
            "technique": "System Network Configuration Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bnet\s+(?:group|localgroup|user)\b",
            "mitreid": "T1087",
            "technique": "Account Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bnetstat\b",
            "mitreid": "T1049",
            "technique": "System Network Connections Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bnslookup\b",
            "mitreid": "T1018",
            "technique": "Remote System Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bping\b",
            "mitreid": "T1018",
            "technique": "Remote System Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bquery\s+user\b",
            "mitreid": "T1033",
            "technique": "System Owner/User Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\breg\s+query\b",
            "mitreid": "T1012",
            "technique": "Query Registry",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\broute\s+print\b",
            "mitreid": "T1016",
            "technique": "System Network Configuration Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bsc\s+query\b",
            "mitreid": "T1007",
            "technique": "System Service Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bsysteminfo\b",
            "mitreid": "T1082",
            "technique": "System Information Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\btasklist\b",
            "mitreid": "T1057",
            "technique": "Process Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\btracert\b",
            "mitreid": "T1018",
            "technique": "Remote System Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\btree\b",
            "mitreid": "T1083",
            "technique": "File and Directory Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bwhoami\b",
            "mitreid": "T1033",
            "technique": "System Owner/User Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bwmic\s+process\s+list\b",
            "mitreid": "T1057",
            "technique": "Process Discovery",
            "tactic": "Discovery"
        },
    ],

    "macos_recon_commmands": [
        {
            "pattern": r"\b(ifconfig)\b",
            "mitreid": "T1016",
            "technique": "System Network Configuration Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(netstat)\b",
            "mitreid": "T1049",
            "technique": "System Network Connections Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(dscl)\b",
            "mitreid": "T1087.002",
            "technique": "Domain Account",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(system_profiler)\b",
            "mitreid": "T1082",
            "technique": "System Information Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(sw_vers)\b",
            "mitreid": "T1082",
            "technique": "System Information Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(whoami)\b",
            "mitreid": "T1033",
            "technique": "System Owner/User Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(ps\s+aux)\b",
            "mitreid": "T1057",
            "technique": "Process Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(ls\s+-la)\b",
            "mitreid": "T1083",
            "technique": "File and Directory Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(find)\b",
            "mitreid": "T1083",
            "technique": "File and Directory Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(mdfind)\b",
            "mitreid": "T1083",
            "technique": "File and Directory Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(lsof)\b",
            "mitreid": "T1007",
            "technique": "System Service Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(kextstat)\b",
            "mitreid": "T1082",
            "technique": "System Information Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(ioreg)\b",
            "mitreid": "T1082",
            "technique": "System Information Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(arp\s+-a)\b",
            "mitreid": "T1018",
            "technique": "Remote System Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(ping)\b",
            "mitreid": "T1018",
            "technique": "Remote System Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(traceroute)\b",
            "mitreid": "T1018",
            "technique": "Remote System Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(nslookup)\b",
            "mitreid": "T1018",
            "technique": "Remote System Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(dig)\b",
            "mitreid": "T1018",
            "technique": "Remote System Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(host)\b",
            "mitreid": "T1018",
            "technique": "Remote System Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\b(ssh)\b",
            "mitreid": "T1021.004",
            "technique": "SSH",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\b(scp)\b",
            "mitreid": "T1021.004",
            "technique": "SSH",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\b(sftp)\b",
            "mitreid": "T1021.004",
            "technique": "SSH",
            "tactic": "Lateral Movement"
        }
    ],

    "windows_temp_paths": [
        {"pattern": r"%(?:TEMP|TMP)%", "mitreid": "T1074", "technique": "Data Staged", "tactic": "Exfiltration"},
        {"pattern": r"\bC:\\(?:Windows\\System32\\)?Temp\b",
         "mitreid": "T1074",
         "technique": "Data Staged",
         "tactic": "Exfiltration"
        },
        {"pattern": r"\\AppData\\Local\\Temp\b",
         "mitreid": "T1074",
         "technique": "Data Staged",
         "tactic": "Exfiltration"
        },
        {"pattern": r"\\ProgramData\\Microsoft\\Windows\\Caches\b",
         "mitreid": "T1074",
         "technique": "Data Staged",
         "tactic": "Exfiltration"
        },
        {"pattern": r"\\Users\\Public\\Public\s+Downloads\b",
         "mitreid": "T1074",
         "technique": "Data Staged",
         "tactic": "Exfiltration"
        },
        {"pattern": r"\\Windows\\(?:System32\\spool|Tasks|debug|Temp)\b",
         "mitreid": "T1074",
         "technique": "Data Staged",
         "tactic": "Exfiltration"
        },
    ],

    "amsi_techniques": [
        {"pattern": r"\bamsiInitFailed\b",
         "mitreid": "T1562.001",
         "technique": "Disable or Modify Tools",
         "tactic": "Defense Evasion"
        },
        {"pattern": r"\bAmsiScanBuffer\(\)",
         "mitreid": "T1562.001",
         "technique": "Disable or Modify Tools",
         "tactic": "Defense Evasion"
        },
        {"pattern": r"\bLoadLibrary\(\"amsi\.dll\"\)",
         "mitreid": "T1562.001",
         "technique": "Disable or Modify Tools",
         "tactic": "Defense Evasion"
        },
        {"pattern": r"\bSystem\.Management\.Automation\.AmsiUtils\b",
         "mitreid": "T1562.001",
         "technique": "Disable or Modify Tools",
         "tactic": "Defense Evasion"
        },
    ],

    "lateral_movement": [
        {
            "pattern": r"\\\\[a-zA-Z0-9_.-]+\\C\$\b",
            "mitreid": "T1021.002",
            "technique": "SMB/Windows Admin Shares",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\b(?:cmd(?:\.exe)?)\s+(?=.*\/q)(?=.*\/c).*?((?:1>\s?.*?)?\s*2>&1)\b",
            "mitreid": "T1021.002",
            "technique": "SMB/Windows Admin Shares",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\bcopy\s+\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9$]+\b",
            "mitreid": "T1021.002",
            "technique": "SMB/Windows Admin Shares",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\bmstsc(\.exe)?",
            "mitreid": "T1021.001",
            "technique": "Remote Desktop Protocol",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\bnet use \\\\.*\\IPC\$\b",
            "mitreid": "T1021.002",
            "technique": "SMB/Windows Admin Shares",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\bpowershell.*(?:Enter-PSSession|Invoke\-Command)\s+-ComputerName\s+[a-zA-Z0-9_.-]+\s+-(?:Credential|ScriptBlock)\b",
            "mitreid": "T1021.006",
            "technique": "Windows Remote Management",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\bpsexec([.]exe)?",
            "mitreid": "T1570",
            "technique": "Lateral Tool Transfer",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\bpsexesvc[.](?:exe|log)\b",
            "mitreid": "T1570",
            "technique": "Lateral Tool Transfer",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\bssh.*?-o.*?StrictHostKeyChecking=no\b",
            "mitreid": "T1021.004",
            "technique": "SSH",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\bwmic\s+/node:\s*[a-zA-Z0-9_.-]+",
            "mitreid": "T1047",
            "technique": "Windows Management Instrumentation",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r'\bcrackmapexec\s+smb\s+[a-zA-Z0-9_.-]+\s+-u\s+[a-zA-Z0-9_.-]+\s+-p\s+[a-zA-Z0-9_.-]+\s+-x\s+\".*\"\b',
            "mitreid": "T1570",
            "technique": "Lateral Tool Transfer",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r'\bschtasks\s+/create\s+/tn\s+[a-zA-Z0-9_.-]+\s+/tr\s+\".*\"\s+/sc\s+[a-zA-Z]+\b',
            "mitreid": "T1053.005",
            "technique": "Scheduled Task",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r'\bwmiexec\.py\s+[a-zA-Z0-9_.-]+\s+\".*\"\b',
            "mitreid": "T1047",
            "technique": "Windows Management Instrumentation",
            "tactic": "Lateral Movement"
        },
    ],

    "malicious_commands": [
        {
            "pattern": r"\bb374k\.php\b",
            "mitreid": "T1505.003",
            "technique": "Web Shell",
            "tactic": "Initial Access"
        },
        {
            "pattern": r"\bbeacon\.exe\b",
            "mitreid": "T1059",
            "technique": "Command and Scripting Interpreter",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bbloodhound\.exe\b",
            "mitreid": "T1087",
            "technique": "Account Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bc99\.php\b",
            "mitreid": "T1505.003",
            "technique": "Web Shell",
            "tactic": "Initial Access"
        },
        {
            "pattern": r"\bchopper\.php\b",
            "mitreid": "T1505.003",
            "technique": "Web Shell",
            "tactic": "Initial Access"
        },
        {
            "pattern": r"\bcme\.exe\b",
            "mitreid": "T1021",
            "technique": "Remote Services",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\bcobaltstrike_beacon\.exe\b",
            "mitreid": "T1059",
            "technique": "Command and Scripting Interpreter",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bcovenant\.exe\b",
            "mitreid": "T1059",
            "technique": "Command and Scripting Interpreter",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bdarkcomet\.exe\b",
            "mitreid": "T1219",
            "technique": "Remote Access Software",
            "tactic": "Command and Control"
        },
        {
            "pattern": r"\beternalblue\.exe\b",
            "mitreid": "T1210",
            "technique": "Exploitation of Remote Services",
            "tactic": "Initial Access"
        },
        {
            "pattern": r"\beternalromance\.exe\b",
            "mitreid": "T1210",
            "technique": "Exploitation of Remote Services",
            "tactic": "Initial Access"
        },
        {
            "pattern": r"\bGetUserSPNs\.py\b",
            "mitreid": "T1558.003",
            "technique": "Kerberoasting",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bimpacket\-scripts\b",
            "mitreid": "T1021",
            "technique": "Remote Services",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\bInvoke\-(?:ReflectivePEInjection|Shellcode|Expression|WmiMethod|KickoffAtomicRunner|SMBExec|Obfuscation|"
            r"CradleCrafter|PSRemoting|TheHash)\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bkoadic\b",
            "mitreid": "T1059",
            "technique": "Command and Scripting Interpreter",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bLaZagne\.exe\b",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\blsassdump\.py\b",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bmeterpreter\.exe\b",
            "mitreid": "T1059",
            "technique": "Command and Scripting Interpreter",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bmimikatz\b",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bmsfconsole\b",
            "mitreid": "T1059",
            "technique": "Command and Scripting Interpreter",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bmsfvenom\b",
            "mitreid": "T1059",
            "technique": "Command and Scripting Interpreter",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bnanocore\.exe\b",
            "mitreid": "T1219",
            "technique": "Remote Access Software",
            "tactic": "Command and Control"
        },
        {
            "pattern": r"\bnjRAT\.exe\b",
            "mitreid": "T1219",
            "technique": "Remote Access Software",
            "tactic": "Command and Control"
        },
        {
            "pattern": r"\bPowerUp\.ps1\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bpowercat\.ps1\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bPowGoop\.ps1\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bprocdump\.exe\b",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bquasar\.exe\b",
            "mitreid": "T1219",
            "technique": "Remote Access Software",
            "tactic": "Command and Control"
        },
        {
            "pattern": r"\bresponder\.py\b",
            "mitreid": "T1557",
            "technique": "Man-in-the-Middle",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\brubeus\.exe\b",
            "mitreid": "T1558",
            "technique": "Steal or Forge Kerberos Tickets",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bseatbelt\.exe\b",
            "mitreid": "T1005",
            "technique": "Data from Local System",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bsharphound\.exe\b",
            "mitreid": "T1087",
            "technique": "Account Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bsharpview\.exe\b",
            "mitreid": "T1087",
            "technique": "Account Discovery",
            "tactic": "Discovery"
        },
        {
            "pattern": r"\bsmbexec\.py\b",
            "mitreid": "T1021.002",
            "technique": "SMB/Windows Admin Shares",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\bwinrm\.vbs\b",
            "mitreid": "T1021.006",
            "technique": "Windows Remote Management",
            "tactic": "Lateral Movement"
        },
        {
            "pattern": r"\bwso\.php\b",
            "mitreid": "T1505.003",
            "technique": "Web Shell",
            "tactic": "Initial Access"
        },
    ],

    "credentials_dumping": [
        {
            "pattern": r"\bGet\-Credential\b",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bInvoke\-Mimikatz\b",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\blsass\.dmp\b",
            "mitreid": "T1003.001",
            "technique": "LSASS Memory",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bMiniDumpWriteDump\b",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bntds\.dit\b",
            "mitreid": "T1003.003",
            "technique": "NTDS",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bntdsutil\.exe.*ntds.*create\b",
            "mitreid": "T1003.003",
            "technique": "NTDS",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bpowershell.*Invoke\-BloodHound.*-CollectionMethod.*",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bprocdump(\.exe)?\s+-ma\s+lsass\.exe\s+[a-zA-Z0-9_.-]+\.dmp",
            "mitreid": "T1003.001",
            "technique": "LSASS Memory",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bprocdump.*lsass\b",
            "mitreid": "T1003.001",
            "technique": "LSASS Memory",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bProcessHacker\b",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\breg\s+save\s+hklm\\(sam|system)\s+[a-zA-Z0-9_.-]+\.hive",
            "mitreid": "T1003.002",
            "technique": "Security Account Manager",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\brundll32(\.exe)?\s+comsvcs\.dll,\s+MiniDump\s+lsass\.exe\s+[a-zA-Z0-9_.-]+\.dmp.*",
            "mitreid": "T1003.001",
            "technique": "LSASS Memory",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\brundll32.*comsvcs\.dll\b",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bsecretsdump(\.py)?\s+.*domain/.*:.*@.*",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bsekurlsa\:\:",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\btasklist.*lsass\b",
            "mitreid": "T1003.001",
            "technique": "LSASS Memory",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\btaskmgr(\.exe)?\s+/create\s+/PID:\d+\s+/DumpFile:[a-zA-Z0-9_.-]+\.dmp",
            "mitreid": "T1003.001",
            "technique": "LSASS Memory",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bwce(\.exe)?\s+-o",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r"\bwmic\s+process\s+call\s+create.*(?:lsass|mimikatz)\b",
            "mitreid": "T1003",
            "technique": "OS Credential Dumping",
            "tactic": "Credential Access"
        },
        {
            "pattern": r'\bntdsutil(\.exe)?\s+".*ac i ntds.*" "ifm" "create full\s+[a-zA-Z]:\\.*"',
            "mitreid": "T1003.003",
            "technique": "NTDS",
            "tactic": "Credential Access"
        },
    ],

    "data_exfiltration": [
        {
            "pattern": r"\bcurl\s+-X\s+(POST|PUT)\s+-d\s+@[a-zA-Z0-9_.-]+\s+https?://[a-zA-Z0-9_.-]+/.*\b",
            "mitreid": "T1041",
            "technique": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bwget\s+--post-file=[a-zA-Z0-9_.-]+\s+https?://[a-zA-Z0-9_.-]+/.*\b",
            "mitreid": "T1041",
            "technique": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bscp\s+-r\s+[a-zA-Z0-9_.-]+\s+[a-zA-Z0-9_.-]+@.*:.*\b",
            "mitreid": "T1048",
            "technique": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bsftp\s+-b\s+[a-zA-Z0-9_.-]+\s+[a-zA-Z0-9_.-]+@.*\b",
            "mitreid": "T1048",
            "technique": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bftp\s+-s:[a-zA-Z0-9_.-]+\s+[a-zA-Z0-9_.-]+\b",
            "mitreid": "T1048.003",
            "technique": "Exfiltration Over Unencrypted Protocol",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\btftp\s+-i\s+[a-zA-Z0-9_.-]+\s+put\s+[a-zA-Z0-9_.-]+\b",
            "mitreid": "T1048.003",
            "technique": "Exfiltration Over Unencrypted Protocol",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bnetcat\s+[a-zA-Z0-9_.-]+\s+\d+\s+<\s+[a-zA-Z0-9_.-]+\b",
            "mitreid": "T1041",
            "technique": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bnc\s+[a-zA-Z0-9_.-]+\s+\d+\s+<\s+[a-zA-Z0-9_.-]+\b",
            "mitreid": "T1041",
            "technique": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bpowershell.*New-Object\s+System\.Net\.Sockets\.TCPClient.*stream.*write.*",
            "mitreid": "T1041",
            "technique": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bpowershell.*Start-BitsTransfer\s+-Source\s+[a-zA-Z0-9_.-]+\s+-Destination\s+https?://[a-zA-Z0-9_.-]+/.*\b",
            "mitreid": "T1041",
            "technique": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bpython\s+-c\s+\"import\s+socket;.*socket\.socket\(socket\.AF_INET,\s+socket\.SOCK_STREAM\)\.connect\(.*;.*\.send\(.*\)\"",
            "mitreid": "T1041",
            "technique": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bperl\s+-e\s+'use\s+Socket;.*socket\(S,\s*PF_INET,\s*SOCK_STREAM,\s*getprotobyname\(\"tcp\"\)\);.*connect\(S,.*\);.*print\s+S\s+.*'",
            "mitreid": "T1041",
            "technique": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bruby\s+-rsocket\s+-e\s+'c\s*=\s*TCPSocket\.new\(.*\);c\.print\(.*\)'",
            "mitreid": "T1041",
            "technique": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bphp\s+-r\s+'\$s\s*=\s*fsockopen\(.*\);.*fwrite\(\$s,.*\);'",
            "mitreid": "T1041",
            "technique": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bopenssl\s+s_client\s+-connect\s+[a-zA-Z0-9_.-]+:\d+\s+-quiet\s+<\s+[a-zA-Z0-9_.-]+\b",
            "mitreid": "T1048",
            "technique": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\baws\s+s3\s+cp\s+[a-zA-Z0-9_.-]+\s+s3://[a-zA-Z0-9_.-]+/.*\b",
            "mitreid": "T1537",
            "technique": "Transfer Data to Cloud Account",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bgsutil\s+cp\s+[a-zA-Z0-9_.-]+\s+gs://[a-zA-Z0-9_.-]+/.*\b",
            "mitreid": "T1537",
            "technique": "Transfer Data to Cloud Account",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\baz\s+storage\s+blob\s+upload\s+-f\s+[a-zA-Z0-9_.-]+\s+-c\s+[a-zA-Z0-9_.-]+.*\b",
            "mitreid": "T1537",
            "technique": "Transfer Data to Cloud Account",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\bpowershell.*System\.Net\.WebClient.*UploadFile.*https?://[a-zA-Z0-9_.-]+/.*\b",
            "mitreid": "T1041",
            "technique": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration"
        },
        {
            "pattern": r"\brsync\s+-avz\s+[a-zA-Z0-9_.-]+\s+[a-zA-Z0-9_.-]+:/.*\b",
            "mitreid": "T1048",
            "technique": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration"
        },
    ],

    "mshta": [
        {
            "pattern": r"mshta(?:\.exe)?\s*[\"\']?.*?(?:vbscript|javascript)\s*:",
            "mitreid": "T1218.011",
            "technique": "Signed Binary Proxy Execution",
            "tactic": "Defense Evasion"
        },
        {
            "pattern": r"mshta(?:\.exe)?\s*[\"\']?\s*(?:https?|ftp|file)://",
            "mitreid": "T1218.011",
            "technique": "Signed Binary Proxy Execution",
            "tactic": "Defense Evasion"
        },
        {
            "pattern": r"mshta(?:\.exe)?.*(?:CreateObject|Wscript\.Shell|Shell\.Application|powershell|document\.write)",
            "mitreid": "T1218.011",
            "technique": "Signed Binary Proxy Execution",
            "tactic": "Defense Evasion"
        },
        {
            "pattern": r"mshta(?:\.exe)?.*(?:-enc|base64)",
            "mitreid": "T1027",
            "technique": "Obfuscated Files or Information",
            "tactic": "Defense Evasion"
        },
    ],

    "suspicious_parameters": [
        {
            "pattern": r"\-(?:EncodedCommand|enc|e)\b",
            "mitreid": "T1027",
            "technique": "Obfuscated Files or Information",
            "tactic": "Defense Evasion"
        },
        {
            "pattern": r"\-(?:ExecutionPolicy|exec)\s+Bypass\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\-(?:NonInteractive|noi)\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\-(?:noprofile|nop)\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\-(?:WindowStyle|window|w)\s+(?:hidden|h)\b",
            "mitreid": "T1564.003",
            "technique": "Hidden Window",
            "tactic": "Defense Evasion"
        },
        {
            "pattern": r"\bbcedit\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bBypass\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bcertutil.*\-encodehex\b",
            "mitreid": "T1027",
            "technique": "Obfuscated Files or Information",
            "tactic": "Defense Evasion"
        },
        {
            "pattern": r"\bClipboardContents\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bGet\-GPPPassword\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bGet\-LSASecret\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\blsass\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bnet\s+user\s+\/\s+add\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bnetsh\s+firewall\s+set\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\breg\s+add\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\brundll32\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\bschtasks\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\btaskkill\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"\s*\<NUL\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"wevtutil\s+cl\b",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
        {
            "pattern": r"(?i)opacity=0\.0[0-9]?\d*",
            "mitreid": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
    ],
}


def find_suspicious_patterns(command_line: str, patterns: list[dict[str, str]]) -> list[dict[str, str]]:
    """
    Finds suspicious patterns in a command line string based on a list of pattern dictionaries.

    Args:
        command_line (str): The command line string to analyze.
        patterns (list[dict[str, str]]): A list of pattern dictionaries to search for.

    Returns:
        list[dict[str, str]]: A list of found suspicious patterns with their MITRE ATT&CK details.
    """
    found_patterns = []
    
    for pattern_info in patterns:
        
        match = re.search(pattern_info["pattern"], command_line, re.IGNORECASE)
        
        if match:
            found_pattern = match.group(0)
            found_patterns.append(
                {"match": found_pattern, **pattern_info}
            )
            
    return found_patterns


def check_macOS_suspicious_commands(command_line: str) -> dict[str, list[list[str]]]:
    """
    Checks for suspicious macOS/AppleScript commands by grouping multiple sets
    of required substrings under a category. If all required substrings appear,
    that combination is recorded under its category.

    Args:
        command_line (str): The command line to check for suspicious macOS/AppleScript commands.

    Returns:
        dict[str, list[list[str]]]: A dictionary where keys are categories of suspicious behavior
                                    and values are lists of matched substring combinations.
    """

    text = command_line.lower()

    # Define categories and the sets of required substrings belonging to each
    patterns_by_category = {
        "infostealer_characteristics": [
            ["telegram", "deskwallet"],
            ["to set visible", "false"],
            ["chflags hidden"],
            ["osascript -e", "system_profiler", "hidden answer"],
            ["tell application finder", "duplicate"],
            ["tell application finder", "duplicate"],
        ],
        "possible_exfiltration": [
            ["display dialog", "curl -"],
            ["osascript -e", "curl -x", "system_profiler"],
            ["osascript -e", "curl -"],
        ],
    }

    results: dict[str, list[list[str]]] = {}
    for category, pattern_groups in patterns_by_category.items():
        matched_combinations = []
        for required_phrases in pattern_groups:
            # If all required substrings appear in text
            if all(phrase in text for phrase in required_phrases):
                matched_combinations.append(required_phrases)
        # Store only if we found matches
        if matched_combinations:
            results[category] = matched_combinations

    return results


def check_for_obfuscation(command_line: str) -> tuple[dict[str, bool], str]:
    """
    Checks for various obfuscation techniques in a command line string.

    This function analyzes the given command line string for common obfuscation techniques
    such as base64 encoding, double encoding, reversed text, and other obfuscation methods.

    Args:
        command_line (str): The command line string to analyze.

    Returns:
        tuple: A tuple containing two elements:
            - A dictionary of flags indicating which obfuscation techniques were detected.
            - The deobfuscated/decoded command line string.
    """

    flags = {
        "base64_encoding": False,
        "obfuscated": False,
        "double_encoding": False,
        "reversed_command": False,
    }

    parsed_command_line = command_line

    reversed_command_line, flags["reversed_command"] = reverse_command(parsed_command_line)

    if flags["reversed_command"]:
        parsed_command_line = reversed_command_line  # Use the reversed command line for further analysis

    decoded_command_line, flags["base64_encoding"], flags["double_encoding"] = identify_and_decode_base64(parsed_command_line)

    if flags["double_encoding"] or flags["base64_encoding"]:
        parsed_command_line = decoded_command_line

    decoded_command_line, flags["obfuscated"] = encode_hex_and_oct_chars(parsed_command_line)
    decoded_command_line, flags["obfuscated"] = concat_multiple_strings(parsed_command_line)

    if flags["obfuscated"]:
        parsed_command_line = decoded_command_line

    return flags, parsed_command_line


def check_social_engineering(command_line: str) -> list[str]:
    """
    Detects social engineering tactics in a given command line.

    This function searches for patterns that indicate social engineering attempts, such as:
    - Use of checkmark emojis that might be used to suggest legitimacy
    - Comment characters in mshta commands that may be used to trick users

    Args:
        command_line (str): The command line text to analyze

    Returns:
        list[str]: A list of matched social engineering patterns
    """

    checkmark_emojis = [
        "\u2705",  # ✅ Check Mark Button
        "\u2714",  # ✔️ Heavy Check Mark
        "\u2611",  # ☑️ Ballot Box with Check
        "\u1f5f8",  # 🗸 Light Check Mark
        "\u1f5f9",  # 🗹 Ballot Box with Bold Check
    ]

    demisto.debug("Checking for social engineering patterns in command.")

    for emoji in checkmark_emojis:
        if emoji in command_line:
            return ["Emoji Found in command line"]

    if re.search("mshta.*?#", command_line, re.IGNORECASE):
        # This is used by attackers to fool a victim to run the mshta command via the explorer
        return ["Comment character detected in mshta command line"]

    return []


def encode_hex_and_oct_chars(command_line: str):
    """
    Decodes hexadecimal and octal escape sequences in a command line string.

    This function searches for hexadecimal (\\xXX) and octal (\\OOO) escape sequences
    in the input string and replaces them with their corresponding ASCII characters.

    Args:
        command_line (str): The input command line string to process.

    Returns:
        tuple: A tuple containing two elements:
            - The processed string with decoded escape sequences (if any were found).
            - A boolean indicating whether any changes were made to the input string.
    """

    def decode_match(match):
        hex_part, octal_part = match.groups()
        if hex_part:
            return chr(int(hex_part, 16))
        elif octal_part:
            return chr(int(octal_part, 8))
        return ""

    pattern = re.compile(r"\\x([0-9A-Fa-f]{2})|\\([0-7]{2,3})")

    parsed = pattern.sub(lambda m: decode_match(m), command_line)

    if parsed != command_line:
        return parsed, True

    else:
        return command_line, False


def concat_multiple_strings(command_line: str):
    """
    Detects and joins multiple string concatenations in a command line string.

    This function identifies patterns where strings are concatenated using the '+'
    operator (e.g., "h" + "e" + "l" + "l" + "o") and joins them together by removing the
    quotes and '+' symbols.

    Args:
        command_line (str): The input command line string to process.

    Returns:
        tuple: A tuple containing two elements:
            - The processed string with concatenated strings joined together (if any were found).
            - A boolean indicating whether any changes were made to the input string.
    """

    if re.search(r"\"\s*\+\s*\"", command_line):
        return re.sub(r"\"(.*?)\"\s*\+", r"\1", command_line), True

    else:
        return command_line, False


def detect_final_powershell_script(data: str) -> bool:
    """
    Determines if the data contains known PowerShell command patterns.

    This function checks if the given string contains any known PowerShell commands
    that would indicate the data is a PowerShell script and not an encoded payload.

    Args:
        data (str): The string to analyze for PowerShell commands.

    Returns:
        bool: True if PowerShell commands are detected, False otherwise.
    """

    for command in KNOWN_POWERSHELL_COMMANDS_BREAKPOINTS:
        if command.lower() in data.lower():
            return True

        else:
            continue

    return False


def try_decode(data: bytes) -> str:
    """
    Try decoding the data with various encoding methods.

    This function attempts to decode binary data using different encodings:
    1. If data starts with 'MZ' (PE file signature), it decodes as UTF-8 after removing null bytes
    2. If data contains null bytes, it tries UTF-16-LE decoding
    3. Otherwise, it uses UTF-8 decoding

    Args:
        data (bytes): The binary data to decode

    Returns:
        str: The decoded string, or an empty string if decoding fails
    """

    try:
        if data.startswith(b"MZ"):
            decoded_str = data.replace(b"\x00", b"").decode("utf-8", errors="ignore")

        elif b"\x00" in data:
            # If they remain the same, try UTF-16-LE
            decoded_str = data.decode("utf-16-le")

        else:
            decoded_str = data.decode("utf-8")

        return decoded_str

    except (UnicodeDecodeError, AttributeError):
        # If decoding fails, return None
        return ""


def decode_base64_until_final_script(encoded_str: str) -> tuple[str, int]:
    """
    Decode a base64 string until it reaches the final PowerShell script.

    This function iteratively decodes a base64 encoded string until it can no longer be
    decoded or until it identifies a final PowerShell script. It keeps track of how many
    decoding iterations were performed.

    Args:
        encoded_str (str): The base64 encoded string to decode

    Returns:
        tuple[str, int]: A tuple containing the decoded string and the number of decoding iterations
    """
    decoded_str = encoded_str
    counter = 0

    while not detect_final_powershell_script(decoded_str):
        initial_string = decoded_str

        try:
            counter += 1
            decoded_bytes = base64.b64decode(decoded_str)
            decoded_str = try_decode(decoded_bytes)
            if not decoded_str:
                return initial_string, counter - 1

        except Exception:
            break

    return decoded_str, counter


def is_base64(possible_base64: str | bytes) -> bool:
    """
    Validates if the provided string is a Base64-encoded string.

    This function performs multiple checks to determine if a string is valid Base64:
    1. Verifies the string contains only valid Base64 characters (A-Z, a-z, 0-9, +, /, =)
    2. Ensures the length is a multiple of 4 (correct padding)
    3. For strings of length 20 or less, requires that the string contains '+', '/' or '='
       as an additional heuristic to reduce false positives
    4. Attempts strict base64 decoding which validates the content

    Args:
        possible_base64 (str | bytes): The string or bytes to validate as Base64

    Returns:
        bool: True if the input is valid Base64, False otherwise
    """
    try:
        if isinstance(possible_base64, str):
            possible_base64 = possible_base64.encode("ascii")

        # Check for valid Base64 characters and correct padding
        if not re.fullmatch(b"[A-Za-z0-9+/]*={0,2}", possible_base64):
            return False

        # Ensure length is a multiple of 4
        if len(possible_base64) % 4 != 0:
            return False

        # Apply heuristic for short strings: must contain '=' if <= 20
        if len(possible_base64) <= 20 and b"=" not in possible_base64:
            return False

        # Attempt strict decoding
        base64.b64decode(possible_base64, validate=True)
        return True
    except Exception:
        return False


def handle_powershell_base64(command_line: str) -> tuple[str, bool, bool]:
    """
    Detects and decodes Base64-encoded PowerShell commands.

    This function searches for PowerShell's -EncodedCommand parameter and decodes
    any Base64-encoded commands found. It can detect multiple levels of encoding.

    Args:
        command_line (str): The PowerShell command line to analyze

    Returns:
        tuple[str, bool, bool]: A tuple containing:
            - The decoded command line
            - A boolean indicating if encoding was detected
            - A boolean indicating if double encoding was detected
    """

    double_encoded_detected = False
    encoded = False
    num_of_encodings = 0
    result = command_line
    powershell_encoded_base64 = re.compile(
        r"""
        -(?:e(?:n(?:c(?:o(?:d(?:e(?:d(?:C(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)\s+
        ["']?([A-Za-z0-9+/]{4,}(?:={0,2}))["']?
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    while matches := powershell_encoded_base64.findall(result):
        demisto.debug(f"Detected -encodedCommand matches: {matches}")

        valid_matches = [match for match in matches if is_base64(match)]

        if not valid_matches:
            demisto.debug("No valid Base64 matches found.")
            return "", False, False

        for match in valid_matches:
            decoded_segment, counter = decode_base64_until_final_script(match)
            num_of_encodings += counter
            demisto.debug(f"Decoded segment: {decoded_segment}")

            if decoded_segment:
                escaped_match = match.replace("+", "\\+")
                encoded_param = re.compile(
                    f"(?i)-(?:e(?:n(?:c(?:o(?:d(?:e(?:d(?:C(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)\\s+[\"']?{escaped_match}"
                )
                result = encoded_param.sub(r"%%TEMP%%", result)
                result = result.replace(r"%%TEMP%%", f'"{decoded_segment}"')

        if num_of_encodings > 1:
            double_encoded_detected = True

    if num_of_encodings != 0:
        encoded = True

    return result, encoded, double_encoded_detected


def handle_general_base64(command_line: str) -> tuple[str, bool, bool]:
    """
    Handles the general case of decoding Base64 in a command line.

    This function searches for any Base64-encoded strings in the given command line
    and attempts to decode them. It handles multiple encoding layers and keeps track
    of whether double encoding was detected.

    Args:
        command_line (str): The command line string to analyze

    Returns:
        tuple[str, bool, bool]: A tuple containing:
            - The decoded command line
            - A boolean indicating if encoding was detected
            - A boolean indicating if double encoding was detected
    """

    result = command_line
    base64_pattern = r"[A-Za-z0-9+/]{4,}(?:={0,2})"
    num_of_encodings = 0
    double_encoded_detected = False
    previous_matches: list[str] = []

    while matches := re.findall(base64_pattern, result):
        valid_matches = [match for match in matches if is_base64(match)]

        if not valid_matches or set(valid_matches).issubset(set(previous_matches)):
            if valid_matches and set(valid_matches).issubset(set(previous_matches)):
                num_of_encodings -= 1

            if num_of_encodings > 1:
                double_encoded_detected = True
                return result, True, double_encoded_detected

            elif num_of_encodings == 1:
                return result, True, double_encoded_detected

            else:
                return result, False, double_encoded_detected

        num_of_encodings += 1

        for match in valid_matches:
            decoded_bytes = base64.b64decode(match)
            decoded_segment = try_decode(decoded_bytes)

            if decoded_segment:
                result = result.replace(match, f'"{decoded_segment}"')

        previous_matches = valid_matches

    return result, False, double_encoded_detected


def identify_and_decode_base64(command_line: str) -> tuple[str, bool, bool]:
    """
    Identifies and decodes all Base64 occurrences in a command line.

    This function checks if "powershell" is in the command line and calls the
    appropriate handler function: handle_powershell_base64 for PowerShell commands
    or handle_general_base64 for other command types.

    Returns:
        tuple[str, bool, bool]: A tuple containing:
            - The command line with decoded content
            - A boolean indicating if any encoding was detected
            - A boolean indicating if double encoding was detected
    """

    if "powershell" in command_line.lower():
        return handle_powershell_base64(command_line)

    else:
        return handle_general_base64(command_line)


def reverse_command(command_line: str) -> tuple[str, bool]:
    """
    Detects if the command line contains a reversed PowerShell string and reverses it.

    Args:
        command_line (str): The command line to check for reversed PowerShell strings.

    Returns:
        tuple[str, bool]: A tuple containing:
            - The command line, reversed if it contained a reversed PowerShell string
            - A boolean indicating if a reversal was performed
    """

    if "llehsrewop" in command_line.lower():
        return command_line[::-1], True
    return command_line, False


def check_mixed_case_powershell(command_line: str) -> list[str]:
    """
    Detects mixed case obfuscation of the word 'powershell' in a command line.

    This function searches for variations of the word 'powershell' that use mixed case
    characters (e.g. PoWeRsHeLL), which is a common obfuscation technique used to evade
    detection. Normal legitimate versions of the word are excluded from the results.

    Args:
        command_line (str): The command line text to analyze

    Returns:
        list[str]: A list of matched obfuscated 'powershell' strings
    """

    mixed_case_powershell_regex = re.compile(r"\b(?=.*[a-z])(?=.*[A-Z])[pP][oO][wW][eE][rR][sS][hH][eE][lL]{2}(\.exe)?\b")

    demisto.debug("Checking for mixed case powershell usage.")

    exclusions = {
        "Powershell",
        "PowerShell",
        "powershell",
        "Powershell.exe",
        "PowerShell.exe",
        "powershell.exe",
    }

    return [match.group() for match in mixed_case_powershell_regex.finditer(command_line) if match.group() not in exclusions]


def check_custom_patterns(command_line: str, custom_patterns: list[str] | None = None) -> list[str]:
    """
    Checks for user-defined patterns in a given command line.

    This function matches custom regular expression patterns against the command line
    text to identify specific patterns of interest defined by the user.

    Args:
        command_line (str): The command line text to analyze
        custom_patterns (list[str] | None, optional): List of regex patterns to match. Defaults to None.

    Returns:
        list[str]: A list of matched patterns from the command line
    """

    matches: list[str] = []
    if custom_patterns:
        # Ensure custom_patterns is a list
        if isinstance(custom_patterns, str):
            custom_patterns = [custom_patterns]  # Convert single string to a list
        for pattern in custom_patterns:
            matches.extend(re.findall(pattern, command_line, re.IGNORECASE))
    return matches


def extract_indicators(command_line: str) -> dict[str, list[str]]:
    """
    Extract various indicators (IP addresses, domains, URLs, etc.) from the command line.

    This function uses the Demisto extractIndicators command to identify and extract
    various indicators from the command line text. It filters out reserved IPs and
    special cases like '::'.

    Args:
        command_line (str): The command line text to extract indicators from

    Returns:
        dict[str, list[str]]: A dictionary mapping indicator types to lists of extracted values
    """

    def is_reserved_ip(ip_str: str) -> bool:
        """
        Check if an IP address is reserved (non-global).

        Args:
            ip_str (str): The IP address as a string

        Returns:
            bool: True if the IP is reserved (not globally routable), False otherwise
        """

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return not ip_obj.is_global

        except ValueError:
            return False

    extracted_by_type: dict[str, list[str]] = {}

    demisto.debug("Attempting to extract indicators from command line.")

    try:
        indicators = demisto.executeCommand("extractIndicators", {"text": command_line})

        if indicators and isinstance(indicators, list):
            contents = indicators[0].get("Contents", {})

            if isinstance(contents, str):
                try:
                    contents = json.loads(contents)
                except json.JSONDecodeError:
                    return {}

            if isinstance(contents, dict):
                for indicator_type, values in contents.items():
                    if isinstance(values, list):
                        for value in values:
                            if value == "::":
                                continue
                            if indicator_type == "IP" and is_reserved_ip(value):
                                continue  # Skip reserved IPs

                            if indicator_type not in extracted_by_type:
                                extracted_by_type[indicator_type] = []
                            extracted_by_type[indicator_type].append(value)

    except Exception as e:
        demisto.debug(f"Failed to extract indicators: {e!s}")

    return extracted_by_type


def calculate_score(results: dict[str, Any]) -> dict[str, Any]:
    """
    Aggregates findings from the analysis and assigns a score (0-100).
    Incorporates bonuses for certain risky combinations.

    The scoring algorithm works as follows:
    1. Each detection adds points based on predefined weights (e.g., obfuscation techniques, malicious commands)
    2. Findings are categorized into high-risk and medium-risk groups
    3. Multiple high-risk findings trigger additional bonus points
    4. Multiple medium-risk findings trigger smaller bonus points
    5. A final score is calculated for both original and decoded command lines
    6. The score is normalized to a 0-100 scale, with higher scores indicating more suspicious activity

    Returns:
        dict: Contains the calculated scores and detailed findings for both original and decoded command lines
    """

    # Define weights for base scoring
    weights: dict[str, int] = {
        "mixed_case_powershell": 25,
        "reversed_command": 25,
        "powershell_suspicious_patterns": 35,
        "credential_dumping": 25,
        "double_encoding": 25,
        "amsi_techniques": 25,
        "malicious_commands": 25,
        "custom_patterns": 25,
        "macOS_suspicious_commands": 25,
        "suspicious_mshta": 25,
        "social_engineering": 25,
        "data_exfiltration": 15,
        "lateral_movement": 15,
        "obfuscated": 15,
        "windows_temp_path": 10,
        "indicators": 10,
        "recon_commands": 10,
        "macos_recon_commands": 10,
        "base64_encoding": 5,
        "suspicious_parameters": 5,
    }

    # Initialize findings and scores for original and decoded
    findings: dict[str, list[Any]] = {"original": [], "decoded": []}
    scores: dict[str, int] = {"original": 0, "decoded": 0}

    # Define risk groups and bonus scores
    high_risk_keys = {
        "mixed_case_powershell",
        "double_encoding",
        "amsi_techniques",
        "malicious_commands",
        "powershell_suspicious_patterns",
        "credential_dumping",
        "reversed_command",
        "macOS_suspicious_commands",
        "suspicious_mshta",
        "custom_patterns",
        "social_engineering",
    }

    medium_risk_keys = {
        "data_exfiltration",
        "lateral_movement",
        "indicators",
        "obfuscated",
    }

    low_risk_keys = {
        "suspicious_parameters",
        "windows_temp_path",
        "recon_commands",
        "macos_recon_commands",
        "base64_encoding",
        "windows_temp_paths",
    }

    risk_bonuses: dict[str, int] = {
        "high": 30,
        "medium": 20,
        "low": 10,
    }

    # Define the fixed theoretical maximum score
    theoretical_max = 120

    # Helper function to calculate score and detect combinations
    def process_context(context_results: dict[str, Any]) -> tuple[int, list[str]]:
        context_score = 0
        context_findings: list[str] = []
        context_keys_detected = set()

        # Calculate base score for each key (count each category once)
        for key, value in context_results.items():
            if value and value != "{}":
                context_keys_detected.add(key)
                if isinstance(value, list) and len(value) > 0:
                    # Add weight once, report how many instances were found
                    context_score += weights.get(key, 0)
                    context_findings.append(f"{key.replace('_', ' ')} detected ({len(value)} instances)")
                else:
                    # Not a list or empty list, just count once
                    context_score += weights.get(key, 0)
                    context_findings.append(f"{key.replace('_', ' ')} detected")

        # Apply combination bonuses based on detected keys
        if (high_risk_keys & context_keys_detected) and len(context_keys_detected) > 1:
            context_score += risk_bonuses["high"]
            context_findings.append("High-risk combination detected")
        elif (medium_risk_keys & context_keys_detected) and len(context_keys_detected) > 1:
            context_score += risk_bonuses["medium"]
            context_findings.append("Medium-risk combination detected")
        elif (low_risk_keys & context_keys_detected) and len(context_keys_detected) > 1:
            context_score += risk_bonuses["low"]
            context_findings.append("Low-risk combination detected")

        return context_score, context_findings

    # Process original
    original_results = results.get("analysis", {}).get("original", {})
    scores["original"], findings["original"] = process_context(original_results)

    # Check global combinations (like double encoding globally)
    if original_results.get("double_encoding", False):
        scores["decoded"] += weights["double_encoding"]
        findings["decoded"].append("double_encoding")

    # Calculate total raw score
    total_raw_score = scores["original"]  # + scores["decoded"]

    # Normalize the score to fit within 0-100 based on the fixed theoretical max
    normalized_score = (total_raw_score / theoretical_max) * 100
    normalized_score = min(normalized_score, 100)  # Cap at 100

    # Determine overall risk level
    risk = "Low Risk"
    if normalized_score > 90:
        risk = "Critical Risk"
    elif normalized_score > 50:
        risk = "High Risk"
    elif normalized_score > 25:
        risk = "Medium Risk"

    return {
        "score": int(round(normalized_score, 0)),
        "findings": findings,
        "risk": risk,
    }


def analyze_command_line(command_line: str, custom_patterns: list[str] | None = None) -> dict[str, Any]:
    """
    Analyzes a command line string for potential security threats and suspicious patterns.

    This function performs a comprehensive analysis of the provided command line, checking for
    various indicators of malicious activity including obfuscation techniques, suspicious commands,
    credential dumping attempts, lateral movement, and more.

    Args:
        command_line (str): The command line string to analyze.
        custom_patterns (list[str] | None, optional): Additional custom patterns to check for in the command line.
                                                     Defaults to None.

    Returns:
        dict[str, Any]: Analysis results containing:
            - original_command: The input command line string
            - parsed_command: The command line after deobfuscation (if applicable)
            - analysis: Detailed analysis results for various security checks
            - score: Numerical risk score (0-100)
            - findings: Detailed findings that contributed to the score
            - risk: Overall risk assessment (Low/Medium/High/Critical Risk)
    """

    results: dict[str, Any] = {
        "original_command": command_line,
        "analysis": {"original": {}},
    }

    flags, parsed_command_line = check_for_obfuscation(command_line)

    if parsed_command_line:
        results["parsed_command"] = parsed_command_line

    # Perform pattern-based checks on the original command line
    for pattern_name, patterns in PATTERNS.items():
        results["analysis"]["original"][pattern_name] = find_suspicious_patterns(parsed_command_line, patterns)

    # Perform other specific checks
    results["analysis"]["original"]["mixed_case_powershell"] = check_mixed_case_powershell(parsed_command_line)
    results["analysis"]["original"]["indicators"] = extract_indicators(parsed_command_line)
    results["analysis"]["original"]["custom_patterns"] = (
        check_custom_patterns(parsed_command_line, custom_patterns) if custom_patterns else []
    )

    # Only set "base64_encoding" if we actually decoded something
    for flag, value in flags.items():
        if value:
            results["analysis"]["original"][flag] = value
    
    if "osascript" in parsed_command_line.lower():
        results["analysis"]["original"]["macOS_suspicious_commands"] = check_macOS_suspicious_commands(parsed_command_line)

    # results["analysis"]["original"] = original_analysis
    score_details = calculate_score(results)
    results.update(score_details)

    return results


def main():
    """
    Entry point for analyzing command lines for suspicious activities and patterns.
    """
    args = demisto.args()
    command_lines = argToList(args.get("command_line", []), separator=" , ")
    custom_patterns = argToList(args.get("custom_patterns", []))
    parsed_results = []

    # Analyze each command line
    results = [analyze_command_line(cmd, custom_patterns) for cmd in command_lines]

    # Prepare readable output for the results

    for result in results:
        readable_output = ""
        mitre_results = []
        
        if result.get("parsed_command", None) != result["original_command"]:
            parsed_command = f"**Decoded Command**: {result['parsed_command']}\n"

        else:
            parsed_command = None

        for findings in result["analysis"]["original"].values():
            if findings:
                for match in findings:
                    try:
                        mitre_results.append(
                            {
                                'mitreid': match['mitreid'],
                                'technique': match['technique'],
                                'tactic': match['tactic'],
                            }
                        )
                    
                    except TypeError:
                        continue
        
        result["findings"]["MITRE"] = [dict(t) for t in {d['mitreid']: d for d in mitre_results}.values()]  # deduping
        mitre_readable = ', '.join([f'{mitre["mitreid"]} - {mitre["technique"]}' for mitre in result['findings']['MITRE']])
        
        readable_output += (
            f"**Command Line**: {result['original_command']}\n"
            f"{parsed_command if parsed_command else ''}"
            f"**Risk**: {result['risk']}\n"
            f"**Score**: {result['score']}\n"
            f"**Findings (Original)**: {', '.join(result['findings']['original'])}\n"
            f"**MITRE**: {mitre_readable}\n\n\n"
        )
        
        parsed_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="CommandLineAnalysis",
                outputs_key_field="original_command",
                outputs=result,
            )
        )

    # Return results
    return_results(parsed_results)


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
