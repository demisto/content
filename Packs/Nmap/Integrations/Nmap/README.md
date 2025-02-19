Run nmap scans with the given parameters.
This integration was integrated and tested with version 7.70 of nmap. The nmap binary is shipped with the integration Docker. You can see the options available for running an nmap scan here: https://nmap.org/book/man-briefoptions.html. Some scan options require **root** access for using raw packet scanning techniques. See [here](https://nmap.org/book/man-port-scanning-techniques.html) for detailed scanning techniques. If you've configured the server to run Docker images with a non-root internal user and you want to use raw packet scanning (for example via the *-sS* option for SYN/ACK scan), make sure to exclude the *demisto/nmap* Docker image as documented For Cortex XSOAR 6 [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users). For Cortex XSOAR 8 Cloud [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). For Cortex XSOAR 8.7 On-prem [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide).

## Configure nmap in Cortex



## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nmap-scan
***
Scan targets with the given parameters


##### Base Command

`nmap-scan`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| targets | The targets to scan. Accepts comma-separated list. | Required | 
| options | The nmap options to use as documented by nmap. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NMAP.Scan.Summary | unknown | Scan summary. | 
| NMAP.Scan.Version | unknown | nmap version. | 
| NMAP.Scan.Started | unknown | Start time epoch. | 
| NMAP.Scan.Ended | unknown | End time epoch. | 
| NMAP.Scan.CommandLine | unknown | The command line being used. | 
| NMAP.Scan.ScanType | unknown | The type of discovery scan. | 
| NMAP.Scan.Hosts.Hostname | unknown | DNS hostname of scanned hostץ | 
| NMAP.Scan.Hosts.Address | unknown | Scanned host address. | 
| NMAP.Scan.Hosts.Status | unknown | Is the host up or down? | 
| NMAP.Scan.Hosts.Services.Port | unknown | The port of the service. | 
| NMAP.Scan.Hosts.Services.Protocol | unknown | The protocol of the service. | 
| NMAP.Scan.Hosts.Services.State | unknown | The state of the service. | 
| NMAP.Scan.Hosts.Services.Banner | unknown | Any captured banner from the service. | 
| NMAP.Scan.Hosts.Services.Service | unknown | The service name. | 
| NMAP.Scan.Hosts.ScriptResults.ID | unknown | The name of the script used. |
| NMAP.Scan.Hosts.ScriptResults.Output | unknown | The raw results of the script execution. |
| NMAP.Scan.Hosts.ScriptResults.Elements | unknown | Additional parseable fields from the script output. |


#### Command Example
```!nmap-scan options="-sV" targets=scanme.nmap.org```

#### Context Example
```
{
    "NMAP": {
        "Scan": {
            "CommandLine": "/usr/bin/nmap -oX - -vvv --stats-every 1s -sV scanme.nmap.org",
            "Ended": 1588340465,
            "Hosts": [
                {
                    "Address": "45.33.32.156",
                    "Hostname": "scanme.nmap.org",
                    "Services": [
                        {
                            "Banner": "",
                            "Port": 21,
                            "Protocol": "tcp",
                            "Service": "tcpwrapped",
                            "State": "open"
                        },
                        {
                            "Banner": "product: OpenSSH version: 6.6.1p1 Ubuntu 2ubuntu2.13 extrainfo: Ubuntu Linux; protocol 2.0 ostype: Linux",
                            "Port": 22,
                            "Protocol": "tcp",
                            "Service": "ssh",
                            "State": "open"
                        },
                        {
                            "Banner": "product: Apache httpd version: 2.4.7 extrainfo: (Ubuntu)",
                            "Port": 80,
                            "Protocol": "tcp",
                            "Service": "http",
                            "State": "open"
                        },
                        {
                            "Banner": "",
                            "Port": 1723,
                            "Protocol": "tcp",
                            "Service": "tcpwrapped",
                            "State": "open"
                        },
                        {
                            "Banner": "",
                            "Port": 5060,
                            "Protocol": "tcp",
                            "Service": "sip",
                            "State": "open"
                        },
                        {
                            "Banner": "product: Nping echo",
                            "Port": 9929,
                            "Protocol": "tcp",
                            "Service": "nping-echo",
                            "State": "open"
                        },
                        {
                            "Banner": "",
                            "Port": 31337,
                            "Protocol": "tcp",
                            "Service": "tcpwrapped",
                            "State": "open"
                        }
                    ],
                    "Status": "up"
                }
            ],
            "ScanType": "connect",
            "Started": 1588340281,
            "Summary": "Nmap done at Fri May  1 13:41:05 2020; 1 IP address (1 host up) scanned in 183.98 seconds",
            "Version": "7.70"
        }
    }
}
```

#### Human Readable Output

>## Nmap done at Fri May  1 13:41:05 2020; 1 IP address (1 host up) scanned in 183.98 seconds
>### Nmap scan report for scanme.nmap.org (45.33.32.156)
>#### Host is up.
>### Services
>|Port|Protocol|State|Service|Banner|
>|---|---|---|---|---|
>| 21 | tcp | open | tcpwrapped |  |
>| 22 | tcp | open | ssh | product: OpenSSH version: 6.6.1p1 Ubuntu 2ubuntu2.13 extrainfo: Ubuntu Linux; protocol 2.0 ostype: Linux |
>| 80 | tcp | open | http | product: Apache httpd version: 2.4.7 extrainfo: (Ubuntu) |
>| 1723 | tcp | open | tcpwrapped |  |
>| 5060 | tcp | open | sip |  |
>| 9929 | tcp | open | nping-echo | product: Nping echo |
>| 31337 | tcp | open | tcpwrapped |  |