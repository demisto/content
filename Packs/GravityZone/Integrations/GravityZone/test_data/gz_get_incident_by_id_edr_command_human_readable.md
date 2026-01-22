### Gravity Zone Incident
|Action Taken|Assigned Priority|Assigned User|Company Name|Created|ID|Last Processed|Last Updated|Number|Permalink|Severity Score|Status|Type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Reported | Unknown | Unassigned | COMPANY_NAME | 2025-12-17T09:02:03+02:00 | INCIDENT_ID_1 | 2025-12-17T09:02:13+02:00 | 2025-12-17T09:02:03+02:00 | 477 | https://localhost/#!/incidents/view/INCIDENT_ID_1 | 33% | 0 (Pending) | Incident (EDR) |

### Incident Notes
**No entries.**

### Incident Alerts
|Date|Detected By|Name|Resources|
|---|---|---|---|
| 2025-12-17T09:01:53+02:00 | RegSecurityDump (EDR Detection) | RegSecurityDump | [<br>  {<br>    "Pid": 1840,<br>    "ProcessPath": "c:\\windows\\system32\\reg.exe",<br>    "CommandLine": "path /y",<br>    "ParentPid": 11908,<br>    "User": "ENDPOINT_NAME\\ENDPOINT_NAME",<br>    "ProcessAccessPrivileges": "elevated",<br>    "ProcessIntegrityLevel": "high",<br>    "Type": "process"<br>  }<br>] |
| 2025-12-17T09:01:48+02:00 | ExternalRemoteServices.RDP.Login (EDR Detection) | ExternalRemoteServices.RDP.Login | [<br>  {<br>    "Domain": "ENDPOINT_NAME",<br>    "Type": "network"<br>  }<br>] |
| 2025-12-16T15:20:18+02:00 | WmicGenericDiscovery (EDR Detection) | WmicGenericDiscovery | [<br>  {<br>    "Pid": 0,<br>    "ProcessPath": "<system>",<br>    "CommandLine": "<did_not_receive>",<br>    "User": "NT AUTHORITY\\SYSTEM",<br>    "ProcessAccessPrivileges": "elevated",<br>    "ProcessIntegrityLevel": "system",<br>    "Type": "process"<br>  }<br>] |
