## Cyber Triage Integration

Initiate agentless forensic triage collections on Windows endpoints directly from Cortex XSOAR.

This integration was integrated and tested with Cyber Triage v3.16.0.

Documentation can be found at [https://docs.cybertriage.com/](https://docs.cybertriage.com/).

## Requirements

- Cyber Triage **Team** version >= 3.16.0 (Standalone desktop version is not supported).
- A Windows administrative account with privileges on target endpoints.

## Configure Cyber Triage in Cortex XSOAR

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Cyber Triage Server Hostname | IP address or hostname of the Cyber Triage server (e.g. 192.168.1.2) | True |
| REST Port | REST API port of the Cyber Triage server. Default: 9443 | True |
| API Key | Bearer token found in Options > Deployment Mode > REST API Key | True |
| Windows Admin Credentials | Administrative Windows account used to push the collector to endpoints | True |
| Trust any certificate (not secure) | Skip SSL certificate verification | False |
| Use system proxy settings | Route requests through system proxy | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After successfully executing a command, a DBot message appears in the War Room with the command details.

### ct-triage-endpoint

***
Initiates a Cyber Triage forensic collection on a Windows endpoint.

#### Base Command

`ct-triage-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_name | IP address or hostname of the Windows endpoint to triage. | Required |
| scan_options | Comma-separated list of data types to collect. Valid values: pr (Processes), nw (Network), nc (Network Caches), st (Startup Items), sc (Scheduled Tasks), ru (Program Run), co (System Config), lo (User Logins), ns (Network Shares), wb (Web Artifacts), fs (Full File System Scan). Default: pr,nw,nc,st,sc,ru,co,lo,ns,wb,fs | Optional |
| malware_scan_requested | Send MD5 hashes to an external malware analysis service. Possible values: yes, no. Default: yes | Optional |
| send_content | Send unknown files to an external malware analysis service. Hash upload must be enabled. Possible values: yes, no. Default: no | Optional |
| incident_name | Cyber Triage incident name that the collection will be grouped under. Default: Default | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTriage.SessionId | String | The session ID for the newly created triage session. |
| Endpoint.IPAddress | String | The IP address of the endpoint that was triaged. |
| Endpoint.Hostname | String | The hostname of the endpoint that was triaged. |

#### Command Example

```
!ct-triage-endpoint endpoint=ct-win10-01 scan_options=pr,nw,st malware_scan_requested=yes send_content=no incident_name=MyIncident
```

#### Human Readable Output

A collection has been scheduled for ct-win10-01
