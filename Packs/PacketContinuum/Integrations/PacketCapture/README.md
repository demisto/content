Integration for Packet Continuum capture server
This integration was integrated and tested with version xx of PacketCapture

## Configure PacketCapture on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PacketCapture.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Rest API Token | True |
    | Packet Continuum Management IP | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### pc-bpf-search

***
Run a bpf search

#### Base Command

`pc-bpf-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_name | Search identifier. | Required | 
| search_filter | BPF search query string. | Required | 
| incident_time | UTC time of event. | Required | 
| incident_delta | Search window from incident time. | Required | 
| max_packets | Max number of returned packets. Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PacketCapture.bpf.checkstatus | String | Status of newly executed search | 
| PacketCapture.bpf.getpcaps | String | URL to download pcaps resulting from search | 
| PacketCapture.bpf.pc.kql.metadata | String | URL to download metadata from PCAPs | 
| PacketCapture.bpf.objects | String | URL to download extracted objects from PCAPs | 

### pc-get-status

***

#### Base Command

`pc-get-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PacketContinuum.ServerInfo.NodeName | String | Node name of capture box | 
| PacketContinuum.ServerInfo.NodeIP | String | Node IP address | 
| PacketContinuum.ServerInfo.Upordown | String | Capture status | 
| PacketContinuum.ServerInfo.Port | String | Server port | 
| PacketContinuum.ServerInfo.Status | String | System status | 
| PacketContinuum.ServerInfo.Duration | String | Capture uptime | 
| PacketContinuum.ServerInfo.BeginTime | String | Capture start time | 
| PacketContinuum.ServerInfo.EndTime | String | Capture end time | 
| PacketContinuum.ServerInfo.License | String | License status | 
| PacketContinuum.ServerInfo.TimeZone | String | Sytem timezone | 
| PacketContinuum.ServerInfo.PreCaptureFilter | String | Precapture filter | 
| PacketContinuum.ServerInfo.VirtualStorage | String | Virtual storage | 
| PacketContinuum.ServerInfo.RealStorage | String | Real Storage | 
| PacketContinuum.ServerInfo.Capturedrops | String | Packet drops | 
| PacketContinuum.ServerInfo.Throughput | String | Capture throughput | 
| PacketContinuum.ServerInfo.CompressionRatio | String | PCAP data compressibility | 

### pc-kql-search

***
Run a kql search

#### Base Command

`pc-kql-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_name | Search identifier. | Required | 
| search_filter | KQL search query string. | Required | 
| incident_time | UTC time of event. | Required | 
| incident_delta | Search window from incident time. | Required | 
| max_packets | Max number of returned packets. Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PacketCapture.kql.checkstatus | String | Status of newly executed search | 
| PacketCapture.kql.getpcaps | String | URL to download pcaps resulting from search | 
| PacketCapture.kql.pc.kql.metadata | String | URL to download metadata from PCAPs | 
| PacketCapture.kql.objects | String | URL to download extracted objects from PCAPs | 
