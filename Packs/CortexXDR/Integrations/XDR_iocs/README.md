## Overview

---
The Cortex XDR - IOC integration allows you to manage Indicators of Compromise (IOCs) seamlessly within Cortex XDR from Cortex XSOAR. This integration enables security teams to add, update, and remove IOCs efficiently, streamlining threat intelligence workflows and bolstering incident response capabilities.

### Key Features:

- Add IOCs (e.g., IPs, domains, hashes) to Cortex XDR.
- Retrieve and update existing IOCs.
- Automate threat intelligence management through playbooks and incident workflows.

## Use Cases

- Automatically enrich incidents with IOCs by fetching data from Cortex XDR.
- Block malicious IPs, domains, or file hashes in real time using the Cortex XDR threat intelligence engine.
- Streamline threat intelligence sharing between XSOAR and Cortex XDR.
- Simplify IOC lifecycle management with automated workflows for creation, updates, and removal.

## Configure Cortex XDR - IOC in Cortex

| **Parameter** | **Description** | **Required** |  
| --- | --- | --- |  
| Server URL | In Cortex XDR, navigate to **Settings** > **Configurations** > **API Keys** and click Copy API URL. | True |  
| API Key ID | In Cortex XDR platform, go to **Settings** > **Configurations** > **API Keys** and copy the Key ID from the ID column. | True |  
| API Key | In Cortex XDR, go to **Settings** > **Configurations** > **API Keys**, click **+ New Key**, set **Security Level** to **Standard**, select an appropriate **Role**, and copy the Generated Key. | True |
| Source Reliability | Source Reliability. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp. | False |
| Indicator Expiration Method | According to which method the indicators from this feed will be expired. | False |
| Run on | Select an engine to run on. | False |
| Trust any certificate (not secure) | When enabled, bypasses certificate validation, allowing connections even if the certificates cannot be verified. | False |
| Use system proxy settings | Use system proxy settings is enabled only when an engine is selected. | False |
| Extensive logging | For debugging purposes. Do not use this option unless advised otherwise. Using this parameter may result in increased processing time. | False |
| Log Level | Debug/Verbose logging can affect the performance of the integration. Recommended usage is to turn it on only during troubleshooting, and turn it off in production. This setting only affects the integration log. The server log is not affected. | False |
| Do not use in CLI by default ||False|
| Fetches indicators | Whether to fetch indicators from Cortex XDR. | false |
| Classifier | Determines the type of indicators that is created originated from this integration instance. | False|
| Mapper (incoming) | Determines how indicators fields from Cortex XDR are mapped to Cortex XSOAR indicator's fields. | False|
| Feed Fetch Interval | Feed Fetch Interval (make sure to set it to at least 15 minutes). | False |
| Sync Query | The query used to collect indicators to sync from Cortex XSOAR to Cortex XDR. | True |
| Tags | Appears in Cortex XSOAR if a modification was made on the Cortex XDR side and is being "mirrored" to Cortex XSOAR. Supports CSV values. | False |  
| Auto Sync | When enabled, indicators will be synced from Cortex XSOAR to Cortex XDR. Disable if you prefer to use a playbook to sync indicators. | False |
| Indicator Reputation | Indicator Reputation. | False |
| XSOAR Severity Field | The Cortex XSOAR indicator field used as severity. | True |
| XSOAR Comment Field Exporting To XDR | The Cortex XSOAR field where comments are stored. The default is comments. Expecting an XSOAR IOC format of a comment (nested dictionary). See *Comments As Tags* argument for more.| True |
| Overriding severity value | If left blank, the original severity level of the indicator will be used. | True | 
| Comments as tags (CSV) | Whether to consider the value at `XSOAR Comment Field Exporting To XDR` as CSV. Requires specifying a `XSOAR Comment Field Exporting To XDR` value different than the default `comments`. | True |
| Bypass exclusion list | Bypass exclusion list. | False |
  
## Commands  

### xdr-iocs-sync

***

Sync IOCs with Cortex XDR.
Run this command manually only when configuring the instance integration with fetch indicators disabled (run this only once).
It is not recommended to run this manually when there are more then 40,000 indicators.

When `fetch indicators` is enabled, the sync mechanism is used by default. This sets the current time as the last sync time and fetches IOCs from Cortex XSOAR to Cortex XDR, sorted by modification time, in batches of 40,000, up to that time. Upon reaching the last sync point, the synchronization becomes bi-directional, first from Cortex XSOAR to Cortex XDR, then from Cortex XDR to Cortex XSOAR.

As a result, the duration of the first sync depends on the number of IOCs in the Cortex XSOAR tenant and the Feed Fetch Interval. For example, if there are 800,000 indicators in Cortex XSOAR and the `Feed Fetch Interval` is set to 20 minutes as recommended, the initial sync process will take approximately 7 hours.
  
#### Base Command  
  
`xdr-iocs-sync`  
#### Input  
  
There are no input arguments for this command.  
  
#### Context Output  
  
There is no context output for this command.  
  
#### Command Example  
```!xdr-iocs-sync```  
#### Human Readable Output  
  
>sync with XDR completed.  
  
### xdr-iocs-push
***  
Push new or modified IOCs to Cortex XDR.
  
  
#### Base Command  
  
`xdr-iocs-push`  
#### Input  
  
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | the indicators | Optional | 


#### Context Output  
  
There is no context output for this command.  
  
#### Command Example  
```xdr-iocs-push```  
  
#### Human Readable Output  
>push success.
  
  
### xdr-iocs-enable  
***  
Enable iocs in XDR server  
  
  
#### Base Command  
  
`xdr-iocs-enable`  
#### Input  
  
| **Argument Name** | **Description** | **Required** |  
| --- | --- | --- |  
| indicator | The indicator to enable | Required |   
  
#### Context Output  
  
There is no context output for this command.  
  
#### Command Example  
```!xdr-iocs-enable indicator=11.11.11.11```  
    
#### Human Readable Output  
  
>indicators 11.11.11.11 enabled.  
  
### xdr-iocs-disable  
***  
Disable iocs in XDR server  
  
  
#### Base Command  
  
`xdr-iocs-disable`  
#### Input  
  
| **Argument Name** | **Description** | **Required** |  
| --- | --- | --- |  
| indicator | The indicator to enable | Required |   
  
#### Context Output  
  
There is no context output for this command.  
  
#### Command Example  
```!xdr-iocs-disable indicator=22.22.22.22```  
  
#### Human Readable Output  
  
>indicators 22.22.22.22 disabled.  
### xdr-iocs-set-sync-time
***
Deprecated. Set sync time manually (Do not use this command unless you understand the consequences).


#### Base Command

`xdr-iocs-set-sync-time`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time | The time of the file creation (use UTC time zone). | Required | 


#### Context Output

There is no context output for this command.
### xdr-iocs-create-sync-file
***
Creates the sync file for the manual process. Run this command when instructed by the XDR support team.


#### Base Command

`xdr-iocs-create-sync-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| zip | Whether to zip the output file. | Required | 
| set_time | Whether to modify the sync time locally. | Required | 

#### Context Output

There is no context output for this command.


#### Base Command

`xdr-iocs-to-keep-file`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

## Troubleshooting

### Outgoing IOCs

- **Performance Issues**:
  - Reduce the frequency of indicators fetch to manage system load (recommended above 20 minutes).
  - Review Cortex XDR API rate limit logs to ensure compliance with API thresholds.
- **Missing IOCs**:
  - Please make sure all IOC are in a supported format both in Cortex XSOAR and Cortex XDR.
  - If using the **xdr-iocs-push** command, please go over the warnings in the war room.
- **Indicator Severity**:
  - In order to override severity, please enable the ***Override severity*** parameter and also choose a severity under ***Overriding severity value***.
- **Severity update from Cortex XSOAR to Cortex XDR**:
  - Due to Cortex XSOAR system limitations, once the severity is manually changed within Cortex XSOAR, it is excluded from being updated by the mirroring process.
