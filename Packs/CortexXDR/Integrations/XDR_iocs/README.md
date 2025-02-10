Cortex XDR is the world's first detection and response app that natively integrates network, endpoint and cloud data to stop sophisticated attacks.

Use the Cortex XDR - IOCs feed integration to sync indicators between Cortex XSOAR and Cortex XDR. The integration will sync indicators according to the defined fetch interval. At each interval, the integration will push new and modified indicators defined in the **Sync Query** from Cortex XSOAR to Cortex XDR. Additionally, the integration will check if there are manual modifications of indicators on Cortex XDR and sync back to Cortex XSOAR. Once per day, the integration will perform a *complete sync* which will also remove indicators that have been deleted/expired in Cortex XSOAR, from Cortex XDR. 


This integration was integrated and tested with Branch: stable-50 of XDR.

## Prerequisites

An API key of type **Advanced** with an **Administrator** role.

## Configure Cortex XDR - IOC in Cortex
  
  
| **Parameter** | **Description** | **Required** |  
| --- | --- | --- |  
| url | Server URL \(e.g. https://example.net\) | True |  
| apikey_id | API Key ID | True |  
| apikey | API Key | True |  
| feed | Fetch indicators | False |  
| severity | The severity in Cortex XDR | True |  
| Tags | Appears in Cortex XSOAR if a modification was made on the Cortex XDR side and is being "mirrored" to Cortex XSOAR | False |  
| query | Sync Query | True |  
| insecure | Trust any certificate \(not secure\) | False |  
| xsoar_severity_field | The Cortex XSOAR indicator field used as severity. | True |  
| xsoar_comments_field | The Cortex XSOAR field where comments are stored. Default is `comments`. Expecting an XSOAR IOC format of a comment (nested dictionary). See `Comments As Tags` for more.| True |  
| comments_as_tags | Whether to consider the value at `xsoar_comments_field` as CSV. Requires specifying a xsoar_comments_field value different than the default `comments`. | True |  
| proxy | Use system proxy settings | False |  
| feedReputation | Indicator Reputation | False |  
| feedReliability | Source Reliability | True |  
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy |  | False |  
| feedExpirationInterval |  | False |  
| feedFetchInterval | Feed Fetch Interval (make sure to set it to at least 15 minutes) | False |  
| feedBypassExclusionList | Bypass exclusion list | False |  
  
## Commands  
You can execute these commands from the CLI, as part of an automation, or in a playbook.  
After you successfully execute a command, a DBot message appears in the War Room with the command details.  
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
Set sync time manually (Do not use this command unless you unredstandard the consequences).


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
