Cortex XDR is the world's first detection and response app that natively integrates network, endpoint and cloud data to stop sophisticated attacks.

Use the Cortex XDR - IOCs feed integration to sync indicators between Cortex XSOAR and Cortex XDR. The integration will sync indicators according to the defined fetch interval. At each interval, the integration will push new and modified indicators defined in the **Sync Query** from Cortex XSOAR to Cortex XDR. Additionally, the integration will check if there are manual modifications of indicators on Cortex XDR and sync back to Cortex XSOAR. Once per day, the integration will perform a *complete sync* which will also remove indicators that have been deleted/expired in Cortex XSOAR, from Cortex XDR. 


This integration was integrated and tested with Branch: stable-50 of XDR.

## Prerequisites

An API key of type **Advanced** with an **Administrator** role.

## Configure Cortex XDR - IOC on Cortex XSOAR  
  
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.  
2. Search for Cortex XDR - IOC.  
3. Click **Add instance** to create and configure a new integration instance.  
  
| **Parameter** | **Description** | **Required** |  
| --- | --- | --- |  
| url | Server URL \(e.g. https://example.net\) | True |  
| apikey_id | API Key ID | True |  
| apikey | API Key | True |  
| feed | Fetch indicators | False |  
| severity | the severity in Cortex XDR | True |  
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
| feedFetchInterval | Feed Fetch Interval | False |  
| feedBypassExclusionList | Bypass exclusion list | False |  
  
4. Click **Test** to validate the URLs, token, and connection.  
## Commands  
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.  
After you successfully execute a command, a DBot message appears in the War Room with the command details.  
### xdr-iocs-sync  
***  
run once when configure the integration (do NOT run this twice!). 
will all the indicators that was synced with XDR and then resync.
  
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
Push new IOCs to XDR. run This every minute (without indicator argument) or ioc trigerd (using indicator argument).
  
  
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

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
