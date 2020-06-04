
XDR handle indicators  
This integration was integrated and tested with version 5.0 of XDR
## Configure XDR iocs on Cortex XSOAR  
  
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.  
2. Search for XDR iocs.  
3. Click **Add instance** to create and configure a new integration instance.  
  
| **Parameter** | **Description** | **Required** |  
| --- | --- | --- |  
| url | Server URL \(e.g. https://example.net\) | True |  
| apikey_id | API Key ID | True |  
| apikey | API Key | True |  
| feed | Fetch indicators | False |  
| severity | the severity in XDR | True |  
| query | query | True |  
| insecure | Trust any certificate \(not secure\) | False |  
| proxy | Use system proxy settings | False |  
| feedReputation | Indicator Reputation | False |  
| feedReliability | Source Reliability | True |  
| feedExpirationPolicy |  | False |  
| feedExpirationInterval |  | False |  
| feedFetchInterval | Feed Fetch Interval | False |  
| feedBypassExclusionList | Bypass exclusion list | False |  
  
4. Click **Test** to validate the URLs, token, and connection.  
## Commands  
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.  
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
  
### xdr-iocs-iocs-to-keep  
***  
Update all iocs to keep and delete the other.  
run this ones a day in 01:00 - 3:00 utc time.  
  
  
#### Base Command  
  
`xdr-iocs-to-keep`  
#### Input  
  
There are no input arguments for this command.  
  
#### Context Output  
  
There is no context output for this command.  
  
#### Command Example  
```xdr-iocs-to-keep```  
  
#### Human Readable Output  
  >sync with XDR completed.
  
  
### xdr-push-iocs  
***  
Push new iocs to XDR run this ones a min.  
  
  
#### Base Command  
  
`xdr-push-iocs`  
#### Input  
  
There are no input arguments for this command.  
  
#### Context Output  
  
There is no context output for this command.  
  
#### Command Example  
```xdr-push-iocs```  
  
#### Human Readable Output  
  
  
  
### xdr-enable-iocs  
***  
Enable iocs in XDR server  
  
  
#### Base Command  
  
`xdr-enable-iocs`  
#### Input  
  
| **Argument Name** | **Description** | **Required** |  
| --- | --- | --- |  
| indicator | The indicator to enable | Required |   
  
#### Context Output  
  
There is no context output for this command.  
  
#### Command Example  
```!xdr-enable-iocs indicator=11.11.11.11```  
    
#### Human Readable Output  
  
>indicators 11.11.11.11 enabled.  
  
### xdr-disable-iocs  
***  
Disable iocs in XDR server  
  
  
#### Base Command  
  
`xdr-disable-iocs`  
#### Input  
  
| **Argument Name** | **Description** | **Required** |  
| --- | --- | --- |  
| indicator | The indicator to enable | Required |   
  
#### Context Output  
  
There is no context output for this command.  
  
#### Command Example  
```!xdr-disable-iocs indicator=22.22.22.22```  
  
#### Human Readable Output  
  
>indicators 22.22.22.22 disabled.  
  