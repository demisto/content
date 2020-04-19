This integration fetches indicators from AlienVault OTX using a TAXII client.

This integration can only fetch indicators from **active** collections - collections which contain at least a single indicator.

## Configure AlienVault OTX TAXII Feed on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AlienVault OTX TAXII Feed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| api_key | API Key | True |
| all_collections | Get All Active Collections - if selected the integration will run on all **active** collections regaurdless of the 
collections supplied in the Collections parameter. Inactive collections will not return indicators. | False |
| collections | Collections to Fetch From | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |


If you do not know which collections are available - do not set the Collections and All Collections parameters -  The resulting error message will list all the accessible collections.
*Note*: not all listed collections are **active**.

4. Click **Test** to validate the URLs, token, and connection.



## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### alienvaultotx-get-indicators
***
Gets the indicators from AlienVault OTX.


##### Base Command

`alienvaultotx-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. The default value is 10. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!alienvaultotx-get-indicators limit=3```


##### Human Readable Output
### Indicators from AlienVault OTX TAXII:
|value|type|
|---|---|
| 1.2.3.4 | IP |
| https://demisto.com | URL |
| demisto.com | Domain |

## Video Demo
![image](doc_files/AlienVault_OTX_Feed_Demo.mp4)
