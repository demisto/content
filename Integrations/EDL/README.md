This integration provides External Dynamic List (EDL) as a service for the system indicators (Outbound feed).


## Use Cases
---
1. Generate feeds to be used on PAN-OS as External Dynamic Lists.
2. Create External Dynamic Lists (EDLs) to track on AutoFocus the IP addresses, URLs and domains used by ransomware, known APT groups, and active malware campaigns.
3. Create External Dynamic Lists to track the IPs and URLs used by Microsoft Office365, or used as tor exit nodes, or used by CDNs and cloud services.

## Configure EDL on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for EDL.
3. Click **Add instance** to create and configure a new integration instance.


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Indicator Query | The query to run to update its list. To view expected results, you can run the following command from the Demisto CLI `!findIndicators query=<your query>` | False |
| EDL Size | Max amount of entries in the service instance. | True |
| Update EDL On Demand Only | When set to true, will only update the service indicators via **edl-update** command. | False |
| Refresh Rate | How often to refresh the export indicators list (<number> <time unit>, e.g., 12 hours, 7 days, 3 months, 1 year) | False |
| Long Running Instance | Must be set to true, otherwise the service will not be available. | False |
| Listen Port | Will run the *External Dynamic List* on this port from within Demisto | True |
| Certificate (Required for HTTPS) | HTTPS Certificate provided by pasting its value into this field. | False |
| Private Key (Required for HTTPS | HTTPS private key provided by pasting its value into this field. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### edl-update
***
Updates values stored in the EDL (only avaialable On-Demand).

##### Base Command

`edl-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query used to retrieve indicators from the system. | Required | 
| edl_size | The maximum number of entries in the EDL. If no value is provided, will use the value specified in the EDL Size parameter configured in the instance configuration. | Optional | 
| print_indicators | Boolean | Required | 


##### Context Output
There is no context output for this command.

##### Command Example
```!edl-update print_indicators=true query=type:IP edl_size=2```

##### Human Readable Output
### EDL was updated successfully with the following values
|Indicators|
|---|
| 1.1.1.1<br>2.2.2.2 |
