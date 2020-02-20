## Overview
---
This integration provides External Dynamic List (EDL) as a service for the system indicators (Outbound feed).

## Use Cases
---
1. Generating feeds to be used on PAN-OS as External Dynamic Lists.
2. Create External Dynamic Lists to track on AutoFocus the IP addresses, URLs and domains used by ransomware, known APT groups and active malware campaigns.
3. Create External Dynamic Lists to track the IPs and URLs used by Microsoft Office365, or used as tor exit nodes, or used by CDNs and cloud services.


## Configure ExportIndicators on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for ExportIndicators.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Indicator Query__: The query to run to update its list. To view expected results, you can run the following command from the Demisto CLI
    `!findIndicators query=<your query>`
    * __EDL Size__: Max amount of entries in the service instance.
    * __Update On Demand Only__: When set to true, will only update the service indicators via **edl-update** command.
    * __Refresh Rate__: How often to refresh the export indicators list (<number> <time unit>, e.g., 12 hours, 7 days, 3
    months, 1 year)
    * __Long Running Instance__: Must be set to true, otherwise the service will not be available.
    * __Listen Port__: Will run the *Export Indicators Service* on this port from within Demisto
    * __Certificate (Required for HTTPS)__: HTTPS Certificate provided by pasting its values into this field.
    * __Private Key (Required for HTTPS)__: HTTPS private key provided by pasting its valuies into this field.
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. edl-update
### 1. edl-update
---
Updates values stored in the EDL (only avaialable On-Demand).
##### Base Command
`edl-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query used to retrieve indicators from the system. | Required | 
| format | The output format. | Optional | 
| list_size | The maximum number of entries in the output. If no value is provided, will use the value specified in the List Size parameter configured in the instance configuration. | Optional | 
| print_indicators | If set to true will print the indicators the that were saved to the EDL service | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!edl-update print_indicators=true query=type:IP format=text list_size=4```

##### Human Readable Output
| **Indicators** |
| --- |
| 1.1.1.1 |
| 2.2.2.2 |
| 3.3.3.3 |
| 4.4.4.4 |
