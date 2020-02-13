## Overview
---
This integration provides an endpoint with a list of indicators as a service for the system indicators.

## Use Cases
---
1. Export list of malicious IPs to block via a firewall.
2. Export list of indicators the a supporting service such as Splunk (via csv output).

## Configure ExportIndicators on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for ExportIndicators.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Indicator Query__: The query to run to update its list. To view expected results, you can run the following command from the Demisto CLI
    `!findIndicators query=<your query>`
    * __Outbound Format__: The default format of the entries in the service. Supported formats: text, json, json-seq, csv
    * __List Size__: Max amount of entries in the service instance.
    * __Update On Demand Only__: When set to true, will only update the service indicators via **eis-update** command.
    * __Refresh Rate__: How often to refresh the export indicators list (<number> <time unit>, e.g., 12 hours, 7 days, 3
    months, 1 year)
    * __Long Running Instance__: Must be set to true, otherwise the service will be available.
    * __Listen Port__: Will run the *Export Indicators Service* on this port from within Demisto
    * __Certificate (Required for HTTPS)__: HTTPS Certificate provided by pasting its values into this field.
    * __Private Key (Required for HTTPS)__: HTTPS private key provided by pasting its valuies into this field.
    * __HTTP Server__: Ignores certificate and private key, and will run the export indicators service
    in HTTP
    * __Username__: The username to authenticate when fetching the indicators.
    * __Password__: The username to authenticate when fetching the indicators.
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. eis-update
### 1. eis-update
---
Updates values stored in the export indicators service (only avaialable On-Demand).
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`eis-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query used to retrieve indicators from the system. | Required | 
| format | The output format. | Optional | 
| list_size | The maximum number of entries in the output. If no value is provided, will use the value specified in the List Size parameter configured in the instance configuration. | Optional | 
| print_indicators | If set to true will print the indicators the that were saved to the export indicators service | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!eis-update print_indicators=true query=type:IP format=text list_size=4```

##### Human Readable Output
| **Indicators** |
| --- |
| 1.1.1.1 |
| 2.2.2.2 |
| 3.3.3.3 |
| 4.4.4.4 |
