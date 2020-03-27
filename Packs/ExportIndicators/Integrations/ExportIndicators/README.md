Use the Export Indicators Service integration to provide an endpoint with a list of indicators as a service for the system indicators.

## Use Cases
---
1. Export a list of malicious IPs to block via a firewall.
2. Export a list of indicators to a service such as Splunk, using a supported output format.

## Configure ExportIndicators on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for ExportIndicators.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Indicator Query__: The query to run to update its list. To view expected results, you can run the following command from the Demisto CLI
    `!findIndicators query=<your query>`
    * __Outbound Format__: The default format of the entries in the service. Supported formats: text, json, json-seq, csv, XSAOR json, XSAOR json-seq, XSOAR csv, PAN-OS URL, Symantec ProxySG and McAfee Web Gateway.
    * __List Size__: Max amount of entries in the service instance.
    * __Update On Demand Only__: When set to true, will only update the service indicators via **eis-update** command.
    * __Refresh Rate__: How often to refresh the export indicators list (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3
    months, 1 year)
    * __Collapse IPs__: Whether to collapse IPs and if so - to ranges or CIDRs
    * __Long Running Instance__: Must be set to true, otherwise the service will be available.
    * __Listen Port__: Will run the *Export Indicators Service* on this port from within Demisto
    * __Certificate (Required for HTTPS)__: HTTPS Certificate provided by pasting its values into this field.
    * __Private Key (Required for HTTPS)__: HTTPS private key provided by pasting its valuies into this field.
    * __HTTP Server__: Ignores certificate and private key, and will run the export indicators service
    in HTTP
    * __Username__: The username to authenticate when fetching the indicators.
    * __Password__: The password to authenticate when fetching the indicators.
    * __Mcafee Gateway Indicator List Type__: For use with McAfee Web Gateway format to indicate the list type.
    * __PAN-OS URL Format Port Strip__: For use with PAN-OS URL format - if checked will strip the port off
    urls. If not checked - url with ports will be ignored.
    * __PAN-OS URL Format Drop Invalid Entries__: For use with PAN-OS URL format - if checked any URL entry which is
    not compliant with PAN-OS EDL URL format the entry is dropped instead of being
    rewritten.
    * __Symantec ProxySG Default Category__: For use with Symantec ProxySG format - set the default category
    for the output.
    * __Symantec ProxySG Listed Categories__: For use with Symantec ProxySG format - set the categories that should
    be listed in the output. If not set will list all existing categories.
4. Click __Test__ to validate the URLs, token, and connection.


### Update values in the export indicators service
---
Updates values stored in the export indicators service (only avaialable On-Demand).


### URL Inline Arguments
---
Use the following arguments in the URL to change the request:

| **Argument Name** | **Description** | **Example** |
| --- | --- | --- |
| n | The maximum number of entries in the output. If no value is provided, will use the value specified in the List Size parameter configured in the instance configuration. | https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?n=50 |
| s | The starting entry index from which to export the indicators. | https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?s=10&n=50 |
| v | The output format. Supports `text`, `csv`, `json`, `json-seq`,`xsoar-json`, `xsoar-seq`, `xsoar-csv`, `mwg`, `panosurl` and `proxysg` (alias: `bluecoat`). | https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=json |
| q | The query used to retrieve indicators from the system. | https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?q="type:ip and sourceBrand:my_source" |
| t | Only with `mwg` format. The type indicated on the top of the exported list. Supports: string, applcontrol, dimension, category, ip, mediatype, number and regex. | https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=mwg&t=ip |
| sp | Only with `panosurl` format. If set will strip ports off URLs, otherwise will ignore URLs with ports. | https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=panosurl&sp |
| di | Only with `panosurl` format. If set will ignore urls which are not compliant with PAN-OS URL format instead of being re-written. | https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=panosurl&di |
| cd | Only with `proxysg` format. The default category for the exported indicators. | https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=proxysg&cd=default_category |
| ca | Only with `proxysg` format. The categories which will be exported. Indicators not falling to these categories will be classified as the default category. | https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=proxysg&ca=category1,category2 |
| tr | Whether to collapse IPs. 0 - to not collapse, 1 - collapse to ranges or 2 - collapse to CIDRs | https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?q="type:ip and sourceBrand:my_source"&tr=1 |


##### Base Command

`eis-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query used to retrieve indicators from the system. | Required | 
| format | The output format. | Optional | 
| list_size | The maximum number of entries in the output. If no value is provided, will use the value specified in the List Size parameter configured in the instance configuration. | Optional | 
| offset | The starting entry index from which to export the indicators. | Optional |
| print_indicators | If set to true will print the indicators the that were saved to the export indicators service | Required | 
| mwg_type | For use with McAfee Web Gateway format to indicate the list type. | Optional |
| strip_port | For use with PAN-OS URL format - if True will strip the port off urls. If not checked - url with ports will be ignored. | Optional |
| drop_invalids | For use with PAN-OS URL format - if checked any URL entry which is not compliant with PAN-OS EDL URL format the entry is dropped instead of being rewritten. | Optional |
| category_attribute | For use with Symantec ProxySG format - set the categories that should be listed in the output. If not set will list all existing categories. | Optional |
| category_default | For use with Symantec ProxySG format - set the default category for the output. | Optional |
| collapse_ips | Whether to collapse IPs, and if so - to ranges or CIDRs | Optional |
 

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
