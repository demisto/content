## How to Access the Export Indicators Service
There are two ways that you can access the Export Indicators Service.
Use these to make sure your indicators are exported properly.

### Access the Export Indicators Service by URL and Port (HTTP)
In a web browser, go to **http://*demisto_address*:*listen_port***.

In case of several Export Indicators Service integration instances - make sure to use **different listening ports** to separate the outbound feeds.

### Access the Export Indicators Service by Instance Name (HTTPS)
**The route will be open without security hardening and might expose you to network risks.**

To access the EDL service by instance name, make sure ***Instance execute external*** is enabled. 

1. In Demisto, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the ***instance.execute.external*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*. See [this documentation](https://xsoar.pan.dev/docs/integrations/long-running#invoking-http-integrations-via-cortex-xsoar-servers-route-handling) for further information.
3. In a web browser, go to **https://*<demisto_address>*/instance/execute/*<instance_name>*** .

### Modify Request Parameters Through the URL
Use the following arguments in the URL to change the request:

1. **n** - The maximum number of entries in the output. If no value is provided, will use the value specified in the *List Size* parameter configured in the instance configuration.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?n=50
2. **s** - The starting entry index from which to export the indicators.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?s=10&n=50
3. **v** - The output format. Supports `text`, `csv`, `json`, `json-seq`,`xsoar-json`, `xsoar-seq`, `xsoar-csv`, `mwg`, `panosurl` and `proxysg` (alias: `bluecoat`).
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=json
4. **q** - The query used to retrieve indicators from the system.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?q="type:ip and sourceBrand:my_source"
5. **t** - Only with `mwg` format. The type indicated on the top of the exported list. Supports: string, applcontrol, dimension, category, ip, mediatype, number and regex.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=mwg&t=ip
6. **sp** - Only with `panosurl` format. If set will strip ports off URLs, otherwise will ignore URLs with ports.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=panosurl&sp 
7. **di** -  Only with `panosurl` format. If set will ignore URLs which are not compliant with PAN-OS URL format instead of being re-written.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=panosurl&di
8. **cd** - Only with `proxysg` format. The default category for the exported indicators.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=proxysg&cd=default_category
9. **ca** - Only with `proxysg` format. The categories which will be exported. Indicators not in these categories will be classified as the default category.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=proxysg&ca=category1,category2
10. **tr** - Whether to collapse IPs. 
    * 0 - Do not collapse. 
    * 1 - Collapse to ranges.
    * 2 - Collapse to CIDRs.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?q="type:ip and sourceBrand:my_source"&tr=1
11. **tx** - Whether to output `csv` or `xsoar-csv` formats as textual web pages.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=xsoar-csv&tx

### When running in On-Demand mode
Please make sure to to run !eis-update for the first time to initialize the export process.
