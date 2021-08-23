## How to Access the Export Indicators Service
There are two ways that you can access the Export Indicators Service.
Use these to make sure your indicators are exported properly.

In case of several Export Indicators Service integration instances - make sure to use **different listening ports** to separate the outbound feeds.

### Access the Export Indicators Service by URL and Port (HTTP)
In a web browser, go to **http://*cortex-xsoar-server-address*:*listen_port***.

**Note**: For security purposes, Cortex XSOAR recommends that you use HTTPS when accessing the indicator service through the URL and port. To do so, you must provide a certificate and private key, in the respective fields. In addition, make sure to provide credentials that must be used to connect to the integration instance.

### Access the Export Indicators Service by Instance Name (HTTPS)

**Note**: By default, the route will be open without security hardening and might expose you to network risks. Cortex XSOAR recommends that you use the service with a username and password. Click **Switch to username and password** and provide the credentials that must be used to access the service.

To access the Export Indicators service by instance name, make sure ***Instance execute external*** is enabled. 

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the `instance.execute.external.<instance_name>` key is set to `true`. If this key does not exist, click **+ Add Server Configuration** and add the `instance.execute.external.<instance_name>` and set the value to `true`. See [this documentation](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.
3. In a web browser, go to `https://<cortex-xsoar_address>/instance/execute/<instance_name>/`.

### Modify Request Parameters Through the URL
Use the following arguments in the URL to change the request:

1. **n** - The maximum number of entries in the output. If no value is provided, will use the value specified in the *List Size* parameter configured in the instance configuration.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?n=50
2. **s** - The starting entry index from which to export the indicators.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?s=10&n=50
3. **v** - The output format. Supports `text`, `csv`, `json`, `json-seq`,`xsoar-json`, `xsoar-seq`, `xsoar-csv`, `mwg`, `panosurl` and `proxysg` (alias: `bluecoat`).
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=json
4. **q** - The query used to retrieve indicators from the system.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?q="type:ip and sourceBrand:my_source"
5. **t** - Only with `mwg` format. The type indicated on the top of the exported list. Supports: string, applcontrol, dimension, category, ip, mediatype, number and regex.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=mwg&t=ip
6. **sp** - Only with `panosurl` format. If set will strip ports off URLs, otherwise will ignore URLs with ports.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=panosurl&sp 
7. **di** - Only with `panosurl` format. If set will ignore URLs which are not compliant with PAN-OS URL format instead of being re-written.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=panosurl&di
8. **cd** - Only with `proxysg` format. The default category for the exported indicators.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=proxysg&cd=default_category
9. **ca** - Only with `proxysg` format. The categories which will be exported. Indicators not in these categories will be classified as the default category.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=proxysg&ca=category1,category2
10. **tr** - Whether to collapse IPs. 
    * 0 - Do not collapse. 
    * 1 - Collapse to ranges.
    * 2 - Collapse to CIDRs.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?q="type:ip and sourceBrand:my_source"&tr=1
11. **tx** - Whether to output `csv` or `xsoar-csv` formats as textual web pages.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=xsoar-csv&tx
12. **sf** - The field by which to sort the indicators by. Only applicable with the `sort_order` argument.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=xsoar-csv&sf=last_seen&so=asc
13. **so** - The direction by which to order the indicators. The options are `asc` or `desc`. Only applicable with the `sort_field` argument.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=xsoar-csv&sf=last_seen&so=desc

### When running in On-Demand mode
Please make sure to to run !eis-update for the first time to initialize the export process.