## How to Access the EDL Service

There are two ways that you can access the EDL service.

### Access the EDL Service by URL and Port (HTTP)
In a web browser, go to **http://*demisto_address*:*listen_port***.


### Access the EDL Service by Instance Name (HTTPS)
**The route will be open without security hardening and might expose you to network risks.**

To access the EDL service by instance name, make sure ***Instance execute external*** is enabled. 

1. In Demisto, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the ***instance.execute.external*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*. See [this documentation](https://xsoar.pan.dev/docs/integrations/long-running#invoking-http-integrations-via-cortex-xsoar-servers-route-handling) for further information.
3. In a web browser, go to **https://*<demisto_address>*/instance/execute/*<instance_name>*** .


### Modify Request Parameters Through the URL
Use the following arguments in the URL to modify the request:

1. **n** - The maximum number of entries in the output. If no value is provided, will use the value specified in the *List Size* parameter configured in the instance configuration.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{EDL_instance_name}?n=50
2. **s** - The starting entry index from which to export the indicators.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{EDL_instance_name}?s=10&n=50
3. **q** - The query used to retrieve indicators from the system.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{EDL_instance_name}?q="type:ip and sourceBrand:my_source"
4. **sp** - If set will strip ports off URLs, otherwise will ignore URLs with ports.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{EDL_instance_name}?v=panosurl&sp 
5. **di** - If set will ignore URLs that are not compliant with PAN-OS URL format instead of being rewritten.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{EDL_instance_name}?v=panosurl&di
6. **tr** - Whether to collapse IPs. 
    * 0 - Do not collapse. 
    * 1 - Collapse to ranges.
    * 2 - Collapse to CIDRs.
 * Example: https://{cortex-xsoar_instance}/instance/execute/{EDL_instance_name}?q="type:ip and sourceBrand:my_source"&tr=1

### When running in On-Demand mode
Make sure you run the `!edl-update` command for the first time to initialize the export process.
