## How to Access the Export Indicators Service
There are two ways that you can access the Export Indicators Service.

### Access the Export Indicators Service by URL and Port (HTTP)
In a web browser, go to **http://*demisto_address*:*listen_port***.


### Access the Export Indicators Service by Instance Name (HTTPS)
To access the EDL service by instance name, make sure ***Instance execute external*** is enabled. 

1. In Demisto, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the ***instance.execute.external*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*.
3. In a web browser, go to **https://*<demisto_address>*/instance/execute/*<instance_name>*** .

### Modify Request Parameters Through the URL
Use the following arguments in the URL to change the request:

1. **n** - The maximum number of entries in the output. If no value is provided, will use the value specified in the List Size parameter configured in the instance configuration.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?n=50
2. **s** - The starting entry index from which to export the indicators.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?s=10&n=50
3. **v** - The output format. Supports `text`, `csv`, `json` and `json-seq`.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?v=json
4. **q** - The query used to retrieve indicators from the system.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?q="type:ip and sourceBrand:my_source"
5. **tr** - Whether to collapse IPs. 
    * 0 - Do not collapse. 
    * 1 - Collapse to ranges.
    * 2 - Collapse to CIDRs.
 * Example: https://{demisto_instance}/instance/execute/{ExportIndicators_instance_name}?q="type:ip and sourceBrand:my_source"&tr=1
