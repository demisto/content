## How to Access the Generic Export Indicators Service
<~XSOAR>
Use one of the following methods to access the Generic Export Indicators Service to make sure your indicators are exported properly.
</~XSOAR>

If you have several Generic Export Indicators Service integration instances, make sure to use **different listening ports** to separate the outbound feeds.
Note: After a successful configuration of an instance, if the 'test button' is clicked again, it may result in a failure due to an incorrect assumption that the port is already in use. Nevertheless, it is important to highlight that despite this issue, the instance will continue to function correctly.
<~XSOAR>

### Access the Generic Export Indicators Service by URL and Port (HTTP)
In a web browser, go to **http://<cortex-xsoar-server-address>:<listen_port>**.

**Note**: For security purposes, Cortex XSOAR recommends that you use HTTPS when accessing the indicator service through the URL and port. To do so, you must provide a certificate and private key, in the respective fields. In addition, make sure to provide credentials that must be used to connect to the integration instance.
</~XSOAR>

### Access the Generic Export Indicators Service by Instance Name (HTTPS)

<~XSIAM>
**Note**: Do not set `username` and `password` in the integration instance if you are running the integration via the hosted instance. The `username` and `password` fields are for usage when running the integration via an on-prem engine.

**Note**: If no `Listen Port` param was given and the test button was clicked, the test will run with the default port 1111. After pressing `save & exit` a new free port will be assigned to the `Listen Port` parameter automatically.

1. To access the **Generic Export Indicators Service** by instance name, set up the **username** and **password** values in the **External Dynamic List Integration** page (**Settings** > **Configurations** > **Integrations** > **External Dynamic List Integration**).
2. You can access the External Dynamic List at the following url: `https://edl-<cortex-xsiam-address>/xsoar/instance/execute/<instance-name>`.
3. For example to test via curl with an instance with instance name: `EDL_instance_1`, XSIAM address `my-xsiam-subdomain.us.paloaltonetworks.com` and credentials test/password:
```
curl -v -u test:password https://edl-my-xsiam-subdomain.us.paloaltonetworks.com/xsoar/instance/execute/EDL_instance_1
```

**Note**: The External Dynamic List is not accessible via web browsers and you will receive an unauthorized error if accessing the External Dynamic List via a browser.


</~XSIAM>
<~XSOAR>
**Note**: By default, the route to access the Generic Export Indicators Service by instance name will be open without security hardening and might expose you to network risks. Cortex XSOAR recommends that you use the service with a username and password. Click **Switch to username and password** and provide the credentials that must be used to access the service.

**Note**: For Cortex XSOAR version greater or equal to 8, if no `Listen Port` param was given and the test button was clicked, the test will run with the default port 1111. After pressing `save & exit` a new available port will be assigned to the `Listen Port` parameter automatically.
For a Cortex XSOAR version lower than 8, the `Listen Port` parameter is required.

To access the Generic Export Indicators Service by instance name, make sure *Instance execute external* is enabled.

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. (For Cortex XSOAR 6.x only) In the **Server Configuration** section, verify that the `instance.execute.external.<instance_name>` key is set to `true`. If this key does not exist, click **+ Add Server Configuration** and add the `instance.execute.external.<instance_name>` and set the value to `true`. See [this documentation](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.
3.  In a web browser, go to:
   (For Cortex XSOAR 6.x) `https://*<xsoar_address>*/instance/execute/*<instance_name>*`
      (For Cortex XSOAR 8 or Cortex XSIAM) `https://ext-<tenant>.crtx.<region>.paloaltonetworks.com/xsoar/instance/execute/<instance-name>`


   In Multi Tenant environments, go to `https://<cortex-xsoar-address>/acc-<account name>/instance/execute/<instance_name>/`

</~XSOAR>

#### Note:
When using more than one server in High Availability (HA) mode, the External Dynamic List (EDL) should be configured to listen on a route, not on a port.

In "route" listen mode, a request received by any of the app servers will be redirected to the one currently running the NGINX container.
This does not happen in "port" listen mode, that's why "route" mode should be used.

If the app server running the container fails, the container should restart on a different app server.
Failover time should be about 1 minute plus the container startup time.

### Modify Request Parameters Through the URL
Use the following arguments in the URL to change the request:

| argument | Description | Example |
| --- | --- | --- |
| **n** | The maximum number of entries in the output. If no value is provided, will use the value specified in the *List Size* parameter configured in the instance configuration. | https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?n=50 |
| **s** | The starting entry index from which to export the indicators. | https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?s=10&n=50 |
| **v** | The output format. Supports `PAN-OS (text)`, `CSV`, `JSON`, `mwg` and `proxysg` (alias: `bluecoat`). | https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=json |
| **q** | The query used to retrieve indicators from the system. If you are using this argument, no more than 100,000 can be exported through the EDL. | https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?q="type:ip and sourceBrand:my_source" |
| **t** | Only with `mwg` format. The type indicated on the top of the exported list. Supports: string, applcontrol, dimension, category, ip, mediatype, number and regex. | https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=mwg&t=ip |
| **sp** | If set. will strip ports off URLs, otherwise will ignore URLs with ports. | https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=text&sp |
| **di** | Only with `PAN-OS (text)` format. If set, will ignore URLs which are not compliant with PAN-OS URL format instead of being re-written. | https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=text&di |
| **pr** | If set, will strip protocols off URLs.| https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=text&pr |
|**cd** | Only with `proxysg` format. The default category for the exported indicators. | https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=proxysg&cd=default_category |
| **ca** | Only with `proxysg` format. The categories which will be exported. Indicators not in these categories will be classified as the default category. | https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=proxysg&ca=category1,category2 |
| **tr** | Only with `PAN-OS (text)` format. Whether to collapse IPs.<br/>* 0 - Do not collapse.<br/>* 1 - Collapse to ranges.<br/>* 2 - Collapse to CIDRs. | https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?q="type:ip and sourceBrand:my_source"&tr=1 |
| **tx** | Whether to output `CSV` formats as textual web pages. | https://{cortex-xsoar_instance}/instance/execute/{ExportIndicators_instance_name}?v=csv&tx |

### When Running in On-Demand Mode
Make sure you run the ***!export-indicators-list-update*** command for the first time to initialize the export process.

### Important Notes:
- If constantly using different queries for the same EDL instance through the *q* inline argument, it is recommended to use different instances of the EDL (one for each query), and set each one with a default query for better performance.
- When using the *q* inline argument, the number of exported indicators is limited to 100,000 due to performance reasons. To export more than 100,000 indicators, create a new instance of the integration with the desired Indicator Query and List Size.