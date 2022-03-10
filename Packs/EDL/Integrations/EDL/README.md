Use the Generic Export Indicators Service integration to provide an endpoint with a list of indicators as a service for the system indicators.

## PAN-OS EDL Management to Export Indicators Service (PAN-OS EDL Service) migration steps
Unlike `PAN-OS EDL Management`, this integration hosts the EDL on the Cortex XSOAR server. Follow these steps to migrate your EDLs.
1. Convert existing EDL lists to indicators in Cortex XSOAR. This can be done automatically:
   1. Extract your EDL as a text file from the web server it's currently hosted on.
   2. Upload it as a file to the Playground and use the `ExtractIndicatorsFromTextFile` automation. e.g, `!ExtractIndicatorsFromTextFile entryID=<entry_id>` 
2. Go to the `Indicators` page and [filter](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/manage-indicators/understand-indicators/indicators-page.html) to find all of the indicators you extracted from the text file.
3. If needed, batch select the indicators and add a tag to the indicators you want to host as a specific EDL. Use this tag in the `Indicator Query` integration parameter when configuring the integration. For example, if you want to create an allowed list of indicators and a blocked list of indicators.
4. Edit the EDL object on the PAN-OS device to pull from the `Export Indicators Service (PAN-OS EDL Service)` instance, as explained in [### Access the Export Indicators Service by Instance Name (HTTPS)](#access-the-export-indicators-service-by-instance-name-(https)). You can edit the EDL object using the [panorama-edit-edl](https://xsoar.pan.dev/docs/reference/integrations/panorama#panorama-edit-edl) command in the `Palo Alto Networks PAN-OS` integration.
5. Commit and push the configuration from the Panorama device to its respective Firewalls using the [PAN-OS Commit Configuration](https://xsoar.pan.dev/docs/reference/playbooks/pan-os-commit-configuration) playbook.
6. If you have a deployment with 100 firewalls or more, we recommend using your Panorama device and creating an EDL object there, which will be populated from the `PAN-OS EDL Service`. Then push the EDL object to the respective firewalls.
7. Follow the instructions in the rest of this guide to make sure that the PAN-OS device is connected to the EDL service.

## Use Cases
---
1. Export a list of malicious IPs to block via a firewall.
2. Export a list of indicators to a service such as Splunk, using a supported output format.
3. Generate feeds to be used on PAN-OS as External Dynamic Lists.
4. Create External Dynamic Lists (EDLs) of the IP addresses, URLs and domains used by ransomware, known APT groups, and active malware campaigns for tracking in AutoFocus.
5. Create External Dynamic Lists to track IPs and URLs commonly used by Microsoft Office365 or CDNs and cloud services, or used as tor exit nodes.

## Configure Generic Export Indicators Service on Cortex XSOAR
---

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Generic Export Indicators Service.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Update list on demand only | Enabling this will prevent automatic list refresh. | False |
| Indicator Query | The query to run to update the indicators list. To view expected results, you can run the following command from the Cortex XSOAR CLI `!findIndicators query=<your query>` | False |
| Outbound Format | The format in which the list will be exported in. | True |
| Exported Fields | For use with JSON and CSV formats - select specific XSOAR fields to export. If given the value 'all' - all XSOAR fields will be exported. If left empty - only value and type will be exported. | False |
| List Size | Maximum number of items in the list. | True |
| Refresh Rate | How often to refresh the list (e.g., 5 minutes, 12 hours, 7 days, to less than 1 minute. 3 months, 1 year). For performance reasons, we do not recommend setting this value less than 1 minute. | False |
| Listen Port | Will run the service on this port from within Cortex XSOAR. Requires a unique port for each long-running integration instance. Do not use the same port for multiple instances. | True |
| Certificate (Required for HTTPS) | For use with HTTPS - the certificate that the service should use. | False |
| Private Key (Required for HTTPS) | For use with HTTPS - the private key that the service should use. | False |
| Username | Uses basic authentication for accessing the list. If empty, no authentication is enforced. | False |
| Password | Uses basic authentication for accessing the list. If empty, no authentication is enforced. | False |
| Add comment to empty list | If selected, add to an empty list the comment "# Empty list". | False |
| Strip ports from URLs | If selected, ports in URLs will be removed. For example, 'www.example.com:9999/path' would become 'www.example.com/path'. | False |
| Strip protocols from URLs | If selected, will strip the protocol from URLs (http/https). | False |
| Truncate URL length | If selected, URLs will be truncated to no more than 254 characters. | False |
| Prepend string to list | String to add to beginning of published list. Supports newline characters (\n). | False |
| Append string to list | String to add to end of published list. Supports newline characters (\n). | False |
| IP Collapsing | For use with PAN-OS (text) format - collapse method for IPs (none, range, CIDR). | False |
| PAN-OS: drop invalid URL entries | For use with PAN-OS (text) format - if selected, any URL entry that is not compliant with PAN-OS URL format is dropped instead of being rewritten. | False |
| McAfee Gateway: Indicator List Type | For use with McAfee Web Gateway format - set the indicator list type. | False |
| Symantec ProxySG: Default Category | For use with Symantec ProxySG format - set the default category for the output. | False |
| Symantec ProxySG: Listed Categories | For use with Symantec ProxySG format - set the categories that should be listed in the output. If not set, will list all existing categories. | False |
| Show CSV formats as Text | If selected, CSV format will appear in a textual webpage instead of initiating a file download. | False |
| XSOAR Indicator Page Size | Internal page size used when querying Cortex XSOAR for the indicators. | False |
| Advanced: NGINX Global Directives | NGINX global directives to be passed on the command line using the -g option. Each directive should end with `;`. For example: `worker_processes 4; timer_resolution 100ms;`. Advanced configuration to be used only if instructed by XSOAR Support. | False |
| Advanced: NGINX Server Conf | NGINX server configuration to be used instead of the default NGINX_SERVER_CONF used in the integration code. Advanced configuration to be used only if instructed by XSOAR Support. | False |
| Advanced: NGINX Read Timeout | NGNIX read timeout in seconds. | False |
| Advanced: use legacy queries | When enabled, the integration will query the server using full queries. Advanced configuration to be used only if instructed by XSOAR Support, or you've encountered log errors in the form of: 'msgpack: invalid code.' | False |

### Access the Export Indicators Service by Instance Name (HTTPS)
**Note**: By default, the route will be open without security hardening and might expose you to network risks. Cortex XSOAR recommends that you use credentials to connect to connect to the integration.

To access the Export Indicators service by instance name, make sure ***Instance execute external*** is enabled. 

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the ***instance.execute.external*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*. See [this documentation](https://xsoar.pan.dev/docs/integrations/long-running#invoking-http-integrations-via-cortex-xsoar-servers-route-handling) for further information.
3. In a web browser, go to `https://*<demisto_address>*/instance/execute/*<instance_name>*` .

### URL Inline Arguments
Use the following arguments in the URL to change the request:

| **Argument Name** | **Description** | **Example** |
| --- | --- | --- |
| n | The maximum number of entries in the output. If no value is provided, will use the value specified in the List Size parameter configured in the instance configuration. | `https://{server_host}/instance/execute/{instance_name}?n=50` |
| s | The starting entry index from which to export the indicators. | `https://{server_host}/instance/execute/{instance_name}?s=10&n=50` |
| v | The output format. Supports `PAN-OS (text)`, `CSV`, `JSON`, `mwg` and `proxysg` (alias: `bluecoat`). | `https://{server_host}/instance/execute/{instance_name}?v=JSON` |
| q | The query used to retrieve indicators from the system. | `https://{server_host}/instance/execute/{instance_name}?q="type:ip and sourceBrand:my_source"` |
| t | Only with `mwg` format. The type indicated on the top of the exported list. Supports: string, applcontrol, dimension, category, ip, mediatype, number and regex. | `https://{server_host}/instance/execute/{instance_name}?v=mwg&t=ip` |
| sp | If set will strip ports off URLs. | `https://{server_host}/instance/execute/{instance_name}?v=PAN-OS (text)&sp` |
| pr | If set will strip protocol off URLs. | `https://{server_host}/instance/execute/{instance_name}?v=text&pr` |
| di | Only with `PAN-OS (text)` format. If set will ignore urls which are not compliant with PAN-OS URL format instead of being re-written. | `https://{server_host}/instance/execute/{instance_name}?v=PAN-OS (text)&di` |
| tr | Only with `PAN-OS (text)`Whether to collapse IPs. 0 - to not collapse, 1 - collapse to ranges or 2 - collapse to CIDRs | `https://{server_host}/instance/execute/{instance_name}?q="type:ip and sourceBrand:my_source"&tr=1` |
| cd | Only with `proxysg` format. The default category for the exported indicators. | `https://{server_host}/instance/execute/{instance_name}?v=proxysg&cd=default_category` |
| ca | Only with `proxysg` format. The categories which will be exported. Indicators not falling to these categories will be classified as the default category. | `https://{server_host}/instance/execute/{instance_name}?v=proxysg&ca=category1,category2` |
| tx | Whether to output `CSV` format as textual web pages. | `https://{server_host}/instance/execute/{instance_name}?v=CSV&tx` |
| fi | Only with `CSV` or `JSON` format - Select fields to export. | `https://{server_host}/instance/execute/{instance_name}?v=CSV&tx` |

## Commands
You can execute these commands from the Cortex XSOAR CLI as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.


### export-indicators-list-update
***
Updates values stored in the List (only available On-Demand).

##### Base Command

`export-indicators-list-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query used to retrieve indicators from the system. Leave empty to use the query from the integration parameters.  | Optional | 
| format | The output format. | Optional | 
| edl_size | The maximum number of entries in the output. If no value is provided, will use the value specified in the List Size parameter configured in the instance configuration. | Optional | 
| print_indicators | If set to true will print the indicators that were saved to the export indicators service | Required | 
| mwg_type | For use with McAfee Web Gateway format to indicate the list type. | Optional |
| url_port_stripping | if True will strip the port off urls. | Optional |
| url_protocol_stripping | if True will strip the port off urls. | Optional |
| drop_invalids | For use with PAN-OS (text) format - if checked any URL entry which is not compliant with PAN-OS EDL URL format the entry is dropped instead of being rewritten. | Optional |
| category_attribute | For use with Symantec ProxySG format - set the categories that should be listed in the output. If not set will list all existing categories. | Optional |
| category_default | For use with Symantec ProxySG format - set the default category for the output. | Optional |
| collapse_ips | For use with PAN-OS (text) format - Whether to collapse IPs, and if so - to ranges or CIDRs | Optional |
| csv_text | If True, will output csv format as textual web pages | Optional |
| add_comment_if_empty | If selected, add to an empty List the comment "# Empty List". | Optional |

##### Context Output
There is no context output for this command.

##### Command Example
```!export-indicators-list-update=type:IP edl_size=2```

##### Human Readable Output
'EDL will be updated the next time you access it'

### Troubleshooting
Memory issue can happen in CSV / JSON format over 150,000 if all fields are selected.

#### In terms of times
10,000 indicators can take 10 - 20 seconds
100,000 indicators can take 1 - 3 minutes
1,000,000: takes over half an hour
In 5 minutes (the default timeout of the integration) it does export between 200,000 - 400,000[[]]
depending on the load on the server. the existing indicators in the server, and the query.
For more than that need to set *NGINX Read Timeout* 