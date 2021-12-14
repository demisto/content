This integration provides External Dynamic List (EDL) as a service for system indicators (Outbound feed). The feed content can then be sent to 3rd parties for improving their security alignment.

## PAN-OS EDL Management to PAN-OS EDL Service migration steps
Unlike `PAN-OS EDL Management`, this integration hosts the EDL on the Cortex XSOAR server. Follow these steps to migrate your EDLs.
1. Convert existing EDL lists to indicators in Cortex XSOAR. This can be done automatically:
   1. Extract your EDL as a text file from the web server it's currently hosted on.
   2. Upload it as a file to the Playground and use the `ExtractIndicatorsFromTextFile` automation. e.g, `!ExtractIndicatorsFromTextFile entryID=<entry_id>` 
2. Go to the `Indicators` page and [filter](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/manage-indicators/understand-indicators/indicators-page.html) to find all of the indicators you extracted from the text file.
3. If needed, batch select the indicators and add a tag to the indicators you want to host as a specific EDL. Use this tag in the `Indicator Query` integration parameter when configuring the integration. For example, if you want to create an allowed list of indicators and a blocked list of indicators.
4. Edit the EDL object on the PAN-OS device to pull from the `PAN-OS EDL Service` instance, as explained in [Access the EDL Service by Instance Name (HTTPS)](#access-the-edl-service-by-instance-name-(https)). You can edit the EDL object using the [panorama-edit-edl](https://xsoar.pan.dev/docs/reference/integrations/panorama#panorama-edit-edl) command in the `Palo Alto Networks PAN-OS` integration.
5. Commit and push the configuration from the Panorama device to its respective Firewalls using the [PAN-OS Commit Configuration](https://xsoar.pan.dev/docs/reference/playbooks/pan-os-commit-configuration) playbook.
6. If you have a deployment with 100 firewalls or more, we recommend using your Panorama device and creating an EDL object there, which will be populated from the `PAN-OS EDL Service`. Then push the EDL object to the respective firewalls.
7. Follow the instructions in the rest of this guide to make sure that the PAN-OS device is connected to the EDL service.

## Use Cases
---
1. Generate feeds to be used on PAN-OS as External Dynamic Lists.
2. Create External Dynamic Lists (EDLs) of the IP addresses, URLs and domains used by ransomware, known APT groups, and active malware campaigns for tracking in AutoFocus.
3. Create External Dynamic Lists to track IPs and URLs commonly used by Microsoft Office365 or CDNs and cloud services, or used as tor exit nodes.

## Configure Palo Alto Networks PAN-OS EDL Service on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for EDL.
3. Click **Add instance** to create and configure a new integration instance.


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Indicator Query | The query to run to update its list. To view expected results, you can run the following command from the Cortex XSOAR CLI `!findIndicators query=<your query>` | False |
| EDL Size | Maximum number of entries in the service instance. | True |
| Update EDL On Demand Only | When set to true, will only update the service indicators via the **edl-update** command. | False |
| Refresh Rate | How often to refresh the export indicators list (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | False |
| Listen Port | By default HTTP. Runs the *External Dynamic List* on this port from within Cortex XSOAR. You can use any available port except for 80, 443, or 9100. When the `instance.execute.external.<instance_name>` key is set to true, Cortex XSOAR redirects the endpoint from HTTPS to the container on the port that you specify here, using port 443 as the secured publicly open port. | True |
| Certificate (Required for HTTPS) | Configure a certificate for the EDL instance. The certificate is provided by pasting its value into this field. Use only when accesing the EDL instance by port. | False |
| Private Key (Required for HTTPS) | Configure a private key. The private key is provided by pasting its value into this field. Use only when accesing the EDL instance by port. | False |
| Credentials | Set user and password for accessing the EDL instance. (Only applicable when https is used and a certificate profile is configured on the pan-os edl object) | False |
| Strip Ports from URLs | If selected, a URL that includes a port number will be reformatted to remove the port. For example, 'www.example.com:9999/path' would become 'www.example.com/path'. | False |
| PAN-OS URL Drop Invalid Entries | If selected, any URL entry that is not compliant with PAN-OS EDL URL format is dropped instead of being rewritten. | False |
| Add Comment To Empty EDL | If selected, add to an empty EDL the comment "# Empty EDL". | False |
| Collapse IPs | Whether to collapse IPs, and if so - to ranges or CIDRs. | False |
| XSOAR Indicator Page Size | Internal page size used when querying XSOAR for the EDL. By default, this value shouldn't be changed | False |
| NGINX Global Directives | NGINX global directives to be passed on the command line using the -g option. Each directive should end with `;`. For example: `worker_processes 4; timer_resolution 100ms;`. Advanced configuration to be used only if instructed by XSOAR Support. | False |
| NGINX Server Conf | NGINX server configuration. To be used instead of the default `NGINX_SERVER_CONF` used in the integration code. Advanced configuration to be used only if instructed by XSOAR Support. | False |
| Advanced: Use Legacy Queries | Legacy Queries : When enabled, the integration will query the Server using full queries. Enable this query mode, if you've been instructed by Support, or you've encountered in the log errors of the form: `msgpack: invalid code`. | False |

4. Click **Test** to validate the URLs, token, and connection.

### Access the EDL Service via XSOAR Server's HTTPS endpoint
**Note: The EDL is open to the same network to which the Cortex XSOAR Server is accessible. Make sure you are aware of the network risks - enabling strong authentication is highly recommended if the route is open to the public.**

To access the EDL service by instance name, make sure ***Instance Execute External*** is enabled.

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the `instance.execute.external.<instance_name>` key is set to `true`. If this key does not exist, click **+ Add Server Configuration** and add the `instance.execute.external.<instance_name>` and set the value to `true`. See [this documentation](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.
3. In a web browser, go to `https://<cortex-xsoar_address>/instance/execute/<instance_name>/`.

### URL Inline Arguments
Use the following arguments in the URL to change the request:

| **Argument Name** | **Description** | **Example** |
| --- | --- | --- |
| n | The maximum number of entries in the output. If no value is provided, will use the value specified in the List Size parameter configured in the instance configuration. | `https://{server_host}/instance/execute/{instance_name}?n=50` |
| s | The starting entry index from which to export the indicators. | `https://{server_host}/instance/execute/{instance_name}?s=10&n=50` |
| q | The query used to retrieve indicators from the system. Make sure to [URL encode](https://www.w3schools.com/tags/ref_urlencode.ASP). | `https://{server_host}/instance/execute/{instance_name}?q=type:IP+and+reputation:Bad` |
| tr | Whether to collapse IPs. 0 - to not collapse, 1 - collapse to ranges or 2 - collapse to CIDRs | `https://{server_host}/instance/execute/{instance_name}?q="type:ip and sourceBrand:my_source"&tr=1` |
| sp | If set, will strip ports off URLs, otherwise will ignore URLs with ports. | `https://{server_host}/instance/execute/{instance_name}?sp` |
| di | If set, will ignore urls which are not compliant with PAN-OS URL format instead of being re-written. | `https://{server_host}/instance/execute/{instance_name}?di` |
| ce | If selected, add to an empty EDL the comment "# Empty EDL". | `https://{server_host}/instance/execute/{instance_name}?ce` |

## Commands
You can execute these commands from the Cortex XSOAR CLI as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### edl-update
***
Updates values stored in the EDL (only available On-Demand).

##### Base Command

`edl-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query used to retrieve indicators from the system. | Required |
| edl_size | The maximum number of entries in the EDL. If no value is provided, will use the value specified in the EDL Size parameter configured in the instance configuration. | Optional |
| collapse_ips | Whether to collapse IPs, and if so - to ranges or CIDRs. | Optional |
| drop_invalids | If True, any URL entry that is not compliant with PAN-OS EDL URL format is dropped instead of being rewritten. | Optional |
| url_port_stripping | If set to True, a URL that includes a port number will be reformatted to remove the port. For example, 'www.example.com:9999/path' would become 'www.example.com/path'. | Optional |
| add_comment_if_empty | If selected, add to an empty EDL the comment "# Empty EDL". | Optional |
| collapse_ips | Whether to collapse IPs to ranges or CIDRs. | Optional |
| offset | The starting entry index from which to export the indicators. | Optional |

##### Context Output
There is no context output for this command.

##### Command Example
```!edl-update query=type:IP edl_size=2```

##### Human Readable Output
'EDL will be updated the next time you access it'
