This integration provides External Dynamic List (EDL) as a service for the system indicators (Outbound feed). The feed content can then be sent to 3rd parties for improving their security alignment.


## Use Cases
---
1. Generate feeds to be used on PAN-OS as External Dynamic Lists.
2. Create External Dynamic Lists (EDLs) of the IP addresses, URLs and domains used by ransomware, known APT groups, and active malware campaigns for tracking in AutoFocus.
3. Create External Dynamic Lists to track IPs and URLs commonly used by Microsoft Office365 or CDNs and cloud services, or used as tor exit nodes.

## Configure EDL on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for EDL.
3. Click **Add instance** to create and configure a new integration instance.


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Indicator Query | The query to run to update its list. To view expected results, you can run the following command from the Cortex XSOAR CLI `!findIndicators query=<your query>` | False |
| EDL Size | Max amount of entries in the service instance. | True |
| Update EDL On Demand Only | When set to true, will only update the service indicators via the **edl-update** command. | False |
| Refresh Rate | How often to refresh the export indicators list (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | False |
| Listen Port | By default HTTP, Will run the *External Dynamic List* on this port from within Cortex XSOAR | True |
| Certificate (Required for HTTPS) | Configure a certificate for the EDL instance. The certificate is provided by pasting its value into this field. Use only when accesing the EDL instance by port. | False |
| Private Key (Required for HTTPS) | Configure a private key. The private key is provided by pasting its value into this field. Use only when accesing the EDL instance by port. | False |
| Credentials | Set user and password for accessing the EDL instance. (Only applicable when https is used and a certificate profile is configured on the pan-os edl object) | False |
| Collapse IPs | Whether to collapse IPs, and if so - to ranges or CIDRs. | False |
| XSOAR Indicator Page Size | Internal page size used when querying XSOAR for the EDL. By default, this value shouldn't be changed | False |

4. Click **Test** to validate the URLs, token, and connection.

### Access the EDL Service by Instance Name (HTTPS)
**The route will be open without security hardening and might expose you to network risks.**

To access the EDL service by instance name, make sure ***Instance execute external*** is enabled.

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the ***instance.execute.external*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*. See [this documentation](https://xsoar.pan.dev/docs/integrations/long-running#invoking-http-integrations-via-cortex-xsoar-servers-route-handling) for further information.
3. In a web browser, go to `https://<cortex-xsoar_address>/instance/execute/<instance_name>` .

### URL Inline Arguments
Use the following arguments in the URL to change the request:

| **Argument Name** | **Description** | **Example** |
| --- | --- | --- |
| n | The maximum number of entries in the output. If no value is provided, will use the value specified in the List Size parameter configured in the instance configuration. | `https://{server_host}/instance/execute/{instance_name}?n=50` |
| s | The starting entry index from which to export the indicators. | `https://{server_host}/instance/execute/{instance_name}?s=10&n=50` |
| q | The query used to retrieve indicators from the system. | `https://{server_host}/instance/execute/{instance_name}?q="type:ip and sourceBrand:my_source"` |
| tr | Whether to collapse IPs. 0 - to not collapse, 1 - collapse to ranges or 2 - collapse to CIDRs | `https://{server_host}/instance/execute/{instance_name}?q="type:ip and sourceBrand:my_source"&tr=1` |
| sp | If set will strip ports off URLs, otherwise will ignore URLs with ports. | `https://{server_host}/instance/execute/{instance_name}?sp` |
| di | If set will ignore urls which are not compliant with PAN-OS URL format instead of being re-written. | `https://{server_host}/instance/execute/{instance_name}?di` |

## Commands
You can execute these commands from the Cortex XSOAR CLI as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### edl-update
***
Updates values stored in the EDL (only avaialable On-Demand).

##### Base Command

`edl-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query used to retrieve indicators from the system. | Required |
| edl_size | The maximum number of entries in the EDL. If no value is provided, will use the value specified in the EDL Size parameter configured in the instance configuration. | Optional |
| print_indicators | Boolean | Required |
| collapse_ips | Whether to collapse IPs, and if so - to ranges or CIDRs. | Optional |


##### Context Output
There is no context output for this command.

##### Command Example
```!edl-update print_indicators=true query=type:IP edl_size=2```

##### Human Readable Output
### EDL was updated successfully with the following values
|Indicators|
|---|
| 1.1.1.1<br/>2.2.2.2 |
