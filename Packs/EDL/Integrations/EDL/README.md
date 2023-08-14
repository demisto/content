Use the Generic Export Indicators Service integration to provide an endpoint with a list of indicators as a service for the system indicators.
For Cortex XSOAR 8, see [Manage External Dynamic Lists in the Cortex XSOAR Administrator Guide](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Administrator-Guide/Manage-External-Dynamic-Lists).

## PAN-OS EDL Management to Export Indicators Service (PAN-OS EDL Service) migration steps
Unlike `PAN-OS EDL Management`, this integration hosts the EDL on the Cortex XSOAR server. Follow these steps to migrate your EDLs.
1. Convert existing EDL lists to indicators in Cortex XSOAR. This can be done automatically:
    1. Extract your EDL as a text file from the web server it's currently hosted on.
    2. Upload it as a file to the Playground and use the `ExtractIndicatorsFromTextFile` automation. e.g., `!ExtractIndicatorsFromTextFile entryID=<entry_id>`
2. Go to the `Indicators` page and [filter](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Indicators) to find all of the indicators you extracted from the text file.
3. If needed, batch select the indicators and add a tag to the indicators you want to host as a specific EDL. Use this tag in the `Indicator Query` integration parameter when configuring the integration. For example, if you want to create an allowed list of indicators and a blocked list of indicators.
4. Edit the EDL object on the PAN-OS device to pull from the `Export Indicators Service (PAN-OS EDL Service)` instance, as explained in [Access the Export Indicators Service by Instance Name (HTTPS)](#access-the-export-indicators-service-by-instance-name-https). You can edit the EDL object using the [panorama-edit-edl](https://xsoar.pan.dev/docs/reference/integrations/panorama#panorama-edit-edl) command in the `Palo Alto Networks PAN-OS` integration.
5. Commit and push the configuration from the Panorama device to its respective Firewalls using the [PAN-OS Commit Configuration](https://xsoar.pan.dev/docs/reference/playbooks/pan-os-commit-configuration) playbook.
6. If you have a deployment with 100 firewalls or more, we recommend using your Panorama device and creating an EDL object there, which will be populated from the `PAN-OS EDL Service`. Then push the EDL object to the respective firewalls.
7. Follow the instructions in the rest of this guide to make sure that the PAN-OS device is connected to the EDL service.

***Important Notes:***
- EDL is designed to spawn on two processes: NGNIX and Python. NGNIX is the process that listens on the configured port, while the Python process listens on the configured port + 1. This means that if an integration was configured for port 9009, the NGNIX process will listen on port 9009 and Python on port 9010. When running without --network=host, the Python port is not exposed to the machine.
- 
- If constantly using different queries for the same EDL instance through the *q* inline argument, it is recommended to use different instances of the EDL (one for each query), and set each one with a default query for better performance.
- When using the *q* inline argument, the number of exported indicators is limited to 100,000 due to performance reasons. To export more than 100,000 indicators, create a new instance of the integration with the desired Indicator Query and List Size.
- Note: After a successful configuration of an instance, if the 'test button' is clicked again, it may result in a failure due to an incorrect assumption that the port is already in use. Nevertheless, it is important to highlight that despite this issue, the instance will continue to function correctly.
## Troubleshooting
- If you are encountering an 504 Gateway error:
  1. Increase the NGINX Read Timeout in the instance configuration (for 1,000,000 indicators, it is recommended to increase the timeout up to 1 hour).
  2. If the issue persists, try to increase the Load Balancer timeout through the Devops team (for 800,000 indicators, it is recommended to increase the timeout up to 1 hour (depends on the indicator query)).
## Use Cases
---
1. Export a list of malicious IPs to block via a firewall.
2. Export a list of indicators to a service such as Splunk, using a supported output format.
3. Generate feeds to be used on PAN-OS as External Dynamic Lists.
4. Create External Dynamic Lists (EDLs) of the IP addresses, URLs, and domains used by ransomware, known APT groups, and active malware campaigns for tracking in AutoFocus.
5. Create External Dynamic Lists to track IPs and URLs commonly used by Microsoft Office365 or CDNs and cloud services, or used as tor exit nodes.

## Configure Generic Export Indicators Service on Cortex XSOAR
---

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Generic Export Indicators Service.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter**                      | **Description**                                                                                                                                                                                                                                      | **Required** |
|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Update list on demand only         | Enabling this prevents automatic list refresh.                                                                                                                                                                                                   | False        |
| Indicator Query                    | The query to run to update the indicators list. To view expected results, run the following command from the Cortex XSOAR CLI `!findIndicators query=<your query>` (Field names in your query should match the [machine name](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Create-a-Custom-Indicator-Field) for each field.)                                                                          | False        |
| Outbound Format                    | The format of the exported list.                                                                                                                                                                                                     | True         |
| Exported Fields                    | For use with JSON and CSV formats - select specific Cortex XSOAR fields to export. If given the value 'all' - all Cortex XSOAR fields are exported. If empty - only value and type are exported.                                                      | False        |
| List Size                          | Maximum number of items in the list.                                                                                                                                                                                                                 | True         |
| Refresh Rate                       | How often to refresh the list (e.g., less than 1 minute, 5 minutes, 12 hours, 7 days, 3 months, 1 year). For performance reasons, we do not recommend setting this value at less than 1 minute.                                                      | False        |
| Listen Port                        | Runs the service on this port from within Cortex XSOAR. Requires a unique port for each long-running integration instance. Do not use the same port for multiple instances.  Note:  If you click the test button more than once, a failure may occur mistakenly indicating that the port is already in use."                                                            | True         |
| Certificate (Required for HTTPS)   | For use with HTTPS - the certificate that the service should use.                                                                                                                                                                                    | False        |
| Private Key (Required for HTTPS)   | For use with HTTPS - the private key that the service should use.                                                                                                                                                                                    | False        |
| Username                           | Uses basic authentication for accessing the list. If empty, no authentication is enforced.                                                                                                                                                           | False        |
| Password                           | Uses basic authentication for accessing the list. If empty, no authentication is enforced.                                                                                                                                                           | False        |
| Add comment to empty list          | If selected, add to an empty list the comment "# Empty list".                                                                                                                                                                                        | False        |
| Strip ports from URLs              | If selected, ports in URLs are removed. For example, 'www.example.com:9999/path' becomes 'www.example.com/path'.                                                                                                                            | False        |
| Strip protocols from URLs          | If selected, strips the protocol from URLs (http/https)/.                                                                                                                                                                                         | False        |
| Truncate URL length                | If selected, URLs are truncated to no more than 254 characters.                                                                                                                                                                                  | False        |
| Prepend string to list             | String to add to beginning of published list. Supports newline characters (\n).                                                                                                                                                                      | False        |
| Append string to list              | String to add to end of published list. Supports newline characters (\n).                                                                                                                                                                            | False        |
| IP Collapsing                      | For use with PAN-OS (text) format - collapse method for IPs (none, range, CIDR).                                                                                                                                                                     | False        |
| PAN-OS: drop invalid URL entries   | For use with PAN-OS (text) format - if selected, any URL entry that is not compliant with PAN-OS URL format is dropped instead of rewritten.                                                                                                   | False        |
| McAfee Gateway: Indicator List Type | For use with McAfee Web Gateway format - set the indicator list type.                                                                                                                                                                                | False        |
| Symantec ProxySG: Default Category | For use with Symantec ProxySG format - set the default category for the output.                                                                                                                                                                      | False        |
| Symantec ProxySG: Listed Categories | For use with Symantec ProxySG format - set the categories that should be listed in the output. If not set, lists all existing categories.                                                                                                        | False        |
| Show CSV formats as Text           | If selected, CSV format appears in a textual webpage instead of initiating a file download.                                                                                                                                                      | False        |
| XSOAR Indicator Page Size          | Internal page size used when querying Cortex XSOAR for the indicators.                                                                                                                                                                               | False        |
| Maximum CIDR network prefix bits size   | CIDRs with a lower network prefix bits number are not included. For example - if the number is 8, then 0.0.0.0/2 is excluded from the list.                                                                                                                                                                    | False         |
| Exclude top level domainGlobs        | Option to remove top level domainGlobs from the list. For example - \*.com.                                                                                                                                                                                     | False         |
| Advanced: NGINX Global Directives  | NGINX global directives to be passed on the command line using the -g option. Each directive should end with `;`. For example: `worker_processes 4; timer_resolution 100ms;`. Advanced configuration to be used only if instructed by Cortex XSOAR Support. | False        |
| Advanced: NGINX Server Conf        | NGINX server configuration to be used instead of the default NGINX_SERVER_CONF used in the integration code. Advanced configuration to be used only if instructed by Cortex XSOAR Support.                                                                  | False        |
| Advanced: NGINX Read Timeout       | NGNIX read timeout in seconds.                                                                                                                                                                                                                       | False        |
| Advanced: use legacy queries       | When enabled, the integration queries the server using full queries. Advanced configuration to be used only if instructed by Cortex XSOAR Support, or you've encountered log errors in the form of: 'msgpack: invalid code.'                             | False        |

### Safeguards
There are two integrations parameters used as safeguards: `Maximum CIDR network prefix bits size` and `Exclude top level domainGlobs`.

These parameters prevent the integration from incorrectly inserting unwanted TLDs or a CIDR with a too wide range.

The default value for `Maximum CIDR network prefix bits size` is 8, which means that CIDRs with a lower network prefix bits number are not included (such as 0.0.0.0/2).


The default value for `Exclude top level domainGlobs` is off. If enabled, the exported list does not hold indicators such as `*.com`, `*.co.uk`, `*.org` and other top level domains.

### Unique Behaviors

#### domainGlob


When parsing ***domainGlob*** indicator types, the parser creates two different inputs (usually how DNS Firewalls work). For example if the ***domainGlob*** `*.bad.com` is  parsed, it outputs two lines to the list:
1. `*.bad.com`
2. `bad.com`


The DNS also blocks `bad.com` which does not happen if only `*.bad.com` is listed.

#### IP Collapsing

When `IP Collapsing` is enabled, duplications of IP ranges are removed. For example if there are 2 CIDRs in the list - `1.2.3.0/8` and `1.2.3.0/16` - only `1.2.3.0/8` will be included in the exported list.

#### Append string to list

Option to add a list of constant values to the exported list.
Expected value is a string, supports newline characters (`\n`).

#### PAN-OS: drop invalid URL entries

When `PAN-OS: drop invalid URL entries` is enabled, any URL entry that is not compliant with PAN-OS URL format is dropped instead of rewritten.

#### Exported Fields
This applies to the `JSON` and `CSV` formats - select specific Cortex XSOAR fields to export.
If given the value `all` - all of Cortex XSOAR's available fields will be exported. If set to empty - only the indicator value and type will be exported.

Optional system fields are:
- `id`
- `modified`
- `sortValues`
- `comments`
- `indicator`
- `value`
- `source`
- `sourceInstances`
- `sourceBrands`
- `investigationIDs`
- `lastSeen`
- `firstSeen`
- `lastSeenEntryID`
- `firstSeenEntryID`
- `CustomFields`
- `tags`
- `expirationStatus`
- `expirationSource`
- `calculatedTime`
- `lastReputationRun`
- `modifiedTime`
- `aggregatedReliability`
- `communitynotes`

In addition to the system fields, you can also search for custom fields.
In order to get the list of all available fields to search by, you can configure the `Exported Fields` parameter with the `all` option and check the list returned.

### Access the Export Indicators Service by Instance Name (HTTPS)
**Note**: By default, the route is open without security hardening and might expose you to network risks. Cortex XSOAR recommends that you use credentials to connect to the integration.

To access the Export Indicators service by instance name, make sure ***Instance execute external*** is enabled.

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the ***instance.execute.external*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*. See [this documentation](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.
3. In a web browser, go to `https://*<demisto_address>*/instance/execute/*<instance_name>*` .

### URL Inline Arguments
Use the following arguments in the URL to change the request:

| **Argument Name** | **Description**                                                                                                                                                     | **Example**                                                                                         |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| n                 | The maximum number of entries in the output. If no value is provided, uses the value specified in the List Size parameter configured in the instance configuration. | `https://{server_host}/instance/execute/{instance_name}?n=50`                                       |
| s                 | The starting entry index from which to export the indicators.                                                                                                       | `https://{server_host}/instance/execute/{instance_name}?s=10&n=50`                                  |
| v                 | The output format. Supports `PAN-OS (text)`, `CSV`, `JSON`, `mwg` and `proxysg` (alias: `bluecoat`).                                                                | `https://{server_host}/instance/execute/{instance_name}?v=JSON`                                     |
| q                 | The query used to retrieve indicators from the system. If you are using this argument, no more than 100,000 can be exported through the EDL.                                                                                                             | `https://{server_host}/instance/execute/{instance_name}?q="type:ip and sourceBrand:my_source"`      |
| t                 | Only with `mwg` format. The type indicated on the top of the exported list. Supports: string, applcontrol, dimension, category, ip, mediatype, number and regex.    | `https://{server_host}/instance/execute/{instance_name}?v=mwg&t=ip`                                 |
| sp                | If set, strips ports off URLs.                                                                                                                                      | `https://{server_host}/instance/execute/{instance_name}?v=PAN-OS (text)&sp`                         |
| pr                | If set, strips protocol off URLs.                                                                                                                                   | `https://{server_host}/instance/execute/{instance_name}?v=text&pr`                                  |
| di                | Only with `PAN-OS (text)` format. If set, ignores URLs which are not compliant with PAN-OS URL format instead of  rewriting the URLs.                               | `https://{server_host}/instance/execute/{instance_name}?v=PAN-OS (text)&di`                         |
| tr                | Only with `PAN-OS (text)`Whether to collapse IPs. 0 - to not collapse, 1 - collapse to ranges or 2 - collapse to CIDRs                                              | `https://{server_host}/instance/execute/{instance_name}?q="type:ip and sourceBrand:my_source"&tr=1` |
| cd                | Only with `proxysg` format. The default category for the exported indicators.                                                                                       | `https://{server_host}/instance/execute/{instance_name}?v=proxysg&cd=default_category`              |
| ca                | Only with `proxysg` format. The categories which are exported. Indicators not falling into these categories are classified as the default category.                 | `https://{server_host}/instance/execute/{instance_name}?v=proxysg&ca=category1,category2`           |
| tx                | Whether to output `CSV` format as textual web pages.                                                                                                                | `https://{server_host}/instance/execute/{instance_name}?v=CSV&tx`                                   |
| mc                | Configure max CIDR size.                                                                                                                                            | `https://{server_host}/instance/execute/{instance_name}?mc=10`                                      |
| nt                 | Configure whether to exclude top level domainGlobs.                                                                                                                         | `https://{server_host}/instance/execute/{instance_name}?nt=true`                                    |


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
| edl_size | The maximum number of entries in the output. If no value is provided, uses the value specified in the List Size parameter configured in the instance configuration. | Optional | 
| print_indicators | If set to true, prints the indicators that were saved to the export indicators service. | Required | 
| mwg_type | For use with McAfee Web Gateway format to indicate the list type. | Optional |
| url_port_stripping | If true, strips the port off URLs. | Optional |
| url_protocol_stripping | If true, strips the port off URLs. | Optional |
| drop_invalids | For use with PAN-OS (text) format - if checked any URL entry which is not compliant with PAN-OS EDL URL format is dropped instead of rewritten. | Optional | 
| category_attribute | For use with Symantec ProxySG format - set the categories that should be listed in the output. If not set lists all existing categories. | Optional |
| category_default | For use with Symantec ProxySG format - set the default category for the output. | Optional |
| collapse_ips | For use with PAN-OS (text) format - Whether to collapse IPs, and if so - to ranges or CIDRs | Optional |
| csv_text | If true, outputs csv format as textual web pages | Optional |
| add_comment_if_empty | If selected, add to an empty List the comment "# Empty List". | Optional |

##### Context Output
There is no context output for this command.

##### Command Example
```!export-indicators-list-update=type:IP edl_size=2```

##### Human Readable Output
'EDL will be updated the next time you access it'


### Troubleshooting
* Indicators that are passed through the integration undergo formatting and deduplication, which may lead to an apparent loss of indicators.  
  For instance, enabling the `Strip ports from URLs` option may cause two URLs that are similar but use different ports to be merged into a single indicator after formatting, resulting in the removal of one of them as a duplicate.
* In case all fields are selected, there is a potential memory issue when dealing with CSV or JSON format files that exceed 150,000 entries.

#### Custom HTTP Headers
The response from EDL's endpoint includes custom headers, starting with the `X-EDL` prefix, that can be used for debugging purposes.  
The headers are:
- `X-EDL-Created` - The date and time the response was created.
- `X-EDL-Query-Time-Secs` - The time it took to execute the query and format the response.
- `X-EDL-Size` - The number of indicators returned in the response.
- `X-EDL-Origin-Size` - The number of indicators originally fetched before formatting and deduplication.


#### Execution Time
* 10,000 indicators can take 10-20 seconds.
* 100,000 indicators can take up to 1-3 minutes.
* 1,000,000 indicators can take over half an hour.

In 5 minutes (the default timeout of the integration) the integration can export between 200,000 to 400,000 indicators,
depending on the load of the server, the existing indicators in the server, and the query used.

The *NGINX Read Timeout* can be set to increase the timeout.
