
Use the Palo Alto Networks NGFW API to automatically generate a Security Lifecycle Review (SLR) Report.

## Configure Automatic SLR on XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Utilities__.
2. Search for "Palo Alto Networks Automatic SLR.
3. Click __Add instance__ to create and configure a new integration instance.

    | Parameter | Description |
    | --- | --- |
    | Name | A meaningful name for the integration instance. |
    | Firewall FQDN/IP | Management FQDN or IP address of the firewall |
    | Firewall TCP Port | Management Port (Default: `443`) of the firewall |
    | Firewall API Key | API Key for the target firewall |
    | Firewall Timeout | Timeout value in seconds for API operations (Default: `300`) |
    | Verify Firewall Certificate | Verify the SSL/TLS Certificate the firewall presents |
    | CSP API Key | The API Key for the Palo Alto Networks Customer Support Portal (CSP) |
    | CSP Timeout | Timeout value in seconds for API operations (Default: `300`) |
    | Verify CSP Certificate | Verify the SSL/TLS Certificate for the CSP |
    | XSOAR System Proxy | Enable if XSOAR utilises a proxy |
    | Enable Verbose Output | Enables debug/verbose output to the war room |
    | Customer Account Name | Name of organisation to appear on the SLR Report |
    | Firewall Deployment Location | Select the logicial deployment location of the firewall |
    | Deployment Country | Set the country the customer/firewall resides in |
    | Deployment Geographic Region | Select the geographic region the customer/firewall resides in |
    | Customer Industry | Select the industry the customer is in |
    | Language | Select the language for the report to be generated in |
    | Prepared By | Set the name of the person who generated the report |
    | Requested By | Set the email address of the person who generated the report |
    | Send To | Set the email address of the receipient who will receive the report |


4. Click __Test__ to validate integration can communicate with the firewall.

__NOTE:__ The test command does not function when `Enable Verbose Output` is set to enabled/true.


## Step-by-step configuration
---

This section will cover how to retrieve the Palo Alto Networks Customer Support Portal (CSP) and PAN-OS API key's

### Firewall API Key

A firewall "Super User" or administrator with a custom "Admin Role" limiting their interaction with the API is required to complete these steps.

This integration requires an API Key for the target firewall in order to run the neccesary API commands.
In order to retireve that API Key either:

Run this command from a terminal, replacing `<firewall>`, `<username>` and `<password>` as needed -

`curl -k -X GET 'https://<firewall>/api/?type=keygen&user=<username>&password=<password>'`

Or

`curl -k -X POST 'https://<firewall>/api/?type=keygen&user=<username>&password=<password>'`

Alternatively, open a browser window and navigate to: `https://<firewall>/api/?type=keygen&user=<username>&password=<password>`

```
<response status="success"> 
    <result> 
        <key>gJlQWE56987nBxIqyfa62sZeRtYuIo2BgzEA9UOnlZBhU</key> 
    </result> 
</response>
```

#### Reference Material
How-to generate an API Key: https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key.html

### Customer Support Portal (CSP) API Key

A Customer Support Portal "Super User" is required to complete these steps.

1. Ensure you have the "Super User" role assigned to your account by logging in to the CSP, then navigating to: __Support Home__ > __Members__ > __Manage Users__
Under the "Roles" column you should have "Super User" assigned.

2. Once you have the correct role assigned to your user, navigate to: __Support Home__ > __Assets__ > __Licensing API__

3. If a key already exists, it will be displayed to you. We will use this key in the integration configuration.

4. If a key does exist, click `Generate` to generate a new API key

**NOTE:** Pay attention to the expiry date and extend/regenerate the key as neccesary.

#### Reference Material
Customer Support Portal Roles: https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClaTCAS
How-to Generate the API Key: https://docs.paloaltonetworks.com/vm-series/10-0/vm-series-deployment/license-the-vm-series-firewall/licensing-api/manage-the-licensing-api-key.html

## Commands
---
You can execute these commands from the Cortex XSOAR CLI or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Dump Integration Parameters
---
In some circumstances, it may be required to get visbility of all currently configured parameters dumped to the context for troubleshooting.

##### Base Command

`!autoslr-dump-params`

##### Arguments

There are no input arguments for this command.

##### Context Output

| **Context Key** | **Description** | **Type** |
| --- | --- | --- |
| AutoSLR.params.csp_host | The CSP base URL | String |
| AutoSLR.params.csp_proxy | Enable/disable system proxy for CSP communications | Boolean |
| AutoSLR.params.csp_timeout | The timeout value for CSP API operations | Integer |
| AutoSLR.params.csp_tls_verify | Enable/disable TLS verification for the CSP | Boolean |
| AutoSLR.params.csp_verbose | Enable/disable verbose output for CSP operations | Boolean |
| AutoSLR.params.ngfw_host | The firewall base URL | String |
| AutoSLR.params.ngfw_port | The firewall TCP port | Integer |
| AutoSLR.params.ngfw_proxy | Enable/disable system proxy for NGFW communications | Boolean |
| AutoSLR.params.ngfw_timeout | The timeout value for NGFW API operations | Integer |
| AutoSLR.params.ngfw_tls_verify | Enable/disable TLS verification for the CSP | Boolean |
| AutoSLR.params.ngfw_verbose | Enable/disable verbose output for CSP operations | Boolean |
| AutoSLR.params.slr_account_name | The account name to appear on the SLR report | String |
| AutoSLR.params.slr_country | The deployment country of the firewall | String |
| AutoSLR.params.slr_deployment_location | The logical deployment location of the firewall | String |
| AutoSLR.params.slr_geographic_region | The geographic region the firewall is deployed in | String |
| AutoSLR.params.slr_industry | The industry of the customer organisation | String |
| AutoSLR.params.slr_language | The language the report should be generated in | String |
| AutoSLR.params.slr_prepared_by | The name of the person who generated the report | String |
| AutoSLR.params.slr_requested_by | The email address of the person who generated the report | String |
| AutoSLR.params.slr_send_to | The email address of the receipient of the report | String |
| AutoSLR.params.system_proxy | Global enable/disable the use of the system proxy | String |
| AutoSLR.params.system_verbose | Global enable/disable the verbose/debugging output | String |

### Retrieve "show system info" Output
---
This command will retrieve certain information about the target firewall for use within other functions.

##### Base Command

`!autoslr-ngfw-system-info`

##### Arguments

There are no input arguments for this command.

##### Context Output

| **Context Key** | **Description** | **Type** |
| --- | --- | --- |
| AutoSLR.ngfw_system_info.hostname | The hostname of the target firewall | String |
| AutoSLR.ngfw_system_info.serial | The serial number of the target firewall | String |
| AutoSLR.ngfw_system_info.software | The PAN-OS software version of the target firewall | String |

### Initiate SLR Generation
---
This command will initiate the *-stats_dump.tar.gz generation job on the target firewall

##### Base Command

`!autoslr-ngfw-generate`

##### Arguments

There are no input arguments for this command.

##### Context Output

| **Context Key** | **Description** | **Type** |
| --- | --- | --- |
| AutoSLR.generate.job_id | The Job ID of the generation task | Integer |

### Check SLR Generation Status
---
This command will check the *-stats_dump.tar.gz generation job on the target firewall

##### Base Command

`!autoslr-ngfw-check`

##### Arguments

| **Argument** | **Description** | **Type** |
| --- | --- | --- |
| job_id | The Job ID of the generation task | Integer |

##### Context Output

| **Context Key** | **Description** | **Type** |
| --- | --- | --- |
| AutoSLR.generate.job_status | The Job status of the generation task | Boolean |

### Download *-stats_dump.tar.gz from the firewall
---
This command will download the *-stats_dump.tar.gz from the target firewall

##### Base Command

`!autoslr-ngfw-download`

##### Arguments

| **Argument** | **Description** | **Type** |
| --- | --- | --- |
| job_id | The Job ID of the generation task | Integer |

##### Context Output

| **Context Key** | **Description** | **Type** |
| --- | --- | --- |
| AutoSLR.generate.file_name | The human readable filename of the downloaded file | String |
| InfoFile.EntryID | The EntryID of the downloaded file | String |

__Note:__ In the default playbook supplied with the content pack, `InfoFile.EntryID` is copied to `AutoSLR.generate.EntryID` for use in the upload function.

### Upload *-stats_dump.tar.gz to Palo Alto Networks
---
This command will upload the *-stats_dump.tar.gz file to Palo Alto Networks for report generation

##### Base Command

`!autoslr-csp-upload`

##### Arguments

| **Argument** | **Description** | **Type** |
| --- | --- | --- |
| input_file | The EntryID of the file to upload | String |

##### Context Output

| **Context Key** | **Description** | **Type** |
| --- | --- | --- |
| AutoSLR.upload.id | The SLR Reference ID returned by the CSP API | String |
| AutoSLR.upload.send_to | The email address the completed report will be sent to | String |
