This integration fetches audit log events from an Oracle Cloud Infrastructure resources.
Audit log events can be used for security audits, to track usage of and changes to Oracle Cloud Infrastructure resources, and to help ensure compliance with standards or regulations.

## API References
[Oracle Cloud Infrastructure Audit Logs API documentation](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/audit_logs.htm)
[Oracle Cloud Infrastructure Audit API Endpoints (available Regions)](https://docs.oracle.com/en-us/iaas/api/#/en/audit/20190901)

## Configure Oracle Cloud Infrastructure Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for *Oracle Cloud Infrastructure*.
3. Click **Add instance** to create and configure a new integration instance.

#### OCI Related Parameters
Oracle Cloud Infrastructure SDKs and CLI require basic configuration information, which is achieved by using configuration parameters either with a configuration file or a runtime defined configuration dictionary. This integration uses the runtime defined configuration dictionary.
More about OCI configuration [here](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm).

| **Parameter**                                                           | **Description**                                                                           | **Required** |
|-------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|--------------|
| Tenancy OCID                                                              | OCID of your tenancy. To get the value, see [Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#Required_Keys_and_OCIDs).                                                 | True         |
| User OCID                                                       | OCID of the user calling the API. To get the value, see [Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#Required_Keys_and_OCIDs). <br> Example: ocid1.user.oc1..<unique_ID> | True        |
| API Key Fingerprint                                                                   | Fingerprint for the public key that was added to this user. To get the value, see [Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#Required_Keys_and_OCIDs).                                                                  | True        |
| Private Key                                                                 | Private Key for authentication. <br> Important: The key pair must be in PEM format. For instructions on generating a key pair in PEM format, see [Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#Required_Keys_and_OCIDs).                                                                       | True         |
| Region                                               | An Oracle Cloud Infrastructure region. See [Regions and Availability Domains](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm#top). <br> Example: us-ashburn-1           | True         |
| First fetch time    | First fetch time (< number > < time unit >, e.g., 12 hours, 1 day, 3 months). Default is 3 days. | False |
| Trust any certificate (not secure) | Use SSL secure connection or ‘None’.  | False  |
| User system proxy settings  | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration.  | False  |

4. Click **Test** to validate the URLs, tokens, and connection.
## Commands
You can execute the following command from the Cortex XSIAM CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

#### oracle-cloud-infrastructure-get-events
***
Manual command to fetch and display events.

#### Base Command

`oracle-cloud-infrastructure-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create events, otherwise the command will only display them. Default is false. | True | 

