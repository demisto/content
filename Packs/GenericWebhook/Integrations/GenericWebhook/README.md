The Generic Webhook integration enables you to push events to Cortex XSOAR or Cortex XSIAM. The Generic Webhook integration can be used when there is no relevant integration, when the integration does not match your organization’s needs, when there are restrictions on pulling information from the third-party solution, or when the triggering source is not an event that can be fetched by Cortex XSOAR or Cortex XSIAM, such as a slack message or a completed form.

Example: Your organization’s employees fill out a Google form to report security incidents. Employees specify the type of incident in a drop-down field with predefined options, the Generic Webhook integration pushes the event into Cortex XSOAR or Cortex XSIAM, and a playbook runs. The incident type and the specific playbook is determined by the incident type field in the drop-down.

The Generic Webhook integration creates incidents in Cortex XSOAR, alerts in Cortex XSIAM 2.x or issues in Cortex XSIAM 3.x. The trigger can be any query posted to the integration.

The Generic Webhook integration is a long-running integration. For more information about long-running integrations, see the [Cortex XSOAR 8 Cloud](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Forward-Requests-to-Long-Running-Integrations), [Cortex XSOAR 8 On-prem](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.9/Cortex-XSOAR-On-prem-Documentation/Integration-commands-in-the-CLI) or [Cortex XSIAM](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Premium-Documentation/Forward-Requests-to-Long-Running-Integrations) documentation.

To use the Generic Webhook integration, you need to complete the following steps:

1. Configure Generic Webhook in Cortex XSOAR or Cortex XSIAM.
2. Set up authentication.
3. Determine the webhook URL.
4. Trigger the webhook to generate incidents, alerts, or issues.

## Configure Generic Webhook on Cortex XSOAR or Cortex XSIAM

1. In the Cortex XSOAR or Cortex XSIAM integrations page, search for **Generic Webhook** and click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Listen Port<br><br>Note: This field only appears in Cortex XSOAR 8 and Cortex XSIAM if you are using an engine. It always appears in Cortex 6.x. | Runs the service on this port. Requires a unique port for each long-running integration instance. Do not use the same port for multiple instances. <br>Note: If you click the test button more than once, a failure may occur, mistakenly indicating that the port is already in use.                           | True |
| username | Username (see [Security](#security) for more details) |  For Cortex XSOAR 6.x - False <br><br> For Cortex XSOAR 8 and Cortex XSIAM if the integration is running on an engine - False <br><br> For Cortex XSOAR 8 and Cortex XSIAM if the integration is not running on an engine - True  |
| password | Password (see [Security](#security) for more details) |  For Cortex XSOAR 6.x - False <br><br> For Cortex XSOAR 8 and Cortex XSIAM if the integration is running on an engine - False <br><br> For Cortex XSOAR 8 and Cortex XSIAM if the integration is not running on an engine - True  |
| certificate | For use with HTTPS - the certificate that the service should use. <br> Supported for Cortex XSOAR On-prem (6.x or 8). Supported for Cortex XSOAR 8 Cloud and Cortex XSIAM only when using an engine. <br><br> Cortex XSOAR 8 Cloud tenants and Cortex XSIAM tenants do not support custom certificates.  | False |
| Private Key | For use with HTTPS - the private key that the service should use.  <br> Supported for Cortex XSOAR On-prem (6.x or 8). Supported for Cortex XSOAR 8 Cloud and Cortex XSIAM only when using an engine. <br><br> Cortex XSOAR 8 Cloud tenants and Cortex XSIAM tenants do not support private keys.  | False |
| Result | Automatically generated webhook trigger link (based on user configuration). | Auto-populated. <br><br> Note: This field does not appear for Cortex XSOAR 6.x or Cortex XSOAR 8.9 On-prem|
| incidentType | Incident, issue, or alert type | False |
| store_samples | Store sample events for mapping (Because this is a push-based integration, it cannot fetch sample events in the mapping wizard). | False |

2. Click **Done**.
3. For Cortex XSOAR 6.x:
     1. Navigate to  **Settings > About > Troubleshooting**.
     2. In the **Server Configuration** section, verify that the value for the ***instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add *instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>* and set the value to *true*. See the following [reference article](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.

## Set up Authentication

Authentication options depend on the product and version.

| **Product** | **Authentication required** | **Authentication options** |
| --- | --- | --- |
| Cortex XSOAR 8 Cloud tenant | Yes                          | - Basic authentication (username and password)  |
| Cortex XSIAM tenant | Yes  | - Basic authentication (username and password) |
| Cortex XSOAR 8 On-prem | No | - Basic authentication (username and password) <br><br> - Custom certificate <br> **NOTE**: For more information about setting up custom certificates for Cortex XSOAR 8 On-prem, see [HTTPS with a signed certificate](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.10/Cortex-XSOAR-On-prem-Documentation/HTTPS-with-a-signed-certificate). |
| Cortex XSOAR 6.x | No| - Basic authentication (username and password) <br><br> - Header-based authentication using `_header:<HEADER-NAME>` syntax <br><br> - Custom certificate <br> **NOTE**: For more information about setting up custom certificates for Cortex XSOAR 6.x, see [HTTPS with a signed certificate](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.14/Cortex-XSOAR-Administrator-Guide/HTTPS-with-a-Signed-Certificate).  |
| Engines (Cortex XSOAR 8 Cloud, Cortex XSOAR 8 On-Prem, Cortex XSIAM, Cortex 6.x) | No | - Basic authentication (username and password) <br><br> - Header-based authentication using `_header:<HEADER-NAME>` syntax (Cortex XSOAR 6.x only) <br><br> - Custom certificate <br> **NOTE**: For more information about setting up custom certificates for engines, see [Configure an engine to use custom certificates](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Configure-an-engine-to-use-custom-certificates). |

## Determine the webhook URL

For Cortex XSIAM and Cortex XSOAR 8 Cloud, the **Results** section of the integration configuration provides the webhook URL. We recommend you verify the URL using the instructions below. For on-prem Cortex XSOAR 6.x and Cortex XSOAR 8, you must use the URL template below to determine the webhook URL.

Prerequisite:
For Cortex XSOAR 8 On-prem, you need to add the ext- FQDN DNS record to map the Cortex XSOAR DNS name to the external IP address.
For example, ext-xsoar.mycompany.com.

| **Product** | **URL** | **Example** |
| --- | --- | --- |
| Cortex XSOAR 8 Cloud and On-prem | `<ext-<CORTEX-TENANT-URL>/xsoar/instance/execute/<INTEGRATION-INSTANCE-NAME>`  | `https://ext-mytenant.crtx.us.paloaltonetworks.com/xsoar/instance/execute/my_instance_01`  |
| Cortex XSIAM  | `<ext-<CORTEX-TENANT-URL>/xsoar/instance/execute/<INTEGRATION-INSTANCE-NAME>` | `https://ext-mytenant.crtx.us.paloaltonetworks.com/xsoar/instance/execute/my_instance_01` |
| Cortex XSOAR 6.x | `<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>` |  `https://my.xsoar.live/instance/execute/webhook`   |

**Notes**:  

* For Cortex XSIAM, you must replace **xdr** in the tenant URL with **crtx**. For example, if your tenant URL is `https://companyname.xdr.eu.paloaltonetworks.com`  the webhook URL is `https://ext-companyname.crtx.eu.paloaltonetworks.com/xsoar/instance/execute/my_instance_01`.
* The string **instance** does not refer to the name of your Cortex instance, it is part of the URL.
* The name of the instance cannot include special characters.
* For Cortex XSOAR 6.x or if you are using an engine, if you are not invoking the integration via the server HTTPS endpoint, you can trigger the webhook URL as follows: `<CORTEX-XSOAR-URL>:<LISTEN_PORT>/` For example, `https://my.xsoar.live:8000/`.

## Usage

The Generic Webhook integration accepts POST HTTP queries, with the following optional fields in the request body:

| **Field** | **Type** | **Description**                                                                                                                                                                   |
|-----------| --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| name      | string | Name of the incident, alert, or issue to be created.                                                                                                                                               |
| type      | string | Type of the incident, alert, or issue to be created. If not provided, the value of the integration parameter ***incidentType*** is used.                                                     |
| occurred  | string | Date the incident occurred in ISO-8601 format. If not provided, the trigger time is used.                                                                                    |
| rawJson   | object | Details of the incident, alert, or issue to be created. Headers can be found in a seperate key. For example, `{"field1":"value1","field2":"value2","headers": {"header_field3": "header_value3"}}` |

**Note**: The cURL examples below are formatted for macOS. For Windows machines, modify as needed.

### Examples

Basic authentication can be used in three ways with the same username/password configured in the integration:

Using -u flag:<br>
`curl -X POST https://ext-companyname.crtx.eu.paloaltonetworks.com/xsoar/instance/execute/my_instance_01 -u "<Username:Password>" -H "Content-Type: application/json" -d '{"name":"incident created via generic webhook","rawJson":{"some_field":"some_value"}}'`

Using Authorization header (where the header value is base64 encoded username:password):<br>
`curl -X POST https://ext-companyname.crtx.eu.paloaltonetworks.com/xsoar/instance/execute/my_instance_01 -H "Authorization: Basic MTIzOjEyMw==" -H "Content-Type: application/json" -d '{"name":"incident created via generic webhook","rawJson":{"some_field":"some_value"}}'`
**Note**: `MTIzOjEyMw==` is Base64 encoded username:password example.

Or embedding credentials directly in the URL:<br>
`curl -X POST https://username:password@ext-companyname.crtx.eu.paloaltonetworks.com/xsoar/instance/execute/my_instance_01 -H "Content-Type: application/json" -d '{"name":"incident created via generic webhook","rawJson":{"some_field":"some_value"}}'`

The request payload does not have to contain the fields mentioned above, and may include any JSON fields and values:<br>
`curl -X POST https://ext-companyname.crtx.eu.paloaltonetworks.com/xsoar/instance/execute/my_instance_01 -u "<Username:Password>" -H "Content-Type: application/json" -d '{"string_field":"string_field_value","array_field":["item1","item2"]}'`

Multiple incidents, alerts, or issues can be created in one request by sending an array as the request body:<br>
`curl -X POST https://ext-companyname.crtx.eu.paloaltonetworks.com/xsoar/instance/execute/my_instance_01 -u "<Username:Password>" -H "Content-Type: application/json" -d '[{"name":"incident1","rawJson":{"some_field":"some_value"}}, {"name":"incident2","rawJson":{"some_field":"some_value"}}]'`

Using custom header authentication (Cortex XSOAR 6.x only). In this example, the username in the integration instance is set to _header:Authorization and the password in the integration instance is set to  `Basic MYIvOkEyMw==` :<br>
`curl -X POST https://ext-companyname.crtx.eu.paloaltonetworks.com/xsoar/instance/execute/my_instance_01 -H "Authorization: Basic MYIvOkEyMw==" -H "Content-Type: application/json" -d '{"name":"incident created via generic webhook","rawJson":{"some_field":"some_value"}}' -v`

The response is an array containing an object with the created incident metadata, such as the incident ID.

The payload can then be mapped. For more information see:

* [Create a mapper (Cortex XSOAR 6.x)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.14/Cortex-XSOAR-Administrator-Guide/Create-a-Mapper)
* [Create a mapper (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-an-incident-mapper)
* [Create a mapper (Cortex XSOAR 8.9 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.9/Cortex-XSOAR-On-prem-Documentation/Create-an-incident-mapper)
* [Create a mapper (Cortex XSIAM)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Map-Fields-to-Alert-Types)

**Note**: To use the mapping wizard, the **Store sample events** for mapping parameter must be set. Because this is a push-based integration, it cannot fetch sample events in the mapping wizard. After you finish mapping, we recommend turning off the sample events storage to reduce performance overhead.

## Authorization headers

For Cortex XSOAR 6.x users, you can use the special `_header:<HEADER-NAME>` syntax to authenticate requests using custom headers from your third-party service. This helps prevent unauthorized creation of incidents. Set the username field in the integration to `_header:<HEADER-NAME>` and provide the header value in the password field.
Example: If the request included in the `Authorization` header the value `Bearer XXX`, then the username should be set to `_header:Authorization` and the password should be set to `Bearer XXX`.

### Troubleshooting authorization headers

* Header Size Limit: Each server or framework may impose a limit on the total size of the headers received in a request. For example, servers such as Nginx or Apache have their own default values that can be configured. FastAPI itself doesn't specifically limit the header size, but underlying ASGI servers like Uvicorn or Hypercorn that run FastAPI do have default limits (For example, Uvicorn has a default of 1MB for the total size of request headers).
* Allowed Characters: Headers should only use ASCII characters. Non-ASCII characters must be encoded.
* Header Names and Values: Certain characters are restricted in header names and values. Typically, names cannot include characters such as : or newlines, and values are restricted from including newlines to protect against header injection attacks.
* Case Sensitivity: Header keys are case-insensitive as per HTTP standards, but it is good practice to keep a consistent casing convention for ease of maintenance and readability.
