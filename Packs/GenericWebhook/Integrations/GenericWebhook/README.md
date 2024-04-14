The Generic Webhook integration is used to create incidents on event triggers. The trigger can be any query posted to the integration.

## Configure Generic Webhook on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Generic Webhook.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Listen Port | Runs the service on this port from within Cortex XSOAR. Requires a unique port for each long-running integration instance. Do not use the same port for multiple instances. <br>Note: If you click the test button more than once, a failure may occur mistakenly indicating that the port is already in use.  <br> (For Cortex XSOAR 8 and Cortex XSIAM) If using an engine, you must enter a Listen Port. If not using an engine, do not enter a Listen Port and an unused port for the Generic Webhook will automatically be generated when the instance is saved.                            | True |
| username | Username (see [Security](#security) for more details) |  (For Cortex XSOAR 6.x) False <br> (For Cortex XSOAR 8 and Cortex XSIAM)  Optional for engines, otherwise mandatory.  |
| password | Password (see [Security](#security) for more details) |  (For Cortex XSOAR 6.x) False <br> (For Cortex XSOAR 8 and Cortex XSIAM)  Optional for engines, otherwise mandatory.  |
| certificate | (For Cortex XSOAR 6.x) For use with HTTPS - the certificate that the service should use.  <br> (For Cortex XSOAR 8 and Cortex XSIAM) Custom certificates are not supported. | False |
| Private Key | (For Cortex XSOAR 6.x) For use with HTTPS - the private key that the service should use.  <br> (For Cortex XSOAR 8 and Cortex XSIAM) When using an engine, configure a private API key. Not supported on the Cortex XSOAR​​ or Cortex XSIAM server. | False |
| incidentType | Incident type | False |
| store_samples | Store sample events for mapping (Because this is a push-based integration, it cannot fetch sample events in the mapping wizard). | False |

4. Click **Done**.
5. For Cortex XSOAR 6.x:
     1. Navigate to  **Settings > About > Troubleshooting**.
     2. In the **Server Configuration** section, verify that the value for the ***instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add *instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>* and set the value to *true*. See the following [reference article](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.

You can now trigger the webhook URL:

- For Cortex XSOAR 6.x: `<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>`. For example, `https://my.demisto.live/instance/execute/webhook`. Note that the string `instance` does not refer to the name of your XSOAR instance, but rather is part of the URL.
- For Cortex XSOAR 8: `<ext-<CORTEX-XSOAR-URL>/xsoar/instance/execute/<INTEGRATION-INSTANCE-NAME>`. For example, <https://ext-dev-tertius.crtx.us.paloaltonetworks.com/xsoar/instance/execute/webhook1>. Note that the string `instance` does not refer to the name of your XSOAR instance, but rather is part of the URL.

If you're not invoking the integration via the server HTTPS endpoint, then you should trigger the webhook URL as follows: `<CORTEX-XSOAR-URL>:<LISTEN_PORT>/`. For example, `https://my.demisto.live:8000/`.

The examples below assume you invoke the integration via the server HTTPS endpoint. In case you don't, replace the URL in the examples as suggested above.

**Note**: The ***Listen Port*** needs to be available, which means it has to be unique for each integration instance. It cannot be used by other long-running integrations.

## Usage

The Generic Webhook integration accepts POST HTTP queries, with the following optional fields in the request body:

| **Field** | **Type** | **Description**                                                                                                                                                                   |
| --- | --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| name | string | Name of the incident to be created.                                                                                                                                               |
| type | string | Type of the incident to be created. If not provided, the value of the integration parameter ***Incident type*** will be used.                                                     |
| occurred | string | Date the incident occurred in ISO-8601 format. If not provided, the trigger time will be used.                                                                                    |
| raw_json | object | Details of the incident to be created. Headers can be found in a seperate key. For example, `{"field1":"value1","field2":"value2","headers": {"header_field3": "header_value3"}}` |

For example, the following triggers the webhook using cURL:

`curl -POST https://my.demisto.live/instance/execute/webhook -H "Authorization: token" -H "Content-Type: application/json" -d '{"name":"incident created via generic webhook","raw_json":{"some_field":"some_value"}}'`

The request payload does not have to contain the fields mentioned above, and may include anything:

`curl -POST https://my.demisto.live/instance/execute/webhook -H "Authorization: token" -H "Content-Type: application/json" -d '{"string_field":"string_field_value","array_field":["item1","item2"]}'`

The payload could then be mapped in the [Cortex XSOAR mapping wizard](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Create-a-Mapper):

- Note that the *Store sample events for mapping* parameter needs to be set.

    <img width="900" src="./../../doc_imgs/mapping.png" />

The response is an array containing an object with the created incident metadata, such as the incident ID.

## Security

- We recommend using the authorization header, as described below, to validate the requests sent from your app. If you do not use this header it might result in incident creation from unexpected requests.
- To validate an incident request creation you can use the *Username/Password* integration parameters for one of the following:
  - Basic authentication
  - Verification token given in a request header, by setting the username to `_header:<HEADER-NAME>` and the password to be the header value. 
     
        For example, if the request included in the `Authorization` header the value `Bearer XXX`, then the username should be set to `_header:Authorization` and the password should be set to `Bearer XXX`.
    
- If you are not using server rerouting as described above, you can configure an HTTPS server by providing a certificate and private key.
