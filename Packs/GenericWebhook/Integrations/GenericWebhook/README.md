The Generic Webhook integration is used to create incidents on event triggers. The trigger can be any query posted to the integration.

## Configure Generic Webhook on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Generic Webhook.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| longRunningPort | Listen Port | True |
| username | Username (see [Security](#security) for more details) | False |
| password | Password (see [Security](#security) for more details) | False |
| certificate | Certificate (Required for HTTPS, in case not using the server rerouting) | False |
| key | Private Key (Required for HTTPS, in case not using the server rerouting) | False |
| incidentType | Incident type | False |
| store_samples | Store sample events for mapping (Because this is a push-based integration, it cannot fetch sample events in the mapping wizard). | False |

4. Click **Done**.
5. Navigate to  **Settings > About > Troubleshooting**.
6. In the **Server Configuration** section, verify that the value for the ***instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add *instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>* and set the value to *true*. See the following [reference article](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.

You can now trigger the webhook URL: `<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>`. For example, `https://my.demisto.live/instance/execute/webhook`

**Note**: The ***Listen Port*** needs to be available, which means it has to be unique for each integration instance. It cannot be used by other long-running integrations.

## Usage
The Generic Webhook integration accepts POST HTTP queries, with the following optional fields in the request body:

| **Field** | **Type** | **Description** |
| --- | --- | --- |
| name | string | Name of the incident to be created. |
| type | string | Type of the incident to be created. If not provided, the value of the integration parameter ***Incident type*** will be used.  |
| occurred | string | Date the incident occurred in ISO-8601 format. If not provided, the trigger time will be used. |
| raw_json | object | Details of the incident to be created. For example, `{"field1":"value1","field2":"value2"}` |

For example, the following triggers the webhook using cURL:

`curl -POST https://my.demisto.live/instance/execute/webhook -H "Authorization: token" -d '{"name":"incident created via generic webhook","raw_json":{"some_field":"some_value"}}'`

The response is an array containing an object with the created incident metadata, such as the incident ID.

## Security
- We recommend using the authorization header, as described below, to validate the requests sent from your app. If you do not use this header it might result in incident creation from unexpected requests.
- To validate an incident request creation you can use the *Username/Password* integration parameters for one of the following:
     * Basic authentication
     * Verification token given in a request header, by setting the username to `_header:<HEADER-NAME>` and the password to be the header value. 
     
        For example, if the request included in the `Authorization` header the value `Bearer XXX`, then the username should be set to `_header:Authorization` and the password should be set to `Bearer XXX`.
    
- If you are not using server rerouting as described above, you can configure an HTTPS server by providing a certificate and private key.
