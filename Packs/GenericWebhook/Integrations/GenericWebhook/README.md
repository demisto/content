Generic webhook to be triggered in order to create incident.

## Configure Generic Webhook on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Generic Webhook.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| longRunningPort | Listen Port | True |
| auth_header | Authorization Verification Token | False |
| incidentType | Incident type | False |

4. Click **Done**.
5. Navigate to  **Settings > About > Troubleshooting**.
6. In the **Server Configuration** section, verify that the ***instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>* and set the value to *true*. See the following [reference article](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.

You can now trigger the webhook URL: `<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>`, e.g. `https://my.demisto.live/instance/execute/webhook`

**Note**: The ***Listen Port*** needs to be available, which means it has to be unique per integration instance, and cannot be used by other long-running integrations.

## Usage
The Generic Webhook accepts POST HTTP queries, with the following optional fields in the request body:
| **Field** | **Type** | **Description** |
| --- | --- | --- |
| name | string | Name of the incident to be created. |
| type | string | Type of the incident to be created. If not provided, the value of the integration parameter ***Incident type*** will be taken.  |
| occurred | string | Occurred date of the incident to be created in ISO-8601 format. If not provided, the trigger time will be taken. |
| raw_json | object | Details of the incident to be created, e.g. `{"field1":"value1","field2":"value2"}` |

For example, triggering the webhook using cURL:

`curl -POST https://my.demisto.live/instance/execute/webhook -H "Authorization: token" -d '{"name":"incident created via generic webhook","raw_json":{"some_field":"some_value"}}'`

The response will be an array containing an object with the created incident metadata, such as the incident ID.

## Security
The ***Authorization Verification Token*** integration parameter allows validation the request received, by verifying the **Authorization** header value equals the value of that parameter.

