# TAXII Service Integration

This integration provides TAXII Services for system indicators (Outbound feed).

## Configure Collections

Each TAXII collection in the integration is represented by a Cortex XSOAR indicator query.

The collections are defined by a JSON object in the following format:

```json
{
  "collection_name": "<Cortex XSOAR indicator query>"
}
```

## How to Access the TAXII Service

(For Cortex XSOAR 6.x)

- `https://*demisto_address*/ins Use one of the following options:tance/execute/*instance_name/taxii-discovery-service`
- `http://*demisto_address*:*listen_port*/taxii-discovery-service`

(For Cortex XSOAR 8 or Cortex XSIAM):

- `https://ext-<tenant>.crtx.<region>.paloaltonetworks.com/xsoar/instance/execute/<instance-name>/{taxii2_api_endpoint}/`
   For running on an engine: `http://demisto_address:listen_port/{taxii2_api_endpoint}/`


## Access the TAXII Service by Instance Name

To access the TAXII service by instance name, make sure ***Instance execute external*** is enabled. 

1. For Cortex XSOAR 6.x:
   1. Navigate to **Settings > About > Troubleshooting**.
   2. In the **Server Configuration** section, verify that the ***instance.execute.external*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*.
2. Trigger the TAXII Service URL:
   - For Cortex XSOAR 6.x: `<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>`. For example, <https://my.demisto.live/instance/execute/taxiiserver>. Note that the string instance does not refer to the name of your XSOAR instance, but rather is part of the URL.
   -  (For Cortex XSOAR 8 or Cortex XSIAM) `https://ext-<tenant>.crtx.<region>.paloaltonetworks.com/xsoar/instance/execute/<instance-name>`

## How to use HTTPS

To use HTTPS, a certificate and private key have to be provided in the integration configuration. 

The `HTTP Server` check box needs to be unchecked.

## How to use authentication

The integration allows the use of basic authentication in the requests.
To enable basic authentication, a user and password have to be supplied in the Credentials parameters in the integration configuration.

The server will then authenticate the requests by the `Authorization` header, expecting basic authentication encrypted in base64 to match the given credentials.

## Troubleshooting

- If the URL address returned in the service response is wrong, you can set it in the **TAXII Service URL Address** integration parameter.
