## TAXII Service Integration

This integration provides TAXII Services for system indicators (Outbound feed). TAXII Service Integration is a long-running integration. For more information about long-running integrations, check out the <~XSIAM>[Forward requests to long-running integrations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Forward-Requests-to-Long-Running-Integrations) article.</~XSIAM> <~XSOAR_SAAS>Forward Requests to Long-Running Integrations article: [Cortex XSOAR 8 Cloud](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Forward-Requests-to-Long-Running-Integrations) or [Cortex XSOAR 8 On-prem](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Integration-commands-in-the-CLI) documentation.</~XSOAR_SAAS>


## Configure Collections
Each TAXII collection in the integration is represented by a Cortex XSOAR indicator query.

The collections are defined by a JSON object in the following format:
```json
{
  "collection_name": "<Cortex XSOAR indicator query>"
}
```

## How to Access the TAXII Service

(For Cortex XSOAR 6.x) Use one of the following options:

- **https://*demisto_address*/instance/execute/*instance_name/taxii-discovery-service**
- **http://*demisto_address*:*listen_port/taxii-discovery-service**

(For Cortex XSOAR 8 or Cortex XSIAM) `https://ext-<tenant>.crtx.<region>.paloaltonetworks.com/xsoar/instance/execute/<instance-name>`
  When running on an engine: http://xsoar_address:listen_port/{taxii2_api_endpoint}/



## Access the TAXII Service by Instance Name
To access the TAXII service by instance name, make sure ***Instance execute external*** is enabled. 

1. For Cortex XSOAR 6.x:
   1. Navigate to **Settings > About > Troubleshooting**.
   2. In the **Server Configuration** section, verify that the ***instance.execute.external*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*.
2. Trigger the webhook URL:

   - For Cortex XSOAR 6.x: **<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>**. For example, https://my.demisto.live/instance/execute/taxiiserver. Note that the string instance does not refer to the name of your XSOAR instance, but rather is part of the URL.

   - (For Cortex XSOAR 8 or Cortex XSIAM) `https://ext-<tenant>.crtx.<region>.paloaltonetworks.com/xsoar/instance/execute/<instance-name>`

## How to use HTTPS
To use HTTPS, a certificate and private key have to be supplied in the integration configuration. 

## How to use authentication
The integration allows the use of basic authentication in the requests.
To enable basic authentication, a user and password have to be supplied in the Credentials parameters in the integration configuration.

The server will then authenticate the requests by the `Authorization` header, expecting basic authentication encrypted in base64 to match the given credentials.
