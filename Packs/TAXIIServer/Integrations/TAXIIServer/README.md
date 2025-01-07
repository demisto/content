# TAXII Service Integration

This integration provides TAXII Services for system indicators (Outbound feed).

The TAXII Service integration is a long-running integration. For more information about long-running integrations, see the [Cortex XSOAR 8 Cloud](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Forward-Requests-to-Long-Running-Integrations), [Cortex XSOAR 8 On-prem](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Integration-commands-in-the-CLI) or [Cortex XSIAM](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Forward-Requests-to-Long-Running-Integrations) documentation.

## Configure Collections

Each TAXII collection in the integration is represented by a Cortex XSOAR indicator query.

The collections are defined by a JSON object in the following format:

```json
{
  "collection_name": "<Cortex XSOAR indicator query>"
}
```

## How to Access the TAXII Service

### For Cortex XSOAR 6.x  
Use one of the following options to access the TAXII service:
- `https://<xsoar_address>/instance/execute/<instance_name>/taxii-discovery-service`
- `http://<xsoar_address>:<listen_port>/taxii-discovery-service`

### For Cortex XSOAR 8 On-prem, Cortex XSOAR 8 Cloud, or Cortex XSIAM:  
Use one of the following options to access the TAXII service:
- `https://ext-<tenant>.crtx.<region>.paloaltonetworks.com/xsoar/instance/execute/<instance-name>/<taxii2_api_endpoint>/`
- When using an engine: `http://<xsoar_address>:<listen_port>/<taxii2_api_endpoint>/`
  
**Note:**  
For Cortex XSOAR 8 On-prem, you need to add the `ext-` FQDN DNS record to map the Cortex XSOAR DNS name to the external IP address.  
For example, `ext-xsoar.mycompany.com`.  



## Access the TAXII Service by Instance Name

To access the TAXII service by instance name, make sure ***Instance execute external*** is enabled. 

1. For Cortex XSOAR 6.x:
   1. Navigate to **Settings > About > Troubleshooting**.
   2. In the **Server Configuration** section, verify that the ***instance.execute.external*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*.
2. Trigger the TAXII Service URL:
   - For Cortex XSOAR 6.x:  
     `<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>`.  
     For example, `https://my.xsoar.live/instance/execute/taxiiserver`. 
   - For Cortex XSOAR 8 On-prem, Cortex XSOAR 8 Cloud, or Cortex XSIAM:  
     `https://ext-<tenant>.crtx.<region>.paloaltonetworks.com/xsoar/instance/execute/<instance-name>`  
     **Note**:
     The string `instance` does not refer to the name of your Cortex XSOAR instance, but rather is part of the URL.

## How to Use HTTPS

To use HTTPS, a certificate and private key have to be provided in the integration configuration.   
The `HTTP Server` checkbox needs to be unchecked.

## Set up Authentication
### For Cortex XSOAR 8 Cloud Tenant or Cortex XSIAM Tenant
The TAXII Service integration running on a Cortex XSOAR 8 Cloud tenant or Cortex XSIAM tenant enables using basic authentication in the requests.  
To enable basic authentication, a user and password have to be supplied in the **Credentials** parameters in the integration configuration.  
The server then authenticates the requests by the `Authorization` header, expecting basic authentication encrypted in base64 to match the given credentials.  
### For Cortex XSOAR On-prem (6.x or 8) or When Using Engines
For Cortex XSOAR On-prem (6.x or 8) or when using engines, you can set up authentication using custom certificates. For more information on setting up a custom certificate for Cortex XSOAR 8 On-prem, see [HTTPS with a signed certificate](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/HTTPS-with-a-signed-certificate). For more information on setting up a custom certificate for Cortex XSOAR 6.x, see [HTTPS with a Signed Certificate](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/HTTPS-with-a-Signed-Certificate).

## Troubleshooting

If the URL address returned in the service response is wrong, you can set it in the **TAXII Service URL Address** integration setting.
