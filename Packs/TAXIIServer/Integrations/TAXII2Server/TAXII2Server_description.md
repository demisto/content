## TAXII2 Service Integration

This integration provides TAXII2 Services for system indicators (Outbound feed).
You can choose to use TAXII v2.0 or TAXII v2.1.

## Configure Collections
Each TAXII collection in the integration is represented by a Cortex XSOAR indicator query.

The collections are defined by a JSON object in the following format:
```json
{
  "collection1_name":{
    "query": "<Cortex XSOAR indicator query>",
    "description": "<Custom collection description>"
  },
  "collection2_name": "<Cortex XSOAR indicator query>"
}
```
You can add a collection description as is doen in `collection1_name`, or enter only a collection query, as in `collection2_name`.


## How to Access the TAXII Service

Use one of the following options:
- **https://*demisto_address*/instance/execute/*instance_name/{taxii2_api_endpoint}/*** 
- **http://*demisto_address*:*listen_port/{taxii2_api_endpoint}/***

## Access the TAXII Service by Instance Name
To access the TAXII service by instance name, make sure *Instance execute external* is enabled. 

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the *instance.execute.external* key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*.

## How to use HTTPS
To use HTTPS, a certificate and private key have to be supplied in the integration configuration. 

## How to use authentication
The integration allows the use of basic authentication in the requests.
To enable basic authentication, a user and password have to be supplied in the Credentials parameters in the integration configuration.

The server will then authenticate the requests by the `Authorization` header, expecting basic authentication encrypted in base64 to match the given credentials.
