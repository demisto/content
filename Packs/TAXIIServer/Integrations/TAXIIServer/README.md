# TAXII Service Integration

This integration provides TAXII Services for system indicators (Outbound feed).

## Configure Collections
Each TAXII collection in the integration is represented by a Demisto indicator query.

The collections are defined by a JSON object in the following format:
```json
{
  "collection_name": "<Demisto indicator query>"
}
```

## How to Access the TAXII Service

To view the available TAXII services, visit the discovery service in one of the following options:

- `https://*demisto_address*/instance/execute/*instance_name/taxii-discovery-service`
- `http://*demisto_address*:*listen_port*/taxii-discovery-service`

## Access the TAXII Service by Instance Name
To access the TAXII service by instance name, make sure ***Instance execute external*** is enabled. 

1. In Demisto, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the ***instance.execute.external*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*.

## How to use HTTPS
To use HTTPS, a certificate and private key have to be provided in the integration configuration. 

The `HTTP Server` check box needs to be unchecked.

## How to use authentication
The integration allows the use of basic authentication in the requests.
To enable basic authentication, a user and password have to be supplied in the Credentials parameters in the integration configuration.

The server will then authenticate the requests by the `Authorization` header, expecting basic authentication encrypted in base64 to match the given credentials.
