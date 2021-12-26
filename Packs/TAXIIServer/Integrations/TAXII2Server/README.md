## TAXII2 Server Integration

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
You can add collection description as it done in `collection1_name`, or enter only collection query, as in `collection2_name`.


## How to Access the TAXII2 Server

Use one of the following options:
- **https://*demisto_address*/instance/execute/*instance_name/{taxii2_api_endpoint}/*** 
- **http://*demisto_address*:*listen_port/{taxii2_api_endpoint}/***

## Access the TAXII Service by Instance Name
To access the TAXII service by instance name, make sure ***Instance execute external*** is enabled. 

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the ***instance.execute.external*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*.

### How to use HTTPS
To use HTTPS, a certificate and private key have to be supplied in the integration configuration. 

### How to use authentication
The integration allows the use of basic authentication in the requests.
To enable basic authentication, a user and password have to be supplied in the Credentials parameters in the integration configuration.

The server will then authenticate the requests by the `Authorization` header, expecting basic authentication encrypted in base64 to match the given credentials.

## TAXII v2.0 API Enpoints

| **URL** | **Method** | **Response** | **TAXII2 Documentation** |
| --- | --- | --- | --- |
| /taxii/ | GET | Server Discovery Information. | [Server Discovery](http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html#_Toc496542727) |
| /{api_root}/ | GET | XSOAR API Root is `threatintel`. | [API Root Information](http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html#_Toc496542729) |
| /{api_root}/collections/ | GET | All XSOAR collections that configure in Collection Json parameter. | [Collections Resource](http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html#_Toc496542734) |
| /{api_root}/collections/{collection_id}/ | GET | XSOAR Collection with given `collection_id`. | [Collection Response](http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html#_Toc496542736) |
| /{api_root}/collections/{collection_id}/manifest/ | GET | Object manifests from the given collection. | [Objects Manifest Resource](http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html#_Toc496542741) |
| /{api_root}/collections/{collection_id}/objects/ | GET | Objects (XSOAR Indicators) from the given collection. | [Object Resource](http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html#_Toc496542738) |

For more information, visit [TAXII2 Documentation](http://docs.oasis-open.org/cti/taxii/v2.0/taxii-v2.0.html).

## TAXII v2.1 API Enpoints

| **URL** | **Method** | **Response** | **TAXII2 Documentation** |
| --- | --- | --- | --- |
| /taxii2/ | GET | Server Discovery Information. | [Server Discovery](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107526) |
| /{api_root}/ | GET | XSOAR API Root is `threatintel`. | [API Root Information](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107528) |
| /{api_root}/collections/ | GET | All XSOAR collections that configure in Collection Json parameter. | [Collections Resource](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107533) |
| /{api_root}/collections/{collection_id}/ | GET | XSOAR Collection with given `collection_id`. | [Collection Response](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107535) |
| /{api_root}/collections/{collection_id}/manifest/ | GET | Object manifests from the given collection. | [Objects Manifest Resource](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107537) |
| /{api_root}/collections/{collection_id}/objects/ | GET | Objects (XSOAR Indicators) from the given collection. | [Object Resource](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107539) |

For more information, visit [TAXII2 Documentation](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html).

## Known limitations
- GET objects by id is not allowed.
- Filtering objects by id or version not allowed.
- POST and DELETE objects is not allowed. Can not add or delete indicators using TAXII2 Server. 

