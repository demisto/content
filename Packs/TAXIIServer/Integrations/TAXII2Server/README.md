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
You can add a collection description as is done in `collection1_name`, or enter only a collection query, as in `collection2_name`.

## How to Access the TAXII2 Server

Use one of the following options:
- **https://*demisto_address*/instance/execute/*instance_name*/{taxii2_api_endpoint}/**
- **http://*demisto_address*:*listen_port*/{taxii2_api_endpoint}/**

## Access the TAXII Service by Instance Name
To access the TAXII service by instance name, make sure ***Instance execute external*** is enabled. 

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the *instance.execute.external* key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*.

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
| /{api_root}/collections/ | GET | All XSOAR collections that configure in Collection JSON parameter. | [Collections Resource](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107533) |
| /{api_root}/collections/{collection_id}/ | GET | Cortex XSOAR Collection with given `collection_id`. | [Collection Response](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107535) |
| /{api_root}/collections/{collection_id}/manifest/ | GET | Object manifests from the given collection. | [Objects Manifest Resource](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107537) |
| /{api_root}/collections/{collection_id}/objects/ | GET | Objects (XSOAR Indicators) from the given collection. | [Object Resource](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107539) |

For more information, visit [TAXII2 Documentation](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html).

## Known limitations
- GET objects by ID is not allowed.
- Filtering objects by ID or version not allowed.
- POST and DELETE objects is not allowed. Cannot add or delete indicators using TAXII2 Server. 


## How UUIDs work in TAXII2 XSOAR

---
### STIX Cyber Objects (SCO)
All STIX SCOs UUIDs follow [STIX 2.1 guidelines](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_64yvzeku5a5c) and use UUID5 with STIX unique namespace 
(`00abedb4-aa42-466c-9c01-fed23315a9b7`). This is used so all SCOs created have persistent UUID across all producers.

### STIX Domain Objects (SDO)
Unlike SCOs, STIX 2.1 specs for SDOs require a UUID4. While this solution works if the UUID is part of the database,
it is not the case in Cortex XSOAR. If the SDO already has a unique UUID stored it will use it, if it will generate a unique and *persistent* UUID using the following method.

A general UUID5 is created using the NameSpace_URL as follows:

`PAWN_UUID = uuid.uuid5(uuid.NAMESPACE_URL, 'https://www.paloaltonetworks.com')`

The generated UUID is then used to create a unique UUID5 per customer:

`UNIQUE_UUID = uuid.uuid5(PAWN_UUID, <UniqueCostumerString>)`

We then use this UUID as a base `namespace` to generate UUIDs for SDOs following the STIX 2.1 specs. Using this method,
we create unique and persistent UUIDs per customer.

## Cortex XSOAR TIM Extension Fields

---
When selected in the integration settings (Cortex XSOAR Extension Fields) the TAXII2 integration will generate an extension object and an extension attribute that holds Cortex XSOAR additional
TIM fields (System generated and custom). A general example of these two related objects will look as follows:
```JSON
{
  "id": "extension-definition--<UUID>",
  "type": "extension-definition",
  "spec_version": "2.1",
  "name": "XSOAR TIM <Cortex XSOAR Type>",
  "description": "This schema adds TIM data to the object",
  "created": "<creation date>",
  "modified": "<modification date>",
  "created_by_ref": "identity--<UUID of creator>",
  "schema": "https://github.com/demisto/content/blob/4265bd5c71913cd9d9ed47d9c37d0d4d3141c3eb/Packs/TAXIIServer/doc_files/XSOAR_indicator_schema.json",
  "version": "1.0",
  "extension_types": ["property-extension"]
},
{
    "type": "ipv4-addr",
    "spec_version": "2.1",
    "id": "ipv4-addr--2f689bf9-0ff2-545f-aa61-e495eb8cecc7",
    "value": "8.8.8.8",
    "extensions":{
        "extension-definition--<UUID>": {
           "Extension_type": "property_extension",
           "Field_1": "Value1",
           "Field_2": "Value2",
           "Field_3": "Value3"
        }
    }
}
```

## Performance Benchmark


| **Indicators Amount** | **Request time (seconds)** |
| --- | --- |
| 10,000 | 5-10 | 
| 50,000 | 30-40 |
| 100,000 | 50-90 |
