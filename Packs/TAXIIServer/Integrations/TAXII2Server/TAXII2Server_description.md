## TAXII2 Service Integration

This integration provides TAXII2 Services for system indicators (Outbound feed).
You can choose to use TAXII v2.0 or TAXII v2.1. TAXII2 Service Integration is a long-running integration. For more information about long-running integrations, check out the <~XSIAM>[Forward requests to long-running integrations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Forward-Requests-to-Long-Running-Integrations) article.</~XSIAM> <~XSOAR_SAAS>Forward Requests to Long-Running Integrations article: [Cortex XSOAR 8 Cloud](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Forward-Requests-to-Long-Running-Integrations) or [Cortex XSOAR 8 On-prem](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Integration-commands-in-the-CLI) documentation.</~XSOAR_SAAS>

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


## How to Access the TAXII Service

(For Cortex XSOAR 6.x) Use one of the following options:
- **https://*xsoar_address*/instance/execute/*instance_name/{taxii2_api_endpoint}/**
- **http://*xsoar_address*:*listen_port/{taxii2_api_endpoint}/**

(For Cortex XSOAR 8 or Cortex XSIAM):
- `https://ext-<tenant>.crtx.<region>.paloaltonetworks.com/xsoar/instance/execute/<instance-name>/<taxii2_api_endpoint>/`
  When running on an engine:  `http://<xsoar_address>:<listen_port>/<taxii2_api_endpoint>/`
  NOTE: The instance name cannot be changed after saving the integration configuration.

## Access the TAXII Service by Instance Name
To access the TAXII service by instance name, make sure *Instance execute external* is enabled. 

<~XSOAR_ON_PREM>
1. Navigate to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the *instance.execute.external* key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*.
</~XSOAR_ON_PREM>

Trigger the TAXII Service URL:

<~XSOAR_ON_PREM>
In a web browser, go to https://*<xsoar_address>*/instance/execute/*<instance_name>*.
</~XSOAR_ON_PREM>

<~XSIAM>
`https://ext-<tenant>.crtx.<region>.paloaltonetworks.com/xsoar/instance/execute/<instance-name>`
</~XSIAM>

<~XSOAR_SAAS> 
`https://ext-<tenant>.crtx.<region>.paloaltonetworks.com/xsoar/instance/execute/<instance-name>`
</~XSOAR_SAAS>


## How to use HTTPS
To use HTTPS, a certificate and private key have to be supplied in the integration configuration. 

## How to use authentication
The integration allows the use of basic authentication in the requests.
To enable basic authentication, a user and password have to be supplied in the Credentials parameters in the integration configuration.

The server will then authenticate the requests by the `Authorization` header, expecting basic authentication encrypted in base64 to match the given credentials.


## STIX types for STIX indicator Domain Object

Some tools require the indicators in STIX to be a STIX indicator type and not an SCO. If that is the case you can select which indicator types will be converted into SDOs using a STIX Pattern for the indicator value.

For example, when `STIX types for STIX indicator Domain Object` is not selected for IPs the TAXII server will output the IP indicators as an SCO:
```json
{
    "objects": [
        {
            "created": "2024-10-01T07:07:00.440957Z",
            "id": "ipv4-addr--cd2ddd9b-6ae2-5d22-aec9-a9940505e5d5",
            "modified": "2024-10-01T07:07:00.440958Z",
            "spec_version": "2.1",
            "type": "ipv4-addr",
            "value": "192.168.1.1"
        }
    ]
}
```

When `ipv4-addr` is selected in `STIX types for STIX indicator Domain Object` the server will output the indicator as a STIX Indicator SDO with the correct pattern:
```json
{
    "objects": [
        {
            "created": "2024-10-01T07:07:00.440957Z",
            "id": "indicator--8d891b3c-0916-582e-b324-7aa39661d128",
            "labels": [
                ""
            ],
            "modified": "2024-10-01T07:07:00.440958Z",
            "pattern": "[ipv4-addr:value = '192.168.1.1']",
            "pattern_type": "stix",
            "spec_version": "2.1",
            "type": "indicator",
            "valid_from": "2024-10-01T07:07:00.440957Z"
        }
    ]
}
```