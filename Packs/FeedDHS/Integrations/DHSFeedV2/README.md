The Cybersecurity and Infrastructure Security Agency’s (CISA’s) free Automated Indicator Sharing (AIS) capability enables the exchange of cyber threat indicators, at machine speed, to the Federal Government community.
Use this version if your certificate supports TAXII 2 protocol.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes).

## Configure DHS Feed v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Discovery Service URL (e.g., https://ais2.cisa.dhs.gov/taxii2/) |  | True |
| Key File as Text | For more information, visit https://us-cert.cisa.gov/ais. | True |
| Certificate File as Text | For more information, visit https://us-cert.cisa.gov/ais. | True |
| Default API Root to use | The default API root to use \(e.g., default, public\). If left empty, the server default API root will be used. When the server has no default root, the first available API root will be used instead. The user must be authorized to reach the selected API root. | False |
| Collection Name To Fetch Indicators From | Indicators will be fetched from this collection. Run the "dhs-get-collections" command to get a valid value. If left empty, the instance will try to fetch from all the collections in the given discovery service. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Feed Fetch Interval |  | False |
| First Fetch Time | The time interval for the first fetch \(retroactive\) in the following format: &amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt; of type minute/hour/day. For example, 1 minute, 12 hour. Limited to 48 hours. | False |
| STIX Objects To Fetch | The objects to fetch, most likely indicators. Might slow down fetch time. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Max Indicators Per Fetch | The maximum number of indicators that can be fetched per fetch. If this field is left empty, there will be no limit on the number of indicators fetched. | False |
| Max STIX Objects Per Poll | Set the number of STIX objects that will be requested with each TAXII poll \(http request\). A single fetch is made of several TAXII polls. Changing this setting can help speed up fetches, or fix issues on slower networks. Please note server restrictions may apply, overriding and limiting the requested limit. | False |
| Complex Observation Mode | Choose how to handle complex observations. Two or more Observation Expressions MAY be combined using a complex observation operator such as "AND", "OR". For example, \`\[ IP = 'b' \] AND \[ URL = 'd' \]\` | False |
| Tags | Supports CSV values. | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dhs-get-indicators

***
Allows you to test your feed and to make sure you can fetch indicators successfully. 
Due to API limitations, running this command may take longer than the default 5 minutes. 
To overcome this issue increase the [execution-timeout](https://xsoar.pan.dev/docs/playbooks/playbooks-field-reference#advanced-fields) from 300 seconds to a higher value, the recommended value is 1800 seconds.


#### Base Command

`dhs-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| raw | Will return only the rawJSON of the indicator object. Possible values are: true, false. Default is false. | Optional | 
| limit | Maximum number of indicators to return. Default is 10. | Optional | 
| added_after | Fetch only indicators that were added to the server after the given time. Provide a &lt;number&gt; and &lt;time unit&gt; of type minute/hour/day. For example, 1 minute, 12 hour, 24 days. Limited to 48 hours. Default is 24 hours. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DHS.Indicators.value | String | Indicator value. | 
| DHS.Indicators.type | String | Indicator type. | 
| DHS.Indicators.rawJSON | String | Indicator rawJSON. | 

#### Command Example

```!dhs-get-indicators limit=3 execution-timeout=1800```

#### Context Example

```json
{
  "DHS.Indicators": [
    {
      "fields": {
        "tags": [
          "cisa-proprietary-false"
        ]
      },
      "rawJSON": {
        "created": "2021-08-09T00:42:54.000Z",
        "created_by_ref": "identity--e8",
        "id": "indicator--e0",
        "indicator_types": [
          "anomalous-activity",
          "attribution"
        ],
        "labels": [
          "cisa-proprietary-false"
        ],
        "modified": "2021-09-26T04:16:13.000Z",
        "name": "sometimes",
        "object_marking_refs": [
          "marking-definition--633",
          "marking-definition--f51"
        ],
        "pattern": "[domain-name:value = 'coronashop.jp']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "spec_version": "2.1",
        "type": "Domain",
        "valid_from": "2021-09-26T00:09:38Z",
        "value": "coronashop.jp"
      },
      "type": "Domain",
      "value": "coronashop.jp"
    },
    {
      "fields": {
        "description": "A totally famous IP Address",
        "tags": [
          "elevated"
        ]
      },
      "rawJSON": {
        "created": "2022-03-01T14:17:59.000Z",
        "created_by_ref": "identity--a9",
        "description": "A totally famous IP Address",
        "id": "indicator--2f5",
        "labels": [
          "elevated"
        ],
        "modified": "2022-03-01T14:17:59.000Z",
        "object_marking_refs": [
          "marking-definition--633"
        ],
        "pattern": "[ipv4-addr:value = '1.1.1.1']",
        "pattern_type": "stix",
        "spec_version": "2.1",
        "type": "IP",
        "valid_from": "2022-03-01T14:17:59.000000Z",
        "value": "1.1.1.1"
      },
      "type": "IP",
      "value": "1.1.1.1"
    },
    {
      "fields": {
        "tags": [
          "elevated"
        ]
      },
      "rawJSON": {
        "created": "2022-02-28T13:18:49.000Z",
        "created_by_ref": "identity--8c4",
        "id": "indicator--9a6",
        "indicator_types": [
          "file-hash-watchlist"
        ],
        "labels": [
          "elevated"
        ],
        "modified": "2022-02-28T13:18:49.000Z",
        "object_marking_refs": [
          "marking-definition--633"
        ],
        "pattern": "[file:hashes.MD5 = 'e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f88e']",
        "pattern_type": "stix",
        "spec_version": "2.1",
        "type": "File",
        "valid_from": "2022-02-28T13:18:49.000000Z",
        "value": "e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f88e"
      },
      "type": "File",
      "value": "e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f88e"
    }
  ]
}
```

#### Human Readable Output

> Found 3 results added after 2022-12-07T10:29:13.079493Z UTC:
>### DHS Indicators
>|value|type|
>|---|---|
>| coronashop.jp | Domain |
>| 1.1.1.1 | IP |
>| e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f88e | File |

### dhs-get-collections

***
Gets the list of collections from the discovery service.

#### Base Command

`dhs-get-collections`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DHS.Collections.ID | String | Collection ID. | 
| DHS.Collections.Name | String | Collection name. | 

#### Command Example

```!dhs-get-collections```

#### Context Example

```json
{
  "DHS.Collections": [
    {
      "ID": "3",
      "Name": "Public Collection"
    }
  ]
}
```

#### Human Readable Output

> ### DHS Server Collections
>|Name|ID|
>|---|---|
>| Public Collection | 3 |

## Breaking Changes

The following are the breaking changes from the previous version of this integration.

### Arguments

#### The following argument was removed in this version:

In the ***dhs-get-indicators*** command, *tlp_color*was removed.

#### The behavior of the following arguments was changed:

In the ***dhs-get-indicators*** command, the default value of the *limit* argument was changed to '10'.

### Outputs

#### The following outputs were removed in this version:

In the *dhs-get-indicators* command:

* *DHS.type* - this output was replaced by *DHS.Indicators.type*.
* *DHS.value* - this output was replaced by *DHS.Indicators.value*.
* *DHS.tlp* - this output was removed.

## Additional Considerations for this version

Use this version if your certificate supports TAXII 2 protocol.

## Known Limitations
"First Fetch Time" parameter can be configured for a maximum of 48 hours, due to limitations in DHS TAXII2 API. 
Therefore, it is not possible to fetch indicators that last appeared in the feed more than 48 hours ago.