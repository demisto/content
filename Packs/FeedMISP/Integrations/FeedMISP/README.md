Indicators feed from MISP.
This integration was integrated and tested with version 1.0 of MISP Feed.

MISP Feed integration allows you to ingest feeds into TIM via an MISP instance.
To ingest feeds via MISP, you must first configure a MISP instance and have the proper credentials.

To ingest specific feeds (Bambenek Consulting Feed, BruteForceBlocker Feed, etc.) directly to TIM without any authorization, you can use one of our dedicated feed content packs available in Marketplace. 

To ingest feeds via a URL, you could use one of the following content packs:
- CSV Feed
- JSON Feed
- Plain Text Feed
- RSS Feed

## Configure MISP Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| API Key | The API Key to use for the connection. | True |
| Timeout | The timeout of the HTTP requests sent to the MISP API (in seconds). If no value is provided, the timeout will be set to 60 seconds.| False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Max. indicators per fetch | Limit the number of indicators retrieved in a fetch run. | False |
| MISP Attribute Tags | Attributes having one of the tags, or being an attribute of an event having one of the tags, will be returned. You can enter a comma-separated list of tags, for example <tag1,tag2,tag3>. The list of MISP tags can be found in your MISP instance under 'Event Actions'>'List Tags' | False |
| MISP Attribute Types | Attributes of one of these types will be returned. You can enter a comma-separated list of types, for example <type1,type2,type3>. The list of MISP types can be found in your MISP instance then 'Event Actions'>'Search Attributes'>'Type dropdown list' | False |
| Query | JSON query to filter MISP attributes. When the query parameter is used, Attribute Types and Attribute Tags parameters are not used. You can check for the correct syntax at https://&lt;Your MISP url&gt;/servers/openapi\#operation/restSearchAttributes | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Tags | Supports CSV values. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### misp-feed-get-indicators
***
Gets indicators from the feed.


#### Base Command

`misp-feed-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 10. | Optional | 
| tags | Tags of the attributes to search for. | Optional | 
| attribute_type | Types of the attributes to search for. | Optional | 
| query | JSON query to filter MISP attributes. When a query argument is used attribute_type and tags arguments are not used. You can check for the correct syntax at https://&lt;Your MISP url&gt;/servers/openapi#operation/restSearchAttributes. | Optional | 


#### Context Output

```json
{
    "MISPFeed": {
        "Indicators": {
            "0": {
              "fields": {
                "Category": "Payload delivery",
                "Description": "desc",
                "SHA256": "somehash",
                "Updated Date": 1607517728,
                "trafficlightprotocol": "GREEN"
              },
              "rawJSON": {
                "FeedURL": "someurl",
                "type": "File",
                "value": {
                  "Event": {
                    "distribution": 1,
                    "id": 123,
                    "info": "some info",
                    "org_id": 1,
                    "orgc_id": 7,
                    "uuid": "some uuid"
                  },
                  "category": "Payload delivery",
                  "comment": "desc",
                  "deleted": false,
                  "disable_correlation": false,
                  "distribution": 5,
                  "event_id": 143,
                  "first_seen": null,
                  "id": 69548,
                  "last_seen": null,
                  "object_id": 0,
                  "object_relation": null,
                  "sharing_group_id": 0,
                  "timestamp": 1607517728,
                  "to_ids": true,
                  "type": "sha256",
                  "uuid": "some uuid",
                  "value": "some hash"
                }
              },
              "service": "MISP",
              "type": "File",
              "value":"somehash"
            }
        }
    }
}
```

#### Command Example
``` !misp-feed-get-indicators tags=tlp:% attribute_type=ip-src ```

#### Human Readable Output
Retrieved 7 indicators.

## Additional Information
If you experience a timeout error while fetching indicators, the following query configuration may be helpful for you.

You can configure the feed to return results from the last 24 hours as shown below:
```json
{
    "returnFormat": "json",
    "type": {
        "OR": []
    },
    "tags": {
        "OR": []
    },
    "last":"24h"
}
```

Both of the above queries can be modified however you would like depending on your specific use case. Additional information can be found here https://www.misp-project.org/openapi/#tag/Attributes/operation/restSearchAttributes