The Cyware Intel Exchange integration allows users to fetch threat intelligence incidents and indicators, enrich IP, domain, URL, and file data, manage tags and notes, perform vulnerability lookups, and run generic API requests. The integration was tested with Cyware Intel Exchange version 3.x.

## Configure Cyware Intel Exchange in Cortex XSOAR

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Endpoint URL | Enter the endpoint URL of your Cyware Intel Exchange instance, e.g. <https://example.cyware.com/ctixapi/>. | True |
| Access Key | Enter the Access Key from the Cyware Intel Exchange application. | True |
| Secret Key | Enter the Secret Key from the Cyware Intel Exchange application. | True |
| Timeout | Enter the maximum time in seconds that Cortex XSOAR should wait for a response from Cyware Intel Exchange. Default is 180 seconds. | False |
| Trust any certificate (not secure) | Specify whether to trust any certificate (not secure). | False |
| Use system proxy settings | Specify whether to use system proxy settings. | False |
| Source Reliability | Reliability of the source providing the intelligence data. Default is "C - Fairly reliable". | False |
| Fetch incidents | Enable to fetch CTIX reports as Cortex XSOAR incidents. | False |
| Fetch indicators | Enable to fetch CTIX indicators from Saved Result Sets. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Incident type | The incident type to assign to fetched CTIX reports. Default is "CTIX Intel". | False |
| First fetch time | How far back to fetch on the first run (e.g., 3 days, 7 days, 1 month). Default is "3 days". | False |
| Incident Fetch CQL Query | Custom CQL query used when fetching incidents. Updates the default CQL query. For example, type = "report" AND confidence_score = "90". | False |
| Saved Result Set Label | The label name of the Saved Result Set to pull indicators from. | False |
| Saved Result Set Version | The version of Saved Result Set to use. Possible values are: v2, v3. | False |
| Retrieve Enriched Data | If enabled, indicators will be enriched via bulk IOC lookup (with relations and enrichment data) before ingestion. | False |
| Feed Fetch Interval | How often the platform polls CTIX for new indicators (e.g. "30 minutes", "1 hour", "12 hours"). Controls the XSOAR feed scheduler cadence. Default is "12 hours". | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Tags | Tags to apply to fetched indicators. Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. Possible values are: RED, AMBER, GREEN, WHITE. | False |
| Max Fetch | Maximum number of incidents to return per fetch run. Allowed Range is 1-200. Default is 10. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or within a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ctix-create-tag

***
Create a new tag in the Cyware Intel Exchange platform

#### Base Command

`ctix-create-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | Enter the tag name. | Required |
| color_code | Enter the tag’s hex color code. For example, #111111. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Tag.name | string | Name of the tag |
| CTIX.Tag.tag_type | string | Type of the tag |
| CTIX.Tag.colour_code | string | Colour code of the tag |
| CTIX.Tag.id | string | Id of the created Tag |
| CTIX.Tag.created | number | Timestamp when the tag was created. |
| CTIX.Tag.modified | number | Timestamp when the tag was modified. |

#### Command Example

```!ctix-create-tag tag_name=xsoar_test_trial color_code=#95A1B1```

#### Context Example

```json
{
    "colour_code": null,
    "created": 1652077948,
    "created_by": "40ab0f84-fb39-4444-95b2-cd155f574aa2",
    "id": "47662c77-b419-419c-9bcf-420e05b01067",
    "modified": 1652077948,
    "modified_by": "40ab0f84-fb39-4444-95b2-cd155f574aa2",
    "name": "xsoar_test_temp",
    "type": "manual"
}
```

### ctix-get-tags

***
Get a paginated list of tags.

#### Base Command

`ctix-get-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default value is 1. | Optional |
| page_size | Page size for pagination. Default value is 10. | Optional |
| q | Search query used to filter results | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Tag.name | string | Name of the tag |
| CTIX.Tag.id | string | ID of the tag |
| CTIX.Tag.colour_code | string | Hex colour code associated with tag |
| CTIX.Tag.tag_type | string | Type of the tag |
| CTIX.Tag.created | number | Timestamp when the tag was created |
| CTIX.Tag.modified | number | Timestamp when the tag was modified |

#### Command Example

```!ctix-get-tags```

#### Context Example

```json
{"next": "tags/?page=2&page_size=1&AccessID=sasfafs-asasvsfasf-vasvasf&Expires=1652078371&Signature=jndjaksbdakbsjdkabscbkjb",
 "page_size": 1,
 "previous": null,
 "results": [{"colour_code": null,
              "created": 1652077948,
              "created_by": {"email": "dummy.account@test.com",
                             "first_name": "dummy",
                             "id": "40ab0f84-fb39-4444-95b2-cd155f574aa2",
                             "last_name": "account"},
              "id": "47662c77-b419-419c-9bcf-420e05b01067",
              "modified": 1652077948,
              "modified_by": {"email": "dummy.account@test.com",
                              "first_name": "dummy",
                              "id": "40ab0f84-fb39-4444-95b2-cd155f574aa2",
                              "last_name": "account"},
              "name": "xsoar_test_temp",
              "type": "manual"}],
 "total": 10}
```

### ctix-disable-or-enable-tags

***
Enable or disable tags in the Cyware Intel Exchange platform.

#### Base Command

`ctix-disable-or-enable-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_ids | IDs of the tags to enable or disable. Supports multiple IDs as a comma-separated list. | Required |
| action | Action to be performed on the tag. Possible values are: enabled, disabled. The default value is disabled. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.TagAction.result | string | Status of the tag action |

#### Command Example

```!ctix-disable-or-enable-tags tag_ids=47662c77-b419-419c-9bcf-420e05b01067 action=disabled```

#### Context Example

```json
{"result": "Action Successfully Executed"}
```

### ctix-allowed-iocs

***
Add a list of same type IOCs to the allowed list.

#### Base Command

`ctix-allowed-iocs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of IOC. Possible values are: ipv4-addr, ipv6-addr, autonomous-system, email-addr, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SSDEEP, url, cidr, domain-name, mutex, windows-registry-key, user-agent. | Required |
| values | Values for the specified IOC type. | Required |
| reason | Reason for adding the IOCs to the allowed list. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Details.invalid | unknown | List of invalid IOCs provided in the request. |
| CTIX.Details.new_created | unknown | List of IOCs added to the whitelist. |
| CTIX.Details.already_exists | unknown | List of IOCs that already exist.|

#### Command Example

```!ctix-allowed-iocs reason=test type="ipv4-addr" values=x.x.x.x,x.x.x.x```

#### Context Example

```json
{
  "details":{
   "already_exists": [
    "x.x.x.x",
    "x.x.x.x"
   ],
   "invalid": [],
   "new_created": []
  }
}
```

### ctix-get-allowed-iocs

***
Get a paginated list of allowed IOCs.

#### Base Command

`ctix-get-allowed-iocs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default value is 1. | Optional |
| page_size | Page size for pagination. Default value is 10. | Optional |
| q | Search query used to filter results | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IOC.id | string | ID of the object. |
| CTIX.IOC.include_emails | boolean | Indicates whether the associated email addresses are whitelisted. |
| CTIX.IOC.include_sub_domains | boolean | Indicates whether the associated subdomains are whitelisted. |
| CTIX.IOC.include_urls | boolean | Indicates whether the associated URLs are whitelisted. |
| CTIX.IOC.type | string | Type of the IOC. |
| CTIX.IOC.value | string | Value of the IOC. |
| CTIX.IOC.created | number | Timestamp when the IOC was created. |
| CTIX.IOC.modified | number | Timestamp when the IOC was last modified. |

#### Command Example

```!ctix-get-allowed-iocs q=type=indicator```

#### Context Example

```json
{"next": "allowed/?page=2&page_size=1", "page_size": 1, "previous": null,
 "results": [{"created": 1652084983, "created_by": {"email":
 "dumy.account@example.com", "first_name": "dumy", "id":
 "40ab0f84-fb39-4444-95b2-cd155f574aa2", "last_name": "account"}, "follow":
 true, "id": "2df4a0ad-b1dd-4a4c-bf71-dcdefce0dcf9", "include_emails": false,
 "include_subdomains": false, "include_urls": false, "modified": 1652097309,
 "modified_by": {"email": "dummt.acount@example.com", "first_name": "", "id":
 "4a5f744c-800a-4fcd-be06-53f4b1b8f966", "last_name": ""}, "type":
 "ipv4-addr", "value": "x.x.x.x"}], "total": 5}
```

### ctix-remove-allowed-ioc

***
Removes an allowed IOC using the specified ID.

#### Base Command

`ctix-remove-allowed-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | IDs of the allowed IOCs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| details | string | Describes the status of the action. |

#### Command Example

```!ctix-remove-allowed-ioc ids=7a33a7ac-ab54-412f-a725-f35c208a54ea```

#### Context Example

```json
{
 "details": "Action applied succesfully"
}
```

### ctix-get-threat-data

***
Command for querying and listing threat data.

#### Base Command

`ctix-get-threat-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search query used to filter results | Required |
| page | Page number for pagination. Default value is 1. | Optional |
| page_size | Page size for pagination. Default value is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.ThreatData.confidence_score | number | Confidence Score of the IOC |
| CTIX.ThreatData.confidence_type | string | Confidence Type of the IOC |
| CTIX.ThreatData.created | number | Timestamp indicating when the IOC was created in the source. |
| CTIX.ThreatData.ctix_created | number | Timestamp indicating when the IOC was created in Cyware Intel Exchange. |
| CTIX.ThreatData.ctix_modified | number | Timestamp indicating when the IOC was modified in Cyware Intel Exchange. |
| CTIX.ThreatData.id | string | ID of the IOC in Cyware Intel Exchange. |
| CTIX.ThreatData.indicator_type | string | Type of the Indicator |
| CTIX.ThreatData.ioc_type | string | Type of IOC |
| CTIX.ThreatData.is_actioned | boolean | Indicates whether the IOC has been actioned |
| CTIX.ThreatData.is_deprecated | boolean | Indicates whether the IOC is deprecated |
| CTIX.ThreatData.is_false_positive | boolean | Indicates whether the IOC is a false positive |
| CTIX.ThreatData.is_reviewed | boolean | Indicates whether the IOC has been reviewed |
| CTIX.ThreatData.is_revoked | boolean | Indicates whether the IOC has been revoked |
| CTIX.ThreatData.is_watchlist | boolean | Indicates whether the IOC is on the watchlist |
| CTIX.ThreatData.is_whitelisted | boolean | Indicates whether the IOC is whitelisted |
| CTIX.ThreatData.modified | boolean | Timestamp indicating when the IOC was last modified |
| CTIX.ThreatData.name | boolean | Name of the indicator |
| CTIX.ThreatData.risk_severity | boolean | Risk severity of the indicator |
| CTIX.ThreatData.source_collections | unknown | Source Collections of the Indicator |
| CTIX.ThreatData.source_confidence | string | Source Confidence of the indicator |
| CTIX.ThreatData.sources | unknown | List of Sources for the indicator |
| CTIX.ThreatData.sub_type | string | Sub Type of the IOC |
| CTIX.ThreatData.tlp | string | TLP of the indicator |
| CTIX.ThreatData.type | string | Type of the IOC |
| CTIX.ThreatData.valid_from | number | Date from which IOC is valid |

#### Command Example

```!ctix-get-threat-data query=type=indicator```

#### Context Example

```json
{
  "next": null,
  "page_size": 10,
  "previous": null,
  "results": [
   {"analyst_score": null,
     "analyst_tlp": null,
     "confidence_score": 50,
     "confidence_type": "ctix",
     "country": null,
     "created": 1652081902,
     "ctix_created": 1652081903,
     "ctix_modified": 1652081903,
     "first_seen": null,
     "id": "1ff2a18a-0574-4015-bbec-bc7692dccb14",
     "indicator_type": "domain-name",
     "ioc_type": "domain-name",
     "is_actioned": false,
     "is_deprecated": false,
     "is_false_positive": false,
     "is_reviewed": false,
     "is_revoked": false,
     "is_watchlist": false,
     "is_whitelisted": false,
     "last_seen": null,
     "modified": 1652081902,
     "name": "example.com",
     "null": [],
     "primary_attribute": null,
     "published_collections": [],
     "risk_severity": "UNKNOWN",
     "source_collections": [{"id": "1981f5f6-49d4-4cad-97b7-8b2d276d2956",
           "name": "dummy"}],
     "source_confidence": "HIGH",
     "sources": [{"id": "48e5966e-5d1b-4cf9-8e79-306aa8702a28",
         "name": "dummy",
         "source_type": "RSS_FEED"}],
     "sub_type": "value",
     "subscriber_collections": [],
     "subscribers": [],
     "tags": [],
     "tlp": "AMBER",
     "type": "indicator",
     "valid_from": 1652081902,
     "valid_until": null}],
 "total": 1}
```

### ctix-get-saved-searches

***
List saved searches with pagination.

#### Base Command

`ctix-get-saved-searches`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default value is 1. | Optional |
| page_size | Number of results per page. Default value is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.SavedSearch.id | string | ID of the object |
| CTIX.SavedSearch.editable | boolean | Indicates whether the saved search is editable |
| CTIX.SavedSearch.is_threat_data_search | boolean | Indicates whether the saved search is a threat data search |
| CTIX.SavedSearch.name | string | Name of the saved search |
| CTIX.SavedSearch.order | number | Order of the saved search |
| CTIX.SavedSearch.pinned | boolean | Indicates whether the saved search is pinned |
| CTIX.SavedSearch.query | string | Query of the saved search |
| CTIX.SavedSearch.shared_type | string | Shared type of the saved search |
| CTIX.SavedSearch.type | string | Type of the saved search |
| CTIX.SavedSearch.meta_data | unknown | Metadata of the saved search |

#### Command Example

```!ctix-get-saved-searches```

#### Context Example

```json
{
 "next": null,
 "page_size": 10,
 "previous": null,
 "results": [
   {
  "created_by": {
    "email": "system.default@example.com",
    "first_name": "System",
    "id": "e99b5f93-4ae8-4560-a848-a4fbae3f4f26",
    "last_name": "Default"
  },
  "description": null,
  "editable": false,
  "id": "d5b54bc7-3b3f-424b-b08d-5e8cf746e998",
  "is_threat_data_search": true,
  "meta_data": null,
  "name": "Indicator",
  "order": 0,
  "pinned": false,
  "query": "type =indicator",
  "shared_type": "global",
  "shared_users": [

  ],
  "type": "cql"
   }
 ],
 "total": 1
}
```

### ctix-get-server-collections

***
List source collections with pagination.

#### Base Command

`ctix-get-server-collections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default value is 1. | Optional |
| page_size | Number of results per page. Default value is 15. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.ServerCollection.name | string | Name of the server |
| CTIX.ServerCollection.id | string | ID of the object |
| CTIX.ServerCollection.inbox | boolean | Indicates whether the inbox is enabled. |
| CTIX.ServerCollection.is_active | boolean | Indicates whether the object is active. |
| CTIX.ServerCollection.is_editable | boolean | Indicates whether the object is editable. |
| CTIX.ServerCollection.polling | boolean | Indicates whether the object polling is enabled. |
| CTIX.ServerCollection.type | string | Returns the Object Type |
| CTIX.ServerCollection.description | string | Description of the object |
| CTIX.ServerCollection.created | number | Timestamp indicating when the object was created |

#### Command Example

```!ctix-get-server-collections```

#### Context Example

```json
{"next": "collection/?page=2&page_size=1", "previous": null, "page_size": 1,
 "total": 7, "results": [{"id": "83b5fd74-8ca0-4f28-a173-1d6863b2acb4",
 "name": "collection", "description": "with description", "is_active": true,
 "type": "DATA_FEED", "is_editable": true, "polling": false, "inbox": true,
 "created": 1652080268, "has_subscribed": null}], "subscriber_name": ""}
```

### ctix-get-actions

***
List enrichment tools.

#### Base Command

`ctix-get-actions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 1. | Optional |
| page_size | Number of results per page. Default is 15. | Optional |
| object_type | Type of the object. | Optional |
| action_type | Type of the action. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Action.action_name | string | Name of the Action |
| CTIX.Action.action_type | unknown | Description of the action |
| CTIX.Action.actioned_on | number | Timestamp of when the action was taken  |
| CTIX.Action.app_name | string | Name of the app for the action |
| CTIX.app_type | string | Type of the app  |
| CTIX.Action.id | string | ID of the action |
| CTIX.Action.object_type | string | Type of the action |

#### Command Example

```!ctix-get-actions action_type=manual object_type=indicator```

#### Context Example

```json
{
 "next": "actions/?page=2&page_size=1&actions_type=manual&object_type=indicator",
 "page_size": 1,
 "previous": null,
 "results": [
   {
  "action_name": "Update Analyst Score",
  "action_type": "manual",
  "actioned_by": {
    "email": "dummy.email@test.com",
    "first_name": "test",
    "id":"40ab0f84-fb39-4444-95b2-cd155f574aa2",
    "last_name": "account"
  },
  "actioned_on": 1651646873,
  "app_name": "CTIX",
  "app_response": {

  },
  "app_type": "ctix",
  "id": "e8fe8d27-6329-4c0b-a3c0-be104be4de55",
  "object_id": "19176d96-716d-48aa-af15-dfeff22e72e2",
  "object_type": "indicator",
  "rule_id": null,
  "rule_name": null,
  "source_id": null,
  "tool": null
   }
 ],
 "total": 38459
  }
```

### ctix-add-indicator-as-false-positive

***
Marks indicators as false positive in bulk.

#### Base Command

`ctix-add-indicator-as-false-positive`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_ids | Comma-separated list of indicator IDs. | Required |
| object_type | Type of object. Possible values are: attack-pattern, campaign, course-of-action, custom-object, grouping, identity, indicator, infrastructure, intrusion-set, location, malware, malware-analysis, observed-data, opinion, report, threat-actor, tool, note, vulnerability, artifact, directory, email-addr, user-account, email-message, file, ipv4-addr, ipv6-addr, mac-addr, autonomous-system, network-traffic, domain-name, process, software, windows-registry-key, mutex, url, observable, x509-certificate. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IndicatorFalsePositive.message | unknown | Returns the result of the false positive action |

#### Command Example

```!ctix-add-indicator-as-false-positive object_ids=19176d96-716d-48aa-af15-dfeff22e72e2,531e47a6-d7cd-47be-ae21-a3260518d4a5 object_type=indicator```

#### Context Example

```json
{"message":"Action Successfully Executed"}
```

### ctix-ioc-manual-review

***
Add IOCs to manual review in bulk.

#### Base Command

`ctix-ioc-manual-review`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_ids | IDs of the objects to add for manual review. | Required |
| object_type | Type of the object. Possible values are: attack-pattern, campaign, course-of-action, custom-object, grouping, identity, indicator, infrastructure, intrusion-set, location, malware, malware-analysis, observed-data, opinion, report, threat-actor, tool, note, vulnerability, artifact, directory, email-addr, user-account, email-message, file, ipv4-addr, ipv6-addr, mac-addr, autonomous-system, network-traffic, domain-name, process, software, windows-registry-key, mutex, url, observable, x509-certificate. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IOCManualReview.message | unknown | Result of the IOC manual review |

#### Command Example

```!ctix-ioc-manual-review object_ids=f3064a83-304e-4801-bec2-2f26a432bfd2,0aced40d-9a83-46cd-a92b-0c776c92594c object_type=indicator```

#### Context Example

```json
{
    "message": "Action Successfully Executed"
}
```

### ctix-deprecate-ioc

***
Deprecates IOCs in bulk

#### Base Command

`ctix-deprecate-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_ids | Comma-separated list of object IDs. | Required |
| object_type | Type of the object. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.DeprecateIOC | unknown | Result of the IOC deprecation request |

#### Command Example

```!ctix-deprecate-ioc object_ids=f3064a83-304e-4801-bec2-2f26a432bfd2,0aced40d-9a83-46cd-a92b-0c776c92594c object_type=indicator```

#### Context Example

```json
{
    "message": "Action Successfully Executed"
}
```

### ctix-add-analyst-tlp

***
Add analyst TLP

#### Base Command

`ctix-add-analyst-tlp`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the object to add analyst TLP. | Required |
| object_type | Type of the object. | Required |
| data | Object details you want to add for the analyst TLP. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.AddAnalystTLP | unknown | Result of adding the analyst TLP. |

#### Command Example

```!ctix-add-analyst-tlp object_id=19176d96-716d-48aa-af15-dfeff22e72e2 object_type=indicator data={\"analyst_tlp\":\"GREEN\"}```

#### Context Example

```json
{
    "message": "Action Successfully Executed"
}
```

### ctix-add-analyst-score

***
Add analyst score for threat data.

#### Base Command

`ctix-add-analyst-score`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the object to add analyst score. | Required |
| object_type | Type of the object. | Required |
| data | Object details you want to add for the analyst score. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.AddAnalystScore | unknown | Result of adding analyst score to threat data |

#### Command Example

```!ctix-add-analyst-score data={"analyst_score":10} object_id=19176d96-716d-48aa-af15-dfeff22e72e2 object_type=indicator```

#### Context Example

```json
{
    "message": "Action Successfully Executed"
}
```

### ctix-saved-result-set

***
Retrieves Threat Data from the Saved Result Set

#### Base Command

`ctix-saved-result-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 1. | Optional |
| page_size | Page size for pagination. Default is 10. | Optional |
| label_name | Tag name for filtering results. | Optional |
| version | Version of the Saved Result Set to Use. Allowed Values are v2 and v3 | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.SavedResultSet.analyst_score | number | Analyst score of the IOC |
| CTIX.SavedResultSet.analyst_tlp | string | Analyst TLP of the IOC |
| CTIX.SavedResultSet.confidence_score | number | Confidence score of the IOC |
| CTIX.SavedResultSet.confidence_type | string | Confidence type of the IOC |
| CTIX.SavedResultSet.country | string | Country of origin for the IOC |
| CTIX.SavedResultSet.created | number | Timestamp of when the IOC was created |
| CTIX.SavedResultSet.ctix_created | number | IOC date of creation in CTIX |
| CTIX.SavedResultSet.ctix_modified | number | IOC date of modification in CTIX |
| CTIX.SavedResultSet.first_seen | date | IOC timestamp when it was first seen |
| CTIX.SavedResultSet.id | number | Object ID of the IOC |
| CTIX.SavedResultSet.indicator_type | string | Type of the indicator  |
| CTIX.SavedResultSet.ioc_type | string | Type of the IOC  |
| CTIX.SavedResultSet.is_actioned | boolean | If there is any action taken on the indicator |
| CTIX.SavedResultSet.is_deprecated | boolean | If the indicator is deprecated or not |
| CTIX.SavedResultSet.is_false_positive | boolean | Value of the indicator is false positive or not |
| CTIX.SavedResultSet.is_reviewed | boolean | Whether the indicator reviewed or not  |
| CTIX.SavedResultSet.is_revoked | boolean | Whether the indicator is revoked or not |
| CTIX.SavedResultSet.is_watchlist | boolean | Whether the indicator is under watchlist or not |
| CTIX.SavedResultSet.is_whitelisted | boolean | Whether the indicator is whitelisted or not |
| CTIX.SavedResultSet.last_seen | date | Timestamp of the when the IOC was last seen |
| CTIX.SavedResultSet.modified | date | Timestamp of the when the IOC was modified |
| CTIX.SavedResultSet.name | string | Name of the indicator |
| CTIX.SavedResultSet.null | unknown | null |
| CTIX.SavedResultSet.primary_attribute | string | Primary attribute of the IOC |
| CTIX.SavedResultSet.published_collections | unknown | Published collections of the IOC |
| CTIX.SavedResultSet.risk_severity | unknown | Risk severity of the IOC |
| CTIX.SavedResultSet.source_collections | unknown | Source collections of the IOC |
| CTIX.SavedResultSet.name | string | Name of the IOC |
| CTIX.SavedResultSet.sources | unknown | Sources of the IOC |
| CTIX.SavedResultSet.sub_type | unknown | Sub type of the IOC |
| CTIX.SavedResultSet.subscriber_collections | unknown | Subscription collections of the IOC |
| CTIX.SavedResultSet.subscribers | unknown | Subscribers of the IOC |
| CTIX.SavedResultSet.tags | unknown | Tags on the IOC |
| CTIX.SavedResultSet.tlp | unknown | TLP of the IOC |
| CTIX.SavedResultSet.type | unknown | Type of the IOC |
| CTIX.SavedResultSet.valid_from | unknown | Timestamp from when the IOC is valid |
| CTIX.SavedResultSet.valid_until | unknown | Timestamp till then the IOC is valid |

#### Command Example

```!ctix-saved-result-set label_name=malware-families```

#### Context Example

```json
{"next": "threat-data/list/?page=2&page_size=1", "page_size": 1, "previous":
 null, "results": [{"analyst_score": null, "analyst_tlp": null,
 "confidence_score": null, "confidence_type": "ctix", "country": null,
 "created": 1652111918, "ctix_created": 1652111957, "ctix_modified":
 1652111957, "first_seen": null, "id":
 "670afacb-2f72-42fe-84cc-b2022ba6a7ed", "indicator_type": null, "ioc_type":
 null, "is_actioned": false, "is_deprecated": false, "is_false_positive":
 false, "is_reviewed": false, "is_revoked": false, "is_watchlist": false,
 "is_whitelisted": false, "last_seen": null, "modified": 1652111949, "name":
 "Test12344", "null": [], "primary_attribute": null, "published_collections":
 [], "risk_severity": null, "source_collections": [{"id":
 "32b98724-8625-4af2-ad83-43b4b5c50885", "name": "Test12344"}],
 "source_confidence": "NONE", "sources": [{"id":
 "5968d895-424f-4271-a1d3-2b01041a17bb", "name": "Test12344", "source_type":
 "WEB_SCRAPPER"}], "sub_type": null, "subscriber_collections": [],
 "subscribers": [], "tags": [], "tlp": "AMBER", "type": "report",
 "valid_from": null, "valid_until": null}], "total": 353243}
```

### ctix-add-tag-indicator

***
Add tag to indicator

#### Base Command

`ctix-add-tag-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 1. | Optional |
| page_size | Total number of results to be fetched. Default is 10. | Optional |
| q | Search query for filtering results. | Optional |
| object_id | Object ID of the indicator. | Optional |
| object_type | Object type of the indicator. | Optional |
| tag_id | Tag ID to add to the indicator. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.TagUpdation.meesage | unknown | Result of the add indicator tag request |

#### Command Example

```!ctix-add-tag-indicator object_id=19176d96-716d-48aa-af15-dfeff22e72e2 object_type=indicator tag_id=fb35000b-82e7-4440-8f18-8b63bba5b372```

#### Context Example

```json
{
    "message": "Action Successfully Executed"
}
```

### ctix-remove-tag-from-indicator

***
Remove tag from indicator

#### Base Command

`ctix-remove-tag-from-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 1. | Optional |
| page_size | Total number of results to be fetched. Default is 10. | Optional |
| q | Search query for filtering results. | Optional |
| object_id | Object ID of the indicator. | Optional |
| object_type | Object type of the indicator. | Optional |
| tag_id | Tag ID to remove from the indicator. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.TagUpdation.message | unknown | Result of the remove indicator tag request |

#### Command Example

```!ctix-remove-tag-from-indicator object_id=19176d96-716d-48aa-af15-dfeff22e72e2 object_type=indicator tag_id=fb35000b-82e7-4440-8f18-8b63bba5b372```

#### Context Example

```json
{
    "message": "Action Successfully Executed"
}
```

### ctix-search-for-tag

***
Search for a tag

#### Base Command

`ctix-search-for-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 1. | Optional |
| page_size | Total number of results to be fetched. Default is 10. | Optional |
| q | Search query for filtering results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.SearchTag.colour_code | unknown | Colour code of the tag |
| CTIX.SearchTag.created | number | Timestamp of when the tag was created |
| CTIX.SearchTag.created_by | unknown | Details of the person who created the tag |
| CTIX.SearchTag.id | string | ID of the tag |
| CTIX.SearchTag.modified | number | Timestamp of when the tag was modified |
| CTIX.SearchTag.modified_by | unknown | Details of the person who modified the tag |
| CTIX.SearchTag.name | unknown | Name of the tag |
| CTIX.SearchTag.type | unknown | Type of the tag |

#### Command Example

```!ctix-search-for-tag q=xsoar_test_trial```

#### Context Example

```json
{"next": "tags/?page=2&page_size=1", "page_size": 1, "previous": null,
 "results": [{"colour_code": null, "created": 1652113918, "created_by":
 {"email": "dummy.account@example.com", "first_name": "dummy", "id":
 "40ab0f84-fb39-4444-95b2-cd155f574aa2", "last_name": "account"}, "id":
 "68981db8-6deb-41f0-9727-74ad81cf47b2", "modified": 1652113918,
 "modified_by": {"email": "dummy.account@example.com", "first_name":
 "dummy", "id": "40ab0f84-fb39-4444-95b2-cd155f574aa2", "last_name":
 "account"}, "name": "xsoar_test", "type": "manual"}], "total": 39893}
```

### ctix-get-indicator-details

***
Get indicator details

#### Base Command

`ctix-get-indicator-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 1. | Optional |
| page_size | Total number of results to be fetched. Default is 10. | Optional |
| object_id | Object ID of the indicator. | Optional |
| object_type | Object type of the indicator. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IndicatorDetails.aliases | string | Aliases of the tag if any |
| CTIX.IndicatorDetails.analyst_description | string | Analyst description provided if any |
| CTIX.IndicatorDetails.analyst_score | number | Analyst score of the indicator |
| CTIX.IndicatorDetails.analyst_tlp | string | Analyst provided TLP on the indicator |
| CTIX.IndicatorDetails.asn | string | ASN of the indicator |
| CTIX.IndicatorDetails.attribute_field | string | Attribute field of the indicator |
| CTIX.IndicatorDetails.attribute_value | string | Attribute value of the indicator |
| CTIX.IndicatorDetails.base_type | string | Base type of the indicator |
| CTIX.IndicatorDetails.confidence_score | number | Confidence score of the IOC |
| CTIX.IndicatorDetails.confidence_type | string | Confidence type of the IOC |
| CTIX.IndicatorDetails.country | string | Country of origin of the IOC |
| CTIX.IndicatorDetails.created | number | Timestamp of when the indicator was created |
| CTIX.IndicatorDetails.ctix_created | number | Timestamp of when the indicator was created in CTIX |
| CTIX.IndicatorDetails.ctix_modified | number | Timestamp of when the indicator was modified in CTIX |
| CTIX.IndicatorDetails.ctix_score | number | CTIX score of the indicator |
| CTIX.IndicatorDetails.ctix_tlp | string | CTIX assigned TLP of the indicator |
| CTIX.IndicatorDetails.defang_analyst_description | string | Defanged analyst description of the indicator |
| CTIX.IndicatorDetails.description | string | Description of the indicator |
| CTIX.IndicatorDetails.fang_analyst_description | string | Fang analyst description of the indicator |
| CTIX.IndicatorDetails.first_seen | number | Timestamp of then the indicator was first seen |
| CTIX.IndicatorDetails.last_seen | number | Timestamp of then the indicator was last seen |
| CTIX.IndicatorDetails.modified | number | Timestamp of then the indicator was modified |
| CTIX.IndicatorDetails.name | string | Name of the indicator |
| CTIX.IndicatorDetails.pattern | string | STIX pattern of the indicator |
| CTIX.IndicatorDetails.pattern_type | string | Pattern type of the indicator |
| CTIX.IndicatorDetails.pattern_version | string | STIX pattern version |
| CTIX.IndicatorDetails.sources | unknown | Sources of the indicator |
| CTIX.IndicatorDetails.sub_type | string | Sub type of the indicator |
| CTIX.IndicatorDetails.tld | string | TLD of the indicator |
| CTIX.IndicatorDetails.tlp | string | TLP of the indicator |
| CTIX.IndicatorDetails.type | string | Type of the indicator |
| CTIX.IndicatorDetails.types | string | Types of the indicator |
| CTIX.IndicatorDetails.valid_from | number | Timestamp of the indicator from then it was valid |
| CTIX.IndicatorDetails.valid_until | unknown | Timestamp of the indicator until when it is valid |

#### Command Example

```!ctix-get-indicator-details object_id=20067ec2-8ad1-470e-b0bb-3c4a72b15883 object_type=indicator```

#### Context Example

```json
{"aliases": null, "analyst_description": null, "analyst_score": null,
 "analyst_tlp": null, "asn": null, "attribute_field": "value",
 "attribute_value": "x.x.x.x", "base_type": "sdo", "confidence_score":
 18, "confidence_type": "CTIX", "country": "Netherlands", "created":
 1651648700, "ctix_created": 1651648700, "ctix_modified": 1652113922,
 "ctix_score": 18, "ctix_tlp": null, "defang_analyst_description": null,
 "description": null, "fang_analyst_description": null, "first_seen": null,
 "last_seen": null, "modified": 1651648700, "name": "x.x.x.x",
 "pattern": "[ipv4-addr:value = x.x.x.x]", "pattern_type": "stix",
 "pattern_version": "2.1", "sources": [{"id":
 "e941f6fb-387b-452c-b77d-b5b05c5e9df2", "name": "Dummy",
 "source_type": "API_FEEDS"}], "sub_type": "ipv4-addr", "tld": "", "tlp":
 "WHITE", "type": "indicator", "types": ["anomalous-activity"], "valid_from":
 1644335851, "valid_until": null}
```

### ctix-get-indicator-tags

***
Get indicator tags

#### Base Command

`ctix-get-indicator-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | Object ID of the indicator. | Optional |
| object_type | Object type of the indicator. | Optional |
| page | Page number for pagination. Default is 1. | Optional |
| page_size | Page size for pagination. Default is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IndicatorTags.notes | unknown | Notes on the indicator's tag |
| CTIX.IndicatorTags.is_deprecated | boolean | If the indicator's tag deprecated or not |
| CTIX.IndicatorTags.is_revoked | boolean | If the indicator's tag revoked or not |
| CTIX.IndicatorTags.ctix_created | number | Timestamp of when the Indicator tag was created in CTIX |
| CTIX.IndicatorTags.is_false_positive | boolean | If the indicator's tag is false positive or not |
| CTIX.IndicatorTags.name | string | Name of the indicator |
| CTIX.IndicatorTags.is_reviewed | boolean | If the indicator reviewed or not |
| CTIX.IndicatorTags.is_whitelisted | boolean | If the indicator whitelisted or not |
| CTIX.IndicatorTags.is_under_review | boolean | If the indicator is under review or not |
| CTIX.IndicatorTags.is_watchlist | boolean | If the indicator is under watchlist or not |
| CTIX.IndicatorTags.tags | unknown | Tags of the indicator |
| CTIX.IndicatorTags.sub_type | unknown | Sub type of the indicator |
| CTIX.IndicatorTags.type | unknown | Type of Indicator |

#### Command Example

```!ctix-get-indicator-tags object_id=20067ec2-8ad1-470e-b0bb-3c4a72b15883 object_type=indicator```

#### Context Example

```json
{
    "notes": [],
    "is_deprecated": false,
    "is_revoked": false,
    "ctix_created": 1651648700,
    "is_false_positive": false,
    "name": "x.x.x.x",
    "is_reviewed": false,
    "is_whitelisted": false,
    "is_under_review": false,
    "is_watchlist": false,
    "tags": [
        {
            "colour_code": null,
            "id": "e2139fd5-fe05-48c5-8aaf-a5dfce900919",
            "name": "test crowd"
        },
        {
            "colour_code": null,
            "id": "fb22e904-ad74-4b6e-987e-46e81caec9ed",
            "name": "MaliciousConfidence/Low"
        }
    ],
    "sub_type": "ipv4-addr",
    "type": "indicator"
}
```

### ctix-get-object-relations

***
Get Object relations

#### Base Command

`ctix-get-object-relations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 1. | Optional |
| page_size | Page size for pagination. Default is 10. | Optional |
| object_id | Object ID of the indicator. | Optional |
| object_type | Object type of the indicator. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IndicatorRelations.relationship_type | unknown | Indicator relation types |
| CTIX.IndicatorRelations.sources | unknown | Indicator sources |
| CTIX.IndicatorRelations.target_ref | unknown | Indicator target reference  |

#### Command Example

```!ctix-get-object-relations object_id=20067ec2-8ad1-470e-b0bb-3c4a72b15883 object_type=indicator```

#### Context Example

```json
{
    "next": null,
    "page_size": 10,
    "previous": null,
    "results": [
        {
            "relationship_type": "related-to",
            "sources": [
                {
                    "id": "48e5966e-5d1b-4cf9-8e79-306aa8702a28",
                    "name": "dummy",
                    "source_type": "RSS_FEED"
                }
            ],
            "target_ref": {
                "created": 1652081903,
                "id": "cb728d0e-3e31-4c3d-8f7d-09726a8bf7a8",
                "modified": 1652081903,
                "name": "Feed 6",
                "object_type": "report",
                "sub_type": null,
                "tlp": "AMBER"
            }
        }
    ],
    "total": 1
}
```

### ctix-get-indicator-observations

***
Get indicator observations

#### Base Command

`ctix-get-indicator-observations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 1. | Optional |
| page_size | Page size for pagination. Default is 10. | Optional |
| object_id | Object ID of the indicator. | Optional |
| object_type | Object type of the indicator. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IndicatorObservations.custom_attributes | unknown | Custom attributes if any |
| CTIX.IndicatorObservations.ctix_modified | number | Timestamp when indicator was modified in CTIX |
| CTIX.IndicatorObservations.created | number | Timestamp when indicator was created |
| CTIX.IndicatorObservations.pattern_type | string | Pattern type of Indicator |
| CTIX.IndicatorObservations.modified | number | Timestamp when indicator was modified  |
| CTIX.IndicatorObservations.ctix_created | number | Timestamp when indicator was created in CTIX |
| CTIX.IndicatorObservations.pattern_version | string | STIX Pattern version of indicator |
| CTIX.IndicatorObservations.confidence | string | Confidence level of the indicator |
| CTIX.IndicatorObservations.valid_from | number | Timestamp when indicator was valid from |
| CTIX.IndicatorObservations.pattern | string | STIX pattern |
| CTIX.IndicatorObservations.fang_description | string | FANG description  |
| CTIX.IndicatorObservations.defang_description | string | DEFANG description |
| CTIX.IndicatorObservations.spec_version | string | STIX Spec version |
| CTIX.IndicatorObservations.tags | unknown | Tags attached to the indicator |
| CTIX.IndicatorObservations.received_id | string | STIX ID when indicator was received |
| CTIX.IndicatorObservations.types | unknown | STIX Types attached to the indicator |
| CTIX.IndicatorObservations.source | unknown | STIX source of the indicator |
| CTIX.IndicatorObservations.id | string | ID of the indicator |
| CTIX.IndicatorObservations.valid_until | number | Timestamp till when the indicator is valid |
| CTIX.IndicatorObservations.sco_object_id | unknown | SCO object ID |
| CTIX.IndicatorObservations.unique_hash | unknown | Unique hash of the indicator |
| CTIX.IndicatorObservations.description | unknown | Description of the indicator |
| CTIX.IndicatorObservations.granular_markings | unknown | Granular Markings if any |
| CTIX.IndicatorObservations.collection | unknown | Collection details of the indicator |

#### Command Example

```!ctix-get-indicator-observations object_id=20067ec2-8ad1-470e-b0bb-3c4a72b15883 object_type=indicator```

#### Context Example

```json
{
 "result": {
  "next": null,
  "page_size": 10,
  "previous": null,
  "results": [
   {
    "custom_attributes": [],
    "ctix_modified": 1651648700,
    "created": 1644335851,
    "pattern_type": "stix",
    "modified": 1651648700,
    "ctix_created": 1651648700,
    "pattern_version": "2.1",
    "confidence": "LOW",
    "valid_from": 1644335851,
    "pattern": "[ipv4-addr:value = 'x.x.x.x']",
    "fang_description": null,
    "defang_description": null,
    "spec_version": "2.1",
    "tags": [
     {
      "colour_code": null,
      "id": "e2139fd5-fe05-48c5-8aaf-a5dfce900919",
      "name": "test crowd"
     },
     {
      "colour_code": null,
      "id": "fb22e904-ad74-4b6e-987e-46e81caec9ed",
      "name": "MaliciousConfidence/Low"
     }
    ],
    "received_id": "indicator--16a66ac2-3524-44a6-9b9d-5bec6bc80d91",
    "types": [
     "anomalous-activity"
    ],
    "source": {
     "id": "e941f6fb-387b-452c-b77d-b5b05c5e9df2",
     "name": "Dummy",
     "source_type": "API_FEEDS"
    },
    "id": "0a11d417-3501-4230-8454-c70e700cf1b8",
    "valid_until": null,
    "sco_object_id": "20067ec2-8ad1-470e-b0bb-3c4a72b15883",
    "unique_hash": "babea09af794cc5ae1403302e9ec5c2d",
    "description": "None",
    "granular_markings": [],
    "collection": {
     "id": "3d7df0f3-8c88-43d2-8742-deee21eb6ee0",
     "name": "test-crowd-ip"
    }
   }
  ],
  "total": 1
 }
}
```

### ctix-get-conversion-feed-source

***
Gets the Source Details of an API feed in Cyware Intel Exchange

#### Base Command

`ctix-get-conversion-feed-source`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 1. | Optional |
| page_size | Page size for pagination. Default is 10. | Optional |
| object_id | Object ID of the indicator. | Optional |
| object_type | Object type of the indicator. | Optional |
| q | Search query to filter feed sources. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.ConversionFeedSource.created | number | Indicator creation timestamp |
| CTIX.ConversionFeedSource.id | string | ID of the Indicator Source |
| CTIX.ConversionFeedSource.name | string | Name of the Indicator Source |
| CTIX.ConversionFeedSource.taxii_option | string | TAXII option |

#### Command Example

```!ctix-get-conversion-feed-source object_id=20067ec2-8ad1-470e-b0bb-3c4a72b15883 object_type=indicator```

#### Context Example

```json
{
 "result": {
  "next": "feed-sources/?page=2&page_size=10&object_id=1ff2a18a-0574-4015-bbec-bc7692dccb14&object_type=indicator",
  "page_size": 10,
  "previous": null,
  "results": [
   {
    "created": 1651841206,
    "id": "9c82a682-254f-410d-a1c0-dc3514415f79",
    "name": "dummy-threatmailbox",
    "taxii_option": "2.1"
   }
  ],
  "total": 31
 }
}
```

### ctix-get-lookup-threat-data

***
Lookup to get threat data

#### Base Command

`ctix-get-lookup-threat-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | Object type of the indicator. | Optional |
| ioc_type | IOC type filter (e.g. ipv4-addr, domain-name, url, MD5). Can be a comma-separated list. | Optional |
| object_names | Will contain the SDO values. For example: If you need to get the object_ids of indicator 127.0.0.1 then the value will be 127.0.0.1. | Optional |
| page_size | Page size for pagination. Default is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.ThreatDataLookup.analyst_score | number | Analyst score of the indicator |
| CTIX.ThreatDataLookup.analyst_tlp | string | Analyst TLP of the indicator |
| CTIX.ThreatDataLookup.confidence_score | number | Confidence score of the indicator |
| CTIX.ThreatDataLookup.confidence_type | string | Confidence type of the indicator |
| CTIX.ThreatDataLookup.country | string | Indicator origin country |
| CTIX.ThreatDataLookup.created | number | Timestamp of when the indicator was created |
| CTIX.ThreatDataLookup.ctix_created | number | Timestamp of when the indicator was created in CTIX |
| CTIX.ThreatDataLookup.ctix_modified | number | Timestamp of when the indicator was modified in CTIX |
| CTIX.ThreatDataLookup.first_seen | number | Timestamp of when the indicator was first seen |
| CTIX.ThreatDataLookup.id | string | Object ID of the Indicator |
| CTIX.ThreatDataLookup.indicator_type | string | Indicator type |
| CTIX.ThreatDataLookup.ioc_type | string | IOC type |
| CTIX.ThreatDataLookup.is_actioned | boolean | Indicates if the indicator has been actioned |
| CTIX.ThreatDataLookup.is_deprecated | boolean | Indicates if the indicator is deprecated |
| CTIX.ThreatDataLookup.is_false_positive | boolean | Indicates if the indicator is a false positive |
| CTIX.ThreatDataLookup.is_reviewed | boolean | Indicates if the indicator has been reviewed |
| CTIX.ThreatDataLookup.is_revoked | boolean | Indicates if the indicator has been revoked |
| CTIX.ThreatDataLookup.is_watchlist | boolean | Indicates if the indicator is watchlisted |
| CTIX.ThreatDataLookup.is_whitelisted | boolean | Indicates if the indicator is whitelisted |
| CTIX.ThreatDataLookup.last_seen | number | Timestamp of when the indicator was last seen |
| CTIX.ThreatDataLookup.modified | number | Timestamp of when the indicator was modified |
| CTIX.ThreatDataLookup.name | string | Name of the indicator |
| CTIX.ThreatDataLookup.null | unknown | null |
| CTIX.ThreatDataLookup.primary_attribute | string | Details of the Primary Attribute |
| CTIX.ThreatDataLookup.published_collections | unknown | Published collections |
| CTIX.ThreatDataLookup.risk_severity | string | Risk severity |
| CTIX.ThreatDataLookup.source_collections | unknown | Source collections |
| CTIX.ThreatDataLookup.source_confidence | string | Source confidence  |
| CTIX.ThreatDataLookup.sources | unknown | Sources |
| CTIX.ThreatDataLookup.sub_type | string | Sub type |
| CTIX.ThreatDataLookup.subscriber_collections | unknown | subscriber collections |
| CTIX.ThreatDataLookup.subscribers | unknown | subscribers |
| CTIX.ThreatDataLookup.tags | unknown | Tags |
| CTIX.ThreatDataLookup.tlp | string | TLP |
| CTIX.ThreatDataLookup.type | string | Type |
| CTIX.ThreatDataLookup.valid_from | number | Timestamp from when the indicator was valid |
| CTIX.ThreatDataLookup.valid_until | number | Timestamp till when the indicator was valid |

#### Command example

```!ctix-get-lookup-threat-data object_names=example.com,3.4.5.6 object_type=indicator```

#### Context Example

```json
{
    "CTIX": {
        "ThreatDataLookup": {
            "analyst_cvss_score": null,
            "analyst_score": null,
            "analyst_tlp": null,
            "confidence_score": 100,
            "confidence_type": "ctix",
            "country": null,
            "created": 1674080000,
            "ctix_created": 1674080000,
            "ctix_modified": 1674080000,
            "custom_attributes": [],
            "first_seen": null,
            "id": "6779a969-6404-4dd7-97ef-dec877c03c4f",
            "indicator_type": "domain-name",
            "ioc_type": "domain-name",
            "is_actioned": false,
            "is_deprecated": false,
            "is_false_positive": false,
            "is_reviewed": false,
            "is_revoked": false,
            "is_watchlist": false,
            "is_whitelisted": false,
            "last_seen": null,
            "modified": 1674080001,
            "name": "example.com",
            "null": [],
            "primary_attribute": null,
            "published_collections": [],
            "risk_severity": null,
            "severity": "UNKNOWN",
            "source_collections": [
                {
                    "id": "a9d67cc1-5de8-460b-8bf4-63abc7ceaa54",
                    "name": "anotherone (OpenAPI)"
                }
            ],
            "source_confidence": "HIGH",
            "sources": [
                {
                    "id": "38102b0e-1af4-4ee2-a62e-dd5f2ffaff5a",
                    "name": "testing (OpenAPI)",
                    "source_type": "MISCELLANEOUS"
                }
            ],
            "sub_type": "value",
            "subscriber_collections": [],
            "subscribers": [],
            "tags": [
                {
                    "colour_code": "#5236E2",
                    "id": "9635c41b-80fb-4a98-a1f3-e5796c72bb29",
                    "name": "created_using_openapi_lookup"
                }
            ],
            "tlp": "AMBER",
            "type": "indicator",
            "valid_from": 1674080000,
            "valid_until": null
        }
    },
    "DBotScore": {
        "Indicator": "example.com",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "domain",
        "Vendor": "Cyware Intel Exchange"
    },
    "Domain": {
        "Malicious": {
            "Description": null,
            "Vendor": "Cyware Intel Exchange"
        },
        "Name": "example.com"
    }
}
```

#### Human Readable Output

>### Lookup Data
>
>|confidence_score|confidence_type|created|ctix_created|ctix_modified|id|indicator_type|ioc_type|is_actioned|is_deprecated|is_false_positive|is_reviewed|is_revoked|is_watchlist|is_whitelisted|modified|name|severity|source_collections|source_confidence|sources|sub_type|tags|tlp|type|valid_from|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>
| 31 | ctix | 1666709826 | 1666874647 | 1670548277 | 10104a10-74a9-45d7-a412-f11531d64a38 | domain-name | domain-name | false | false | false | false | false | false | false | 1667442806 | example.com | UNKNOWN | {'id': '2a5a9989-030d-466b-b676-223d2b1f4d1e', 'name': 'Indicators v4'}, {'id': '5f4230a4-cc3a-4d32-b3ee-c53a373e2a8f', 'name': 'https://www.example.com/index.xml'}, {'id': '2dc18ee7-ee80-4fa7-953d-4df824f8e8ce', 'name': 'https://www.example.com/index.xml'} | MEDIUM | {'id': '131392bb-ecdf-45ae-8f22-b1160cf03401', 'name': 'Mandiant Threat Intelligence', 'source_type': 'API_FEEDS'}, {'id': '87e622e3-e8e5-4692-9b79-00efead3f874', 'name': 'https://www.example.com/index.xml', 'source_type': 'RSS_FEED'}, {'id': '0647eb19-c559-4d27-a441-b70117315e18', 'name': 'https://www.example.com/index.xml', 'source_type': 'RSS_FEED'} | value | AMBER | indicator | 1530174464 |

### ctix-get-create-threat-data

***
Get or create threat data

#### Base Command

`ctix-get-create-threat-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | Type of the object. | Optional |
| object_names | Will contain the SDO values. For example: If you need to get the object_ids of indicator 127.0.0.1 then the value will be 127.0.0.1. | Required |
| page_size | Page size for pagination. Default value is 10. | Optional |
| source | The source of the threat data. | Optional |
| collection | The collection to store the threat data in. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.ThreatDataGetCreate.Found.analyst_score | number | Analyst score of the indicator |
| CTIX.ThreatDataGetCreate.Found.analyst_tlp | string | Analyst TLP of the indicator |
| CTIX.ThreatDataGetCreate.Found.confidence_score | number | Confidence score of the indicator |
| CTIX.ThreatDataGetCreate.Found.confidence_type | string | Confidence type of the indicator |
| CTIX.ThreatDataGetCreate.Found.country | string | Indicator origin country |
| CTIX.ThreatDataGetCreate.Found.created | number | Timestamp of when the indicator was created |
| CTIX.ThreatDataGetCreate.Found.ctix_created | number | Timestamp of when the indicator was created in CTIX |
| CTIX.ThreatDataGetCreate.Found.ctix_modified | number | Timestamp of when the indicator was modified in CTIX |
| CTIX.ThreatDataGetCreate.Found.first_seen | number | Timestamp of when the indicator was first seen |
| CTIX.ThreatDataGetCreate.Found.id | string | Indicator ID |
| CTIX.ThreatDataGetCreate.Found.indicator_type | string | Indicator type |
| CTIX.ThreatDataGetCreate.Found.ioc_type | string | IOC type |
| CTIX.ThreatDataGetCreate.Found.is_actioned | boolean | Is actioned |
| CTIX.ThreatDataGetCreate.Found.is_deprecated | boolean | is deprecated |
| CTIX.ThreatDataGetCreate.Found.is_false_positive | boolean | is false positive |
| CTIX.ThreatDataGetCreate.Found.is_reviewed | boolean | is reviewed  |
| CTIX.ThreatDataGetCreate.Found.is_revoked | boolean | is revoked |
| CTIX.ThreatDataGetCreate.Found.is_watchlist | boolean | is watchlisted |
| CTIX.ThreatDataGetCreate.Found.is_whitelisted | boolean | is allowed |
| CTIX.ThreatDataGetCreate.Found.last_seen | number | Timestamp of when the indicator was last seen |
| CTIX.ThreatDataGetCreate.Found.modified | number | Timestamp of when the indicator was modified |
| CTIX.ThreatDataGetCreate.Found.name | string | name of the indicator |
| CTIX.ThreatDataGetCreate.Found.null | unknown | null |
| CTIX.ThreatDataGetCreate.Found.primary_attribute | string | Primary Attribute |
| CTIX.ThreatDataGetCreate.Found.published_collections | unknown | published collections |
| CTIX.ThreatDataGetCreate.Found.risk_severity | string | Risk severity |
| CTIX.ThreatDataGetCreate.Found.source_collections | unknown | sources collections |
| CTIX.ThreatDataGetCreate.Found.source_confidence | string | Source confidence  |
| CTIX.ThreatDataGetCreate.Found.sources | unknown | sources |
| CTIX.ThreatDataGetCreate.Found.sub_type | string | Sub type |
| CTIX.ThreatDataGetCreate.Found.subscriber_collections | unknown | subscriber collections |
| CTIX.ThreatDataGetCreate.Found.subscribers | unknown | subscribers |
| CTIX.ThreatDataGetCreate.Found.tags | unknown | Tags |
| CTIX.ThreatDataGetCreate.Found.tlp | string | TLP |
| CTIX.ThreatDataGetCreate.Found.type | string | Type |
| CTIX.ThreatDataGetCreate.Found.valid_from | number | Timestamp from when the indicator was valid |
| CTIX.ThreatDataGetCreate.Found.valid_until | number | Timestamp till when the indicator was valid |
| CTIX.ThreatDataGetCreate.NotFoundCreated | string | IOCs that weren't found, and therefore were created |
| CTIX.ThreatDataGetCreate.NotFoundInvalid | string | IOCs that were found to be invalid, so they were not created |

#### Command example

```!ctix-get-create-threat-data object_names=example.com,x.x.x.x,zzzzz collection=some_collection source=some_source```

#### Context Example

```json
{
    "CTIX": {
        "ThreatDataGetCreate": {
            "Found": {
                "analyst_cvss_score": null,
                "analyst_score": null,
                "analyst_tlp": null,
                "confidence_score": 100,
                "confidence_type": "ctix",
                "country": null,
                "created": 1674080000,
                "ctix_created": 1674080000,
                "ctix_modified": 1674080000,
                "custom_attributes": [],
                "first_seen": null,
                "id": "6779a969-6404-4dd7-97ef-dec877c03c4f",
                "indicator_type": "domain-name",
                "ioc_type": "domain-name",
                "is_actioned": false,
                "is_deprecated": false,
                "is_false_positive": false,
                "is_reviewed": false,
                "is_revoked": false,
                "is_watchlist": false,
                "is_whitelisted": false,
                "last_seen": null,
                "modified": 1674080001,
                "name": "example.com",
                "null": [],
                "primary_attribute": null,
                "published_collections": [],
                "risk_severity": null,
                "severity": "UNKNOWN",
                "source_collections": [
                    {
                        "id": "a9d67cc1-5de8-460b-8bf4-63abc7ceaa54",
                        "name": "anotherone (OpenAPI)"
                    }
                ],
                "source_confidence": "HIGH",
                "sources": [
                    {
                        "id": "38102b0e-1af4-4ee2-a62e-dd5f2ffaff5a",
                        "name": "testing (OpenAPI)",
                        "source_type": "MISCELLANEOUS"
                    }
                ],
                "sub_type": "value",
                "subscriber_collections": [],
                "subscribers": [],
                "tags": [
                    {
                        "colour_code": "#5236E2",
                        "id": "9635c41b-80fb-4a98-a1f3-e5796c72bb29",
                        "name": "created_using_openapi_lookup"
                    }
                ],
                "tlp": "AMBER",
                "type": "indicator",
                "valid_from": 1674080000,
                "valid_until": null
            },
            "NotFoundCreated": [
                "x.x.x.x"
            ],
            "NotFoundInvalid": [
                "zzzzz"
            ]
        }
    },
    "DBotScore": {
        "Indicator": "example.com",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "domain",
        "Vendor": "Cyware Intel Exchange"
    },
    "Domain": {
        "Malicious": {
            "Description": null,
            "Vendor": "Cyware Intel Exchange"
        },
        "Name": "example.com"
    }
}
```

#### Human Readable Output

>### Not Found: Invalid
>
>|Name|
>|---|
>| zzzzz |

### domain

***
Lookup domain threat data

Notice: Using this command to submit indicators may make the data publicly available. Refer to the vendor’s documentation for more details.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Will contain domain SDO values. For example: If you need to get the object_ids of indicator example.com then the value will be example.com. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| Domain.Name | String | The domain name. For example: "google.com". |

#### Command example

```!domain domain="example.com" using="Cyware Intel Exchange_instance"```

#### Context Example

```json
{
    "CTIX": {
        "ThreatDataLookup": {
            "Found": {
                "analyst_score": null,
                "analyst_tlp": null,
                "confidence_score": 31,
                "confidence_type": "ctix",
                "country": null,
                "created": 1666709826,
                "ctix_created": 1666874647,
                "ctix_modified": 1670548277,
                "first_seen": null,
                "id": "10104a10-74a9-45d7-a412-f11531d64a38",
                "indicator_type": "domain-name",
                "ioc_type": "domain-name",
                "is_actioned": false,
                "is_deprecated": false,
                "is_false_positive": false,
                "is_reviewed": false,
                "is_revoked": false,
                "is_watchlist": false,
                "is_whitelisted": false,
                "last_seen": null,
                "modified": 1667442806,
                "name": "example.com",
                "null": [],
                "primary_attribute": null,
                "published_collections": [],
                "risk_severity": "UNKNOWN",
                "source_collections": [
                    {
                        "id": "2a5a9989-030d-466b-b676-223d2b1f4d1e",
                        "name": "Indicators v4"
                    },
                    {
                        "id": "5f4230a4-cc3a-4d32-b3ee-c53a373e2a8f",
                        "name": "https://www.example.com/index.xml"
                    },
                    {
                        "id": "2dc18ee7-ee80-4fa7-953d-4df824f8e8ce",
                        "name": "https://www.example.com/index.xml"
                    }
                ],
                "source_confidence": "MEDIUM",
                "sources": [
                    {
                        "id": "131392bb-ecdf-45ae-8f22-b1160cf03401",
                        "name": "Mandiant Threat Intelligence",
                        "source_type": "API_FEEDS"
                    },
                    {
                        "id": "87e622e3-e8e5-4692-9b79-00efead3f874",
                        "name": "https://www.example.com/index.xml",
                        "source_type": "RSS_FEED"
                    },
                    {
                        "id": "0647eb19-c559-4d27-a441-b70117315e18",
                        "name": "https://www.example.com/index.xml",
                        "source_type": "RSS_FEED"
                    }
                ],
                "sub_type": "value",
                "subscriber_collections": [],
                "subscribers": [],
                "tags": [],
                "tlp": "AMBER",
                "type": "indicator",
                "valid_from": 1530174464,
                "valid_until": null
            }
        }
    },
    "DBotScore": {
        "Indicator": "example.com",
        "Reliability": "C - Fairly reliable",
        "Score": 2,
        "Type": "domain",
        "Vendor": "Cyware Intel Exchange"
    },
    "Domain": {
        "Name": "example.com"
    }
}
```

#### Human Readable Output

>### Lookup Data
>
>|confidence_score|confidence_type|created|ctix_created|ctix_modified|id|indicator_type|ioc_type|is_actioned|is_deprecated|is_false_positive|is_reviewed|is_revoked|is_watchlist|is_whitelisted|modified|name|risk_severity|source_collections|source_confidence|sources|sub_type|tlp|type|valid_from|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 31 | ctix | 1666709826 | 1666874647 | 1670548277 | 10104a10-74a9-45d7-a412-f11531d64a38 | domain-name | domain-name | false | false | false | false | false | false | false | 1667442806 | example.com | UNKNOWN | {'id': '2a5a9989-030d-466b-b676-223d2b1f4d1e', 'name': 'Indicators v4'},, {'id': '5f4230a4-cc3a-4d32-b3ee-c53a373e2a8f', 'name': 'https://www.example.com/index.xml'},, {'id': '2dc18ee7-ee80-4fa7-953d-4df824f8e8ce', 'name': 'https://www.example.com/index.xml'} | MEDIUM | {'id': '131392bb-ecdf-45ae-8f22-b1160cf03401', 'name': 'Mandiant Threat Intelligence', 'source_type': 'API_FEEDS'},, {'id': '87e622e3-e8e5-4692-9b79-00efead3f874', 'name': 'https://www.example.com/index.xml', 'source_type': 'RSS_FEED'},, {'id': '0647eb19-c559-4d27-a441-b70117315e18', 'name': 'https://www.example.com/index.xml', 'source_type': 'RSS_FEED'} | value | AMBER | indicator | 1530174464 |

### ip

***
Lookup IP threat data.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Will contain IP SDO values. For example: If you need to get the object_ids of indicator 1.2.3.4 then the value will be 1.2.3.4. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score provided by the vendor. |
| IP.Address | String | The IP address. For example: 1.2.3.4. |

#### Command example

```!ip ip="x.x.x.x" using="Cyware Intel Exchange_instance"```

#### Context Example

```json
{
    "CTIX": {
        "ThreatDataLookup": {
            "Found": {
                "analyst_score": null,
                "analyst_tlp": null,
                "confidence_score": 100,
                "confidence_type": "ctix",
                "country": "United States",
                "created": 1666710084,
                "ctix_created": 1666874647,
                "ctix_modified": 1671604244,
                "first_seen": null,
                "id": "5c2517a2-759f-4eb8-b9fa-346ff20cfaaf",
                "indicator_type": "ipv4-addr",
                "ioc_type": "ipv4-addr",
                "is_actioned": false,
                "is_deprecated": false,
                "is_false_positive": false,
                "is_reviewed": false,
                "is_revoked": false,
                "is_watchlist": false,
                "is_whitelisted": false,
                "last_seen": null,
                "modified": 1669170873,
                "name": "x.x.x.x",
                "null": [],
                "primary_attribute": null,
                "published_collections": [],
                "risk_severity": "UNKNOWN",
                "source_collections": [
                    {
                        "id": "2a5a9989-030d-466b-b676-223d2b1f4d1e",
                        "name": "Indicators v4"
                    },
                    {
                        "id": "fe150b23-6354-4a9b-8c27-202abc758ba3",
                        "name": "NCAS JG Test"
                    }
                ],
                "source_confidence": "HIGH",
                "sources": [
                    {
                        "id": "131392bb-ecdf-45ae-8f22-b1160cf03401",
                        "name": "Mandiant Threat Intelligence",
                        "source_type": "API_FEEDS"
                    },
                    {
                        "id": "50cbaaee-8083-494c-b42a-7c7fb73ca2dc",
                        "name": "NCAS JG Test",
                        "source_type": "RSS_FEED"
                    }
                ],
                "sub_type": "value",
                "subscriber_collections": [],
                "subscribers": [],
                "tags": [
                    {
                        "colour_code": "#5236E2",
                        "id": "f82fa004-75cc-4824-b129-914ec13728b5",
                        "name": "Destruction"
                    }
                ],
                "tlp": "AMBER",
                "type": "indicator",
                "valid_from": 1409607591,
                "valid_until": null
            }
        }
    },
    "DBotScore": {
        "Indicator": "x.x.x.x",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "ip",
        "Vendor": "Cyware Intel Exchange"
    },
    "IP": {
        "Address": "x.x.x.x",
        "Malicious": {
            "Description": null,
            "Vendor": "Cyware Intel Exchange"
        }
    }
}
```

#### Human Readable Output

>### Lookup Data
>
>|confidence_score|confidence_type|country|created|ctix_created|ctix_modified|id|indicator_type|ioc_type|is_actioned|is_deprecated|is_false_positive|is_reviewed|is_revoked|is_watchlist|is_whitelisted|modified|name|risk_severity|source_collections|source_confidence|sources|sub_type|tags|tlp|type|valid_from|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>
| 100 | ctix | United States | 1666710084 | 1666874647 | 1671604244 | 5c2517a2-759f-4eb8-b9fa-346ff20cfaaf | ipv4-addr | ipv4-addr | false | false | false | false | false | false | false | 1669170873 | x.x.x.x | UNKNOWN | {'id': '2a5a9989-030d-466b-b676-223d2b1f4d1e', 'name': 'Indicators v4'}, {'id': 'fe150b23-6354-4a9b-8c27-202abc758ba3', 'name': 'NCAS JG Test'} | HIGH | {'id': '131392bb-ecdf-45ae-8f22-b1160cf03401', 'name': 'Mandiant Threat Intelligence', 'source_type': 'API_FEEDS'}, {'id': '50cbaaee-8083-494c-b42a-7c7fb73ca2dc', 'name': 'NCAS JG Test', 'source_type': 'RSS_FEED'} | value | {'colour_code': '#5236E2', 'id': 'f82fa004-75cc-4824-b129-914ec13728b5', 'name': 'Destruction'} | AMBER | indicator | 1409607591 |

### file

***
Lookup file threat data

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Will contain file SDO values. For example: If you need to get the object_ids of a file hash 3ed0a30799543fa2c3a913c7985bffed then the value will be 3ed0a30799543fa2c3a913c7985bffed. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| File.MD5 | String | The MD5 hash of the file. |
| File.SHA1 | String | The SHA1 hash of the file. |
| File.SHA256 | String | The SHA256 hash of the file. |

#### Command example

```!file file="9c57753557ed258d731987834c56fa4c" using="Cyware Intel Exchange_instance"```

#### Context Example

```json
{
    "CTIX": {
        "ThreatDataLookup": {
            "Found": {
                "analyst_score": null,
                "analyst_tlp": null,
                "confidence_score": 100,
                "confidence_type": "ctix",
                "country": null,
                "created": 1673710318,
                "ctix_created": 1674124925,
                "ctix_modified": 1674124925,
                "first_seen": null,
                "id": "4ea5874d-0d6e-4a65-a8db-61d825d9fb8e",
                "indicator_type": "file",
                "ioc_type": "MD5",
                "is_actioned": false,
                "is_deprecated": false,
                "is_false_positive": false,
                "is_reviewed": false,
                "is_revoked": false,
                "is_watchlist": false,
                "is_whitelisted": false,
                "last_seen": null,
                "modified": 1673710318,
                "name": "9c57753557ed258d731987834c56fa4c",
                "null": [],
                "primary_attribute": null,
                "published_collections": [],
                "risk_severity": "UNKNOWN",
                "source_collections": [
                    {
                        "id": "2a5a9989-030d-466b-b676-223d2b1f4d1e",
                        "name": "Indicators v4"
                    }
                ],
                "source_confidence": "HIGH",
                "sources": [
                    {
                        "id": "131392bb-ecdf-45ae-8f22-b1160cf03401",
                        "name": "Mandiant Threat Intelligence",
                        "source_type": "API_FEEDS"
                    }
                ],
                "sub_type": "MD5",
                "subscriber_collections": [],
                "subscribers": [],
                "tags": [],
                "tlp": "AMBER",
                "type": "indicator",
                "valid_from": 1671281161,
                "valid_until": null
            }
        }
    },
    "DBotScore": {
        "Indicator": "9c57753557ed258d731987834c56fa4c",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "file",
        "Vendor": "Cyware Intel Exchange"
    },
    "File": {
        "Hashes": [],
        "Malicious": {
            "Description": null,
            "Vendor": "Cyware Intel Exchange"
        },
        "Name": "9c57753557ed258d731987834c56fa4c"
    }
}
```

#### Human Readable Output

>### Lookup Data
>
>|confidence_score|confidence_type|created|ctix_created|ctix_modified|id|indicator_type|ioc_type|is_actioned|is_deprecated|is_false_positive|is_reviewed|is_revoked|is_watchlist|is_whitelisted|modified|name|risk_severity|source_collections|source_confidence|sources|sub_type|tlp|type|valid_from|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 100 | ctix | 1673710318 | 1674124925 | 1674124925 | 4ea5874d-0d6e-4a65-a8db-61d825d9fb8e | file | MD5 | false | false | false | false | false | false | false | 1673710318 | 9c57753557ed258d731987834c56fa4c | UNKNOWN | {'id': '2a5a9989-030d-466b-b676-223d2b1f4d1e', 'name': 'Indicators v4'} | HIGH | {'id': '131392bb-ecdf-45ae-8f22-b1160cf03401', 'name': 'Mandiant Threat Intelligence', 'source_type': 'API_FEEDS'} | MD5 | AMBER | indicator | 1671281161 |

### url

***
Lookup URL threat data

Notice: Using this command to submit indicators may make the data publicly available. Refer to the vendor’s documentation for more details.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Will contain URL SDO values. For example: If you need to get the object_ids of a URL <https://cyware.com/> then the value will be <https://cyware.com/>. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score provided by the vendor. |
| URL.Data | String | The URL |

#### Command example

```!url url="http://example.com/" using="Cyware Intel Exchange_instance"```

#### Context Example

```json
{
    "CTIX": {
        "ThreatDataLookup": {
            "Found": {
                "analyst_score": null,
                "analyst_tlp": null,
                "confidence_score": 100,
                "confidence_type": "ctix",
                "country": null,
                "created": 1674166009,
                "ctix_created": 1674166009,
                "ctix_modified": 1674166009,
                "first_seen": null,
                "id": "dcada258-5fc2-4c42-b7d6-e8ffda6c5a9e",
                "indicator_type": "url",
                "ioc_type": "url",
                "is_actioned": false,
                "is_deprecated": false,
                "is_false_positive": false,
                "is_reviewed": false,
                "is_revoked": false,
                "is_watchlist": false,
                "is_whitelisted": false,
                "last_seen": null,
                "modified": 1674166010,
                "name": "http://example.com/",
                "null": [],
                "primary_attribute": null,
                "published_collections": [
                    {
                        "id": "ad842594-8faa-49fb-841e-7ff99a685718",
                        "name": null
                    }
                ],
                "risk_severity": "UNKNOWN",
                "source_collections": [
                    {
                        "id": "5432c580-e1f9-40c3-b40a-a47686dfcf22",
                        "name": "Free Text"
                    }
                ],
                "source_confidence": "HIGH",
                "sources": [
                    {
                        "id": "7eb93036-688e-4916-ab1f-fe9015c16b78",
                        "name": "Import",
                        "source_type": "CUSTOM_STIX_SOURCES"
                    }
                ],
                "sub_type": "value",
                "subscriber_collections": [],
                "subscribers": [],
                "tags": [],
                "tlp": "AMBER",
                "type": "indicator",
                "valid_from": 1674166009,
                "valid_until": null
            }
        }
    },
    "DBotScore": {
        "Indicator": "http://example.com/",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "url",
        "Vendor": "Cyware Intel Exchange"
    },
    "URL": {
        "Data": "http://example.com/",
        "Malicious": {
            "Description": null,
            "Vendor": "Cyware Intel Exchange"
        }
    }
}
```

#### Human Readable Output

>### Lookup Data
>
>|confidence_score|confidence_type|created|ctix_created|ctix_modified|id|indicator_type|ioc_type|is_actioned|is_deprecated|is_false_positive|is_reviewed|is_revoked|is_watchlist|is_whitelisted|modified|name|published_collections|risk_severity|source_collections|source_confidence|sources|sub_type|tlp|type|valid_from|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 100 | ctix | 1674166009 | 1674166009 | 1674166009 | dcada258-5fc2-4c42-b7d6-e8ffda6c5a9e | url | url | false | false | false | false | false | false | false | 1674166010 | <http://example.com/> | {'id': 'ad842594-8faa-49fb-841e-7ff99a685718', 'name': None} | UNKNOWN | {'id': '5432c580-e1f9-40c3-b40a-a47686dfcf22', 'name': 'Free Text'} | HIGH | {'id': '7eb93036-688e-4916-ab1f-fe9015c16b78', 'name': 'Import', 'source_type': 'CUSTOM_STIX_SOURCES'} | value | AMBER | indicator | 1674166009 |

### ctix-get-all-notes

***
Get paginated list of notes

#### Base Command

`ctix-get-all-notes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | If set, retrieves only notes associated with the threat data object with ID = object_id. | Optional |
| page | Page number for pagination. Default value is 1. | Optional |
| page_size | Page size for pagination. Default value is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Note.created | integer | The timestamp when the note was created |
| CTIX.Note.created_by | unknown | The user who created the note |
| CTIX.Note.created_by.email | string | The email of the user who created the note |
| CTIX.Note.created_by.first_name | string | The first name of the user who created the note |
| CTIX.Note.created_by.id | string | The ID of the user who created the note |
| CTIX.Note.created_by.last_name | string | The last name of the user who created the note |
| CTIX.Note.id | string | The ID of the Note |
| CTIX.Note.is_json | boolean | A flag indicating whether the Note is in JSON format |
| CTIX.Note.meta_data | unknown | Meta data for the Note |
| CTIX.Note.meta_data.component | string | The component for the Note |
| CTIX.Note.modified | integer | The timestamp when the Note was last modified |
| CTIX.Note.modified_by | unknown | The user who last modified the Note |
| CTIX.Note.modified_by.email | string | The email of the user who last modified the Note |
| CTIX.Note.modified_by.first_name | string | The first name of the user who last modified the Note |
| CTIX.Note.modified_by.id | string | The ID of the user who last modified the Note |
| CTIX.Note.modified_by.last_name | string | The last name of the user who last modified the Note |
| CTIX.Note.object_id | string | The object ID of the Note |
| CTIX.Note.text | string | The text of the Note |
| CTIX.Note.title | string | The title of the Note |
| CTIX.Note.type | string | The type of the Note |

#### Command example

```!ctix-get-all-notes page_size=1```

#### Context Example

```json
{
    "CTIX": {
        "Note": {
            "created": 1674173772,
            "created_by": {
                "email": "some.user@example.com",
                "first_name": "some",
                "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                "last_name": "user"
            },
            "id": "f8f67182-bf72-47df-9a90-31b2bd829a9d",
            "is_json": false,
            "meta_data": {
                "component": "threatdata",
                "object_id": "ba82b524-15b3-4071-8008-e58754f8d134",
                "type": "indicator"
            },
            "modified": 1674173772,
            "modified_by": {
                "email": "some.user@example.com",
                "first_name": "some",
                "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                "last_name": "user"
            },
            "object_id": "ba82b524-15b3-4071-8008-e58754f8d134",
            "text": "this is the old text",
            "title": null,
            "type": "threatdata"
        }
    }
}
```

#### Human Readable Output

>### Note Data
>
>|created|created_by|id|is_json|meta_data|modified|modified_by|object_id|text|type|
>|---|---|---|---|---|---|---|---|---|---|
>| 1674173772 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | f8f67182-bf72-47df-9a90-31b2bd829a9d | false | component: threatdata, object_id: ba82b524-15b3-4071-8008-e58754f8d134, type: indicator | 1674173772 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | ba82b524-15b3-4071-8008-e58754f8d134 | this is the old text | threatdata |

### ctix-get-note-details

***
Get details of a note by ID

#### Base Command

`ctix-get-note-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the note. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Note.created | integer | The timestamp when the note was created |
| CTIX.Note.created_by | unknown | The user who created the note |
| CTIX.Note.created_by.email | string | The email of the user who created the note |
| CTIX.Note.created_by.first_name | string | The first name of the user who created the note |
| CTIX.Note.created_by.id | string | The ID of the user who created the note |
| CTIX.Note.created_by.last_name | string | The last name of the user who created the note |
| CTIX.Note.id | string | The ID of the note |
| CTIX.Note.is_json | boolean | A flag indicating whether the note is in JSON format |
| CTIX.Note.meta_data | unknown | Meta data for the note |
| CTIX.Note.meta_data.component | string | The component for the note |
| CTIX.Note.modified | integer | The timestamp when the note was last modified |
| CTIX.Note.modified_by | unknown | The user who last modified the note |
| CTIX.Note.modified_by.email | string | The email of the user who last modified the note |
| CTIX.Note.modified_by.first_name | string | The first name of the user who last modified the note |
| CTIX.Note.modified_by.id | string | The ID of the user who last modified the note |
| CTIX.Note.modified_by.last_name | string | The last name of the user who last modified the note |
| CTIX.Note.object_id | string | The object ID of the note |
| CTIX.Note.text | string | The text of the note |
| CTIX.Note.title | string | The title of the note |
| CTIX.Note.type | string | The type of the note |

#### Command example

```!ctix-get-note-details id="7d739870-ce7d-415b-bbbf-25f4bbc6be66"```

#### Context Example

```json
{
    "CTIX": {
        "Note": {
            "created": 1671821868,
            "created_by": {
                "email": "some.user@example.com",
                "first_name": "some",
                "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                "last_name": "user"
            },
            "id": "7d739870-ce7d-415b-bbbf-25f4bbc6be66",
            "is_json": false,
            "meta_data": {
                "component": "threatdata",
                "object_id": "fake",
                "type": "indicator"
            },
            "modified": 1674173787,
            "modified_by": {
                "email": "some.user@example.com",
                "first_name": "some",
                "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                "last_name": "user"
            },
            "object_id": "fake",
            "text": "this is the new text",
            "title": null,
            "type": "threatdata"
        }
    }
}
```

#### Human Readable Output

>### Note Detail Data
>
>|created|created_by|id|is_json|meta_data|modified|modified_by|object_id|text|type|
>|---|---|---|---|---|---|---|---|---|---|
>| 1671821868 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | 7d739870-ce7d-415b-bbbf-25f4bbc6be66 | false | component: threatdata, object_id: fake, type: indicator | 1674173787 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | fake | this is the new text | threatdata |

### ctix-create-note

***
Creates a new note from the parameter 'text'

#### Base Command

`ctix-create-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | The text that you want the note to have. | Required |
| object_id | if set, will associate note to the Threat Data object with the provided ID. | Optional |
| object_type | only required if `object_id` is set, used to specify the type of object `object_id` is. Possible values are: indicator, malware, threat-actor, vulnerability, attack-pattern, campaign, course-of-action, identity, infrastructure, intrusion-set, location, malware-analysis, observed-data, opinion, tool, report, custom-object, observable, incident, note. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Note.created | integer | The timestamp when the note was created |
| CTIX.Note.created_by | unknown | The user who created the note |
| CTIX.Note.created_by.email | string | The email of the user who created the note |
| CTIX.Note.created_by.first_name | string | The first name of the user who created the note |
| CTIX.Note.created_by.id | string | The ID of the user who created the note |
| CTIX.Note.created_by.last_name | string | The last name of the user who created the note |
| CTIX.Note.id | string | The ID of the note |
| CTIX.Note.is_json | boolean | A flag indicating whether the note is in JSON format |
| CTIX.Note.meta_data | unknown | Meta data for the note |
| CTIX.Note.meta_data.component | string | The component for the note |
| CTIX.Note.modified | integer | The timestamp when the note was last modified |
| CTIX.Note.modified_by | unknown | The user who last modified the note |
| CTIX.Note.modified_by.email | string | The email of the user who last modified the note |
| CTIX.Note.modified_by.first_name | string | The first name of the user who last modified the note |
| CTIX.Note.modified_by.id | string | The ID of the user who last modified the note |
| CTIX.Note.modified_by.last_name | string | The last name of the user who last modified the note |
| CTIX.Note.object_id | string | The object ID of the note |
| CTIX.Note.text | string | The text of the note |
| CTIX.Note.title | string | The title of the note |
| CTIX.Note.type | string | The type of the note |

#### Command example

```!ctix-create-note text="hello world x100"```

#### Context Example

```json
{
    "CTIX": {
        "Note": {
            "created": 1674173831,
            "created_by": {
                "email": "some.user@example.com",
                "first_name": "some",
                "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                "last_name": "user"
            },
            "id": "35ee1841-8357-43e0-b372-aff9800cdc55",
            "is_json": false,
            "meta_data": {
                "component": "notes"
            },
            "modified": 1674173831,
            "modified_by": {
                "email": "some.user@example.com",
                "first_name": "some",
                "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                "last_name": "user"
            },
            "object_id": null,
            "text": "hello world x100",
            "title": null,
            "type": "notes"
        }
    }
}
```

#### Human Readable Output

>### Created Note Data
>
>|created|created_by|id|is_json|meta_data|modified|modified_by|text|type|
>|---|---|---|---|---|---|---|---|---|
>| 1674173831 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | 35ee1841-8357-43e0-b372-aff9800cdc55 | false | component: notes | 1674173831 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | hello world x100 | notes |

#### Command example

```!ctix-create-note text="hello world x100" object_id="da1a6268-e589-4231-a334-68fb0c2cc1e0" object_type=indicator```

#### Context Example

```json
{
    "CTIX": {
        "Note": {
            "created": 1674173838,
            "created_by": {
                "email": "some.user@example.com",
                "first_name": "some",
                "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                "last_name": "user"
            },
            "id": "e5584583-6d45-4fe8-82b4-a802007c38f0",
            "is_json": false,
            "meta_data": {
                "component": "threatdata",
                "object_id": "da1a6268-e589-4231-a334-68fb0c2cc1e0",
                "type": "indicator"
            },
            "modified": 1674173838,
            "modified_by": {
                "email": "some.user@example.com",
                "first_name": "some",
                "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                "last_name": "user"
            },
            "object_id": "da1a6268-e589-4231-a334-68fb0c2cc1e0",
            "text": "hello world x100",
            "title": null,
            "type": "threatdata"
        }
    }
}
```

#### Human Readable Output

>### Created Note Data
>
>|created|created_by|id|is_json|meta_data|modified|modified_by|object_id|text|type|
>|---|---|---|---|---|---|---|---|---|---|
>| 1674173838 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | e5584583-6d45-4fe8-82b4-a802007c38f0 | false | component: threatdata, object_id: da1a6268-e589-4231-a334-68fb0c2cc1e0, type: indicator | 1674173838 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | da1a6268-e589-4231-a334-68fb0c2cc1e0 | hello world x100 | threatdata |

### ctix-update-note

***
Updates the note text from an existing note, as specified by its ID

#### Base Command

`ctix-update-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the note. | Required |
| text | The updated text that you want the note to have. | Optional |
| object_id | If set, will associate the note to the Threat Data object with the provided ID. | Optional |
| object_type | Only required if `object_id` is set, used to specify the type of object `object_id` is. Possible values are: indicator, malware, threat-actor, vulnerability, attack-pattern, campaign, course-of-action, identity, infrastructure, intrusion-set, location, malware-analysis, observed-data, opinion, tool, report, custom-object, observable, incident, note. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Note.created | integer | The timestamp when the note was created |
| CTIX.Note.created_by | unknown | The user who created the note |
| CTIX.Note.created_by.email | string | The email of the user who created the note |
| CTIX.Note.created_by.first_name | string | The first name of the user who created the note |
| CTIX.Note.created_by.id | string | The ID of the user who created the note |
| CTIX.Note.created_by.last_name | string | The last name of the user who created the note |
| CTIX.Note.id | string | The ID of the note |
| CTIX.Note.is_json | boolean | A flag indicating whether the note is in JSON format |
| CTIX.Note.meta_data | unknown | Meta data for the note |
| CTIX.Note.meta_data.component | string | The component for the note |
| CTIX.Note.modified | integer | The timestamp when the note was last modified |
| CTIX.Note.modified_by | unknown | The user who last modified the note |
| CTIX.Note.modified_by.email | string | The email of the user who last modified the note |
| CTIX.Note.modified_by.first_name | string | The first name of the user who last modified the note |
| CTIX.Note.modified_by.id | string | The ID of the user who last modified the note |
| CTIX.Note.modified_by.last_name | string | The last name of the user who last modified the note |
| CTIX.Note.object_id | string | The object ID of the note |
| CTIX.Note.text | string | The text of the note |
| CTIX.Note.title | string | The title of the note |
| CTIX.Note.type | string | The type of the note |

#### Command example

```!ctix-update-note id="7d739870-ce7d-415b-bbbf-25f4bbc6be66" text="this is a test"```

#### Context Example

```json
{
    "CTIX": {
        "Note": {
            "created": 1671821868,
            "created_by": {
                "email": "some.user@example.com",
                "first_name": "some",
                "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                "last_name": "user"
            },
            "id": "7d739870-ce7d-415b-bbbf-25f4bbc6be66",
            "is_json": false,
            "meta_data": {
                "component": "threatdata",
                "object_id": "fake",
                "type": "indicator"
            },
            "modified": 1674173815,
            "modified_by": {
                "email": "some.user@example.com",
                "first_name": "some",
                "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                "last_name": "user"
            },
            "object_id": "fake",
            "text": "this is a test",
            "title": null,
            "type": "threatdata"
        }
    }
}
```

#### Human Readable Output

>### Updated Note Data
>
>|created|created_by|id|is_json|meta_data|modified|modified_by|object_id|text|type|
>|---|---|---|---|---|---|---|---|---|---|
>| 1671821868 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | 7d739870-ce7d-415b-bbbf-25f4bbc6be66 | false | component: threatdata, object_id: fake, type: indicator | 1674173815 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | fake | this is a test | threatdata |

#### Command example

```!ctix-update-note id="7d739870-ce7d-415b-bbbf-25f4bbc6be66" object_id="da1a6268-e589-4231-a334-68fb0c2cc1e0" object_type=indicator```

#### Context Example

```json
{
    "CTIX": {
        "Note": {
            "created": 1671821868,
            "created_by": {
                "email": "some.user@example.com",
                "first_name": "some",
                "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                "last_name": "user"
            },
            "id": "7d739870-ce7d-415b-bbbf-25f4bbc6be66",
            "is_json": false,
            "meta_data": {
                "component": "threatdata",
                "object_id": "fake",
                "type": "indicator"
            },
            "modified": 1674173824,
            "modified_by": {
                "email": "some.user@example.com",
                "first_name": "some",
                "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                "last_name": "user"
            },
            "object_id": "da1a6268-e589-4231-a334-68fb0c2cc1e0",
            "text": "this is a test",
            "title": null,
            "type": "threatdata"
        }
    }
}
```

#### Human Readable Output

>### Updated Note Data
>
>|created|created_by|id|is_json|meta_data|modified|modified_by|object_id|text|type|
>|---|---|---|---|---|---|---|---|---|---|
>| 1671821868 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | 7d739870-ce7d-415b-bbbf-25f4bbc6be66 | false | component: threatdata, object_id: fake, type: indicator | 1674173824 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | da1a6268-e589-4231-a334-68fb0c2cc1e0 | this is a test | threatdata |

### ctix-delete-note

***
Deletes an existing note using its ID.

#### Base Command

`ctix-delete-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the ID of the note. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Note.deletion.details | string | Returns the status of the note deletion request. |

#### Command example

```!ctix-delete-note id="7d739870-ce7d-415b-bbbf-25f4bbc6be66"```

#### Context Example

```json
{
    "CTIX": {
        "Note": {
            "details": "success"
        }
    }
}
```

#### Human Readable Output

>### Deleted Note Data
>
>|details|
>|---|
>| success |

### ctix-make-request

***
Allows you to make any API call to Cyware Intel Exchange endpoints.

#### Base Command

`ctix-make-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The HTTP method you would like to call. Possible values are: GET, POST, PUT, DELETE. | Required |
| endpoint | URL suffix of the API call to CTIX. | Required |
| body | Any data you would like to pass, in JSON format. | Optional |
| params | Any parameters you would like to pass, in JSON format. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!ctix-make-request type=POST endpoint=ingestion/notes/ body="{\"text\": \"this is the old text\",\"type\": \"threatdata\",\"meta_data\": {\"component\": \"threatdata\",\"object_id\": \"ba82b524-15b3-4071-8008-e58754f8d134\",\"type\": \"indicator\"},\"object_id\": \"ba82b524-15b3-4071-8008-e58754f8d134\"}"```

#### Context Example

```json
{
    "CTIX": {
        "Request": {
            "POST": {
                "ingestion/notes/": {
                    "created": 1674173772,
                    "created_by": {
                        "email": "some.user@example.com",
                        "first_name": "some",
                        "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                        "last_name": "user"
                    },
                    "id": "f8f67182-bf72-47df-9a90-31b2bd829a9d",
                    "is_json": false,
                    "meta_data": {
                        "component": "threatdata",
                        "object_id": "ba82b524-15b3-4071-8008-e58754f8d134",
                        "type": "indicator"
                    },
                    "modified": 1674173772,
                    "modified_by": {
                        "email": "some.user@example.com",
                        "first_name": "some",
                        "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                        "last_name": "user"
                    },
                    "object_id": "ba82b524-15b3-4071-8008-e58754f8d134",
                    "text": "this is the old text",
                    "title": null,
                    "type": "threatdata"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### HTTP Response Data
>
>|created|created_by|id|is_json|meta_data|modified|modified_by|object_id|text|type|
>|---|---|---|---|---|---|---|---|---|---|
>| 1674173772 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | f8f67182-bf72-47df-9a90-31b2bd829a9d | false | component: threatdata, object_id: ba82b524-15b3-4071-8008-e58754f8d134, type: indicator | 1674173772 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | ba82b524-15b3-4071-8008-e58754f8d134 | this is the old text | threatdata |

#### Command example

```!ctix-make-request type=GET endpoint=ingestion/notes/ params="{\"page\": 1, \"page_size\": 1}"```

#### Context Example

```json
{
    "CTIX": {
        "Request": {
            "GET": {
                "ingestion/notes/": {
                    "created": 1674173772,
                    "created_by": {
                        "email": "some.user@example.com",
                        "first_name": "some",
                        "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                        "last_name": "user"
                    },
                    "id": "f8f67182-bf72-47df-9a90-31b2bd829a9d",
                    "is_json": false,
                    "meta_data": {
                        "component": "threatdata",
                        "object_id": "ba82b524-15b3-4071-8008-e58754f8d134",
                        "type": "indicator"
                    },
                    "modified": 1674173772,
                    "modified_by": {
                        "email": "some.user@example.com",
                        "first_name": "some",
                        "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                        "last_name": "user"
                    },
                    "object_id": "ba82b524-15b3-4071-8008-e58754f8d134",
                    "text": "this is the old text",
                    "title": null,
                    "type": "threatdata"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### HTTP Response Data
>
>|created|created_by|id|is_json|meta_data|modified|modified_by|object_id|text|type|
>|---|---|---|---|---|---|---|---|---|---|
>| 1674173772 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | f8f67182-bf72-47df-9a90-31b2bd829a9d | false | component: threatdata, object_id: ba82b524-15b3-4071-8008-e58754f8d134, type: indicator | 1674173772 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | ba82b524-15b3-4071-8008-e58754f8d134 | this is the old text | threatdata |

#### Command example

```!ctix-make-request type=PUT endpoint=ingestion/notes/7d739870-ce7d-415b-bbbf-25f4bbc6be66/ body="{\"text\": \"this is the new text\"}"```

#### Context Example

```json
{
    "CTIX": {
        "Request": {
            "PUT": {
                "ingestion/notes/7d739870-ce7d-415b-bbbf-25f4bbc6be66/": {
                    "created": 1671821868,
                    "created_by": {
                        "email": "some.user@example.com",
                        "first_name": "some",
                        "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                        "last_name": "user"
                    },
                    "id": "7d739870-ce7d-415b-bbbf-25f4bbc6be66",
                    "is_json": false,
                    "meta_data": {
                        "component": "threatdata",
                        "object_id": "fake",
                        "type": "indicator"
                    },
                    "modified": 1674173787,
                    "modified_by": {
                        "email": "some.user@example.com",
                        "first_name": "some",
                        "id": "5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a",
                        "last_name": "user"
                    },
                    "object_id": "fake",
                    "text": "this is the new text",
                    "title": null,
                    "type": "threatdata"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### HTTP Response Data
>
>|created|created_by|id|is_json|meta_data|modified|modified_by|object_id|text|type|
>|---|---|---|---|---|---|---|---|---|---|
>| 1671821868 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | 7d739870-ce7d-415b-bbbf-25f4bbc6be66 | false | component: threatdata, object_id: fake, type: indicator | 1674173787 | email: some.user@example.com, first_name: some, id: 5b03c17e-a1f8-43ab-b0d5-9e178fb95c4a, last_name: user | fake | this is the new text | threatdata |

#### Command example

```!ctix-make-request type=DELETE endpoint=ingestion/notes/1e2f348b-8168-4330-933b-24263ab9116a/```

#### Context Example

```json
{
    "CTIX": {
        "Request": {
            "DELETE": {
                "ingestion/notes/1e2f348b-8168-4330-933b-24263ab9116a/": {
                    "details": "success"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### HTTP Response Data
>
>|details|
>|---|
>| success |

### ctix-get-vulnerability-data

***
Lookup vulnerability data

#### Base Command

`ctix-get-vulnerability-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | The CVE identifier to look up information about | Required |
| extra_fields | A comma separated list of extra fields to return in the response | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.VulnerabilityLookup.cpes | string | CPEs |
| CTIX.VulnerabilityLookup.cvss2 | number | CVSS2 |
| CTIX.VulnerabilityLookup.cvss3 | number | CVSS3 |
| CTIX.VulnerabilityLookup.dbot_reputation | integer | DbotReputation |
| CTIX.VulnerabilityLookup.description | string | Description |
| CTIX.VulnerabilityLookup.last_modified | string | LastModified |
| CTIX.VulnerabilityLookup.created | string | LastPublished |
| CTIX.VulnerabilityLookup.name | string | Name |
| CTIX.VulnerabilityLookup.uuid | string | UUID |
| CTIX.VulnerabilityLookup.extra_data | string | Extra data |

#### Command example

```!ctix-get-vulnerability-data cve=CVE-2023-30837``

#### Human Readable Output

>### HTTP Response Data

|cpes|cvss2|cvss3|dbot_reputation|description|extra_data|last_modified|last_published|name|uuid|
|---|---|---|---|---|---|---|---|---|
| cpe:2.3:a:vyper_project:vyper:*:*:*:*:*:*:*:* | None | None | 3 | Remote exploitation of a design error vulnerability in Vyper_project Vyper could could allow an attacker to cause a Denial of Service (DoS) condition on the targeted host.  A design error vulnerability has been identified in Vyper. Specifically, this issue occurs due to storage allocator overflow. Further details are not available at the time of this writing. ACTI will update this report as more details become available. | {} | 2023-05-08 05:48:58 | 2023-05-08 05:48:58 | CVE-2023-30837 | 32316b0b-58a4-4f14-8d06-3e1678841eca |

### cve

***
Lookup vulnerability info

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | The CVE identifier to look up information about | Required |
| extra_fields | A comma separated list of extra fields to return in the response | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.VulnerabilityLookup.cpes | string | CPEs |
| CTIX.VulnerabilityLookup.cvss2 | number | CVSS2 |
| CTIX.VulnerabilityLookup.cvss3 | number | CVSS3 |
| CTIX.VulnerabilityLookup.dbot_reputation | integer | DbotReputation |
| CTIX.VulnerabilityLookup.description | string | Description |
| CTIX.VulnerabilityLookup.last_modified | string | LastModified |
| CTIX.VulnerabilityLookup.created | string | LastPublished |
| CTIX.VulnerabilityLookup.name | string | Name |
| CTIX.VulnerabilityLookup.uuid | string | UUID |
| CTIX.VulnerabilityLookup.extra_data | string | Extra data |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| DBotScore.Score | number | The actual score. |

#### Command example

```!cve cve=CVE-2023-30837``

#### Human Readable Output

>### HTTP Response Data

|cpes|cvss2|cvss3|dbot_reputation|description|extra_data|last_modified|last_published|name|uuid|
|---|---|---|---|---|---|---|---|---|
| cpe:2.3:a:vyper_project:vyper:*:*:*:*:*:*:*:* | None | None | 3 | Remote exploitation of a design error vulnerability in Vyper_project Vyper could could allow an attacker to cause a Denial of Service (DoS) condition on the targeted host.  A design error vulnerability has been identified in Vyper. Specifically, this issue occurs due to storage allocator overflow. Further details are not available at the time of this writing. ACTI will update this report as more details become available. | {} | 2023-05-08 05:48:58 | 2023-05-08 05:48:58 | CVE-2023-30837 | 32316b0b-58a4-4f14-8d06-3e1678841eca |

### ctix-bulk-ioc-lookup-advanced

***
Performs a bulk lookup for threat data objects in Cyware Intel Exchange and retrieves details such as basic info, enriched data, and relations.

#### Base Command

`ctix-bulk-ioc-lookup-advanced`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The SDO object type to look up (e.g. indicator, malware, threat-actor). | Required |
| value | Comma-separated list of up to 100 threat data object values to look up. | Optional |
| object_id | Comma-separated list of up to 100 threat data object IDs to look up. | Optional |
| enrichment_data | Pass true to retrieve the latest five enrichment data objects. Default is false. Possible values are: true, false. | Optional |
| relation_data | Pass true to retrieve the latest 100 relation details. Default is false. Possible values are: true, false. | Optional |
| enrichment_tools | Comma-separated list of up to five enrichment tool names to filter enrichment data. | Optional |
| fields | Comma-separated list of field names to retrieve specific details. By default all fields are retrieved. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.BulkIOCLookupAdvanced.id | String | ID of the threat data object. |
| CTIX.BulkIOCLookupAdvanced.name | String | Value of the threat data object. |
| CTIX.BulkIOCLookupAdvanced.object_type | String | SDO type of the threat data object. |
| CTIX.BulkIOCLookupAdvanced.ioc_type | String | IOC type (hash type for hashes, indicator type key for others). |
| CTIX.BulkIOCLookupAdvanced.sub_type | String | Sub-type of the indicator. |
| CTIX.BulkIOCLookupAdvanced.confidence_score | Number | Confidence score calculated by the Cyware Intel Exchange confidence score engine. |
| CTIX.BulkIOCLookupAdvanced.analyst_score | String | Score assigned to the threat data object by an analyst. |
| CTIX.BulkIOCLookupAdvanced.tlp | String | TLP assigned to the threat data object by the source. |
| CTIX.BulkIOCLookupAdvanced.analyst_tlp | String | TLP assigned to the threat data object by an analyst. |
| CTIX.BulkIOCLookupAdvanced.country | String | Country where the threat data object was seen. |
| CTIX.BulkIOCLookupAdvanced.description | String | Source description of the threat data. |
| CTIX.BulkIOCLookupAdvanced.is_deprecated | Boolean | True if the IOC is marked as deprecated. |
| CTIX.BulkIOCLookupAdvanced.is_false_positive | Boolean | True if the IOC is marked as a false positive. |
| CTIX.BulkIOCLookupAdvanced.is_reviewed | Boolean | True if the threat data object is manually reviewed. |
| CTIX.BulkIOCLookupAdvanced.is_whitelisted | Boolean | True if the IOC is marked as an allowed indicator. |
| CTIX.BulkIOCLookupAdvanced.manual_review | Boolean | True if the threat data is marked for manual review by an analyst. |
| CTIX.BulkIOCLookupAdvanced.created | Number | Source created timestamp of the threat data object. |
| CTIX.BulkIOCLookupAdvanced.modified | Number | Source modified timestamp of the threat data object. |
| CTIX.BulkIOCLookupAdvanced.ctix_created | Number | Created timestamp of the threat data object in Cyware Intel Exchange. |
| CTIX.BulkIOCLookupAdvanced.ctix_modified | Number | Last modified timestamp of the threat data object in Cyware Intel Exchange. |
| CTIX.BulkIOCLookupAdvanced.first_seen | Number | First seen timestamp of the threat data object. |
| CTIX.BulkIOCLookupAdvanced.last_seen | Number | Last seen timestamp of the threat data object. |
| CTIX.BulkIOCLookupAdvanced.valid_from | Number | Timestamp since when this threat data object is valid. |
| CTIX.BulkIOCLookupAdvanced.valid_until | Number | Timestamp until when this threat data object is valid. |
| CTIX.BulkIOCLookupAdvanced.sources | Unknown | List of sources that reported the threat data object. |
| CTIX.BulkIOCLookupAdvanced.tags | Unknown | Tags associated with the threat data object. |
| CTIX.BulkIOCLookupAdvanced.published_collections | Unknown | List of collections in which the IOC is published. |
| CTIX.BulkIOCLookupAdvanced.relations | Unknown | List of related threat data objects (requires relation_data=true). |
| CTIX.BulkIOCLookupAdvanced.enrichment_data | Unknown | List of enrichment objects from enrichment tools (requires enrichment_data=true). |
| CTIX.BulkIOCLookupAdvanced.custom_attributes | Unknown | List of custom attributes with name and value details. |

#### Command Example

```!ctix-bulk-ioc-lookup-advanced object_type=indicator value=1.2.3.4,evil.example.com enrichment_data=true relation_data=true```

#### Context Example

```json
{
    "CTIX": {
        "BulkIOCLookupAdvanced": {
            "confidence_score": 85,
            "country": null,
            "created": 1674080000,
            "ctix_created": 1674080000,
            "ctix_modified": 1674080001,
            "enrichment_data": [],
            "first_seen": null,
            "id": "6779a969-6404-4dd7-97ef-dec877c03c4f",
            "ioc_type": "ipv4-addr",
            "is_deprecated": false,
            "is_false_positive": false,
            "is_reviewed": false,
            "is_whitelisted": false,
            "last_seen": null,
            "modified": 1674080001,
            "name": "1.2.3.4",
            "object_type": "indicator",
            "relations": [],
            "sources": [
                {
                    "id": "38102b0e-1af4-4ee2-a62e-dd5f2ffaff5a",
                    "name": "Example Feed",
                    "source_type": "API_FEEDS"
                }
            ],
            "sub_type": "value",
            "tags": [],
            "tlp": "AMBER",
            "valid_from": 1674080000,
            "valid_until": null
        }
    }
}
```

#### Human Readable Output

>### Bulk IOC Lookup Advanced
>
>|confidence_score|created|ctix_created|ctix_modified|id|ioc_type|is_deprecated|is_false_positive|is_reviewed|is_whitelisted|modified|name|object_type|sources|sub_type|tlp|valid_from|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 85 | 1674080000 | 1674080000 | 1674080001 | 6779a969-6404-4dd7-97ef-dec877c03c4f | ipv4-addr | false | false | false | false | 1674080001 | 1.2.3.4 | indicator | {'id': '38102b0e-1af4-4ee2-a62e-dd5f2ffaff5a', 'name': 'Example Feed', 'source_type': 'API_FEEDS'} | value | AMBER | 1674080000 |
