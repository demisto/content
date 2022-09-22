This is example Threat Intelligence eXhange(CTIX) integration which enriches IP/Domain/URL/File Data.
This integration was integrated and tested with version 3.0.0 of CTIX

## Configure CTIX on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CTIX.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Endpoint URL | Enter the endpoint URL of your CTIX Instance. | True |
    | Access Key | Enter the Access Key from the CTIX application. | True |
    | Secret Key | Enter the Secret Key from the CTIX application. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch incidents |  | False |
    | Incidents Fetch Interval |  | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ctix-create-tag
***
Create new tag in the ctix platform


#### Base Command

`ctix-create-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | New tag's name. | Required | 
| color_code | New tag's hex colour code e.g #111111. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Tag.name | string | Name of the tag | 
| CTIX.Tag.tag_type | string | Type of the tag \(manual\) | 
| CTIX.Tag.colour_code | string | Colour Code of the tag | 
| CTIX.Tag.id | string | Id of the Created Tag | 
| CTIX.Tag.created | number | Created at timestamp | 
| CTIX.Tag.modified | number | Modified at timestamp | 

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
Get paginated list of tags


#### Base Command

`ctix-get-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 1. | Optional | 
| page_size | Page size for pagination. Default is 10. | Optional | 
| q | search query parameter. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Tag.name | string | Name of the tag | 
| CTIX.Tag.id | string | ID of the tag | 
| CTIX.Tag.colour_code | string | Hex colour code associated with tag | 
| CTIX.Tag.tag_type | string | Type of the tag | 
| CTIX.Tag.created | number | Created at timestamp | 
| CTIX.Tag.modified | number | Modified at timestamp | 

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

### ctix-delete-tag
***
Delete a tag with given tag_name


#### Base Command

`ctix-delete-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | Name of the tag. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.DeleteTag.result | string | Status | 

#### Command Example
```!ctix-delete-tag tag_name=xsoar_test_trial```

#### Context Example
```json
{"result": "Action Successfully Executed"}
```
### ctix-allowed-iocs
***
Adds list of same type of iocs to allowed


#### Base Command

`ctix-allowed-iocs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of ioc. Possible values are: ipv4-addr, ipv6-addr, autonomous-system, email-addr, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SSDEEP, url, cidr, domain-name, mutex, windows-registry-key, user-agent. | Required | 
| values | Values of the given type. | Required | 
| reason | Descriptive reason. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Details.invalid | unknown | Invalid iocs sent in request | 
| CTIX.Details.new_created | unknown | List of iocs added to whitelist | 
| CTIX.Details.already_exists | unknown | List of iocs already existing | 


#### Command Example
```!ctix-allowed-iocs reason=test type="ipv4-addr" values=x.x.x.x,x.x.xx.x```

#### Context Example
```json
{
		"details":{
			"already_exists": [
				"x.x.x.x",
				"x.x.xx.x"
			],
			"invalid": [],
			"new_created": []
		}
}
```

### ctix-get-allowed-iocs
***
get paginated list of allowed iocs


#### Base Command

`ctix-get-allowed-iocs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number . Default is 1. | Optional | 
| page_size | Page size. Default is 10. | Optional | 
| q | query param for searching. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IOC.id | string | ID of the object | 
| CTIX.IOC.include_emails | boolean | If enabled then the emails to the corresponding emails will be whitelisted | 
| CTIX.IOC.include_sub_domains | boolean | If enabled then the emails to the corresponding sub domains will be whitelisted | 
| CTIX.IOC.include_urls | boolean | If enabled then the emails to the corresponding urls will be whitelisted | 
| CTIX.IOC.type | string | Type of the ioc | 
| CTIX.IOC.value | string | Value of the ioc | 
| CTIX.IOC.created | number | Created at timestamp | 
| CTIX.IOC.modified | number | Modified at timestamp | 

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
Removes a alloweded ioc with given id


#### Base Command

`ctix-remove-allowed-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | allowed IOC ids. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| details | string | Operation result | 

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
Command for querying and listing threat data


#### Base Command

`ctix-get-threat-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query statement for the thread data, please refer to the documentation. | Required | 
| page | page. Default is 1. | Optional | 
| page_size | size of page. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.ThreatData.confidence_score | number | Confidence Score of the IOC | 
| CTIX.ThreatData.confidence_type | string | Confidence Type of the IOC | 
| CTIX.ThreatData.created | number | When the IOC was created in source | 
| CTIX.ThreatData.ctix_created | number | When the IOC was created in CTIX | 
| CTIX.ThreatData.ctix_modified | number | When the IOC was modified in CTIX | 
| CTIX.ThreatData.id | string | ID of the IOC in CTIX | 
| CTIX.ThreatData.indicator_type | string | Type of the Indicator | 
| CTIX.ThreatData.ioc_type | string | Type of IOC | 
| CTIX.ThreatData.is_actioned | boolean | Is Actioned | 
| CTIX.ThreatData.is_deprecated | boolean | Is Deprecated | 
| CTIX.ThreatData.is_false_positive | boolean | Is False Positive | 
| CTIX.ThreatData.is_reviewed | boolean | Is reviewed | 
| CTIX.ThreatData.is_revoked | boolean | Is revoked | 
| CTIX.ThreatData.is_watchlist | boolean | Is Watchlist | 
| CTIX.ThreatData.is_whitelisted | boolean | Is alloweded | 
| CTIX.ThreatData.modified | boolean | When the indicator modified | 
| CTIX.ThreatData.name | boolean | Name of the indicator | 
| CTIX.ThreatData.risk_severity | boolean | risk severity of the indicator | 
| CTIX.ThreatData.source_collections | unknown | Source Collections of the Indicator | 
| CTIX.ThreatData.source_confidence | string | Source Confidence of the indicator | 
| CTIX.ThreatData.sources | unknown | sources of the indicator | 
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
Saved Search listing api with pagination


#### Base Command

`ctix-get-saved-searches`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. | Optional | 
| page_size | page size. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.SavedSearch.id | string | ID of the object | 
| CTIX.SavedSearch.editable | boolean |  | 
| CTIX.SavedSearch.is_threat_data_search | boolean |  | 
| CTIX.SavedSearch.name | string |  | 
| CTIX.SavedSearch.order | number |  | 
| CTIX.SavedSearch.pinned | boolean |  | 
| CTIX.SavedSearch.query | string |  | 
| CTIX.SavedSearch.shared_type | string |  | 
| CTIX.SavedSearch.type | string |  | 
| CTIX.SavedSearch.meta_data | unknown |  | 

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
Source Collection listing api with pagination


#### Base Command

`ctix-get-server-collections`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. | Optional | 
| page_size | page size. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.ServerCollection.name | string | Name of the server | 
| CTIX.ServerCollection.id | string | ID of the object | 
| CTIX.ServerCollection.inbox | boolean | Inbox is enabled or not | 
| CTIX.ServerCollection.is_active | boolean | Object if active or not | 
| CTIX.ServerCollection.is_editable | boolean | Object if editable or not | 
| CTIX.ServerCollection.polling | boolean | Object polling is enabled or not | 
| CTIX.ServerCollection.type | string | Object type  | 
| CTIX.ServerCollection.description | string | description of the object | 
| CTIX.ServerCollection.created | number | Created timestamp | 

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
Enrichment tools listing API


#### Base Command

`ctix-get-actions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. | Optional | 
| page_size | page size. | Optional | 
| object_type | object type. | Optional | 
| action_type | action type. | Optional | 


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
 


#### Base Command

`ctix-add-indicator-as-false-positive`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_ids | , seperated list of indicator ids. | Required | 
| object_type | Type of object. Possible values are: attack-pattern, campaign, course-of-action, custom-object, grouping, identity, indicator, infrastructure, intrusion-set, location, malware, malware-analysis, observed-data, opinion, report, threat-actor, tool, note, vulnerability, artifact, directory, email-addr, user-account, email-message, file, ipv4-addr, ipv6-addr, mac-addr, autonomous-system, network-traffic, domain-name, process, software, windows-registry-key, mutex, url, observable, x509-certificate. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IndicatorFalsePositive.message | unknown | Indicator change result | 

#### Command Example
```!ctix-add-indicator-as-false-positive object_ids=19176d96-716d-48aa-af15-dfeff22e72e2,531e47a6-d7cd-47be-ae21-a3260518d4a5 object_type=indicator```

#### Context Example
```json
{"message":"Action Successfully Executed"}
```

### ctix-ioc-manual-review
***
Adds ioc to manual review bulk api


#### Base Command

`ctix-ioc-manual-review`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_ids | Object ids of the items to be added for manual review. | Required | 
| object_type | object type. Possible values are: attack-pattern, campaign, course-of-action, custom-object, grouping, identity, indicator, infrastructure, intrusion-set, location, malware, malware-analysis, observed-data, opinion, report, threat-actor, tool, note, vulnerability, artifact, directory, email-addr, user-account, email-message, file, ipv4-addr, ipv6-addr, mac-addr, autonomous-system, network-traffic, domain-name, process, software, windows-registry-key, mutex, url, observable, x509-certificate. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IOCManualReview.message | unknown | IOC Manual Review result | 

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
Deprecate ioc bulk api


#### Base Command

`ctix-deprecate-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_ids | Object ids . | Required | 
| object_type | object type. | Required | 


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
Add Analyst TLP


#### Base Command

`ctix-add-analyst-tlp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | object id. | Required | 
| object_type | object type. | Required | 
| data | data. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.AddAnalystTLP | unknown | Result of the addition of analyst TLP | 

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
Add Analyst Score for a Threat data


#### Base Command

`ctix-add-analyst-score`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | object id. | Required | 
| object_type | object type. | Required | 
| data | data. | Required | 


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
Saved Result Set


#### Base Command

`ctix-saved-result-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. Default is 1. | Optional | 
| page_size | page size. Default is 10. | Optional | 
| label_name | label name. | Optional | 
| query | CQL. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.SavedResultSet.analyst_score | number | Analyst score of the IOC | 
| CTIX.SavedResultSet.analyst_tlp | string | Analyst TLP of the IOC | 
| CTIX.SavedResultSet.confidence_score | number | Confidence score of the IOC | 
| CTIX.SavedResultSet.confidence_type | string | Confidence type of the IOC | 
| CTIX.SavedResultSet.country | string | Country of origin for the IOC | 
| CTIX.SavedResultSet.created | number | IOC creation date | 
| CTIX.SavedResultSet.ctix_created | number | IOC date of creation in CTIX | 
| CTIX.SavedResultSet.ctix_modified | number | IOC date of modification in CTIX | 
| CTIX.SavedResultSet.first_seen | date | IOC timestamp when it was first seen | 
| CTIX.SavedResultSet.id | number | IOC ID | 
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
```!ctix-saved-result-set label_name=test query=type=indicator```

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
Adding Tag to Indicator


#### Base Command

`ctix-add-tag-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page from where data will be taken. Default is 1. | Optional | 
| page_size | total number of results to be fetched. Default is 10. | Optional | 
| q | query. | Optional | 
| object_id | object id. | Optional | 
| object_type | object type. | Optional | 
| tag_id | tag id. | Optional | 


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
Remove Tag From Indicator


#### Base Command

`ctix-remove-tag-from-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | which page to bring the data from. Default is 1. | Optional | 
| page_size | number of pages to bring data from. Default is 10. | Optional | 
| q | query. | Optional | 
| object_id | object_id. | Optional | 
| object_type | object_type. | Optional | 
| tag_id | tag_id. | Optional | 


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
Search for tag


#### Base Command

`ctix-search-for-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | number of page from where data needs to brought. Default is 1. | Optional | 
| page_size | size of the result. Default is 10. | Optional | 
| q | query. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.SearchTag.colour_code | unknown | Colour code of the tag | 
| CTIX.SearchTag.created | number | Timestamp of when the tag was created | 
| CTIX.SearchTag.created_by | unknown | details of the person who created the tag | 
| CTIX.SearchTag.id | string | ID of the tag | 
| CTIX.SearchTag.modified | number | Timestamp of when the tag was modified | 
| CTIX.SearchTag.modified_by | unknown | Details of the person who modified the tag | 
| CTIX.SearchTag.name | unknown | Name of the tag | 
| CTIX.SearchTag.type | unknown | type of the tag | 

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
Get Indicator Details


#### Base Command

`ctix-get-indicator-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | from where data has to be brought. Default is 1. | Optional | 
| page_size | total number of results. Default is 10. | Optional | 
| object_id | object id. | Optional | 
| object_type | object type. | Optional | 


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
| CTIX.IndicatorDetails.pattern_type | string | pattern type of the indicator | 
| CTIX.IndicatorDetails.pattern_version | string | STIX pattern version | 
| CTIX.IndicatorDetails.sources | unknown | Sources of the indicator | 
| CTIX.IndicatorDetails.sub_type | string | Sub type of the indicator | 
| CTIX.IndicatorDetails.tld | string | TLD of the indicator | 
| CTIX.IndicatorDetails.tlp | string | TLP of the indicator | 
| CTIX.IndicatorDetails.type | string | Type of the indicator | 
| CTIX.IndicatorDetails.types | string | Types of the indicator | 
| CTIX.IndicatorDetails.valid_from | number | Timestamp of the indicator from then it was valid | 
| CTIX.IndicatorDetails.valid_until | unknown | Timestamp of the indicator till  | 

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
Get Indicator Tags


#### Base Command

`ctix-get-indicator-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | object id. | Optional | 
| object_type | object type. | Optional | 
| page | page. Default is 1. | Optional | 
| page_size | page size. Default is 10. | Optional | 


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

### ctix-get-indicator-relations
***
Get Indicator Relations


#### Base Command

`ctix-get-indicator-relations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. Default is 1. | Optional | 
| page_size | page size. Default is 10. | Optional | 
| object_id | object id. | Optional | 
| object_type | object type. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IndicatorRelations.relationship_type | unknown | Indicator relation types | 
| CTIX.IndicatorRelations.sources | unknown | Indicator sources | 
| CTIX.IndicatorRelations.target_ref | unknown | Indicator target reference  | 

#### Command Example
```!ctix-get-indicator-relations object_id=20067ec2-8ad1-470e-b0bb-3c4a72b15883 object_type=indicator```

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
Get Indicator Observations


#### Base Command

`ctix-get-indicator-observations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. | Optional | 
| page_size | page size. | Optional | 
| object_id | object id. | Optional | 
| object_type | object type. | Optional | 


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
| CTIX.IndicatorObservations.id | string | id of the indicator | 
| CTIX.IndicatorObservations.valid_until | number | Timestamp till when the indicator is valid | 
| CTIX.IndicatorObservations.sco_object_id | unknown | SCO object ID | 
| CTIX.IndicatorObservations.unique_hash | unknown | unique hash of the indicator | 
| CTIX.IndicatorObservations.description | unknown | description of the indicator | 
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
 


#### Base Command

`ctix-get-conversion-feed-source`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. Default is 1. | Optional | 
| page_size | page size. Default is 10. | Optional | 
| object_id | object id. | Optional | 
| object_type | object type. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.ConversionFeedSource.created | number | Indicator creation timestamp | 
| CTIX.ConversionFeedSource.id | string | ID of the indicator | 
| CTIX.ConversionFeedSource.name | string | name of the indicator | 
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
| object_type | object type. | Optional | 
| object_names | Will contain the SDO values. Example: If you need to get the object_ids of indicator 127.0.0.1 then the value will be 127.0.0.1. | Optional | 
| page_size | size of the page. Default is 10. | Optional | 


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
| CTIX.ThreatDataLookup.id | string | Indicator ID | 
| CTIX.ThreatDataLookup.indicator_type | string | Indicator type | 
| CTIX.ThreatDataLookup.ioc_type | string | IOC type | 
| CTIX.ThreatDataLookup.is_actioned | boolean | Is actioned | 
| CTIX.ThreatDataLookup.is_deprecated | boolean | is deprecated | 
| CTIX.ThreatDataLookup.is_false_positive | boolean | is false positive | 
| CTIX.ThreatDataLookup.is_reviewed | boolean | is reviewed  | 
| CTIX.ThreatDataLookup.is_revoked | boolean | is revoked | 
| CTIX.ThreatDataLookup.is_watchlist | boolean | is watchlisted | 
| CTIX.ThreatDataLookup.is_whitelisted | boolean | is whitelisted | 
| CTIX.ThreatDataLookup.last_seen | number | Timestamp of when the indicator was last seen | 
| CTIX.ThreatDataLookup.modified | number | Timestamp of when the indicator was modified | 
| CTIX.ThreatDataLookup.name | string | name of the indicator | 
| CTIX.ThreatDataLookup.null | unknown | null | 
| CTIX.ThreatDataLookup.primary_attribute | string | Primary Attribute | 
| CTIX.ThreatDataLookup.published_collections | unknown | published collections | 
| CTIX.ThreatDataLookup.risk_severity | string | Risk severity | 
| CTIX.ThreatDataLookup.source_collections | unknown | sources collections | 
| CTIX.ThreatDataLookup.source_confidence | string | Source confidence  | 
| CTIX.ThreatDataLookup.sources | unknown | sources | 
| CTIX.ThreatDataLookup.sub_type | string | Sub type | 
| CTIX.ThreatDataLookup.subscriber_collections | unknown | subscriber collections | 
| CTIX.ThreatDataLookup.subscribers | unknown | subscribers | 
| CTIX.ThreatDataLookup.tags | unknown | Tags | 
| CTIX.ThreatDataLookup.tlp | string | TLP | 
| CTIX.ThreatDataLookup.type | string | Type | 
| CTIX.ThreatDataLookup.valid_from | number | Timestamp from when the indicator was valid | 
| CTIX.ThreatDataLookup.valid_until | number | Timestamp till when the indicator was valid | 

#### Command Example
```!ctix-get-lookup-threat-data object_names=example.com, test.com object_type=indicator```

#### Context Example
```json
{"next": null,
 "page_size": 10,
 "previous": null,
 "results": [{"analyst_score": null,
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